//! Event-driven lifetime of the OS-reported Unix peer at registration time.
//! This does not replace the connection's UID admission or observe socket EOF.
//! Profile control connections revoke on either event (or error).
//! On macOS, LOCAL_PEERTOKEN follows the socket's most recent process, so this
//! cannot recover an original connector after a pre-registration FD handoff.
//! Register once before publishing a capability; never reselect its owner.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};

use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::net::UnixStream;

pub(crate) struct PeerProcess {
    uid: u32,
    watch: AsyncFd<OwnedFd>,
    exited: bool,
}

impl PeerProcess {
    /// Register a kernel watch before publishing the peer identity. Must be
    /// called in a Tokio IO runtime. No numeric PID is accepted from the caller.
    pub(crate) fn from_peer(stream: &UnixStream) -> io::Result<Self> {
        let (uid, fd) = platform::watch_peer(stream)?;
        let mut peer = Self {
            uid,
            // kqueue descriptors support readability, not a writable filter.
            watch: AsyncFd::with_interest(fd, Interest::READABLE)?,
            exited: false,
        };
        if peer.has_exited()? {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "peer process already exited",
            ));
        }
        Ok(peer)
    }

    pub(crate) fn uid(&self) -> u32 {
        self.uid
    }

    /// A synchronous publication check. Once observed, exit is sticky even
    /// after macOS consumes its one-shot NOTE_EXIT event.
    pub(crate) fn has_exited(&mut self) -> io::Result<bool> {
        if !self.exited {
            self.exited = platform::has_exited(self.watch.get_ref().as_raw_fd())?;
        }
        Ok(self.exited)
    }

    /// Cancellation preserves the registered watch and any unread exit event.
    /// Errors must be treated as revocation by the eventual session owner.
    pub(crate) async fn wait_exit(&mut self) -> io::Result<()> {
        if self.has_exited()? {
            return Ok(());
        }
        loop {
            let mut ready = self.watch.readable().await?;
            if platform::has_exited(self.watch.get_ref().as_raw_fd())? {
                self.exited = true;
                return Ok(());
            }
            ready.clear_ready();
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::mem::size_of_val;
    use std::os::fd::{FromRawFd, RawFd};

    pub(super) fn watch_peer(stream: &UnixStream) -> io::Result<(u32, OwnedFd)> {
        let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = size_of_val(&cred) as libc::socklen_t;
        // SAFETY: the destination and its length describe a live ucred object.
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut cred as *mut libc::ucred).cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if len as usize != size_of_val(&cred) || cred.pid <= 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid peer credentials",
            ));
        }
        let mut raw: RawFd = -1;
        len = size_of_val(&raw) as libc::socklen_t;
        // SO_PEERPIDFD pins the socket's saved struct pid, not a freshly looked
        // up numeric PID. Linux < 6.5 is explicitly unsupported; no PID fallback.
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERPIDFD,
                (&mut raw as *mut RawFd).cast(),
                &mut len,
            )
        } != 0
        {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP)
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "SO_PEERPIDFD unavailable",
                ));
            }
            return Err(error);
        }
        if raw < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing peer pidfd",
            ));
        }
        // SAFETY: successful SO_PEERPIDFD installs one new, exclusively owned FD.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if len as usize != size_of_val(&raw) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid peer pidfd size",
            ));
        }
        // pidfd_prepare uses O_CLOEXEC; assert the contract rather than allowing
        // a watch to survive an unrelated child exec if the OS changes it.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) };
        if flags < 0 {
            return Err(io::Error::last_os_error());
        }
        if flags & libc::FD_CLOEXEC == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer pidfd lacks CLOEXEC",
            ));
        }
        Ok((cred.uid, fd))
    }

    pub(super) fn has_exited(fd: RawFd) -> io::Result<bool> {
        let mut pollfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            // Zero timeout: this syscall never blocks the async runtime.
            let result = unsafe { libc::poll(&mut pollfd, 1, 0) };
            if result >= 0 {
                if pollfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    return Err(io::Error::other("peer pidfd poll failed"));
                }
                return Ok(pollfd.revents & (libc::POLLIN | libc::POLLHUP) != 0);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use std::mem::size_of_val;
    use std::os::fd::{FromRawFd, RawFd};
    use std::ptr;

    type CFRef = *const c_void;
    const DYNAMIC_INFORMATION: u32 = 1 << 3;

    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn CFRelease(value: CFRef);
        fn CFDataCreate(allocator: CFRef, bytes: *const u8, length: isize) -> CFRef;
        fn CFDictionaryCreate(
            allocator: CFRef,
            keys: *const CFRef,
            values: *const CFRef,
            count: isize,
            key_callbacks: CFRef,
            value_callbacks: CFRef,
        ) -> CFRef;
    }
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecGuestAttributeAudit: CFRef;
        fn SecCodeCopyGuestWithAttributes(
            host: CFRef,
            attributes: CFRef,
            flags: u32,
            code: *mut CFRef,
        ) -> i32;
        fn SecCodeCopySigningInformation(code: CFRef, flags: u32, info: *mut CFRef) -> i32;
    }

    struct OwnedCF(CFRef);
    impl OwnedCF {
        fn new(value: CFRef) -> io::Result<Self> {
            if value.is_null() {
                Err(io::Error::other("missing Security framework result"))
            } else {
                Ok(Self(value))
            }
        }
    }
    impl Drop for OwnedCF {
        fn drop(&mut self) {
            // Every successful Create/Copy result is owned exactly once.
            unsafe { CFRelease(self.0) };
        }
    }

    fn security_result(status: i32) -> io::Result<()> {
        if status == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "peer dynamic identity unavailable (OSStatus {status})"
            )))
        }
    }

    fn verify_live_generation(token: &[u32; 8]) -> io::Result<()> {
        let data = OwnedCF::new(unsafe {
            CFDataCreate(
                ptr::null(),
                token.as_ptr().cast(),
                size_of_val(token) as isize,
            )
        })?;
        let key = unsafe { kSecGuestAttributeAudit };
        // Null callbacks borrow the static key and data, both outliving attrs.
        let attrs = OwnedCF::new(unsafe {
            CFDictionaryCreate(ptr::null(), &key, &data.0, 1, ptr::null(), ptr::null())
        })?;
        let mut code = ptr::null();
        security_result(unsafe {
            SecCodeCopyGuestWithAttributes(ptr::null(), attrs.0, 0, &mut code)
        })?;
        let code = OwnedCF::new(code)?;
        let mut info = ptr::null();
        // CopyGuest alone is lazy. Dynamic information invokes the kernel's
        // audit-token-aware status lookup, checking PID + pidversion *after*
        // kqueue attachment. No signature validity/TeamID is required: unsigned
        // or ad-hoc source peers have the same process lifetime semantics.
        security_result(unsafe {
            SecCodeCopySigningInformation(code.0, DYNAMIC_INFORMATION, &mut info)
        })?;
        let _info = OwnedCF::new(info)?;
        Ok(())
    }

    fn peer_token(stream: &UnixStream) -> io::Result<[u32; 8]> {
        let mut token = [0_u32; 8];
        let mut len = size_of_val(&token) as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                stream.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                token.as_mut_ptr().cast(),
                &mut len,
            )
        } != 0
        {
            return Err(io::Error::last_os_error());
        }
        if len as usize != size_of_val(&token) || token[5] == 0 || token[5] > i32::MAX as u32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid peer audit token",
            ));
        }
        Ok(token)
    }

    pub(super) fn watch_peer(stream: &UnixStream) -> io::Result<(u32, OwnedFd)> {
        // Public audit_token_t: euid is word 1, pid word 5, pidversion word 7.
        let token = peer_token(stream)?;
        let raw = unsafe { libc::kqueue() };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: kqueue returned a new, exclusively owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let change = libc::kevent {
            ident: token[5] as usize,
            filter: libc::EVFILT_PROC,
            flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_RECEIPT,
            fflags: libc::NOTE_EXIT,
            data: 0,
            udata: ptr::null_mut(),
        };
        let mut receipt: libc::kevent = unsafe { std::mem::zeroed() };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        let count = unsafe { libc::kevent(raw, &change, 1, &mut receipt, 1, &zero) };
        if count < 0 {
            return Err(io::Error::last_os_error());
        }
        if count != 1 || receipt.flags & libc::EV_ERROR == 0 {
            return Err(io::Error::other(
                "missing process-watch registration receipt",
            ));
        }
        if receipt.data != 0 {
            return Err(io::Error::from_raw_os_error(receipt.data as i32));
        }
        verify_live_generation(&token)?;
        Ok((token[1], fd))
    }

    pub(super) fn has_exited(fd: RawFd) -> io::Result<bool> {
        let mut event: libc::kevent = unsafe { std::mem::zeroed() };
        let zero = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        loop {
            let count = unsafe { libc::kevent(fd, ptr::null(), 0, &mut event, 1, &zero) };
            if count == 0 {
                return Ok(false);
            }
            if count > 0 {
                if event.flags & libc::EV_ERROR != 0 {
                    return Err(io::Error::from_raw_os_error(event.data as i32));
                }
                if event.filter != libc::EVFILT_PROC || event.fflags & libc::NOTE_EXIT == 0 {
                    return Err(io::Error::other("unexpected process-watch event"));
                }
                return Ok(true);
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn rejects_changed_generation(stream: &UnixStream) -> bool {
        let Ok(mut token) = peer_token(stream) else {
            return false;
        };
        if verify_live_generation(&token).is_err() {
            return false;
        }
        token[7] = token[7].wrapping_add(1);
        verify_live_generation(&token).is_err()
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::*;
    use std::os::fd::RawFd;
    pub(super) fn watch_peer(_: &UnixStream) -> io::Result<(u32, OwnedFd)> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer process monitoring unavailable",
        ))
    }
    pub(super) fn has_exited(_: RawFd) -> io::Result<bool> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "peer process monitoring unavailable",
        ))
    }
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream as StdStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixListener;
    use tokio::time::timeout;

    const FIXTURE: &str = "ipc::owner::tests::peer_process_fixture";
    const WAIT: Duration = Duration::from_secs(5);

    fn fixture_command() -> Command {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.args(["--exact", FIXTURE, "--ignored", "--nocapture"]);
        command.stdout(Stdio::null()).stderr(Stdio::inherit());
        command
    }

    // Test-only explicit inheritance: proves a surviving descendant retaining
    // the socket cannot hide the original connector's process exit.
    fn inherit(command: &mut Command, fds: Vec<i32>) {
        unsafe {
            command.pre_exec(move || {
                for fd in &fds {
                    if libc::fcntl(*fd, libc::F_SETFD, 0) < 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Ok(())
            });
        }
    }

    #[test]
    #[ignore = "subprocess fixture invoked only by owner tests"]
    fn peer_process_fixture() {
        let role = std::env::var("REKEY_TEST_OWNER_ROLE").unwrap();
        let raw = std::env::var("REKEY_TEST_OWNER_CONTROL_FD")
            .unwrap()
            .parse()
            .unwrap();
        // SAFETY: these descriptors were explicitly passed to this fixture by
        // pre_exec and each is adopted only once in this process.
        let mut control = unsafe { StdStream::from_raw_fd(raw) };
        if role == "holder" {
            let socket = std::env::var("REKEY_TEST_OWNER_SOCKET_FD")
                .unwrap()
                .parse()
                .unwrap();
            let mut socket = unsafe { StdStream::from_raw_fd(socket) };
            control.write_all(b"H").unwrap();
            let mut byte = [0];
            while control.read_exact(&mut byte).is_ok() {
                if byte == *b"Q" {
                    break;
                }
                assert_eq!(&byte, b"P");
                socket.write_all(b"H").unwrap();
            }
            return;
        }
        let mut socket =
            StdStream::connect(std::env::var_os("REKEY_TEST_OWNER_SOCKET").unwrap()).unwrap();
        let _holder = if role == "owner-with-holder" {
            let mut child = fixture_command();
            child
                .env("REKEY_TEST_OWNER_ROLE", "holder")
                .env(
                    "REKEY_TEST_OWNER_CONTROL_FD",
                    control.as_raw_fd().to_string(),
                )
                .env("REKEY_TEST_OWNER_SOCKET_FD", socket.as_raw_fd().to_string())
                .stdin(Stdio::null());
            inherit(&mut child, vec![control.as_raw_fd(), socket.as_raw_fd()]);
            Some(child.spawn().unwrap())
        } else {
            None
        };
        drop(control);
        socket.write_all(b"R").unwrap();
        let mut command = [0];
        std::io::stdin().read_exact(&mut command).unwrap();
        assert_eq!(&command, b"X");
    }

    struct Fixture {
        child: Child,
        socket: UnixStream,
        control: UnixStream,
        _dir: TempDir,
    }
    impl Fixture {
        async fn spawn(holder: bool) -> Self {
            // /tmp keeps the Unix socket name below the macOS path limit.
            let dir = tempfile::Builder::new()
                .prefix("rekey-owner-")
                .tempdir_in("/tmp")
                .unwrap();
            let path = dir.path().join("peer.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (control, inherited) = StdStream::pair().unwrap();
            control.set_nonblocking(true).unwrap();
            let control = UnixStream::from_std(control).unwrap();
            let mut child = fixture_command();
            child
                .env(
                    "REKEY_TEST_OWNER_ROLE",
                    if holder { "owner-with-holder" } else { "owner" },
                )
                .env("REKEY_TEST_OWNER_SOCKET", &path)
                .env(
                    "REKEY_TEST_OWNER_CONTROL_FD",
                    inherited.as_raw_fd().to_string(),
                )
                .stdin(Stdio::piped());
            inherit(&mut child, vec![inherited.as_raw_fd()]);
            let child = child.spawn().unwrap();
            drop(inherited);
            let (socket, _) = timeout(WAIT, listener.accept()).await.unwrap().unwrap();
            let mut fixture = Self {
                child,
                socket,
                control,
                _dir: dir,
            };
            let mut byte = [0];
            timeout(WAIT, fixture.socket.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&byte, b"R");
            if holder {
                timeout(WAIT, fixture.control.read_exact(&mut byte))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(&byte, b"H");
            }
            fixture
        }
        fn kill_owner(&mut self) {
            self.child.kill().unwrap();
            assert!(!self.child.wait().unwrap().success());
        }
        fn exit_owner(&mut self) {
            self.child.stdin.as_mut().unwrap().write_all(b"X").unwrap();
            assert!(self.child.wait().unwrap().success());
        }
        async fn holder_retains_socket(&mut self) {
            self.control.write_all(b"P").await.unwrap();
            let mut byte = [0];
            timeout(WAIT, self.socket.read_exact(&mut byte))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&byte, b"H");
        }
        async fn stop_holder(&mut self) {
            self.control.write_all(b"Q").await.unwrap();
            let mut byte = [0];
            assert_eq!(
                timeout(WAIT, self.control.read(&mut byte))
                    .await
                    .unwrap()
                    .unwrap(),
                0
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            // Dropping control also ends a descendant on test failure.
        }
    }

    #[tokio::test]
    async fn observes_normal_process_exit_and_keeps_exit_sticky() {
        let mut fixture = Fixture::spawn(false).await;
        let mut owner = PeerProcess::from_peer(&fixture.socket).unwrap();
        assert_eq!(owner.uid(), unsafe { libc::geteuid() });
        assert_ne!(
            unsafe { libc::fcntl(owner.watch.get_ref().as_raw_fd(), libc::F_GETFD) }
                & libc::FD_CLOEXEC,
            0
        );
        assert!(!owner.has_exited().unwrap());
        fixture.exit_owner();
        timeout(WAIT, owner.wait_exit()).await.unwrap().unwrap();
        assert!(owner.has_exited().unwrap());
        timeout(Duration::from_millis(50), owner.wait_exit())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn rejects_a_peer_that_exited_before_registration() {
        let mut fixture = Fixture::spawn(false).await;
        fixture.kill_owner();
        assert!(PeerProcess::from_peer(&fixture.socket).is_err());
    }

    #[tokio::test]
    async fn sigkill_is_observed_while_descendant_keeps_socket_open() {
        let mut fixture = Fixture::spawn(true).await;
        let mut owner = PeerProcess::from_peer(&fixture.socket).unwrap();
        // A later writer must not replace the already registered owner.
        fixture.holder_retains_socket().await;
        fixture.kill_owner();
        timeout(WAIT, owner.wait_exit()).await.unwrap().unwrap();
        fixture.holder_retains_socket().await;
        fixture.stop_holder().await;
    }

    #[tokio::test]
    async fn retained_socket_cannot_register_an_already_dead_owner() {
        let mut fixture = Fixture::spawn(true).await;
        fixture.kill_owner();
        assert!(PeerProcess::from_peer(&fixture.socket).is_err());
        fixture.holder_retains_socket().await;
        fixture.stop_holder().await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn peer_pidfd_rejects_dead_connector_even_after_descendant_writes() {
        let mut fixture = Fixture::spawn(true).await;
        fixture.kill_owner();
        fixture.holder_retains_socket().await;
        assert!(PeerProcess::from_peer(&fixture.socket).is_err());
        fixture.stop_holder().await;
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn preregistration_writer_handoff_changes_the_macos_observed_peer() {
        // Platform limitation, NOT protection of the original connector:
        // LOCAL_PEERTOKEN now refers to the surviving most recent writer.
        let mut fixture = Fixture::spawn(true).await;
        fixture.kill_owner();
        fixture.holder_retains_socket().await;
        let mut observed_writer = PeerProcess::from_peer(&fixture.socket).unwrap();
        assert!(!observed_writer.has_exited().unwrap());
        fixture.stop_holder().await;
        timeout(WAIT, observed_writer.wait_exit())
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn cancelled_wait_can_be_resumed() {
        let mut fixture = Fixture::spawn(false).await;
        let mut owner = PeerProcess::from_peer(&fixture.socket).unwrap();
        assert!(
            timeout(Duration::from_millis(30), owner.wait_exit())
                .await
                .is_err()
        );
        assert!(!owner.has_exited().unwrap());
        fixture.kill_owner();
        timeout(WAIT, owner.wait_exit()).await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn independent_owner_watches_do_not_affect_each_other() {
        let mut first = Fixture::spawn(false).await;
        let mut second = Fixture::spawn(false).await;
        let mut a = PeerProcess::from_peer(&first.socket).unwrap();
        let mut b = PeerProcess::from_peer(&second.socket).unwrap();
        first.kill_owner();
        timeout(WAIT, a.wait_exit()).await.unwrap().unwrap();
        assert!(!b.has_exited().unwrap());
        second.kill_owner();
        timeout(WAIT, b.wait_exit()).await.unwrap().unwrap();
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn dynamic_query_rejects_the_wrong_pid_generation() {
        let _fixture = Fixture::spawn(false).await;
        assert!(platform::rejects_changed_generation(&_fixture.socket));
    }
}
