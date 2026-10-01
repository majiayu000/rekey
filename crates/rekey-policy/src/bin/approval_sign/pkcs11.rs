//! Fixed operator PKCS#11 signing, isolated from the Broker and agent API.
use super::{Result, now};
use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    mechanism::{
        Mechanism,
        eddsa::{EddsaParams, EddsaSignatureScheme},
    },
    object::{Attribute, AttributeType, KeyType, ObjectClass},
    session::UserType,
    slot::Slot,
    types::AuthPin,
};
use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Write},
    num::NonZeroUsize,
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{
            fs::{MetadataExt, OpenOptionsExt},
            net::UnixStream,
            process::CommandExt,
        },
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const ERROR: &str = "PKCS11 signing failed; device result may be unknown; no automatic retry";
const PROFILE_ERROR: &str = "invalid private PKCS11 profile";
const CHILD_MODE: &str = "--internal-pkcs11-child";
const FRAME_LIMIT: usize = 128 * 1024;
const MESSAGE_LIMIT: usize = 65536;
const CURVE: &[u8] = b"\x13\x0cedwards25519";
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Profile {
    record_type: String,
    library_path: String,
    library_sha256: String,
    library_version: Version,
    slot_id: u64,
    token_serial: String,
    key_id: String,
    public_key: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Version {
    major: u8,
    minor: u8,
}

fn canonical_path(path: &str) -> bool {
    path.len() <= 4096
        && path.starts_with('/')
        && path != "/"
        && !path.as_bytes().contains(&0)
        && path
            .split('/')
            .skip(1)
            .all(|part| !matches!(part, "" | "." | ".."))
}
fn hex(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len().is_multiple_of(2)
        && value.len() <= max_bytes * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

// Each component is no-follow. Native code remains an explicit G1 operator trust boundary.
fn trusted_library(path: &str) -> Result<File> {
    if !canonical_path(path) {
        return Err(PROFILE_ERROR.into());
    }
    let mut current = PathBuf::from("/");
    for component in Path::new(path).components().skip(1) {
        current.push(component);
        let meta = std::fs::symlink_metadata(&current)?;
        if meta.file_type().is_symlink()
            || (meta.uid() != 0 && meta.uid() != unsafe { libc::geteuid() })
            || meta.mode() & 0o022 != 0
                && !(meta.uid() == 0 && meta.is_dir() && meta.mode() & 0o1000 != 0)
        {
            return Err(PROFILE_ERROR.into());
        }
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.nlink() != 1 || meta.mode() & 0o022 != 0 {
        return Err(PROFILE_ERROR.into());
    }
    Ok(file)
}
fn library_hash(path: &str, deadline: &Deadline) -> Result<String> {
    deadline.check()?;
    let mut file = trusted_library(path)?;
    let before = file.metadata()?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 8192];
    loop {
        deadline.check()?;
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    let after = file.metadata()?;
    let named = std::fs::symlink_metadata(path)?;
    if (
        before.dev(),
        before.ino(),
        before.len(),
        before.mtime(),
        before.mtime_nsec(),
        before.ctime(),
        before.ctime_nsec(),
    ) != (
        after.dev(),
        after.ino(),
        after.len(),
        after.mtime(),
        after.mtime_nsec(),
        after.ctime(),
        after.ctime_nsec(),
    ) || (named.dev(), named.ino()) != (before.dev(), before.ino())
    {
        return Err(PROFILE_ERROR.into());
    }
    Ok(HEXLOWER.encode(&hash.finalize()))
}

impl Profile {
    pub(super) fn load(path: &str) -> Result<Self> {
        let load = || -> Result<Self> {
            let mut file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path)?;
            let meta = file.metadata()?;
            if !meta.is_file()
                || meta.uid() != unsafe { libc::geteuid() }
                || meta.mode() & 0o777 != 0o600
                || meta.nlink() != 1
                || meta.len() > 65536
            {
                return Err(PROFILE_ERROR.into());
            }
            let mut bytes = Zeroizing::new(Vec::new());
            (&mut file).take(65537).read_to_end(&mut bytes)?;
            if bytes.len() > 65536 {
                return Err(PROFILE_ERROR.into());
            }
            let profile: Self = serde_json::from_slice(&bytes)?;
            profile.validate()?;
            Ok(profile)
        };
        load().map_err(|_| PROFILE_ERROR.into())
    }
    fn validate(&self) -> Result<()> {
        if self.record_type != "rekey.pkcs11.approval.v1"
            || !canonical_path(&self.library_path)
            || !hex(&self.library_sha256, 32)
            || self.library_sha256.len() != 64
            || !hex(&self.key_id, 64)
            || self.token_serial.is_empty()
            || self.token_serial.len() > 16
            || self.token_serial.trim() != self.token_serial
            || !self.token_serial.bytes().all(|b| (33..=126).contains(&b))
        {
            return Err(PROFILE_ERROR.into());
        }
        rekey_policy::validate_ed25519_public_key(&self.public_key)?;
        Ok(())
    }
    pub(super) fn check(&self, policy_key: &[u8]) -> Result<()> {
        if rekey_policy::validate_ed25519_public_key(&self.public_key)?.as_slice() != policy_key {
            return Err("PKCS11 public key does not match policy approver".into());
        }
        Ok(())
    }
    pub(super) fn public_review(&self) -> Value {
        json!(self)
    }
    pub(super) fn sign(&self, message: &[u8], policy_key: &[u8], expires: i64) -> Result<Vec<u8>> {
        self.check(policy_key)?;
        #[cfg(test)]
        if let Some(result) = TEST_SIGN.with(|hook| {
            hook.borrow_mut()
                .as_mut()
                .map(|hook| hook(message, expires))
        }) {
            let signature = result.map_err(|_| ERROR)?;
            verify_signature(message, policy_key, &signature)?;
            return Ok(signature);
        }
        let signing = || -> Result<Vec<u8>> {
            let deadline = Deadline::new(expires)?;
            let mut signals = Signals::install()?;
            let result = (|| {
                if library_hash(&self.library_path, &deadline)? != self.library_sha256 {
                    return Err(ERROR.into());
                }
                deadline.check()?;
                let pin = read_pin(&deadline)?;
                let input = Input {
                    profile: self.clone(),
                    pin,
                    message: BASE64URL_NOPAD.encode(message),
                    expires_at_ms: expires,
                };
                let mut frame = Zeroizing::new(serde_json::to_vec(&input)?);
                if frame.len() > FRAME_LIMIT || message.len() > MESSAGE_LIMIT {
                    return Err(ERROR.into());
                }
                let signature = self_exec(&mut frame, &deadline)?;
                verify_signature(message, policy_key, &signature)?;
                deadline.check()?;
                Ok(signature)
            })();
            finish_signing(&mut signals, &deadline, result)
        };
        signing().map_err(|_| ERROR.into())
    }
}
fn finish_signing(
    signals: &mut Signals,
    deadline: &Deadline,
    result: Result<Vec<u8>>,
) -> Result<Vec<u8>> {
    signals.restore()?;
    deadline.check()?;
    result
}

fn verify_signature(message: &[u8], public_key: &[u8], signature: &[u8]) -> Result<()> {
    if signature.len() != 64 {
        return Err(ERROR.into());
    }
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(message, signature)
        .map_err(|_| ERROR.into())
}

#[derive(Clone)]
struct Deadline {
    until: Instant,
    expires_at_ms: i64,
}
impl Deadline {
    fn new(expires: i64) -> Result<Self> {
        let remaining = expires
            .checked_sub(now()?.as_unix_ms())
            .filter(|ms| *ms > 0)
            .ok_or(ERROR)?;
        Ok(Self {
            until: Instant::now() + Duration::from_millis((remaining as u64).min(10000)),
            expires_at_ms: expires,
        })
    }
    fn check(&self) -> Result<()> {
        if INTERRUPTED.load(Ordering::SeqCst)
            || Instant::now() >= self.until
            || now()?.as_unix_ms() >= self.expires_at_ms
        {
            return Err(ERROR.into());
        }
        Ok(())
    }
    fn poll(&self, fd: RawFd, events: i16) -> Result<()> {
        loop {
            self.check()?;
            let millis = self
                .until
                .saturating_duration_since(Instant::now())
                .as_millis()
                .clamp(1, 100) as i32;
            let mut pfd = libc::pollfd {
                fd,
                events,
                revents: 0,
            };
            let n = unsafe { libc::poll(&mut pfd, 1, millis) };
            if n < 0 && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                return Err(ERROR.into());
            }
            if n > 0 {
                if pfd.revents & (libc::POLLERR | libc::POLLNVAL) != 0 {
                    return Err(ERROR.into());
                }
                if pfd.revents & (events | libc::POLLHUP) != 0 {
                    return Ok(());
                }
            }
        }
    }
}
extern "C" fn interrupt(_: i32) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}
struct Signals {
    previous: Vec<(i32, libc::sigaction)>,
}
impl Signals {
    fn install() -> Result<Self> {
        INTERRUPTED.store(false, Ordering::SeqCst);
        let mut guard = Self {
            previous: Vec::new(),
        };
        for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = interrupt as *const () as usize;
            unsafe {
                libc::sigemptyset(&mut action.sa_mask);
            }
            let mut previous = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, &action, &mut previous) } != 0 {
                return Err(ERROR.into());
            }
            guard.previous.push((signal, previous));
        }
        // Private socket writes use MSG_NOSIGNAL, never a process-global SIGPIPE override.
        Ok(guard)
    }
    fn restore(&mut self) -> Result<()> {
        #[cfg(test)]
        TEST_RESTORE_WINDOW.with(|hook| {
            if let Some(hook) = hook.borrow_mut().as_mut() {
                hook();
            }
        });
        let mut failed = false;
        for (signal, previous) in self.previous.drain(..).rev() {
            failed |= unsafe { libc::sigaction(signal, &previous, std::ptr::null_mut()) } != 0;
        }
        if failed { Err(ERROR.into()) } else { Ok(()) }
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

struct Tty {
    file: File,
    attrs: libc::termios,
    restored: bool,
}
impl Tty {
    fn hide(file: File) -> Result<Self> {
        let mut attrs = unsafe { std::mem::zeroed() };
        if unsafe { libc::isatty(file.as_raw_fd()) } != 1
            || unsafe { libc::tcgetattr(file.as_raw_fd(), &mut attrs) } != 0
        {
            return Err(ERROR.into());
        }
        let mut guard = Self {
            file,
            attrs,
            restored: false,
        };
        let mut hidden = guard.attrs;
        hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
        if unsafe { libc::tcsetattr(guard.file.as_raw_fd(), libc::TCSAFLUSH, &hidden) } != 0 {
            return Err(ERROR.into());
        }
        // Fixed prompt after echo is disabled; never print PIN or module errors.
        guard.file.write_all(b"PKCS11 PIN: ")?;
        Ok(guard)
    }
    fn restore(&mut self) -> Result<()> {
        if self.restored {
            return Ok(());
        }
        if unsafe { libc::tcsetattr(self.file.as_raw_fd(), libc::TCSAFLUSH, &self.attrs) } != 0 {
            return Err(ERROR.into());
        }
        self.restored = true;
        Ok(())
    }
}
impl Drop for Tty {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}
fn read_pin(deadline: &Deadline) -> Result<Zeroizing<String>> {
    deadline.check()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/dev/tty")?;
    read_pin_from(file, deadline)
}
fn read_pin_from(file: File, deadline: &Deadline) -> Result<Zeroizing<String>> {
    deadline.check()?;
    let mut tty = Tty::hide(file)?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(128));
    let result = (|| -> Result<Zeroizing<String>> {
        loop {
            deadline.poll(tty.file.as_raw_fd(), libc::POLLIN)?;
            let mut byte = Zeroizing::new([0u8; 1]);
            match tty.file.read(&mut *byte) {
                Ok(1) if byte[0] == b'\n' => break,
                Ok(1) if bytes.len() < 128 => bytes.push(byte[0]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                    ) =>
                {
                    continue;
                }
                _ => return Err(ERROR.into()),
            }
        }
        if bytes.is_empty() || std::str::from_utf8(&bytes).is_err() || bytes.contains(&0) {
            return Err(ERROR.into());
        }
        let text = String::from_utf8(std::mem::take(&mut *bytes)).map_err(|_| ERROR)?;
        deadline.check()?;
        Ok(Zeroizing::new(text))
    })();
    tty.restore()?;
    result
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: Profile,
    pin: Zeroizing<String>,
    message: String,
    expires_at_ms: i64,
}

struct ChildGuard {
    child: Child,
    reaped: bool,
    deadline: Deadline,
}
impl ChildGuard {
    fn reap(&mut self, deadline: &Deadline) -> Result<()> {
        loop {
            deadline.check()?;
            if let Some(status) = self.child.try_wait()? {
                self.reaped = true;
                return if status.success() {
                    Ok(())
                } else {
                    Err(ERROR.into())
                };
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
impl ChildGuard {
    fn terminate(&mut self) {
        #[cfg(test)]
        if TEST_KILL_ACK_PENDING.with(|pending| pending.get()) {
            return;
        }
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        if !self.reaped {
            let _ = self.child.kill();
        }
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
        if self.reaped {
            return;
        }
        loop {
            // Nonblocking reaping only. A driver-blocked child remains uncertain;
            // neither cancellation nor cleanup gets a fresh time budget.
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = true;
                    return;
                }
                Err(_) => return,
                Ok(None) => (),
            }
            if Instant::now() >= self.deadline.until
                || now().map_or(true, |time| {
                    time.as_unix_ms() >= self.deadline.expires_at_ms
                })
            {
                return;
            }
            std::thread::sleep(
                Duration::from_millis(5).min(
                    self.deadline
                        .until
                        .saturating_duration_since(Instant::now()),
                ),
            );
        }
    }
}

fn send(stream: &mut UnixStream, bytes: &[u8], deadline: &Deadline) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        deadline.poll(stream.as_raw_fd(), libc::POLLOUT)?;
        let sent = unsafe {
            libc::send(
                stream.as_raw_fd(),
                bytes[offset..].as_ptr() as *const _,
                bytes.len() - offset,
                libc::MSG_NOSIGNAL,
            )
        };
        let result = if sent < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(sent as usize)
        };
        match result {
            Ok(0) => return Err(ERROR.into()),
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(ERROR.into()),
        }
    }
    Ok(())
}
fn receive(stream: &mut UnixStream, bytes: &mut [u8], deadline: &Deadline) -> Result<()> {
    let mut offset = 0;
    while offset < bytes.len() {
        deadline.poll(stream.as_raw_fd(), libc::POLLIN)?;
        match stream.read(&mut bytes[offset..]) {
            Ok(0) => return Err(ERROR.into()),
            Ok(n) => offset += n,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(ERROR.into()),
        }
    }
    Ok(())
}
fn self_exec(frame: &mut [u8], deadline: &Deadline) -> Result<Vec<u8>> {
    deadline.check()?;
    let (mut parent, child_channel) = UnixStream::pair()?;
    parent.set_nonblocking(true)?;
    child_channel.set_nonblocking(true)?;
    let inherited = child_channel.as_raw_fd();
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args([CHILD_MODE, "3"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .env_clear();
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0
                || libc::dup2(inherited, 3) < 0
                || libc::fcntl(3, libc::F_SETFD, 0) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut guard = ChildGuard {
        child: command.spawn()?,
        reaped: false,
        deadline: deadline.clone(),
    };
    drop(child_channel);
    send(&mut parent, &(frame.len() as u32).to_be_bytes(), deadline)?;
    send(&mut parent, frame, deadline)?;
    response(&mut parent, &mut guard, deadline)
}
fn response(
    parent: &mut UnixStream,
    guard: &mut ChildGuard,
    deadline: &Deadline,
) -> Result<Vec<u8>> {
    let mut response = [0u8; 65];
    receive(parent, &mut response[..1], deadline)?;
    if response[0] != 1 {
        return Err(ERROR.into());
    }
    receive(parent, &mut response[1..], deadline)?;
    // The child must finish successfully; extra bytes cannot be a success frame.
    let mut extra = [0u8; 1];
    deadline.poll(parent.as_raw_fd(), libc::POLLIN)?;
    if parent.read(&mut extra)? != 0 {
        return Err(ERROR.into());
    }
    guard.reap(deadline)?;
    Ok(response[1..].to_vec())
}

fn parent_identity(channel: &UnixStream) -> Result<()> {
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(ERROR.into());
    }
    #[cfg(target_os = "linux")]
    {
        let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        if unsafe {
            libc::getsockopt(
                channel.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                &mut credentials as *mut _ as *mut _,
                &mut len,
            )
        } != 0
            || credentials.pid != parent
            || credentials.uid != unsafe { libc::geteuid() }
        {
            return Err(ERROR.into());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let mut pid: libc::pid_t = 0;
        let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
        let (mut uid, mut gid) = (0, 0);
        if unsafe {
            libc::getsockopt(
                channel.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERPID,
                &mut pid as *mut _ as *mut _,
                &mut len,
            )
        } != 0
            || unsafe { libc::getpeereid(channel.as_raw_fd(), &mut uid, &mut gid) } != 0
            || pid != parent
            || uid != unsafe { libc::geteuid() }
        {
            return Err(ERROR.into());
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = channel;
        return Err(ERROR.into());
    }
    #[cfg(target_os = "linux")]
    let parent_path = PathBuf::from(format!("/proc/{parent}/exe"));
    #[cfg(target_os = "macos")]
    let parent_path = {
        let mut bytes = [0u8; 4096];
        let n =
            unsafe { libc::proc_pidpath(parent, bytes.as_mut_ptr() as *mut _, bytes.len() as u32) };
        if n <= 0 {
            return Err(ERROR.into());
        }
        let end = bytes.iter().position(|byte| *byte == 0).ok_or(ERROR)?;
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(&bytes[..end]))
    };
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        let ours = std::fs::metadata(std::env::current_exe()?)?;
        let theirs = std::fs::metadata(parent_path)?;
        if (ours.dev(), ours.ino()) != (theirs.dev(), theirs.ino()) {
            return Err(ERROR.into());
        }
    }
    Ok(())
}

pub(super) fn internal_child(args: &[String]) -> bool {
    if args.first().is_none_or(|arg| arg != CHILD_MODE) {
        return false;
    }
    let result = (|| -> Result<()> {
        if args != [CHILD_MODE, "3"] {
            return Err(ERROR.into());
        }
        // An arbitrary public invocation cannot supply a PIN: require the private socket
        // from the current parent, whose actual executable is this same signer.
        let mut info = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(3, &mut info) } != 0
            || info.st_mode & libc::S_IFMT != libc::S_IFSOCK
        {
            return Err(ERROR.into());
        }
        let mut channel = unsafe { UnixStream::from_raw_fd(3) };
        // Only this self-exec inherits the channel. Native helpers must not inherit it.
        if unsafe { libc::fcntl(channel.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
            return Err(ERROR.into());
        }
        parent_identity(&channel)?;
        channel.set_nonblocking(true)?;
        let initial = Deadline::new(now()?.as_unix_ms().checked_add(10000).ok_or(ERROR)?)?;
        let mut size = [0u8; 4];
        receive(&mut channel, &mut size, &initial)?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > FRAME_LIMIT {
            return Err(ERROR.into());
        }
        let mut frame = Zeroizing::new(vec![0u8; size]);
        receive(&mut channel, &mut frame, &initial)?;
        let input: Input = serde_json::from_slice(&frame)?;
        input.profile.validate()?;
        if input.pin.is_empty() || input.pin.len() > 128 || input.pin.as_bytes().contains(&0) {
            return Err(ERROR.into());
        }
        let message = BASE64URL_NOPAD.decode(input.message.as_bytes())?;
        if message.len() > MESSAGE_LIMIT || !message.starts_with(b"RKAPPROVAL\0\x01") {
            return Err(ERROR.into());
        }
        let deadline = Deadline::new(input.expires_at_ms)?;
        let signature = hardware_sign(&input.profile, input.pin, &message, &deadline)?;
        deadline.check()?;
        let mut output = [0u8; 65];
        output[0] = 1;
        output[1..].copy_from_slice(&signature);
        send(&mut channel, &output, &deadline)?;
        Ok(())
    })();
    // No SDK errors, child output or profile text reaches stdout/stderr.
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}

fn restrictions(attributes: &[Attribute]) -> Result<()> {
    let expected = [
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::AlwaysSensitive(true),
        Attribute::NeverExtractable(true),
        Attribute::Extractable(false),
        Attribute::AlwaysAuthenticate(false),
        Attribute::EcParams(CURVE.to_vec()),
    ];
    if attributes.len() != expected.len()
        || expected
            .iter()
            .any(|wanted| attributes.iter().filter(|value| *value == wanted).count() != 1)
    {
        return Err(ERROR.into());
    }
    Ok(())
}
fn select_one(
    objects: impl Iterator<Item = cryptoki::error::Result<cryptoki::object::ObjectHandle>>,
) -> Result<cryptoki::object::ObjectHandle> {
    let mut found = objects
        .take(2)
        .collect::<cryptoki::error::Result<Vec<_>>>()?;
    if found.len() != 1 {
        return Err(ERROR.into());
    }
    Ok(found.remove(0))
}
fn hardware_sign(
    profile: &Profile,
    mut pin: Zeroizing<String>,
    message: &[u8],
    deadline: &Deadline,
) -> Result<Vec<u8>> {
    deadline.check()?;
    if library_hash(&profile.library_path, deadline)? != profile.library_sha256 {
        return Err(ERROR.into());
    }
    deadline.check()?;
    let module = Pkcs11::new(&profile.library_path)?;
    module.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK))?;
    let version = module.get_library_info()?.library_version();
    if version.major() != profile.library_version.major
        || version.minor() != profile.library_version.minor
    {
        return Err(ERROR.into());
    }
    let slot = Slot::try_from(profile.slot_id)?;
    let token = module.get_token_info(slot)?;
    if token.serial_number() != profile.token_serial || token.protected_authentication_path() {
        return Err(ERROR.into());
    }
    let session = module.open_ro_session(slot)?;
    let auth = AuthPin::new(std::mem::take(&mut *pin).into_boxed_str());
    session.login(UserType::User, Some(&auth))?;
    drop(auth);
    deadline.check()?;
    let id = HEXLOWER.decode(profile.key_id.as_bytes())?;
    let template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::KeyType(KeyType::EC_EDWARDS),
        Attribute::Id(id),
    ];
    let object = select_one(
        session.iter_objects_with_cache_size(&template, NonZeroUsize::new(2).ok_or(ERROR)?)?,
    )?;
    let attributes = session.get_attributes(
        object,
        &[
            AttributeType::Token,
            AttributeType::Private,
            AttributeType::Sign,
            AttributeType::Sensitive,
            AttributeType::AlwaysSensitive,
            AttributeType::NeverExtractable,
            AttributeType::Extractable,
            AttributeType::AlwaysAuthenticate,
            AttributeType::EcParams,
        ],
    )?;
    restrictions(&attributes)?;
    deadline.check()?;
    let signature = session.sign(
        &Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519)),
        object,
        message,
    )?;
    verify_signature(
        message,
        &HEXLOWER.decode(profile.public_key.as_bytes())?,
        &signature,
    )?;
    deadline.check()?;
    session.logout()?;
    drop(session);
    module.finalize()?;
    deadline.check()?;
    Ok(signature)
}

#[cfg(test)]
type SignHook = Box<dyn FnMut(&[u8], i64) -> Result<Vec<u8>>>;
#[cfg(test)]
thread_local! { static TEST_SIGN: std::cell::RefCell<Option<SignHook>> = std::cell::RefCell::new(None); }
#[cfg(test)]
thread_local! {
    static TEST_RESTORE_WINDOW: std::cell::RefCell<Option<Box<dyn FnMut()>>> = std::cell::RefCell::new(None);
    static TEST_KILL_ACK_PENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
#[cfg(test)]
#[path = "pkcs11_tests.rs"]
mod tests;
