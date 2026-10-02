//! Pinned payload guard; all termination uses cgroup.kill, never PID snapshots.
use super::{BrokerError, denied, linux_cgroup as cgroup};
use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use tokio::io::unix::AsyncFd;

pub(super) struct KillPluginTree {
    pub(super) payload: cgroup::Payload,
    pub(super) ack: File,
    pub(super) _lifetime: File,
    pub(super) end: i64,
    removed: bool,
}
impl KillPluginTree {
    pub(super) fn prepare(end: i64) -> io::Result<(Self, File, File)> {
        let payload = cgroup::prepare(end)?;
        let pipes = (|| {
            let (ack, ready) = cgroup::ack_socket()?;
            let (guardian_lifetime, lifetime) = cgroup::pipe()?;
            Ok((ack, ready, guardian_lifetime, lifetime))
        })();
        match pipes {
            Ok((ack, ready, guardian_lifetime, lifetime)) => Ok((
                Self {
                    payload,
                    ack,
                    _lifetime: lifetime,
                    end,
                    removed: false,
                },
                ready,
                guardian_lifetime,
            )),
            Err(error) => {
                let _ = cgroup::remove(payload.root.as_raw_fd(), &payload.name);
                Err(error)
            }
        }
    }
    pub(super) fn check_guardian(&self) -> io::Result<()> {
        let mut fd = libc::pollfd {
            fd: self.ack.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        loop {
            cgroup::budget(self.end)?;
            if unsafe { libc::poll(&mut fd, 1, 0) } >= 0 {
                break;
            }
            let error = io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::EINTR) {
                return Err(error);
            }
        }
        if fd.revents != 0 {
            Err(io::Error::other("plugin guardian lost"))
        } else {
            Ok(())
        }
    }
    pub(super) async fn guardian_lost(&self) -> BrokerError {
        let file = match self.ack.try_clone().and_then(AsyncFd::new) {
            Ok(file) => file,
            Err(error) => return BrokerError::Io(error),
        };
        match file.readable().await {
            Ok(_) => denied("plugin-spawn"),
            Err(error) => BrokerError::Io(error),
        }
    }
    pub(super) async fn finish(&mut self, end: i64) -> Result<(), BrokerError> {
        self.check_guardian().map_err(super::linux::launch_error)?;
        cgroup::write_fd(self.payload.kill.as_raw_fd(), b"1").map_err(BrokerError::Io)?;
        loop {
            cgroup::budget(end).map_err(super::linux::launch_error)?;
            self.check_guardian().map_err(super::linux::launch_error)?;
            if cgroup::empty(self.payload.events.as_raw_fd()).map_err(BrokerError::Io)? {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        cgroup::remove(self.payload.root.as_raw_fd(), &self.payload.name)
            .map_err(BrokerError::Io)?;
        self.removed = true;
        self.check_guardian().map_err(super::linux::launch_error)?;
        Ok(())
    }
}
impl Drop for KillPluginTree {
    fn drop(&mut self) {
        if !self.removed {
            // No wait in Drop. Closing lifetime transfers drain/deletion to the
            // already execed guardian, including cancellation and Broker death.
            // One best-effort write, no EINTR retry/wait in cancellation Drop.
            unsafe {
                libc::lseek(self.payload.kill.as_raw_fd(), 0, libc::SEEK_SET);
                libc::write(self.payload.kill.as_raw_fd(), b"1".as_ptr().cast(), 1);
            }
            // Before spawn (or failed arming), no guardian may exist. Remove an
            // already empty leaf without waiting; retain a populated leaf for
            // the guardian. Read failure is never treated as empty.
            if cgroup::empty(self.payload.events.as_raw_fd()).is_ok_and(|empty| empty) {
                let _ = cgroup::remove(self.payload.root.as_raw_fd(), &self.payload.name);
            }
        }
    }
}
