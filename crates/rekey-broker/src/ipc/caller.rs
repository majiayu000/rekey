//! Best-effort labels from kernel peer/process facts. Never an authorization identity.
use std::os::fd::AsRawFd;
use std::path::Path;

use tokio::net::UnixStream;

pub(crate) fn unix_caller(stream: &UnixStream) -> String {
    #[cfg(target_os = "macos")]
    let Some((pid, audit)) = peer_identity(stream) else {
        return "unknown".into();
    };
    #[cfg(target_os = "linux")]
    let Some(pid) = peer_pid(stream) else {
        return "unknown".into();
    };
    caller_from_processes(pid, process, |candidate| {
        #[cfg(target_os = "macos")]
        {
            candidate == pid && rekey_vault::generation_anchor::peer_has_own_team(audit)
        }
        #[cfg(target_os = "linux")]
        {
            let _ = candidate;
            true
        }
    })
}

fn caller_from_processes(
    mut pid: i32,
    mut inspect: impl FnMut(i32) -> Option<(String, i32)>,
    mut trusted_mcp: impl FnMut(i32) -> bool,
) -> String {
    let mut nearest = None;
    for _ in 0..32 {
        let Some((path, parent)) = inspect(pid) else {
            break;
        };
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        if nearest.is_none() {
            nearest = Some(name.to_owned());
        }
        // A copied or unsigned rekey-mcp cannot inherit an Agent label from
        // its parent on macOS. This label never grants extra authorization.
        if name == "rekey-mcp" && !trusted_mcp(pid) {
            return "script:rekey-mcp".into();
        }
        let known = match name {
            "claude" => Some("claude-code"),
            "codex" => Some("codex"),
            "Cursor" | "cursor" => Some("cursor"),
            "Code" => Some("vscode"),
            _ => None,
        };
        if let Some(label) = known {
            return label.into();
        }
        if parent <= 1 || parent == pid {
            break;
        }
        pid = parent;
    }
    nearest.map_or_else(|| "unknown".into(), |name| format!("script:{name}"))
}

#[cfg(target_os = "macos")]
fn peer_identity(stream: &UnixStream) -> Option<(i32, [u32; 8])> {
    let mut token = [0u32; 8];
    let mut size = std::mem::size_of_val(&token) as libc::socklen_t;
    // The audit token is obtained from the kernel, never request metadata.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut size,
        )
    };
    (rc == 0
        && size as usize == std::mem::size_of_val(&token)
        && token[5] > 0
        && token[5] <= i32::MAX as u32)
        .then_some((token[5] as i32, token))
}

#[cfg(target_os = "linux")]
fn peer_pid(stream: &UnixStream) -> Option<i32> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    (rc == 0 && size as usize == std::mem::size_of_val(&credentials) && credentials.pid > 0)
        .then_some(credentials.pid)
}

#[cfg(target_os = "macos")]
fn process(pid: i32) -> Option<(String, i32)> {
    let mut buffer = [0u8; 4096];
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if len <= 0 {
        return None;
    }
    let end = buffer.iter().position(|b| *b == 0).unwrap_or(len as usize);
    let path = std::str::from_utf8(&buffer[..end]).ok()?.to_owned();
    let mut info: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of_val(&info) as i32;
    let rc = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            size,
        )
    };
    (rc == size).then_some((path, info.pbi_ppid as i32))
}

#[cfg(target_os = "linux")]
fn process(pid: i32) -> Option<(String, i32)> {
    let path = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()?
        .to_str()?
        .to_owned();
    let status = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let parent = status
        .rsplit_once(')')?
        .1
        .split_whitespace()
        .nth(1)?
        .parse()
        .ok()?;
    Some((path, parent))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn processes(pid: i32) -> Option<(String, i32)> {
        match pid {
            7 => Some(("/synthetic/rekey-mcp".into(), 8)),
            8 => Some(("/synthetic/claude".into(), 1)),
            9 => Some(("/synthetic/script".into(), 7)),
            _ => None,
        }
    }

    #[test]
    fn untrusted_mcp_cannot_borrow_its_agent_parents_label() {
        let mut checked = Vec::new();
        assert_eq!(
            caller_from_processes(7, processes, |pid| {
                checked.push(pid);
                false
            }),
            "script:rekey-mcp"
        );
        assert_eq!(checked, vec![7]);
        assert_eq!(
            caller_from_processes(7, processes, |pid| pid == 7),
            "claude-code"
        );
    }

    #[test]
    fn an_audit_token_for_a_child_does_not_attest_an_mcp_ancestor() {
        assert_eq!(
            caller_from_processes(9, processes, |pid| pid == 9),
            "script:rekey-mcp"
        );
        // Linux keeps its existing best-effort process-chain attribution.
        assert_eq!(caller_from_processes(9, processes, |_| true), "claude-code");
        assert_eq!(caller_from_processes(10, processes, |_| true), "unknown");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn kernel_audit_token_is_captured_whole_and_cannot_be_supplied_by_metadata() {
        let (stream, _peer) = UnixStream::pair().unwrap();
        let (pid, token) = peer_identity(&stream).unwrap();
        assert_eq!(pid as u32, std::process::id());
        assert_eq!(token[5], std::process::id());
        assert!(!rekey_vault::generation_anchor::peer_has_own_team([0; 8]));
    }
}
