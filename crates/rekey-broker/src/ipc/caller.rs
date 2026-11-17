//! Best-effort labels from kernel peer/process facts. Never an authorization identity.
use std::os::fd::AsRawFd;
use std::path::Path;

use tokio::net::UnixStream;

mod known;
#[cfg(target_os = "macos")]
mod signing;
mod tcp;

pub(crate) use tcp::tcp_caller;

/// Rekey's own clients never name a `script:` caller; the label names the
/// program that ran them.
const REKEY_BINARIES: [&str; 2] = ["rekey", "rekey-mcp"];
const SCRIPT_LABEL_BYTES: usize = 128;

/// The Unix peer (CLI, MCP, SSH agent client) labelled from its process chain.
pub(crate) async fn unix_caller(stream: &UnixStream) -> String {
    #[cfg(target_os = "macos")]
    let Some((pid, audit)) = peer_identity(stream) else {
        return "unknown".into();
    };
    #[cfg(target_os = "linux")]
    let Some(pid) = peer_pid(stream) else {
        return "unknown".into();
    };
    // Signature and process-table queries block; keep them off the reactor.
    tokio::task::spawn_blocking(move || {
        process_caller(pid, |candidate| {
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
    })
    .await
    .unwrap_or_else(|_| "unknown".into())
}

fn process_caller(pid: i32, trusted_mcp: impl FnMut(i32) -> bool) -> String {
    caller_from_processes(pid, process, signed, trusted_mcp)
}

#[cfg(target_os = "macos")]
fn signed(pid: i32, path: &str) -> Option<&'static str> {
    signing::label(pid, path)
}

/// Linux has no code signature to consult; real paths decide.
#[cfg(target_os = "linux")]
fn signed(_pid: i32, _path: &str) -> Option<&'static str> {
    None
}

fn caller_from_processes(
    mut pid: i32,
    mut inspect: impl FnMut(i32) -> Option<(String, i32)>,
    mut signed: impl FnMut(i32, &str) -> Option<&'static str>,
    mut trusted_mcp: impl FnMut(i32) -> bool,
) -> String {
    let mut peer = None;
    let mut script = None;
    for _ in 0..32 {
        let Some((path, parent)) = inspect(pid) else {
            break;
        };
        let name = Path::new(&path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        // A copied or unsigned rekey-mcp cannot inherit an Agent label from
        // its parent on macOS. This label never grants extra authorization.
        if name == "rekey-mcp" && !trusted_mcp(pid) {
            return "script:rekey-mcp".into();
        }
        let own = REKEY_BINARIES.contains(&name);
        let known = if own {
            None
        } else {
            known::by_path(&path).or_else(|| signed(pid, &path))
        };
        if let Some(label) = known {
            return label.into();
        }
        peer.get_or_insert_with(|| name.to_owned());
        if !own && script.is_none() {
            script = Some(name.to_owned());
        }
        if parent <= 1 || parent == pid {
            break;
        }
        pid = parent;
    }
    script
        .or(peer)
        .map_or_else(|| "unknown".into(), |name| script_label(&name))
}

/// Audit contexts reject control characters and labels over 256 bytes.
fn script_label(name: &str) -> String {
    let mut label = String::from("script:");
    for character in name.chars() {
        if label.len() + character.len_utf8() > SCRIPT_LABEL_BYTES {
            break;
        }
        label.push(if character.is_control() {
            '_'
        } else {
            character
        });
    }
    label
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

/// SO_PEERCRED's PID, not a pidfd: PID reuse can only mislabel, and a label
/// is never an authorization identity.
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
mod tests;
