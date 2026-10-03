//! Fixed Profile launcher support, not a general mount or environment policy.
use std::collections::BTreeMap;
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::ffi::{CStr, OsStr};
#[cfg(target_os = "macos")]
use std::fs;
#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::mem::MaybeUninit;
use std::num::NonZeroU16;
#[cfg(target_os = "macos")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "macos")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "macos")]
use std::path::{Path, PathBuf};
#[cfg(target_os = "macos")]
use std::ptr;

use super::BrokerError;

pub(super) fn invalid(message: &str) -> BrokerError {
    rekey_domain::DomainError::InvalidLaunchPlan(message.to_owned()).into()
}

// Directory identity covers symlinks, case aliases and APFS firmlinks.
#[cfg(target_os = "macos")]
pub(super) fn contains(root: &Path, path: &Path) -> Result<bool, BrokerError> {
    let root = fs::metadata(root).map_err(BrokerError::Io)?;
    for ancestor in path.ancestors() {
        let entry = fs::metadata(ancestor).map_err(BrokerError::Io)?;
        if (root.dev(), root.ino()) == (entry.dev(), entry.ino()) {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(target_os = "macos")]
pub(super) fn overlaps(a: &Path, b: &Path) -> Result<bool, BrokerError> {
    Ok(contains(a, b)? || contains(b, a)?)
}

#[cfg(target_os = "macos")]
pub(super) fn user_home() -> io::Result<PathBuf> {
    let mut record = MaybeUninit::uninit();
    let mut result = ptr::null_mut();
    let mut buffer = vec![0u8; 64 * 1024];
    // SAFETY: the reentrant lookup writes only to these live buffers. Copy
    // pw_dir before freeing them; HOME is never an identity input.
    unsafe {
        let code = libc::getpwuid_r(
            libc::geteuid(),
            record.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        );
        if code != 0 {
            return Err(io::Error::from_raw_os_error(code));
        }
        if result.is_null() || (*result).pw_dir.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "cannot resolve launcher home",
            ));
        }
        Path::new(OsStr::from_bytes(
            CStr::from_ptr((*result).pw_dir).to_bytes(),
        ))
        .canonicalize()
    }
}

#[cfg(target_os = "macos")]
pub(super) fn check_stdio_fd(fd: libc::c_int) -> io::Result<()> {
    let null_device = fs::metadata("/dev/null")?;
    let mut st = MaybeUninit::uninit();
    // SAFETY: fstat initializes st on success; isatty only inspects this fd.
    let safe = unsafe {
        if libc::fstat(fd, st.as_mut_ptr()) != 0 {
            return Err(io::Error::last_os_error());
        }
        let st = st.assume_init();
        let kind = st.st_mode & libc::S_IFMT;
        kind == libc::S_IFREG
            || kind == libc::S_IFIFO
            || (kind == libc::S_IFCHR
                && (libc::isatty(fd) == 1 || st.st_rdev as u64 == null_device.rdev()))
    };
    if safe {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Agent stdio must be a file, pipe, TTY or null",
        ))
    }
}

/// This boundary accepts only the public routes the parent configured. It does
/// not trust ambient account keys: all retained SDK authentication is derived
/// from this run's capability. No provider route means no provider environment.
pub(super) fn sdk_environment(
    port: Option<NonZeroU16>,
    capability: &str,
) -> Vec<(OsString, OsString)> {
    let variables: BTreeMap<_, _> = rekey_domain::sandbox::PROFILE_CHILD_ENV
        .iter()
        .filter_map(|name| std::env::var_os(name).map(|value| (*name, value)))
        .collect();
    let mut env = Vec::new();
    for name in ["TERM", "COLORTERM"] {
        if let Some(value) = variables.get(name) {
            env.push((name.into(), value.clone()));
        }
    }
    let Some(port) = port else {
        return env;
    };
    for (base, suffix) in [("ANTHROPIC_BASE_URL", ""), ("OPENAI_BASE_URL", "/v1")] {
        let Some(value) = variables.get(base).and_then(|v| v.to_str()) else {
            continue;
        };
        if !valid_sdk_route(value, port, suffix) {
            continue;
        }
        env.push((base.into(), value.into()));
        let auth = if base == "ANTHROPIC_BASE_URL" {
            // The parent's adapter chooses bearer versus API key; only one is
            // copied, and its value always comes from this capability.
            if variables.contains_key("ANTHROPIC_AUTH_TOKEN")
                && !variables.contains_key("ANTHROPIC_API_KEY")
            {
                "ANTHROPIC_AUTH_TOKEN"
            } else {
                "ANTHROPIC_API_KEY"
            }
        } else {
            "OPENAI_API_KEY"
        };
        env.push((auth.into(), format!("rkc_{capability}").into()));
    }
    env
}

fn valid_sdk_route(value: &str, port: NonZeroU16, suffix: &str) -> bool {
    let prefix = format!("http://127.0.0.1:{port}/p/");
    let Some(slug) = value
        .strip_prefix(&prefix)
        .and_then(|s| s.strip_suffix(suffix))
    else {
        return false;
    };
    (1..=64).contains(&slug.len())
        && slug.as_bytes()[0].is_ascii_alphanumeric()
        && slug.as_bytes()[slug.len() - 1].is_ascii_alphanumeric()
        && slug
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

#[cfg(target_os = "macos")]
pub(super) fn private_environment(env: &mut Vec<(OsString, OsString)>, scratch: &Path) {
    env.retain(|(key, _)| key != "HOME" && key != "TMPDIR");
    for name in ["HOME", "TMPDIR"] {
        env.push((name.into(), scratch.as_os_str().to_owned()));
    }
    for (name, leaf) in [
        ("CODEX_HOME", "codex"),
        ("CLAUDE_CONFIG_DIR", "claude"),
        ("CLAUDE_CODE_TMPDIR", "claude-tmp"),
    ] {
        env.push((name.into(), scratch.join(leaf).into_os_string()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sdk_routes_are_exact_loopback_paths() {
        let port = NonZeroU16::new(12345).unwrap();
        assert!(valid_sdk_route("http://127.0.0.1:12345/p/a-1", port, ""));
        assert!(valid_sdk_route(
            "http://127.0.0.1:12345/p/a_2/v1",
            port,
            "/v1"
        ));
        for value in [
            "http://localhost:12345/p/a",
            "http://127.0.0.1:12346/p/a",
            "http://127.0.0.1:12345/p/../b",
            "http://127.0.0.1:12345/p/%61",
            "http://127.0.0.1:12345/p/a?q=x",
            "http://127.0.0.1:12345/p/",
        ] {
            assert!(!valid_sdk_route(value, port, ""));
        }
    }
}
