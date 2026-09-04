//! Closed `linux-netns-v1` launch plan. No filesystem or process IO.

use crate::error::DomainError;

pub const LINUX_NETNS_V1: &str = "linux-netns-v1";
pub const CHILD_PATH: &str = "/usr/bin:/bin";
pub const CHILD_HOME: &str = "/tmp";
pub const CHILD_LANG: &str = "C";
pub const CAPABILITY_ENV: &str = "REKEY_CAPABILITY";
pub const CAPABILITY_STDIN_MAX_BYTES: usize = 128;
pub const BWRAP_CANDIDATES: &[&str] = &["/usr/bin/bwrap", "/bin/bwrap"];

fn invalid(msg: &str) -> DomainError {
    DomainError::InvalidLaunchPlan(msg.to_owned())
}

fn absolute_lexical<'a>(path: &'a str, what: &str) -> Result<&'a str, DomainError> {
    if !path.starts_with('/') || path.len() == 1 {
        return Err(invalid(&format!("{what} must be an absolute path")));
    }
    if path.as_bytes().contains(&0) {
        return Err(invalid(&format!("{what} must not contain NUL")));
    }
    if path.ends_with('/') {
        return Err(invalid(&format!("{what} must not have a trailing slash")));
    }
    for component in path[1..].split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(invalid(&format!(
                "{what} must not contain empty, '.', or '..' components"
            )));
        }
    }
    Ok(path)
}

fn is_lexical_descendant(parent: &str, child: &str) -> bool {
    child == parent
        || child.starts_with(parent) && child.as_bytes().get(parent.len()) == Some(&b'/')
}

/// Capability tokens are bearer material: visible ASCII, no space, bounded.
pub fn validate_capability_token(raw: &str) -> Result<(), DomainError> {
    if raw.is_empty() || raw.len() > CAPABILITY_STDIN_MAX_BYTES {
        return Err(invalid(
            "capability must be 1 through 128 visible ASCII bytes",
        ));
    }
    if !raw.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(invalid(
            "capability must be 1 through 128 visible ASCII bytes",
        ));
    }
    Ok(())
}

pub fn validate_command_argv(argv: &[&str]) -> Result<(), DomainError> {
    if argv.is_empty() {
        return Err(invalid("command must not be empty"));
    }
    let command = absolute_lexical(argv[0], "command")?;
    if BWRAP_CANDIDATES.contains(&command) || command.ends_with("/bwrap") {
        return Err(invalid("command must not be bubblewrap"));
    }
    for (index, arg) in argv.iter().enumerate() {
        if arg.is_empty() {
            return Err(invalid("command arguments must not be empty"));
        }
        if arg.as_bytes().contains(&0) {
            return Err(invalid("command arguments must not contain NUL"));
        }
        if index == 0 {
            continue;
        }
        if *arg == "--share-net" {
            return Err(invalid("command must not request shared networking"));
        }
    }
    Ok(())
}

pub fn validate_disjoint_paths(state_dir: &str, agent_socket: &str) -> Result<(), DomainError> {
    let state_dir = absolute_lexical(state_dir, "state directory")?;
    let agent_socket = absolute_lexical(agent_socket, "agent socket")?;
    if is_lexical_descendant(state_dir, agent_socket)
        || is_lexical_descendant(agent_socket, state_dir)
    {
        return Err(invalid(
            "agent socket must be disjoint from the state directory",
        ));
    }
    if let Some(parent) = agent_socket.rsplit_once('/').map(|(parent, _)| parent)
        && !parent.is_empty()
        && (is_lexical_descendant(state_dir, parent) || is_lexical_descendant(parent, state_dir))
    {
        return Err(invalid(
            "agent socket must be disjoint from the state directory",
        ));
    }
    Ok(())
}

pub fn validate_launch_plan(
    state_dir: &str,
    agent_socket: &str,
    argv: &[&str],
) -> Result<(), DomainError> {
    validate_disjoint_paths(state_dir, agent_socket)?;
    validate_command_argv(argv)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disjoint_paths_accept_isolated_runtime() {
        validate_disjoint_paths("/var/lib/rekey/state", "/run/rekey-agent/agent.sock").unwrap();
        validate_disjoint_paths("/tmp/rk/s", "/tmp/rk/agent/agent.sock").unwrap();
    }

    #[test]
    fn overlapping_default_g1_socket_is_rejected() {
        let error =
            validate_disjoint_paths("/tmp/rk/s", "/tmp/rk/s/runtime/agent.sock").unwrap_err();
        assert!(matches!(error, DomainError::InvalidLaunchPlan(_)));
    }

    #[test]
    fn relative_and_dot_paths_are_rejected() {
        assert!(validate_disjoint_paths("state", "/run/agent.sock").is_err());
        assert!(validate_disjoint_paths("/tmp/rk/s/..", "/run/agent.sock").is_err());
        assert!(validate_command_argv(&["python3"]).is_err());
        assert!(validate_command_argv(&["/usr/bin/../bin/python3"]).is_err());
    }

    #[test]
    fn bwrap_and_share_net_are_rejected() {
        assert!(validate_command_argv(&["/usr/bin/bwrap", "--unshare-net"]).is_err());
        assert!(validate_command_argv(&["/usr/bin/python3", "--share-net"]).is_err());
    }

    #[test]
    fn capability_charset_is_closed() {
        validate_capability_token("abcDEF012-_").unwrap();
        assert!(validate_capability_token("").is_err());
        assert!(validate_capability_token("has space").is_err());
        assert!(validate_capability_token("newline\n").is_err());
        assert!(validate_capability_token(&"a".repeat(129)).is_err());
    }
}
