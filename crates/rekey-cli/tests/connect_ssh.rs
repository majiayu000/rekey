//! `rekey connect --with-ssh` against an isolated HOME. `ssh -G` evaluates the
//! written configuration exactly as OpenSSH would, without connecting anywhere.
mod connect_support;

use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::Path;
use std::process::{Command, Stdio};

use connect_support::*;

fn with_ssh(f: &Fixture, hosts: &[&str]) -> Command {
    let mut command = f.command("codex");
    command.arg("--with-ssh");
    for host in hosts {
        command.args(["--ssh-host", host]);
    }
    command
}
/// The settings OpenSSH resolves for `host` that a misplaced block could capture.
fn resolved(config: &Path, host: &str) -> BTreeSet<String> {
    let output = Command::new("ssh")
        .arg("-G")
        .arg("-F")
        .arg(config)
        .arg(host)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success(), "{}", output_text(&output));
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| {
            ["identityagent ", "identityfile ", "user ", "forwardagent "]
                .iter()
                .any(|key| line.starts_with(key))
        })
        .map(str::to_owned)
        .collect()
}

#[test]
fn with_ssh_scopes_identity_agent_to_the_selected_hosts_only() {
    let f = Fixture::new();
    let config = f.home().join(".ssh/config");
    fs::create_dir(config.parent().unwrap()).unwrap();
    let included = f.root.join("included.conf");
    fs::write(&included, "User included-user\n").unwrap();
    // Global directives at the top of the file: Include, IdentityFile and friends.
    let original = format!(
        "Include {}\nIdentityFile {}\nForwardAgent yes\n\nHost example.org\n    User example-user\n",
        included.display(),
        f.root.join("id_global").display()
    );
    fs::write(&config, &original).unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let hosts = ["github.com", "gitlab.com", "other.example", "example.org"];
    let before: Vec<_> = hosts.iter().map(|host| resolved(&config, host)).collect();

    let output = with_ssh(&f, &["github.com"])
        .arg("--print")
        .output()
        .unwrap();
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    assert!(
        text.contains(&format!("Target: {}", config.display())),
        "{text}"
    );
    assert!(text.contains("<existing SSH configuration retained outside Rekey markers>"));
    assert!(text.contains("+ Host github.com") && text.contains("+ Match all"));
    assert!(
        !text.contains("included"),
        "existing SSH settings stay hidden"
    );
    assert_eq!(fs::read_to_string(&config).unwrap(), original);

    confirm(with_ssh(&f, &["github.com"]));
    let socket = f.root.join("vault/ssh-agent.sock");
    let agent = format!("identityagent {}", socket.display());
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        format!(
            "# rekey:begin\nHost github.com\n    IdentityAgent \"{}\"\nMatch all\n# rekey:end\n{original}",
            socket.display()
        )
    );
    assert_eq!(fs::metadata(&config).unwrap().mode() & 0o777, 0o600);
    let backups = siblings(&config, "backup");
    assert_eq!(backups.len(), 1);
    assert_eq!(fs::read_to_string(&backups[0]).unwrap(), original);
    assert_eq!(fs::metadata(&backups[0]).unwrap().mode() & 0o777, 0o600);
    // Only github.com changes, and only by IdentityAgent.
    for (host, before) in hosts.iter().zip(&before) {
        let mut expected = before.clone();
        if *host == "github.com" {
            expected.insert(agent.clone());
        }
        assert_eq!(resolved(&config, host), expected, "{host}");
    }

    // A new host list replaces the marked block; the rest stays byte-for-byte.
    confirm(with_ssh(&f, &["gitlab.com", "github.com"]));
    let text = fs::read_to_string(&config).unwrap();
    assert_eq!(text.matches("# rekey:begin").count(), 1);
    assert!(text.starts_with("# rekey:begin\nHost gitlab.com github.com\n"));
    assert!(text.ends_with(&format!("# rekey:end\n{original}")));
    for (host, before) in hosts.iter().zip(&before) {
        let mut expected = before.clone();
        if host.starts_with("git") {
            expected.insert(agent.clone());
        }
        assert_eq!(resolved(&config, host), expected, "{host}");
    }
    let output = with_ssh(&f, &["gitlab.com", "github.com"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        output_text(&output).contains("Already configured; no files changed."),
        "{}",
        output_text(&output)
    );
}

#[test]
fn with_ssh_creates_a_private_config_when_none_exists() {
    let f = Fixture::new();
    confirm(with_ssh(&f, &["github.com"]));
    let config = f.home().join(".ssh/config");
    assert_eq!(
        fs::metadata(config.parent().unwrap()).unwrap().mode() & 0o777,
        0o700
    );
    assert_eq!(fs::metadata(&config).unwrap().mode() & 0o777, 0o600);
    assert!(siblings(&config, "backup").is_empty());
    let agent = format!(
        "identityagent {}",
        f.root.join("vault/ssh-agent.sock").display()
    );
    assert!(resolved(&config, "github.com").contains(&agent));
    assert!(!resolved(&config, "other.example").contains(&agent));
}

#[test]
fn with_ssh_refuses_patterns_and_writes_nothing() {
    let f = Fixture::new();
    for host in [
        "*",
        "*.example.com",
        "github.?om",
        "!github.com",
        "github.com,gitlab.com",
        "git hub.com",
        "",
    ] {
        let output = with_ssh(&f, &["github.com", host]).output().unwrap();
        let text = output_text(&output);
        assert_eq!(output.status.code(), Some(2), "{host:?}: {text}");
        assert!(
            text.contains("concrete hostname") && !text.contains("Target:"),
            "{host:?}: {text}"
        );
    }
    // --with-ssh needs a host, and a host needs --with-ssh.
    for args in [&["--with-ssh"][..], &["--ssh-host", "github.com"]] {
        let output = f.command("codex").args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
    }
    assert!(!f.home().join(".ssh").exists());
    assert_eq!(fs::read_dir(f.project()).unwrap().count(), 0);
}
