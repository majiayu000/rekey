//! Pre-commit hook chaining for `rekey connect --with-hooks` and `rekey hooks`.
//! Hooks run with a stub `rekey` that records the scan; no vault or broker.
mod connect_support;

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use connect_support::*;

/// Ends with `exit`, so a scan appended after it would never run.
const EXIT_HOOK: &str = "#!/bin/sh\n# existing operator hook\nprintf 'original %s %s\\n' \"${0##*/}\" \"$*\" >> \"$REKEY_TEST_LOG\"\nexit 0\n";
/// Ends with `exec`, like the hooks that hook managers generate.
const EXEC_HOOK: &str = "#!/usr/bin/env bash\nprintf 'original %s %s\\n' \"${0##*/}\" \"$*\" >> \"$REKEY_TEST_LOG\"\nexec true\n";
/// Not a shell script: shell lines added to it would be Python syntax errors.
const PYTHON_HOOK: &str = "#!/usr/bin/env python3\nimport os, sys\nwith open(os.environ['REKEY_TEST_LOG'], 'a') as log:\n    log.write('original %s %r %r\\n' % (os.path.basename(sys.argv[0]), sys.argv[1:], sys.stdin.read()))\n";

fn hook_path(f: &Fixture) -> PathBuf {
    f.project().join(".git/hooks/pre-commit")
}
fn chained_path(f: &Fixture) -> PathBuf {
    f.project().join(".git/hooks/pre-commit.rekey-chained")
}
fn mode(path: &Path) -> u32 {
    fs::metadata(path).unwrap().mode() & 0o777
}
fn existing_hook(f: &Fixture, text: &str, mode: u32) -> PathBuf {
    let path = f.write(".git/hooks/pre-commit", text.as_bytes());
    fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
    path
}
fn connect_with_hooks(f: &Fixture) -> Command {
    let mut command = f.command("claude-code");
    command.arg("--with-hooks");
    command
}
/// PATH whose `rekey` is a stub: it drains stdin, logs its arguments and exits
/// with $REKEY_TEST_SCAN_EXIT.
fn stub_path(f: &Fixture) -> String {
    let dir = f.root.join("stub");
    if !dir.exists() {
        fs::create_dir(&dir).unwrap();
        let stub = dir.join("rekey");
        fs::write(
            &stub,
            b"#!/bin/sh\ncat > /dev/null\nprintf 'scan %s\\n' \"$*\" >> \"$REKEY_TEST_LOG\"\nexit \"${REKEY_TEST_SCAN_EXIT:-0}\"\n",
        )
        .unwrap();
        fs::set_permissions(&stub, fs::Permissions::from_mode(0o700)).unwrap();
    }
    format!("{}:{}", dir.display(), std::env::var("PATH").unwrap())
}
fn take_log(f: &Fixture) -> String {
    let path = f.root.join("hook.log");
    let text = fs::read_to_string(&path).unwrap_or_default();
    let _ = fs::remove_file(path);
    text
}
fn scanned(f: &Fixture) -> String {
    format!(
        "scan --state-dir {} scan --staged\n",
        f.root.join("vault").display()
    )
}
fn with_stub(f: &Fixture, command: &mut Command, scan_exit: u8) {
    command
        .current_dir(f.project())
        .env("PATH", stub_path(f))
        .env("REKEY_TEST_LOG", f.root.join("hook.log"))
        .env("REKEY_TEST_SCAN_EXIT", scan_exit.to_string());
}
/// A real `git commit` of one staged change, so Git itself invokes the hook.
fn commit(f: &Fixture, scan_exit: u8) -> Output {
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(f.project().join("change.txt"))
        .and_then(|mut file| writeln!(file, "{scan_exit}"))
        .unwrap();
    assert!(f.git(&["add", "change.txt"]).status.success());
    let mut command = Command::new("git");
    command.args([
        "-c",
        "user.name=Rekey Test",
        "-c",
        "user.email=test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "test",
    ]);
    with_stub(f, &mut command, scan_exit);
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "true")
        .stdin(Stdio::null())
        .output()
        .unwrap()
}
/// Run the installed hook directly with explicit arguments and standard input.
fn run_hook(f: &Fixture, args: &[&str], input: &str, scan_exit: u8) -> Output {
    let mut command = Command::new(hook_path(f));
    command.args(args);
    with_stub(f, &mut command, scan_exit);
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // A hook that never reads its input may exit first; that is not a failure.
    let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
    child.wait_with_output().unwrap()
}

#[test]
fn shell_hooks_ending_in_exit_or_exec_run_the_scan_first_and_keep_their_name() {
    for original in [EXIT_HOOK, EXEC_HOOK] {
        let f = Fixture::new();
        f.git_init();
        let path = existing_hook(&f, original, 0o755);
        confirm(connect_with_hooks(&f));
        let (shebang, body) = original.split_once('\n').unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            format!(
                "{shebang}\n# rekey:begin\nrekey --state-dir '{}' scan --staged </dev/null || exit $?\n# rekey:end\n{body}",
                f.root.join("vault").display()
            )
        );
        assert_eq!(mode(&path), 0o755);
        assert!(!chained_path(&f).exists());
        let backup = siblings(&path, "backup");
        assert_eq!(fs::read_to_string(&backup[0]).unwrap(), original);
        // Git runs the scan before the original body, which still sees itself as pre-commit.
        let output = commit(&f, 0);
        assert!(output.status.success(), "{}", output_text(&output));
        assert_eq!(
            take_log(&f),
            format!("{}original pre-commit \n", scanned(&f))
        );
        // A finding blocks the commit before the original hook runs.
        let output = commit(&f, 3);
        assert!(!output.status.success());
        assert_eq!(take_log(&f), scanned(&f));
        // Reinstalling changes nothing.
        let output = connect_with_hooks(&f)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert!(
            output_text(&output).contains("Already configured; no files changed."),
            "{}",
            output_text(&output)
        );
    }
}

#[test]
fn non_shell_hook_is_chained_with_the_same_arguments_and_input() {
    let f = Fixture::new();
    f.git_init();
    let path = existing_hook(&f, PYTHON_HOOK, 0o755);
    let text = confirm(connect_with_hooks(&f));
    assert!(text.contains("pre-commit.rekey-chained"), "{text}");
    let chained = chained_path(&f);
    assert_eq!(fs::read_to_string(&chained).unwrap(), PYTHON_HOOK);
    assert_eq!(mode(&chained), 0o755);
    let wrapper = fs::read_to_string(&path).unwrap();
    assert!(
        wrapper.starts_with("#!/bin/sh\n# rekey:begin\n"),
        "{wrapper}"
    );
    assert_eq!(mode(&path), 0o700);
    let output = run_hook(&f, &["first", "second arg"], "staged input", 0);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        take_log(&f),
        format!(
            "{}original pre-commit.rekey-chained ['first', 'second arg'] 'staged input'\n",
            scanned(&f)
        )
    );
    let output = run_hook(&f, &["first"], "staged input", 5);
    assert_eq!(output.status.code(), Some(5), "{}", output_text(&output));
    assert_eq!(take_log(&f), scanned(&f));
    let output = commit(&f, 0);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(
        take_log(&f),
        format!("{}original pre-commit.rekey-chained [] ''\n", scanned(&f))
    );
}

#[test]
fn reinstall_is_idempotent_and_uninstall_restores_each_original_exactly() {
    for original in [None, Some(EXIT_HOOK), Some(EXEC_HOOK), Some(PYTHON_HOOK)] {
        let f = Fixture::new();
        f.git_init();
        let path = hook_path(&f);
        if let Some(original) = original {
            existing_hook(&f, original, 0o755);
        }
        let preview = f.hooks("install").arg("--print").output().unwrap();
        assert!(preview.status.success(), "{}", output_text(&preview));
        assert!(output_text(&preview).contains("# rekey:begin"));
        assert_eq!(fs::read_to_string(&path).ok().as_deref(), original);
        confirm(f.hooks("install"));
        let installed = fs::read(&path).unwrap();
        let output = f.hooks("install").stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success()
                && output_text(&output).contains("Already configured; no files changed."),
            "{}",
            output_text(&output)
        );
        // connect --with-hooks writes exactly the same hook.
        confirm(connect_with_hooks(&f));
        assert_eq!(fs::read(&path).unwrap(), installed);
        confirm(f.hooks("uninstall"));
        match original {
            Some(original) => {
                assert_eq!(fs::read_to_string(&path).unwrap(), original);
                assert_eq!(mode(&path), 0o755);
            }
            None => assert!(!path.exists()),
        }
        assert!(!chained_path(&f).exists());
        let output = f.hooks("uninstall").stdin(Stdio::null()).output().unwrap();
        assert!(
            output.status.success()
                && output_text(&output).contains("No Rekey pre-commit hook is installed"),
            "{}",
            output_text(&output)
        );
    }
}

#[test]
fn reinstall_moves_a_legacy_appended_block_ahead_of_the_original() {
    for original in [EXIT_HOOK, PYTHON_HOOK] {
        let f = Fixture::new();
        f.git_init();
        let legacy = format!(
            "{original}\n# rekey:begin\nrekey --state-dir '{}' scan --staged || exit $?\n# rekey:end\n",
            f.root.join("vault").display()
        );
        let path = existing_hook(&f, &legacy, 0o700);
        confirm(f.hooks("install"));
        let hook = fs::read_to_string(&path).unwrap();
        assert_eq!(hook.matches("# rekey:begin").count(), 1, "{hook}");
        if original == PYTHON_HOOK {
            assert_eq!(
                fs::read_to_string(chained_path(&f)).unwrap(),
                format!("{original}\n")
            );
        } else {
            assert!(hook.starts_with("#!/bin/sh\n# rekey:begin\n"), "{hook}");
        }
        let output = commit(&f, 0);
        assert!(output.status.success(), "{}", output_text(&output));
        let log = take_log(&f);
        assert!(
            log.starts_with(&scanned(&f)) && log.contains("original pre-commit"),
            "{log}"
        );
    }
}

#[test]
fn a_disabled_hook_stays_disabled_behind_the_wrapper() {
    let f = Fixture::new();
    f.git_init();
    let path = existing_hook(&f, EXIT_HOOK, 0o644);
    confirm(f.hooks("install"));
    assert_eq!(fs::read_to_string(chained_path(&f)).unwrap(), EXIT_HOOK);
    assert_eq!(mode(&chained_path(&f)), 0o644);
    // Git ignores a hook that is not executable; behind the wrapper it stays ignored.
    let output = commit(&f, 0);
    assert!(output.status.success(), "{}", output_text(&output));
    assert_eq!(take_log(&f), scanned(&f));
    confirm(f.hooks("uninstall"));
    assert_eq!(fs::read_to_string(&path).unwrap(), EXIT_HOOK);
    assert_eq!(mode(&path), 0o644);
}

#[test]
fn an_unrelated_chained_file_is_never_overwritten_or_resurrected() {
    let f = Fixture::new();
    f.git_init();
    let stale = b"#!/bin/sh\necho stale\n";
    let chained = f.write(".git/hooks/pre-commit.rekey-chained", stale);
    // Without a pre-commit hook, a new wrapper would start running the stale file.
    let output = connect_with_hooks(&f).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output_text(&output).contains("pre-commit.rekey-chained")
            && !output_text(&output).contains("Target:"),
        "{}",
        output_text(&output)
    );
    assert!(!hook_path(&f).exists());
    // A non-shell hook is never moved over a different chained file.
    let path = existing_hook(&f, PYTHON_HOOK, 0o755);
    let output = connect_with_hooks(&f).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(
        output_text(&output).contains("pre-commit.rekey-chained")
            && !output_text(&output).contains("Target:"),
        "{}",
        output_text(&output)
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), PYTHON_HOOK);
    assert_eq!(fs::read(&chained).unwrap(), stale);
}

#[test]
fn a_committable_hooks_directory_gets_the_local_path_warning() {
    let f = Fixture::new();
    f.git_init();
    fs::create_dir(f.project().join(".githooks")).unwrap();
    assert!(
        f.git(&["config", "core.hooksPath", ".githooks"])
            .status
            .success()
    );
    let output = f.hooks("install").arg("--print").output().unwrap();
    let text = output_text(&output);
    assert!(output.status.success(), "{text}");
    let (target, rest) = text.split_once("+++ after").unwrap();
    assert!(
        target.contains(&format!(
            "Target: {}",
            f.project().join(".githooks/pre-commit").display()
        )),
        "{text}"
    );
    assert!(rest.contains(LOCAL_PATH_WARNING), "{text}");
    assert!(!f.project().join(".githooks/pre-commit").exists());
}
