use super::*;
use std::os::fd::AsRawFd;
use std::process::{Command as StdCommand, Stdio};
use std::sync::OnceLock;
use std::time::Duration;

fn probe() -> &'static Path {
    static PROBE: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &PROBE
        .get_or_init(|| {
            let directory = tempfile::tempdir().unwrap();
            let source = directory.path().join("probe.c");
            let artifact = directory.path().join("probe");
            fs::write(&source, include_str!("linux_probe.c")).unwrap();
            let output = StdCommand::new("/usr/bin/cc")
                .args(["-O0", "-Wall", "-Wextra", "-Werror", "-pthread"])
                .arg(source)
                .arg("-o")
                .arg(&artifact)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            (directory, artifact)
        })
        .1
}

fn control(input: &str) -> String {
    let output = StdCommand::new(probe()).arg(input).output().unwrap();
    assert!(output.status.success(), "control {input}: {output:?}");
    String::from_utf8(output.stdout).unwrap()
}

async fn sandbox(input: &str) -> String {
    String::from_utf8(
        run(
            probe(),
            None,
            input.as_bytes(),
            Instant::now() + Duration::from_secs(4),
        )
        .await
        .unwrap_or_else(|error| panic!("payload must run successfully for {input}: {error:?}")),
    )
    .unwrap()
}

#[tokio::test]
async fn packaged_artifact_uses_real_linux_backend_for_both_operations() {
    let executable = std::env::current_exe().unwrap();
    let artifact = executable
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("rekey-github-create-issue");
    for (operation, body) in [
        (
            IssueOperation::CreateIssue,
            br#"{"title":"linux"}"#.as_slice(),
        ),
        (IssueOperation::CreateIssueComment, br#"{"body":"linux"}"#),
    ] {
        assert_eq!(
            normalize_with_artifact(
                &artifact,
                None,
                operation,
                body,
                Instant::now() + Duration::from_secs(4)
            )
            .await
            .unwrap(),
            body
        );
    }
    assert_eq!(
        sandbox("ok").await,
        "OK\n",
        "native C startup must also succeed"
    );
}

#[tokio::test]
async fn native_files_network_and_readonly_root_with_successful_controls() {
    let directory = tempfile::tempdir().unwrap();
    let secret = directory.path().join("private");
    fs::write(&secret, b"host-canary").unwrap();
    let socket = directory.path().join("socket");
    let _uds = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for input in [
        format!("read {}", secret.display()),
        "read /etc/passwd".into(),
    ] {
        assert_eq!(control(&input), "read=0 errno=0\n");
        assert_eq!(sandbox(&input).await, "read=-1 errno=2\n");
    }
    for input in [
        format!("unix {}", socket.display()),
        format!("tcp {}", tcp.local_addr().unwrap().port()),
    ] {
        assert_eq!(control(&input), "connect=0 errno=0\n");
        assert_eq!(sandbox(&input).await, "socket=-1 errno=1\n");
    }
    let write = format!("write {}", directory.path().join("out").display());
    assert_eq!(control(&write), "write=0 errno=0\n");
    assert_eq!(sandbox(&write).await, "write=-1 errno=2\n");
    assert_eq!(sandbox("write /new-file").await, "write=-1 errno=30\n");
    assert_eq!(control("external_exec"), "");
    assert_eq!(sandbox("external_exec").await, "exec=-1 errno=2\n");
    assert_eq!(sandbox("env").await, "PWD=/\n");
    let (_snapshot, executable) = snapshot(probe(), None).unwrap();
    let mut command = launch_command(&executable, Instant::now() + Duration::from_secs(4)).unwrap();
    command.env("REKEY_PLUGIN_HOST_SENTINEL", "must-not-pass");
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(b"env").await.unwrap();
    let output = tokio::time::timeout(Duration::from_secs(4), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"PWD=/\n");
    assert_eq!(
        sandbox("fds").await,
        "fds=0\n",
        "including the consumed BPF descriptor"
    );
}

#[tokio::test]
async fn native_process_namespace_and_memfd_syscalls_are_denied() {
    let plain = control("syscalls");
    for name in ["fork", "clone3", "unshare", "memfd"] {
        assert!(plain.contains(&format!("{name}=0 errno=0\n")), "{plain}");
    }
    let isolated = sandbox("syscalls").await;
    for name in ["fork", "clone3", "unshare", "memfd"] {
        assert!(
            isolated.contains(&format!("{name}=-1 errno=1\n")),
            "{isolated}"
        );
    }
}

#[tokio::test]
async fn thread_cross_process_io_uring_and_execveat_are_denied() {
    let plain = control("restricted");
    assert!(plain.contains("thread=0\n"), "{plain}");
    assert!(plain.contains("process_vm=1 errno=0\n"), "{plain}");
    for name in ["pidfd", "io_uring", "ptrace"] {
        assert!(plain.contains(&format!("{name}=0 errno=0\n")), "{plain}");
    }
    let isolated = sandbox("restricted").await;
    assert!(isolated.contains("thread=1\n"), "{isolated}");
    for name in ["pidfd", "process_vm", "io_uring", "ptrace"] {
        assert!(
            isolated.contains(&format!("{name}=-1 errno=1\n")),
            "{isolated}"
        );
    }
    assert_eq!(control("execveat"), "OK\n");
    assert_eq!(sandbox("execveat").await, "execveat=-1 errno=1\n");
}

#[tokio::test]
async fn address_space_and_seccomp_survive_self_exec() {
    for mode in ["limits", "selfexec"] {
        let plain = control(mode);
        assert!(plain.contains("mmap96=0 errno=0\n"), "{plain}");
        assert!(plain.contains("socket=0 errno=0\n"), "{plain}");
        let isolated = sandbox(mode).await;
        assert_eq!(
            isolated.matches("as=67108864/67108864\n").count(),
            if mode == "selfexec" { 2 } else { 1 }
        );
        assert!(isolated.contains("raise=-1 errno=1\n"), "{isolated}");
        assert!(isolated.contains("mmap96=-1 errno=12\n"), "{isolated}");
        assert!(isolated.contains("socket=-1 errno=1\n"), "{isolated}");
    }
}

#[tokio::test]
async fn cpu_output_deadline_and_crash_fail_closed_after_confirmed_startup() {
    assert_eq!(sandbox("ok").await, "OK\n");
    for (input, expected) in [
        ("cpu", "plugin-exit"),
        ("overflow", "plugin-output-too-large"),
        ("crash", "plugin-exit"),
    ] {
        let started = Instant::now();
        assert!(
            matches!(run(probe(),None,input.as_bytes(),started+Duration::from_secs(5)).await,
            Err(BrokerError::Denied(reason)) if reason==expected),
            "{input}"
        );
        if input == "cpu" {
            assert!(
                started.elapsed() < Duration::from_secs(4),
                "CPU hard limit must beat wall deadline"
            );
        }
    }
    let started = Instant::now();
    assert!(matches!(
        run(
            probe(),
            None,
            b"orphan",
            started + Duration::from_millis(500)
        )
        .await,
        Err(BrokerError::Denied("plugin-deadline"))
    ));
    assert!(started.elapsed() < Duration::from_secs(2));
    assert!(matches!(
        run(
            probe(),
            None,
            &vec![b'x'; MAX_ISSUE_WIRE_BYTES + 1],
            Instant::now() + Duration::from_secs(1)
        )
        .await,
        Err(BrokerError::Denied("plugin-input-too-large"))
    ));
    let (_snapshot, executable) = snapshot(probe(), None).unwrap();
    assert!(matches!(
        launch_command(&executable, Instant::now() - Duration::from_secs(1)),
        Err(BrokerError::Denied("plugin-deadline"))
    ));
}

#[tokio::test]
async fn cpu_hard_limit_kills_started_payload_ignoring_soft_signal() {
    use tokio::io::AsyncBufReadExt;
    let (_snapshot, executable) = snapshot(probe(), None).unwrap();
    let mut command = launch_command(&executable, Instant::now() + Duration::from_secs(6)).unwrap();
    let started = Instant::now();
    let mut child = command.spawn().unwrap();
    let mut input = child.stdin.take().unwrap();
    input.write_all(b"cpu").await.unwrap();
    drop(input);
    let mut lines = tokio::io::BufReader::new(child.stdout.take().unwrap()).lines();
    let ready = tokio::time::timeout(Duration::from_secs(3), lines.next_line())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ready.as_deref(), Some("READY"));
    let status = tokio::time::timeout(Duration::from_secs(4), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.code(), Some(128 + libc::SIGKILL));
    assert!(
        started.elapsed() >= Duration::from_millis(1500),
        "not an immediate seccomp or launcher failure"
    );
}

#[test]
fn inherited_high_fd_and_filter_fd_do_not_survive_lowered_hard_limit() {
    const MARKER: &str = "REKEY_TEST_LINUX_LOW_FDS";
    const AMBIENT: &str = "REKEY_TEST_LINUX_AMBIENT_FDS";
    if std::env::var_os(MARKER).is_none() {
        use std::os::unix::process::CommandExt;
        for inject_ambient in [false, true] {
            let files = [tempfile::tempfile().unwrap(), tempfile::tempfile().unwrap()];
            let fds = files.each_ref().map(|file| file.as_raw_fd());
            let mut command = StdCommand::new(std::env::current_exe().unwrap());
            command.args(["--exact", "github_issue_plugin::linux_tests::inherited_high_fd_and_filter_fd_do_not_survive_lowered_hard_limit", "--nocapture"])
                .env(MARKER, "1").env_remove(AMBIENT);
            if inject_ambient {
                command.env(AMBIENT, format!("{},{}", fds[0], fds[1]));
                // SAFETY: only the disposable child inherits these two test-owned
                // files; the parent process and its other descriptors are untouched.
                unsafe {
                    command.pre_exec(move || {
                        for fd in fds {
                            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                                return Err(std::io::Error::last_os_error());
                            }
                        }
                        Ok(())
                    });
                }
            }
            assert!(
                command.status().unwrap().success(),
                "injected ambient={inject_ambient}"
            );
        }
        return;
    }
    probe();
    // Keep every inherited CI descriptor live: it must also be removed by the
    // production runner. The fixture owns FD 500, rather than assuming it is the
    // only inheritable descriptor in the test host.
    assert_eq!(control("fd 500"), "fd=500 open=0\n");
    if let Ok(fds) = std::env::var(AMBIENT) {
        for fd in fds.split(',') {
            assert_eq!(control(&format!("fd {fd}")), format!("fd={fd} open=1\n"));
        }
    }
    let baseline = control("fds");
    let inherited: usize = baseline
        .strip_prefix("fds=")
        .unwrap()
        .strip_suffix('\n')
        .unwrap()
        .parse()
        .unwrap();
    let file = tempfile::tempfile().unwrap();
    // SAFETY: only this disposable test subprocess changes its descriptor limit.
    unsafe {
        assert_eq!(libc::dup2(file.as_raw_fd(), 500), 500);
        assert_eq!(
            libc::setrlimit(
                libc::RLIMIT_NOFILE,
                &libc::rlimit {
                    rlim_cur: 128,
                    rlim_max: 128
                }
            ),
            0
        );
    }
    assert_eq!(control("fd 500"), "fd=500 open=1\n");
    assert_eq!(control("fds"), format!("fds={}\n", inherited + 1));
    println!(
        "plain inherited={inherited}; with FD500={}; sandbox must have zero",
        inherited + 1
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert_eq!(runtime.block_on(sandbox("fds")), "fds=0\n");
    assert_eq!(runtime.block_on(sandbox("fd 500")), "fd=500 open=0\n");
}

fn descendants(pid: u32) -> Vec<u32> {
    let tasks = match fs::read_dir(format!("/proc/{pid}/task")) {
        Ok(tasks) => tasks,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("read task list: {error}"),
    };
    let mut children = std::collections::BTreeSet::new();
    for task in tasks {
        let task = task.unwrap();
        match fs::read_to_string(task.path().join("children")) {
            Ok(pids) => children.extend(
                pids.split_whitespace()
                    .map(|value| value.parse::<u32>().unwrap()),
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("read descendants: {error}"),
        }
    }
    let mut found = Vec::new();
    for child in children {
        found.push(child);
        found.extend(descendants(child));
    }
    found
}

fn live(pid: u32) -> bool {
    match fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !stat.rsplit_once(") ").unwrap().1.starts_with('Z'),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("read process state: {error}"),
    }
}
async fn assert_gone(pids: &[u32]) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while pids.iter().copied().any(live) {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("namespace descendants must terminate");
}

#[test]
fn production_run_cancellation_cleans_entire_started_namespace() {
    const MARKER: &str = "REKEY_TEST_LINUX_RUN_CANCEL";
    if std::env::var_os(MARKER).is_none() {
        let status = StdCommand::new(std::env::current_exe().unwrap())
            .args(["--exact", "github_issue_plugin::linux_tests::production_run_cancellation_cleans_entire_started_namespace", "--nocapture"])
            .env(MARKER, "1").status().unwrap();
        assert!(status.success());
        return;
    }
    let artifact = probe().to_owned();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        // This isolated helper has one launcher. Observe actual payload sleep in
        // main after READY, not a guessed delay or an unexecuted spawn future.
        let tid = unsafe { libc::syscall(libc::SYS_gettid) };
        let children = format!("/proc/self/task/{tid}/children");
        let task = tokio::spawn(async move {
            run(
                &artifact,
                None,
                b"orphan",
                Instant::now() + Duration::from_secs(10),
            )
            .await
        });
        let pids = tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                assert!(!task.is_finished(), "real run must remain pending");
                for child in fs::read_to_string(&children).unwrap().split_whitespace() {
                    let launcher = child.parse::<u32>().unwrap();
                    let mut pids = descendants(launcher);
                    if let Some(payload) = pids.last()
                        && fs::read_to_string(format!("/proc/{payload}/wchan"))
                            .is_ok_and(|state| state.contains("hrtimer_nanosleep"))
                    {
                        assert!(pids.len() >= 2);
                        pids.push(launcher);
                        return pids;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("payload must actually enter main and sleep");
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_gone(&pids).await;
    });
}

#[test]
fn parent_death_fixture() {
    let Some(mode) = std::env::var_os("REKEY_TEST_LINUX_PLUGIN_PARENT") else {
        return;
    };
    if mode == "plain" || mode == "plain-startup" {
        let mut command = StdCommand::new(probe());
        if mode == "plain" {
            command.arg("orphan");
        } else {
            command.stdin(Stdio::piped());
        }
        let mut child = command.spawn().unwrap();
        println!("LAUNCHER {}", child.id());
        std::io::stdout().flush().unwrap();
        child.wait().unwrap();
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_snapshot, executable) = snapshot(probe(), None).unwrap();
            let mut command =
                launch_command(&executable, Instant::now() + Duration::from_secs(5)).unwrap();
            command.stdout(Stdio::inherit());
            let mut child = command.spawn().unwrap();
            println!("LAUNCHER {}", child.id().unwrap());
            std::io::stdout().flush().unwrap();
            if mode != "sandbox-startup" {
                child
                    .stdin
                    .take()
                    .unwrap()
                    .write_all(b"orphan")
                    .await
                    .unwrap();
            }
            child.wait().await.unwrap();
        });
    }
}

#[tokio::test]
async fn parent_sigkill_after_ready_kills_uncooperative_payload_with_live_control() {
    use tokio::io::AsyncBufReadExt;
    for mode in ["plain", "sandbox"] {
        let mut parent = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "github_issue_plugin::linux_tests::parent_death_fixture",
                "--nocapture",
            ])
            .env("REKEY_TEST_LINUX_PLUGIN_PARENT", mode)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let parent_pid = parent.id().unwrap();
        let mut lines = tokio::io::BufReader::new(parent.stdout.take().unwrap()).lines();
        let readiness = tokio::time::timeout(Duration::from_secs(5), async {
            let mut launcher = None;
            let mut ready = false;
            let mut observed = String::new();
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(pid) = line.strip_prefix("LAUNCHER ") {
                    launcher = Some(pid.parse::<u32>().unwrap());
                }
                if line == "READY" {
                    ready = true;
                }
                observed.push_str(&line);
                observed.push('\n');
                if ready && let Some(launcher) = launcher {
                    return Some((launcher, observed));
                }
            }
            None
        })
        .await;
        let (launcher, observed) = match readiness {
            Ok(Some(result)) => result,
            failure => {
                // Kill the whole dedicated fixture subtree before reaping. The
                // async reader is dropped; there is no blocked reader thread.
                for pid in descendants(parent_pid).into_iter().rev() {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                parent.start_kill().unwrap();
                parent.wait().await.unwrap();
                panic!("fixture did not reach READY: {failure:?}");
            }
        };
        let mut pids = descendants(launcher);
        pids.push(launcher);
        parent.start_kill().unwrap();
        parent.wait().await.unwrap();
        if mode == "sandbox" {
            assert_gone(&pids).await;
            assert!(pids.len() >= 3);
            assert!(
                observed.contains("clear_pdeathsig=-1 errno=1"),
                "{observed}"
            );
            assert!(observed.contains("setsid=-1 errno=1"), "{observed}");
        } else {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let survived = live(launcher);
            // SAFETY: only the observed disposable control payload is killed.
            assert_eq!(unsafe { libc::kill(launcher as i32, libc::SIGKILL) }, 0);
            assert_gone(&pids).await;
            assert!(survived, "unconfined payload must ignore parent death");
            assert!(observed.contains("clear_pdeathsig=0 errno=0"), "{observed}");
            assert!(observed.contains("setsid=0 errno=0"), "{observed}");
        }
    }
}

#[tokio::test]
async fn parent_sigkill_before_ready_kills_sandbox_with_live_control() {
    use tokio::io::AsyncBufReadExt;
    for mode in ["plain-startup", "sandbox-startup"] {
        let mut parent = tokio::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "github_issue_plugin::linux_tests::parent_death_fixture",
                "--nocapture",
            ])
            .env("REKEY_TEST_LINUX_PLUGIN_PARENT", mode)
            .stdout(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let parent_pid = parent.id().unwrap();
        let mut lines = tokio::io::BufReader::new(parent.stdout.take().unwrap()).lines();
        let launcher = tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(line) = lines.next_line().await.unwrap() {
                if let Some(pid) = line.strip_prefix("LAUNCHER ") {
                    return Some(pid.parse::<u32>().unwrap());
                }
            }
            None
        })
        .await;
        let launcher = match launcher {
            Ok(Some(pid)) => pid,
            failure => {
                for pid in descendants(parent_pid).into_iter().rev() {
                    unsafe {
                        libc::kill(pid as i32, libc::SIGKILL);
                    }
                }
                parent.start_kill().unwrap();
                parent.wait().await.unwrap();
                panic!("fixture did not print LAUNCHER: {failure:?}");
            }
        };
        let mut pids = descendants(launcher);
        pids.push(launcher);
        parent.start_kill().unwrap();
        parent.wait().await.unwrap();
        if mode == "sandbox-startup" {
            assert_gone(&pids).await;
        } else {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let survived = live(launcher);
            // SAFETY: only the observed disposable control payload is killed.
            assert_eq!(unsafe { libc::kill(launcher as i32, libc::SIGKILL) }, 0);
            assert_gone(&pids).await;
            assert!(survived, "unconfined payload must ignore parent death");
        }
    }
}

#[cfg(target_arch = "x86_64")]
#[tokio::test]
async fn x32_and_compat_abi_are_killed() {
    for mode in ["x32", "i386"] {
        assert!(control(mode).contains("ESCAPED"));
        assert!(matches!(
            run(
                probe(),
                None,
                mode.as_bytes(),
                Instant::now() + Duration::from_secs(4)
            )
            .await,
            Err(BrokerError::Denied("plugin-exit"))
        ));
    }
}
