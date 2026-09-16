use super::*;
use std::process::Command as StdCommand;
use std::sync::OnceLock;

// Malicious native artifact deliberately has no cooperation with the runner.
const SOURCE: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
int main(void) {
 char b[4096]={0}; if(read(0,b,sizeof(b)-1)<1)return 9;
 if(!strcmp(b,"overflow")) { for(int i=0;i<300000;i++)putchar('x'); return 0; }
 if(!strcmp(b,"spin")) { for(;;){} }
 if(!strcmp(b,"crash")) {raise(SIGABRT);return 9;}
 if(!strcmp(b,"sleep")) { sleep(10);return 0; }
 if(!strcmp(b,"memory")) { for(;;) {char *p=malloc(1024*1024);if(!p)return 19;memset(p,1,1024*1024);usleep(1000);} }
 if(!strcmp(b,"fork")) { pid_t p=fork();if(p<0)return 19;if(!p)_exit(0);return 0; }
 if(!strcmp(b,"exec")) { execl("/bin/sh","sh","-c","true",NULL);return 19; }
 if(!strcmp(b,"env")) {extern char **environ;return environ[0]?8:0;}
 if(!strncmp(b,"fd ",3))return fcntl(atoi(b+3),F_GETFD)<0?19:0;
 if(!strncmp(b,"read ",5))return open(b+5,O_RDONLY)<0?19:0;
 if(!strncmp(b,"write ",6))return open(b+6,O_WRONLY|O_CREAT,0600)<0?19:0;
 if(!strncmp(b,"unix ",5)) {int fd=socket(AF_UNIX,SOCK_STREAM,0);if(fd<0)return 19;struct sockaddr_un a={.sun_family=AF_UNIX};strcpy(a.sun_path,b+5);return connect(fd,(void*)&a,sizeof(a))<0?19:0;}
 if(!strncmp(b,"tcp ",4)) {int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return 19;struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(b+4)),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};return connect(fd,(void*)&a,sizeof(a))<0?19:0;}
 if(!strncmp(b,"orphan ",7)) {pid_t p=getppid();printf("PLUGIN_READY %d\n",getpid());fflush(stdout);while(getppid()==p)usleep(1000);int fd=socket(AF_INET,SOCK_STREAM,0);struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(b+7)),.sin_addr.s_addr=htonl(INADDR_LOOPBACK)};int escaped=open("/etc/passwd",O_RDONLY)>=0 || (fd>=0 && connect(fd,(void*)&a,sizeof(a))==0);if(escaped)sleep(10);return escaped?0:19;}
 puts("{\"title\":\"attacker changed title\"}");return 0;
}
"#;

fn probe() -> &'static Path {
    static PROBE: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &PROBE
        .get_or_init(|| {
            let dir = tempfile::tempdir().unwrap();
            let source = dir.path().join("probe.c");
            let binary = dir.path().join("probe");
            fs::write(&source, SOURCE).unwrap();
            let output = StdCommand::new("/usr/bin/cc")
                .args(["-O0", "-Wall", "-Werror"])
                .arg(source)
                .arg("-o")
                .arg(&binary)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            (dir, binary)
        })
        .1
}

async fn attack(input: &[u8]) -> Result<Vec<u8>, BrokerError> {
    run(probe(), input, Instant::now() + Duration::from_secs(4)).await
}

fn unconfined(input: &[u8]) -> std::process::Output {
    let mut child = StdCommand::new(probe())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

#[tokio::test]
async fn real_packaged_sidecar_normalizes_public_body() {
    let body = br#"{ "body": "details", "title": "reference" }"#;
    assert_eq!(
        normalize(body, Instant::now() + Duration::from_secs(4))
            .await
            .unwrap(),
        br#"{"title":"reference","body":"details"}"#
    );
}

#[tokio::test]
async fn native_fork_exec_environment_and_inherited_fd_are_bounded() {
    for input in [b"fork".as_slice(), b"exec"] {
        assert!(unconfined(input).status.success());
        assert!(attack(input).await.is_err());
    }
    assert!(attack(b"env").await.is_ok());
    use std::os::fd::AsRawFd;
    let canary = tempfile::tempfile().unwrap();
    let fd = canary.as_raw_fd();
    // SAFETY: test-owned descriptor, deliberately inheritable to attack cleanup.
    assert_eq!(unsafe { libc::fcntl(fd, libc::F_SETFD, 0) }, 0);
    let input = format!("fd {fd}");
    assert!(unconfined(input.as_bytes()).status.success());
    assert!(attack(input.as_bytes()).await.is_err());
}

#[tokio::test]
async fn native_files_and_network_are_denied_with_successful_controls() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().join("secret");
    fs::write(&secret, b"private-canary").unwrap();
    let socket_path = dir.path().join("agent.sock");
    let _uds = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
    let tcp = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for input in [
        format!("read {}", secret.display()),
        "read /etc/passwd".to_owned(),
        format!("write {}", dir.path().join("out").display()),
        format!("unix {}", socket_path.display()),
        format!("tcp {}", tcp.local_addr().unwrap().port()),
    ] {
        assert!(
            unconfined(input.as_bytes()).status.success(),
            "control: {input}"
        );
        assert!(attack(input.as_bytes()).await.is_err(), "sandbox: {input}");
    }
}

#[tokio::test]
async fn output_cpu_memory_and_absolute_deadline_fail_closed() {
    assert!(matches!(
        attack(b"overflow").await,
        Err(BrokerError::Denied("plugin-output-too-large"))
    ));
    assert!(matches!(
        attack(b"spin").await,
        Err(BrokerError::Denied("plugin-exit"))
    ));
    assert!(matches!(
        attack(b"memory").await,
        Err(BrokerError::Denied("plugin-memory-budget"))
    ));
    let start = Instant::now();
    assert!(matches!(
        run(probe(), b"sleep", start + Duration::from_millis(100)).await,
        Err(BrokerError::Denied("plugin-deadline"))
    ));
    assert!(start.elapsed() < Duration::from_secs(1));
    let (_snapshot, executable) = snapshot(probe()).unwrap();
    assert!(matches!(
        launch_command(&executable, Instant::now() - Duration::from_millis(1)),
        Err(BrokerError::Denied("plugin-deadline"))
    ));
    assert!(matches!(
        attack(b"crash").await,
        Err(BrokerError::Denied("plugin-exit"))
    ));
    assert!(
        run(
            probe(),
            &vec![b'x'; MAX_ISSUE_WIRE_BYTES + 1],
            Instant::now() + Duration::from_secs(1)
        )
        .await
        .is_err()
    );
}

#[tokio::test]
async fn malicious_output_cannot_equal_approved_body_and_symlink_is_rejected() {
    let output = attack(b"fake-effect").await.unwrap();
    assert_ne!(
        output,
        normalize_issue_body(br#"{"title":"approved"}"#).unwrap()
    );
    assert!(matches!(
        normalize_with_artifact(
            probe(),
            br#"{"title":"approved"}"#,
            Instant::now() + Duration::from_secs(4)
        )
        .await,
        Err(BrokerError::Denied("plugin-output-mismatch"))
    ));
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("artifact");
    std::os::unix::fs::symlink(probe(), &link).unwrap();
    assert!(snapshot(&link).is_err());
}

#[test]
fn inherited_high_fd_after_lowering_both_limits() {
    const MARKER: &str = "REKEY_TEST_LOW_FD_LIMIT";
    if std::env::var_os(MARKER).is_none() {
        let status = StdCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "github_issue_plugin::tests::inherited_high_fd_after_lowering_both_limits",
                "--nocapture",
            ])
            .env(MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let artifact = probe(); // compiler needs the original limit
    let file = tempfile::tempfile().unwrap();
    use std::os::fd::AsRawFd;
    // SAFETY: isolated test process intentionally lowers its own resource limits.
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
        assert!(libc::fcntl(500, libc::F_GETFD) >= 0);
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    assert!(
        runtime
            .block_on(run(
                artifact,
                b"fd 500",
                Instant::now() + Duration::from_secs(4)
            ))
            .is_err()
    );
}

// Separate process: killing this test host must not kill the outer test runner.
#[test]
fn parent_exit_fixture() {
    let Some(mode) = std::env::var_os("REKEY_TEST_PARENT_EXIT") else {
        return;
    };
    let input = format!(
        "orphan {}",
        std::env::var("REKEY_TEST_ORPHAN_PORT").unwrap()
    );
    if mode == "plain" {
        let mut child = StdCommand::new(probe())
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.as_bytes())
            .unwrap();
        child.wait().unwrap();
    } else {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (_snapshot, executable) = snapshot(probe()).unwrap();
            let mut command =
                launch_command(&executable, Instant::now() + Duration::from_secs(20)).unwrap();
            command.stdout(Stdio::inherit()); // test observer's pipe, same sandbox launcher
            let mut child = command.spawn().unwrap();
            child
                .stdin
                .take()
                .unwrap()
                .write_all(input.as_bytes())
                .await
                .unwrap();
            child.wait().await.unwrap();
        });
    }
}

fn process_live(pid: i32) -> bool {
    let output = StdCommand::new("/bin/ps")
        .args(["-p", &pid.to_string(), "-o", "stat="])
        .output()
        .unwrap();
    let state = String::from_utf8(output.stdout).unwrap();
    output.status.success() && !state.trim().is_empty() && !state.trim().starts_with('Z')
}

#[test]
fn parent_sigkill_preserves_confinement_with_live_unconfined_control() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for mode in ["plain", "sandbox"] {
        let mut parent = StdCommand::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "github_issue_plugin::tests::parent_exit_fixture",
                "--nocapture",
            ])
            .env("REKEY_TEST_PARENT_EXIT", mode)
            .env(
                "REKEY_TEST_ORPHAN_PORT",
                listener.local_addr().unwrap().port().to_string(),
            )
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        use std::io::BufRead;
        let mut lines = std::io::BufReader::new(parent.stdout.take().unwrap()).lines();
        let descendant = loop {
            let line = lines.next().expect("fixture readiness EOF").unwrap();
            if let Some(pid) = line.strip_prefix("PLUGIN_READY ") {
                break pid.parse::<i32>().unwrap();
            }
        };
        assert!(process_live(descendant));
        parent.kill().unwrap();
        parent.wait().unwrap();
        std::thread::sleep(Duration::from_millis(200));
        let remained = process_live(descendant);
        // SAFETY: disposable fixture PID; cleanup successful unconfined control.
        if remained {
            unsafe {
                libc::kill(descendant, libc::SIGKILL);
            }
        }
        assert_eq!(remained, mode == "plain", "parent exit boundary: {mode}");
    }
}
