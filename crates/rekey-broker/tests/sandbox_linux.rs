//! Actual linux-netns-v1 launcher acceptance, using only disposable fixtures.
//! Requires bubblewrap plus user, mount, network and PID namespaces. A namespace
//! setup failure is a failed test, never counted as a denied attack.
#![cfg(target_os = "linux")]

mod common;

use std::fs;
use std::io::Write;
use std::net::{TcpListener, UdpSocket};
use std::os::fd::AsRawFd;
use std::os::unix::fs::symlink;
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

const PROBE_SOURCE: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
static int outcome(int result) { if (result < 0) { perror("probe"); return 19; } return 0; }
static int uds(const char *path) {
  int fd=socket(AF_UNIX,SOCK_STREAM,0); if(fd<0)return -1;
  struct sockaddr_un a={.sun_family=AF_UNIX};
  if(strlen(path)>=sizeof(a.sun_path))exit(90);
  strcpy(a.sun_path,path);
  if(connect(fd,(void*)&a,sizeof(a))<0) { close(fd); return -1; } return fd;
}
int main(int argc,char **argv) {
  alarm(12); if(argc<2)return 90;
  if(!strcmp(argv[1],"exit"))return atoi(argv[2]);
  if(!strcmp(argv[1],"read")) {
    int fd=open(argv[2],O_RDONLY); if(fd<0)return outcome(-1);
    char c; return outcome((int)read(fd,&c,1));
  }
  if(!strcmp(argv[1],"write")) return outcome(open(argv[2],O_WRONLY|O_CREAT,0600));
  if(!strcmp(argv[1],"unix")) return outcome(uds(argv[2]));
  if(!strcmp(argv[1],"tcp")||!strcmp(argv[1],"udp")) {
    int udp=!strcmp(argv[1],"udp"), v6=strchr(argv[2],':')!=NULL;
    int fd=socket(v6?AF_INET6:AF_INET,udp?SOCK_DGRAM:SOCK_STREAM,0); if(fd<0)return outcome(-1);
    struct sockaddr_in a={.sin_family=AF_INET,.sin_port=htons(atoi(argv[3]))};
    struct sockaddr_in6 b={.sin6_family=AF_INET6,.sin6_port=htons(atoi(argv[3]))};
    if(v6)inet_pton(AF_INET6,argv[2],&b.sin6_addr);else inet_pton(AF_INET,argv[2],&a.sin_addr);
    void *addr=v6?(void*)&b:(void*)&a; socklen_t len=v6?sizeof(b):sizeof(a);
    if(!udp)return outcome(connect(fd,addr,len));
    struct timeval timeout={.tv_sec=0,.tv_usec=200000};
    if(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))<0)return 90;
    if(sendto(fd,"x",1,0,addr,len)!=1)return outcome(-1);
    char reply; int got=(int)recv(fd,&reply,1,0);
    return got==1&&reply=='x'?0:19;
  }
  if(!strcmp(argv[1],"fd")) { char c; return outcome((int)read(atoi(argv[2]),&c,1)); }
  if(!strcmp(argv[1],"socket-fd")) return outcome((int)send(atoi(argv[2]),"x",1,0));
  if(!strcmp(argv[1],"env")) {
    if(getenv("PARENT_CANARY")||getenv("HTTP_PROXY")||getenv("LD_LIBRARY_PATH"))return 91;
    if(!getenv("REKEY_CAPABILITY")||strcmp(getenv("REKEY_CAPABILITY"),"fixture-capability"))return 92;
    char cwd[4096]; if(!getcwd(cwd,sizeof(cwd))||strcmp(cwd,getenv("HOME"))||strcmp(cwd,"/tmp"))return 93;
    if(open("scratch-ok",O_WRONLY|O_CREAT,0600)<0)return 94;
    puts(cwd); return 0;
  }
  if(!strcmp(argv[1],"fork")) {
    pid_t p=fork(); if(p<0)return 95; if(!p) { execl(argv[0],argv[0],"read",argv[2],NULL); _exit(96); }
    int s; if(waitpid(p,&s,0)<0)return 97; return WIFEXITED(s)?WEXITSTATUS(s):98;
  }
  if(!strcmp(argv[1],"execute")) {
    const char *token=getenv("REKEY_CAPABILITY"); if(!token)return 92;
    char meta[1024]; int n=snprintf(meta,sizeof(meta),"{\"capability_token\":\"%s\",\"action_id\":\"%s\",\"action_version\":%s,\"content_type\":\"application/json\",\"extra_headers\":[],\"approval_grants\":[]}",token,argv[3],argv[4]);
    if(n<0||n>=(int)sizeof(meta))return 90;
    unsigned char h[36]={'R','K','I','P',0,1,2,0,0,1,0,0,1,2,3,4,5,6,0x47,8,0x89,10,11,12,13,14,15,16};
    uint32_t len=htonl(n),body=htonl(2); memcpy(h+28,&len,4);memcpy(h+32,&body,4);
    int fd=uds(argv[2]); if(fd<0)return outcome(-1);
    if(write(fd,h,36)!=36||write(fd,meta,n)!=n||write(fd,"{}",2)!=2)return 95;
    char reply[8192]; ssize_t total=0,got; while((got=read(fd,reply+total,sizeof(reply)-total))>0) { total+=got; if(total>=36) { uint32_t m,b;memcpy(&m,reply+28,4);memcpy(&b,reply+32,4);if(total>=36+ntohl(m)+ntohl(b))break; } if(total==sizeof(reply))return 96; }
    if(total<36)return 97;
    return write(1,reply,total)==total?0:98;
  }
  return 90;
}
"#;

fn probe() -> &'static Path {
    static PROBE: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &PROBE
        .get_or_init(|| {
            let dir = tempfile::Builder::new()
                .prefix("rk-probe-")
                .tempdir_in("/var/tmp")
                .unwrap();
            let source = dir.path().join("probe.c");
            let binary = dir.path().join("probe");
            fs::write(&source, PROBE_SOURCE).unwrap();
            let output = Command::new("/usr/bin/cc")
                .args(["-Wall", "-Werror"])
                .arg(&source)
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

struct Fixture {
    _root: tempfile::TempDir,
    state: PathBuf,
    socket: PathBuf,
    code: PathBuf,
    _listener: UnixListener,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rk\"-")
            .tempdir_in("/var/tmp")
            .unwrap();
        let state = root.path().join("s");
        let code = root.path().join("code");
        fs::create_dir(&state).unwrap();
        fs::create_dir(&code).unwrap();
        fs::create_dir(root.path().join("a")).unwrap();
        fs::write(state.join("secret"), "fixture-secret").unwrap();
        let socket = root.path().join("a/agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        Self {
            _root: root,
            state,
            socket,
            code,
            _listener: listener,
        }
    }

    fn launch(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_rekeyd"));
        cmd.current_dir(&self.code)
            .arg("agent-run")
            .arg("--state-dir")
            .arg(&self.state)
            .arg("--agent-socket")
            .arg(&self.socket)
            .arg("--")
            .arg(probe())
            .args(args);
        cmd
    }

    fn output(&self, args: &[&str]) -> Output {
        let output = self.launch(args).output().unwrap();
        self._listener.set_nonblocking(true).unwrap();
        loop {
            match self._listener.accept() {
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("fixture listener: {error}"),
            }
        }
        output
    }
}

fn succeeds(output: &Output) {
    assert!(
        output.status.success(),
        "status={:?}, stderr={}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
}

fn denied(f: &Fixture, args: &[&str]) {
    let control = Command::new(probe()).args(args).output().unwrap();
    succeeds(&control);
    let output = f.output(args);
    assert_eq!(
        output.status.code(),
        Some(19),
        "sandbox must start and reject the operation: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn sandbox_hides_state_and_admin_but_keeps_agent_socket() {
    let f = Fixture::new();
    succeeds(&f.output(&["exit", "0"]));
    let secret = f.state.join("secret");
    denied(&f, &["read", secret.to_str().unwrap()]);
    let alias = f.code.join("alias");
    symlink(&secret, &alias).unwrap();
    denied(&f, &["read", alias.to_str().unwrap()]);
    let admin = f.state.join("admin.sock");
    let _admin = UnixListener::bind(&admin).unwrap();
    denied(&f, &["unix", admin.to_str().unwrap()]);
    succeeds(&f.output(&["unix", f.socket.to_str().unwrap()]));
    denied(&f, &["fork", secret.to_str().unwrap()]);
    let public = f.code.join("public");
    fs::write(&public, "not a credential").unwrap();
    succeeds(&f.output(&["read", public.to_str().unwrap()]));
    denied(&f, &["write", f.code.join("readonly").to_str().unwrap()]);
}

#[test]
fn sandbox_denies_tcp_and_udp_with_successful_unsandboxed_controls() {
    let f = Fixture::new();
    succeeds(&f.output(&["exit", "0"]));
    for address in ["127.0.0.1", "::1"] {
        let tcp = TcpListener::bind((address, 0)).unwrap();
        denied(
            &f,
            &[
                "tcp",
                address,
                &tcp.local_addr().unwrap().port().to_string(),
            ],
        );
        // New network namespaces still allow their own loopback sendto. Require
        // a reply from the outer listener to prove crossing the boundary.
        let udp = UdpSocket::bind((address, 0)).unwrap();
        udp.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let control_peer = udp.try_clone().unwrap();
        let echo = std::thread::spawn(move || {
            let mut packet = [0; 2];
            let (length, source) = control_peer.recv_from(&mut packet).unwrap();
            assert_eq!(&packet[..length], b"x");
            assert_eq!(control_peer.send_to(b"x", source).unwrap(), 1);
        });
        denied(
            &f,
            &[
                "udp",
                address,
                &udp.local_addr().unwrap().port().to_string(),
            ],
        );
        echo.join().unwrap();
        udp.set_read_timeout(Some(std::time::Duration::from_millis(100)))
            .unwrap();
        let mut packet = [0; 2];
        let error = udp.recv(&mut packet).unwrap_err();
        assert!(matches!(
            error.kind(),
            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
        ));
    }
}

#[test]
fn sandbox_drops_environment_and_uses_tmp_overlay() {
    let f = Fixture::new();
    let mut child = Command::new(env!("CARGO_BIN_EXE_rekeyd"))
        .current_dir(&f.code)
        .args(["agent-run", "--state-dir"])
        .arg(&f.state)
        .arg("--agent-socket")
        .arg(&f.socket)
        .args(["--capability-stdin", "--"])
        .arg(probe())
        .arg("env")
        .env("PARENT_CANARY", "never-inherit")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("LD_LIBRARY_PATH", "/not-present")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"fixture-capability\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    succeeds(&output);
    assert_eq!(output.stdout, b"/tmp\n");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("fixture-capability"));
}

#[test]
fn sandbox_closes_inherited_nonstandard_file_and_socket_descriptors() {
    let f = Fixture::new();
    let secret = fs::File::open(f.state.join("secret")).unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    for (mode, fd) in [
        ("fd", secret.as_raw_fd()),
        ("socket-fd", socket.as_raw_fd()),
    ] {
        for (target, lowered) in [(211, false), (500, true)] {
            // The second variant keeps FD 500 open while reducing both limits
            // to 128, so an rlimit-bounded close loop cannot satisfy the test.
            let inherit = |cmd: &mut Command| {
                // SAFETY: only async-signal-safe calls in the spawned test child.
                unsafe {
                    cmd.pre_exec(move || {
                        if libc::dup2(fd, target) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if lowered
                            && libc::setrlimit(
                                libc::RLIMIT_NOFILE,
                                &libc::rlimit {
                                    rlim_cur: 128,
                                    rlim_max: 128,
                                },
                            ) != 0
                        {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
            };
            let number = target.to_string();
            let mut control = Command::new(probe());
            control.args([mode, &number]);
            inherit(&mut control);
            succeeds(&control.output().unwrap());
            let mut cmd = f.launch(&[mode, &number]);
            inherit(&mut cmd);
            let output = cmd.output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(19),
                "mode={mode}, fd={target}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_executes_authorized_action_through_real_broker() {
    let broker = common::start_broker_disjoint().await;
    common::unlock(&broker).await;
    let secret = b"linux-netns-credential-canary";
    let credential = common::add_credential(&broker, "linux-netns", secret).await;
    let (action, version) = common::create_action(&broker, &credential).await;
    let token = common::create_session(&broker, &action, version).await;
    let code = broker.dir.path().join("code");
    fs::create_dir(&code).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_rekeyd"));
    command
        .current_dir(code)
        .args(["agent-run", "--state-dir"])
        .arg(&broker.state_dir)
        .arg("--agent-socket")
        .arg(broker.agent_sock().canonicalize().unwrap())
        .args(["--capability-stdin", "--"])
        .arg(probe())
        .arg("execute")
        .arg(broker.agent_sock().canonicalize().unwrap())
        .arg(action)
        .arg(version.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child_token = token.clone();
    let output = tokio::task::spawn_blocking(move || {
        let mut child = command.spawn().unwrap();
        writeln!(child.stdin.take().unwrap(), "{child_token}").unwrap();
        child.wait_with_output().unwrap()
    })
    .await
    .unwrap();
    succeeds(&output);
    let header =
        rekey_domain::ipc::FrameHeader::decode(output.stdout[..36].try_into().unwrap()).unwrap();
    assert_eq!(
        header.message_type,
        rekey_domain::ipc::resp_msg::OK,
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert_eq!(
        &output.stdout[36 + header.metadata_len as usize..],
        b"{\"ok\":true}"
    );
    for bytes in [&output.stdout, &output.stderr] {
        assert!(!bytes.windows(secret.len()).any(|w| w == secret));
        assert!(!bytes.windows(token.len()).any(|w| w == token.as_bytes()));
    }
    let requests = broker.fake.take_requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/v1/things");
    assert_eq!(
        requests[0].auth_value,
        b"Bearer linux-netns-credential-canary"
    );
    broker.shutdown().await;
}
