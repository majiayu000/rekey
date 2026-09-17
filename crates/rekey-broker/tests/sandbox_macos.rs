//! Real macOS kernel boundary tests. Only disposable fixtures are attacked.
#![cfg(target_os = "macos")]

mod common;

use std::fs;
use std::io::{BufRead, BufReader, Read, Write};
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
#include <mach/mach.h>
#include <netdb.h>
#include <servers/bootstrap.h>
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
  if(!strcmp(argv[1],"terminate")) { raise(SIGTERM); return 99; }
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
    return outcome(udp?(int)sendto(fd,"x",1,0,addr,len):connect(fd,addr,len));
  }
  if(!strcmp(argv[1],"dns")) { struct addrinfo *r=NULL; int e=getaddrinfo("localhost",NULL,NULL,&r); if(!e)freeaddrinfo(r); return e?19:0; }
  if(!strcmp(argv[1],"mach")) { mach_port_t p; return bootstrap_look_up(bootstrap_port,"com.apple.system.opendirectoryd.libinfo",&p)==KERN_SUCCESS?0:19; }
  if(!strcmp(argv[1],"signal")) return outcome(kill(atoi(argv[2]),0));
  if(!strcmp(argv[1],"task")) { mach_port_t p; return task_for_pid(mach_task_self(),atoi(argv[2]),&p)==KERN_SUCCESS?0:19; }
  if(!strcmp(argv[1],"fd")) { char c; return outcome((int)read(atoi(argv[2]),&c,1)); }
  if(!strcmp(argv[1],"socket-fd")) return outcome((int)send(atoi(argv[2]),"x",1,0));
  if(!strcmp(argv[1],"env")) {
    if(getenv("PARENT_CANARY")||getenv("HTTP_PROXY")||getenv("DYLD_LIBRARY_PATH"))return 91;
    if(!getenv("REKEY_CAPABILITY")||strcmp(getenv("REKEY_CAPABILITY"),"fixture-capability"))return 92;
    char cwd[4096]; if(!getcwd(cwd,sizeof(cwd))||strcmp(cwd,getenv("HOME"))||strcmp(cwd,getenv("TMPDIR")))return 93;
    if(open("scratch-ok",O_WRONLY|O_CREAT,0600)<0)return 94;
    puts(cwd); return 0;
  }
  if(!strcmp(argv[1],"fork")) {
    pid_t p=fork(); if(p<0)return 95; if(!p) { execl(argv[0],argv[0],"read",argv[2],NULL); _exit(96); }
    int s; if(waitpid(p,&s,0)<0)return 97; return WIFEXITED(s)?WEXITSTATUS(s):98;
  }
  if(!strcmp(argv[1],"orphan")) {
    char cwd[4096]; if(!getcwd(cwd,sizeof(cwd)))return 93;
    pid_t parent=getppid(); printf("ready %s\n",cwd); fflush(stdout);
    while(getppid()==parent)usleep(10000);
    if(setsid()<0)perror("setsid");
    pid_t p=fork(); if(p<0)return 95; if(p)return 0;
    int forbidden=open(argv[2],O_RDONLY)>=0 || uds(argv[3])>=0;
    puts(forbidden?"ESCAPED":"still-confined"); return forbidden?99:0;
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
                .tempdir_in("/private/tmp")
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
    root: tempfile::TempDir,
    state: PathBuf,
    socket: PathBuf,
    code: PathBuf,
    _listener: UnixListener,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::Builder::new()
            .prefix("rk\"-")
            .tempdir_in("/private/tmp")
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
            root,
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
        // Drain the peer-validation connection so many cases do not fill backlog.
        let drain = self._listener.try_clone().unwrap();
        let task = std::thread::spawn(move || drain.accept().unwrap());
        let output = self.launch(args).output().unwrap();
        task.join().unwrap();
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
fn sandbox_files_network_processes_and_descendants() {
    let f = Fixture::new();
    let secret = f.state.join("secret");
    denied(&f, &["read", secret.to_str().unwrap()]);
    let alias = f.code.join("alias");
    symlink(&secret, &alias).unwrap();
    denied(&f, &["read", alias.to_str().unwrap()]);
    let other_path = f.root.path().join("other.sock");
    let _other = UnixListener::bind(&other_path).unwrap();
    denied(&f, &["unix", other_path.to_str().unwrap()]);
    let admin_path = f.state.join("admin.sock");
    let _admin = UnixListener::bind(&admin_path).unwrap();
    denied(&f, &["unix", admin_path.to_str().unwrap()]);
    succeeds(&f.output(&["unix", f.socket.to_str().unwrap()]));
    let writable = f.code.join("must-stay-readonly");
    denied(&f, &["write", writable.to_str().unwrap()]);
    denied(&f, &["fork", secret.to_str().unwrap()]);
    denied(&f, &["signal", &std::process::id().to_string()]);
    denied(&f, &["mach"]);
    denied(&f, &["dns"]);
    // task_for_pid may already be denied by taskgated/TCC in the control.
    // Report that boundary explicitly rather than counting it as sandbox proof.
    let target = std::process::id().to_string();
    let control = Command::new(probe())
        .args(["task", &target])
        .output()
        .unwrap();
    let task_output = f.output(&["task", &target]);
    assert_eq!(task_output.status.code(), Some(19));
    eprintln!(
        "task_for_pid control_success={} (only a successful control attributes denial to Seatbelt)",
        control.status.success()
    );
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
        let udp = UdpSocket::bind((address, 0)).unwrap();
        denied(
            &f,
            &[
                "udp",
                address,
                &udp.local_addr().unwrap().port().to_string(),
            ],
        );
    }
    // Direct DNS transport is UDP, subject to the same OS egress boundary.
    denied(&f, &["udp", "192.0.2.1", "53"]);
    let code_file = f.code.join("input");
    fs::write(&code_file, "public").unwrap();
    succeeds(&f.output(&["read", code_file.to_str().unwrap()]));
}

#[test]
fn sandbox_drops_environment_and_uses_private_scratch() {
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
        .env("DYLD_LIBRARY_PATH", "/not-present")
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
    let scratch = String::from_utf8(output.stdout).unwrap();
    assert!(scratch.trim().starts_with("/private/tmp/rekey-agent-"));
    assert!(
        !Path::new(scratch.trim()).exists(),
        "normal completion cleans scratch"
    );
}

#[test]
fn sandbox_closes_inherited_descriptors_and_rejects_socket_output() {
    let f = Fixture::new();
    let secret = fs::File::open(f.state.join("secret")).unwrap();
    let (socket, _peer) = UnixStream::pair().unwrap();
    for (mode, fd) in [
        ("fd", secret.as_raw_fd()),
        ("socket-fd", socket.as_raw_fd()),
    ] {
        let mut cmd = f.launch(&[mode, "211"]);
        // SAFETY: dup2 is async-signal-safe; only the spawned test child changes.
        unsafe {
            cmd.pre_exec(move || {
                if libc::dup2(fd, 211) < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let output = cmd.output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(19),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let (socket, _peer) = UnixStream::pair().unwrap();
    let output = f
        .launch(&["read", f.code.to_str().unwrap()])
        .stdout(Stdio::from(std::os::fd::OwnedFd::from(socket)))
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(5));
    // BrokerError::Io deliberately redacts OS details at the public boundary.
    assert!(String::from_utf8_lossy(&output.stderr).contains("ipc unavailable"));
}

#[test]
fn sandbox_remains_on_orphaned_descendants_after_launcher_death() {
    let f = Fixture::new();
    let secret = f.state.join("secret");
    let admin_path = f.state.join("admin.sock");
    let _admin = UnixListener::bind(&admin_path).unwrap();
    let mut child = f
        .launch(&[
            "orphan",
            secret.to_str().unwrap(),
            admin_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut output = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    output.read_line(&mut line).unwrap();
    let scratch = line.trim().strip_prefix("ready ").expect("probe started");
    assert!(scratch.starts_with("/private/tmp/rekey-agent-"));
    child.kill().unwrap();
    child.wait().unwrap();
    let mut rest = String::new();
    output.read_to_string(&mut rest).unwrap();
    assert_eq!(rest, "still-confined\n");
    fs::remove_dir_all(scratch).unwrap();
}

#[test]
fn sandbox_rejects_broad_code_roots_and_forwards_exit_status() {
    let f = Fixture::new();
    for root in [
        PathBuf::from("/"),
        std::env::var_os("HOME").unwrap().into(),
        PathBuf::from("/private/tmp"),
        f.state.clone(),
        f.socket.parent().unwrap().to_path_buf(),
    ] {
        let output = f.launch(&["exit", "0"]).current_dir(root).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("code directory"));
    }
    assert_eq!(f.output(&["exit", "23"]).status.code(), Some(23));
    assert_eq!(f.output(&["terminate"]).status.code(), Some(5));
    let output = f
        .launch(&["exit", "0"])
        .stdout(Stdio::null())
        .output()
        .unwrap();
    succeeds(&output);
}

#[test]
fn sandbox_rejects_apfs_and_case_aliases_of_protected_trees() {
    use std::os::unix::fs::MetadataExt;
    let f = Fixture::new();
    let data = Path::new("/System/Volumes/Data");
    let alias = data.join(f.state.strip_prefix("/").unwrap());
    let ordinary = fs::metadata(&f.state).unwrap();
    let aliased = fs::metadata(&alias).unwrap();
    assert_eq!(
        (ordinary.dev(), ordinary.ino()),
        (aliased.dev(), aliased.ino())
    );
    // Reversed spelling: the protected state uses Data-volume spelling while
    // the read-only code grant is the ordinary ancestor containing the canary.
    let mut alternate = Fixture::new();
    alternate.state = data.join(alternate.state.strip_prefix("/").unwrap());
    let output = alternate
        .launch(&["read", alternate.state.join("secret").to_str().unwrap()])
        .current_dir(alternate.root.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    // An Admin endpoint inside state cannot masquerade as a disjoint Agent
    // endpoint through the alternate Data-volume spelling, even for same UID.
    let mut endpoint_alias = Fixture::new();
    let protected_socket = endpoint_alias.state.join("admin.sock");
    let _admin = UnixListener::bind(&protected_socket).unwrap();
    endpoint_alias.socket = data.join(protected_socket.strip_prefix("/").unwrap());
    let output = endpoint_alias.launch(&["exit", "0"]).output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    // CWD may be normalized by getcwd; both directions still must fail closed.
    for root in [
        data.to_path_buf(),
        data.join("private/tmp"),
        alias.parent().unwrap().to_path_buf(),
        PathBuf::from("/System"),
    ] {
        let output = f
            .launch(&["read", f.state.join("secret").to_str().unwrap()])
            .current_dir(root)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
    // Existing differently-cased paths on this filesystem must not bypass it.
    let case_alias = PathBuf::from(f.state.to_str().unwrap().replace("/private/", "/PRIVATE/"));
    if case_alias.exists() {
        let output = f
            .launch(&["exit", "0"])
            .arg("unused")
            .current_dir(case_alias)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn sandbox_executes_authorized_action_through_real_broker() {
    let broker = common::start_broker_disjoint().await;
    common::unlock(&broker).await;
    let secret = b"seatbelt-credential-canary";
    let credential = common::add_credential(&broker, "seatbelt", secret).await;
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
    assert_eq!(requests[0].auth_value, b"Bearer seatbelt-credential-canary");
    broker.shutdown().await;
}
