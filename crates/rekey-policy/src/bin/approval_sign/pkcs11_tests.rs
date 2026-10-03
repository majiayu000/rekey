//! Injected and pure contract tests; no physical token acceptance is claimed.
use super::super::{
    Ed25519KeyPair, KeyPair, SystemRandom, Timestamp, now, parse_and_verify_approval_grant,
    parse_and_verify_policy_bundle, parse_policy_trust, run_args,
};
use super::*;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tempfile::TempDir;

static SERIAL: Mutex<()> = Mutex::new(());

fn id() -> String {
    let mut bytes = [0u8; 16];
    aws_lc_rs::rand::SecureRandom::fill(&SystemRandom::new(), &mut bytes).unwrap();
    uuid::Uuid::from_bytes(bytes).to_string()
}
fn now_ms() -> i64 {
    now().unwrap().as_unix_ms()
}

#[test]
fn pkcs11_help_names_explicit_private_profile() {
    let _serial = SERIAL.lock().unwrap();
    let mut output = Vec::new();
    run_args(vec!["--help".into()], &mut output).unwrap();
    assert!(
        String::from_utf8(output)
            .unwrap()
            .contains("--pkcs11-profile")
    );
}

impl Fixture {
    fn profile(&self) -> Value {
        let key = Ed25519KeyPair::from_pkcs8(&self.approver_der).unwrap();
        json!({"record_type":"rekey.pkcs11.approval.v1","library_path":self.path("never-loaded-module.so").canonicalize().unwrap().display().to_string(),
               "library_sha256":HEXLOWER.encode(&Sha256::digest(b"not a PKCS11 module")),"library_version":{"major":1,"minor":2},
               "slot_id":7,"token_serial":"SYNTHETIC-TOKEN","key_id":"a1","public_key":HEXLOWER.encode(key.public_key().as_ref())})
    }
    fn save_profile(&self, value: &Value) {
        write_json(&self.path("pkcs11.json"), value);
        fs::set_permissions(self.path("pkcs11.json"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fn args(&self, sign: bool, digest: &str) -> Vec<String> {
        let mut args = vec![
            if sign { "sign".into() } else { "review".into() },
            self.path("request.json").display().to_string(),
        ];
        for (flag, value) in [
            ("--policy", self.path("policy.json").display().to_string()),
            ("--trust", self.path("trust.json").display().to_string()),
            ("--action", self.path("action.json").display().to_string()),
            ("--approver-id", self.approver.clone()),
            ("--origin-key", self.origin_hex.clone()),
            (
                "--pkcs11-profile",
                self.path("pkcs11.json").display().to_string(),
            ),
        ] {
            args.extend([flag.into(), value]);
        }
        if sign {
            args.extend([
                "--reviewed-sha256".into(),
                digest.into(),
                "--output".into(),
                self.path("grant.json").display().to_string(),
            ]);
        }
        args
    }
    fn review(&self) -> Value {
        let mut output = Vec::new();
        run_args(self.args(false, ""), &mut output).unwrap();
        serde_json::from_slice(&output).unwrap()
    }
    fn sign(&self, digest: &str) -> Result<()> {
        run_args(self.args(true, digest), &mut Vec::new())
    }
}
struct Hook;
impl Drop for Hook {
    fn drop(&mut self) {
        TEST_SIGN.with(|hook| *hook.borrow_mut() = None);
    }
}
fn hook(f: impl FnMut(&[u8], i64) -> Result<Vec<u8>> + 'static) -> Hook {
    TEST_SIGN.with(|hook| *hook.borrow_mut() = Some(Box::new(f)));
    Hook
}

#[test]
fn profile_private_closed_schema_and_public_identity_is_bound_without_module_load() {
    let _serial = SERIAL.lock().unwrap();
    let fixture = Fixture::new();
    let value = fixture.profile();
    fixture.save_profile(&value);
    let review = fixture.review();
    assert_eq!(review["review"]["pkcs11"], value);
    assert!(!fixture.path("grant.json").exists());
    for field in [
        "slot_id",
        "library_sha256",
        "key_id",
        "token_serial",
        "library_version",
    ] {
        let mut altered = value.clone();
        altered[field] = match field {
            "slot_id" => json!(8),
            "library_version" => json!({"major":2,"minor":2}),
            "library_sha256" => json!("0".repeat(64)),
            "key_id" => json!("a2"),
            _ => json!("ANOTHER-TOKEN"),
        };
        fixture.save_profile(&altered);
        assert_ne!(
            fixture.review()["reviewed_sha256"],
            review["reviewed_sha256"]
        );
    }
    fixture.save_profile(&value);
    let path = fixture.path("pkcs11.json");
    for mode in [0o644, 0o400, 0o700] {
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
        assert!(Profile::load(path.to_str().unwrap()).is_err());
    }
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let hard = fixture.path("hard.json");
    fs::hard_link(&path, &hard).unwrap();
    assert!(Profile::load(path.to_str().unwrap()).is_err());
    fs::remove_file(hard).unwrap();
    let link = fixture.path("link.json");
    std::os::unix::fs::symlink(&path, &link).unwrap();
    assert!(Profile::load(link.to_str().unwrap()).is_err());
    for raw in [
        b"{}".as_slice(),
        b"{",
        b"{\"record_type\":\"a\",\"record_type\":\"b\"}",
    ] {
        fs::write(&path, raw).unwrap();
        assert!(Profile::load(path.to_str().unwrap()).is_err());
    }
    let mut extra = value.clone();
    extra["pin"] = json!("SYNTHETIC-PIN-CANARY");
    fixture.save_profile(&extra);
    assert_eq!(
        Profile::load(path.to_str().unwrap())
            .err()
            .unwrap()
            .to_string(),
        PROFILE_ERROR
    );
    fs::write(&path, vec![b' '; 65537]).unwrap();
    assert!(Profile::load(path.to_str().unwrap()).is_err());
}

#[test]
fn wrong_policy_key_and_digest_disagreement_cause_no_signing_effect() {
    let _serial = SERIAL.lock().unwrap();
    let fixture = Fixture::new();
    let original = fixture.profile();
    fixture.save_profile(&original);
    let calls = Arc::new(Mutex::new(0));
    let seen = calls.clone();
    let _hook = hook(move |_, _| {
        *seen.lock().unwrap() += 1;
        Err("SYNTHETIC-PIN-CANARY".into())
    });
    let reviewed = fixture.review();
    let digest = reviewed["reviewed_sha256"].as_str().unwrap();
    assert!(
        fixture
            .sign(&"0".repeat(64))
            .unwrap_err()
            .to_string()
            .contains("reviewed digest mismatch")
    );
    let mut changed = original.clone();
    changed["key_id"] = json!("bb");
    fixture.save_profile(&changed);
    assert!(
        fixture
            .sign(digest)
            .unwrap_err()
            .to_string()
            .contains("reviewed digest mismatch")
    );
    let other = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
    changed["public_key"] = json!(
        HEXLOWER.encode(
            Ed25519KeyPair::from_pkcs8(other.as_ref())
                .unwrap()
                .public_key()
                .as_ref()
        )
    );
    fixture.save_profile(&changed);
    assert!(
        run_args(fixture.args(false, ""), &mut Vec::new())
            .unwrap_err()
            .to_string()
            .contains("does not match policy approver")
    );
    assert_eq!(*calls.lock().unwrap(), 0);
    assert!(!fixture.path("grant.json").exists());
}

#[test]
fn injected_exact_rkapproval_jcs_signature_verified_and_output_private_create_new() {
    let _serial = SERIAL.lock().unwrap();
    let fixture = Fixture::new();
    fixture.save_profile(&fixture.profile());
    let review = fixture.review();
    let digest = review["reviewed_sha256"].as_str().unwrap();
    let key = fixture.approver_der.clone();
    let capture = Arc::new(Mutex::new(Vec::new()));
    let captured = capture.clone();
    let _hook = hook(move |message, _| {
        captured.lock().unwrap().push(message.to_vec());
        Ok(Ed25519KeyPair::from_pkcs8(&key)
            .unwrap()
            .sign(message)
            .as_ref()
            .to_vec())
    });
    fixture.sign(digest).unwrap();
    let bytes = fs::read(fixture.path("grant.json")).unwrap();
    let trust = parse_policy_trust(&fs::read(fixture.path("trust.json")).unwrap()).unwrap();
    let policy = parse_and_verify_policy_bundle(
        &fs::read(fixture.path("policy.json")).unwrap(),
        &trust,
        now().unwrap(),
    )
    .unwrap();
    parse_and_verify_approval_grant(&bytes, policy.snapshot()).unwrap();
    let mut grant: Value = serde_json::from_slice(&bytes).unwrap();
    grant.as_object_mut().unwrap().remove("signature");
    let mut expected = b"RKAPPROVAL\0\x01".to_vec();
    expected.extend(serde_jcs::to_vec(&grant).unwrap());
    assert_eq!(capture.lock().unwrap()[0], expected);
    assert_eq!(
        fs::metadata(fixture.path("grant.json")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(fixture.sign(digest).is_err());
    assert_eq!(fs::read(fixture.path("grant.json")).unwrap(), bytes);
}

#[test]
fn injected_bad_signature_and_failure_never_write_grant() {
    let _serial = SERIAL.lock().unwrap();
    for mode in 0..4 {
        let fixture = Fixture::new();
        fixture.save_profile(&fixture.profile());
        let review = fixture.review();
        let key = fixture.approver_der.clone();
        let _hook = hook(move |message, _| match mode {
            0 => Ok(vec![0; 63]),
            1 => Ok(vec![0; 64]),
            2 => Err("SYNTHETIC-PIN-CANARY".into()),
            _ => Ok(Ed25519KeyPair::from_pkcs8(&key)
                .unwrap()
                .sign(message)
                .as_ref()
                .to_vec()),
        });
        if mode == 3 {
            let path = fixture.path("grant.json");
            std::os::unix::fs::symlink(fixture.path("never-write"), path).unwrap();
        }
        assert!(
            fixture
                .sign(review["reviewed_sha256"].as_str().unwrap())
                .is_err()
        );
        assert!(!fixture.path("grant.json").is_file());
    }
}

#[test]
fn injected_late_valid_signature_expired_challenge_never_writes_grant() {
    let _serial = SERIAL.lock().unwrap();
    let fixture = Fixture::new();
    fixture.save_profile(&fixture.profile());
    let mut request: Value =
        serde_json::from_slice(&fs::read(fixture.path("request.json")).unwrap()).unwrap();
    let mut inner = request["challenge"]["challenge"].clone();
    inner["max_expires_at_ms"] = json!(now_ms() + 250);
    let origin = Ed25519KeyPair::from_pkcs8(&fixture.origin_der).unwrap();
    request["challenge"] = signed_envelope(&inner, &origin);
    write_json(&fixture.path("request.json"), &request);
    let reviewed = fixture.review();
    let key = fixture.approver_der.clone();
    let _hook = hook(move |message, _| {
        std::thread::sleep(Duration::from_millis(300));
        Ok(Ed25519KeyPair::from_pkcs8(&key)
            .unwrap()
            .sign(message)
            .as_ref()
            .to_vec())
    });
    assert!(
        fixture
            .sign(reviewed["reviewed_sha256"].as_str().unwrap())
            .unwrap_err()
            .to_string()
            .contains("expired while signing")
    );
    assert!(!fixture.path("grant.json").exists());
}

#[test]
fn key_restrictions_fixed_curve_and_no_private_value_attributes() {
    let _serial = SERIAL.lock().unwrap();
    let attrs = vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sign(true),
        Attribute::Sensitive(true),
        Attribute::AlwaysSensitive(true),
        Attribute::NeverExtractable(true),
        Attribute::Extractable(false),
        Attribute::AlwaysAuthenticate(false),
        Attribute::EcParams(CURVE.to_vec()),
    ];
    restrictions(&attrs).unwrap();
    assert_eq!(CURVE, b"\x13\x0cedwards25519");
    for index in 0..attrs.len() {
        let mut bad = attrs.clone();
        bad.remove(index);
        assert!(restrictions(&bad).is_err());
    }
    for forbidden in [
        Attribute::Extractable(true),
        Attribute::AlwaysAuthenticate(true),
        Attribute::EcParams(vec![6, 3, 43, 101, 112]),
        Attribute::Value(vec![1]),
    ] {
        let mut bad = attrs.clone();
        bad.push(forbidden);
        assert!(restrictions(&bad).is_err());
    }
    let mechanism = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519));
    assert_eq!(
        mechanism.mechanism_type(),
        cryptoki::mechanism::MechanismType::EDDSA
    );
}

#[test]
fn library_hash_real_file_changed_content_and_unsafe_ancestor() {
    let _serial = SERIAL.lock().unwrap();
    let fixture = Fixture::new();
    let profile: Profile = serde_json::from_value(fixture.profile()).unwrap();
    assert_eq!(
        library_hash(
            &profile.library_path,
            &Deadline::new(now_ms() + 1000).unwrap()
        )
        .unwrap(),
        profile.library_sha256
    );
    fs::write(&profile.library_path, b"replacement").unwrap();
    assert_ne!(
        library_hash(
            &profile.library_path,
            &Deadline::new(now_ms() + 1000).unwrap()
        )
        .unwrap(),
        profile.library_sha256
    );
    let dir = Path::new(&profile.library_path).parent().unwrap();
    fs::set_permissions(dir, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        library_hash(
            &profile.library_path,
            &Deadline::new(now_ms() + 1000).unwrap()
        )
        .is_err()
    );
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn deadlines_socket_frame_bounds_peer_rejection_and_tty_regular_file_reject() {
    let _serial = SERIAL.lock().unwrap();
    assert!(Deadline::new(now_ms() - 1).is_err());
    let fixture = Fixture::new();
    let profile: Profile = serde_json::from_value(fixture.profile()).unwrap();
    let expired = Deadline {
        until: Instant::now(),
        expires_at_ms: now_ms() + 1000,
    };
    assert!(library_hash(&profile.library_path, &expired).is_err());
    let deadline = Deadline {
        until: Instant::now(),
        expires_at_ms: now_ms() + 1000,
    };
    assert!(deadline.check().is_err());
    let (mut one, two) = UnixStream::pair().unwrap();
    one.set_nonblocking(true).unwrap();
    two.set_nonblocking(true).unwrap();
    assert!(parent_identity(&one).is_err());
    let deadline = Deadline {
        until: Instant::now() + Duration::from_millis(30),
        expires_at_ms: now_ms() + 1000,
    };
    assert!(receive(&mut one, &mut [0u8; 1], &deadline).is_err());
    drop(two);
    let deadline = Deadline::new(now_ms() + 1000).unwrap();
    assert!(send(&mut one, b"SYNTHETIC-PIN-CANARY", &deadline).is_err());
    let tempfile = tempfile::tempfile().unwrap();
    assert!(read_pin_from(tempfile, &deadline).is_err());
}

#[test]
fn object_selection_is_bounded_at_two_and_duplicate_or_sdk_error_rejects() {
    let _serial = SERIAL.lock().unwrap();
    use cryptoki::object::ObjectHandle;
    assert!(select_one(std::iter::empty()).is_err());
    let one = unsafe { ObjectHandle::new_from_raw(1) };
    assert_eq!(select_one(std::iter::once(Ok(one))).unwrap(), one);
    let count = std::cell::Cell::new(0);
    let stream = std::iter::repeat_with(|| {
        count.set(count.get() + 1);
        Ok(one)
    });
    assert!(select_one(stream).is_err());
    assert_eq!(count.get(), 2);
    assert!(
        select_one(std::iter::once(Err(
            cryptoki::error::Error::NullFunctionPointer
        )))
        .is_err()
    );
}

#[test]
fn malformed_closed_late_child_frames_fail_guard_kills_and_reaps() {
    let _serial = SERIAL.lock().unwrap();
    for wire in [vec![0], vec![1, 2], vec![1; 66], Vec::new()] {
        let (mut parent, mut child) = UnixStream::pair().unwrap();
        parent.set_nonblocking(true).unwrap();
        let writer = std::thread::spawn(move || {
            child.write_all(&wire).unwrap();
        });
        let mut command = Command::new("/usr/bin/python3");
        command
            .args(["-c", "import time;time.sleep(60)"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let deadline = Deadline {
            until: Instant::now() + Duration::from_millis(50),
            expires_at_ms: now_ms() + 1000,
        };
        let mut guard = ChildGuard {
            child: command.spawn().unwrap(),
            reaped: false,
            deadline: deadline.clone(),
        };
        let pid = guard.child.id() as i32;
        assert!(response(&mut parent, &mut guard, &deadline).is_err());
        drop(guard);
        writer.join().unwrap();
        let mut status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    let (mut parent, _child) = UnixStream::pair().unwrap();
    parent.set_nonblocking(true).unwrap();
    let deadline = Deadline {
        until: Instant::now() + Duration::from_millis(20),
        expires_at_ms: now_ms() + 1000,
    };
    assert!(receive(&mut parent, &mut [0u8; 1], &deadline).is_err());
}

#[test]
fn actual_synthetic_pty_pin_hidden_bounded_utf8_timeout_and_metadata_restore() {
    let _serial = SERIAL.lock().unwrap();
    fn pair() -> (File, File) {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0,
            "actual PTY prerequisite failed; never a skipped PASS"
        );
        let slave_file = unsafe { File::from_raw_fd(slave) };
        let master_file = unsafe { File::from_raw_fd(master) };
        let flags = unsafe { libc::fcntl(slave, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(slave, libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        (master_file, slave_file)
    }
    for input in [
        b"SYNTHETIC-PIN-CANARY\n".to_vec(),
        vec![b'a'; 129],
        vec![255, b'\n'],
        Vec::new(),
    ] {
        let (mut master, slave) = pair();
        let observed = slave.try_clone().unwrap();
        let mut before = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observed.as_raw_fd(), &mut before) },
            0
        );
        let deadline = Deadline {
            until: Instant::now() + Duration::from_millis(250),
            expires_at_ms: now_ms() + 1000,
        };
        let reader = std::thread::spawn(move || {
            read_pin_from(slave, &deadline)
                .map(|pin| pin.len())
                .map_err(|_| ())
        });
        let mut prompt = [0u8; 12];
        master.read_exact(&mut prompt).unwrap();
        assert_eq!(&prompt, b"PKCS11 PIN: ");
        let mut hidden = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observed.as_raw_fd(), &mut hidden) },
            0
        );
        assert_eq!(hidden.c_lflag & libc::ECHO, 0);
        if !input.is_empty() {
            master.write_all(&input).unwrap();
            if input.len() == 129 {
                master.write_all(b"\n").unwrap();
            }
        }
        let result = reader.join().unwrap();
        assert_eq!(result.is_ok(), input == b"SYNTHETIC-PIN-CANARY\n");
        let mut after = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::tcgetattr(observed.as_raw_fd(), &mut after) },
            0
        );
        assert_eq!(after.c_lflag, before.c_lflag);
        assert_eq!(after.c_iflag, before.c_iflag);
        assert_eq!(after.c_oflag, before.c_oflag);
        assert_eq!(after.c_cflag, before.c_cflag);
        assert_eq!(after.c_cc, before.c_cc);
    }
}

#[test]
fn pure_profile_rejects_noncanonical_path_and_signing_sources_are_exclusive() {
    let _serial = SERIAL.lock().unwrap();
    let fixture = Fixture::new();
    let mut value = fixture.profile();
    for path in [
        "relative.so",
        "/x/../module.so",
        "/x/./module.so",
        "/x/.",
        "//module.so",
        "/x/module.so/",
    ] {
        value["library_path"] = json!(path);
        fixture.save_profile(&value);
        assert!(Profile::load(fixture.path("pkcs11.json").to_str().unwrap()).is_err());
    }
    fixture.save_profile(&fixture.profile());
    let mut args = fixture.args(false, "");
    args.extend(["--vault-transit-profile".into(), "never-read".into()]);
    assert_eq!(
        run_args(args, &mut Vec::new()).unwrap_err().to_string(),
        super::super::USAGE
    );
    let mut args = fixture.args(true, &"0".repeat(64));
    args.extend(["--key-file".into(), "never-read".into()]);
    assert_eq!(
        run_args(args, &mut Vec::new()).unwrap_err().to_string(),
        super::super::USAGE
    );
}

#[test]
fn actual_handled_sigterm_restores_synthetic_tty_and_original_handlers() {
    let _serial = SERIAL.lock().unwrap();
    // Observe libc's installed representation as the baseline. On Linux x86_64,
    // even reinstalling SIG_DFL adds glibc's SA_RESTORER trampoline flag:
    // glibc/sysdeps/unix/sysv/linux/x86_64/libc_sigaction.c, SET_SA_RESTORER.
    // Keep exact flag equality below instead of masking restoration mistakes.
    for signal in [libc::SIGINT, libc::SIGTERM, libc::SIGHUP, libc::SIGQUIT] {
        let mut original = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(signal, std::ptr::null(), &mut original) },
            0
        );
        assert_eq!(
            unsafe { libc::sigaction(signal, &original, std::ptr::null_mut()) },
            0
        );
    }
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    let mut master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    let observed = slave.try_clone().unwrap();
    let flags = unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(slave.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut before = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(observed.as_raw_fd(), &mut before) },
        0
    );
    let mut signals = Signals::install().unwrap();
    let saved = signals.previous.clone();
    let interruptor = std::thread::spawn(move || {
        let mut poll = libc::pollfd {
            fd: master.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 500) }, 1);
        let mut prompt = [0; 12];
        master.read_exact(&mut prompt).unwrap();
        assert_eq!(&prompt, b"PKCS11 PIN: ");
        assert_eq!(unsafe { libc::kill(libc::getpid(), libc::SIGTERM) }, 0);
        master
    });
    let deadline = Deadline::new(now_ms() + 1000).unwrap();
    let result = read_pin_from(slave, &deadline);
    let _master = interruptor.join().unwrap();
    signals.restore().unwrap();
    INTERRUPTED.store(false, Ordering::SeqCst);
    assert!(result.is_err());
    let mut after = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::tcgetattr(observed.as_raw_fd(), &mut after) },
        0
    );
    assert_eq!(before.c_lflag, after.c_lflag);
    assert_eq!(before.c_cc, after.c_cc);
    for (signal, old) in saved {
        let mut actual = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(signal, std::ptr::null(), &mut actual) },
            0
        );
        assert_eq!(actual.sa_sigaction, old.sa_sigaction);
        assert_eq!(actual.sa_flags, old.sa_flags);
    }
}

#[test]
fn restoration_window_caught_interrupt_cannot_return_success() {
    let _serial = SERIAL.lock().unwrap();
    let deadline = Deadline::new(now_ms() + 1000).unwrap();
    let mut signals = Signals::install().unwrap();
    deadline.check().unwrap();
    TEST_RESTORE_WINDOW
        .with(|hook| *hook.borrow_mut() = Some(Box::new(|| interrupt(libc::SIGTERM))));
    let result = finish_signing(&mut signals, &deadline, Ok(vec![1; 64]));
    TEST_RESTORE_WINDOW.with(|hook| *hook.borrow_mut() = None);
    INTERRUPTED.store(false, Ordering::SeqCst);
    assert!(
        result.is_err(),
        "caught interruption during final restoration returned success"
    );
}

#[test]
fn injected_kill_ack_pending_cleanup_obeys_original_budget_not_hardware_evidence() {
    let _serial = SERIAL.lock().unwrap();
    let mut command = Command::new("/usr/bin/python3");
    command
        .args(["-c", "import time;time.sleep(.3)"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let deadline = Deadline {
        until: Instant::now() + Duration::from_millis(20),
        expires_at_ms: now_ms() + 1000,
    };
    let guard = ChildGuard {
        child: command.spawn().unwrap(),
        reaped: false,
        deadline,
    };
    let pid = guard.child.id() as i32;
    // Simulates accepted kill with a still-pending child, never an actual driver D-state.
    TEST_KILL_ACK_PENDING.with(|pending| pending.set(true));
    let started = Instant::now();
    drop(guard);
    let elapsed = started.elapsed();
    TEST_KILL_ACK_PENDING.with(|pending| pending.set(false));
    // The injected pending case returns without claiming synchronous reaping.
    if elapsed < Duration::from_millis(150) {
        let mut pending_status = 0;
        assert_eq!(
            unsafe { libc::waitpid(pid, &mut pending_status, libc::WNOHANG) },
            0
        );
    }
    // Fixture-owned process cleanup uses nonblocking checks, outside production cleanup.
    unsafe {
        libc::kill(-pid, libc::SIGKILL);
    }
    let cleanup = Instant::now() + Duration::from_secs(1);
    let mut status = 0;
    loop {
        let n = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if n == pid || n < 0 {
            break;
        }
        assert!(Instant::now() < cleanup);
        std::thread::sleep(Duration::from_millis(2));
    }
    assert!(
        elapsed < Duration::from_millis(150),
        "cleanup exceeded original budget: {elapsed:?}"
    );
}

#[test]
fn restoration_window_expiration_cannot_return_success() {
    let _serial = SERIAL.lock().unwrap();
    let deadline = Deadline {
        until: Instant::now() + Duration::from_millis(10),
        expires_at_ms: now_ms() + 1000,
    };
    let mut signals = Signals::install().unwrap();
    deadline.check().unwrap();
    TEST_RESTORE_WINDOW.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(|| std::thread::sleep(Duration::from_millis(20))))
    });
    let result = finish_signing(&mut signals, &deadline, Ok(vec![1; 64]));
    TEST_RESTORE_WINDOW.with(|hook| *hook.borrow_mut() = None);
    assert!(result.is_err());
}

fn write_json(path: &std::path::Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}
fn signed_envelope(challenge: &Value, origin: &Ed25519KeyPair) -> Value {
    let mut message = b"RKCHALLENGE\0\x02".to_vec();
    message.extend(serde_jcs::to_vec(challenge).unwrap());
    json!({
        "record_type": "rekey.approval.challenge.envelope.v2",
        "challenge": challenge,
        "signature": BASE64URL_NOPAD.encode(origin.sign(&message).as_ref()),
    })
}
struct Fixture {
    dir: TempDir,
    approver: String,
    origin_hex: String,
    origin_der: Vec<u8>,
    approver_der: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("never-loaded-module.so"),
            b"not a PKCS11 module",
        )
        .unwrap();
        let signer_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let signer = Ed25519KeyPair::from_pkcs8(signer_der.as_ref()).unwrap();
        let approver_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let key = Ed25519KeyPair::from_pkcs8(approver_der.as_ref()).unwrap();
        let origin_der = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let origin = Ed25519KeyPair::from_pkcs8(origin_der.as_ref()).unwrap();
        let origin_hex = HEXLOWER.encode(origin.public_key().as_ref());
        fs::write(dir.path().join("key.der"), approver_der.as_ref()).unwrap();
        fs::set_permissions(
            dir.path().join("key.der"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        let signer_id = id();
        let approver = id();
        let action_id = id();
        let principal = id();
        let rule = id();
        let created = now_ms();
        let policy_expiry = created + 300_000;
        let trust = json!({"format_version":1,"signer_id":signer_id,"algorithm":"ed25519","public_key":HEXLOWER.encode(signer.public_key().as_ref())});
        let resource = json!({"type":"test.resource","id":"one"});
        let snapshot = json!({"format_version":4,"version":1,"expires_at_ms":policy_expiry,
            "approvers":[{"approver_id":approver,"algorithm":"ed25519","public_key":HEXLOWER.encode(key.public_key().as_ref())}],
            "workload_identities":[],"bindings":[{"action_id":action_id,"version":1,"resource":resource,"parameter_schema_id":"test/v1","parameter_schema":{"type":"object","required":["message"],"properties":{"message":{"type":"string"}},"additionalProperties":false}}],
            "rules":[{"id":rule,"effect":"require-approval","principal_id":principal,"action_id":action_id,"version":1,"resource":resource,"parameters":{"kind":"any_validated"},"approver":{"kind":"ed25519","keys":[HEXLOWER.encode(key.public_key().as_ref())],"threshold":1},"approval":{"mode":"one-time","max_uses":1}}]});
        let mut bundle = json!({"format_version":1,"signer_id":signer_id,"snapshot":snapshot});
        let mut message = b"RKPOLICY\0\x01".to_vec();
        message.extend(serde_jcs::to_vec(&bundle).unwrap());
        bundle["signature"] = BASE64URL_NOPAD
            .encode(signer.sign(&message).as_ref())
            .into();
        write_json(&dir.path().join("trust.json"), &trust);
        write_json(&dir.path().join("policy.json"), &bundle);
        let verified = parse_and_verify_policy_bundle(
            &serde_json::to_vec(&bundle).unwrap(),
            &parse_policy_trust(&serde_json::to_vec(&trust).unwrap()).unwrap(),
            Timestamp::from_unix_ms(created),
        )
        .unwrap();
        let action = json!({"id":action_id,"name":"approval-test","version":1,"enabled":true,"credential_id":id(),"origin":"https://example.com","method":"POST","target":{"kind":"fixed","path":"/approved"},"auth":{"header_name":"authorization","prefix":"Bearer "},"timeout_ms":5000,"request_policy":{"max_body_bytes":4096,"allowed_extra_headers":[]},"response_policy":{"max_body_bytes":4096,"allowed_headers":[]}});
        let parsed: rekey_domain::action::FixedHttpAction =
            serde_json::from_value(action.clone()).unwrap();
        parsed.validate().unwrap();
        write_json(&dir.path().join("action.json"), &action);
        let body = r#"{"message":"approved"}"#;
        let (_, parameters, _) = verified
            .snapshot()
            .canonicalize(
                &parsed,
                rekey_policy::ActionRequest {
                    params: &Default::default(),
                    query: &Default::default(),
                    content_type: Some("application/json"),
                    headers: &[],
                    body: body.as_bytes(),
                },
            )
            .unwrap();
        let inner = json!({"record_type":"rekey.approval.challenge.v2","approval_request_id":id(),"tenant_id":id(),"principal_id":principal,"session_id":id(),"action_id":action_id,"action_version":1,"resource":resource,"schema_id":"test/v1","parameter_sha256":HEXLOWER.encode(&parameters.canonical_hash),"policy_version":1,"policy_sha256":HEXLOWER.encode(&verified.policy_digest()),"policy_rule_id":rule,"mode":"one-time","approver":{"kind":"ed25519","keys":[HEXLOWER.encode(key.public_key().as_ref())],"threshold":1},"max_uses":1,"created_at_ms":created,"max_expires_at_ms":created+120_000});
        let request = json!({"challenge":signed_envelope(&inner, &origin),"content_type":"application/json","headers":[],"body":body});
        write_json(&dir.path().join("request.json"), &request);
        Self {
            dir,
            approver,
            origin_hex,
            origin_der: origin_der.as_ref().to_vec(),
            approver_der: approver_der.as_ref().to_vec(),
        }
    }
    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}
