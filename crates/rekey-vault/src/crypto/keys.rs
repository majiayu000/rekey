use std::fmt;

use secrecy::{ExposeSecret, SecretBox};
use zeroize::Zeroize;

use crate::error::AuthorityError;

macro_rules! key_type {
    ($(#[$doc:meta])* $name:ident, $storage:ty) => {
        $(#[$doc])*
        pub struct $name($storage);

        impl $name {
            pub fn generate() -> Result<Self, AuthorityError> {
                let mut bytes = super::random_array()?;
                Ok(Self::from_bytes(&mut bytes))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    };
}

key_type!(
    /// Key-encryption key derived from a password or recovery key. Only ever
    /// wraps and unwraps the VRK; never touches credential payloads.
    Kek, SecretBox<[u8; super::KEY_LEN]>
);

impl Kek {
    /// Copies bytes into protected ownership and zeroizes the caller buffer.
    pub fn from_bytes(bytes: &mut [u8; super::KEY_LEN]) -> Self {
        let boxed = SecretBox::new(Box::new(*bytes));
        bytes.zeroize();
        Self(boxed)
    }

    pub(crate) fn bytes(&self) -> &[u8; super::KEY_LEN] {
        self.0.expose_secret()
    }
}

#[cfg(not(target_os = "linux"))]
type ResidentKey = SecretBox<[u8; super::KEY_LEN]>;

// Linux locks are per page and do not stack. A separate mapping prevents a
// short-lived DEK's release from unlocking a page shared with a live VRK.
#[cfg(target_os = "linux")]
struct ResidentKey {
    pointer: std::ptr::NonNull<[u8; super::KEY_LEN]>,
    kind: &'static str,
}

// SAFETY: the mapping has one owner, is immutable after construction, and is
// unmapped only through exclusive Drop. No writable pointer escapes this type.
#[cfg(target_os = "linux")]
unsafe impl Send for ResidentKey {}
// SAFETY: shared access only yields immutable references; mutation is limited
// to construction and exclusive Drop, with no interior mutability.
#[cfg(target_os = "linux")]
unsafe impl Sync for ResidentKey {}

#[cfg(target_os = "linux")]
impl ResidentKey {
    fn from_bytes(bytes: &mut [u8; super::KEY_LEN], kind: &'static str) -> Self {
        // SAFETY: anonymous mmap chooses a fresh page-aligned mapping. KEY_LEN
        // is nonzero; no existing mapping or file descriptor is supplied.
        let mapped = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                super::KEY_LEN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if mapped == libc::MAP_FAILED {
            std::alloc::handle_alloc_error(std::alloc::Layout::new::<[u8; super::KEY_LEN]>());
        }
        let pointer = std::ptr::NonNull::new(mapped.cast()).unwrap_or_else(|| {
            std::alloc::handle_alloc_error(std::alloc::Layout::new::<[u8; super::KEY_LEN]>())
        });
        let mut key = Self { pointer, kind };
        // SAFETY: the complete range belongs to the live mapping. Try locking
        // while it still contains only zeros, before copying the secret.
        if unsafe { libc::mlock(mapped, super::KEY_LEN) } != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            tracing::warn!(event = "vault.key_mlock_failed", key_kind = kind, errno);
        }
        // SAFETY: this newly-created owner has exclusive access to KEY_LEN
        // initialized writable bytes; the mapping outlives the copy.
        unsafe { key.pointer.as_mut() }.copy_from_slice(bytes);
        bytes.zeroize();
        key
    }

    fn bytes(&self) -> &[u8; super::KEY_LEN] {
        // SAFETY: the owner keeps the mapping live; only immutable references
        // are exposed, and their lifetimes cannot outlive this borrow.
        unsafe { self.pointer.as_ref() }
    }
}

#[cfg(target_os = "linux")]
impl Drop for ResidentKey {
    fn drop(&mut self) {
        // SAFETY: Drop has exclusive access and the mapping is still live.
        unsafe { self.pointer.as_mut() }.zeroize();
        // SAFETY: this is the original mmap address and length. munmap also
        // removes its page lock, after zeroization; no separate munlock needed.
        if unsafe { libc::munmap(self.pointer.as_ptr().cast(), super::KEY_LEN) } != 0 {
            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            tracing::warn!(
                event = "vault.key_munmap_failed",
                key_kind = self.kind,
                errno
            );
        }
    }
}

macro_rules! resident_key_type {
    ($(#[$doc:meta])* $name:ident, $kind:literal) => {
        key_type!($(#[$doc])* $name, ResidentKey);

        impl $name {
            /// Copies bytes into protected ownership and zeroizes the caller buffer.
            pub fn from_bytes(bytes: &mut [u8; super::KEY_LEN]) -> Self {
                #[cfg(target_os = "linux")]
                let key = ResidentKey::from_bytes(bytes, $kind);
                #[cfg(not(target_os = "linux"))]
                let key = {
                    let boxed = SecretBox::new(Box::new(*bytes));
                    bytes.zeroize();
                    boxed
                };
                Self(key)
            }

            pub(crate) fn bytes(&self) -> &[u8; super::KEY_LEN] {
                #[cfg(target_os = "linux")]
                { self.0.bytes() }
                #[cfg(not(target_os = "linux"))]
                { self.0.expose_secret() }
            }
        }
    };
}

resident_key_type!(
    /// Vault Root Key. Exists in memory only inside the AuthorityWorker while
    /// the vault is unlocked.
    RootKey, "vrk"
);
resident_key_type!(
    /// Per-credential-version data encryption key.
    DataKey, "dek"
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_ownership_preserves_bytes_erases_inputs_and_redacts_debug() {
        let mut input = [0x5a; super::super::KEY_LEN];
        let root = RootKey::from_bytes(&mut input);
        assert!(input.iter().all(|byte| *byte == 0));
        let address = root.bytes().as_ptr();
        let moved = Box::new(root);
        assert!(address == moved.bytes().as_ptr());
        assert!(moved.bytes().iter().all(|byte| *byte == 0x5a));
        assert_eq!(format!("{moved:?}"), "RootKey([REDACTED])");

        input.fill(0x3c);
        let dek = DataKey::from_bytes(&mut input);
        assert!(input.iter().all(|byte| *byte == 0));
        assert!(dek.bytes().iter().all(|byte| *byte == 0x3c));
        assert_eq!(format!("{dek:?}"), "DataKey([REDACTED])");

        input.fill(0x7e);
        let kek = Kek::from_bytes(&mut input);
        assert!(input.iter().all(|byte| *byte == 0));
        assert!(kek.bytes().iter().all(|byte| *byte == 0x7e));
        assert_eq!(format!("{kek:?}"), "Kek([REDACTED])");
    }

    #[cfg(target_os = "linux")]
    mod linux {
        use super::*;
        use std::collections::BTreeMap;
        use std::sync::{Arc, Mutex};
        use tracing::{Event, Metadata, Subscriber, field, span};

        const CHILD: &str = "REKEY_KEY_MEMORY_TEST_CHILD";

        fn child_or_run(test: &str) -> bool {
            if std::env::var(CHILD).as_deref() == Ok(test) {
                println!("entered isolated key-memory test");
                return true;
            }
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", test, "--nocapture", "--test-threads=1"])
                .env(CHILD, test)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "isolated child failed:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr),
            );
            let stdout = String::from_utf8_lossy(&output.stdout);
            assert!(stdout.contains("entered isolated key-memory test"));
            assert!(stdout.contains("test result: ok. 1 passed;"));
            false
        }

        fn status_field(name: &str) -> String {
            std::fs::read_to_string("/proc/self/status")
                .unwrap()
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap()
                .trim()
                .to_owned()
        }

        fn locked_bytes() -> usize {
            status_field("VmLck:")
                .split_whitespace()
                .next()
                .unwrap()
                .parse::<usize>()
                .unwrap()
                * 1024
        }

        #[test]
        fn independent_pages_survive_other_key_drop() {
            if !child_or_run(
                concat!(module_path!(), "::independent_pages_survive_other_key_drop")
                    .strip_prefix("rekey_vault::")
                    .unwrap(),
            ) {
                return;
            }
            // SAFETY: sysconf reads the page size and changes no process state.
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            assert!(page_size > 0);
            let page_size = page_size as usize;
            let baseline = locked_bytes();
            let root = RootKey::from_bytes(&mut [0x5a; super::super::super::KEY_LEN]);
            let dek = DataKey::from_bytes(&mut [0x3c; super::super::super::KEY_LEN]);
            assert!(
                root.bytes().as_ptr() as usize / page_size
                    != dek.bytes().as_ptr() as usize / page_size
            );
            assert_eq!(
                locked_bytes(),
                baseline + 2 * page_size,
                "Linux test requires memlock allowance for two pages"
            );
            drop(dek);
            assert_eq!(locked_bytes(), baseline + page_size);
            assert!(root.bytes().iter().all(|byte| *byte == 0x5a));
            drop(root);
            assert_eq!(locked_bytes(), baseline);
        }

        #[derive(Default)]
        struct Fields(BTreeMap<String, String>);

        impl field::Visit for Fields {
            fn record_str(&mut self, field: &field::Field, value: &str) {
                self.0.insert(field.name().to_owned(), value.to_owned());
            }

            fn record_debug(&mut self, field: &field::Field, value: &dyn fmt::Debug) {
                self.0.insert(field.name().to_owned(), format!("{value:?}"));
            }
        }

        struct Warnings(Arc<Mutex<Vec<Fields>>>);

        impl Subscriber for Warnings {
            fn enabled(&self, metadata: &Metadata<'_>) -> bool {
                *metadata.level() == tracing::Level::WARN
            }
            fn new_span(&self, _: &span::Attributes<'_>) -> span::Id {
                span::Id::from_u64(1)
            }
            fn record(&self, _: &span::Id, _: &span::Record<'_>) {}
            fn record_follows_from(&self, _: &span::Id, _: &span::Id) {}
            fn enter(&self, _: &span::Id) {}
            fn exit(&self, _: &span::Id) {}
            fn event(&self, event: &Event<'_>) {
                let mut fields = Fields::default();
                event.record(&mut fields);
                self.0.lock().unwrap().push(fields);
            }
        }

        #[test]
        fn zero_memlock_limit_warns_without_blocking_key_use() {
            if !child_or_run(
                concat!(
                    module_path!(),
                    "::zero_memlock_limit_warns_without_blocking_key_use"
                )
                .strip_prefix("rekey_vault::")
                .unwrap(),
            ) {
                return;
            }
            let capabilities = u64::from_str_radix(&status_field("CapEff:"), 16).unwrap();
            assert_eq!(
                capabilities & (1 << 14),
                0,
                "run this test without CAP_IPC_LOCK, which bypasses RLIMIT_MEMLOCK"
            );
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: only this dedicated child lowers its own memlock limit.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
            let baseline = locked_bytes();
            let warnings = Arc::new(Mutex::new(Vec::new()));
            tracing::subscriber::with_default(Warnings(warnings.clone()), || {
                let mut bytes = [0x5a; super::super::super::KEY_LEN];
                let root = RootKey::from_bytes(&mut bytes);
                assert!(bytes.iter().all(|byte| *byte == 0));
                bytes.fill(0x3c);
                let dek = DataKey::from_bytes(&mut bytes);
                assert!(bytes.iter().all(|byte| *byte == 0));
                let wrapped =
                    crate::crypto::aead::seal(root.bytes(), b"test", dek.bytes()).unwrap();
                let opened = crate::crypto::aead::open(
                    root.bytes(),
                    b"test",
                    &wrapped.nonce,
                    &wrapped.ciphertext,
                )
                .unwrap();
                assert!(opened.as_slice() == dek.bytes());
                assert_eq!(locked_bytes(), baseline);
            });
            let warnings = warnings.lock().unwrap();
            assert_eq!(warnings.len(), 2);
            for (warning, kind) in warnings.iter().zip(["vrk", "dek"]) {
                assert_eq!(warning.0.len(), 3);
                assert_eq!(warning.0["event"], "vault.key_mlock_failed");
                assert_eq!(warning.0["key_kind"], kind);
                assert!(warning.0["errno"].parse::<i32>().unwrap() > 0);
            }
        }
    }
}
