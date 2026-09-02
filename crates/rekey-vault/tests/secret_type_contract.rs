//! Compile-time negative assertions: secret-bearing types must never gain
//! Clone, Copy, Serialize, or Display; Debug must stay redacted.

use rekey_vault::crypto::keys::{DataKey, Kek, RootKey};
use rekey_vault::secret::SecretInput;

/// static_assertions-style negative impl check: compiles only when `$ty`
/// implements none of the listed traits.
macro_rules! assert_not_impl_any {
    ($ty:ty: $($trait:path),+ $(,)?) => {
        const _: fn() = || {
            trait AmbiguousIfImpl<A> {
                fn some_item() {}
            }
            impl<T: ?Sized> AmbiguousIfImpl<()> for T {}
            $({
                #[allow(dead_code)]
                struct Invalid;
                impl<T: ?Sized + $trait> AmbiguousIfImpl<Invalid> for T {}
            })+
            let _ = <$ty as AmbiguousIfImpl<_>>::some_item;
        };
    };
}

assert_not_impl_any!(RootKey: Clone, Copy, std::fmt::Display, serde::Serialize);
assert_not_impl_any!(DataKey: Clone, Copy, std::fmt::Display, serde::Serialize);
assert_not_impl_any!(Kek: Clone, Copy, std::fmt::Display, serde::Serialize);
assert_not_impl_any!(SecretInput: Clone, Copy, std::fmt::Display, serde::Serialize);
assert_not_impl_any!(
    rekey_vault::secret::PreparedCredential: Clone, Copy, std::fmt::Display, serde::Serialize
);

#[test]
fn debug_output_is_redacted_without_length() {
    let input = SecretInput::new(b"super-secret-value".to_vec());
    assert_eq!(format!("{input:?}"), "SecretInput([REDACTED])");

    let mut root_bytes = [7u8; 32];
    let key = RootKey::from_bytes(&mut root_bytes);
    assert_eq!(root_bytes, [0u8; 32]);
    assert_eq!(format!("{key:?}"), "RootKey([REDACTED])");

    let mut data_bytes = [8u8; 32];
    let dk = DataKey::from_bytes(&mut data_bytes);
    assert_eq!(data_bytes, [0u8; 32]);
    assert_eq!(format!("{dk:?}"), "DataKey([REDACTED])");
}

#[test]
fn secret_input_exposes_only_via_explicit_call() {
    let input = SecretInput::new(b"abc".to_vec());
    assert_eq!(input.expose(), b"abc");
    assert!(!input.is_empty());
}
