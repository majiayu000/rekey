//! Exact encrypted reference and the Worker-owned, no-UI native lookup.
use std::path::Path;
use std::time::Instant;

use rekey_domain::ids::{ActionId, CredentialId, RequestId};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::Worker;
use crate::command::AuditDraft;
use crate::error::AuthorityError;
use crate::model::outcome;
use crate::now_ms;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Reference {
    credential_type: String,
    pub(super) keychain_path: String,
    pub(super) service: String,
    pub(super) account: String,
    pub(super) reference_expires_at_ms: i64,
}

fn unavailable() -> AuthorityError {
    AuthorityError::CredentialSourceUnavailable
}

impl Reference {
    pub(super) fn import(bytes: &[u8], now: i64) -> Result<Self, AuthorityError> {
        let reference = Self::decode(bytes)?;
        let safe = |s: &str| !s.is_empty() && !s.chars().any(char::is_control);
        if reference.credential_type != "macos-keychain-source-v1"
            || !safe(&reference.keychain_path)
            || !Path::new(&reference.keychain_path).is_absolute()
            || !safe(&reference.service)
            || !safe(&reference.account)
            || reference.service == "com.starlight.rekey.remembered-unlock"
            || reference
                .reference_expires_at_ms
                .checked_sub(now)
                .is_none_or(|ttl| ttl <= 0)
        {
            return Err(unavailable());
        }
        Ok(reference)
    }
    // Imported references are sealed; do not duplicate validation at execution.
    pub(super) fn decode(bytes: &[u8]) -> Result<Self, AuthorityError> {
        serde_json::from_slice(bytes).map_err(|_| unavailable())
    }
    fn current(&self, deadline: Instant) -> Result<(), AuthorityError> {
        if Instant::now() >= deadline || now_ms()? >= self.reference_expires_at_ms {
            return Err(unavailable());
        }
        Ok(())
    }
}

pub(super) fn validate_value(
    bytes: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
    if bytes.is_empty()
        || bytes.len() > 64 * 1024
        || std::str::from_utf8(&bytes).is_err()
        || bytes.iter().any(|b| !matches!(b, 0x20..=0x7e))
    {
        return Err(unavailable());
    }
    Ok(bytes)
}

impl Worker {
    pub(super) fn resolve_keychain(
        &mut self,
        bytes: Zeroizing<Vec<u8>>,
        credential_id: CredentialId,
        version: u64,
        execution: (RequestId, ActionId, u64, Instant),
    ) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
        let (request_id, action_id, action_version, deadline) = execution;
        let reference = Reference::decode(&bytes)?;
        let check_execution = |worker: &mut Self| -> Result<(), AuthorityError> {
            worker.require_unlocked()?;
            reference.current(deadline)?;
            let credential = worker.load_verified_credential(credential_id)?;
            if credential.state != rekey_domain::credential::CredentialState::Active
                || credential.current_version != version
            {
                return Err(unavailable());
            }
            let action = worker.action_get(action_id, action_version)?;
            if action.state != crate::model::ActionState::Active
                || action.action.credential_id != credential_id
                || action.action.text_stream.is_some()
                || action.action.native_plugin.is_some()
            {
                return Err(unavailable());
            }
            let rows = worker.store.unterminated_executions()?;
            let matches = rows
                .iter()
                .filter(|row| {
                    row.request_id == request_id
                        && row.credential_id == Some(credential_id)
                        && row.action_id == Some(action_id)
                        && row.action_version == Some(action_version)
                })
                .count();
            if matches != 1 {
                return Err(unavailable());
            }
            Ok(())
        };
        check_execution(self)?;
        let digest = format!("{:x}", Sha256::digest(&bytes));
        let audit = |phase: &'static str, result: &'static str| AuditDraft {
            request_id: Some(request_id),
            session_id: None,
            action_id: Some(action_id),
            action_version: Some(action_version),
            credential_id: Some(credential_id),
            credential_version: Some(version),
            authorization: None,
            approval: None,
            request_context: None,
            usage: None,
            event_type: phase,
            outcome: result,
            reason_code: format!("macos-keychain-source:{digest}"),
            upstream_status: None,
            latency_ms: None,
        };
        self.append_audit(audit("credential.source.started", outcome::SUCCESS))?;
        check_execution(self)?;
        #[cfg(test)]
        let result = match self.keychain_fixture.as_mut() {
            Some(provider) => provider(&reference),
            None => native_lookup(&reference),
        };
        #[cfg(not(test))]
        let result = native_lookup(&reference);
        let result = result.and_then(validate_value);
        let current = check_execution(self);
        self.append_audit(audit(
            "credential.source.finished",
            if result.is_ok() && current.is_ok() {
                outcome::SUCCESS
            } else {
                outcome::FAILURE
            },
        ))?;
        current?;
        reference.current(deadline)?;
        result
    }
}

#[cfg(not(target_os = "macos"))]
fn native_lookup(_: &Reference) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
    Err(unavailable())
}

#[cfg(target_os = "macos")]
mod native {
    use super::*;
    use core_foundation::array::CFArray;
    use core_foundation::base::{CFType, TCFType};
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::CFData;
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework_sys::item::*;
    use security_framework_sys::keychain::SecKeychainSetUserInteractionAllowed;
    use security_framework_sys::keychain_item::SecItemCopyMatching;

    // Official SecItem.h declaration, exported by Security.tbd. Cached sys omits it.
    unsafe extern "C" {
        static kSecUseAuthenticationUIFail: CFStringRef;
    }

    pub(super) fn query(reference: &Reference, keychain: CFType) -> CFDictionary<CFString, CFType> {
        // Constants use get-rule; dictionary retains its keys and values.
        unsafe {
            let key = |raw| CFString::wrap_under_get_rule(raw);
            CFDictionary::from_CFType_pairs(&[
                (key(kSecClass), key(kSecClassGenericPassword).into_CFType()),
                (
                    key(kSecAttrService),
                    CFString::new(&reference.service).into_CFType(),
                ),
                (
                    key(kSecAttrAccount),
                    CFString::new(&reference.account).into_CFType(),
                ),
                (
                    key(kSecMatchSearchList),
                    CFArray::from_CFTypes(&[keychain]).into_CFType(),
                ),
                (
                    key(kSecMatchCaseInsensitive),
                    CFBoolean::false_value().into_CFType(),
                ),
                (
                    key(kSecAttrSynchronizable),
                    CFBoolean::false_value().into_CFType(),
                ),
                (key(kSecMatchLimit), CFNumber::from(2_i64).into_CFType()),
                (key(kSecReturnData), CFBoolean::true_value().into_CFType()),
                (
                    key(kSecUseAuthenticationUI),
                    key(kSecUseAuthenticationUIFail).into_CFType(),
                ),
            ])
        }
    }

    pub(super) fn decode_result(
        status: i32,
        result: Option<CFType>,
    ) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
        if status != 0 {
            return Err(unavailable());
        }
        let result = result.ok_or_else(unavailable)?;
        let data = if let Some(data) = result.downcast::<CFData>() {
            data
        } else {
            let array = result.downcast::<CFArray>().ok_or_else(unavailable)?;
            if array.len() != 1 {
                return Err(unavailable());
            }
            let member =
                unsafe { CFType::wrap_under_get_rule(*array.get(0).ok_or_else(unavailable)?) };
            member.downcast::<CFData>().ok_or_else(unavailable)?
        };
        if data.len() <= 0 || data.len() > 64 * 1024 {
            return Err(unavailable());
        }
        let bytes = Zeroizing::new(data.bytes().to_vec());
        // CFData is immutable OS-owned storage. Release it; only our copy is wiped.
        drop(data);
        drop(result);
        validate_value(bytes)
    }

    pub(super) fn lookup(reference: &Reference) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
        // File-Keychain access also needs the process-level no-UI setting. This
        // Broker is noninteractive; never re-enable prompts after the lookup.
        if unsafe { SecKeychainSetUserInteractionAllowed(0) } != 0 {
            return Err(unavailable());
        }
        let keychain =
            SecKeychain::open(Path::new(&reference.keychain_path)).map_err(|_| unavailable())?;
        let query = query(reference, keychain.into_CFType());
        let mut result = std::ptr::null();
        let status = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        // API returns retained result. Even a failure with a nonnull result releases it.
        let result = if result.is_null() {
            None
        } else {
            Some(unsafe { CFType::wrap_under_create_rule(result) })
        };
        decode_result(status, result)
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn keychain_actual_query_is_exact_single_file_numeric_two_and_no_ui() {
            let reference = Reference::import(br#"{"credential_type":"macos-keychain-source-v1","keychain_path":"/synthetic.keychain","service":"Exact.Service","account":"Exact.Account","reference_expires_at_ms":2000}"#,1000).unwrap();
            // Stand-in only for pure dictionary construction. No Keychain object is opened.
            let q = query(&reference, CFString::new("one-file-fixture").into_CFType());
            assert_eq!(q.len(), 9);
            unsafe {
                let key = |raw| CFString::wrap_under_get_rule(raw);
                assert_eq!(
                    q.get(key(kSecClass)).downcast::<CFString>().unwrap(),
                    key(kSecClassGenericPassword)
                );
                assert_eq!(
                    q.get(key(kSecAttrService))
                        .downcast::<CFString>()
                        .unwrap()
                        .to_string(),
                    "Exact.Service"
                );
                assert_eq!(
                    q.get(key(kSecAttrAccount))
                        .downcast::<CFString>()
                        .unwrap()
                        .to_string(),
                    "Exact.Account"
                );
                assert_eq!(
                    q.get(key(kSecMatchLimit))
                        .downcast::<CFNumber>()
                        .unwrap()
                        .to_i64(),
                    Some(2)
                );
                assert_eq!(
                    q.get(key(kSecMatchCaseInsensitive))
                        .downcast::<CFBoolean>()
                        .unwrap(),
                    CFBoolean::false_value()
                );
                assert_eq!(
                    q.get(key(kSecAttrSynchronizable))
                        .downcast::<CFBoolean>()
                        .unwrap(),
                    CFBoolean::false_value()
                );
                assert_eq!(
                    q.get(key(kSecReturnData)).downcast::<CFBoolean>().unwrap(),
                    CFBoolean::true_value()
                );
                assert_eq!(
                    q.get(key(kSecUseAuthenticationUI))
                        .downcast::<CFString>()
                        .unwrap(),
                    key(kSecUseAuthenticationUIFail)
                );
                assert_eq!(
                    q.get(key(kSecMatchSearchList))
                        .downcast::<CFArray>()
                        .unwrap()
                        .len(),
                    1
                );
            }
        }
        #[test]
        fn keychain_native_buffers_status_type_multiplicity_and_null_fail_closed() {
            for status in [-25300, -25293, -25308, -1] {
                assert!(
                    decode_result(
                        status,
                        Some(CFData::from_buffer(b"synthetic").into_CFType())
                    )
                    .is_err()
                );
            }
            assert!(decode_result(0, None).is_err());
            assert!(decode_result(0, Some(CFString::new("wrong-type").into_CFType())).is_err());
            for values in [
                vec![],
                vec![
                    CFData::from_buffer(b"one").into_CFType(),
                    CFData::from_buffer(b"two").into_CFType(),
                ],
                vec![CFString::new("wrong-member").into_CFType()],
            ] {
                assert!(
                    decode_result(0, Some(CFArray::from_CFTypes(&values).into_CFType())).is_err()
                );
            }
            for value in [
                vec![],
                vec![b'x'; 65537],
                vec![255],
                b"bad\r\nvalue".to_vec(),
            ] {
                assert!(decode_result(0, Some(CFData::from_buffer(&value).into_CFType())).is_err());
            }
            let array = CFArray::from_CFTypes(&[
                CFData::from_buffer(b"synthetic-native-value").into_CFType()
            ]);
            assert_eq!(
                decode_result(0, Some(array.into_CFType()))
                    .unwrap()
                    .as_slice(),
                b"synthetic-native-value"
            );
        }
    }
}
#[cfg(target_os = "macos")]
fn native_lookup(reference: &Reference) -> Result<Zeroizing<Vec<u8>>, AuthorityError> {
    native::lookup(reference)
}
