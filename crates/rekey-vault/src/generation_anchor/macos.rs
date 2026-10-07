//! Public Security.framework adapter. Synthetic tests never call Keychain APIs.
//! Protected-item permissions and concurrent CAS still require signed-device
//! verification; a file-mode test does not establish the production L1 claim.

use std::{io, ptr, sync::OnceLock};

use core_foundation::{
    base::{CFType, CFTypeRef, TCFType},
    boolean::CFBoolean,
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryGetValue, CFDictionaryRef},
    number::CFNumber,
    string::{CFString, CFStringRef},
};
use rekey_domain::ids::VaultId;
use security_framework_sys::{
    code_signing::{
        SecCodeCheckValidity, SecCodeCopyGuestWithAttributes, SecCodeCopySelf, SecCodeRef,
        SecRequirementCreateWithString, kSecGuestAttributeAudit,
    },
    item::*,
    keychain_item::{SecItemAdd, SecItemCopyMatching, SecItemUpdate},
};

use super::{AuthorityError, integrity, storage};

const UNSIGNED: i32 = -67062;
const ITEM_NOT_FOUND: i32 = -25300;
const DUPLICATE_ITEM: i32 = -25299;
const SIGNING_INFORMATION: u32 = 1 << 1;
const SIGNATURE_ADHOC: i32 = 2;
const VALUE_MARKER: &[u8] = b"RKGEN\0\x01";

#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    static kSecCodeInfoIdentifier: CFStringRef;
    static kSecCodeInfoFlags: CFStringRef;
    static kSecCodeInfoTeamIdentifier: CFStringRef;
    static kSecAttrGeneric: CFStringRef;
    static kSecAttrAccessible: CFStringRef;
    static kSecAttrAccessibleWhenUnlockedThisDeviceOnly: CFStringRef;
    static kSecMatchLimitOne: CFStringRef;
    static kSecUseAuthenticationUIFail: CFStringRef;
    fn SecCodeCopySigningInformation(
        code: SecCodeRef,
        flags: u32,
        info: *mut CFDictionaryRef,
    ) -> i32;
}

fn status(result: i32, operation: &'static str) -> Result<(), AuthorityError> {
    if result == 0 {
        Ok(())
    } else {
        Err(storage(
            operation,
            io::Error::other(format!("OSStatus {result}")),
        ))
    }
}

// Create/Copy results enter an owning wrapper exactly once. Other CF objects
// are retained via their wrappers; no pointer escapes a synchronous call.
unsafe fn owned(value: CFTypeRef, operation: &'static str) -> Result<CFType, AuthorityError> {
    if value.is_null() {
        return Err(storage(
            operation,
            io::Error::other("missing framework result"),
        ));
    }
    Ok(unsafe { CFType::wrap_under_create_rule(value) })
}

fn attribute(dictionary: &CFDictionary, key: CFStringRef) -> Option<CFType> {
    // SAFETY: the dictionary and static framework key are alive; a returned
    // borrowed value is retained before the dictionary can be released.
    let value = unsafe { CFDictionaryGetValue(dictionary.as_concrete_TypeRef(), key.cast()) };
    (!value.is_null()).then(|| unsafe { CFType::wrap_under_get_rule(value) })
}

fn pair(key: CFStringRef, value: CFType) -> (CFString, CFType) {
    // All callers use immutable Security.framework CFString constants.
    (unsafe { CFString::wrap_under_get_rule(key) }, value)
}

fn string(value: CFStringRef) -> CFType {
    unsafe { CFString::wrap_under_get_rule(value) }.as_CFType()
}

/// None is only explicitly unsigned or a valid ad-hoc signature. Broken or
/// untrusted signatures and failed Security queries never enable file mode.
pub(super) fn own_team() -> Result<Option<String>, AuthorityError> {
    let mut raw_code = ptr::null_mut();
    status(
        unsafe { SecCodeCopySelf(0, &mut raw_code) },
        "SecCodeCopySelf",
    )?;
    let code = unsafe { owned(raw_code.cast(), "SecCodeCopySelf") }?;
    code_team(code.as_CFTypeRef().cast_mut().cast())
}

fn code_team(raw_code: SecCodeRef) -> Result<Option<String>, AuthorityError> {
    let validity = unsafe { SecCodeCheckValidity(raw_code, 0, ptr::null_mut()) };
    if validity != 0 && validity != UNSIGNED {
        status(validity, "self signature")?;
    }
    let mut raw_info = ptr::null();
    status(
        unsafe { SecCodeCopySigningInformation(raw_code, SIGNING_INFORMATION, &mut raw_info) },
        "SecCodeCopySigningInformation",
    )?;
    let info = unsafe { owned(raw_info.cast(), "SecCodeCopySigningInformation") }?
        .downcast::<CFDictionary>()
        .ok_or_else(integrity)?;
    let identifier = attribute(&info, unsafe { kSecCodeInfoIdentifier });
    if validity == UNSIGNED && identifier.is_none() {
        return Ok(None);
    }
    status(validity, "self signature")?;
    if identifier
        .and_then(|value| value.downcast::<CFString>())
        .is_none()
    {
        return Err(integrity());
    }
    let flags = attribute(&info, unsafe { kSecCodeInfoFlags })
        .and_then(|value| value.downcast::<CFNumber>())
        .and_then(|value| value.to_i32())
        .ok_or_else(integrity)?;
    if flags & SIGNATURE_ADHOC != 0 {
        return Ok(None);
    }
    let text = CFString::new("anchor apple generic and anchor trusted");
    let mut raw_requirement = ptr::null_mut();
    status(
        unsafe {
            SecRequirementCreateWithString(text.as_concrete_TypeRef(), 0, &mut raw_requirement)
        },
        "SecRequirementCreateWithString",
    )?;
    let requirement = unsafe { owned(raw_requirement.cast(), "SecRequirementCreateWithString") }?;
    status(
        unsafe { SecCodeCheckValidity(raw_code, 0, requirement.as_CFTypeRef().cast_mut().cast()) },
        "trusted self signature",
    )?;
    let team = attribute(&info, unsafe { kSecCodeInfoTeamIdentifier })
        .and_then(|value| value.downcast::<CFString>())
        .map(|value| value.to_string())
        .filter(|value| !value.is_empty())
        .ok_or_else(integrity)?;
    Ok(Some(team))
}

/// Code identity comes from the kernel's complete audit token, including
/// pidversion. No PID supplied by an IPC client or pathname is trusted here.
pub(super) fn peer_has_own_team(audit: [u32; 8]) -> Result<bool, AuthorityError> {
    static CALLER_OWN_TEAM: OnceLock<Option<String>> = OnceLock::new();
    let own = match CALLER_OWN_TEAM.get() {
        Some(team) => team,
        None => {
            // Only a successful immutable self identity is cached. Signature
            // failures remain retryable and peer code is verified each time.
            let team = own_team()?;
            CALLER_OWN_TEAM.get_or_init(|| team)
        }
    };
    let Some(own) = own else {
        return Ok(false);
    };
    let bytes: Vec<u8> = audit.iter().flat_map(|word| word.to_ne_bytes()).collect();
    let attributes = CFDictionary::from_CFType_pairs(&[pair(
        unsafe { kSecGuestAttributeAudit },
        CFData::from_buffer(&bytes).as_CFType(),
    )]);
    let mut raw_code = ptr::null_mut();
    status(
        unsafe {
            SecCodeCopyGuestWithAttributes(
                ptr::null_mut(),
                attributes.as_concrete_TypeRef(),
                0,
                &mut raw_code,
            )
        },
        "SecCodeCopyGuestWithAttributes",
    )?;
    let code = unsafe { owned(raw_code.cast(), "SecCodeCopyGuestWithAttributes") }?;
    Ok(code_team(code.as_CFTypeRef().cast_mut().cast())?.is_some_and(|peer| &peer == own))
}

pub(super) struct ProtectedAnchor {
    account: String,
    access_group: String,
}

impl ProtectedAnchor {
    pub(super) fn new(vault: VaultId, team: &str) -> Self {
        Self {
            account: vault.to_string(),
            access_group: format!("{team}.com.rekey"),
        }
    }

    fn query(&self) -> Vec<(CFString, CFType)> {
        // Fixed, non-synchronizing DPK namespace. UI fail applies to reads and
        // both mutation forms; permissions errors stay errors, not absence.
        unsafe {
            vec![
                pair(kSecClass, string(kSecClassGenericPassword)),
                pair(
                    kSecAttrService,
                    CFString::new("com.rekey.generation").as_CFType(),
                ),
                pair(kSecAttrAccount, CFString::new(&self.account).as_CFType()),
                pair(
                    kSecAttrAccessGroup,
                    CFString::new(&self.access_group).as_CFType(),
                ),
                pair(kSecAttrSynchronizable, CFBoolean::false_value().as_CFType()),
                pair(
                    kSecUseDataProtectionKeychain,
                    CFBoolean::true_value().as_CFType(),
                ),
                pair(kSecUseAuthenticationUI, string(kSecUseAuthenticationUIFail)),
            ]
        }
    }

    pub(super) fn read(&self) -> Result<Option<u64>, AuthorityError> {
        let mut fields = self.query();
        unsafe {
            fields.push(pair(kSecMatchLimit, string(kSecMatchLimitOne)));
            fields.push(pair(
                kSecReturnAttributes,
                CFBoolean::true_value().as_CFType(),
            ));
        }
        let query = CFDictionary::from_CFType_pairs(&fields);
        let mut result = ptr::null();
        let code = unsafe { SecItemCopyMatching(query.as_concrete_TypeRef(), &mut result) };
        if code == ITEM_NOT_FOUND {
            return Ok(None);
        }
        status(code, "SecItemCopyMatching")?;
        let attrs = unsafe { owned(result, "SecItemCopyMatching") }?
            .downcast::<CFDictionary>()
            .ok_or_else(integrity)?;
        if attribute(&attrs, unsafe { kSecAttrAccessible })
            != Some(string(unsafe {
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            }))
        {
            return Err(integrity());
        }
        let data = attribute(&attrs, unsafe { kSecAttrGeneric })
            .and_then(|value| value.downcast::<CFData>())
            .ok_or_else(integrity)?;
        let value = u64::from_be_bytes(data.bytes().try_into().map_err(|_| integrity())?);
        if value == 0 {
            return Err(integrity());
        }
        Ok(Some(value))
    }

    pub(super) fn advance(&self, expected: Option<u64>, next: u64) -> Result<(), AuthorityError> {
        let mut fields = self.query();
        let next = CFData::from_buffer(&next.to_be_bytes()).as_CFType();
        match expected {
            None => {
                unsafe {
                    fields.push(pair(kSecAttrGeneric, next));
                    fields.push(pair(
                        kSecAttrAccessible,
                        string(kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
                    ));
                    fields.push(pair(
                        kSecValueData,
                        CFData::from_buffer(VALUE_MARKER).as_CFType(),
                    ));
                }
                let query = CFDictionary::from_CFType_pairs(&fields);
                let code = unsafe { SecItemAdd(query.as_concrete_TypeRef(), ptr::null_mut()) };
                if code == DUPLICATE_ITEM {
                    return Err(integrity());
                }
                status(code, "SecItemAdd")
            }
            Some(old) => {
                fields.push(pair(
                    unsafe { kSecAttrGeneric },
                    CFData::from_buffer(&old.to_be_bytes()).as_CFType(),
                ));
                let query = CFDictionary::from_CFType_pairs(&fields);
                let update =
                    CFDictionary::from_CFType_pairs(&[pair(unsafe { kSecAttrGeneric }, next)]);
                let code = unsafe {
                    SecItemUpdate(query.as_concrete_TypeRef(), update.as_concrete_TypeRef())
                };
                if code == ITEM_NOT_FOUND {
                    return Err(integrity());
                }
                status(code, "SecItemUpdate CAS")
            }
        }
    }
}
