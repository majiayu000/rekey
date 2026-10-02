use rekey_domain::ids::VaultId;

use super::{AAD_VERSION_V1, CRYPTO_SUITE_V1_CODE};

pub const AAD_MAGIC: [u8; 4] = *b"RKAD";
pub const AAD_LEN: usize = 84;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AadPurpose {
    WrapVrk,
    WrapDek,
    CredentialPayload,
    VaultIntegrity,
    CredentialState,
    PolicyState,
    PolicyTrust,
    PolicyBundle,
    LeaseJournalWrapDek,
    LeaseJournalPayload,
    LeaseJournalState,
    AuditRetention,
}

impl AadPurpose {
    pub fn code(&self) -> u16 {
        match self {
            Self::WrapVrk => 1,
            Self::WrapDek => 2,
            Self::CredentialPayload => 3,
            Self::VaultIntegrity => 4,
            Self::CredentialState => 5,
            Self::PolicyState => 6,
            Self::PolicyTrust => 7,
            Self::PolicyBundle => 8,
            Self::LeaseJournalWrapDek => 9,
            Self::LeaseJournalPayload => 10,
            Self::LeaseJournalState => 11,
            Self::AuditRetention => 12,
        }
    }
}

/// Canonical AAD v1: fixed order, fixed width, big-endian. Any field change
/// flips authentication, which is exactly the anti-swap property we want.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AadV1 {
    pub purpose: AadPurpose,
    pub vault_id: VaultId,
    pub object_id: [u8; 16],
    pub object_version: u64,
    pub credential_kind: u16,
    pub constraints_hash: [u8; 32],
}

impl AadV1 {
    pub fn encode(&self) -> [u8; AAD_LEN] {
        let mut out = [0u8; AAD_LEN];
        out[0..4].copy_from_slice(&AAD_MAGIC);
        out[4..6].copy_from_slice(&AAD_VERSION_V1.to_be_bytes());
        out[6..8].copy_from_slice(&self.purpose.code().to_be_bytes());
        out[8..24].copy_from_slice(self.vault_id.as_bytes());
        out[24..40].copy_from_slice(&self.object_id);
        out[40..48].copy_from_slice(&self.object_version.to_be_bytes());
        out[48..50].copy_from_slice(&self.credential_kind.to_be_bytes());
        out[50..52].copy_from_slice(&CRYPTO_SUITE_V1_CODE.to_be_bytes());
        out[52..84].copy_from_slice(&self.constraints_hash);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vault_id() -> VaultId {
        VaultId::from_bytes([0x11; 16]).unwrap()
    }

    #[test]
    fn golden_vector() {
        let aad = AadV1 {
            purpose: AadPurpose::WrapDek,
            vault_id: vault_id(),
            object_id: [0x22; 16],
            object_version: 3,
            credential_kind: 1,
            constraints_hash: [0u8; 32],
        };
        let enc = aad.encode();
        assert_eq!(enc.len(), AAD_LEN);

        let mut expected = Vec::with_capacity(AAD_LEN);
        expected.extend_from_slice(b"RKAD");
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(&2u16.to_be_bytes());
        expected.extend_from_slice(&[0x11; 16]);
        expected.extend_from_slice(&[0x22; 16]);
        expected.extend_from_slice(&3u64.to_be_bytes());
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(&1u16.to_be_bytes());
        expected.extend_from_slice(&[0u8; 32]);
        assert_eq!(enc.as_slice(), expected.as_slice());
    }

    #[test]
    fn every_field_changes_encoding() {
        let base = AadV1 {
            purpose: AadPurpose::WrapVrk,
            vault_id: vault_id(),
            object_id: [0x22; 16],
            object_version: 1,
            credential_kind: 0,
            constraints_hash: [0u8; 32],
        };
        let variants = [
            AadV1 {
                purpose: AadPurpose::WrapDek,
                ..base
            },
            AadV1 {
                purpose: AadPurpose::VaultIntegrity,
                ..base
            },
            AadV1 {
                purpose: AadPurpose::CredentialState,
                ..base
            },
            AadV1 {
                purpose: AadPurpose::PolicyState,
                ..base
            },
            AadV1 {
                purpose: AadPurpose::PolicyTrust,
                ..base
            },
            AadV1 {
                purpose: AadPurpose::PolicyBundle,
                ..base
            },
            AadV1 {
                vault_id: VaultId::from_bytes([0x12; 16]).unwrap(),
                ..base
            },
            AadV1 {
                object_id: [0x23; 16],
                ..base
            },
            AadV1 {
                object_version: 2,
                ..base
            },
            AadV1 {
                credential_kind: 1,
                ..base
            },
            AadV1 {
                constraints_hash: [1u8; 32],
                ..base
            },
        ];
        for v in variants {
            assert_ne!(v.encode(), base.encode());
        }
    }
    #[test]
    fn azure_kind_uses_tag_eight_without_changing_the_84_byte_layout() {
        let azure = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id: vault_id(),
            object_id: [0x22; 16],
            object_version: 1,
            credential_kind: rekey_domain::credential::CredentialKind::AzureKeyVaultSource
                .aad_code(),
            constraints_hash: [0; 32],
        };
        let encoded = azure.encode();
        assert_eq!(encoded.len(), 84);
        assert_eq!(&encoded[48..50], &8u16.to_be_bytes());
        let mut wrong = azure;
        wrong.credential_kind = 7;
        assert_ne!(encoded, wrong.encode());
    }
    #[test]
    fn onepassword_kind_uses_tag_nine_without_changing_the_84_byte_layout() {
        let onepassword = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id: vault_id(),
            object_id: [0x22; 16],
            object_version: 1,
            credential_kind: rekey_domain::credential::CredentialKind::OnePasswordConnectSource
                .aad_code(),
            constraints_hash: [0; 32],
        };
        let encoded = onepassword.encode();
        assert_eq!(encoded.len(), 84);
        assert_eq!(&encoded[48..50], &9u16.to_be_bytes());
        let mut wrong = onepassword;
        wrong.credential_kind = 8;
        assert_ne!(encoded, wrong.encode());
    }
    #[test]
    fn keychain_kind_uses_tag_ten_and_retains_84_byte_aad() {
        let source = AadV1 {
            purpose: AadPurpose::CredentialPayload,
            vault_id: vault_id(),
            object_id: [0x22; 16],
            object_version: 1,
            credential_kind: rekey_domain::credential::CredentialKind::MacosKeychainSource
                .aad_code(),
            constraints_hash: [0; 32],
        };
        let bytes = source.encode();
        assert_eq!(bytes.len(), 84);
        assert_eq!(&bytes[48..50], &10u16.to_be_bytes());
        let mut other = source;
        other.credential_kind = 9;
        assert_ne!(bytes, other.encode());
    }
}
