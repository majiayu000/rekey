use std::fmt;
use std::str::FromStr;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::error::DomainError;

fn parse_canonical_uuid(s: &str) -> Result<Uuid, DomainError> {
    // Only the canonical lowercase hyphenated form is accepted; uuid's own
    // parser would also accept braced, simple, and urn forms.
    if s.len() != 36 || s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err(DomainError::InvalidId);
    }
    let uuid = Uuid::try_parse(s).map_err(|_| DomainError::InvalidId)?;
    if uuid.is_nil() {
        return Err(DomainError::InvalidId);
    }
    Ok(uuid)
}

macro_rules! typed_id {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(Uuid);

        impl $name {
            pub fn new_random() -> Self {
                Self(Uuid::new_v4())
            }

            pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, DomainError> {
                let uuid = Uuid::from_bytes(bytes);
                if uuid.is_nil() {
                    return Err(DomainError::InvalidId);
                }
                Ok(Self(uuid))
            }

            pub fn as_bytes(&self) -> &[u8; 16] {
                self.0.as_bytes()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0.hyphenated())
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.0.hyphenated())
            }
        }

        impl FromStr for $name {
            type Err = DomainError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                parse_canonical_uuid(s).map(Self)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let s = String::deserialize(deserializer)?;
                s.parse().map_err(|_| D::Error::custom("invalid identifier"))
            }
        }
    };
}

typed_id!(
    /// Identifies one vault instance.
    VaultId
);
typed_id!(
    /// Identifies one credential across all of its versions.
    CredentialId
);
typed_id!(
    /// Identifies one fixed action across all of its versions.
    ActionId
);
typed_id!(
    /// Identifies one capability session.
    SessionId
);
typed_id!(
    /// Correlates one transport request or one Broker-minted execution audit.
    RequestId
);
typed_id!(
    /// Identifies one VRK key wrapper row.
    WrapperId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_roundtrip() {
        let id = CredentialId::new_random();
        let s = id.to_string();
        assert_eq!(s.len(), 36);
        assert_eq!(s.parse::<CredentialId>().unwrap(), id);
    }

    #[test]
    fn rejects_non_canonical_forms() {
        let id = CredentialId::new_random();
        let upper = id.to_string().to_uppercase();
        assert_eq!(upper.parse::<CredentialId>(), Err(DomainError::InvalidId));
        let simple = id.to_string().replace('-', "");
        assert_eq!(simple.parse::<CredentialId>(), Err(DomainError::InvalidId));
        assert_eq!("".parse::<CredentialId>(), Err(DomainError::InvalidId));
        assert_eq!(
            "00000000-0000-0000-0000-000000000000".parse::<CredentialId>(),
            Err(DomainError::InvalidId)
        );
    }

    #[test]
    fn ids_are_distinct_types() {
        // Compile-time property: this must not compile if uncommented.
        // let a: ActionId = CredentialId::new_random();
        let bytes = *CredentialId::new_random().as_bytes();
        assert!(CredentialId::from_bytes(bytes).is_ok());
        assert!(CredentialId::from_bytes([0u8; 16]).is_err());
    }
}
