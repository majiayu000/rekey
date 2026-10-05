//! OAuth/AWS source material has a dedicated preparation purpose. No Agent
//! IPC operation returns these payloads or their secret fields.

use rekey_domain::{
    credential::{CredentialKind, CredentialLabel, CredentialMetadata},
    ids::CredentialId,
};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::time::Instant;
use zeroize::Zeroizing;

use aws_lc_rs::{encoding::AsBigEndian, signature};

use super::{Worker, ensure_mutation_current};
use crate::{
    AuthorityError,
    command::{OAuthGrantUpdateReason, UnlockProof},
    secret::{PreparedCredential, SecretInput},
};

fn invalid() -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition("invalid credential source payload".into())
        .into()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OAuthFields<'a> {
    #[serde(borrow)]
    credential_type: &'a RawValue,
    #[serde(borrow)]
    provider: &'a RawValue,
    #[serde(borrow)]
    client_id: &'a RawValue,
    #[serde(borrow)]
    scopes: &'a RawValue,
    #[serde(borrow)]
    client_secret: Option<&'a RawValue>,
    #[serde(borrow)]
    refresh_token: Option<&'a RawValue>,
    #[serde(borrow)]
    access_token: Option<&'a RawValue>,
    #[serde(rename = "expires_at_ms")]
    _expires_at_ms: Option<i64>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsFields<'a> {
    #[serde(borrow)]
    credential_type: &'a RawValue,
    #[serde(borrow)]
    access_key_id: &'a RawValue,
    #[serde(borrow)]
    secret_access_key: &'a RawValue,
    #[serde(borrow)]
    session_token: Option<&'a RawValue>,
}
#[derive(Deserialize)]
struct GitHubRootFields<'a> {
    #[serde(borrow)]
    credential_type: &'a RawValue,
    #[serde(borrow)]
    private_key_pkcs1_der_base64: &'a RawValue,
}
fn text(raw: &RawValue) -> Result<Zeroizing<String>, AuthorityError> {
    serde_json::from_str::<String>(raw.get())
        .map(Zeroizing::new)
        .map_err(|_| invalid())
}
fn secret(raw: &RawValue) -> Result<Zeroizing<String>, AuthorityError> {
    let value = text(raw)?;
    if value.is_empty() {
        return Err(invalid());
    }
    Ok(value)
}
fn oauth_fields(payload: &[u8]) -> Result<OAuthFields<'_>, AuthorityError> {
    let fields: OAuthFields<'_> = serde_json::from_slice(payload).map_err(|_| invalid())?;
    if text(fields.credential_type)?.as_str() != "oauth-grant-v1"
        || text(fields.provider)?.is_empty()
        || text(fields.client_id)?.is_empty()
        || !fields.scopes.get().starts_with('[')
    {
        return Err(invalid());
    }
    // Notion access grants are persisted encrypted with their actual optional
    // expiry. Other access tokens belong only to the broker's bounded cache.
    if fields.access_token.is_some() && text(fields.provider)?.as_str() != "notion" {
        return Err(invalid());
    }
    for value in [
        fields.client_secret,
        fields.refresh_token,
        fields.access_token,
    ]
    .into_iter()
    .flatten()
    {
        secret(value)?;
    }
    Ok(fields)
}
fn aws_fields(payload: &[u8]) -> Result<AwsFields<'_>, AuthorityError> {
    let fields: AwsFields<'_> = serde_json::from_slice(payload).map_err(|_| invalid())?;
    if text(fields.credential_type)?.as_str() != "aws-static-v1" {
        return Err(invalid());
    }
    secret(fields.access_key_id)?;
    secret(fields.secret_access_key)?;
    if let Some(value) = fields.session_token {
        secret(value)?;
    }
    Ok(fields)
}
pub(super) fn validate_oauth(payload: &[u8]) -> Result<(), AuthorityError> {
    oauth_fields(payload).map(|_| ())
}
pub(super) fn validate_aws(payload: &[u8]) -> Result<(), AuthorityError> {
    aws_fields(payload).map(|_| ())
}

/// Called only by the Authority's scan command. Borrowed JSON avoids an
/// unzeroized serde_json::Value copy of an entire grant; decoded fields are
/// zeroized immediately after each complete-value match.
pub(super) fn scan_payload(
    kind: CredentialKind,
    payload: &[u8],
    mut scan: impl FnMut(&[u8]) -> Result<(), AuthorityError>,
) -> Result<(), AuthorityError> {
    // A Secure Enclave reference contains public lookup metadata, not an
    // exportable private key. Do not treat that descriptor as secret material.
    if kind == CredentialKind::SshSecureEnclaveP256 {
        return Ok(());
    }
    scan(payload)?;
    match kind {
        CredentialKind::GitHubAppInstallation => {
            let fields: GitHubRootFields<'_> =
                serde_json::from_slice(payload).map_err(|_| invalid())?;
            if text(fields.credential_type)?.as_str() != "github-app-root-v1" {
                return Err(invalid());
            }
            let encoded = secret(fields.private_key_pkcs1_der_base64)?;
            scan(encoded.as_bytes())?;
            let der = Zeroizing::new(
                data_encoding::BASE64
                    .decode(encoded.as_bytes())
                    .map_err(|_| invalid())?,
            );
            scan(&der)?;
        }
        CredentialKind::SshEd25519 => {
            // The dedicated SSH importer/generator stores normalized PKCS8.
            // RFC 8410 encodes its 32-byte seed in this nested OCTET STRING;
            // borrow it instead of allocating a library Seed without Drop.
            let offset = payload
                .windows(4)
                .position(|value| value == b"\x04\x22\x04\x20")
                .ok_or(AuthorityError::CryptoFailure)?;
            let seed = payload
                .get(offset + 4..offset + 36)
                .ok_or(AuthorityError::CryptoFailure)?;
            scan(seed)?;
        }
        CredentialKind::SshP256 => {
            let key = signature::EcdsaKeyPair::from_pkcs8(
                &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                payload,
            )
            .map_err(|_| AuthorityError::CryptoFailure)?;
            let scalar = key
                .private_key()
                .as_be_bytes()
                .map_err(|_| AuthorityError::CryptoFailure)?;
            scan(scalar.as_ref())?;
        }
        CredentialKind::OAuthGrant => {
            let fields = oauth_fields(payload)?;
            for raw in [
                fields.client_secret,
                fields.refresh_token,
                fields.access_token,
            ]
            .into_iter()
            .flatten()
            {
                let value = secret(raw)?;
                scan(value.as_bytes())?;
            }
        }
        CredentialKind::AwsStatic => {
            let fields = aws_fields(payload)?;
            for raw in [fields.access_key_id, fields.secret_access_key] {
                let value = secret(raw)?;
                scan(value.as_bytes())?;
            }
            if let Some(raw) = fields.session_token {
                let value = secret(raw)?;
                scan(value.as_bytes())?;
            }
        }
        _ => {}
    }
    Ok(())
}

impl Worker {
    pub(super) fn oauth_grant_create(
        &mut self,
        label: CredentialLabel,
        payload: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        drop(proof);
        ensure_mutation_current(not_after)?;
        validate_oauth(payload.expose())?;
        self.insert_credential(label, CredentialKind::OAuthGrant, payload, not_after)
    }
    pub(super) fn oauth_grant_update(
        &mut self,
        credential_id: CredentialId,
        expected_version: u64,
        payload: SecretInput,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        drop(proof);
        validate_oauth(payload.expose())?;
        self.rotate_credential_inner(
            credential_id,
            CredentialKind::OAuthGrant,
            Some(expected_version),
            payload,
            not_after,
            "credential.rotated",
        )
    }
    pub(super) fn rotate_oauth_grant(
        &mut self,
        credential_id: CredentialId,
        expected_version: u64,
        payload: SecretInput,
        reason: OAuthGrantUpdateReason,
        not_after: Instant,
    ) -> Result<CredentialMetadata, AuthorityError> {
        self.require_unlocked()?;
        ensure_mutation_current(Some(not_after))?;
        validate_oauth(payload.expose())?;
        self.rotate_credential_inner(
            credential_id,
            CredentialKind::OAuthGrant,
            Some(expected_version),
            payload,
            Some(not_after),
            reason.event_type(),
        )
    }
    pub(super) fn prepare_oauth_grant(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<PreparedCredential, AuthorityError> {
        if self.load_verified_credential(credential_id)?.kind != CredentialKind::OAuthGrant {
            return Err(AuthorityError::CredentialSourceUnavailable);
        }
        self.prepare_internal_credential(credential_id)
    }
    pub(super) fn prepare_aws_static(
        &mut self,
        credential_id: CredentialId,
    ) -> Result<PreparedCredential, AuthorityError> {
        if self.load_verified_credential(credential_id)?.kind != CredentialKind::AwsStatic {
            return Err(AuthorityError::CredentialSourceUnavailable);
        }
        self.prepare_internal_credential(credential_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_covers_github_root_field_and_decoded_der_without_exposing_it() {
        let der = b"synthetic-github-root-der-0123";
        let encoded = data_encoding::BASE64.encode(der);
        let payload = format!(
            r#"{{"credential_type":"github-app-root-v1","app_id":123,"private_key_pkcs1_der_base64":"{encoded}"}}"#
        );
        let mut matched = 0;
        scan_payload(
            CredentialKind::GitHubAppInstallation,
            payload.as_bytes(),
            |material| {
                if material == encoded.as_bytes() || material == der {
                    matched += 1;
                }
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(matched, 2);
    }

    #[test]
    fn scan_covers_ssh_pkcs8_and_private_components_but_ignores_enclave_references() {
        let seed = [7; 32];
        let key = signature::Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let pkcs8 = key.to_pkcs8().unwrap();
        let mut matched = 0;
        scan_payload(CredentialKind::SshEd25519, pkcs8.as_ref(), |material| {
            if material == pkcs8.as_ref() || material == seed {
                matched += 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(matched, 2);
        let pkcs8 = signature::EcdsaKeyPair::generate_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &aws_lc_rs::rand::SystemRandom::new(),
        )
        .unwrap();
        let key = signature::EcdsaKeyPair::from_pkcs8(
            &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            pkcs8.as_ref(),
        )
        .unwrap();
        let scalar = key.private_key().as_be_bytes().unwrap();
        let mut matched = 0;
        scan_payload(CredentialKind::SshP256, pkcs8.as_ref(), |material| {
            if material == pkcs8.as_ref() || material == scalar.as_ref() {
                matched += 1;
            }
            Ok(())
        })
        .unwrap();
        assert_eq!(matched, 2);
        scan_payload(
            CredentialKind::SshSecureEnclaveP256,
            b"synthetic-public-reference",
            |_| panic!("public reference must not be scanned as a secret"),
        )
        .unwrap();
    }
}
