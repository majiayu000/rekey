use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use data_encoding::BASE64URL_NOPAD;
use rekey_domain::Timestamp;
use rekey_domain::authorization::{ApprovalMode, PolicyVersion, ResourceRef, SchemaId};
use rekey_domain::ids::{
    ActionId, ApprovalId, ApprovalRequestId, ApproverId, PolicyRuleId, PolicySignerId, PrincipalId,
    SessionId, TenantId,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::json::parse_unique_json;
use crate::{
    APPROVAL_GRANT_MAX_BYTES, PolicyError, PolicySnapshot, SNAPSHOT_FORMAT_VERSION,
    SNAPSHOT_MAX_BYTES, SignatureAlgorithm, TRUST_MAX_BYTES, ValidatedSnapshot,
    decode_lower_hex_32, parse_and_validate_snapshot, parse_and_validate_snapshot_for_load,
    validate_ed25519_public_key,
};

const POLICY_FORMAT_VERSION: u32 = 1;
const APPROVAL_FORMAT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyTrustFile {
    format_version: u32,
    signer_id: PolicySignerId,
    algorithm: SignatureAlgorithm,
    public_key: String,
}

#[derive(Debug, Clone)]
pub struct ValidatedPolicyTrust {
    signer_id: PolicySignerId,
    public_key: [u8; 32],
    canonical: Vec<u8>,
}

impl ValidatedPolicyTrust {
    pub fn from_parts(signer_id: PolicySignerId, public_key: [u8; 32]) -> Self {
        Self {
            signer_id,
            public_key,
            canonical: Vec::new(),
        }
    }

    pub fn signer_id(&self) -> PolicySignerId {
        self.signer_id
    }

    pub fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyBundleEnvelope {
    format_version: u32,
    signer_id: PolicySignerId,
    snapshot: Value,
    signature: String,
}

pub struct ValidatedPolicyBundle {
    signer_id: PolicySignerId,
    snapshot: ValidatedSnapshot,
    bundle_digest: [u8; 32],
    canonical: Vec<u8>,
}

impl ValidatedPolicyBundle {
    pub fn signer_id(&self) -> PolicySignerId {
        self.signer_id
    }

    pub fn snapshot(&self) -> &ValidatedSnapshot {
        &self.snapshot
    }

    pub fn into_snapshot(self) -> ValidatedSnapshot {
        self.snapshot
    }

    pub fn policy_digest(&self) -> [u8; 32] {
        self.snapshot.digest()
    }

    pub fn bundle_digest(&self) -> [u8; 32] {
        self.bundle_digest
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedApprovalGrant {
    pub format_version: u32,
    pub approval_id: ApprovalId,
    pub approval_request_id: ApprovalRequestId,
    pub approver_id: ApproverId,
    pub tenant_id: TenantId,
    pub principal_id: PrincipalId,
    pub session_id: SessionId,
    pub action_id: ActionId,
    pub action_version: u64,
    pub resource: ResourceRef,
    pub schema_id: SchemaId,
    pub parameter_sha256: String,
    pub policy_version: PolicyVersion,
    pub policy_sha256: String,
    pub policy_rule_id: PolicyRuleId,
    pub mode: ApprovalMode,
    pub not_before_ms: i64,
    pub expires_at_ms: i64,
    pub max_uses: u32,
    pub signature: String,
}

#[derive(Debug, Clone)]
pub struct VerifiedApprovalGrant {
    grant: SignedApprovalGrant,
    parameter_hash: [u8; 32],
    policy_digest: [u8; 32],
    grant_digest: [u8; 32],
}

impl VerifiedApprovalGrant {
    pub fn grant(&self) -> &SignedApprovalGrant {
        &self.grant
    }

    pub fn parameter_hash(&self) -> [u8; 32] {
        self.parameter_hash
    }

    pub fn policy_digest(&self) -> [u8; 32] {
        self.policy_digest
    }

    pub fn grant_digest(&self) -> [u8; 32] {
        self.grant_digest
    }
}

pub fn parse_policy_trust(bytes: &[u8]) -> Result<ValidatedPolicyTrust, PolicyError> {
    if bytes.len() > TRUST_MAX_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let value = parse_unique_json(bytes)?;
    let trust: PolicyTrustFile =
        serde_json::from_value(value.clone()).map_err(|_| PolicyError::Malformed)?;
    if trust.format_version != POLICY_FORMAT_VERSION {
        return Err(PolicyError::UnsupportedFormat);
    }
    let public_key = validate_ed25519_public_key(&trust.public_key)?;
    let canonical = serde_jcs::to_vec(&value).map_err(|_| PolicyError::Malformed)?;
    Ok(ValidatedPolicyTrust {
        signer_id: trust.signer_id,
        public_key,
        canonical,
    })
}

pub fn parse_and_verify_policy_bundle(
    bytes: &[u8],
    trust: &ValidatedPolicyTrust,
    now: Timestamp,
) -> Result<ValidatedPolicyBundle, PolicyError> {
    parse_and_verify_policy_bundle_inner(bytes, trust, Some(now))
}

pub fn parse_and_verify_policy_bundle_for_load(
    bytes: &[u8],
    trust: &ValidatedPolicyTrust,
) -> Result<ValidatedPolicyBundle, PolicyError> {
    parse_and_verify_policy_bundle_inner(bytes, trust, None)
}

fn parse_and_verify_policy_bundle_inner(
    bytes: &[u8],
    trust: &ValidatedPolicyTrust,
    now: Option<Timestamp>,
) -> Result<ValidatedPolicyBundle, PolicyError> {
    if bytes.len() > SNAPSHOT_MAX_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let value = parse_unique_json(bytes)?;
    let envelope: PolicyBundleEnvelope =
        serde_json::from_value(value.clone()).map_err(|_| PolicyError::Malformed)?;
    if envelope.format_version != POLICY_FORMAT_VERSION {
        return Err(PolicyError::UnsupportedFormat);
    }
    if envelope.signer_id != trust.signer_id {
        return Err(PolicyError::InvalidSignature);
    }
    let snapshot_shape: PolicySnapshot =
        serde_json::from_value(envelope.snapshot.clone()).map_err(|_| PolicyError::Malformed)?;
    if snapshot_shape.format_version != SNAPSHOT_FORMAT_VERSION {
        return Err(PolicyError::UnsupportedFormat);
    }
    verify_signed_value(
        &value,
        &envelope.signature,
        b"RKPOLICY\0\x01",
        &trust.public_key,
    )?;
    let snapshot_bytes =
        serde_jcs::to_vec(&envelope.snapshot).map_err(|_| PolicyError::Malformed)?;
    let snapshot = match now {
        Some(now) => parse_and_validate_snapshot(&snapshot_bytes, now)?,
        None => parse_and_validate_snapshot_for_load(&snapshot_bytes)?,
    };
    let canonical = serde_jcs::to_vec(&value).map_err(|_| PolicyError::Malformed)?;
    let bundle_digest = sha256(&canonical);
    Ok(ValidatedPolicyBundle {
        signer_id: envelope.signer_id,
        snapshot,
        bundle_digest,
        canonical,
    })
}

pub fn parse_and_verify_approval_grant(
    bytes: &[u8],
    snapshot: &ValidatedSnapshot,
) -> Result<VerifiedApprovalGrant, PolicyError> {
    if bytes.len() > APPROVAL_GRANT_MAX_BYTES {
        return Err(PolicyError::TooLarge);
    }
    let value = parse_unique_json(bytes)?;
    let grant: SignedApprovalGrant =
        serde_json::from_value(value.clone()).map_err(|_| PolicyError::Malformed)?;
    if grant.format_version != APPROVAL_FORMAT_VERSION
        || grant.action_version == 0
        || grant.not_before_ms < 0
        || grant.expires_at_ms <= grant.not_before_ms
        || grant.max_uses == 0
        || grant.max_uses > 10_000
        || (grant.mode == ApprovalMode::OneTime && grant.max_uses != 1)
    {
        return Err(PolicyError::Invalid);
    }
    let parameter_hash = decode_lower_hex_32(&grant.parameter_sha256)?;
    let policy_digest = decode_lower_hex_32(&grant.policy_sha256)?;
    let public_key = snapshot
        .approver_key(grant.approver_id)
        .ok_or(PolicyError::InvalidSignature)?;
    verify_signed_value(&value, &grant.signature, b"RKAPPROVAL\0\x01", public_key)?;
    let canonical = serde_jcs::to_vec(&value).map_err(|_| PolicyError::Malformed)?;
    let grant_digest = sha256(&canonical);
    Ok(VerifiedApprovalGrant {
        grant,
        parameter_hash,
        policy_digest,
        grant_digest,
    })
}

fn verify_signed_value(
    value: &Value,
    signature: &str,
    prefix: &[u8],
    public_key: &[u8; 32],
) -> Result<(), PolicyError> {
    let signature_bytes = BASE64URL_NOPAD
        .decode(signature.as_bytes())
        .map_err(|_| PolicyError::InvalidSignature)?;
    if signature_bytes.len() != 64 || BASE64URL_NOPAD.encode(&signature_bytes) != signature {
        return Err(PolicyError::InvalidSignature);
    }
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .ok_or(PolicyError::Malformed)?
        .remove("signature")
        .ok_or(PolicyError::Malformed)?;
    let canonical = serde_jcs::to_vec(&unsigned).map_err(|_| PolicyError::Malformed)?;
    let mut message = Vec::with_capacity(prefix.len() + canonical.len());
    message.extend_from_slice(prefix);
    message.extend_from_slice(&canonical);
    UnparsedPublicKey::new(&ED25519, public_key)
        .verify(&message, &signature_bytes)
        .map_err(|_| PolicyError::InvalidSignature)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{Ed25519KeyPair, KeyPair};
    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};
    use rekey_domain::authorization::ApprovalMode;
    use rekey_domain::ids::{ApproverId, PolicySignerId};
    use serde_json::{Value, json};

    use super::*;

    fn key_pair() -> Ed25519KeyPair {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap()
    }

    fn sign(mut unsigned: Value, prefix: &[u8], key: &Ed25519KeyPair) -> Vec<u8> {
        let mut message = prefix.to_vec();
        message.extend_from_slice(&serde_jcs::to_vec(&unsigned).unwrap());
        let signature = BASE64URL_NOPAD.encode(key.sign(&message).as_ref());
        unsigned
            .as_object_mut()
            .unwrap()
            .insert("signature".to_owned(), signature.into());
        serde_jcs::to_vec(&unsigned).unwrap()
    }

    fn fixture() -> (
        ValidatedPolicyTrust,
        ValidatedPolicyBundle,
        Ed25519KeyPair,
        ApproverId,
    ) {
        let signer = key_pair();
        let signer_id = PolicySignerId::new_random();
        let approver = key_pair();
        let approver_id = ApproverId::new_random();
        let trust_json = json!({
            "format_version": 1,
            "signer_id": signer_id,
            "algorithm": "ed25519",
            "public_key": HEXLOWER.encode(signer.public_key().as_ref()),
        });
        let trust = parse_policy_trust(&serde_json::to_vec(&trust_json).unwrap()).unwrap();
        let action_id = ActionId::new_random();
        let principal_id = PrincipalId::new_random();
        let resource = json!({"type": "test.resource", "id": "one"});
        let unsigned = json!({
            "format_version": 1,
            "signer_id": signer_id,
            "snapshot": {
                "format_version": 2,
                "version": 1,
                "expires_at_ms": 10_000,
                "approvers": [{
                    "approver_id": approver_id,
                    "algorithm": "ed25519",
                    "public_key": HEXLOWER.encode(approver.public_key().as_ref()),
                }],
                "bindings": [{
                    "action_id": action_id,
                    "version": 1,
                    "resource": resource,
                    "parameter_schema_id": "test/v1",
                    "parameter_schema": {},
                }],
                "rules": [{
                    "id": PolicyRuleId::new_random(),
                    "effect": "require-approval",
                    "principal_id": principal_id,
                    "action_id": action_id,
                    "version": 1,
                    "resource": resource,
                    "parameters": {"kind": "any_validated"},
                    "approval": {
                        "approver_ids": [approver_id],
                        "quorum": 1,
                        "mode": "one-time",
                        "max_uses": 1
                    }
                }]
            }
        });
        let bundle_bytes = sign(unsigned, b"RKPOLICY\0\x01", &signer);
        let bundle =
            parse_and_verify_policy_bundle(&bundle_bytes, &trust, Timestamp::from_unix_ms(1))
                .unwrap();
        (trust, bundle, approver, approver_id)
    }

    #[test]
    fn trust_and_bundle_are_closed_canonical_and_signature_bound() {
        let (trust, bundle, _, _) = fixture();
        let canonical = bundle.canonical_bytes().to_vec();
        let pretty =
            serde_json::to_vec_pretty(&serde_json::from_slice::<Value>(&canonical).unwrap())
                .unwrap();
        let reparsed =
            parse_and_verify_policy_bundle(&pretty, &trust, Timestamp::from_unix_ms(1)).unwrap();
        assert_eq!(bundle.bundle_digest(), reparsed.bundle_digest());
        assert_eq!(bundle.policy_digest(), reparsed.policy_digest());

        let mut tampered: Value = serde_json::from_slice(&canonical).unwrap();
        tampered["snapshot"]["expires_at_ms"] = 9_999.into();
        assert!(
            parse_and_verify_policy_bundle(
                &serde_json::to_vec(&tampered).unwrap(),
                &trust,
                Timestamp::from_unix_ms(1),
            )
            .is_err()
        );

        let duplicate = format!(
            "{{\"format_version\":1,\"format_version\":1,\"signer_id\":\"{}\",\"algorithm\":\"ed25519\",\"public_key\":\"{}\"}}",
            trust.signer_id(),
            HEXLOWER.encode(trust.public_key())
        );
        assert!(parse_policy_trust(duplicate.as_bytes()).is_err());
        let mut unknown: Value = serde_json::from_slice(trust.canonical_bytes()).unwrap();
        unknown["extra"] = true.into();
        assert!(parse_policy_trust(&serde_json::to_vec(&unknown).unwrap()).is_err());

        let mut malformed_snapshot: Value = serde_json::from_slice(&canonical).unwrap();
        malformed_snapshot["snapshot"]["unknown"] = true.into();
        malformed_snapshot["signature"] = "invalid".into();
        assert!(matches!(
            parse_and_verify_policy_bundle(
                &serde_json::to_vec(&malformed_snapshot).unwrap(),
                &trust,
                Timestamp::from_unix_ms(1),
            ),
            Err(PolicyError::Malformed)
        ));

        for public_key in [[0u8; 32], [0xffu8; 32]] {
            let malformed = json!({
                "format_version": 1,
                "signer_id": PolicySignerId::new_random(),
                "algorithm": "ed25519",
                "public_key": HEXLOWER.encode(&public_key),
            });
            assert!(parse_policy_trust(&serde_json::to_vec(&malformed).unwrap()).is_err());
        }
    }

    #[test]
    fn approval_signature_binds_every_authorization_field() {
        let (_, bundle, approver, approver_id) = fixture();
        let snapshot = bundle.snapshot();
        let ids = (
            ApprovalId::new_random(),
            ApprovalRequestId::new_random(),
            TenantId::new_random(),
            PrincipalId::new_random(),
            SessionId::new_random(),
            ActionId::new_random(),
            PolicyRuleId::new_random(),
        );
        let unsigned = json!({
            "format_version": 1,
            "approval_id": ids.0,
            "approval_request_id": ids.1,
            "approver_id": approver_id,
            "tenant_id": ids.2,
            "principal_id": ids.3,
            "session_id": ids.4,
            "action_id": ids.5,
            "action_version": 1,
            "resource": {"type": "test.resource", "id": "one"},
            "schema_id": "test/v1",
            "parameter_sha256": HEXLOWER.encode(&[1u8; 32]),
            "policy_version": 1,
            "policy_sha256": HEXLOWER.encode(&snapshot.digest()),
            "policy_rule_id": ids.6,
            "mode": ApprovalMode::OneTime,
            "not_before_ms": 1,
            "expires_at_ms": 100,
            "max_uses": 1,
        });
        let signed = sign(unsigned, b"RKAPPROVAL\0\x01", &approver);
        assert!(parse_and_verify_approval_grant(&signed, snapshot).is_ok());

        let original: Value = serde_json::from_slice(&signed).unwrap();
        for field in [
            "approval_id",
            "approval_request_id",
            "approver_id",
            "tenant_id",
            "principal_id",
            "session_id",
            "action_id",
            "action_version",
            "schema_id",
            "parameter_sha256",
            "policy_version",
            "policy_sha256",
            "policy_rule_id",
            "mode",
            "not_before_ms",
            "expires_at_ms",
            "max_uses",
        ] {
            let mut tampered = original.clone();
            tampered[field] = match field {
                "approval_id" => ApprovalId::new_random().to_string().into(),
                "approval_request_id" => ApprovalRequestId::new_random().to_string().into(),
                "approver_id" => ApproverId::new_random().to_string().into(),
                "tenant_id" => TenantId::new_random().to_string().into(),
                "principal_id" => PrincipalId::new_random().to_string().into(),
                "session_id" => SessionId::new_random().to_string().into(),
                "action_id" => ActionId::new_random().to_string().into(),
                "schema_id" => "other/v1".into(),
                "parameter_sha256" | "policy_sha256" => HEXLOWER.encode(&[2u8; 32]).into(),
                "policy_rule_id" => PolicyRuleId::new_random().to_string().into(),
                "mode" => "time-window".into(),
                _ => (tampered[field].as_i64().unwrap() + 1).into(),
            };
            assert!(
                parse_and_verify_approval_grant(&serde_json::to_vec(&tampered).unwrap(), snapshot)
                    .is_err(),
                "tampering {field} must fail"
            );
        }
        let mut resource_tamper = original;
        resource_tamper["resource"]["id"] = "two".into();
        assert!(
            parse_and_verify_approval_grant(
                &serde_json::to_vec(&resource_tamper).unwrap(),
                snapshot
            )
            .is_err()
        );
    }
}
