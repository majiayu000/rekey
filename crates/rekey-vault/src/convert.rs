//! Conversions between persisted records and validated domain types.

use std::collections::BTreeSet;

use rekey_domain::Timestamp;
use rekey_domain::action::{
    ActionName, ExactPath, FixedHttpAction, FixedMethod, HeaderCredentialUse, HeaderName,
    HeaderPrefix, HttpsOrigin, RequestPolicy, ResponsePolicy,
};
use rekey_domain::credential::{CredentialLabel, CredentialMetadata};

use crate::error::AuthorityError;
use crate::model::{ActionRecord, ActionState, CredentialRecord};

fn integrity<T, E>(result: Result<T, E>) -> Result<T, AuthorityError> {
    result.map_err(|_| AuthorityError::StorageIntegrityFailed)
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
}

pub fn record_to_metadata(r: &CredentialRecord) -> Result<CredentialMetadata, AuthorityError> {
    Ok(CredentialMetadata {
        id: r.credential_id,
        label: integrity(CredentialLabel::new(&r.label))?,
        kind: r.kind,
        state: r.state,
        current_version: r.current_version,
        created_at: Timestamp::from_unix_ms(r.created_at_ms),
        updated_at: Timestamp::from_unix_ms(r.updated_at_ms),
    })
}

pub fn headers_to_json(headers: &BTreeSet<HeaderName>) -> Result<String, AuthorityError> {
    let names: Vec<&str> = headers.iter().map(HeaderName::as_str).collect();
    serde_json::to_string(&names).map_err(|_| AuthorityError::StorageIntegrityFailed)
}

pub fn headers_from_json(json: &str) -> Result<BTreeSet<HeaderName>, AuthorityError> {
    let names: Vec<String> = integrity(serde_json::from_str(json))?;
    names
        .iter()
        .map(|n| integrity(HeaderName::new(n)))
        .collect()
}

pub fn action_to_record(a: &FixedHttpAction, now_ms: i64) -> Result<ActionRecord, AuthorityError> {
    Ok(ActionRecord {
        action_id: a.id,
        version: a.version,
        name: a.name.as_str().to_owned(),
        state: ActionState::Active,
        credential_id: a.credential_id,
        origin: a.origin.as_str().to_owned(),
        method: a.method.as_str().to_owned(),
        exact_path: a.exact_path.as_str().to_owned(),
        auth_header: a.auth.header_name.as_str().to_owned(),
        auth_prefix: a.auth.prefix.as_str().to_owned(),
        request_max_bytes: a.request_policy.max_body_bytes,
        allowed_extra_headers_json: headers_to_json(&a.request_policy.allowed_extra_headers)?,
        response_max_bytes: a.response_policy.max_body_bytes,
        allowed_response_headers_json: headers_to_json(&a.response_policy.allowed_headers)?,
        timeout_ms: a.timeout_ms,
        created_at_ms: now_ms,
    })
}

pub fn record_to_action(r: &ActionRecord) -> Result<FixedHttpAction, AuthorityError> {
    let action = FixedHttpAction {
        id: r.action_id,
        name: integrity(ActionName::new(&r.name))?,
        version: r.version,
        // Retired versions stay executable by sessions that pinned them;
        // only disabled actions stop serving.
        enabled: r.state != ActionState::Disabled,
        credential_id: r.credential_id,
        origin: integrity(HttpsOrigin::parse(&r.origin))?,
        method: integrity(FixedMethod::parse(&r.method))?,
        exact_path: integrity(ExactPath::parse(&r.exact_path))?,
        auth: integrity(HeaderCredentialUse::new(
            integrity(HeaderName::new(&r.auth_header))?,
            integrity(HeaderPrefix::new(&r.auth_prefix))?,
        ))?,
        timeout_ms: r.timeout_ms,
        request_policy: RequestPolicy {
            max_body_bytes: r.request_max_bytes,
            allowed_extra_headers: headers_from_json(&r.allowed_extra_headers_json)?,
        },
        response_policy: ResponsePolicy {
            max_body_bytes: r.response_max_bytes,
            allowed_headers: headers_from_json(&r.allowed_response_headers_json)?,
        },
    };
    integrity(action.validate())?;
    Ok(action)
}
