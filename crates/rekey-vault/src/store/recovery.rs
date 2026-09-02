use rekey_domain::DomainError;
use rekey_domain::ids::{ActionId, CredentialId, PolicyRuleId, PrincipalId, RequestId, SessionId};

use super::sqlite::{SqliteRecordStore, blob16, blob32, storage};
use crate::error::AuthorityError;
use crate::model::AuthorizationEvidence;

pub struct UnterminatedExecution {
    pub request_id: RequestId,
    pub session_id: Option<SessionId>,
    pub action_id: Option<ActionId>,
    pub action_version: Option<u64>,
    pub credential_id: Option<CredentialId>,
    pub authorization: Option<AuthorizationEvidence>,
}

pub(super) fn optional_id<T, F>(
    bytes: Option<Vec<u8>>,
    decode: F,
) -> Result<Option<T>, AuthorityError>
where
    F: FnOnce([u8; 16]) -> Result<T, DomainError>,
{
    bytes
        .map(|value| decode(blob16(value)?).map_err(|_| AuthorityError::StorageIntegrityFailed))
        .transpose()
}

#[allow(clippy::too_many_arguments)]
pub(super) fn authorization_from_columns(
    principal_id: Option<Vec<u8>>,
    policy_version: Option<i64>,
    policy_digest: Option<Vec<u8>>,
    policy_rule_id: Option<Vec<u8>>,
    resource_type: Option<String>,
    resource_id: Option<String>,
    parameter_hash: Option<Vec<u8>>,
) -> Result<Option<AuthorizationEvidence>, AuthorityError> {
    match (
        principal_id,
        policy_version,
        policy_digest,
        policy_rule_id,
        resource_type,
        resource_id,
        parameter_hash,
    ) {
        (None, None, None, None, None, None, None) => Ok(None),
        (
            Some(principal_id),
            Some(policy_version),
            Some(policy_digest),
            policy_rule_id,
            Some(resource_type),
            Some(resource_id),
            Some(parameter_hash),
        ) => {
            let policy_version = u64::try_from(policy_version)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
            if policy_version == 0 {
                return Err(AuthorityError::StorageIntegrityFailed);
            }
            Ok(Some(AuthorizationEvidence {
                principal_id: PrincipalId::from_bytes(blob16(principal_id)?)
                    .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                policy_version,
                policy_digest: blob32(policy_digest)?,
                policy_rule_id: optional_id(policy_rule_id, PolicyRuleId::from_bytes)?,
                resource_type,
                resource_id,
                parameter_hash: blob32(parameter_hash)?,
            }))
        }
        _ => Err(AuthorityError::StorageIntegrityFailed),
    }
}

impl SqliteRecordStore {
    /// `execution.started` rows that have no terminal twin.
    pub fn unterminated_executions(&self) -> Result<Vec<UnterminatedExecution>, AuthorityError> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT a.request_id, a.session_id, a.action_id, a.action_version, a.credential_id,
                        a.principal_id, a.policy_version, a.policy_digest, a.policy_rule_id,
                        a.resource_type, a.resource_id, a.parameter_hash
                 FROM audit_events a
                 WHERE a.event_type = 'execution.started'
                   AND a.request_id IS NOT NULL
                   AND NOT EXISTS (
                     SELECT 1 FROM audit_events b
                     WHERE b.request_id = a.request_id
                       AND b.event_type IN (
                         'execution.finished', 'execution.blocked', 'execution.indeterminate'
                       )
                   )
                 ORDER BY a.sequence",
            )
            .map_err(storage)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Option<Vec<u8>>>(1)?,
                    row.get::<_, Option<Vec<u8>>>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<Vec<u8>>>(5)?,
                    row.get::<_, Option<i64>>(6)?,
                    row.get::<_, Option<Vec<u8>>>(7)?,
                    row.get::<_, Option<Vec<u8>>>(8)?,
                    row.get::<_, Option<String>>(9)?,
                    row.get::<_, Option<String>>(10)?,
                    row.get::<_, Option<Vec<u8>>>(11)?,
                ))
            })
            .map_err(storage)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(storage)?;
        rows.into_iter()
            .map(
                |(
                    request_id,
                    session_id,
                    action_id,
                    action_version,
                    credential_id,
                    principal_id,
                    policy_version,
                    policy_digest,
                    policy_rule_id,
                    resource_type,
                    resource_id,
                    parameter_hash,
                )| {
                    Ok(UnterminatedExecution {
                        request_id: RequestId::from_bytes(blob16(request_id)?)
                            .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
                        session_id: optional_id(session_id, SessionId::from_bytes)?,
                        action_id: optional_id(action_id, ActionId::from_bytes)?,
                        action_version: action_version
                            .map(|value| {
                                u64::try_from(value)
                                    .map_err(|_| AuthorityError::StorageIntegrityFailed)
                            })
                            .transpose()?,
                        credential_id: optional_id(credential_id, CredentialId::from_bytes)?,
                        authorization: authorization_from_columns(
                            principal_id,
                            policy_version,
                            policy_digest,
                            policy_rule_id,
                            resource_type,
                            resource_id,
                            parameter_hash,
                        )?,
                    })
                },
            )
            .collect()
    }
}
