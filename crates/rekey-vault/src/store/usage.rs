//! Single request ledger. Every trusted read verifies its entire authenticated set.
use super::{
    SqliteRecordStore,
    sqlite::{blob12, blob16, blob32, commit_audited, storage},
};
use crate::{
    command::ProfileUsageStart,
    crypto,
    error::AuthorityError,
    model::{
        AuditEvent, UsageAdmission, UsageContext, UsageRecord, UsageState, UsageTotals, event_type,
        outcome,
    },
    now_ms,
};
use rekey_domain::{
    audit::{UsageEvidence, UsageSource},
    ids::{PrincipalId, RequestId, VaultId},
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior, params};
use std::time::Instant;

fn corrupt<T>() -> Result<T, AuthorityError> {
    Err(AuthorityError::StorageIntegrityFailed)
}
fn invalid() -> AuthorityError {
    rekey_domain::DomainError::InvalidActionDefinition("invalid profile usage operation".into())
        .into()
}
fn one(changed: usize) -> Result<(), AuthorityError> {
    if changed == 1 { Ok(()) } else { corrupt() }
}
fn get<T: rusqlite::types::FromSql>(
    row: &rusqlite::Row<'_>,
    index: usize,
) -> Result<T, AuthorityError> {
    row.get(index)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)
}
fn load(conn: &Connection) -> Result<(Vec<UsageRecord>, UsageState), AuthorityError> {
    let mut query = conn.prepare("SELECT request_id,principal_id,instance_slug,utc_day,started_at_ms,context_json,generation_max_output,output_tokens,source,terminal_json,settled_at_ms FROM profile_usage ORDER BY request_id").map_err(storage)?;
    let mut results = query.query([]).map_err(storage)?;
    let mut rows = Vec::new();
    while let Some(r) = results.next().map_err(storage)? {
        rows.push(UsageRecord {
            request_id: RequestId::from_bytes(blob16(get(r, 0)?)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            principal_id: PrincipalId::from_bytes(blob16(get(r, 1)?)?)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?,
            instance_slug: get(r, 2)?,
            utc_day: get(r, 3)?,
            started_at_ms: get(r, 4)?,
            context_json: get(r, 5)?,
            generation_max_output: get(r, 6)?,
            output_tokens: get(r, 7)?,
            source: get(r, 8)?,
            terminal_json: get(r, 9)?,
            settled_at_ms: get(r, 10)?,
        });
    }
    let mut query = conn.prepare("SELECT revision,record_count,records_digest,seal_nonce,seal_ciphertext FROM profile_usage_state WHERE singleton=1").map_err(storage)?;
    let state = query
        .query_row([], |r| {
            Ok((|| -> Result<UsageState, AuthorityError> {
                Ok(UsageState {
                    revision: get(r, 0)?,
                    record_count: get(r, 1)?,
                    records_digest: blob32(get(r, 2)?)?,
                    seal_nonce: blob12(get(r, 3)?)?,
                    seal_ciphertext: blob16(get(r, 4)?)?,
                })
            })())
        })
        .optional()
        .map_err(storage)?
        .ok_or(AuthorityError::StorageIntegrityFailed)??;
    Ok((rows, state))
}
pub(crate) fn verified(
    conn: &Connection,
    key: &[u8; 32],
    vault: VaultId,
) -> Result<(Vec<UsageRecord>, UsageState), AuthorityError> {
    let (rows, state) = load(conn)?;
    crypto::usage::verify(key, vault, &rows, &state)?;
    // Decode context only after authenticating the complete raw row text.
    for row in &rows {
        let context: UsageContext = serde_json::from_str(&row.context_json)
            .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
        if context.authorization.principal_id != row.principal_id
            || row.utc_day != row.started_at_ms / 86_400_000
        {
            return corrupt();
        }
    }
    Ok((rows, state))
}
pub(super) fn initial_state(
    tx: &Transaction<'_>,
    state: &UsageState,
) -> Result<(), AuthorityError> {
    one(tx.execute("INSERT INTO profile_usage_state(singleton,revision,record_count,records_digest,seal_nonce,seal_ciphertext) VALUES(1,?1,?2,?3,?4,?5)",params![state.revision as i64,state.record_count as i64,state.records_digest.as_slice(),state.seal_nonce.as_slice(),state.seal_ciphertext.as_slice()]).map_err(storage)?)
}
pub(super) fn replace_state(
    tx: &Transaction<'_>,
    state: &UsageState,
) -> Result<(), AuthorityError> {
    one(tx.execute("UPDATE profile_usage_state SET revision=?1,record_count=?2,records_digest=?3,seal_nonce=?4,seal_ciphertext=?5 WHERE singleton=1",params![state.revision as i64,state.record_count as i64,state.records_digest.as_slice(),state.seal_nonce.as_slice(),state.seal_ciphertext.as_slice()]).map_err(storage)?)
}
fn write(tx: &Transaction<'_>, row: &UsageRecord, insert: bool) -> Result<(), AuthorityError> {
    let sql = if insert {
        "INSERT INTO profile_usage(request_id,principal_id,instance_slug,utc_day,started_at_ms,context_json,generation_max_output,output_tokens,source,terminal_json,settled_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)"
    } else {
        "UPDATE profile_usage SET principal_id=?2,instance_slug=?3,utc_day=?4,started_at_ms=?5,context_json=?6,generation_max_output=?7,output_tokens=?8,source=?9,terminal_json=?10,settled_at_ms=?11 WHERE request_id=?1"
    };
    one(tx
        .execute(
            sql,
            params![
                row.request_id.as_bytes().as_slice(),
                row.principal_id.as_bytes().as_slice(),
                row.instance_slug,
                row.utc_day,
                row.started_at_ms,
                row.context_json,
                row.generation_max_output.map(|v| v as i64),
                row.output_tokens.map(|v| v as i64),
                row.source,
                row.terminal_json,
                row.settled_at_ms
            ],
        )
        .map_err(storage)?)
}
fn totals(
    rows: &[UsageRecord],
    principal: PrincipalId,
    instance: &str,
    day: i64,
) -> Result<UsageTotals, AuthorityError> {
    rows.iter()
        .filter(|r| r.principal_id == principal && r.instance_slug == instance && r.utc_day == day)
        .try_fold(UsageTotals::default(), |mut sum, row| {
            sum.requests = sum
                .requests
                .checked_add(1)
                .ok_or(AuthorityError::StorageIntegrityFailed)?;
            sum.output_tokens = sum
                .output_tokens
                .checked_add(row.output_tokens.unwrap_or(0))
                .ok_or(AuthorityError::StorageIntegrityFailed)?;
            Ok(sum)
        })
}
fn current(not_after: Instant, wall: Option<i64>) -> Result<(), AuthorityError> {
    if Instant::now() >= not_after {
        return Err(AuthorityError::AuthorityBusy);
    }
    if let Some(wall) = wall
        && now_ms()? >= wall
    {
        return Err(AuthorityError::AuthorityBusy);
    }
    Ok(())
}
fn next_state(
    key: &[u8; 32],
    vault: VaultId,
    rows: &[UsageRecord],
    state: &UsageState,
) -> Result<UsageState, AuthorityError> {
    crypto::usage::seal(
        key,
        vault,
        rows,
        state
            .revision
            .checked_add(1)
            .ok_or(AuthorityError::StorageIntegrityFailed)?,
    )
}
fn event_context(event: &AuditEvent) -> Result<UsageContext, AuthorityError> {
    Ok(UsageContext {
        request_context: event.request_context.clone(),
        session_id: event.session_id.ok_or_else(invalid)?,
        action_id: event.action_id.ok_or_else(invalid)?,
        action_version: event.action_version.ok_or_else(invalid)?,
        credential_id: event.credential_id.ok_or_else(invalid)?,
        credential_version: event.credential_version,
        authorization: event.authorization.clone().ok_or_else(invalid)?,
    })
}
fn settle_row(
    row: &mut UsageRecord,
    measured: Option<u64>,
    event: &mut AuditEvent,
) -> Result<bool, AuthorityError> {
    let stored: UsageContext = serde_json::from_str(&row.context_json)
        .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
    let mut actual = event_context(event)?;
    if stored.credential_version.is_none() {
        actual.credential_version = None;
    }
    if event.request_id != Some(row.request_id) || actual != stored {
        return Err(invalid());
    }
    let (output, source) = match (row.generation_max_output, measured) {
        (Some(_), Some(n)) => (n, UsageSource::Measured),
        (Some(max), None) => (max, UsageSource::Indeterminate),
        (None, None) => (0, UsageSource::NotApplicable),
        (None, Some(_)) => return Err(invalid()),
    };
    let source_text = match source {
        UsageSource::Measured => "measured",
        UsageSource::Indeterminate => "indeterminate",
        UsageSource::NotApplicable => "not-applicable",
    };
    let terminal = serde_json::to_string(&(
        event.event_type,
        event.outcome,
        &event.reason_code,
        event.upstream_status,
        event.latency_ms,
        event.credential_version,
    ))
    .map_err(|_| invalid())?;
    if row.output_tokens.is_some() {
        return if row.output_tokens == Some(output)
            && row.source.as_deref() == Some(source_text)
            && row.terminal_json.as_deref() == Some(&terminal)
        {
            Ok(false)
        } else {
            Err(invalid())
        };
    }
    row.output_tokens = Some(output);
    row.source = Some(source_text.into());
    row.terminal_json = Some(terminal);
    row.settled_at_ms = Some(event.created_at_ms);
    event.usage = Some(UsageEvidence {
        instance_slug: row.instance_slug.clone(),
        utc_day: row.utc_day,
        output_tokens: output,
        source,
    });
    Ok(true)
}
impl SqliteRecordStore {
    pub(crate) fn verified_usage(
        &self,
        key: &[u8; 32],
        vault: VaultId,
    ) -> Result<(Vec<UsageRecord>, UsageState), AuthorityError> {
        let tx = self.conn.unchecked_transaction().map_err(storage)?;
        verified(&tx, key, vault)
    }
    pub(crate) fn profile_usage(
        &self,
        key: &[u8; 32],
        vault: VaultId,
        principal: PrincipalId,
        instance: &str,
        day: i64,
    ) -> Result<UsageTotals, AuthorityError> {
        let (rows, _) = self.verified_usage(key, vault)?;
        totals(&rows, principal, instance, day)
    }
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn begin_profile_execution(
        &mut self,
        key: &[u8; 32],
        vault: VaultId,
        mut row: UsageRecord,
        usage: &ProfileUsageStart,
        events: &[AuditEvent],
        not_after: Instant,
        wall: Option<i64>,
    ) -> Result<UsageAdmission, AuthorityError> {
        current(not_after, wall)?;
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityError::AuditCommitFailed)?;
        let (mut rows, state) = verified(&tx, key, vault)?;
        if rows.iter().any(|r| r.request_id == row.request_id) {
            return Err(invalid());
        }
        row.started_at_ms = now_ms()?;
        row.utc_day = row.started_at_ms / 86_400_000;
        let sum = totals(&rows, row.principal_id, &row.instance_slug, row.utc_day)?;
        let admitted = sum.requests < usage.max_requests_per_day
            && sum.output_tokens < usage.max_output_tokens_per_day;
        if admitted {
            write(&tx, &row, true)?;
            rows.push(row);
            rows.sort_by_key(|r| *r.request_id.as_bytes());
            replace_state(&tx, &next_state(key, vault, &rows, &state)?)?;
            for event in events {
                super::audit::insert(&tx, event)?;
            }
        } else {
            let mut blocked = events.last().ok_or_else(invalid)?.clone();
            blocked.event_type = event_type::EXECUTION_BLOCKED;
            blocked.outcome = outcome::DENIED;
            blocked.reason_code = "profile-daily-budget".into();
            super::audit::insert(&tx, &blocked)?;
        }
        current(not_after, wall)?;
        commit_audited(tx)?;
        Ok(if admitted {
            UsageAdmission::Started
        } else {
            UsageAdmission::BudgetDenied
        })
    }
    pub(crate) fn settle_profile_execution(
        &mut self,
        key: &[u8; 32],
        vault: VaultId,
        request: RequestId,
        measured: Option<u64>,
        mut event: AuditEvent,
    ) -> Result<(), AuthorityError> {
        let tx = self
            .conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| AuthorityError::AuditCommitFailed)?;
        let (mut rows, state) = verified(&tx, key, vault)?;
        let row = rows
            .iter_mut()
            .find(|r| r.request_id == request)
            .ok_or_else(invalid)?;
        if !settle_row(row, measured, &mut event)? {
            return Ok(());
        }
        write(&tx, row, false)?;
        replace_state(&tx, &next_state(key, vault, &rows, &state)?)?;
        super::audit::insert(&tx, &event)?;
        commit_audited(tx)
    }
    pub(crate) fn recover_profile_usage(
        &mut self,
        key: &[u8; 32],
        vault: VaultId,
    ) -> Result<(), AuthorityError> {
        let tx = self
            .conn
            .transaction()
            .map_err(|_| AuthorityError::AuditCommitFailed)?;
        let (mut rows, state) = verified(&tx, key, vault)?;
        let mut changed = false;
        for row in rows.iter_mut().filter(|r| r.output_tokens.is_none()) {
            let ctx: UsageContext = serde_json::from_str(&row.context_json)
                .map_err(|_| AuthorityError::StorageIntegrityFailed)?;
            let mut event = AuditEvent {
                event_id: crypto::random_array()?,
                request_id: Some(row.request_id),
                session_id: Some(ctx.session_id),
                action_id: Some(ctx.action_id),
                action_version: Some(ctx.action_version),
                credential_id: Some(ctx.credential_id),
                credential_version: ctx.credential_version,
                authorization: Some(ctx.authorization),
                approval: None,
                request_context: ctx.request_context,
                usage: None,
                event_type: event_type::EXECUTION_INDETERMINATE,
                outcome: outcome::UNKNOWN,
                reason_code: "profile-abandoned-on-unlock".into(),
                upstream_status: None,
                latency_ms: None,
                created_at_ms: now_ms()?,
            };
            settle_row(row, None, &mut event)?;
            write(&tx, row, false)?;
            super::audit::insert(&tx, &event)?;
            changed = true;
        }
        if !changed {
            return Ok(());
        }
        replace_state(&tx, &next_state(key, vault, &rows, &state)?)?;
        commit_audited(tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AuthorizationEvidence;
    use rekey_domain::ids::{ActionId, CredentialId, PolicyRuleId, SessionId};

    #[test]
    fn settling_on_a_later_day_charges_only_authenticated_admission_day() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = SqliteRecordStore::create(&dir.path().join("fixture.db")).unwrap();
        let vault = VaultId::new_random();
        let key = [17; 32];
        let principal = PrincipalId::new_random();
        let context = UsageContext {
            request_context: None,
            session_id: SessionId::new_random(),
            action_id: ActionId::new_random(),
            action_version: 1,
            credential_id: CredentialId::new_random(),
            credential_version: None,
            authorization: AuthorizationEvidence {
                principal_id: principal,
                policy_version: 1,
                policy_digest: [2; 32],
                policy_rule_id: Some(PolicyRuleId::new_random()),
                resource_type: "action".into(),
                resource_id: "fixture".into(),
                parameter_hash: [3; 32],
            },
        };
        let row = UsageRecord {
            request_id: RequestId::new_random(),
            principal_id: principal,
            instance_slug: "sample-model".into(),
            utc_day: 3,
            started_at_ms: 3 * 86_400_000 + 100,
            context_json: serde_json::to_string(&context).unwrap(),
            generation_max_output: Some(20),
            output_tokens: None,
            source: None,
            terminal_json: None,
            settled_at_ms: None,
        };
        let state = crypto::usage::seal(&key, vault, std::slice::from_ref(&row), 1).unwrap();
        let tx = store.conn.transaction().unwrap();
        write(&tx, &row, true).unwrap();
        initial_state(&tx, &state).unwrap();
        tx.commit().unwrap();
        let event = AuditEvent {
            event_id: [5; 16],
            request_id: Some(row.request_id),
            session_id: Some(context.session_id),
            action_id: Some(context.action_id),
            action_version: Some(1),
            credential_id: Some(context.credential_id),
            credential_version: Some(1),
            authorization: Some(context.authorization),
            approval: None,
            request_context: None,
            usage: None,
            event_type: event_type::EXECUTION_FINISHED,
            outcome: outcome::SUCCESS,
            reason_code: "finished".into(),
            upstream_status: Some(200),
            latency_ms: Some(5),
            created_at_ms: 4 * 86_400_000 + 100,
        };
        store
            .settle_profile_execution(&key, vault, row.request_id, Some(7), event)
            .unwrap();
        assert_eq!(
            store
                .profile_usage(&key, vault, principal, "sample-model", 3)
                .unwrap(),
            UsageTotals {
                requests: 1,
                output_tokens: 7
            }
        );
        assert_eq!(
            store
                .profile_usage(&key, vault, principal, "sample-model", 4)
                .unwrap(),
            UsageTotals::default()
        );
        let json: String = store
            .conn
            .query_row("SELECT metadata_json FROM audit_events", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_value::<UsageEvidence>(
                serde_json::from_str::<serde_json::Value>(&json).unwrap()["usage"].clone()
            )
            .unwrap()
            .utc_day,
            3
        );
    }
}
