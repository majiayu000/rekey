use std::collections::BTreeSet;
use std::time::Instant;

use rekey_domain::credential::CredentialKind;

use super::{Worker, ensure_mutation_current, unlock_audit};
use crate::AuthorityError;
use crate::command::UnlockProof;
use crate::hygiene::{
    EnvImportEntry, EnvImportReport, EnvImportRequest, ScanCredential, ScanFinding, ScanInput,
    finding, invalid, matching_positions, validate_scan_inputs,
};
use crate::model::outcome;
use crate::secret::SecretInput;

impl Worker {
    pub(super) fn scan_credentials(
        &mut self,
        inputs: Vec<ScanInput>,
        credentials: Vec<ScanCredential>,
    ) -> Result<Vec<ScanFinding>, AuthorityError> {
        self.require_unlocked()?;
        validate_scan_inputs(&inputs)?;
        let mut positions = BTreeSet::new();
        let mut findings = Vec::new();
        for credential in credentials {
            // Prepared bytes are consumed inside the Authority thread. No
            // plaintext, encodings, or digest is returned to the broker.
            let prepared = self.prepare_internal_credential(credential.credential_id)?;
            let kind = prepared.kind();
            prepared.consume(|payload| {
                super::tokens::scan_payload(kind, payload, |secret| {
                    for input in &inputs {
                        for offset in matching_positions(&input.bytes, secret)? {
                            if positions.insert((
                                input.path.clone(),
                                offset,
                                credential.connection.clone(),
                            )) {
                                findings.push(finding(input, offset, &credential.connection));
                            }
                            if findings.len() > crate::hygiene::SCAN_MAX_FINDINGS {
                                return Err(invalid(
                                    "too many scan findings; scan a smaller input",
                                ));
                            }
                        }
                    }
                    Ok(())
                })
            })?;
        }
        let mut audit = unlock_audit("scan.performed", outcome::SUCCESS, "complete-match");
        audit.reason_code = format!("requests=1;findings={}", findings.len());
        // Audit failure returns no result and faults the worker, as for every
        // other sensitive operation.
        self.append_audit(audit)?;
        Ok(findings)
    }

    pub(super) fn import_env(
        &mut self,
        request: EnvImportRequest,
        proof: UnlockProof,
        not_after: Option<Instant>,
    ) -> Result<EnvImportReport, AuthorityError> {
        self.require_unlocked()?;
        self.verify_proof(&proof)?;
        drop(proof);
        ensure_mutation_current(not_after)?;
        let parsed = crate::hygiene::env::load_env(&request.path)?;
        let mut keys = BTreeSet::new();
        let mut labels = BTreeSet::new();
        let existing = self.credential_list()?;
        for selection in &request.selections {
            if !keys.insert(&selection.key)
                || !labels.insert(selection.label.as_str())
                || !parsed
                    .entries
                    .iter()
                    .any(|entry| entry.key == selection.key)
            {
                return Err(invalid("dotenv import key is unavailable or duplicated"));
            }
            if existing
                .iter()
                .any(|credential| credential.label.as_str() == selection.label.as_str())
            {
                return Err(AuthorityError::CredentialConflict);
            }
        }
        let mut imported = Vec::new();
        for selection in request.selections {
            ensure_mutation_current(not_after)?;
            let entry = parsed
                .entries
                .iter()
                .find(|entry| entry.key == selection.key)
                .ok_or_else(|| invalid("dotenv import key is unavailable"))?;
            let credential = self.insert_credential(
                selection.label,
                CredentialKind::OpaqueToken,
                SecretInput::from_slice(&entry.value),
                not_after,
            )?;
            imported.push(EnvImportEntry {
                key: selection.key,
                credential,
            });
        }
        let mut audit = unlock_audit("env.imported", outcome::SUCCESS, "selected-keys");
        audit.reason_code = format!(
            "imported={};unsupported={}",
            imported.len(),
            parsed.unsupported.len()
        );
        self.append_audit(audit)?;
        Ok(EnvImportReport {
            entries: imported,
            unsupported: parsed.unsupported,
        })
    }
}
