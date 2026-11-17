//! Agent SCAN (agent 15) wire types. Responses carry positions, signed
//! connection names and counts only, never matched content.

use serde::{Deserialize, Serialize};

/// Bytes one kernel-verified system user may submit for scanning in one
/// fixed 60-second window (SPEC agent-call model §9.1). Caller labels never
/// select or reset this budget.
pub const SCAN_USER_BYTES_PER_MINUTE: u64 = 600 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanMeta {
    pub path: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanFinding {
    pub path: String,
    pub line: u32,
    pub column: u32,
    pub connection: String,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScanResponse {
    pub findings: Vec<ScanFinding>,
    /// Distinct policy-referenced credentials that were revoked, missing or
    /// not a scannable kind; they were skipped and the rest were scanned.
    pub unavailable_credentials: u32,
}
