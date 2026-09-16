//! Public CreateIssue body contract. No identities, credentials, or IO.
use serde::{Deserialize, Serialize};

/// Worst-case JSON escaping of the existing 256-byte title and 32 KiB body.
pub const MAX_ISSUE_WIRE_BYTES: usize = 256 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIssueBody {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid GitHub CreateIssue public body")]
pub struct InvalidIssueBody;

pub fn normalize_issue_body(input: &[u8]) -> Result<Vec<u8>, InvalidIssueBody> {
    if input.len() > MAX_ISSUE_WIRE_BYTES {
        return Err(InvalidIssueBody);
    }
    let issue: CreateIssueBody = serde_json::from_slice(input).map_err(|_| InvalidIssueBody)?;
    if issue.title.is_empty()
        || issue.title.len() > 256
        || issue
            .body
            .as_ref()
            .is_some_and(|body| body.len() > 32 * 1024)
    {
        return Err(InvalidIssueBody);
    }
    serde_json::to_vec(&issue).map_err(|_| InvalidIssueBody)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_body_contract_and_normalization() {
        assert_eq!(
            normalize_issue_body(br#"{ "body": "b", "title": "t" }"#).unwrap(),
            br#"{"title":"t","body":"b"}"#
        );
        for body in [
            br#"{"title":""}"#.as_slice(),
            br#"{"title":"t","url":"https://evil"}"#,
            br#"{"title":"t","title":"changed"}"#,
        ] {
            assert!(normalize_issue_body(body).is_err());
        }
        assert!(
            normalize_issue_body(
                &serde_json::to_vec(&serde_json::json!({"title":"a".repeat(257)})).unwrap()
            )
            .is_err()
        );
    }
}
