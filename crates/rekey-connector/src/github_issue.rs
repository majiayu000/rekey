//! Public GitHub issue operation contracts. No identities, credentials, or IO.
use serde::{Deserialize, Serialize};

/// Bounds the complete request or response envelope, including JSON escaping.
pub const MAX_ISSUE_WIRE_BYTES: usize = 256 * 1024;

#[derive(Debug, Clone, Copy)]
pub enum IssueOperation {
    CreateIssue,
    CreateIssueComment,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIssueBody {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CreateIssueCommentBody {
    body: String,
}

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "operation",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum IssueEnvelope {
    CreateIssue(CreateIssueBody),
    CreateIssueComment(CreateIssueCommentBody),
}

#[derive(Debug, thiserror::Error)]
#[error("invalid GitHub issue public request")]
pub struct InvalidIssueBody;

impl IssueEnvelope {
    fn canonical_body(&self) -> Result<Vec<u8>, InvalidIssueBody> {
        match self {
            Self::CreateIssue(issue) => {
                if issue.title.is_empty()
                    || issue.title.len() > 256
                    || issue
                        .body
                        .as_ref()
                        .is_some_and(|body| body.len() > 32 * 1024)
                {
                    return Err(InvalidIssueBody);
                }
                serde_json::to_vec(issue).map_err(|_| InvalidIssueBody)
            }
            Self::CreateIssueComment(comment) => {
                if comment.body.is_empty() || comment.body.len() > 32 * 1024 {
                    return Err(InvalidIssueBody);
                }
                serde_json::to_vec(comment).map_err(|_| InvalidIssueBody)
            }
        }
    }
}

impl IssueOperation {
    fn parse_body(self, input: &[u8]) -> Result<IssueEnvelope, InvalidIssueBody> {
        if input.len() > MAX_ISSUE_WIRE_BYTES {
            return Err(InvalidIssueBody);
        }
        match self {
            Self::CreateIssue => serde_json::from_slice(input).map(IssueEnvelope::CreateIssue),
            Self::CreateIssueComment => {
                serde_json::from_slice(input).map(IssueEnvelope::CreateIssueComment)
            }
        }
        .map_err(|_| InvalidIssueBody)
    }

    pub fn normalize_body(self, input: &[u8]) -> Result<Vec<u8>, InvalidIssueBody> {
        self.parse_body(input)?.canonical_body()
    }

    /// Returns the closed canonical envelope and its trusted network body.
    pub fn prepare(self, input: &[u8]) -> Result<(Vec<u8>, Vec<u8>), InvalidIssueBody> {
        let request = self.parse_body(input)?;
        let body = request.canonical_body()?;
        let envelope = serde_json::to_vec(&request).map_err(|_| InvalidIssueBody)?;
        if envelope.len() > MAX_ISSUE_WIRE_BYTES {
            return Err(InvalidIssueBody);
        }
        Ok((envelope, body))
    }
}

pub fn normalize_issue_body(input: &[u8]) -> Result<Vec<u8>, InvalidIssueBody> {
    IssueOperation::CreateIssue.normalize_body(input)
}

pub fn normalize_comment_body(input: &[u8]) -> Result<Vec<u8>, InvalidIssueBody> {
    IssueOperation::CreateIssueComment.normalize_body(input)
}

pub fn normalize_issue_envelope(input: &[u8]) -> Result<Vec<u8>, InvalidIssueBody> {
    if input.len() > MAX_ISSUE_WIRE_BYTES {
        return Err(InvalidIssueBody);
    }
    let request: IssueEnvelope = serde_json::from_slice(input).map_err(|_| InvalidIssueBody)?;
    request.canonical_body()?;
    let output = serde_json::to_vec(&request).map_err(|_| InvalidIssueBody)?;
    if output.len() > MAX_ISSUE_WIRE_BYTES {
        return Err(InvalidIssueBody);
    }
    Ok(output)
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
        for value in [
            serde_json::json!({"title":"a".repeat(257)}),
            serde_json::json!({"title":"t","body":"a".repeat(32769)}),
        ] {
            assert!(normalize_issue_body(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn comment_body_is_closed_and_bounded() {
        assert_eq!(
            normalize_comment_body(br#"{ "body": "comment" }"#).unwrap(),
            br#"{"body":"comment"}"#
        );
        for body in [
            br#"{"body":""}"#.as_slice(),
            br#"{}"#,
            br#"{"body":"x","body":"y"}"#,
            br#"{"body":"x","title":"t"}"#,
        ] {
            assert!(normalize_comment_body(body).is_err());
        }
        assert!(
            normalize_comment_body(
                &serde_json::to_vec(&serde_json::json!({"body":"a".repeat(32769)})).unwrap()
            )
            .is_err()
        );
    }

    #[test]
    fn both_operation_envelopes_are_canonical_and_closed() {
        for (operation, body, expected) in [
            (
                IssueOperation::CreateIssue,
                br#"{ "body": "b", "title": "t" }"#.as_slice(),
                br#"{"operation":"create_issue","body":{"title":"t","body":"b"}}"#.as_slice(),
            ),
            (
                IssueOperation::CreateIssueComment,
                br#"{ "body": "b" }"#,
                br#"{"operation":"create_issue_comment","body":{"body":"b"}}"#,
            ),
        ] {
            let (envelope, canonical_body) = operation.prepare(body).unwrap();
            assert_eq!(envelope, expected);
            assert_eq!(canonical_body, operation.normalize_body(body).unwrap());
            assert_eq!(normalize_issue_envelope(&envelope).unwrap(), expected);
        }
        for input in [
            r#"{"operation":"unknown","body":{"body":"b"}}"#,
            r#"{"operation":"create_issue","body":{"body":"b"}}"#,
            r#"{"operation":"create_issue_comment","body":{"title":"t","body":"b"}}"#,
            r#"{"operation":"create_issue_comment","body":{"body":"b"},"route":"evil"}"#,
            r#"{"operation":"create_issue_comment","operation":"create_issue_comment","body":{"body":"b"}}"#,
            r#"{"operation":"create_issue_comment","body":{"body":"b"},"body":{"body":"b"}}"#,
            r#"{"operation":"create_issue_comment","body":{"body":"b","body":"b"}}"#,
            r#"{"body":{"body":"b","body":"b"},"operation":"create_issue_comment"}"#,
            r#"{"body":{"body":"b"},"body":{"body":"b"},"operation":"create_issue_comment"}"#,
            r#"{"body":{"body":"b"},"operation":"create_issue_comment","operation":"create_issue_comment"}"#,
            r#"{"body":{"title":"t","title":"t"},"operation":"create_issue"}"#,
            r#"{"operation":"create_issue","body":{"title":"t","body":null,"body":"b"}}"#,
            r#"{"body":{"title":"t","route":"evil"},"operation":"create_issue"}"#,
        ] {
            assert!(
                normalize_issue_envelope(input.as_bytes()).is_err(),
                "{input}"
            );
        }
        assert!(normalize_issue_envelope(&vec![b' '; MAX_ISSUE_WIRE_BYTES + 1]).is_err());
    }
}
