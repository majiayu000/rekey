//! Local approval reply validation, preserving the broker's reviewed bytes.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::{
    ApprovalChallenge, ApprovalRequestId, ApproverSpec, FrameError,
    LOCAL_APPROVAL_REVIEW_RECORD_TYPE, LocalApprovalReview, LocalApprovalReviewResponse,
    LocalApprovalState, RESPONSE_BODY_MAX_BYTES, SESSION_APPROVAL_REVIEW_RECORD_TYPE,
};

const SSH_SCHEMA_ID: &str = "rekey.ssh-sign.v1";

/// The broker's SSH review envelope has no HTTP request fields.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalSshApprovalReview {
    record_type: String,
    challenge: ApprovalChallenge,
    ssh: BTreeMap<String, Box<serde_json::value::RawValue>>,
}

/// Validates one `APPROVAL_LOCAL_REVIEW` reply exactly as the daemon emits it.
/// Returns the metadata and the original UTF-8 review body (None when the
/// review was already cleared). Clients must not re-serialize the body: the
/// review digest covers these exact bytes.
pub fn validate_local_review_reply<'a>(
    id: ApprovalRequestId,
    metadata: &[u8],
    body: &'a [u8],
) -> Result<(LocalApprovalReviewResponse, Option<&'a str>), FrameError> {
    let metadata: LocalApprovalReviewResponse =
        serde_json::from_slice(metadata).map_err(|_| FrameError::InvalidField)?;
    let lower_hex_digest = metadata.review_sha256.len() == 64
        && metadata
            .review_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if metadata.approval_request_id != id
        || metadata.record_type != LOCAL_APPROVAL_REVIEW_RECORD_TYPE
        || !lower_hex_digest
        || metadata.body_len as usize != body.len()
        || body.len() > RESPONSE_BODY_MAX_BYTES as usize
    {
        return Err(FrameError::InvalidField);
    }
    if body.is_empty() {
        if matches!(
            metadata.state,
            LocalApprovalState::Pending | LocalApprovalState::Approved
        ) {
            return Err(FrameError::InvalidField);
        }
        return Ok((metadata, None));
    }
    let original = std::str::from_utf8(body).map_err(|_| FrameError::InvalidField)?;
    let challenge = match serde_json::from_str::<LocalApprovalReview>(original) {
        Ok(review)
            if matches!(
                review.record_type.as_str(),
                LOCAL_APPROVAL_REVIEW_RECORD_TYPE | SESSION_APPROVAL_REVIEW_RECORD_TYPE
            ) && review.challenge.schema_id.as_str() != SSH_SCHEMA_ID =>
        {
            review.challenge
        }
        _ => {
            let review: LocalSshApprovalReview =
                serde_json::from_str(original).map_err(|_| FrameError::InvalidField)?;
            if review.record_type != LOCAL_APPROVAL_REVIEW_RECORD_TYPE
                || review.challenge.schema_id.as_str() != SSH_SCHEMA_ID
                || review.ssh.is_empty()
            {
                return Err(FrameError::InvalidField);
            }
            review.challenge
        }
    };
    challenge.validate().map_err(|_| FrameError::InvalidField)?;
    if challenge.approval_request_id != id
        || !matches!(challenge.approver, ApproverSpec::LocalPresence {})
    {
        return Err(FrameError::InvalidField);
    }
    Ok((metadata, Some(original)))
}
