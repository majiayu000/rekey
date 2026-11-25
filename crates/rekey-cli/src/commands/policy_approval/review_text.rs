//! Readable `approval review` output for a person at a terminal. The App and
//! pipes keep the exact JSON; the digest always covers the daemon's bytes.

use rekey_domain::ids::ApprovalRequestId;
use rekey_domain::ipc::LocalApprovalReviewResponse;
use serde_json::Value;

fn field<'a>(review: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(review, |value, key| value.get(key))
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        Some(value) => value.to_string(),
        None => "—".into(),
    }
}

pub(super) fn render(
    id: ApprovalRequestId,
    metadata: &LocalApprovalReviewResponse,
    review_json: Option<&str>,
    now_ms: i64,
) -> String {
    let state = serde_json::to_value(metadata.state)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default();
    let mut out = format!("审批请求 {id}（状态：{state}）\n");
    let Some(review) = review_json.and_then(|raw| serde_json::from_str::<Value>(raw).ok()) else {
        out.push_str("这条请求已结束，没有可批准的内容。\n");
        return out;
    };
    if let Some(ssh) = review.get("ssh") {
        out.push_str(&format!(
            "SSH 签名：{}\n主机：{}\n用途：{}\n",
            text(ssh.get("key")),
            text(ssh.get("host")),
            text(field(ssh, &["use", "purpose"])),
        ));
    } else {
        let request = review.get("canonical_request").cloned().unwrap_or_default();
        let mut target = format!(
            "{}{}",
            text(review.get("origin")),
            text(request.get("path"))
        );
        if let Some(query) = request
            .get("query")
            .and_then(Value::as_object)
            .filter(|q| !q.is_empty())
        {
            let pairs: Vec<String> = query
                .iter()
                .map(|(k, v)| format!("{k}={}", text(Some(v))))
                .collect();
            target.push('?');
            target.push_str(&pairs.join("&"));
        }
        out.push_str(&format!(
            "连接：{}\n请求：{} {target}\n",
            text(review.get("action_name")),
            text(review.get("method")),
        ));
        if let Some(headers) = request
            .get("headers")
            .and_then(Value::as_array)
            .filter(|h| !h.is_empty())
        {
            let pairs: Vec<String> = headers
                .iter()
                .filter_map(Value::as_array)
                .map(|pair| {
                    pair.iter()
                        .map(|v| text(Some(v)))
                        .collect::<Vec<_>>()
                        .join(": ")
                })
                .collect();
            out.push_str(&format!("请求头：{}\n", pairs.join("; ")));
        }
        match (
            request.get("body"),
            request.get("body_encoding").and_then(Value::as_str),
        ) {
            (Some(Value::String(body)), Some("text")) if !body.is_empty() => {
                out.push_str(&format!("正文：{body}\n"));
            }
            (Some(Value::String(body)), Some(encoding)) if !body.is_empty() => {
                out.push_str(&format!("正文：{encoding} 编码，{} 个字符\n", body.len()));
            }
            _ => out.push_str("正文：无\n"),
        }
    }
    if let Some(expires) =
        field(&review, &["challenge", "max_expires_at_ms"]).and_then(Value::as_i64)
    {
        let seconds = (expires - now_ms).max(0) / 1000;
        out.push_str(&format!(
            "剩余时间：{} 分 {} 秒\n",
            seconds / 60,
            seconds % 60
        ));
    }
    if metadata.state == rekey_domain::ipc::LocalApprovalState::Pending {
        let sha = &metadata.review_sha256;
        out.push_str(&format!(
            "\n批准：rekey approval approve {id} --review-sha256 {sha} --password\n拒绝：rekey approval reject {id} --review-sha256 {sha} --password\n",
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rekey_domain::ipc::LocalApprovalState;

    #[test]
    fn pending_http_review_names_the_target_body_and_decision_commands() {
        let id: ApprovalRequestId =
            serde_json::from_value(serde_json::json!("6f9619ff-8b86-4011-b42d-00c04fc964ff"))
                .unwrap();
        let metadata = LocalApprovalReviewResponse {
            record_type: "rekey.approval.local-review.v1".into(),
            approval_request_id: id,
            review_sha256: "a".repeat(64),
            state: LocalApprovalState::Pending,
            body_len: 0,
        };
        let review = r#"{"action_name":"github-pat","method":"POST","origin":"https://api.github.com","canonical_request":{"path":"/repos/o/r/issues","query":{"a":"1"},"headers":[["accept","application/json"]],"body":"{\"title\":\"Hi\"}","body_encoding":"text"},"challenge":{"max_expires_at_ms":125000}}"#;
        let text = render(id, &metadata, Some(review), 5_000);
        assert!(text.contains("连接：github-pat"), "{text}");
        assert!(
            text.contains("请求：POST https://api.github.com/repos/o/r/issues?a=1"),
            "{text}"
        );
        assert!(text.contains("请求头：accept: application/json"), "{text}");
        assert!(text.contains("正文：{\"title\":\"Hi\"}"), "{text}");
        assert!(text.contains("剩余时间：2 分 0 秒"), "{text}");
        assert!(text.contains(&format!("--review-sha256 {}", "a".repeat(64))));
    }
}
