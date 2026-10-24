//! Human-facing rendering of CLI errors. Agents and pipes keep the one-line
//! JSON contract; a person at a terminal gets a localized explanation and a
//! concrete next command instead of Agent-oriented `next` text.

use std::io::IsTerminal;

use super::CliError;

/// `REKEY_OUTPUT=json` always wins; `REKEY_OUTPUT=human` forces this mode
/// (tests, scripts that want the human text); otherwise a TTY stderr decides.
pub(super) fn enabled() -> bool {
    match std::env::var("REKEY_OUTPUT").as_deref() {
        Ok("json") => false,
        Ok("human") => true,
        _ => std::io::stderr().is_terminal(),
    }
}

// The macOS App path does not exist on other platforms, which use team mode
// with external signing.
#[cfg(target_os = "macos")]
mod platform {
    pub const START_SERVICE: &str = "打开 Rekey App（或运行 `rekeyd serve`）";
    pub const CREATE_VAULT: &str = "运行 `rekey setup` 在 Rekey App 中创建保险库";
    pub const ADD_KEY: &str = "用 `rekey add <provider> --app` 在 App 中添加密钥；仅测试时可用 `rekey add <provider>` 基础模式（不安全）";
    pub const SIGN_RULES: &str = "改用 `rekey add <provider> --app` 在 App 中签署";
    pub const APPROVE: &str = "在 Rekey App 中批准，或用 `rekey approval pending` 查看待批准请求";
    pub const EDIT_RULES: &str = "在 Rekey App 中编辑这条连接的规则并重新签署";
}
#[cfg(not(target_os = "macos"))]
mod platform {
    pub const START_SERVICE: &str =
        "启动 Rekey 服务（`systemctl --user start rekey.service` 或 `rekeyd serve`）";
    pub const CREATE_VAULT: &str = "运行 `rekey init --mode team` 创建保险库";
    pub const ADD_KEY: &str = "用 `rekey credential add` 保存密钥，再按团队模式的外部签名流程签署并激活连接（见安装说明）；`rekey add <provider>` 基础模式仅限测试";
    pub const SIGN_RULES: &str = "按团队模式的外部签名流程签署（见安装说明）";
    pub const APPROVE: &str = "用 `rekey approval pending` 查看待批准请求并处理";
    pub const EDIT_RULES: &str = "按团队模式的外部签名流程修改并重新签署这条连接的规则";
}

/// Localized summary and next step for a stable error code.
fn hint(code: &str) -> (&'static str, String) {
    use platform::*;
    let (summary, next): (&'static str, String) = match code {
        "IPC_UNAVAILABLE" => (
            "连不上 Rekey 后台服务。",
            format!(
                "{START_SERVICE}，再用 `rekey status` 确认。如果刚才是写操作，它可能已经执行，先确认结果，不要直接重放。"
            ),
        ),
        "LOCKED" => (
            "保险库已锁定。",
            "运行 `rekey unlock`（`--remember 7d` 可在重启后自动解锁，但属于基础模式，仅限测试）。".into(),
        ),
        "NOT_INITIALIZED" => ("还没有创建保险库。", format!("{CREATE_VAULT}。")),
        "NOT_CONFIGURED" => ("这个服务还没有配置连接。", format!("{ADD_KEY}。")),
        "TRUST_MISMATCH" => (
            "这个保险库信任的签名密钥不在本机 CLI 手里。",
            format!("{SIGN_RULES}；基础模式仅限测试，需另建保险库。"),
        ),
        "SIGNER_UNAVAILABLE" | "SIGNER_FAILED" => (
            "找不到或无法运行规则签名工具。",
            format!("确认 Rekey 安装完整（签名工具与 `rekey` 在同一目录），或{SIGN_RULES}。"),
        ),
        "INVALID_UNLOCK_CREDENTIAL" | "AUTHENTICATION_FAILED" => (
            "身份验证没有通过（密码、恢复密钥或系统认证授权无效、缺失或已过期）。",
            "重新执行命令并完成验证；忘记密码可用 `rekey unlock --recovery` 配合恢复密钥。".into(),
        ),
        "UNLOCK_RATE_LIMITED" => ("解锁尝试过于频繁，已被暂时限制。", "稍等片刻再试。".into()),
        "BUDGET_EXCEEDED" => (
            "已用完这条连接签署的预算。",
            format!("等预算窗口重置后再试；需要更多额度或其它模型时，{EDIT_RULES}。"),
        ),
        "RATE_LIMITED" => ("请求太频繁。", "稍后再试；写操作不要自动重试。".into()),
        "AUTHORITY_BUSY" => (
            "Rekey 正忙，当前不能确认这次操作的结果。",
            "先检查当前状态和下面的具体建议；写操作不要自动重试。".into(),
        ),
        "APPROVAL_REQUIRED" => ("这次调用需要你在本机批准。", format!("{APPROVE}。")),
        "DENIED" | "REQUEST_DENIED" | "ACTION_DENIED" => (
            "当前规则不允许这次调用。",
            "用 `rekey connection list` 查看已签署的连接，用 `rekey access list` 处理 Agent 的访问申请；明确拒绝的规则不能靠批准放行。".into(),
        ),
        "UPSTREAM_ERROR" | "UPSTREAM_FAILED" => (
            "上游服务请求失败。",
            "检查网络和上游服务状态。若开着 Clash/Surge 的 TUN（fake-ip）模式，给后台服务设置 `REKEY_DOH_URL` 或改用真实 DNS；写操作不要自动重试。".into(),
        ),
        "UPSTREAM_INDETERMINATE" => (
            "上游可能已经执行了这次请求，但结果无法确认。",
            "先到上游服务确认是否已生效，再决定是否重试。".into(),
        ),
        "RESPONSE_BLOCKED" | "RESPONSE_SECURITY_VIOLATION" => (
            "上游响应里出现了凭据内容，Rekey 已拦截。",
            "不要重试这次请求；检查上游接口是否会回显凭据。".into(),
        ),
        "CREDENTIAL_UNAVAILABLE" => (
            "所需凭据不可用（可能已删除或吊销）。",
            format!("用 `rekey credential list` 检查；需要时重新添加：{ADD_KEY}。"),
        ),
        "USAGE" | "INVALID_INPUT" => (
            "输入不正确。",
            "检查命令参数（加 `--help` 查看用法）和下面的具体建议。".into(),
        ),
        "UNSUPPORTED_VAULT_LAYOUT" | "UNSUPPORTED_FORMAT_VERSION" => (
            "保险库格式与当前版本不兼容（各版本线不互相迁移）。",
            "为这个版本新建保险库；不要删除或改写旧保险库，旧版本仍可打开它。".into(),
        ),
        "INSECURE_STATE_PERMISSIONS" => (
            "保险库目录权限过宽。",
            "把状态目录权限收紧到仅本人可读写（0700）后再试。".into(),
        ),
        "ROLLBACK_SUSPECTED" => (
            "检测到保险库可能被回滚到旧快照。",
            "如果不是你刚刚主动恢复的备份，不要确认，先排查；确认无误后才按运维手册用 `rekey rollback-confirm` 显式确认。".into(),
        ),
        "UNSUPPORTED_PLATFORM" => (
            "当前平台不支持这个功能。",
            "查看文档中的平台支持说明。".into(),
        ),
        _ => (
            "操作失败。",
            "运行 `rekey status` 查看状态；写操作不要自动重试。".into(),
        ),
    };
    (summary, next)
}

/// Remote or call-site text may carry terminal escapes (ANSI/OSC); show
/// control characters escaped so they cannot rewrite the visible error.
fn printable(text: &str) -> String {
    text.chars()
        .flat_map(|c| -> Box<dyn Iterator<Item = char>> {
            if c.is_control() {
                Box::new(c.escape_default())
            } else {
                Box::new(std::iter::once(c))
            }
        })
        .collect()
}

pub(super) fn render(err: &CliError) -> String {
    let (summary, next) = hint(&err.code);
    let code = printable(&err.code);
    let mut out = format!("错误：{summary}\n");
    if !err.message.is_empty() {
        out.push_str(&format!("详情：{}\n", printable(&err.message)));
    }
    out.push_str(&format!("下一步：{next}\n"));
    // Server or call-site guidance is specific to this failure (OAuth
    // settings, budget reset time, ...); keep it verbatim.
    if let Some(specific) = err
        .next
        .as_deref()
        .filter(|text| *text != super::local_next(&err.code))
    {
        out.push_str(&format!("具体建议：{}\n", printable(specific)));
    }
    if let Some(approval) = &err.approval {
        out.push_str(&format!("批准请求：{}\n", approval.challenge_id));
    }
    match &err.request_id {
        Some(id) => out.push_str(&format!("({code}, request_id={id})")),
        None => out.push_str(&format!("({code})")),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_localized_hint_and_code() {
        let err = CliError::local("LOCKED", "vault is locked");
        let text = render(&err);
        assert!(text.starts_with("错误：保险库已锁定。\n"));
        assert!(text.contains("详情：vault is locked\n"));
        assert!(text.contains("`rekey unlock`"));
        assert!(text.ends_with("(LOCKED)"));
    }

    #[test]
    fn keeps_specific_next_and_omits_generic_local_next() {
        let generic = render(&CliError::local("INVALID_INPUT", "bad flag"));
        assert!(!generic.contains("具体建议："));

        let mut err = CliError::local("BUDGET_EXCEEDED", "daily budget exhausted");
        err.next = Some("Retry after 2026-10-23T00:00:00Z.".to_owned());
        let text = render(&err);
        assert!(text.contains("下一步：等预算窗口重置后再试"));
        assert!(text.contains("具体建议：Retry after 2026-10-23T00:00:00Z.\n"));
    }

    #[test]
    fn ipc_failures_keep_the_no_replay_warning() {
        let text = render(&CliError::local("IPC_UNAVAILABLE", "broker unreachable"));
        assert!(text.contains("不要直接重放"), "{text}");
    }

    #[test]
    fn busy_outcome_does_not_turn_an_uncertain_commit_into_a_retry() {
        let mut err = CliError::local("AUTHORITY_BUSY", "installation may already have committed");
        err.next = Some("Inspect installed Actions; do not retry automatically.".into());
        let text = render(&err);
        assert!(text.contains("不能确认"));
        assert!(text.contains("写操作不要自动重试"));
        assert!(text.contains("Inspect installed Actions; do not retry automatically."));
        assert!(!text.contains("没有执行"));
        assert!(!text.contains("重试同一条命令"));
    }

    #[test]
    fn control_characters_from_remote_text_are_escaped() {
        let mut err = CliError::local("UPSTREAM_FAILED", "bad\u{1b}]8;;http://x\u{7}link\u{1b}[2J");
        err.code = "X\u{1b}[31m".to_owned();
        err.next = Some("retry\rnow\u{9b}".to_owned());
        let text = render(&err);
        assert!(
            !text.chars().any(|c| c.is_control() && c != '\n'),
            "{text:?}"
        );
        assert!(text.contains("详情：bad\\u{1b}]8;;http://x\\u{7}link\\u{1b}[2J\n"));
        assert!(text.contains("具体建议：retry\\rnow\\u{9b}\n"));
        assert!(text.ends_with("(X\\u{1b}[31m)"));
    }

    #[test]
    fn unknown_codes_fall_back_without_losing_the_code() {
        let text = render(&CliError::local("SOMETHING_NEW", "x"));
        assert!(text.contains("错误：操作失败。"));
        assert!(text.ends_with("(SOMETHING_NEW)"));
    }
}
