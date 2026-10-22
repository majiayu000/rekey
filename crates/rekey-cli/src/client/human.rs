//! Human-facing rendering of CLI errors. Agents and pipes keep the one-line
//! JSON contract; a person at a terminal gets a localized explanation and a
//! concrete next command instead of Agent-oriented `next` text.

use std::io::IsTerminal;

use super::CliError;

pub(super) fn json_output_forced() -> bool {
    std::env::var("REKEY_OUTPUT").as_deref() == Ok("json")
}

/// `REKEY_OUTPUT=json` always wins; `REKEY_OUTPUT=human` forces this mode
/// (tests, scripts that want the human text); otherwise a TTY stderr decides.
pub(super) fn enabled() -> bool {
    match std::env::var("REKEY_OUTPUT").as_deref() {
        Ok("json") => false,
        Ok("human") => true,
        _ => std::io::stderr().is_terminal(),
    }
}

#[cfg(target_os = "macos")]
const NOT_CONFIGURED_NEXT: &str = "用 `rekey add <provider> --app` 在 App 中添加密钥；仅测试时可用 `rekey add <provider>` 基础模式（不安全）。";
#[cfg(not(target_os = "macos"))]
const NOT_CONFIGURED_NEXT: &str = "用 `rekey credential add` 保存密钥，再按团队模式的外部签名流程签署并激活连接（见安装说明）；`rekey add <provider>` 基础模式仅限测试。";

/// Localized summary and next step for a stable error code.
fn hint(code: &str) -> (&'static str, &'static str) {
    match code {
        "IPC_UNAVAILABLE" => (
            "连不上 Rekey 后台服务。",
            "打开 Rekey App（或运行 `rekeyd serve`），再用 `rekey status` 确认。",
        ),
        "LOCKED" => (
            "保险库已锁定。",
            "运行 `rekey unlock`（`--remember 7d` 可在重启后自动解锁，但属于基础模式，仅限测试）。",
        ),
        "NOT_INITIALIZED" => (
            "还没有创建保险库。",
            "打开 Rekey App 创建保险库，或运行 `rekey init --mode personal`。",
        ),
        "NOT_CONFIGURED" => ("这个服务还没有配置连接。", NOT_CONFIGURED_NEXT),
        "TRUST_MISMATCH" => (
            "这个保险库信任的签名密钥不在本机 CLI 手里（例如 App 的 Secure Enclave 密钥）。",
            "改用 `rekey add <provider> --app` 在 App 里完成（基础模式仅限测试，需另建保险库）。",
        ),
        "SIGNER_UNAVAILABLE" | "SIGNER_FAILED" => (
            "找不到或无法运行规则签名工具。",
            "确认 Rekey 安装完整（签名工具与 `rekey` 在同一目录），或改用 `rekey add <provider> --app`。",
        ),
        "INVALID_UNLOCK_CREDENTIAL" | "AUTHENTICATION_FAILED" => (
            "身份验证没有通过（密码、恢复密钥或系统认证授权无效、缺失或已过期）。",
            "重新执行命令并完成验证；忘记密码可用 `rekey unlock --recovery` 配合恢复密钥。",
        ),
        "UNLOCK_RATE_LIMITED" => ("解锁尝试过于频繁，已被暂时限制。", "稍等片刻再试。"),
        "BUDGET_EXCEEDED" => (
            "已用完这条连接的每日预算（默认 100 次请求 / 10 万输出 token）。",
            "等预算窗口重置后再试；需要其它模型时用 `rekey add <provider> --name <新名字> --model <模型>` 新建一条连接。",
        ),
        "RATE_LIMITED" => ("请求太频繁。", "稍后再试。"),
        "AUTHORITY_BUSY" => ("Rekey 正忙于处理其它请求。", "等几秒再重试同一条命令。"),
        "APPROVAL_REQUIRED" => (
            "这次调用需要你在本机批准。",
            "在 Rekey App 的通知里批准，或用 `rekey approval pending` 查看待批准请求。",
        ),
        "DENIED" | "REQUEST_DENIED" | "ACTION_DENIED" => (
            "当前规则不允许这次调用。",
            "用 `rekey connection list` 查看已有连接；需要新能力时在 App 中批准 Agent 的访问申请。",
        ),
        "UPSTREAM_ERROR" | "UPSTREAM_FAILED" => (
            "上游服务请求失败。",
            "检查网络和上游服务状态。若开着 Clash/Surge 的 TUN（fake-ip）模式，给后台服务设置 `REKEY_DOH_URL` 或改用真实 DNS；写操作不要自动重试。",
        ),
        "UPSTREAM_INDETERMINATE" => (
            "上游可能已经执行了这次请求，但结果无法确认。",
            "先到上游服务确认是否已生效，再决定是否重试。",
        ),
        "RESPONSE_BLOCKED" | "RESPONSE_SECURITY_VIOLATION" => (
            "上游响应里出现了密钥内容，Rekey 已拦截。",
            "不要重试这次请求；检查上游接口是否会回显凭据。",
        ),
        "CREDENTIAL_UNAVAILABLE" => (
            "所需凭据不可用（可能已删除或吊销）。",
            "用 `rekey credential list` 检查，必要时重新 `rekey add <provider>`。",
        ),
        "USAGE" | "INVALID_INPUT" => ("命令参数不正确。", "加 `--help` 查看用法。"),
        "UNSUPPORTED_VAULT_LAYOUT" | "UNSUPPORTED_FORMAT_VERSION" => (
            "保险库格式与当前版本不兼容（各版本线不互相迁移）。",
            "为这个版本新建保险库；不要删除旧保险库，旧版本仍可打开它。",
        ),
        "INSECURE_STATE_PERMISSIONS" => (
            "保险库目录权限过宽。",
            "把状态目录权限收紧到仅本人可读写（0700）后再试。",
        ),
        "ROLLBACK_SUSPECTED" => (
            "检测到保险库可能被回滚到旧快照。",
            "确认是否刚恢复过备份；需要时按文档用 `rekey rollback-confirm` 显式确认。",
        ),
        "UNSUPPORTED_PLATFORM" => ("当前平台不支持这个功能。", "查看文档中的平台支持说明。"),
        _ => (
            "操作失败。",
            "运行 `rekey status` 查看状态；写操作不要自动重试。",
        ),
    }
}

pub(super) fn render(err: &CliError) -> String {
    let (summary, next) = hint(&err.code);
    let mut out = format!("错误：{summary}\n");
    if !err.message.is_empty() {
        out.push_str(&format!("详情：{}\n", err.message));
    }
    out.push_str(&format!("下一步：{next}\n"));
    // Server or call-site guidance is specific to this failure (OAuth
    // settings, budget reset time, ...); keep it verbatim.
    if let Some(specific) = err
        .next
        .as_deref()
        .filter(|text| *text != super::local_next(&err.code))
    {
        out.push_str(&format!("具体建议：{specific}\n"));
    }
    if let Some(approval) = &err.approval {
        out.push_str(&format!("批准请求：{}\n", approval.challenge_id));
    }
    match &err.request_id {
        Some(id) => out.push_str(&format!("({}, request_id={id})", err.code)),
        None => out.push_str(&format!("({})", err.code)),
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
    fn unknown_codes_fall_back_without_losing_the_code() {
        let text = render(&CliError::local("SOMETHING_NEW", "x"));
        assert!(text.contains("错误：操作失败。"));
        assert!(text.ends_with("(SOMETHING_NEW)"));
    }
}
