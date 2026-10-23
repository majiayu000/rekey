# 第 3 次独立审查（2026-10-22）

范围：只核对 review-2.md “处置（作者）”里 2 条必须改和 9 条建议改是否落实，以及新写的句子能否回到一手来源。

## 总评：可以交付

2 条必须改都已落实，新句子能在源码和 sallyport 官方文档里找到依据。9 条建议改也都已落实。`check_report.py` 复跑结果是“没有发现问题”（exit 0）。下面列的 4 处都是措辞问题，不影响交付；作者可以顺手改，改完不用再审。

## 必须改

| # | 结论 | 核对 |
|---|---|---|
| 1 01 §5 绕过结论 | 落实，回源成立 | 01:97 现在写的是“不开 `--remember` 时同用户进程无法自批准，但你自己也无法在 CLI 批准；CLI 只接受 presence 证明，这类证明只在 App 或 `--remember` 路径下产生”。源码依据：`policy_approval.rs` L409–L410 固定用 `read_step_up(ProofKind::Presence, true)` + `proof_body(ProofKind::Presence, …)`；broker 端两条批准路径（`admin.rs` `local_approval_decision` 和 `connection_approval_decision` L1696–L1714）都只调用 `verify_proof(UnlockProof::Presence(proof))`。`desktop.rs` L154–L162 的 `verify_presence` 要求存在 `PresenceState::Active` 授予，否则拒绝；授予只在 `remember_desktop`（L184 起，拒绝用 presence 换 presence）和 `resume_desktop`（从已记住的文件恢复）里产生。`remember_desktop` 的调用方只有 `DESKTOP_REMEMBER`（`admin.rs` L434），而这个消息只由 CLI `unlock --remember`（`mod.rs` L472）和 App（`apps/macos/Model.swift` L1750 的 `desktop-remember`）发出。结论成立。02:13–27、03 G01 与此一致。 |
| 2 sallyport 审批模式 | 落实，回源成立 | 本次取了 `docs/05-approvals.md`（固定 commit `22a457f`）：`session` 模式在新进程首次调用时触发，持续到进程退出；`per-call` 要求 key 或 MCP server 设置 `confirm=click/touchid`；原文还写明会话审批是默认，逐次审批需要手动开启。00:10、01:13/:123/:136/:173、02:72 都已改成“默认按进程审批，逐次审批可选”，全文没有残留“按调用审批”的说法。 |

## 建议改

| # | 结论 | 核对 |
|---|---|---|
| 1 12/12 出处 | 落实，回源成立 | `docs/releases/v0.3.0-alpha.2.md` L22–L24 原文是“相同生产组件源码的本机 fixture 复测……12/12 合成凭据反射探针拒绝……不代表真实 provider 或发布包验收”。01:81、02:61、03 G15 改写为“修复源码的本机 fixture”，并注明“不是 httpbin、不是发布包”，没有说过头。 |
| 2 A3 补 presence 前提 | 落实 | 01:83 |
| 3 表头与 SSRF 链接 | 落实 | 01:78 表头已改为“A1 实测，其余读源码”；AgentSecrets `engine.go@be53766` L250–L255 确实是 SSRF 私网/回环拦截。 |
| 4 00 直接回答 | 落实，与 01 一致 | “现在还算不上好用；默认安全比实测竞品好；不用 App 时审批走不完；App 主路径没测”分别对应 01 §3/§5/§10，没有说过头。措辞见下文第 4 条。 |
| 5 放弃门槛 | 落实 | 02:7 改为“补完 P0 和 P1 后仍要理解 10 个以上概念”。 |
| 6 sallyport 补充信息 | 落实，回源成立 | GitHub API 本次现取：189★，`pushed_at` 2026-07-19T00:59:02Z，latest release v0.8.16（2026-07-17），未归档。README 存档写有“Requires Apple Silicon and macOS 14 or newer”。02:72 已写明先确认项目还在维护。 |
| 7 计数口径 | 落实 | 43 = 35 实跑 + 6 份 not-run + 2 份驱动失败（`agentsecrets/_driver-…`，以及标记 `excluded:true` 的 `rekey/A1-k1.json`）。`agg.py` L6 跳过以 `_` 开头的文件，`agent-pass.txt` 里已经没有 `_driver` 这一行。措辞见下文第 3 条。 |
| 8 1Password 概念数 | 落实 | 01:42 |
| 9 过程说明与 E 等级 | 落实 | 正文已经没有“复核/读码”这类说明。00:22 那句“经过独立审查”属于正常的出处说明，可以保留。 |

## 可选措辞（不阻塞交付）

1. **“sallyport 只读了 README”已经不准确**（00:19、01:25、01:181）。作者已经回读了 `docs/05-approvals.md`。建议改为“只读了 README 和 docs/05-approvals.md，未实测”。
2. **“默认点击，可改 Touch ID”的出处**（01:123）。这句链接到 05-approvals.md，但“`sessionAuth` 默认为 `click`”写在 `docs/14-trust-model.md` 的 L42 和 L117。建议补上这个链接。
3. **“1 份保留、1 份排除”**（01:30）。现在 `agg.py` 两份都不计入汇总，“保留”容易让人以为它进了统计。建议改为“2 份驱动失败记录，都不计入汇总”。
4. **00:7 的“因为一个格式 bug 批不了”**只说了第一层原因。按 01 §5，修好 bug 以后，不开 `--remember` 仍然拿不到 presence 证明。建议改为“因为一个格式 bug，而且 CLI 只认 App 或 `--remember` 产生的 presence 证明”。
