# 追赶台账 — Rekey — 20261022-s3（易用性）

分类：必备 / 差异化 / 建议不做（由用户决定）。Kano：M 必备、O 一维、A 魅力、I 无差别。证据等级（图例）：E2 只看了官方文档，E3 读过固定版本源码，E4 实际跑过。证据见 [01](01-competitor-research.md)。

| ID | 能力 | 我方现状 | 竞品依据 | 要做的工作 | 验收标准 | 分类 | Kano | 优先级 | 状态 |
|---|---|---|---|---|---|---|---|---|---|
| G01 | 不用 GUI 也能批准 | 部分：CLI `approval review` 因记录类型不匹配报 INVALID_FRAME（[local.rs#L189](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-broker/src/executor/local.rs#L189)） | OneCLI 有 Web 卡片批准 [E4]；sallyport 用点击或 Touch ID [E2] | 修校验和测试夹具；基础模式改用密码 step-up 批准，不接受 `--remember` 文件作证明（源码推断该文件可被用于自批准） | 无 App 时 A3 能完成；同用户的另一进程只凭本地文件不能完成批准 | 必备 | M | P0 | done（未提交，2026-10-23） |
| G02 | describe 显示规则、模型、过期时间 | 缺失 | 无直接竞品依据，来自自测（本轮 Agent 猜模型名） | 扩展 describe 和 list 的输出 | Agent 首次调用就选对模型 | 必备 | M | P0 | done（未提交，2026-10-23） |
| G03 | 报错说清根因 | 部分：private-address 只显示为 `upstream request failed` | AgentSecrets 写清原因 [E3]；Agent Vault strict 模式带 proposal_hint [E4] | 把内部原因映射成公开错误码和 hint | 每类拒绝都有可操作的 next | 必备 | M | P0 | done（未提交，2026-10-23） |
| G04 | 审批 ID 一致 | 部分：`next` 指向错误的 ID | — | 统一用 challenge_id，或两个 ID 都接受 | 不出现 approval-request-unknown | 必备 | M | P0 | done（未提交，2026-10-23） |
| G05 | Agent 文档契约测试 | 未查 | Agent Vault #449 文档里的命令不存在；用户声音 P6 | 用测试校验 skill/MCP 文档里的命令都存在 | CI 守住 | 差异化 | O | P0 | done（未提交，2026-10-23） |
| G06 | 精简首次使用 | 统一口径 11 个概念，CLI 路径另有 6 条绕行 | Agent Vault 12、OneCLI 11、AgentSecrets 10；sallyport 自称两分钟上手 [E2] | 首次 add 前确认信任根；隐藏高级命令；L1-dev 警告只提示一次 | App 路径和 CLI 路径重测 H1，概念 ≤ 10 且没有绕行 | 差异化 | O | P1 | todo |
| G07 | 端口冲突时可操作 | 只报 `ipc unavailable` | — | 自动选端口或提示改哪里 | 不需要手写 service.json | 必备 | M | P1 | todo |
| G08 | 默认行为与文档一致 | generic 读要审批，README 写读允许 | — | 二选一并同步文档 | 文档与 `list --json` 一致 | 必备 | M | P1 | todo |
| G09 | 规则临期提醒 | 缺失 | — | 临期 7 天时 CLI、MCP next 和 App 都提醒 | 测试覆盖 | 差异化 | O | P1 | todo |
| G10 | 首屏讲清差异 | README 首段是格式号和免责说明 | OneCLI、Agent Vault 首屏一句话讲清做什么 | 改首屏，配实测对照表 | — | 差异化 | A | P1 | todo |
| G11 | 公开可下载的一步式 add | 只在未发布的 0.5 里有 | Agent Vault 7 条命令就能用 | 0.5 发布 + 全新机器安装验收 | 新机按 README 15 分钟内走通 | 必备 | M | P1 | todo（需你授权发布） |
| G12 | 零改动接入（透明代理） | 不支持，属于设计选择 | Agent Vault `run -- claude` | — | — | 建议不做 | I | — | 待你决定 |
| G15 | 回显封口用当前版本复测 | 只有 0.3.0-alpha.2 修复源码的本机 fixture 12/12 | Agent Vault 3/3、OneCLI 2/3 泄露 [E4]；sallyport 自述不封口 [E2] | 当前版本跑 httpbin 回显（换一个不受 fake-ip 影响的网络） | 回显中不出现 Key | 差异化 | A | P1 | todo |
| G13 | 同一 host 多把 Key、多账号 | 未查 | 用户声音 P4，约 14 人 | 先查现状 | — | 必备 | O | P2 | todo |
| G14 | 团队、云同步 | 不做 | OneCLI、AgentSecrets | — | — | 建议不做 | — | — | 待你决定 |

## 与上一轮相比

- 新增：G01–G14。上一轮台账主题是 SSE、市场和定位，这一轮聚焦易用性。
- 关闭：上一轮“继续降低上手成本”中的 CLI 一步式 add，在 0.5 源码里已经实现（PR #85），但还没有发布，所以转成 G11。
