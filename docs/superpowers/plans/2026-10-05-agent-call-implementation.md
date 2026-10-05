# Rekey 0.4 并行实现

基线：`origin/main` @ `043a020`，整合分支 `codex/agent-call-model-20261005`。行为合同：[Agent 调用模型 SPEC](../specs/2026-10-05-rekey-agent-call-model.md)；§15 推荐值已采用。当前工作版本 `0.4.0-alpha.1`，vault/backup26、policy7，旧保险库在新目录重建，无迁移。

复用 Authority、固定出站、审计、反射密封和 personal 签名流程，替换默认个人调用合同。三个执行 lane 使用独占工作树，integration 汇总，不覆盖原工作树未提交资料。

| Lane | 所有权 | 实际交付 |
|---|---|---|
| policy | domain、policy、App | 签名 HTTP / SSH / T1 记录、规则、Preset、公共 DTO、policy7、OAuth/T1/SSH 完整 App 草案审阅与签署 |
| clients | CLI、MCP binary、connect、Claude 插件、客户端脚本 | 本机无令牌调用、公开发现/等待、T1 adapter、MCP 配置、quickstart 与 Swift/真实 Agent 合同 |
| hygiene | vault、卫生模块、SSH Authority | vault26、dotenv/精确扫描、非导出 SSH 签名、OAuth/AWS 密文类型与轮换 |
| integration | broker、基线、集成测试 | 请求执行、审批与时间窗、本机 HTTP、OAuth callback/refresh、派生签发、审计、整合与安全收尾 |

## IPC 合同

新增操作码为 **12 个**，满足 SPEC 上限：

| 通道 | 编号 | 操作 |
|---|---|---|
| agent | 9–16 | LIST_CAPABILITIES、DESCRIBE、CALL、REQUEST_ACCESS、AWAIT_ACCESS、AWAIT_UNLOCK、SCAN、DERIVE_CREDENTIAL |
| admin | 62–65 | IMPORT_ENV、SSH_KEY、ACCESS_RESOLVE、OAUTH_LOGIN |

AWAIT_APPROVAL / CANCEL_APPROVAL 复用 agent6/7，为本机无令牌审批合同；预设目录和完整 Connection 编辑基线复用 admin52/60。编号与 DTO 以 [`rekey-domain::ipc`](../../../crates/rekey-domain/src/ipc.rs) 为准。秘密/证明只进帧正文，CALL metadata 只承载公开请求参数，普通结果及 T1 临时值按各自明确的 body 合同返回。

## 里程碑与交付边界

以下只记录实现交付和剩余工作，不是另一个验收 tracker。C1–C16、原始日志和通过/待验状态统一见[canonical 验收报告](../../evidence/agent-call-acceptance-2026-10-05.md)。

| 里程碑 | 当前实现交付 | 尚未闭合 |
|---|---|---|
| M1 调用核心 | Connection / 规则 / Preset、CALL、CLI discovery/call/http/dry-run、错误 next、调用方只收紧、格式26/7；默认移除 run / Profile / 本机 capability。 | 通过软件测试不代替真实设备/Agent 验收；发布线还未冻结。 |
| M2 MCP 与服务 | MCP 工具与动态操作、loopback HTTP 公开占位标记、connect/说明书/插件；MCP13 unit +11 stdio、HTTP 拒绝合同已绿。 | Claude 插件 user/project 隔离安装已通过；实际对话、完整 C15、公开下载安装仍待验。 |
| M3 人在回路 | request/await/await_unlock、同规则审批窗口、App 完整 Connection 审阅签署与 Activity；Codex 已实际完成审批和访问请求链。 | Claude 账号阻塞；真实 Touch ID 次数/两分钟计时、App 通知与交互仍待验。 |
| M4 开发卫生 | daemon dotenv 预览/导入/私有备份与原子改写、精确 scan、受管 pre-commit；最终 workspace 中 broker/vault hygiene 已绿。 | App→签署→改写→真实 SDK 完整现场链仍待验；并发编辑残余窗口不作 CAS 承诺。 |
| M5 SSH | Authority 内签名、标准 agent/session-bind、host/git 规则、Git smart HTTP；App 生成、公钥与完整 SSH 编辑/签署；真实 OpenSSH GitHub push 已通过并清理。 | 正式签名 App 上真实生成、host 登记和系统认证交互仍待验。 |
| M6 OAuth 与 T1 | Google/GitHub/Slack/Notion 有限操作与用户 client、callback/refresh/cache/rotation；AWS AssumeRole、EKS、GitHub App 固定签名目标/权限/TTL；App 与 CLI adapter 已落地，delegated9 通过。 | 真实 OAuth provider 与云服务可用性仍待验；T1 明确把临时值交给进程。 |
| M7 发布 | 默认指南/运维/候选说明、独立安全审查与专项修复、软件 gates、短 fuzz 与真实 Codex/SSH 证据；Codex 真实 GitHub 读/审批创建关闭分项已实测。 | Claude、真实 OAuth provider、完整C15/C16、签名包初始化/设备交互、公开 tag/包/下载/安装未闭合，未发布。 |

SPEC 要求每个里程碑出预发布版本；目前仅汇总一个本地 `0.4.0-alpha.1` 候选，**没有把 M1–M7 分别公开预发布**。不得用源码交付或本地测试改写为“七个里程碑都已发布/冻结”。

## 检查与规模约束

最终 `cargo test --workspace --no-fail-fast -- --test-threads=1` exit0，101 组汇总 **917 passed /0 failed /9 ignored**，原始日志 `/tmp/rekey-call-workspace-submission.log`。default/lab all-targets check 与 strict Clippy 已通过；完整命令、日志和 ignored 解释只在 canonical 报告维护。局部 worktree 的旧依赖检查失败保留为失败记录，不混入最终通过数。

上述整合统计先于旧性能夹具恢复；perf lane全仓的一项计时失败和两次独立复跑结果在canonical报告记录，不混成全绿。性能60秒实跑1 passed，default新增1个ignored。上述整合统计包含 User-Agent、OAuth 生命周期修复、两项新增 OAuth 回归及三个原生 Agent 手动测试的编译；ignored 不计通过。原生 Codex 独立通过，真实 GitHub 双客户端整体测试因 Claude 账号仍失败，分项和总结果在 canonical 报告分别列明。

旧 policy6 / Profile / G2 runtime 夹具作为 lab 企业储备保留；lab gate 只声明 `--features lab` all-targets 编译/Clippy 和归档脚本语法，不声称旧运行时验收通过。默认 P0 fault、备份耐久、ENOSPC、crypto、机械和 fuzz 门槛仍保留，不能用归档来掩盖新合同失败。

生产代码净增量目标为每阶段≤3,000行，测试另计。当前并行 commits / 整合 diff 混有多阶段、lab 条件编译重排以及 `src` 内 inline tests；不能把 `git diff --stat` 总净增行当作生产净增或各里程碑的证明。**尚未按里程碑拆分生产/测试行数，因此未证明每阶段达标**；这项需在发布收尾核实，不删测试或误算归档来凑数字。新增 IPC 数已按常量表独立核对为12。
