# Rekey 0.4 功能事实矩阵

当前源码候选为 0.4.0-alpha.1，vault26 / policy7。[当前 SPEC](../superpowers/specs/2026-10-05-rekey-agent-call-model.md)与[实施记录](../superpowers/plans/2026-10-05-agent-call-implementation.md)为行为与验收来源。各项发布状态仍为 Pending，完成代码与软件检查不等同真实设备、Agent 或公开安装验收。

2026-10-06 整合 `main` @ `0828fca` 的 SSE 安全回收、首次 HTTP handoff 和认证账本优化，同时保留下列 Connection 准入/审批合同。整合头的软件验证与性能复测另行记录；下方 0.3 数据及此前 0.4 历史规模 debug 测量不代表新头已通过或具有相同时延。

| 能力 | 实现与证据入口 | 当前边界 |
|---|---|---|
| 无令牌 Connection | domain/connection、policy/connections、broker/executor/local；真实 IPC / HTTP / MCP tests | 调用方标注仅收紧；G1同用户模型 |
| 默认读 / 写审批 / 危险写拒绝 | policy tests/connections、broker tests/personal_policy | Deny 不能被审批绕过；时间窗至多8h，锁定/策略变更清除 |
| CLI / MCP / connect / 插件 | CLI tests/agent_call、connect、hygiene；broker tests/mcp_stdio | MCP、CLI说明与hook绑定所选vault；Claude本轮按用户要求不验，Codex结果见canonical验收报告 |
| HTTP / LLM / SSE | runtime/gateway、executor/llm；personal_policy、MCP stdio | Host/Origin/入站真实Key拒绝，持久预算按Connection共享 |
| Connection 准入与收尾 | lifecycle、execution_supervisor、audit、executor/local、runtime/local_calls；验收见 connection_admission tests | 合同为全局120 / 每Connection4，在途许可持有至终态审计完成；一次审批与小时额度只在 durable started 成功时消费；故障拒绝继续执行。软件回归不替代真实负载或设备验收 |
| 访问请求 / 等待 / App | runtime/local_calls、macOS Model/Forms、ConnectionContract | 真实 Touch ID次数与C16仍待设备验收 |
| dotenv / 精确 scan / hook | vault/hygiene、CLI hygiene tests | 0600备份与有界扫描；锁定hook默认告警放行 |
| SSH agent / Git HTTP | broker/ssh_agent、SSH UDS tests、github-git preset | 软件SSH签名及真实OpenSSH git push通过；App/SE设备签名另行验收 |
| OAuth 4 providers | broker/oauth、vault/authority/tokens、OAuth scopes presets | 专项合成测试通过；供应商grant/登录与账户权限另行验收 |
| 显式 T1 | domain DerivedCredentialTarget、broker/derived、runtime/derived、delegated_credentials | Agent收到临时值；目标/权限/TTL签名固定；9项合成合同通过，真实云服务待验 |
| 人类凭据管理 | App保存/轮转、scripts/test-human-vault.py | 默认App/CLI不显示、复制或导出长期密钥；保存与轮转通过签名Connection扫描验证，逐次A2及审计故障仍验 |
| run / Profile / 本机capability | Removed in default | 仅lab工作负载代码保留，不提供旧vault迁移 |
| Seatbelt / netns / G2 | Lab reserve | 编译/脚本语法不宣称运行时或企业部署通过 |
| Vault / backup / A2 / audit | 原Authority安全合同继续，完整workspace验收 | 历史设备证据不能升格为新0.4验证 |
| 发布 | release workflow / signed App/pkg / public smoke | Pending；以实际GitHub版本与安装证据为准 |

## 0.3 历史证据

下表只适用于原0.3源码/二进制，包含已经移除的个人入口，不是0.4行为说明。

### 0.3 功能事实矩阵（历史 v3 设计）

发布前候选快照；发布后的状态以 [GitHub release](https://github.com/majiayu000/rekey/releases/tag/v0.3.0-alpha.2) 与完整 workflow 为准。

目标：**0.3.0-alpha.2 未发布候选**。本表描述当前源码与有界软件证据，当前 0.3 候选的
`Release` 均为 **Pending**。旧 v2 发布结果仅适用于其历史二进制，不可升级为 v3 证明。
[v3 SPEC](../superpowers/specs/2026-10-02-rekey-v3-personal-first.md)定义要求，
[唯一实施记录](../superpowers/plans/2026-10-03-v3-implementation.md)保留各冻结批次的实际命令、失败与复验。
GLM Responses最终源码默认全仓通过1,021/0 failed/6 ignored；两配置严格Clippy、all-targets编译与22流式/16网关定向通过。
CI收尾修复源码默认全仓1,021/0 failed/6 ignored，两配置严格Clippy与Lab runtime/Admin IPC定向通过；最终Lab完整复跑1,489/0 failed/6 ignored（1943.187秒）通过；此前1,488/1/6及首次relay503、22项AppRole复验均作为历史记录保留。
历史失败与本轮产物、设备范围见实施记录；本地结果不替代安装后的体验或 Release 验收。

## 2026-10-06 SSE 修复候选（未发布）

本机整合候选来源为 `2e1a152`，发布基线仍是 `043a020`。原协议 `optimized-v6`
的 4MiB text/tool SSE 在 c1 和 c4 下各完成 192/192，成功正文 SHA-256 无差异。
修复回收已发前缀和安全检查后的工具元数据尾，保留累计 wire/retained 限额、
完整反射投影、EOF/审计结算及取消错误合同；不放宽 0.3 冻结格式。
这不提升 L1/L2，不证明真实 provider 或 c16/c64 容量通过。
本轮整合验收与原始数据入口见[复评后续处理](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/docs/peerscope/rounds/20261006-s3/02-my-plan.md)。

## 默认本地产品

| 能力 | 当前事实及源码/测试入口 | 未覆盖边界 | Release |
|---|---|---|---|
| Vault、密码与恢复 | [Authority](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-vault/src/authority.rs)、[bootstrap tests](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-vault/tests/bootstrap_contract.rs)；空目录初始化、候选根校验后发布 | 真实用户备份灾难演练不是单元测试 | Pending |
| A2 管理证明 | [Admin IPC](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/src/ipc/admin.rs)、[CLI](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-cli/src/commands/mod.rs)；shutdown任意状态需proof、reveal不接受A1 token替代；后台状态查询不续空闲期限，已到期锁定等待查询完成并重新检查 | 系统认证设备行为 | Pending |
| Presence | [App PresenceKey](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/apps/macos/PresenceKey.swift)、[desktop authority](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-vault/src/authority/desktop.rs)；显式读取、原七天双时钟上限、不自动恢复；K不能签发新授权或修改密码/恢复因子，step-up共用失败退避；仅固定十秒复用LAContext | V1/context 已实测；已安装 App 全流程待验 | Pending |
| 服务端身份 | [macOS peer](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-cli/src/client/macos_peer.rs)、[测试](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-cli/tests/macos_peer_identity.rs)；发送证明前验证同Team精确daemon ID，有签名正负向软件证据 | Peer校验不是完整L1证明 | Pending |
| 内存加固 | [crypto](https://github.com/majiayu000/rekey/tree/v0.3.0-alpha.2/crates/rekey-vault/src/crypto)、[V2 probe](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/scripts/v3/memory_probe.c)；根/DEK零化、页锁/core限制有有界证据 | V2 正对照与候选 LLDB 拒绝已实测；不证明所有内存副本消失 | Pending |
| 回滚检测与明确恢复 | [generation tests](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-vault/tests/generation_rollback.rs)、[真实CLI测试](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/tests/rollback_cli.rs)；业务+1、外锚先保留、疑似状态无根、显式context确认后保持Locked | 真实 DPK 读/写/删权限与 CAS 已实测；不防 root/整钥匙串回滚 | Pending |
| 认证状态与备份 | [backup tests](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-vault/tests/backup_restore.rs)；完整Action/策略/用量封印、实际副本校验、receipt含generation | 不是迁移或旧因子远程失效 | Pending |
| 固定/模板Action | [Action](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-domain/src/action.rs)、[模板](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-domain/src/template.rs)、[package](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-policy/src/templates.rs)；原子安装、类型化绑定与一次规范化 | 未知模板不猜成LLM；安装不自动授权 | Pending |
| 个人/团队模式 | [personal policy](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-policy/src/personal.rs)、[App signing](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/apps/macos/PolicySigning.swift)；固定P256/Ed25519信任、原字节签署、完整差异 | 此前安装版 App 完整审阅/真实SE签署激活通过；可见取消和新复用流程弹窗次数未验 | Pending |
| 个人逐能力规则 | 必填 template-default/allow/require-approval；snapshot6；只生成既有permit或一次local-presence规则 | 软件联合检查及此前安装版 App SE签署激活通过；新认证复用的物理弹窗次数未验 | Pending |
| Approver与本机审批 | [local broker tests](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/tests/local_approval.rs)、[真实CLI](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/tests/local_approval_cli.rs)；完整review绑定、逐次Presence、owner wait/cancel、一次消费 | Remote枚举不代表实现；后台通知不读K | Pending |
| 外部审批 | [approval tests](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/tests/approval_contract.rs)；Ed25519成员、quorum、one-time/time-window；grant v1、challenge v2 | 独立sign CLI保留窄单人能力，不冒充所有library模式 | Pending |
| Profile与owner | [profile sessions](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/tests/profile_sessions.rs)、[实际run](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/tests/profile_run.rs)；同一签名scope、固定peer owner、EOF/死亡撤销 | 注册前FD移交不能还原最初connector | Pending |
| 共享LLM预算 | [executor](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/src/executor.rs)、[LLM](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/src/executor/llm.rs)；model/max在共同入口，principal+instance+UTCday持久 | 在途超额；同代数旧快照可重置用量；完整账本成本增长；不是硬费用封顶 | Pending |
| Raw SSE与遮蔽 | [stream observer](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/src/executor/llm_stream.rs)；raw+decoded、累计尾与SDK拼装投影、终帧等待EOF及durable settle | 未知跨delta语义拒绝；有限编码不防任意变换 | Pending |
| MCP与SDK gateway | [MCP](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/src/bin/rekey-mcp.rs)、[gateway tests](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/crates/rekey-broker/tests/gateway.rs)；只读Profile发现、精确loopback、所有入口共用执行器；非200流式错误经完整遮蔽和审计后返回原状态及允许头，socket写入无进展30秒即关闭 | 新增修复验证见实施记录；真实客户端+synthetic upstream不是实际provider | Pending |
| Activity | [App Model](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/apps/macos/Model.swift)；daemon可信审计上下文、分页/分组/预算元数据 | 不记录正文或密钥；不是SIEM/云监控 | Pending |
| App引导与文案 | [Forms](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/apps/macos/Forms.swift)、[UI harness](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/scripts/test-macos-ui.swift)；setup/add、完整确认、保护下限、只读旧格式指引 | T12新账户三命令/五分钟未验 | Pending |
| macOS安装分发 | [pkg builder](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/scripts/build-macos-pkg.sh)、[release](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/.github/workflows/release.yml)；daemon独立bundle/profile、SMAppService与cask接线 | 本地双 profile App/pkg 签名、公证、Gatekeeper 已通过；此前候选已在当前账户安装并核对收据/链接/哈希；GLM 升级版也已安装核对；登录项生命周期未验 | Pending |
| Linux用户服务 | [generator](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/scripts/rekey-service-unit.py)、[harness](https://github.com/majiayu000/rekey/blob/v0.3.0-alpha.2/scripts/p1-service-manager.sh)；Ubuntu24.04.4 arm64真实非root用户bus下，release CLI/BrokerRuntime夹具与release daemon生命周期均通过 | 排空/故障恢复、锁定启动/信号停机/SIGKILL重启/新证明停用已验；不代替x86公开下载或macOS登录项 | Pending |

## 保护等级与隔离

当前只确认 L1-dev 的 Agent API 边界；Locked且无会话显示L0，未知/故障不宣称等级。
签名身份是独立标签，不会把保护等级提升到L1。L1需要V1/V2及受保护锚实机验收；
L2还需要实际受限子树与拒绝其它网络访问。Linux Profile netns目前拒绝启动，旧
agent-run参考不能替代该保证；Codex Seatbelt仍有managed-preferences兼容限制。

## 企业储备（lab）

工作负载身份、JWKS/OIDC、审批relay、外部Vault/云/Keychain/PKCS#11来源、原生插件、
指标、投递/归档、controlplane与standby/DR保留源码，执行入口需`--features lab`。
其历史合同和合成/field记录仍只适用于各自版本、拓扑、provider与权限配置；默认发布不包含它们。
参见[用户指南](../user-guide.md)和[运维指南](../operations-runbook.md)的lab标记，
不从共享纯类型推断默认功能已开放。

## 格式与发布事实

当前 vault25 / policy6 已于2026-10-05冻结，继续覆盖所有0.3版本，包括预发布；永久不迁移、不回填、不双读旧格式。
0.3 发布线必须保留持久格式及规范化签名语义；不兼容变化须另行规划发布线并先修订 SPEC。改号不要求重建 vault25 / policy6。
[候选说明](../releases/v0.3.0-alpha.2.md)列出全部Pending发布门槛。
历史公开行为见[v2 alpha.2](../releases/v2.0.0-alpha.2.md)及[v2 alpha.1](../releases/v2.0.0-alpha.1.md)；
[v3.0.0-alpha.4 的公共发布与两平台下载安装检查](https://github.com/majiayu000/rekey/actions/runs/37262839187)已完成；本表不修改历史标签与证据。当前 0.3 候选须重新通过发布门槛，签名安装与 GLM 的有界真机结果按下节记录，后续实际客户端和500次零交互结果见下节；不扩展为完整产品验收。

## 2026-10-03 审查修复合流与设备证据

安全修复现已合流到最新候选源码。独立修复产物的 [V1 与十秒复用](../evidence/v3-review-v1-presence-2026-10-03.json)、[V2 LLDB 对照](../evidence/v3-review-v2-lldb-2026-10-03.json)和 [App ZIP 公证](../evidence/v3-review-notarization-2026-10-03.json)已有实测通过证据；该 ZIP 基于 `50d79f3`，不包含后续 M3 和回滚代码，不代表本候选 pkg 或全安装验收。最新统一产物验收继续单独记录，Release 仍 Pending。

2026-10-04 的[统一候选证据](../evidence/v3-release-acceptance-2026-10-04.json)覆盖默认全仓、签名公证 pkg、真实受保护代数/旧库检测和 SE 无交互保护。此前候选已在当前账户安装，未公开发布；新 GLM 候选 App 已公证，GLM 升级 pkg 也已公证并安装；真实 provider 通过 Rekey 的路径和 T12 仍未验收。

2026-10-04 用户指定 GLM 验收：增加固定 `glm@1` Messages 模板及 App 服务选择，复用 Anthropic gateway 协议与预算合同；不增加任意 endpoint 参数。真实 GLM 调用、流式与用量结果待记录，不能据此标记 M3 真实 provider 或 T11 通过。

当前账户 CLI 验收已另建独立个人库，经生产 Secure Enclave 签署和真实 daemon 完成信任根安装、GLM Profile 激活及 run 启动/退出撤销。证明材料仅在源码外私有目录，现有两份保险库保留；该签名 helper 路径不替代 App 首次接入、登录项生命周期或 T12。

原 Clash 配置下普通 HTTPS→GLM 实测 200；修复前 Rekey→GLM 为 502/UPSTREAM_FAILED。原因定位到 I6 公网 DNS 筛查与 198.18.* fake-IP 的兼容性。仅系统全虚拟地址答案触发 Cloudflare DoH，查询 A/AAAA 后沿用全部公网检查、地址固定和 TLS 域名验证；不修改 Clash、不增加 provider 例外。签名修复候选实际 `rekey run` 的普通/流式 GLM 请求均返回 200、正常结束并返回用量；17 项上游回归通过。产物、检查及范围见[统一证据](../evidence/v3-release-acceptance-2026-10-04.json)的 `fake_ip_compatibility`，不代表 500 次、Claude Code/Codex 或新账户验收。

GLM Responses 接入合同：新增固定 `glm-responses@1`（POST `/api/v1/responses`、Bearer），复用 OpenAI Responses 网关与预算。App接入页明确选择GLM/Codex；源码与软件检查已通过，最终App/pkg已签名、公证、装订且通过Gatekeeper。正常屏幕解锁后，最终签名候选的真实Codex0.160.0已通过：单请求完成、输出11token、会话撤销且六类Key编码检查零命中。此前锁屏的-25308与过期短期测试策略拒绝保留；最终公证pkg现已安装；安装版SDK复测结果见下段。

当前账户 Agent 实测：签名安装版`1e3b5cd`的GLM Messages普通/SSE及真实Claude Code通过；同一run完成500次授权调用，499成功/1上游超时，无UI/自动重试，按T11零交互条件通过。实际网关拒绝、Agent/MCP有界泄漏探针、正常/SIGKILL撤销及签名helper一次审批/跨owner/迟到结果守卫通过。该helper注入active-window检查，仍需已安装App的焦点/可见取消验证；新账户T12与公开发布未验。全部边界及原始失败见统一证据的`current_account_agent_acceptance`。

最终签名候选`abf8c2f`的两个真实客户端均已通过：Codex9.611秒（输入13352/输出11），Claude Code4.361秒（输入139/输出13），各一轮成功、一条execution.finished、退出后零会话。当前账户pkg升级的系统管理员认证在300秒后超时，未写入payload；`/Applications/Rekey.app`仍为`1e3b5cd`版本。附加connect/MCP实测因再次自动锁屏，在客户端启动前停止，不冒充MCP客户端通过。源码未改变，沿用匹配SHA的1021/0/6与strict/Swift检查；详见统一候选JSON。

2026-10-04晚间：最终Responses公证pkg已在当前账户安装，16个bundle文件与已装订候选一致，版本/收据/root所有的CLI链接/严格签名/Gatekeeper通过。安装版真实Claude Code（8.222秒、输入140/输出18）和Codex（9.008秒、输入13346/输出11）均返回OK、各一轮正常结算并退出撤销；测试daemon密码证明停机，无新增系统在场认证。当前在线stapler验证因Apple CloudKit TLS -1200失败，源App此前装订验证成功；失败未隐去，未绕过TLS。实际App焦点/取消、登录项生命周期、新账户T12及公开Release仍Pending。

最终安装版connect/MCP实测通过：临时Git项目的MCP传输配置由CLI生成，真实Codex完成一次工具调用和两轮模型请求，三条execution.finished、无indeterminate、六类Key编码零命中、退出后零会话。项目信任只保存在隔离CODEX_HOME；本次进程为已授权的Rekey固定provider工具设置approve，shell保持只读。之前客户端未加载信任/拒绝工具的记录保留，不改用户设置，不扩展为新账户T12或L2。


2026-10-05 续验：当前账户实际安装版完成个人策略完整差异审阅、Touch ID/SE签署与active v3读回；Claude Code/Codex和CLI生成配置→真实MCP工具调用通过。针对用户反馈的重复认证，同次策略激活现共用已有固定十秒 context，结束/失败/取消作废；软件同一context和取消边界验证通过，实际弹窗次数未测。新公证包及默认全仓/安装状态见统一证据 `follow_through_20261005`。实际 canary 显示后清理、可见审批取消、默认旧库占用下的SMAppService生命周期与新账户T12仍待验收，不提高保护等级或Release状态。
