# Rekey v3 功能事实矩阵

目标：**3.0.0-alpha.1 未发布候选**。本表描述当前源码与有界软件证据，所有 v3
`Release` 均为 **Pending**。旧 v2 发布结果仅适用于其历史二进制，不可升级为 v3 证明。
[v3 SPEC](../superpowers/specs/2026-10-02-rekey-v3-personal-first.md)定义要求，
[唯一实施记录](../superpowers/plans/2026-10-03-v3-implementation.md)保留各冻结批次的实际命令、失败与复验。
GLM Responses最终源码默认全仓通过1,021/0 failed/6 ignored；两配置严格Clippy、all-targets编译与22流式/16网关定向通过。
CI收尾修复源码默认全仓1,021/0 failed/6 ignored，两配置严格Clippy与Lab runtime/Admin IPC定向通过；最终Lab完整复跑1,489/0 failed/6 ignored（1943.187秒）通过；此前1,488/1/6及首次relay503、22项AppRole复验均作为历史记录保留。
历史失败与本轮产物、设备范围见实施记录；本地结果不替代安装后的体验或 Release 验收。

## 默认本地产品

| 能力 | 当前事实及源码/测试入口 | 未覆盖边界 | Release |
|---|---|---|---|
| Vault、密码与恢复 | [Authority](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-vault/src/authority.rs)、[bootstrap tests](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-vault/tests/bootstrap_contract.rs)；空目录初始化、候选根校验后发布 | 真实用户备份灾难演练不是单元测试 | Pending |
| A2 管理证明 | [Admin IPC](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/ipc/admin.rs)、[CLI](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-cli/src/commands/mod.rs)；shutdown任意状态需proof、reveal不接受A1 token替代；后台状态查询不续空闲期限，已到期锁定等待查询完成并重新检查 | 系统认证设备行为 | Pending |
| Presence | [App PresenceKey](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/apps/macos/PresenceKey.swift)、[desktop authority](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-vault/src/authority/desktop.rs)；显式读取、原七天双时钟上限、不自动恢复；K不能签发新授权或修改密码/恢复因子，step-up共用失败退避；仅固定十秒复用LAContext | V1/context 已实测；已安装 App 全流程待验 | Pending |
| 服务端身份 | [macOS peer](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-cli/src/client/macos_peer.rs)、[测试](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-cli/tests/macos_peer_identity.rs)；发送证明前验证同Team精确daemon ID，有签名正负向软件证据 | Peer校验不是完整L1证明 | Pending |
| 内存加固 | [crypto](https://github.com/majiayu000/rekey/tree/v3.0.0-alpha.1/crates/rekey-vault/src/crypto)、[V2 probe](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/scripts/v3/memory_probe.c)；根/DEK零化、页锁/core限制有有界证据 | V2 正对照与候选 LLDB 拒绝已实测；不证明所有内存副本消失 | Pending |
| 回滚检测与明确恢复 | [generation tests](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-vault/tests/generation_rollback.rs)、[真实CLI测试](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/tests/rollback_cli.rs)；业务+1、外锚先保留、疑似状态无根、显式context确认后保持Locked | 真实 DPK 读/写/删权限与 CAS 已实测；不防 root/整钥匙串回滚 | Pending |
| 认证状态与备份 | [backup tests](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-vault/tests/backup_restore.rs)；完整Action/策略/用量封印、实际副本校验、receipt含generation | 不是迁移或旧因子远程失效 | Pending |
| 固定/模板Action | [Action](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-domain/src/action.rs)、[模板](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-domain/src/template.rs)、[package](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-policy/src/templates.rs)；原子安装、类型化绑定与一次规范化 | 未知模板不猜成LLM；安装不自动授权 | Pending |
| 个人/团队模式 | [personal policy](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-policy/src/personal.rs)、[App signing](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/apps/macos/PolicySigning.swift)；固定P256/Ed25519信任、原字节签署、完整差异 | 此前安装版 App 完整审阅/真实SE签署激活通过；可见取消和新复用流程弹窗次数未验 | Pending |
| 个人逐能力规则 | 必填 template-default/allow/require-approval；snapshot6；只生成既有permit或一次local-presence规则 | 软件联合检查及此前安装版 App SE签署激活通过；新认证复用的物理弹窗次数未验 | Pending |
| Approver与本机审批 | [local broker tests](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/tests/local_approval.rs)、[真实CLI](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/tests/local_approval_cli.rs)；完整review绑定、逐次Presence、owner wait/cancel、一次消费 | Remote枚举不代表实现；后台通知不读K | Pending |
| 外部审批 | [approval tests](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/tests/approval_contract.rs)；Ed25519成员、quorum、one-time/time-window；grant v1、challenge v2 | 独立sign CLI保留窄单人能力，不冒充所有library模式 | Pending |
| Profile与owner | [profile sessions](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/tests/profile_sessions.rs)、[实际run](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/tests/profile_run.rs)；同一签名scope、固定peer owner、EOF/死亡撤销 | 注册前FD移交不能还原最初connector | Pending |
| 共享LLM预算 | [executor](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/executor.rs)、[LLM](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/executor/llm.rs)；model/max在共同入口，principal+instance+UTCday持久 | 有界在途超额；不是硬费用封顶 | Pending |
| Raw SSE与遮蔽 | [stream observer](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/executor/llm_stream.rs)；raw+decoded、累计尾与SDK拼装投影、终帧等待EOF及durable settle | 未知跨delta语义拒绝；有限编码不防任意变换 | Pending |
| MCP与SDK gateway | [MCP](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/bin/rekey-mcp.rs)、[gateway tests](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/tests/gateway.rs)；只读Profile发现、精确loopback、所有入口共用执行器；非200流式错误经完整遮蔽和审计后返回原状态及允许头，socket写入无进展30秒即关闭 | 新增修复验证见实施记录；真实客户端+synthetic upstream不是实际provider | Pending |
| Activity | [App Model](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/apps/macos/Model.swift)；daemon可信审计上下文、分页/分组/预算元数据 | 不记录正文或密钥；不是SIEM/云监控 | Pending |
| App引导与文案 | [Forms](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/apps/macos/Forms.swift)、[UI harness](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/scripts/test-macos-ui.swift)；setup/add、完整确认、保护下限、只读旧格式指引 | T12新账户三命令/五分钟未验 | Pending |
| macOS安装分发 | [pkg builder](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/scripts/build-macos-pkg.sh)、[release](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/.github/workflows/release.yml)；daemon独立bundle/profile、SMAppService与cask接线 | 本地双 profile App/pkg 签名、公证、Gatekeeper 已通过；此前候选已在当前账户安装并核对收据/链接/哈希；GLM 升级版也已安装核对；登录项生命周期未验 | Pending |
| Linux用户服务 | [generator](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/scripts/rekey-service-unit.py)、[harness](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/scripts/p1-service-manager.sh)；Ubuntu24.04.4 arm64真实非root用户bus下，release CLI/BrokerRuntime夹具与release daemon生命周期均通过 | 排空/故障恢复、锁定启动/信号停机/SIGKILL重启/新证明停用已验；不代替x86公开下载或macOS登录项 | Pending |

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

当前 vault25 / policy6 已于2026-10-05冻结，覆盖所有v3预发布与正式版本；永久不迁移、不回填、不双读旧格式。
同一主版本必须保留持久格式及规范化签名语义，破坏性变化进入下一主版本。
[候选说明](../releases/v3.0.0-alpha.1.md)列出全部Pending发布门槛。
历史公开行为见[v2 alpha.2](../releases/v2.0.0-alpha.2.md)及[v2 alpha.1](../releases/v2.0.0-alpha.1.md)；
本表不修改这些历史事实；候选尚未公开发布，签名安装与 GLM 的有界真机结果按下节记录，后续实际客户端和500次零交互结果见下节；不扩展为完整产品验收。

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
