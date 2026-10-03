# Rekey v3 功能事实矩阵

目标：**3.0.0-alpha.1 未发布候选**。本表描述当前源码与有界软件证据，所有 v3
`Release` 均为 **Pending**。旧 v2 发布结果仅适用于其历史二进制，不可升级为 v3 证明。
[v3 SPEC](../superpowers/specs/2026-10-02-rekey-v3-personal-first.md)定义要求，
[唯一实施记录](../superpowers/plans/2026-10-03-v3-implementation.md)保留各冻结批次的实际命令、失败与复验。
统一候选默认全仓已重跑通过 1,013/0 failed/6 ignored；Lab 最终全仓仍在运行，两配置严格 Clippy 通过。
历史失败与本轮产物、设备范围见实施记录；本地结果不替代安装后的体验或 Release 验收。

## 默认本地产品

| 能力 | 当前事实及源码/测试入口 | 未覆盖边界 | Release |
|---|---|---|---|
| Vault、密码与恢复 | [Authority](../../crates/rekey-vault/src/authority.rs)、[bootstrap tests](../../crates/rekey-vault/tests/bootstrap_contract.rs)；空目录初始化、候选根校验后发布 | 真实用户备份灾难演练不是单元测试 | Pending |
| A2 管理证明 | [Admin IPC](../../crates/rekey-broker/src/ipc/admin.rs)、[CLI](../../crates/rekey-cli/src/commands/mod.rs)；shutdown任意状态需proof、reveal不接受A1 token替代 | 系统认证设备行为 | Pending |
| Presence | [App PresenceKey](../../apps/macos/PresenceKey.swift)、[desktop authority](../../crates/rekey-vault/src/authority/desktop.rs)；显式读取、原七天双时钟上限、不自动恢复；K不能签发新授权或修改密码/恢复因子，step-up共用失败退避；仅固定十秒复用LAContext | V1/context 已实测；已安装 App 全流程待验 | Pending |
| 服务端身份 | [macOS peer](../../crates/rekey-cli/src/client/macos_peer.rs)、[测试](../../crates/rekey-cli/tests/macos_peer_identity.rs)；发送证明前验证同Team精确daemon ID，有签名正负向软件证据 | Peer校验不是完整L1证明 | Pending |
| 内存加固 | [crypto](../../crates/rekey-vault/src/crypto)、[V2 probe](../../scripts/v3/memory_probe.c)；根/DEK零化、页锁/core限制有有界证据 | V2 正对照与候选 LLDB 拒绝已实测；不证明所有内存副本消失 | Pending |
| 回滚检测与明确恢复 | [generation tests](../../crates/rekey-vault/tests/generation_rollback.rs)、[真实CLI测试](../../tests/rollback_cli.rs)；业务+1、外锚先保留、疑似状态无根、显式context确认后保持Locked | 真实 DPK 读/写/删权限与 CAS 已实测；不防 root/整钥匙串回滚 | Pending |
| 认证状态与备份 | [backup tests](../../crates/rekey-vault/tests/backup_restore.rs)；完整Action/策略/用量封印、实际副本校验、receipt含generation | 不是迁移或旧因子远程失效 | Pending |
| 固定/模板Action | [Action](../../crates/rekey-domain/src/action.rs)、[模板](../../crates/rekey-domain/src/template.rs)、[package](../../crates/rekey-policy/src/templates.rs)；原子安装、类型化绑定与一次规范化 | 未知模板不猜成LLM；安装不自动授权 | Pending |
| 个人/团队模式 | [personal policy](../../crates/rekey-policy/src/personal.rs)、[App signing](../../apps/macos/PolicySigning.swift)；固定P256/Ed25519信任、原字节签署、完整差异 | 真实SE签署/取消设备验收 | Pending |
| 个人逐能力规则 | 必填 template-default/allow/require-approval；snapshot6；只生成既有permit或一次local-presence规则 | 软件联合检查通过；真实SE签署仍待设备验收 | Pending |
| Approver与本机审批 | [local broker tests](../../crates/rekey-broker/tests/local_approval.rs)、[真实CLI](../../tests/local_approval_cli.rs)；完整review绑定、逐次Presence、owner wait/cancel、一次消费 | Remote枚举不代表实现；后台通知不读K | Pending |
| 外部审批 | [approval tests](../../crates/rekey-broker/tests/approval_contract.rs)；Ed25519成员、quorum、one-time/time-window；grant v1、challenge v2 | 独立sign CLI保留窄单人能力，不冒充所有library模式 | Pending |
| Profile与owner | [profile sessions](../../crates/rekey-broker/tests/profile_sessions.rs)、[实际run](../../tests/profile_run.rs)；同一签名scope、固定peer owner、EOF/死亡撤销 | 注册前FD移交不能还原最初connector | Pending |
| 共享LLM预算 | [executor](../../crates/rekey-broker/src/executor.rs)、[LLM](../../crates/rekey-broker/src/executor/llm.rs)；model/max在共同入口，principal+instance+UTCday持久 | 有界在途超额；不是硬费用封顶 | Pending |
| Raw SSE与遮蔽 | [stream observer](../../crates/rekey-broker/src/executor/llm_stream.rs)；raw+decoded、累计尾与SDK拼装投影、终帧等待EOF及durable settle | 未知跨delta语义拒绝；有限编码不防任意变换 | Pending |
| MCP与SDK gateway | [MCP](../../crates/rekey-broker/src/bin/rekey-mcp.rs)、[gateway tests](../../crates/rekey-broker/tests/gateway.rs)；只读Profile发现、精确loopback、所有入口共用执行器 | 真实客户端+synthetic upstream不是实际provider | Pending |
| Activity | [App Model](../../apps/macos/Model.swift)；daemon可信审计上下文、分页/分组/预算元数据 | 不记录正文或密钥；不是SIEM/云监控 | Pending |
| App引导与文案 | [Forms](../../apps/macos/Forms.swift)、[UI harness](../../scripts/test-macos-ui.swift)；setup/add、完整确认、保护下限、只读旧格式指引 | T12新账户三命令/五分钟未验 | Pending |
| macOS安装分发 | [pkg builder](../../scripts/build-macos-pkg.sh)、[release](../../.github/workflows/release.yml)；daemon独立bundle/profile、SMAppService与cask接线 | 本地双 profile App/pkg 签名、公证、Gatekeeper 已通过；此前候选已在当前账户安装并核对收据/链接/哈希；GLM 升级版也已安装核对；登录项生命周期未验 | Pending |
| Linux用户服务 | [generator](../../scripts/rekey-service-unit.py)、[harness](../../scripts/p1-service-manager.sh)；真实--user/default.target/no User=，生成/语法通过 | 临时环境无user bus，生命周期未验 | Pending |

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

当前 vault25 / policy6 预GA格式未最终冻结；永久不迁移、不回填、不双读旧格式。
GA同一主版本的次/补丁版本必须保留持久格式，破坏性变化进入下一主版本。
[候选说明](../releases/v3.0.0-alpha.1.md)列出全部Pending发布门槛。
历史公开行为见[v2 alpha.2](../releases/v2.0.0-alpha.2.md)及[v2 alpha.1](../releases/v2.0.0-alpha.1.md)；
本表不修改这些历史事实，也不宣称当前候选已上传、签名安装或通过真实provider验收。

## 2026-10-03 审查修复合流与设备证据

安全修复现已合流到最新候选源码。独立修复产物的 [V1 与十秒复用](../evidence/v3-review-v1-presence-2026-10-03.json)、[V2 LLDB 对照](../evidence/v3-review-v2-lldb-2026-10-03.json)和 [App ZIP 公证](../evidence/v3-review-notarization-2026-10-03.json)已有实测通过证据；该 ZIP 基于 `50d79f3`，不包含后续 M3 和回滚代码，不代表本候选 pkg 或全安装验收。最新统一产物验收继续单独记录，Release 仍 Pending。

2026-10-04 的[统一候选证据](../evidence/v3-release-acceptance-2026-10-04.json)覆盖默认全仓、签名公证 pkg、真实受保护代数/旧库检测和 SE 无交互保护。此前候选已在当前账户安装，未公开发布；新 GLM 候选 App 已公证，GLM 升级 pkg 也已公证并安装；真实 provider 通过 Rekey 的路径和 T12 仍未验收。

2026-10-04 用户指定 GLM 验收：增加固定 `glm@1` Messages 模板及 App 服务选择，复用 Anthropic gateway 协议与预算合同；不增加任意 endpoint 参数。真实 GLM 调用、流式与用量结果待记录，不能据此标记 M3 真实 provider 或 T11 通过。

当前账户 CLI 验收已另建独立个人库，经生产 Secure Enclave 签署和真实 daemon 完成信任根安装、GLM Profile 激活及 run 启动/退出撤销。证明材料仅在源码外私有目录，现有两份保险库保留；该签名 helper 路径不替代 App 首次接入、登录项生命周期或 T12。

原 Clash 配置下普通 HTTPS→GLM 实测 200；经当前 Rekey→GLM 为 502/UPSTREAM_FAILED。原因定位到 I6 公网 DNS 筛查与 198.18.* fake-IP 的兼容性，保持用户网络配置不动；不把该失败表述为服务不可用，也不放宽公网检查。
