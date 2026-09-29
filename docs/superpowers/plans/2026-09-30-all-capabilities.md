# Rekey 全部剩余功能实现与验收清单

2026-09-30。用户已要求逐项实现全部设计功能并完整测试，允许原生 threads。新授权覆盖 9 月 16 日“外部只做规格”的旧实施范围。随后用户要求先推进其他工作，真实外部环境配置和现场验收暂后置，代码实现与本地测试继续。

## 实施与完成合同

基线为 origin/main `acfa8fea6a0a620a80963008ce3fc5dc3d580cff`，实现工作树位于主仓库 `.git/codex/worktrees/all-capabilities-20260930`。原 `ci/macos-developer-id` 工作区及其未提交内容保留。每项先冻结已有规格中的最小切片，再实现实际调用链、错误及秘密边界，不添加兼容迁移或通用适配平台。

功能完成需要实际入口、持久状态/执行链、正负测试和相关端到端验收；外部权限、WORM、HSM、VM隔离、容灾和RPO/RTO需现场证据，fixture通过不能关闭这些声明。用户未授权发布、部署或使用真实凭证，本轮不据此执行。独立人工安全审查与自动化审阅分别记录。

测试责任由协调员承担整合后的 workspace 全套、all-targets check、Clippy、fmt、机械 API/CLI 依赖边界；线程运行各自定向检查，日志在主仓库 `.git/codex/threads/all-capabilities-20260930/`。首批为 DYN-05、AUD-07 与已有功能的发布包补齐，之后按共享类型/schema依赖推进下一项。新增功能没有通过验证前不提高 Feature Truth Matrix 的成熟度。

## 逐项清单

| ID | 功能 | 当前状态/责任 | 新验收证据 |
| --- | --- | --- | --- |
| APR-08 | 托管远程审批服务 | 实现中：单组织 HTTPS 文件中继；现场后置 | 最小接口、身份、收据与本地链路方案已冻结；实现尚待验证 |
| APR-09 | 通知与审批操作界面 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| APR-10 | 人员目录与组织关系 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| AUD-06 | 审计保留与删除 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| AUD-07 | 远程投递与 SIEM | 源码及本地验收通过；真实 SIEM 后置 | 27 项测试；CLI→TLS、ACK 丢失/重启、永久失败、独立修复复核 |
| AUD-08 | WORM / Legal Hold | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| BAK-07 | 复制与故障转移 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| BAK-08 | RPO/RTO 与脑裂演练 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| DYN-05 | 租约续期 | 源码及本地验收通过；现场验证后置 | parser/deadline 6、UDS 21；真实本地 Vault 1.20.3/Postgres 单次续期与角色删除；workspace 578 passed |
| DYN-06 | 持久租约及重启清理 | 实现中：Authority 加密 journal，然后接 Broker 恢复链路 | Stage A schema 15 / encrypted rows+set manifest 规格已冻结；尚待验证 |
| ENT-01 | 集中控制面 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| ENT-02 | 多租户隔离 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| ENT-03 | SSO/SCIM/组织 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| ENT-04 | HA/容灾/多节点 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| ENT-05 | 企业现场验证 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-01 | AWS Secrets 或 KMS | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-02 | GCP Secrets 或 KMS | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-03 | Azure Secrets 或 KMS | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-04 | 1Password | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-05 | PKCS#11/HSM | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-06 | OS Keychain 凭证源 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| EXT-07 | 通用签名/Provider | 固定 Vault Transit 切片通过合同测试；现场及其他 provider 后置 | 11 项 Transit / 6 项软件签名；独立复审；workspace 589 passed |
| KEY-04 | VRK/DEK 轮换 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| NET-07 | Agent 可见流式响应 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| OS-05 | macOS 隔离启动器 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| OS-06 | 跨平台强隔离 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| SDK-04 | 动态插件加载 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| UX-04 | 可视化策略审批流程 | 复用 APR-09/POL-09，不重复计数 | 尚未新增验收证据 |
| VEX-01 | 私网 Vault | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| VEX-02 | Vault 登录方式 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| VEX-03 | Vault 续期/Namespace/引擎 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| VEX-04 | KV 最新版与写入 | 待实现；真实环境验收暂后置 | 尚未新增验收证据 |
| P-08 | 可观测性 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |
| P-10 | Connector 隔离 | 已有有界实现；完整范围与测试逐项复核 | 尚未新增验收证据 |

## 交付缺口

MCP、policy/approval signer、onboarding/repair/backup/audit 辅助工具已补入未来发布归档；精确 workflow 本地打包、归档清单/文档链接、解包 MCP/Seatbelt 和签名器真实 Broker 入口验收通过；当前 alpha.2 公共下载不因此自动更新。服务商分组/一键接入及全部原生点击路径按实际最小交互逐项落实，不能把 CLI bridge 测试作为全部 GUI 验收。

## 依赖与现场输入

DYN-06 journal/恢复清理及外部 CredentialKind 修改由单一集成者分配新 schema 格式并统一 crypto/AAD/IPC 接线；不得多个线程各自碰同一文件。EXT-07/05 独立 signer 与审计运输工具可独立推进。ENT-01/02 先固定节点/租户归属；ENT-03/APR-10 再接稳定身份及实际撤权；ENT-04/BAK-07/08/ENT-05 需独立 fencing 和真实主备演练。

真实账号/节点信息待用户后续提供。保留所有未实现条目，不把候选规格、有限实现或历史测试相加为完成百分比。

首批本地证据保存在 `.git/codex/threads/all-capabilities-20260930/first-batch-acceptance.json` 与对应日志。workspace 报告合计 578 passed/0 failed/1 ignored（性能用例）；完整 workspace/all-targets/Clippy/fmt/机械边界及独立复查已完成。候选归档未签名、公证或发布。该首批结果不关闭其余待实现条目。

第二批 Transit 合同测试已整合，完整 workspace 报告合计 589 passed/0 failed/1 ignored；all-targets、Clippy、fmt 和机械边界通过。首次全量运行的一项旧审计超时夹具提前结束，定向重跑及暂停并行耗时测试后的完整重跑均通过；未改用例超时或弱化断言，负载关联尚未证明。独立 Transit 复审无剩余 actionable finding。证据在 `transit-batch-acceptance.json`；真实 Vault 签名 ACL/撤权及远程 grant 现场链路保留待验收。
