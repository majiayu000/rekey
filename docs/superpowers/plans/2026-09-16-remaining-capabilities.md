# 剩余功能并行实施

2026-09-16，基于 `ceb5f58`。用户已授权并行推进此前盘点的剩余功能；旧处置文档中“未授权实施”不再作为阻止本轮工作的理由。用户随后明确选择“先完成本地功能，外部部分先做规格”。具体部署、外部账号、保留责任和威胁模型仍须明确，不能用模拟测试替代现场验证。

## 计数与范围

9 月 10 日清单的 35 条“待设计”中，KEY-05、POL-09、UX-02 已有 macOS 本机实现，按当前最小合同不重复开发。其余 32 条加原计划 P-08、P-10，共 34 个文档条目。UX-04 是 APR-09/POL-09 的体验汇总，不是独立工作包；ENT-04 与 BAK-07/08 有依赖，不能重复计数。Windows、旧代理、Agent 读取上游秘密以及不可追溯撤销的离线备份不计入本轮。

## 首轮并行与验收

| Lane | 交付 | 独占文件范围 | 验证 |
| --- | --- | --- | --- |
| metrics | P-08 现有 Admin socket 的本机指标快照与 CLI 文本导出 | domain IPC、broker、CLI、Agent 通道拒绝测试及专用 spec | workspace check；指标及恶意 Broker 定向测试 |
| approval_ui | APR-09/UX-04 审批信封的本机详情审阅 | macOS 源码、Swift 合同测试及专用 spec | workspace check；Swift 编译与真实 CLI 桥接测试 |
| remaining_plan | 对剩余功能给出最小切片与依赖 | 只读 | 当前代码与规格锚点 |
| coordinator | 集成、基线同步、独立复核与完整验收 | 独立 integration worktree | fmt、workspace check/test、机械契约、专项验收 |

两条实现 lane 从同一基线使用独立 worktree。原 main 的未提交文件保留。所有验证使用临时合成保险库；不读取或修改真实凭证，不修改全局服务/代理/配置，不进行远程发布或合并。日志保存在主仓库 `.git/codex/threads/rekey-remaining-20260916/`。

## 完整待办与依赖

“待规格”表示技术设计尚未完成，不等同于需要用户再次授权。仅“待输入”涉及无法从仓库推导的产品或部署事实。实现及验收证据未到达前不得标记完成。

| ID | 剩余内容 | 当前推进状态 / 依赖 |
| --- | --- | --- |
| APR-08 | 托管远程审批服务 | 待输入：部署位置、审批者认证；本机来源签名已有 |
| APR-09 | 通知与审批操作界面 | 本机详情审阅已实现并验收；通知渠道及托管部分已有外部规格 |
| APR-10 | 人员目录与组织关系 | 依赖 ENT-03 的稳定人员身份 |
| AUD-06 | 审计保留与删除 | 已实现并通过专项验收：显式 Admin cutoff 清理，保留完整 execution 链并使旧分页快照显式失效。自动保留策略另需时限及责任约定 |
| AUD-07 | 远程投递与 SIEM | 待输入：唯一接收端、认证及交付确认语义 |
| AUD-08 | WORM / Legal Hold | 待输入：存储服务、合规保留及解冻责任 |
| BAK-07 | 复制与故障转移 | 依赖 ENT-04 的单写者与主权转移合同 |
| BAK-08 | RPO/RTO 与脑裂演练 | 依赖 BAK-07；必须有真实拓扑和演练 |
| DYN-05 | 租约续期 | 外部规格已完成：现有 Action 期限内单租约至多一次续期，失败停止业务 IO 后 exact revoke |
| DYN-06 | 持久租约及重启清理 | 外部规格已完成：加密 journal、精确来源版本、解锁后恢复清理及无法原子化的 acquire 窗口 |
| ENT-01 | 集中控制面 | 待输入：自托管/托管模式、管理对象和部署拓扑 |
| ENT-02 | 多租户隔离 | 依赖明确的租户及管理信任边界 |
| ENT-03 | SSO/SCIM/组织 | 待输入：身份源、组织模型、撤权时限 |
| ENT-04 | HA/容灾/多节点 | 待输入：节点拓扑、单写者仲裁及可用性目标 |
| ENT-05 | 企业现场验证 | 依赖实际交付范围与现场环境；内部测试不替代 |
| EXT-01 | AWS Secrets 或 KMS | 待输入：服务、唯一操作、认证方式及专用环境 |
| EXT-02 | GCP Secrets 或 KMS | 待输入：服务、唯一操作、认证方式及专用环境 |
| EXT-03 | Azure Secrets 或 KMS | 待输入：服务、唯一操作、认证方式及专用环境 |
| EXT-04 | 1Password | 待输入：具体凭证源、访问方式及专用环境 |
| EXT-05 | PKCS#11/HSM | 待输入：硬件或模块、签名操作与信任边界 |
| EXT-06 | OS Keychain 凭证源 | 已有具体外部规格：与解锁包装区分，仍需确定使用的上游凭证及访问主体 |
| EXT-07 | 通用签名/Provider | 待输入：第一个固定操作，避免任意秘密代理 |
| KEY-04 | VRK/DEK 轮换 | DEK 与 Locked 状态双因素 VRK 轮换均已实现、通过独立审查及专项验收；不撤销历史备份或替换上游凭证 |
| NET-07 | Agent 可见流式响应 | 用户已接受独立流式接口及部分响应失败合同；固定 Anthropic 纯文本 Action 已实现并通过真实 TLS/UDS 专项验收，旧非流式合同保留 |
| OS-05 | macOS 隔离启动器 | 用户已选择 Seatbelt；`macos-seatbelt-v1` 本机实验实现与定向攻击/真实 Broker 授权测试完成，发布前仍需人工安全审查 |
| OS-06 | 跨平台强隔离 | macOS 本机与 LinuxKit 容器已有专项证据；Linux 新增确定性攻击测试并修复继承 FD 泄露。原生 Ubuntu、其他平台及完整强隔离仍待逐平台验收 |
| SDK-04 | 动态插件加载 | GitHub CreateIssue/CreateIssueComment 两操作的 Action 路径/可信摘要/协议登记及 macOS/Linux GNU 隔离加载已实现；LinuxKit arm64 已验收，x86_64/原生 Ubuntu 与通用多凭证效果插件仍未完成 |
| UX-04 | 可视化策略审批流程 | 复用 APR-09/POL-09，不单独计实现 |
| VEX-01 | 私网 Vault | 待输入：固定目标和部署信任；待规格定义 SSRF/DNS 边界 |
| VEX-02 | Vault 登录方式 | 待输入：AppRole/Kubernetes/OIDC 中选定一种 |
| VEX-03 | Vault 续期/Namespace/引擎 | 待输入：一个具体新增效果；复用租约生命周期 |
| VEX-04 | KV 最新版与写入 | 已有具体外部规格：精确版本与写入不确定性，真实挂载/权限仍待输入 |
| P-08 | 可观测性 | 本机快照及原子 textfile 发布已实现并经本地验收；OTel/远程采集/告警仍未完成 |
| P-10 | Connector 隔离 | macOS Seatbelt 与 Linux GNU 最小 rootfs/seccomp 参考插件已通过攻击及 Broker 专项；Linux 有 AS64MiB 硬限额及 READY 后父死证据，macOS 保持 RSS 采样。总物理资源上限与完整启动阶段父死保障仍未完成 |

隔离与流式的具体提案见 [实施边界](../specs/2026-09-16-local-isolation-and-streaming.md)。macOS 已选择并实现实验 Seatbelt；用户也已接受独立流式接口及 GitHub CreateIssue 参考插件，两条具体执行链均已实现并通过专项验收。

## 后续技术设计

- DEK 轮换保持 VRK、credential ID/version/state 和 AAD 不变，逐版本解密后以新随机 DEK 重加密，密文替换与成功审计在同一事务提交。必须包含退休和撤销版本；坏密文、审计/SQL 失败和截止时间到期应整体回滚。该切片不能承诺修复 VRK 泄漏或撤销旧备份。
- DYN-05 可限定到当前固定 Action 的绝对期限内续期，保留同一租约与最终 revoke。它是后续工程切片，不需要新 provider；本轮按用户选择保留为外部规格，官方 renewal API 已核实。
- DYN-06 需要加密的持久 lease journal、精确 credential version 绑定及成功解锁后的恢复清理；服务端已发租约但客户端尚未持久登记的 SIGKILL 窗口无法消除，不能承诺全部未知租约都能主动撤销。
- P-10 先定义子进程的效果协议与网络/秘密所有权，再做资源和攻击测试；SDK-04 必须在这个边界稳定后实施。
- NET-07 已按用户接受的独立合同实现 Anthropic 文本流；已发送前缀不可收回，只有 completed 代表成功。工具流式、多 provider 与实网验收仍不在该切片内。

## 完成记录

- APR-09：只读绑定详情、精确 action@version 元数据和原始信封导出已实现。worker 的 Swift app/contract 编译及 UIContract 通过，独立审查无 finding；不能显示信封不存在的原始参数，也不在 UI 验签或签发。
- P-08：本地 Admin 指标及 CLI Prometheus 文本已实现；6 项定向测试与独立审查通过，完整 P-08 仍为部分完成。
- KEY-04 DEK 切片已整合：5 种凭证、历史和撤销版本、重复轮换、两代备份恢复、错误证明、SQL/审计/提交失败及截止时间回滚均有定向测试；独立代码审查无 finding。
- AUD-06 显式清理已整合：10 项定向测试、独立审查及真实 CLI/Broker 临时库验证通过；仅完整、无审批关联的过期执行组可删，整库 477 项测试通过、1 项忽略，check/clippy/fmt 通过。
- KEY-04 VRK 已整合：全部类型/历史、三类 policy seals、replay 保留、双因素、两代备份、失败回滚及提交前后 SIGKILL 通过。真实 CLI/IPC 和 bounded stop 通过；未注入慢 COMMIT、掉电或目录 fsync 故障，隐藏 TTY 未实操。最终整库 491 项通过、0 失败、1 项原有性能基准忽略；check --all-targets、clippy -D warnings、fmt 和机械合同通过。
- 首轮已整合，workspace check --all-targets、test --workspace --offline、clippy -D warnings、Swift 合同与机械边界全部通过。测试日志保存在上述本地 artifact 目录。
- 外部 25 个 ID 已形成 [具体最小规格提案](../specs/2026-09-16-external-capabilities.md)，包含官方 API 来源、信任/秘密归属、输入输出、失败合同及本地/现场验收；未实现、未创建外部资源。另补 P-08 远程指标文件采集规格，明确低权限 collector 与新鲜度门禁。

未发布、未合并；“规格完成”与“功能完成”分别记录。

## 本轮收尾

截至 `a75447a`，本机已交付指标快照、审批详情审阅、DEK/VRK 轮换、显式执行审计清理，以及 macOS 实验 Seatbelt 启动器。外部 25 个条目及远程指标采集已交付规格提案，尚无外部部署验收。随后用户已选择本仓库 GitHub CreateIssue 参考插件，并接受独立流式的部分响应失败合同；这两项已整合到当前源码并通过专项验收。不能将 Agent 启动隔离算作动态插件隔离完成。

最终源码位于本地 `codex/remaining-integration-20260916` worktree，原 main 的既有未提交内容保持不变。未推送、合并、打包发布或安装替换运行服务。密钥、认证与 IPC 的源码仍需合并前人工安全审查，自动化/代理审阅不能替代该要求。


## 继续实施（2026-09-16）

用户再次授权继续并行完成。保持本地优先、外部规格和不发布范围，本轮从 `a75447a` 开始：

| Lane | 最小交付 | 边界 |
| --- | --- | --- |
| metrics_export | 一次性把现有本机指标原子发布到受控 textfile 目录 | 独立 worktree；不部署 Node Exporter、调度器或 Prometheus |
| plugin_slice | 用现有真实 Connector 的实现证据选择 P-10/SDK-04 最小切片 | 只读收敛后再冻结实现合同；不能把 echo 或独立模块测试算动态调用链 |
| stream_contract | 基于实际 IPC/transport 与官方流式 API 明确 NET-07 合同 | 不默默修改既有完整检查后返回的响应语义 |
| coordinator | 更新唯一剩余清单、集成与完整验证 | 原 main 未提交内容保留；不推送/合并/全局安装 |

每个新增能力只有实现及定向验收通过才更新完成状态；研究结论和规格单独标记。


### 本轮集成交付

- P-08 textfile：原子发布 `rekey.prom`，固定权限、互斥及失败失效；真实本机 Broker 烟测与 8 项专项通过。ACL 与远程采集新鲜度由运维显式保证。
- P-10 参考插件：macOS 固定打包 GitHub CreateIssue sidecar；8 项攻击、真实 Broker 效果与 revoke-before-success 测试通过。SDK-04 注册及完整硬资源隔离仍未完成。
- NET-07：8 项真实 TLS/UDS、4 项跨块 sealer/parser、CLI 完成/错误协议、MCP 拒载及 v10 格式拒绝通过。仅本地 fixture；没有实际 provider 账号验收。
- 独立审查发现并修复 deadline、MCP、SSE 混合换行及插件安装入口共 4 项 P2，复核通过。
- 当前源码格式为 11，明确拒绝旧状态与备份，不迁移。最终整库结果另见本节收尾记录。


### 最终本地验证

整合后 `cargo test --workspace --offline -- --test-threads=1` 全绿：531 项通过、0 失败、1 项既有忽略项（含测试子进程报告）。`cargo check --workspace --all-targets --offline`、Clippy warnings denied、fmt、机械 API/CLI 依赖边界及 diff 检查通过。打包清单验证了本地 staging 的文档链接、三个二进制及缺 sidecar 的拒绝；未验证发布签名、公证或远程安装。

首轮整库暴露的预准入错误回包回归已在生产路径修复，原 Agent IPC 断言保留；策略进程验收中旧格式 10 的精确断言已更新为 11。并发验证时出现的既有 VRK 3 秒准备时间断言，在原断言不变的单独及最终串行整库运行中通过。日志位于主仓库 `.git/codex/threads/remaining-next-20260916/`。

后续仍为：SDK-04 的 Admin artifact 注册/绑定，P-10 完整硬资源限额及逐平台验收，P-08 远程采集/告警，以及外部与企业规格的实际目标接入。当前三项本机交付不关闭这些较大的工作包。安全相关变更仍须合并前人工审查。


## 用户授权推送并继续（2026-09-16）

已将此前六个本机提交推送至 `origin/codex/remaining-integration-20260916`，远端 tip 已核对为 `d6de59f8efe2c6ac79ae05768d5936ce480aaf37`；未合并。下一轮沿用独立线程，实施 Action 版本内的单协议 artifact 登记（规格 `2026-09-16-action-plugin-registration.md`），并核实当前 macOS 资源限额。外部服务/企业目标仍只交付规格。


### 本轮本机进展

- SDK-04 的单协议 Action 登记已实现，真实 Broker 7 项、域模型 2 项、存储 23 项、备份 14 项、既有 runner 攻击 8 项通过。原生执行实证仅限 macOS；非 macOS 拒绝路径有条件测试，本机没有执行。
- 独立审查未发现生产 P1/P2；CLI update/disable 验收缺口已补。自动门禁要求的 Authority dispatch 拆分经机械比较证明原方法仅改变可见性。
- P-10 已完成当前 macOS 资源候选的 7 组小型探针：jetsam direct 限额有效，但经过现有 sandbox-exec 链路丢失，不能直接用于生产硬限制；AS 为虚拟空间限额，不能混同 RSS。具体来源、结果与局限已写回 GitHub 参考插件规格。
- 源码格式升为 12，旧库/备份明确拒绝。登记不包含 artifact 文件，备份恢复需重新提供相同路径和摘要文件。


### 本轮收尾验证（2026-09-17）

整合后的 release CLI/Broker/TLS P6 验收通过；整库串行 541 项通过、0 失败、1 项既有忽略项，check all-targets、Clippy、fmt、机械边界及本地打包清单通过。源码格式为 12。新的 Action 绑定插件登记仅限 GitHub CreateIssue 单协议，实际运行验收为 macOS。

剩余工作为通用多效果插件、完整硬资源及父死保障、逐平台验收、P-08 远程采集与告警，以及外部/企业规格的实际目标接入。当前 sandbox-exec 链路的 jetsam 负向结果已明确记录，未用它冒充硬内存隔离。继续保持无合并、无发布部署、无真实外部账号操作；安全相关变更须合并前人工审查。

## 2026-09-17 继续本地实现

最小切片是 GitHub 两操作协议（不新建通用效果框架）与 Linux Agent 启动器的确定性攻击验收。两条实现使用独立 worktree，父线程只整合、更新规格/脚本并运行完整验证。macOS 资源候选独立只读研究。具体结果待新鲜验证后记录，外部/企业仍按此前约定仅为规格。

### 本轮实现与独立审查

- GitHub 两操作：唯一 github-issues-v1，Broker 绑定 operation 并逐字节核对规范 envelope；同一 artifact 支持创建 Issue 和评论，仍无任意效果/网络接口。源码格式13，拒绝旧状态/备份。真实 Broker9项、connector3项、域模型29项、存储24项、备份15项及 GitHub runner/profile26项定向通过；恢复旧格式时保留原本 UnsupportedFormatVersion 分类。
- Linux：5项真实启动器攻击验收最初4项通过，FD211的state文件读取成功暴露了漏洞；Linux pre_exec 的 close_range(CLOEXEC) 修复后，最终整合源码 root 与 UID/GID65534 各5项通过，包含 file/socket、高FD降低limit、网络成功控制组和真实 Broker/Agent授权请求。Linux all-targets check/Clippy通过，非mac显式插件登记拒绝1项覆盖两操作，connector3项通过。
- 跨平台 Clippy 发现既有 metrics sticky-bit 常量在 Linux 被判同类型 cast；改用等价 POSIX八进制掩码，未改变权限合同。
- P-10 新探针再次否定“最后一次 SETEXEC 加 jetsam 即可完成硬隔离”：插件 self-exec 可清空限额。固定可信自设沙箱 sidecar 是另一信任合同，不能用于关闭任意 artifact 或父死立即终止；完整结果已写入参考插件规格。
- 独立审查覆盖两操作生产路径、Linux攻击测试和FD修复，无安全阻断finding。保留原有 Issue number 响应断言；安全变更仍需合并前人工审查。

日志：主仓库 `.git/codex/threads/remaining-effects-20260917/`。Linux环境为 Docker Desktop LinuxKit6.12.76/arm64 + Debian bookworm，只在专用容器放开 seccomp/systempaths，无宿主挂载、额外capability或privileged；不视为原生Ubuntu或Linux插件实现。最终整库、P6、打包与推送结果在下节记录。

### 最终验证与交付（2026-09-17）

最终源码 `cargo test --workspace --offline -- --test-threads=1`：548项通过、0失败、1项既有忽略（含子进程报告）。macOS/Linux all-targets check、Clippy warnings denied、fmt、机械API/CLI依赖边界均通过；两平台 release CLI/Broker/本地TLS P6通过。实际release工作流复制段生成本地staging后，三个二进制、归档清单与文档链接检查通过；新增隔离规格已加入打包清单。没有发布签名、公证、远程安装或真实GitHub写入。临时测试容器已清理，本机保留构建缓存镜像。

交付分支仍为 `codex/remaining-integration-20260916`，按已有授权提交并推送；未合并、未部署。原 main 的既有修改保持原样。当前格式13，旧库及备份明确拒绝，不做迁移。

后续尚未关闭：通用多凭证效果插件及Linux/其他平台插件后端；任意原生插件硬内存及父死保障；其余系统的现场隔离验收；P-08远程采集/告警及外部/企业25个条目的实际目标接入。后两类按用户此前选择仅交付规格，不创建外部资源。合并前人工安全审查仍必需，自动化与线程审阅不能替代。


## 2026-09-17 Linux 插件后端进行中

本轮沿用 `c9945ed`，先冻结 GitHub 参考插件规格中的 Linux 合同，再并行研究/实现。最小范围是 Linux GNU x86_64/aarch64 显式登记与原生固定两操作；macOS 继续 Seatbelt。研究探针已证明 AS64MiB 跨 self-exec 保留、CPU hard2秒、READY 后父死清理；最终默认拒绝 allowlist 仍需通过真实执行验收。P6新增登记 artifact 被修改时零远程请求负控，再恢复原摘要执行两操作。外部/企业不创建资源，仍按此前约定保留规格。


## Linux 插件后端本轮交付

- 完成 Linux GNU 显式登记后端：只读最小 rootfs、固定 GNU 四个运行库、强制五类 namespace、默认拒绝 seccomp、CPU1/2秒、AS64MiB、NOFILE128，以及全范围 FD 清理。保持协议 github-issues-v1 与格式13；macOS 继续 Seatbelt，Linux 未登记的内置操作保持进程内解析。
- LinuxKit arm64 整合验收 root/UID65534 各通过 runner11项（含 helper）及真实 Broker9项；Linux Agent5项回归通过。两平台 all-targets check/Clippy、P6 release CLI/Broker/本地TLS均通过，含篡改登记artifact零上游请求负控。macOS整库548项通过、0失败、1项既有忽略。fmt、API/CLI依赖及本地打包清单/文档链接检查通过。
- 实现与测试设计独立审查发现并修正 namespace 可降级参数及测试控制组/清理证据问题，最终无阻断项。证据：主仓库 `.git/codex/threads/remaining-linux-plugin-20260917/`。

当前尚未关闭：通用多凭证效果插件；任意原生插件的总物理资源上限及完整启动窗口父死保障；x86_64/原生 Ubuntu 等实际平台验收；P-08远程采集/告警及外部/企业25条的实际接入。后两类继续按用户选择仅交付规格，不创建外部资源。AS64MiB不是硬RSS总量；READY后子树停止运行不等于所有后代同步reap。源码交付不等于发布、部署或人工安全审查完成。


### 原生 CI 首轮发现与修复

手动 security-gate `35132053559` 的 Linux G2 任务通过；Ubuntu 24.04.5/x86_64 的首轮插件测试包含真实 reference、资源、取消/父死及 x32/兼容 ABI 拒绝，但整库因 FD 控制组假设失败。CI 已继承两个额外 FD，原控制把总数写死为1；修复保留 ambient FD，直接确认FD500，要求数量严格增加1，沙箱仍必须全部为0，并注入两个额外FD复现。没有改生产过滤器或放宽沙箱断言。

macOS CI 的既有 VRK SQL截止测试在并行KDF争用下先耗尽3秒准备时间，尚未到达预期SQL阶段；security-gate改用与本地验收一致的 `--test-threads=1`，保持全部测试、3秒期限、SQL阶段及回滚断言不变。首轮失败记录保留；后续必须以新提交重跑，不能将其他通过项当成整库成功。

FD修复后最终 LinuxKit arm64 整库以 UID65534 串行运行：550项通过、0失败、1项既有忽略（含helper子报告），VRK SQL截止阶段测试通过。all-targets check/Clippy、Mac check、fmt、diff均通过。完整套件须安装procps并使用普通用户：root会绕过不可读目录权限；这两个环境问题均未修改测试断言。修复提交仍需原生CI重新验证。
