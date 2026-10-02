# Rekey 全部剩余功能实现与验收清单

2026-09-30。用户已要求逐项实现全部设计功能并完整测试，允许原生 threads。新授权覆盖 9 月 16 日“外部只做规格”的旧实施范围。2026-10-02 用户授权 Docker 测试环境及本轮外部验收；先执行可用的本地真实服务与容器演练，真实云账号和硬件仍需实际环境。

## 实施与完成合同

基线为 origin/main `acfa8fea6a0a620a80963008ce3fc5dc3d580cff`，实现工作树位于主仓库 `.git/codex/worktrees/all-capabilities-20260930`。原 `ci/macos-developer-id` 工作区及其未提交内容保留。 宿主随后将主仓库 `.git` 改为只读，当前实施副本转到 `outputs/rekey-implementation-20260930/integration`，独立 Git 历史仍从上述两项本地提交衔接；源码哈希清单与证据位于同级目录。每项先冻结已有规格中的最小切片，再实现实际调用链、错误及秘密边界，不添加兼容迁移或通用适配平台。

功能完成需要实际入口、持久状态/执行链、正负测试和相关端到端验收；外部权限、WORM、HSM、VM隔离、容灾和RPO/RTO需现场证据，fixture通过不能关闭这些声明。本轮已授权上传分支、创建 PR 与一次性 Docker 测试环境；不据此发布版本或使用生产凭证。独立人工安全审查与自动化审阅分别记录。

测试责任由协调员承担整合后的 workspace 全套、all-targets check、Clippy、fmt、机械 API/CLI 依赖边界；线程运行各自定向检查，日志在主仓库 `.git/codex/threads/all-capabilities-20260930/`。首批为 DYN-05、AUD-07 与已有功能的发布包补齐，之后按共享类型/schema依赖推进下一项。新增功能没有通过验证前不提高 Feature Truth Matrix 的成熟度。

## 逐项清单

| ID | 功能 | 当前状态/责任 | 新验收证据 |
| --- | --- | --- | --- |
| APR-08 | 托管远程审批服务 | 单组织 HTTPS 文件中继、整合全量和本地实际服务通过；客户部署待验收 | 本轮完整 Rust 与 HTTPS→独立 signer→真实 Broker 通过；不是通用托管平台 |
| APR-09 | 通知与审批操作界面 | 原生文件审批流程及远程 pull inbox 已实现，本地原生点击链通过 | 真实 HTTPS relay/inbox→signer→Broker；原生App文件流程实际HTTP200，非规则编辑器或托管网页UI |
| APR-10 | 人员目录与组织关系 | SCIM消费/持久停用/事务门禁及明确Admin自证明已实现；客户节点撤权链待验收 | 本轮完整 Rust 含 relay/目录 TLS 合同通过，controlplane86通过；真实 IdP/双节点回执待验收 |
| AUD-06 | 审计保留与删除 | 授权持久 sealed 后台策略已整合 format21；本轮完整 IPC/Actor 验收通过 | 未知结果同步关闭准入、desktop 恢复验 seal、SET 继承原 deadline；本轮完整 Rust 1032/0/1，旧严格 IPC 环境失败已复测关闭 |
| AUD-07 | 远程投递与 SIEM | 源码及本地真实 CLI/TLS 验收通过；客户 SIEM 待现场 | 本轮 28/28；修复 format21 备份回执 snapshot_cut 精确校验，ACK 游标仍从零开始 |
| AUD-08 | WORM / Legal Hold | 源码合同测试及独立复核通过；实际 WORM/权限现场后置 | 23 项测试：TLS、官方 SigV4 向量、ACK 丢失/重启、版本早期持久 pin、Hold、fsync/容量/超时 |
| BAK-07 | 复制与故障转移 | 快照复制和 Docker 主备手动恢复通过；持续复制/自动切换未实现 | 独立容器卷、外部 daemon fencing、快照哈希及切点、恢复策略、新授权真实请求全部通过 |
| BAK-08 | RPO/RTO 与脑裂演练 | Docker 脑裂拒绝、独立 fencing、完整提升与计时流程已实现并通过 | 断网旧主仍活跃时拒绝提升，删除旧容器后禁止重启；本次 RTO 1361.31ms，故意丢失 1 次写入；提交间隔界限 1420.23–1760.71ms，非 SLA |
| DYN-05 | 租约续期 | 源码及本地验收通过；现场验证后置 | parser/deadline 6、UDS 21；真实本地 Vault 1.20.3/Postgres 单次续期与角色删除；workspace 578 passed |
| DYN-06 | 持久租约及重启清理 | A+B 修复已整合；本轮完整 Rust 与真实崩溃恢复通过 | 实际 Broker/SQLite/TLS 的 5 个 journal 恢复场景通过，含 SIGKILL、未知获取及清理恢复；客户 Vault 部署另验 |
| ENT-01 | 集中控制面 | 控制面目标绑定和固定文件工具本地验收通过；现场待验收 | 本轮完整 controlplane 86/86，之前严格 PTY 失败已复测通过 |
| ENT-02 | 多租户隔离 | 实际 vault/root 提交绑定及固定双节点注册/回执已实现；现场隔离待验证 | 本地 Authority 测试可证明目标校验；真实节点、VM/UID/磁盘/网络/备份隔离待现场验证 |
| ENT-03 | SSO/SCIM/组织 | 节点PKCE/管理会话/逐次目录门禁与本地撤权已实现；本轮本地合同通过 | 完整 Rust 的 TLS/loopback/UDS 与原生 OIDC16 通过；Keycloak workload 交换现场通过，不能代替管理 SSO/SCIM 双节点验收 |
| ENT-04 | HA/容灾/多节点 | Docker 有界主备容灾演练通过；跨物理机 HA 待现场 | 真实 Broker/CLI/UDS + 测试 TLS；独立外部 daemon 控制；主备卷隔离、旧令牌拒绝和清理通过 |
| ENT-05 | 企业现场验证 | 已开始执行可用真实本地服务验收；客户环境未整体通过 | 完整 Rust 1032 通过/0 失败/1 忽略；controlplane86、audit delivery28、archive23；外部服务逐门记录 |
| EXT-01 | AWS Secrets 或 KMS | 固定 ARN/VersionId 源已实现，本轮本地 TLS/UDS/blackbox 通过；真实账号待验收 | kind7/schema17/opcode42；完整 Rust 已消除旧监听 EPERM，含 token/响应头封口；客户 IAM/KMS 权限未实测 |
| EXT-02 | GCP Secrets 或 KMS | 固定数值 SecretVersion 源已实现，本轮本地 TLS/UDS/blackbox 通过；真实账号待验收 | kind6/schema16/opcode41；完整响应头封口和本轮完整 Rust 通过；客户 IAM 权限未实测 |
| EXT-03 | Azure Secrets 或 KMS | 固定 Azure 源及 OWS 修复已整合，本轮本地 TLS/UDS/blackbox 通过 | kind8/schema18/opcode43；旧 IdP 启动/监听失败已复测关闭；客户租户/权限待验收 |
| EXT-04 | 1Password | 固定 item/field 源已整合，本轮严格 TLS/UDS/blackbox 通过 | kind9/schema19/opcode44；旧源扫描误读 Unix socket 已修复；真实 Connect/客户 ACL 待验收 |
| EXT-05 | PKCS#11/HSM | PKCS#11 实现、真实 SoftHSM/控制 TTY/Broker 链通过；实体硬件待验收 | SoftHSM2.6 容器生成 Ed25519 key；生产 signer 校验不可导出等属性；错误PIN无grant，正确PIN隐藏、签名验证、实际Broker一次成功及重放拒绝；容器清理完成 |
| EXT-06 | OS Keychain 凭证源 | format21 源码和真实临时文件 Keychain 验收通过；客户条目ACL另验 | 新原生门：限定fixture可访问的实际条目→真实Broker/TLS；反射值拒绝、锁定无UI且无业务请求、审计无canary；临时Keychain清理通过并接入macOS CI |
| EXT-07 | 通用签名/Provider | 固定 Vault Transit 切片通过合同测试；现场及其他 provider 后置 | 11 项 Transit / 6 项软件签名；独立复审；workspace 589 passed |
| KEY-04 | VRK/DEK 轮换 | 既定 VRK/DEK 代码已具备；journal 轮换接入；隐藏 TTY/故障验收待补 | Stage A 定向 151/151 含 DEK/VRK；源合同见 key04-dek/vrk-rotation；旧备份不追溯撤销 |
| NET-07 | Agent 可见流式响应 | 固定 Anthropic 纯文本流已具备；现场后置 | executor/text_stream.rs、tests/text_stream.rs；MCP 明确拒绝流，不承诺通用 SSE/tools |
| OS-05 | macOS 隔离启动器 | 实验 Seatbelt 的本轮实际运行通过；较弱保证保持 | sandbox_macos 合同及归档实际入口通过；同 UID 宿主与父 SIGKILL 后全后代终止不在保证内 |
| OS-06 | 跨平台强隔离 | Mac/Linux 有界后端实际合同通过，不能提升为统一强隔离保证 | 本轮 Mac workspace 和 Ubuntu sandbox_linux 网络/FD/真实 Broker 通过；Windows 不在既定范围 |
| SDK-04 | 动态插件加载 | 两种固定协议原生插件已具备；本轮 Mac/Linux 实际合同通过 | Ubuntu 实际注册 artifact、Broker/native_plugin 与 GitHub plugin 合同通过；不是插件市场 |
| UX-04 | 可视化策略审批流程 | 最小原生文件流程已实现，真实原生点击链通过 | 独立 QA App：完整草稿显示/0600原样导出、逐次step-up信任与激活、指定主体授权、正文交接、独立signer、grant导入、一次HTTP200；审计与重放拒绝通过 |
| VEX-01 | 私网 Vault | 已实现，本轮完整 TLS/UDS 合同通过；客户私网部署待验收 | typed audit error/原绝对deadline及本地严格私网 TLS 通过，完整 Rust 与 KV release 脚本通过 |
| VEX-02 | Vault 登录方式 | 单次AppRole登录/读取/撤销已整合，本轮完整本地合同通过 | 旧 socket bind EPERM 已复测关闭；完整 Rust、KV/dynamic release 脚本通过，客户 AppRole ACL 待验收 |
| VEX-03 | Vault token续期候选 | 仅现场证明单次TTL不足才选token一次续期；Namespace/额外引擎明确未选 | 不是首轮默认实现；保持已有DYN-05租约续期；现场需求尚未提供 |
| VEX-04 | KV 显式最新版读取 | 显式latest单读冻结和真实版本审计已实现，本轮 UDS/TLS 合同通过 | 本轮完整 Rust 与 KV release 脚本通过；客户现场后置，写入未选入本切片 |
| P-08 | 可观测性 | Linux 调度输出/新鲜度规则已实现，真实工具的14项验收通过；客户部署待验收 | 22 个规则向量使用真实 promtool3.15，unit 使用真实 systemd-analyze；rate 的末位舍入使用官方 fuzzy_compare，保留全部向量/标签/告警，Ubuntu 必需门持续执行 |
| P-10 | Connector 隔离 | Linux委派 cgroup-v2/guardian 与真实整组OOM验收通过；完整启动故障矩阵仍OPEN | Ubuntu 实际 artifact/seccomp/AS/READY 前后父进程死亡/取消清理，以及2464657整组OOM均通过；旧作业后续主动取消以修依赖，不能算整门通过，mac物理内存与全启动故障注入未关闭 |

## 交付缺口

MCP、policy/approval signer、onboarding/repair/backup/audit 辅助工具已补入未来发布归档；精确 workflow 本地打包、归档清单/文档链接、解包 MCP/Seatbelt 和签名器真实 Broker 入口验收通过；当前 alpha.2 公共下载不因此自动更新。服务商分组/一键接入及全部原生点击路径按实际最小交互逐项落实，不能把 CLI bridge 测试作为全部 GUI 验收。

## 依赖与现场输入

DYN-06 journal/恢复清理及外部 CredentialKind 修改由单一集成者分配新 schema 格式并统一 crypto/AAD/IPC 接线；不得多个线程各自碰同一文件。EXT-07/05 独立 signer 与审计运输工具可独立推进。ENT-01/02 先固定节点/租户归属；ENT-03/APR-10 再接稳定身份及实际撤权；ENT-04/BAK-07/08/ENT-05 需独立 fencing 和真实主备演练。

真实账号/节点信息待用户后续提供。保留所有未实现条目，不把候选规格、有限实现或历史测试相加为完成百分比。

首批本地证据保存在 `.git/codex/threads/all-capabilities-20260930/first-batch-acceptance.json` 与对应日志。workspace 报告合计 578 passed/0 failed/1 ignored（性能用例）；完整 workspace/all-targets/Clippy/fmt/机械边界及独立复查已完成。候选归档未签名、公证或发布。该首批结果不关闭其余待实现条目。

第二批 Transit 合同测试已整合，完整 workspace 报告合计 589 passed/0 failed/1 ignored；all-targets、Clippy、fmt 和机械边界通过。首次全量运行的一项旧审计超时夹具提前结束，定向重跑及暂停并行耗时测试后的完整重跑均通过；未改用例超时或弱化断言，负载关联尚未证明。独立 Transit 复审无剩余 actionable finding。证据在 `transit-batch-acceptance.json`；真实 Vault 签名 ACL/撤权及远程 grant 现场链路保留待验收。

当前宿主权限变更后的验证：可写独立副本 `cargo check --workspace --locked --offline`、all-targets Clippy warnings denied 通过。归档测试 22 passed，1 项真实 TLS 监听因 sandbox `EPERM` 阻断；保持原测试，不降级、不计为通过。此前 unrestricted 环境的 23 项通过单独保留，不能覆盖当前新整合代码的全量验证。

迁移后纯模型/connector/policy library 共 43 passed；Vault 定向 151 passed/0 failed。已实际尝试当前 `cargo test --workspace --locked --offline -- --test-threads=1`，首先到达 relay TLS fixtures，15 项因 IdP 子进程不能启动监听而失败；同一 ThreadingHTTPServer bind 单独复现 EPERM，证据 `loopback-bind-proof.json`。全套未通过，不提交本批，不借旧 589 结果覆盖。

DYN-06 修复验收：冻结补丁 `42e4cfc1c0eac8abd2d5d40a125eb689e523b6c3073479245fc6d386e0ef96d1` 的五个源码 SHA 已核对。四项新增真实 Authority Actor/SQLite 无监听回归在整合树通过，两个 P2 经独立静态复查关闭；全量网络运行仍保留缺口，不提交本批。GCP 下一项仅从该源码快照起步，不用历史 full-suite 结果覆盖新代码。

后续最小合同已冻结：[GCP](../specs/2026-09-30-gcp-secret-source.md)、[指标调度/消费](../specs/2026-09-30-metrics-deployment.md)、[原生策略与审批文件流程](../specs/2026-09-30-native-policy-approval-flow.md)。三项现均已在隔离源码树实施并整合；GCP 的共享源码与原生 Swift 文件始终由互不重叠的写线程负责。原生初版 61 个断言曾用 compact 响应夹具，不能证明真实 CLI；独立复审后修复并改为实际 pretty 布局，整合重跑 80 个断言。规则工具和监听权限缺口保留；规格、编译和有限本地测试不计为全部功能完成。

GCP 最终 header/decoder 与原生三项 P2 修复均经独立静态复查关闭，实际源码哈希逐项匹配。整合 GCP/header/既有源回归共 29 项通过；原生 80 个本地断言及完整 Mac14 编译通过；P-08 生成器 10 项通过，规则工具缺失的两项明确失败。全部新批次仍未通过当前完整 workspace/TLS/UDS/GUI/现场验收，不提交，不借旧批次结果覆盖。下一项 AWS 固定版本源已冻结四文件最小合同，现有 aws-lc-rs HMAC 与缓存 time 0.3.55 UTC 转换避免 SDK/新依赖升级；隔离 INDEX baselineb557a3ff4f96903f38b3f0e38132fcd29b9f4b96（仅冻结正确的凭据 stdin flag 与 STS header 副本边界）。

AWS normalization combined24files `0f7efd866b58857e608f8b2d3485f2f2d7973dd1fc8e88e280e3b1f2facc26a6` 已在整合树逐 SHA 匹配，fresh alltargets/check、Clippy、fuzzing feature 编译和 293 项定向测试通过。独立生产复审关闭规范化 STS token 反射的 P2；响应头场景被正文提前拦截的测试隔离问题已修正、fresh 20 项通过和独立静态复审关闭。最终 24 文件 combined SHA `a5238163ab51518781e11b1e3f39aeee16db89ab6b6f23a332334ef9110876dc`。当前源格式17，拒绝先前16及更早。Azure协议固定2025-07-01，在 AWS gate 后冻结 kind8/schema18/opcode43，准备下一单写线程。P-10另有42行有界计划：cgroup memory.max存在暂时超限且macOS尚无已验收硬原语，整体仍OPEN。

Azure 首轮实际 21 文件 SHA 匹配，root alltargets 编译和 14 项纯/Actor 测试通过。新增实际 OWS 探测表明 source value/source header/business header 可回显去边缘空白的 bootstrap token 并到达 business；独立首轮复审 P2 OPEN。规范已先补固定 HTTP/Bearer parsed 表示，唯一 writer 同步修复 Azure/GCP，并探测完整 business value 的相同边界。保持原始传输字节，不引入泛化变换或新的 token 输入规则；最终测试/实际 SHA 复查完成前不计为收口。

1Password Connect 的协议合同已冻结为固定公网 v1 item/一个字段、expected 当前 item version及单一本地使用期限；不是历史版本读取或云端最新同步证明。编号尚未分配，未实现/未测。ENT-01/02的43行只读计划指出现有policy status不含实际vault/root绑定；后续需先冻结最小typed激活绑定和回执增量，不把文件送达当节点已生效。

Azure final25 patch `4d7283d13c72612fb9b1f3b0ce543a542fbdf2bd6285b80e30bfa136550023d6` 已整合：root Azure27/GCP20/AWS20/AAD3，同源码线程Vault112/domain+connector50/CLI2，共234项去重通过；check/Clippy/fuzzing/fmt通过，最终独立复审关闭本轮bootstrap与完整value OWS。当前完整workspace真实尝试仍15个IdP child启动失败；独立TCP/UDS bind/listen均errno1，失败子进程日志未保留，不把Cargo日志伪称直接含EPERM。无跳过、提交或发布。其他Opaque/Vault/AWS业务值及Vault来源token的同类边界仍是静态待核验，下一切片先补实际探测和统一现有HTTP封口，再推进1Password。

Fixed HTTP OWS final6 patch `2705f949a40f41cc266866b6b78da044f670f20b0d16d11a614b9103060daf38` 已逐文件实际 SHA 整合。root executor102 + GitHub10 通过，alltargets/check/Clippy/fmt/mechanical/CLI依赖通过；Opaque/AWS完整值实际RED→GREEN，Vault KV/Dynamic原有入口已拒绝OWS且新增2项证明。独立只读复核实际6SHA匹配且无新findings；无schema变化，无重复监听，无新full-suite通过声明。

1Password下一单写合同已分配尚未实现的 kind/AAD9、format19、typedrotate44；现行源码仍18。最小4新文件/零新依赖，固定item/field GET，不扩大历史版本、私网或同步新鲜度保证。

ENT-01/02最小规范已写 `2026-09-30-controlplane.md`（未实现）：复用activation/status opcode，Authority提交前绑定实际vault与重建JCS trust文档摘要；恢复trust的canonical buffer为空，明确不能hash空值或RKPTseal。节点文件投递/回执合计3新文件；1Password共享writer结束后再串行写Rust接线。

1Password final25 INDEXpatch `6d00596731e63fcda08a5796396b1b99b074e8b9c31775d242594882e1a8dc16` 已逐SHA整合；root源27/core260/CLI2及同源码既有回归85，共374项去重通过。check/Clippy/fmt/fuzzfeature/mechanical通过；显式null安全marker与parsedselected bootstrap两项P2经最终独立复审关闭。旧VRK并发限流断言失败保留，单项及全core串行复测通过，未改断言/20ms配置且因果未证明。严格TLS/UDS实际仍失败；线程过宽GitHub filter触及旧native-sidecar7项失败（2明确EPERM、其余根因未确认）原证据保留。未commit/publish，不把374或旧workspace结果当全部功能/全部运行验收。

后续两条独立代码 lane：现有来源decoded bootstrap边界仅实际探测后修既有source/tests（不动ABI/格式）；ENT-01/02先做真实Authority目标绑定/status/精确audit接线（不动source executor模块），现有节点helper和全部脚本/原生调用随后接同一合同。两者无共享可写文件或运行状态，均从1Password final25/374项源码快照起步。

本批 decoded-bootstrap：13个既有文件，Azure/AWS/GCP/Vault KV/Dynamic和有效GitHub签名探针真实RED→GREEN；107项来源/issuer去重线程定向通过。Dynamic decoded lease ID被接受但公开audit反射数0，不称公开审计泄漏；既有exact revoke/unknown intent保持。Keycloak生产未改，已有解析拒绝证据。root已逐文件SHA整合，后续最终复审/组合验证仍在进行。

ENT-01/02 Rust18文件已逐SHA整合，RawValue保留嵌套重复key，Authority step-up后/事务和exact retry前校验真实vault和canonical trust文档SHA，status保留持久activation time及expiry latch。8项真实SQLite、37domain、8policy、1status、4CLI线程定向通过；24脚本和2Swift文件已更新必填public target，syntax24通过。固定file helper在独立copy开发；不将fakeCLI或文件送达当真实激活/企业隔离，完整workspace门槛尚未通过，无提交或发布。

组合源码最终root验收：177项去重Rust定向通过（58目标/状态/CLI、107来源/issuer、12既有签名策略集成），重复Actor探针不重复计数，3个空filter历史命令不计通过项；workspace all-targets check、Clippy -Dwarnings、fmt/diff、机械合同和CLI依赖图通过。macOS完整warnings-as-errors编译及80项native流程断言通过，24脚本仅syntax通过，未声称其监听runtime通过。最终独立复审39个source/caller SHA且18policy SHA未变，无可确认P0/P1/P2。evidence/policy-target/root-final-acceptance.json留实际57files SHA、命令和唯一test IDs。固定filehelper尚在独立lane做receipt/fsync故障测试。

ENT filehelper初审3个P2 OPEN（executable ancestors可被其他UIDrename、100条pretty审计页超过64KiB、SIGKILL不运行rpassword Drop导致TTY raw未恢复），先更新controlplane spec再bounded修现有两files。root首次55 suite=54PASS/1ERROR，PID观测已改抓真实Popen对象，不放宽期限/断言；实际失败留证。线程已闭合前两P2并62PASS，第三proof-free PTY termios恢复测试进行中；必须最终新SHA root suite和独立复审才关闭，未计helper现场完成。

2026-09-30 controlplane final：两文件最终SHA整合；ROOT67项66通过/1失败（严格synthetic PTY恢复setter实际EPERM），all-targets/AST/diff通过；独立最终复审静态关闭3处P2，原OPEN报告保留。未通过项未跳过或降低断言，实际Authority hidden TTY激活、双VM及全workspace门槛仍未通过，无提交或发布。

下一切片已冻结 `2026-09-30-identity-directory.md`：A独占relay目录消费/持久停用/事务门禁；B独占Broker已有policy roll-forward会话撤销。两copy/files/targets独立，原生线程定向验收；完整OIDC管理登录、目录到签名节点应用回执及真实现场仍待实现/验收。

B节点前置：单一admin.rs实际SHA整合，ROOT6项真实Authority/SQLite/signer/session聚焦测试通过，first activation/exact retry保持行为、roll-forward全撤会话，实际deadline/reconcile/fault路径覆盖；独立复审进行中。未声称目录变更已签名并应用到两个节点。当前format19 debug包为目录/B整合前不可变快照，inventory/18个有效readonly入口/实际离线SQLite header19通过，无部署或发布。

目录最终：ROOT13项与B会话6项聚焦通过，alltargets/Clippy/fmt/diff通过；审查P1真实SQLite/并发RED->GREEN修复后逐SHA整合、独立final36line复审关闭。已有signer-live脚本已接config2/SCIM handler且AST通过，但TLS/UDS无法实际运行。目录回执两node仍pending，不能称完整离职链。C1严格OIDC IDToken验证规范已冻结，完整授权码与管理IPC门禁后续串行。

2026-10-01 C1 ROOT16真实RSA验签+10Workload回归通过；C3 ROOT20单测+1离线注册通过，21TLS只编译。C1独立审查已收集，C3复审中。完整C2节点PKCE/管理身份/逐次门禁合同已冻结，尚未实现，不能称SSO完成。


2026-10-01 continuation: H1 standby receiver integrated at two actual SHA;
ROOT13 tests/all-targets/diff PASS and independent final no confirmed findings.
Cooperative root-directory flock and artifact/receipt/object/parent fsync provide
durable VERIFIED publication and identical retry; no SSH/power-loss/fencing/HA
claim. Native OIDC caller ROOT16 new+80 existing assertions and full macOS14 App
compile PASS; independent review closed focus/lifecycle/display/profile findings.
Helper path-only wiring ROOT4 new checks PASS and final review no findings; old
strict PTY gate remains unpassed. C2 initial ROOT74 unique tests/check/Clippy/fmt
PASS; strict fixture compiled/listed only. Independent review found1P1+3P2 in
Begin/lock, monotonic access expiry, terminal-audit budget and Cancel publication;
spec amended before isolated fix worker. OIDC completion remains OPEN until fix
SHA integration, root retest and independent closure. Existing operator caller
path propagation ROOT5 quickstart/14 backup/12 service-generator and2 repair helper
checks PASS, independent read-only review active. H2 snapshot/restore-cut exact
source plan active; real environments stay deferred per user, no commit/publish.


2026-10-01 C2 final: 原1P1+3P2及后续审计timeout P2全部独立复审
关闭；真实SQLite锁/Actor队列/late-ready三项RED->GREEN，ROOT最终OIDC25、
累计84去重实际测试通过，exact19source冻结收据见oidc-node/root-final-acceptance.json。
严格TLS/loopback/UDS仅compile/list，不称完整现场SSO。H2已从该stable
API冻结新401file copy/INDEX067611..，18existing files限7production+
directreturntestcaller。VEX04从独立401file copy/INDEXbebf72..实现显式latest
单读冻结+actualversion audit；两写入scope/target独立，根整合/复测/复审仍pending。
私网Vault规划必须核actualvault/部署归属，不把principal当tenant；未实施。

2026-10-01 continued acceptance: VEX04 ROOT17 unique pure/realActor tests PASS, deadline first-poll P2 independently CLOSED at exact five SHA. H2 ROOT34 unique snapshot/cut/policy/journal tests PASS; independent review one lossy-path P2 OPEN, spec amended before bounded fix. Current bins rebuilt offline; not a full workspace/socket/TTY or HA acceptance.

2026-10-01 H2 final: ROOT36 feature cases plus IPC regressions =51 unique Rust, 4 real offline CLI delegate/SQLite cases PASS. Canonical Unicode path, exact copied input SHA/pre-restore cut, wrongSHA/wrongproof/nonempty target verified; random test proof only stdin and init recovery output discarded. PathP2 and test-only UUID fixture supplement independently CLOSED at final18SHA. Actual invalid filename creation EPERM and Linux-specific case remain unaccepted, no fencing/HA/full-workspace claim. C2 current19SHA supplementary provenance recorded postH2; original84 result preserved. VEX01 native isolated writer active after latest stable.

2026-10-01 VEX01 ROOT40/checkClippyfmt PASS at exact7source; independent actualFINAL2P1OPEN (original revoke deadline and typed audit timeout error), originalreports retained and spec-first boundedfixactive. EXT06 frozen SDK-backed noUI source specification, 29file nativewriter active format20/kind10/op49 reserved, integration still19. VEX02 readonlyplan45lines16SHA selects existingKVkind/newclosedAppRolemarker; implementation must wait privatefix and Nativeexecutionmain stable.

2026-10-01 当前源码20：VEX01 ROOT43及独立两P1闭环；EXT06独立29SHA/67unique审查无确认问题，ROOT18 focused+Domain40通过。扩大vault检查发现backup夹具硬编码19（真实失败保留），ROOT改为当前FORMAT_VERSION，并修复storage旧格式schema构造源；全vault回归和2test-only独立补审进行中，未宣布全workspace通过。早期format18/19收据与debug包均为不可变历史快照。VEX02最小AppRole合同先写spec/baselines，无token renew/Namespace/引擎扩展。

2026-10-01 format20整合闭环：ROOTVault全包230（早期汇总240为算术错误，逐harness日志保留并更正）、Domain40/adminIPC8/connector7及Native18focused均通过；checkalltargets/Clippy-Dwarnings/fmt/两机械扫描/CLI normal依赖树通过。2test-only格式夹具补审CLOSED。EXT06本地源码合同完成，真实Keychain API调用0；VEX01本地43完成。AppRole从actual406文件INDEX3b993ee992b8c50748fc8afb6473b440cea9535e隔离副本起步，只写7owned，无新增kind/format/opcode。全workspace及现场门槛仍未通过，不提交/发布。

2026-10-01 AUD06最小年龄入口：audit prune --older-than-days与before-ms恰选一项，固定24h天/checked arithmetic/proof后clock，仍每次Admin step-up，无协议/schema/自动proof。2新用例真实RED→GREEN；实际全CLI27通过/6 client UnixListener.bind EPERM失败，全部失败保留不skip；既有prune6 Actor/SQLite通过，checkalltargets/Clippy/fmt通过，独立措辞P2修订后CLOSED。无人值守retention policy、全类清理、归档ACK依赖和物理安全擦除不由本切片完成。源码收据audit-retention-age-final-acceptance.json。H2 current20另4真实离线CLI案例通过，历史19收据保留。

2026-10-01 VEX02当前整合：线程7owned（5 changed）逐SHA复制，ROOT SDK2声明临时token生命周期并集。独立9SHA/69worker IDs审查无确认P0/P1/P2；Azure/1Password两处备份format19预期实际失败后，仅test断言改用FORMAT_VERSION并独立补审。新ROOT定向266 unique通过/1运行时UnixListener.bind EPERM；SDK19另通过，checkalltargets/Clippy/fmt/两机械检查/CLI normal树通过。receipt=`approle-integrated-final-acceptance.json`；186/2旧失败和15/1运行时失败日志均保留。局部通过不代表完整workspace或真实Vault/TLS/UDS/TTY/Keychain/HA验收；无提交、发布。

2026-10-01 剩余实现继续：Linux、DR 两个隔离写线程；DR实际FINAL收集后独立审阅确认3P1（可信执行祖先/来源、输出目录inode、rekeyd及policy依赖清单），原候选不计关闭，原线程有界修复。HSM spec先冻结，cryptoki=0.12.0正常registry依赖由Cargo离线resolver生成lock，官方Git blob/index和包SHA核实；新增3依赖包、无既有包升级，ROOTworkspace alltargets及机械边界通过。HSM新线程实际spawn因threadlimit拒绝，没有虚报启动，等待复用已完成线程。AUD06后台授权选择仍待用户回答；不保存密码，不以手动年龄prune冒充自动policy。

2026-10-01 剩余最小入口整合：DR原3P1经独立审阅全部关闭（末项以可信祖先先于mkdir为新边界，真实ROOT9测试RED→GREEN）。ROOT完整backup23通过；完整controlplane86项运行85通过/1原严格PTY失败，失败不skip。Linux5changed/7postSHA从407冻结副本逐preimage匹配；独立actualFINAL未确认P0/P1/P2，ROOT11pure及workspacealltargets通过。Linux真正workspace cross101缺gcc保留，adapter compile/clippy不代替实际Broker/内核；所有现场门仍OPEN。HSM OWN3私有signer写线程正在验证，尚未整合或计关闭。

2026-10-01 用户明确允许“Admin step-up设置/撤销后，后台仅unlocked清理原完整执行组，不保存密码/自动解锁”。spec/baselines先冻结，再创建416actualsource INDEX71e189c31b1d25116322cc263245f200715fa562隔离副本，单writer23生产+5既有测试，预留格式21/Admin50-51。HSM标准registry依赖符合用户选择，官方index缓存已可离线解析；actual3SHA候选整合，ROOT14focused及实际binary5入口检查通过，但独立2P1未闭环；先修spec原deadline非阻塞reap和最终signalrestore检查，再由原HSMonlywriter有界修复。原滤错0tests不计PASS；所有旧失败/候选收据保持不可变。

2026-10-01 HSM两P1 actual独立FINAL均CLOSED；最新3SHA从589008f7完整patch逐preimage整合，ROOTworkspacealltargets/17focused/build/实际binary5/fmt通过。ROOT Clippy实际101为两处尾部unit expression，原writer仅有界机械修复，旧日志保留；不提升真实HSM/驱动/控制TTY验收。自动保留独立writer ownership补充desktop cfg(test) Worker初始化一行，现29owned；无新模块/依赖。

2026-10-01 HSM最终机械补审actualFINAL通过，source3SHA/patch60a1eaff一致；ROOT最新workspacealltargets、17focused、Clippy-Dwarnings、fmt与两机械扫描通过。正常cryptoki registry依赖保留，不vendoring；真实token/硬件/控制TTY未验收。完整工作区将按security-gate既有单测试线程策略在format21稳定后一次运行，避免KDF竞争。

2026-10-01 AUD06首候选actualFINAL收集，29 pre/post及全416SHA逐项验证后整合，ROOT当前format21/HSM最终修复保持。独立首轮确认2P1+1P2：异步stop不能同步关闭全准入，desktop resume漏seal，新增SET重置Admin原deadline；先修spec SHAeed24adda，再原29线程有界修复，不宣称完成。首候选63uniquePASS，Admin IPC未就绪底因未定/CLI fake-reply bind EPERM保留。ROOT4格式桥接改动独立FINAL通过：DR当前21常量及2fixture、旧拒绝夹具SQL源引用当前FORMAT_VERSION，真实RED→Python23/Rust8+1/check GREEN，旧目标断言未弱化。ROOT实际CLI5help/parser通过，完整workspace等待修复稳定后单owner执行。

2026-10-01 当前 format21 收口：AUD06 原 2P1+1P2 经实际独立 FINAL 全部 CLOSED；exact29/416SHA 验证后只整合修复的5文件，ROOT Broker6/Vault4/Desktop2（集合有重叠）及 CLI5通过。当前 all-targets check、全 workspace Clippy -D warnings、fmt、两项零匹配机械检查和 CLI 正常依赖树通过。完整单线程 no-fail-fast Rust 运行83个目标：755通过、276失败、1忽略，整体101；Broker内嵌子测试摘要不重复计数。HSM17在全量运行中均通过，同二进制旧 Vault Transit8项因 bind EPERM失败。失败保留，不skip，不提交。

完整测试另外暴露2处验收脚本写死 target 路径：P1及quickstart现以 cargo metadata target_directory 取实际目录，独立只读审查无发现。P1复测已越过旧127缺文件，严格 fixture 仍因EPERM整体101；quickstart当前6运行5通过/1 Broker退出5失败，底因未证明。审计投递27运行24通过/3监听EPERM errors，归档23运行22通过/1监听EPERM error；备份当前21完整23通过。完整控制面既有86运行85通过/1严格控制TTY恢复失败记录保留。Linux内核/HSM实体/真实provider/IdP/双节点与fencing、promotion、脑裂、RPO/RTO门未关闭；不宣称所有34项完成、全量绿色或已发布。证据：format21-workspace-test-results.json、format21-script-path-fixes-receipt.json、format21-final-python-results.json。全部改动仍在本隔离integration，未覆盖原工作区。

2026-10-02 继续收口：通过 GitHub 连接器实时核实 main=acfa8fe；保护规则要求 PR、squash 和 Ubuntu/macOS/G2 三门。Git CLI DNS 仍失败。连接器首次 create_tree 被工具审批拒绝（需要审批，而会话策略never）；未上传对象、未建PR、未改远端。隔离副本已配置 origin 和经实时核实的 origin/main，本地原8commit可转移bundle已验证。新发现 archive smoke 格式19陈旧断言，修至JSON精确21，6正负输入通过。原生Model重新warnings-as-errors编译通过，flow80/OIDC16断言通过，无Keychain/API/GUI现场声明。

Linux CI 委派的最小接线已实现：现有workflow内临时Cargo runner只为插件相关test/executable创建独立同UID/GID service（Delegate=memory），P6在LinuxCI强制使用同入口。独立取消P2及格式守卫P3经 actual FINAL 静态复审关闭：特权client组kill/reap后stop指定unit，启动到PID赋值窗口有覆盖；测试退出码不变。实际生成shell对synthetic sudo/setsid的5路由/argv/stdin/退出检查通过；延迟启动及赋值前窗口各old失败→修复通过。真实root UID/systemd/cgroup/kernel尚未执行，完整workspace仍沿用755PASS/276FAIL/1ignored失败结论，无skip或绿色声明。证据：20261002-github-write-blocker.json、20261002-ci-plugin-runner-final2-mock.log、20261002-release-format-exact.json。

## 2026-10-02 当前收口证据（取代旧环境失败结论）

工作副本仍是 `outputs/rekey-implementation-20260930/integration`。Git 上传已成功，草稿 PR 为 https://github.com/majiayu000/rekey/pull/59；本轮行为修复跟踪 https://github.com/majiayu000/rekey/issues/60。旧工具审批拒绝是历史状态，不再是当前上传阻塞。

完整 `cargo test --workspace --locked --no-fail-fast -- --test-threads=1`：83 个目标，1032 通过、0 失败、1 忽略（性能专用用例），退出 0。结果按每个顶层目标的最终摘要计数，不重复计入子进程测试。旧 755/276/1 保留为历史失败证据。修复包括显式 Admin 主体重发、管理 socket 正文限额、macOS canonical temp/socket 扫描、目录撤权后的旧夹具、Vault journal 的事务型审计断言、旧格式/目标绑定夹具和 fuzz lock。策略替换仍撤销所有旧令牌；OIDC 不得代发其他主体，workload 接口仍拒绝指定主体。辅助验收脚本同步改为激活后重新 step-up 签发。

Docker 演练运行 3 的 `report.json` 为 PASS 且 cleanup_complete=true：Docker 29.5.3，镜像 sha256:7466ba795a1acc0c8aaed8c14bfbeed8b51e4fe573127f87b7919acce07ce8cb。RTO 从断网操作开始至备机首次真实成功业务响应，包含拒绝、fence、传输、恢复、解锁与重发；RPO 是本次凭证写入样本的丢失量及单调时钟提交间隔界限，不是全系统复制 SLA。可信管理员仍可重新建立容器，Docker daemon/宿主不是独立故障域。旧 artifact-only `--require-field` 的非零合同保持不变。

日志与收据：`outputs/rekey-implementation-20260930/evidence/20261002-pr-closeout/`；可随 PR 审查的非敏感汇总为 [本轮验收记录](../../evidence/local-capabilities-2026-10-02.json)。PR 必需 Ubuntu/macOS/G2 的精确提交结果以 [PR checks](https://github.com/majiayu000/rekey/pull/59/checks) 为准；这份本地记录不将等待中的检查算作通过，历史独立审查也不替代本轮改动审查。真实硬件 HSM、客户云权限、IdP/SCIM 双节点撤权、SIEM/WORM、物理故障域不能由上述结果关闭，原生文件审批点击链的结果见下文。


同日现场补验：真实 Docker Keycloak 26.7.3 的交换、已签发撤销、反射拒绝与过期拒绝通过，清理全部成功。真实 HTTPS 审批 relay、独立 signer/真实 Broker 和 5 个 SIGKILL/journal 恢复场景通过。原生点击发现 Action 返回结构字段不匹配，Model 改为严格读取 `request_policy.max_body_bytes`，实际 CLI/Actor 合同复测通过，80 个文件流程断言和16个OIDC边界断言通过；独立 QA App 完成完整策略到审批执行链，一次 upstream effect、CLI 重放退出4，合成状态与测试偏好已清理。真实 macOS login Keychain 记忆解锁条目跨进程及到期删除通过（不等于 EXT-06 凭证源验收）。

PKCS#11 本地真实模块门已从 injected 扩展到 SoftHSM2.6：固定库hash/version/slot/serial/public key及生产私钥属性校验，真正控制TTY隐藏PIN、错误PIN无输出grant、正确PIN签名、真实Broker拒绝改体/错会话/重放，仅一次业务响应。该软件token保存在一次性容器，已移除；不宣称物理硬件防导出或厂商驱动已验收。收据 `pkcs11-acceptance.json` 与 `gui-acceptance.json` 位于本轮 evidence 目录。

`cc15af0` CI：G2（含Docker DR）及performance通过；Ubuntu在信号测试对glibc附加SA_RESTORER位的旧假设处失败，macOS完整Rust通过后在Python深度JSON夹具的解析分类假设处失败。前者先以libc安装表示建立基线，仍比较精确恢复标志；后者允许解析深度拒绝或ACK形状拒绝，保留永久失败、仅一次发送及游标不推进。两者都是夹具修复，不放宽生产准入。


同日 EXT06 真实门关闭：`scripts/test-keychain-live.py --bin-dir target/debug` 在本机通过，创建一次性文件 Keychain 并仅信任测试 helper/fixture，真实条目读取、上游反射封口、锁定拒绝及无额外业务效果、审计 canary 与删除清理均通过。fixture 的 TLS ready 文件早于 Admin socket，首次新脚本失败已保留，随后等待两个实际入口就绪并复测通过；没有弱化生产 Keychain 查询。旧“API0”条目为历史状态。七项 release 脚本 P3、Vault KV、Vault dynamic、GitHub App、GitHub extension、workload identity 与 Darwin launchd 均已本轮通过。最新本地证据在 `20261002-pr-closeout/`。

`20cad7b` 的 macOS 完整 workspace/辅助验收通过，随后真实依赖审计发现 cryptoki0.12.0 命中 RUSTSEC-2026-0286。当前精确升级到0.12.1，两份lock仅该包版本/hash变化，不忽略advisory；本地cargo audit通过，重新构建的真实SoftHSM/TTY/Broker签名链也通过。Ubuntu完整workspace通过后，真实promtool暴露rate()结果与1只差一个尾数位；使用官方末位浮点容差，全部14项部署测试及22个规则向量通过，生产PromQL不变。历史失败日志保留。
