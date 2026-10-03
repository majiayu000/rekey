# Rekey v3 实施与验收清单

用户于 2026-10-03 确认范围为整份 `2026-10-02-rekey-v3-personal-first.md`，按依赖分批推进。以 `origin/main@4cdb531` 为基础，使用 `codex/v3-integration-20261003` 集成；原工作区和 PR #61 保持独立。

本清单是唯一实施跟踪表。代码存在、自动化检查通过、签名设备验收、公开发布分别记录，不互相替代。三个并行 lane 使用独立 worktree；协调者负责集成和 workspace 全量检查。

## 依赖与责任

1. V1/V2/V3 独立原型并行；协调者串行执行签名、钥匙串与临时 daemon 检查。
2. M0 默认构建 / lab 分离，和通过前置验证的 M1 子项并行；共享类型和格式变更串行集成。
3. M1 的 proof、服务端身份与存储接口稳定后，实施 M2 个人策略和模板；M3 依赖其规范类型。
4. M3 完成后运行签名产物攻击矩阵与真实 Agent 接入；M4 对照公开产物验收。

## 跟踪表

| 项目 | 状态 | 实施 / 验收证据 |
|---|---|---|
| V1 数据保护钥匙串、访问组、userPresence | 本机授权 profile 对照通过 | Developer ID profile 下创建和交互读取成功；owner 静默读取拒绝，ad-hoc 显式组缺 entitlement、默认组找不到条目；清理成功。证据：`docs/evidence/v3-review-v1-presence-2026-10-03.json`；不代表已安装 App 或完整 L1 |
| V2 签名 hardened rekeyd 内存访问 | 本机 lldb 对照通过 | 相同 Developer ID 签名、仅 runtime flags 不同的临时已解锁 daemon：Apple lldb 对普通版本附加并分离，对 hardened 版本拒绝。直接 task_for_pid 两边仍拒绝，仅作辅助。证据：`docs/evidence/v3-review-v2-lldb-2026-10-03.json`；不代表完整 L1 |
| V3 peer audit token 与动态签名身份 | 原型实测通过 | `scripts/v3/peer_probe.swift`；正确 Team/ID 成功，错误 ID 和 ad-hoc 均零字节；不宣称解决所有内核时序竞态 |
| 原型统一入口与结果报告 | 已实现，审查通过 | `scripts/v3/run.py`；7 项报告/清理/LLDB 判定回归测试通过；只用合成数据 |
| M0 lab feature / 默认构建 / 发布和CI分离 | 本批验收通过 | 默认/lab all-targets 编译通过；84 文件补丁独立复核通过；M1 合流默认 597 / lab 1,061 项测试通过，各 2 项忽略 |
| M0 README / spec 状态 / 格式冻结规则 | 已实现，未发布 | README 只列现有入口；35 企业 spec 标 Lab，两份研究稿改 v4；永久不迁移，GA 主版本内冻结格式；编译器源输入物理行 40,371 / 60,754（非有效代码量） |
| M1 SHUTDOWN 全状态 step-up | 本批默认验收通过 | 29 项不重复定向 Rust 测试及 synthetic human-vault smoke 通过；Locked 验证不解锁，证明验证前超时不触发停机；独立审查通过 |
| M1 presence proof 与钥匙串 UI | 统一候选已合入修复；已安装流程待验 | proof3、受保护 K、固定双时钟期限、显式 A2 和取消边界已实现；此前默认 698/2 ignored、真实 CLI 与 Swift 82/53/108/16 断言通过。独立修复分支的 V1 及真实认证 context 固定十秒复用通过；已安装 App 完整操作仍待验收，不提高完整 L1 承诺 |
| M1 desktop-reveal step-up / 明文清零 | 本批默认验收通过 | password/recovery 逐次证明、Zeroizing 响应所有权；UI 94 项边界断言通过，失焦关闭待验证表单；旧 desktop token 不再授权明文 |
| M1 生产客户端签名校验 / 等级显示 | 本批验收通过 | 签名 CLI 对错误 ID 同团队/ad-hoc 服务均在发送前拒绝，服务收到零字节；status/UI 展示本地验证结果；同团队 release daemon 的 status/unlock/shutdown 正向通过；仍不代表完整 L1 |
| M1 rollback generation / MAC / 外部计数 | 软件回归完成；设备验收待做 | C1/B1、B2/C2事务与root wire/UI共54文件已合流；四项并发/错误路径审查问题关闭，含实际旧源RED→修复GREEN。Vault默认/lab各122定向、root严格检查及真实CLI回滚/恢复通过；UI UUID互通修复后真实Swift→CLI通过。本轮签名候选已实测 DPK 读/写/删权限、并发 CAS 和旧数据库认证后疑似回滚；设备证据见 `docs/evidence/v3-release-acceptance-2026-10-04.json`，完整矩阵仍待验 |
| M1 memory hardening / core limit | 本批验收通过 | Linux arm64 容器实测 core=0/dumpable=0、独立 key 页生命周期、mlock 失败告警继续；macOS 回归与独立审查通过。仅覆盖拥有型 VRK/DEK 缓冲，非所有栈/AEAD 临时副本 |
| M1 pkg / LaunchAgent / SMAppService | 源码与 CI 接线已实现，设备验收待做 | pkg 9 项合成结构检查和独立审查通过；静态 LaunchAgent 与 App 显式注册、无-k 启动、逐次 proof 停用入口已编译；103 UI 边界断言通过。Installer 证书与独立 daemon profile 已生成；本轮统一 App/pkg 已签名、公证、装订并通过 Gatekeeper。此前候选 pkg 已在当前账户安装并核对收据/链接/哈希；GLM 升级版 pkg 也已安装并核对签名/Gatekeeper/哈希，实际登录项生命周期和真实 CI 仍未验 |
| M1 独立安全审查 | 待完成 | 原型代码审查不等同于产品安全验收 |
| M2 P-256 信任根 / 固定模式 / App 初始化 | 本批软件验收通过 | format23；显式 personal/team、P-256 DER 验签、完整 mode/algorithm/key seal 与备份/轮换通过；App 本机密钥初始化已接线，已实测生产 PolicySigning 的 SE 建钥/读回、私钥导出拒绝和无交互签名拒绝；当前账户已使用生产 PolicySigning.swift 的签名 helper 完成 SE 签署与真实 daemon 激活；硬件取消与已安装 App 流程未验。draft/sign/activate 见下项 |
| M2 个人策略 draft / diff / App 签名激活 | 本批软件验收通过 | 默认 683 / lab 1,147 项通过，各 2 ignored；纯草案 8/8、真实 CLI P-256 黑盒、Swift 47 项签名取消/字节保真断言通过；四份独立审查关闭。当前账户签名 helper 已完成生产 SE 签署→真实 CLI 激活；完整 App 审阅/取消流程未验 |
| M2 模板规范与路径/query渲染 | 纯合同本批验收通过 | 18 个领域测试与 10 个包验签/schema 测试通过，独立审查无待修问题；单 Action 物化、团队 Ed25519、来源摘要与离线 schema 已实现；存储、授权和执行链已接线，见下列运行时证据 |
| M2 ActionTarget / 内容认证 / 格式 | 本批软件验收通过 | format22；完整原始 Action 行 AEAD、全状态重封/轮换、实际备份副本和恢复验证；44 项定向测试及独立审查通过。数值列篡改错误映射 P2 已关闭；无迁移 |
| M2 原子安装 / 规范执行 / 客户端 | 本批软件验收通过 | 52/53、原子批安装、render→审批哈希→HTTP 已接线；全量默认 647 / lab 1,111 项通过，各 2 项忽略；stdin 尾修 CLI 黑盒、lab CLI 62/1 ignored、Swift 实际 CLI 与 103 流程断言通过；独立审查关闭 |
| M2 anthropic/openai/github/generic 模板 | 本批软件验收通过 | 四个内置声明、风险默认值、App 能力/多绑定选择已接；真实 CLI GitHub 一次安装 16 Action、Swift OpenAI 安装 2 Action 通过；策略激活仍需独立完成 |
| M2 Approver / local-presence / 面板 | 本批软件验收通过；签名设备T10待做 | 完整原始审批正文、逐次 Presence、owner wait/cancel、一次消费及个人高风险草案已接通；独立审查、默认750/lab1,216（各2 ignored）、双配置strict Clippy与Swift328项断言通过。真实CLI/MCP单次批准执行通过，无硬件验收替代 |
| M3 Profile / 会话生命周期 / rekey run | 软件与macOS隔离已合流 | Profile15/Runtime8/RunCLI5 及个人编辑后端11/App4独立审查关闭；真实CLI默认/lab各2个生命周期场景及1个子进程fixture通过，SIGKILL后5秒内撤销。已合流整数组编辑、旧摘要拒绝和过期续期；Swift32/55/82/112/65/16断言及真实临时CLI通过。macOS Seatbelt helper7/glue4已合流并验证控制连接EOF后直接子进程和scratch清理；Linux Profile netns明确Unsupported，未宣称L2 |
| M3 gateway / 认证 / SSE / model与预算 | 相关软件用例通过；真实provider待验 | Gateway11/SSE9/通用SDK2独立审查关闭；Header 16KiB完整请求绕过已有RED→修复。Anthropic beta6已合流：仅声明可选beta=true且绑定审批/上游，default/lab定向146次通过。真实Claude/Codex→真实Broker+合成上游各1/1通过，审计哈希/预算/用量/撤销通过；不替代provider或L2验收 |
| M3 MCP v2 / await_approval / GET | 本批软件已合流 | MCP6及独立审查关闭，无参数环境接入、Agent8签名Profile发现、多Action选择和owner审批保留。root实际stdio9/9、bin15/15通过；测试接收端首字节改用既有CLI响应时限，后续帧仍2秒。新live脚本两轮合成运行通过，未运行真实Codex |
| M3 rekey connect / diff / 备份 | 软件已合流，客户端路由合成验收通过 | 项目MCP配置/diff/TTY默认拒绝/备份与原子发布通过；显式--client适配4文件与47次定向测试通过。Claude2.1.281/Codex0.160.0已通过真实CLI→合成Admin/HTTP/SSE路由；后续真实Broker+合成上游也已通过；真实provider未验，Codex仅批准的preferences-routing场景，不证明L2 |
| M3 活动页 / 审计统计 | 软件已合流，真实CLI数据互通通过 | 后端52与App4冻结补丁独立审查关闭；可信历史上下文、今日UTC稳定分页、已测量/上限token分列。App32 Activity/65 local/112 flow断言及严格编译通过，实际MCP调用→CLI audit JSON→App decoder与真实Swift CLI流程通过；通知回归RED与修复证据保留。 |
| M3 遮蔽增强 / 编码与压缩限制 | 本批验收通过 | JSON/hex/base64 对齐、禁止压缩头；独立审查的窗口/短秘密问题已关闭；流式跨片回归通过；11 项 decoded source 合流回归通过；真实 TLS streaming 8/8，通过 marker fast path 避免逐字节重复扫描 |
| M3 连续 500 次零交互与真实Agent接入 | 合成软件T11合流复测通过；真实Agent/签名待验 | root实际run→MCP→daemon完整500响应、第501拒绝、上游500，重复list不耗额度；Profile耗尽不会截断最后响应。m3-mcp-root-stdio.log记录9/9通过，不能替代真实Claude Code/Codex或Touch ID设备验收 |
| M4 新账户 5 分钟接入 | 最小入口已合流；设备验收待做 | setup/add固定App入口、显式保存/能力安装/个人策略编辑与取消后复用已安装版本已实现；20最终检查通过。实际新用户安装/SE/5分钟T12未验收 |
| M4 格式冻结 / 基线 / GA 发布 | 候选版本、文档及分发接线已实现；GA未发布 | 3.0.0-alpha.1、vault25/policy6；完整运行与定向修复已记录，GA最终格式冻结与公开发布仍待完成 |

## 当前收尾状态（2026-10-03，尚未发布）

- 默认与 `lab` 两配置完整workspace测试均已运行：默认仅VRK崩溃夹具超时，lab仅GCP期限夹具与插件故障清理失败，原日志在主工作区 `outputs/rekey-v3-20261003/v3-final-{joined,lab}/`。三处test-only修正经独立审查，随后按原workspace特性图重跑默认VRK全组、lab的GCP全组/插件全组/VRK全组均通过；修后all-targets、两配置strict Clippy与fmt通过，证据在 `v3-final-test-tail/`。没有将初跑失败记为一次全仓通过，也没有叠加嵌套子进程为独立用例数。
- Swift实际个人草案、软件P256签署激活与读回覆盖三种逐能力规则，真实默认CLI检查通过。snapshot6要求显式rule字段，Vault仍为25；UUID仅在ID字段规范为小写。普通Ed25519签名自定义模板已接通Profile与实际run→MCP，同名模板不能获得内置LLM/Gateway语义；可信risk值已在能力选择卡显示。
- 管理前置拒绝与真正的Authority工作错误已区分：前者及时返回，后者保留状态核对和故障关闭。独立审查关闭，原排空/轮换等待回归、审计故障自停和generation期限/恢复的对应全仓用例及尾修定向复验通过。首次默认9项失败及中止的旧lab运行保留，不以复跑抹除历史；CLI子进程启动超时的具体环境原因仍未确定，其原时限未放宽。VRK现在将setup与轮换各自限定25秒并确保panic回收child；GCP先观测真实发送，再等原绝对期限，保留精确请求数；插件故障测试直接断言自动停服的Faulted。三处不改生产执行或错误合同。
- `3.0.0-alpha.1`为未发布候选。签名pkg/cask生成、systemd-user接线、保守等级与旧格式/短Key提示已有软件检查；所有公开Release项仍Pending。永久不迁移，GA后仅主版本可改变持久格式。
- Linux新Profile netns仍明确未实现；Codex Seatbelt的managed-preferences限制保留。V1/V2、真实DPK/SE/CAS、Installer/登录项生命周期、真实provider、签名设备T11、新账户T12和独立人工安全审查仍需外部验收，不宣称完整L1/L2。未使用真实凭据，未发布或安装到用户环境。

## 本机首轮探针记录

本机 macOS 26.5.1，SDK 26.5，使用项目对应 Developer ID Team `C5UWZ934C2`。原始结果：主工作区 `outputs/rekey-v3-20261003/signed-run-1/report.json`。V1 的进程退出码为 -9，缺授权 profile 是环境诊断，尚未取得钥匙串 API 返回码。V2 的 signed 与 ad-hoc 均返回 Mach 5。V3 三个场景的有效身份 / 错误 ID / ad-hoc 结果符合预期。

原型结果不能被描述成整份 v3 已完成，不能提高当前产品的 G1/L1-dev 承诺。

## 按批次保留的历史证据（当前状态以上表为准）

M0 补丁已冻结并整合；来源 `outputs/rekey-v3-20261003/m0/m0-frozen.patch`，
SHA-256 `57f077ce514ecaeaa57d1750c4909aaf1b97fc0e556fc8be68badba74378e1a9`。
统计口径为 rustc `.d` 源输入去重后的物理行，包含 inline cfg/test 文本；33.55%
是该口径的差异，不能宣传为实际机器码或有效生产代码缩减。

不依赖 V1 的 password/recovery 管理修复已完成：Locked SHUTDOWN 校验不解锁、
验证失败不能触发停机、逐次 reveal step-up、Rust 响应体清零所有权。
只读计划位于 `outputs/rekey-v3-20261003/m1-admin-plan.md`。presence 与 L1 承诺继续受 V1/V2 验收约束。

签名正向证据：`outputs/rekey-v3-20261003/production-peer-positive.json`（release
CLI/daemon 的最终签名哈希，Locked/Unlocked 均返回 `verified_signature` 且 `lab_enabled=false`）。
早先 debug 产物在并发 release 编译期间初始化超时，记录保留，不计作通过。
release 临时 vault 的 Swift UIContract 及 80 项 native flow 边界检查通过；未运行真实 GUI 点击。

默认 workspace 全量检查采用 CI 的串行测试设置通过：589 passed / 2 ignored（包含嵌套验收脚本的输出）。默认严格 Clippy、default/lab all-targets 编译、格式和 CLI 依赖合同通过。并发运行时的两个 deadline fixture 失败保留为环境敏感性记录，未增加超时或删除断言。

M1 管理补丁已冻结并整合，SHA-256 `5213d261bbd01430973a2148f5fabb3a4e0bea3b4f062ab30ec54189d24270b3`。独立复核确认 worker 与 integration 的 20 个文件哈希一致。新版 release CLI 的真实临时 vault UIContract 通过，包括单次证明查看和 Locked SHUTDOWN；Linux mlock 两项及 daemon process hardening 子进程测试通过。

Lab 全量检查首次因传入 `RUST_TEST_THREADS=1` 影响嵌套 libtest 的 readiness 行而等待，已停止本轮测试进程；按 CI 实际使用的 `-- --test-threads=1` 运行该测试通过。未改产品或测试来绕过断言，合流后全量以 CI 命令重新运行。

M1 集成默认 workspace 检查：597 passed / 2 ignored；默认 all-targets check、严格 Clippy、Swift App 严格编译、94 个 native flow 断言通过。Lab 全量使用 CI 参数方式串行通过：1,061 passed / 2 ignored，日志 `outputs/rekey-v3-20261003/m1-test-lab-final.log`。OIDC 测试清理调用已改为逐次 proof，定向复测 1/1 通过；未改变产品拒绝合同。Linux 镜像为 `rust:1.95-slim-bookworm` arm64、去除全部 capabilities、memlock 上限 64 MiB；测试中的零额度只在独立子进程设置。

新版签名 release CLI / rekeyd 正向链已通过：Locked/Unlocked status、unlock、lock、错误证明不停止服务、正确证明停掉 Locked daemon。证据 `outputs/rekey-v3-20261003/production-peer-positive-m1.json` 含最终签名哈希；仍不将签名校验单独称为完整 L1。

M2 首批单 Action 物化与团队模板验签纯合同完成：root 默认 workspace 613 passed / 2 ignored，all-targets check 和严格 Clippy 通过，独立审查确认五文件哈希一致。日志 `outputs/rekey-v3-20261003/m2-test-default-serial.log`。后续接 ActionTarget、完整行内容认证、存储、授权与 HTTP；安装运行时尚未实现。

M2 存储已合流：单一 ActionTarget、format22 和完整 Action 行 seal（含退役/禁用、VRK 轮换、实际备份快照与恢复）。最终补丁 SHA-256 `8a4d4eac678003441a73713a15beabd447cf492fe71a101eb23049eeac0c08dd`，42 文件。独立审查发现并修复数值字段篡改被当成普通存储错误的问题，44 项定向检查通过。统一执行链完成前模板执行保持明确拒绝；领域/存储测试不代表运行时已可用。

下一批安装与执行使用 `m2-runtime-preflight.json` 的两个独立工作区；root 拥有冻结 IPC、CLI、Swift 与集成检查。安装将一次证明、全部新 Action、逐条审计放进同一事务。模板来源闭合反序列化新增负测发现 Serde unit variant 忽略额外字段，已改为零字段 struct variant；JSON 形状不变，9 项 IPC 测试通过。CLI/UI 独立审查的忙碌早退临时文件清理问题已补修，正在运行对应回归。

M2 安装执行批已完成本地合流：默认 workspace 647 passed / 2 ignored，lab 1,111 passed / 2 ignored（串行参数方式）。默认严格 Clippy、lab all-targets check、机械禁用符号及 CLI 依赖边界通过。完整日志 `m2-runtime-test-{default,lab}-final.log`；各源码审查记录位于同一输出目录的 `review/`。

全量测试启动后又关闭模板 UI 的同 UID 请求文件 TOCTOU：App 保留请求内存快照，catalog 一行、install proof+JSON 两行经匿名 stdin 传入，CLI 一次有界读取。尾修另外通过真实 CLI 黑盒、完整 lab CLI 62 passed / 1 ignored、Swift 实际临时 vault 链、103 native flow 断言及全 App 严格编译。busy 请求明确提示未提交；安装超时保留不确定结果并禁止自动重试。未进行真实 GUI 点击或 signed pkg 安装。

失败记录保留：backup 完整性失败会新增 runtime.faulted，测试已验证该事件唯一、停止授权、无 backup success/release，未弱化产品；一次 lab CLI 检查混用默认 daemon 产物失败，同 feature 重建后全部通过。后续 feature 组合检查顺序执行，避免同 target 的二进制互相覆盖。

个人签名下一批使用 `m2-personal-preflight.json` 和隔离工作区，先实现 typed Ed25519/P256 信任根、显式不可变 mode 和认证存储。真实 SE/Touch ID、policy draft/diff、local-presence 与 M3 仍非完成项。

个人模式基础批已完成本地验证：默认 workspace 657 passed / 2 ignored，随后新增 policy_mode 6/6 定向通过；lab 完整 workspace 1,127 passed / 2 ignored（含这 6 项）。format23 拒绝旧格式，不迁移；模式与信任算法不可变，P256 真实软件签名、篡改错误、重开、VRK 轮换、实际备份及恢复已覆盖。日志 `m2-personal-test-{default,lab}.log`、`m2-personal-policy-mode-root.log`。

App 已有显式模式选择、按 vault ID 创建/加载本机 SE 签名公钥和匿名 stdin 安装信任根；Swift strict-concurrency 构建、真实 CLI 合成 vault 流程与 108 项流程断言通过。CLI 真实黑盒 6/6、Python backup 23、audit 28、human-vault smoke 通过；默认严格 Clippy、默认/lab all-targets check、格式及 CLI 依赖边界通过。审查报告 `review/m2-policy-key-review.md`、`m2-policy-store-review.md`、`m2-app-policy-key-review.md`、`m2-personal-glue-review.md` 均无待修问题。没有运行本机 Keychain/SE 认证；签名 helper 尚未接入草稿激活 UI，不能据此宣称个人模式全流程或 L1 已验收。

下一批纯草稿生成器已冻结（补丁 `b9444ba858c87f5bf14059c439fec287c8555cd0da4949a4d3fb5309da111ace`）：8/8 测试与独立审查通过，拒绝 JCS 数值舍入，完整替换差异不保留未选授权；待合流 daemon opcode54、CLI 与 App 精确字节签名流程。local-presence、回滚检测、Profile/网关/MCP 和 T11 仍未完成。

个人草案批已完成本地软件验证：默认 workspace 683 passed / 2 ignored，lab 1,147 passed / 2 ignored，日志 `m2-draft-test-{default,lab}.log`。只读 opcode54 从认证后的模式、信任根、策略和 Action 生成完整替换草案，拒绝 JCS 不精确整数并预留实际激活报文的签名空间；禁用操作后不能再激活旧草案。CLI 输出准确签名字节，激活经匿名 stdin 传入 proof 与 bundle。真实临时 vault 的 P-256 签名、首次/幂等激活、过时版本、禁用操作和空授权替换黑盒通过。

App 展示全部差异和目标定义，签名前后核对 vault/trust/version/workspace，按原始字节请求 SE 签名。独立审查发现窗口关闭后的迟到签名仍可能提交，现由视图退出作废上下文；完整 App 严格编译与最终 47 项合成个人策略断言通过。CLI 的文件元数据校验顺序和空签名体两个 P2 已关闭；纯生成器、runtime、CLI、App 四份最终审查均无待修问题。没有真实 Keychain/SE 调用或 GUI 点击，亦未公开发布。

Presence 批已合入集成工作区：daemon 只在当前 Unlocked 且进程内有效授权下接受 proof3，记录 K 哈希而非 K；重复或失败 resume 保留同票据原有 monotonic 上限，删除旧票据失败时 fault 并返回原 storage 错误。两项独立审查 P2 已关闭，完整补丁 `66009d0cd1636ea901977fee9687fc91f58f508b1703ad62ab8a8f2744fa078f`。CLI 的 --presence 必须走既有显式 stdin，离线解密和 VRK 重包不接受其替代必要因子；真实合成 vault 全生命周期在最终 backend 上通过。

App 删除旧无保护钥匙串读取与后台自动恢复，保留独立 A1 添加会话；系统认证七天授权默认关闭，每次明确操作才读取 DPK 条目，并作工作区/视图/取消复核。五文件补丁 `6b523bacbfa04dd9d8b5ee0e21103de325ee6147c98cd42016b1be920447c722` 经独立审查、严格 Swift 编译、82 presence /53 personal /108 flow /16 OIDC 合成断言及真实临时 CLI 流程通过。未运行真实 Keychain/SE/GUI。

打包脚本现支持并在正式 App 构建中要求 provisioning profile；核对 Team、App ID、访问组、期限、发行属性和叶证书 DER，仅 App 声明访问组权限，standalone 工具不声明。release/CI 接线已改，11 项合成配置测试及独立审查通过。旧无交互钥匙串跨进程测试移除，DPK 的真实签名设备权限仍交 V1 验收，不能由合成测试替代。

本批默认 workspace 698 passed /2 ignored、默认严格 Clippy/all-targets、格式、机械符号和纯 IPC CLI 依赖检查通过。lab 两轮在未修改的 relay 测试首次 PUT 分别收到 503（预期201），原失败日志 `m1-presence-test-lab.log`、`m1-presence-test-lab-final.log` 保留。独立诊断确认目录 Unknown 可触发安全拒绝，但具体偶发原因尚未确定；不以复跑通过宣称修复。排除 relay 后的完整 lab workspace 已通过 1,120 项、2 ignored，日志 `m1-presence-test-lab-core.log`。relay 按原 workspace 特性图独立验收 22/22 通过（`m1-presence-relay-workspace-final.log`），加先前同源 relay 单元 20/20，分组覆盖合计 1,162 passed /2 ignored；这不抹去原全套两次失败。

M2 Approver 格式已合流：四份冻结补丁和共享 harness 一行 format4 尾修；合流前 93/93 源码哈希一致。Domain/Policy 17 文件、Broker/relay 11 文件、根脚本/格式 glue 38 文件和 Swift 4 文件均独立审查关闭。组合 default/lab all-targets、真实 Swift→CLI 临时 vault 和 Swift 112 flow /82 presence /53 personal /16 OIDC 断言通过。完整 default 首轮发现 root integration harness 仍签 snapshot3，已仅更新正向 fixture 为4，生产版本拒绝保持，broker_ipc 5/5 复测通过；最终默认全套706 passed /2 ignored及真实P3外部审批（单人/双人、重放/篡改/过期与审计）通过；lab全套1,172 passed /2 ignored与集成strict Clippy也通过。P3脚本顶部同时改为读取Cargo实际target_directory，避免多worktree验收读错二进制，4行尾修独立审查通过。LocalPresence 运行时依赖合同已固定，upstream Domain/Policy/Vault 另树实施中，不能将枚举/面板计为本机批准完成。

Approver 本批完整回归已结束：`m2-approver-test-default-final.log` 706 passed /2 ignored，`m2-approver-test-lab-final.log` 1,172 passed /2 ignored，集成默认 strict Clippy 通过；最终 root流水退出0。先前 presence批 relay两次偶发503仍保留为未归因历史失败，不用本次通过冒充已修复。新local审查另外复现既有JCS数值碰撞：大整数、小数及非零underflow可在规范化丢精度；原body仍发上游。证据 `review/m2-jcs-number-precheck.md` 与 `m2-jcs-number-probe/`，下一local upstream批在唯一canonicalize边界修复，未修完前不得宣称完整T10。

本机审批 upstream 已独立审查关闭并合流：12文件 patch `d398e64c4d69f05cd037992209582c692d89be8b4d1588022b11d9b4a28670da`，review `acc0978656813a16d22b917bd9444ba1cd40966e081b903fd9dacad4ddd5e725`。default/lab全目标check、D/P/V双配置strict Clippy及定向检查通过；root integration workspace check通过。JCS原始数值与规范结果的精确十进制检查已进入唯一canonicalize边界，拒绝舍入和非零下溢；先前精度finding关闭，但T10完整本机链仍等Broker/CLI/App。三路隔离写tree正在实现，root仅独立接MCP两文件与合流测试；APPROVAL_REQUIRED结构、owner wait/cancel、一次消费和Presence决定合同保持冻结。

本机审批运行时批已完成软件联合验收：49/49审查源码哈希与integration一致；默认workspace 750 passed /2 ignored，lab workspace 1,216 passed /2 ignored，日志 `m2-local-integration-test-{default,lab}.log`；default/lab all-targets check及strict Clippy、fmt、禁用符号和CLI依赖边界通过。Broker的审批期限尾修、真实CLI单次生命周期、MCP显式重试以及个人P-256高风险规则均在最终合流代码上重跑。CLI/MCP均使用真实Broker/Authority和模拟上游，不能称为真实provider或签名设备测试。

App完整严格编译及328个合成断言通过（65 local、82 presence、53 personal、112 flow、16 OIDC），日志在 `m2-local-swift/`；最终lab二进制的Swift→CLI临时vault完整流程也通过，`real-cli-check.json`记录exit0。原始正文哈希、默认拒绝、取消认证不提交、失焦/退出作废、通知不触发认证均已接线；真实Keychain/SE/通知权限仍未使用。个人RequireApproval模板现在生成LocalPresence一次性规则，不降级Permit。MCP两版本协商、GET和内容类型处理、owner await/cancel已落地，Profile自动发现尚未实现。

M3下一批按 `m3-foundation-preflight.json` 三路隔离实施：签名Profile纯模型、单一认证用量账本、OS进程监视。当前signed policy仍是format4/vault24；SPEC中format5/vault25为下一批合同。macOS实测证实注册前写入/FD移交可改变OS报告peer，不能追溯最初connector；注册后监视必须固定，真实run的五秒撤销仍待后续端到端。Cursor先做MCP，官方BYOK后端不能访问用户loopback，未冒充本机provider支持。

M3 foundation 已合流 Profile15、Owner2、Usage52、wire1 和外部44处格式夹具及脚本同步，源码不再是前一批 snapshot4/vault24：当前为 snapshot5/vault25。各 lane 最终补丁和审查位于 `outputs/rekey-v3-20261003/m3-{profile,owner,usage}/` 及 `review/`；root 新鲜合流 all-targets check 和 policy_mode6 通过，尚未将这些定向结果称为全量回归。Usage 独立审查发现已解锁重复 resume 会提前结算活请求，修为仅 Locked→Unlocked 恢复；空账本恢复改用同一 deferred 事务避免无故抢写锁，保留原审计到期断言。

下一阶段使用 `m3-runtime-preflight.json`：独立 worktree 并行实现 Broker Profile 签发/owner 控制与 CLI run，第三路只读核对 LLM 共同准入和结算接口，待上游 scope 冻结后接线。此阶段先支持明确验证的非 LLM 内置模板，未接完的 LLM 或隔离模式明确拒绝，不能将临时限制当作最终 SPEC 完成。

外部格式同步的定向复测：备份同步23项、审计投递28项通过，后者使用当前源码新构建的显式 binary 路径。保留首次备份演练遗漏 FORMAT_VERSION24 和审计测试缺默认 binary 的失败日志；生产演练常量及旧 durable-header 断言现已同步25。没有改故意拒绝旧格式的测试。

- Foundation integration gate first attempt exposed one stale root TestAuthority snapshot4 fixture. Updated src/lib.rs and current policy fuzz seed to5/profiles; focused broker_ipc regression now passes. Full default/lab rerun in progress; prior failed logs preserved in outputs/rekey-v3-20261003/m3-foundation-initial-*.

M3 foundation 冻结切片全量结果：默认786 passed /3 ignored；lab 首轮 relay 重启测试201期望收到503，保留 `m3-foundation-test-lab.log`。排除relay后的lab core 1,208 passed /3 ignored与lab workspace严格Clippy通过，不能拼接为完整lab全套通过；relay正在独立隔离lane做确定性诊断。

M3 Runtime8、RunCLI5、LLM7、Connect6、真实Run E2E1、个人Profile后端11和App4已按冻结补丁合入；各 `m3-*-final.json` 与 `review/` 保留独立审查及真实定向证据。新鲜合流all-targets check、m3-joined-checks.json全部组合定向及默认/lab strict检查通过。随后MCP6、relay测试修复及live MCP脚本按冻结补丁合流。relay已确定性复现TLS握手阻塞单accept线程并最小移入worker，21单元/24contract通过；历史那次连接本身不可追溯，新的完整lab合流gate仍待跑。raw SSE、网关、隔离、活动页与整库防回滚仍未完成。

M3 SSE9、Activity52/App4、通用SDK2已通过冻结hash与独立审查合流。`m3-core-audit-joined/checks.json`的实际CLI构建、Broker共同LLM、CLI Profile与workspace严格Clippy通过；root connect指导格式随后修正，`format-correction-checks.json`全0。`m3-activity-interop/final-checks.json`记录实际MCP→CLI审计页→App统计与Swift真实临时vault互通全0，两脚本尾审关闭。上述均为合成软件证据，最终HTTP/客户端适配和整套workspace gate仍待合流。

M3 Gateway11、显式客户端适配4、Anthropic beta6 和 M1 Header generation14 已按冻结补丁/文件hash合流，各自独立审查关闭。安装客户端的路由验收仅使用合成Admin/HTTP，115个artifact哈希和22条进程收据已核对；Codex preferences-routing不得视为L2。真实Broker+FakeUpstream接入正在独立树进行。

联合全套前三轮发现3个旧测试边界：500ms策略到期后再mint、buffered Action用于stream审批测试、policy draft旧--principal参数。分别只修正测试输入/观测点并保留负面断言，定向复验通过；历史失败日志完整保留。`m3-full-joined/round4-checks.json`当前执行default/lab no-fail-fast完整检查，尚未宣称通过。macOS Profile helper7和CLI/runtime glue4尚在独立树，helper死亡后的direct Agent/临时目录存活问题已实证，生命周期审查未关闭。

真实安装客户端→真实Broker/Authority→合成上游已完成：Claude/Codex各1/1，单次请求、output3/pending0、canonical audit hash、session.created/revoked匹配及进程清理均通过。`m3-sdk-broker-live`单测试文件和10条最终检查独立审查关闭，待整合。B1候选root/header先验证再发布6文件default/lab各85项通过；Profile helper7+glue4最终TERM收据审查关闭，实际EOF direct Agent和scratch均清理。这些候选待当前完整gate结束后按hash合流。

`round4`已发现并保留两个真实RED：RESPONSE_TOO_LARGE被映射为INVALID_INPUT，以及Gateway release调用debug-only ID构造函数；两文件最小修补已独立审查，待完整gate停止后应用。下一批并行C1外锚adapter及M4最小入口；无真实Keychain/安装/发布操作。

2026-10-03 后续合流：`round4`完整完成，default 937 passed/2 failed/3 ignored，lab 1,405 passed/2 failed/3 ignored，两配置相同的响应错误映射和release ID构造问题已最小修复。`reviewed-tail-checks.json`全部0，包括实际release policy进程验收；不能以这些定向复验替代新全量green。已按hash合流helper7/glue4/B1六文件/真实SDK单测试/root修补两文件共20，原失败证据保留。

C1四文件已通过独立审查和7条最终检查并合流，integration all-targets0；signed daemon不回退文件模式。macOS打包已进一步合流独立daemon bundle/profile、固定内部link和对应pkg fresh/public gate；profile13/pkg10/27脚本语法与workspacealltargets均通过，新daemon profile secret仍需发布环境配置，未真实安装/签名/调用Keychain。

M4首次引导六源码与打包URLscheme已合流，20最终检查通过；C2 UI四文件12最终检查（新增49恢复断言）已审查，仅overlay联合wire树等待core尾审。联合Domain/Broker/CLI生产workspacecheck0、Domain IPC16项0、实际CLI回滚与两步恢复1/1通过。独立审查发现并发init锁外检查/失败清理会删除其他成功attempt数据的P1，worker已用同锁所有权与真实屏障用例修复，等待尾审。完整workspace default/lab、实际Swift→新CLI及旧restore consumers仍在收尾；不提前声明整份SPEC或硬件安全等级完成。

本次回滚合流已完成：B2/C2 final26、root wire/fixture24、UI4共54文件，root补丁 `e405968e5a8be5d62890aa375508b5b0bd36db66f9849d74751927bc29124189`。并发init误清理、普通mutation疑似回滚后未及时撤销、错误confirm提前改动Unlocked数据库、超时核验后late unlock重开四项已独立复核关闭，报告 `review/m1-rollback-review.md`。root隔离合流默认/lab all-targets与lab strict通过，generation3/header12/实际CLI2及超时停止状态1定向通过；主集成all-targets通过，不替代最终workspace全量。

剩余本地工作已由 `v3-closure-plan/closure-plan.md` 逐项对照源码：恢复消费者13文件已独立审查、实际P0与大文件RSS通过，P2/P7尾部流水仍在收尾；Linux用户服务与真实pkg哈希cask在独立分发线；个人模板默认规则的明确覆盖尚待实现。root界面五文件已增加保守保护级别、精确旧格式错误重建指引和短密钥提示，Swift App/harness严格编译、保护18/回滚50/onboarding43断言通过。所有数字均为相应冻结批次，最终合流与硬件验收未提前计为通过。

## 2026-10-03 审查修复（独立分支）

基于 `e281673`，在 `codex/v3-review-fixes-20261003` 修复；尚未合入正在实施 M3 的集成工作区，其未提交改动保留。

- I3 明确禁止 presence 签发七天授权、修改密码和轮换恢复密钥。前两项接受密码或恢复密钥，恢复密钥轮换保持仅接受密码。拒绝 presence 请求保留原票据及永久因子；CLI、App 与原先允许这些操作的旧测试均已同步。
- 已解锁 step-up、unlock 和 Locked shutdown 使用同一失败计数与指数退避；切换操作或 lock 不重置限速。presence 成功不能清零密码猜测失败计数。
- App 仅复用同一保险库的 LAContext，首次成功读取后固定十秒，到期、失败、切换保险库、替换 K、锁定或清理管理会话时作废；不缓存 K。合成时钟和 context 身份测试通过；真机 fixture 编译未改动的生产 `PresenceKey.swift`，禁用交互的读取在 8.01 秒成功、11.00 秒拒绝，重新认证后成功，显式作废后再次拒绝。该证据覆盖真实 context/钥匙串读取，不替代已安装 App 操作流程。
- L1-dev CLI 在交互式秘密输入前及自动化证明发送前提示，同一进程只提示一次；App 证明/认证表单显示服务签名未验证警告。stdout JSON 合同保持。
- V2 采用同一 Developer ID 身份的普通/hardened daemon 与 Apple LLDB 对照，普通版本可附加并分离，hardened 版本拒绝。证据为 `docs/evidence/v3-review-v2-lldb-2026-10-03.json`。用户登录后已生成 V1 探针和正式 App 的独立 Developer ID profile；V1 正向/静默/ad-hoc 对照及精确清理通过，证据为 `docs/evidence/v3-review-v1-presence-2026-10-03.json`。系统在场认证成功，不区分指纹与允许的系统密码回退。
- 正式 `com.starlight.rekey` App 已使用匹配 profile 完成本地构建；App 和五个内置工具均通过 Team/ID、runtime、时间戳及严格签名检查，内置 CLI 版本命令成功。修复打包脚本 `--extract-certificates` 输出前缀的参数写法后，完整脚本退出 0。初次时间戳错误重试成功，原因未归因；未安装、未注册服务或发布。
- 基于 `50d79f3` 的独立修复版 App 已获 Apple 公证 `Accepted`（提交 `f91a2a5c-9cd9-4577-a4c8-da9dc326b206`，日志无 issues）。票据装订/验证、严格签名及 Gatekeeper 通过；最终 ZIP 解压后同样通过，Gatekeeper 返回 `Notarized Developer ID`。证据为 `docs/evidence/v3-review-notarization-2026-10-03.json`。首次下载公证日志遇到 TLS 连接错误，原命令重试成功；未绕过证书校验。该证据不覆盖 Installer pkg、已安装 App 流程或服务注册。

设备/签名补充批重跑默认 workspace：753 passed、0 failed、2 ignored；11 项 profile 配置测试、workspace check、格式、shell 语法与 CLI 依赖边界通过。新打包产物的 CLI/daemon 在独立合成状态下完成 init、status、unlock、lock、Locked shutdown，签名 CLI 未出现 L1-dev 警告，daemon 正常退出；不使用现有用户 vault 或安装服务。本批未重复 lab 全套。

本轮默认 `cargo test --workspace`：753 passed、0 failed、2 ignored；default/lab all-targets check、默认 strict Clippy、fmt、机械禁用符号和 CLI 纯 IPC 依赖边界通过。完整 App strict-concurrency 编译、88 presence /65 local 合成断言和 7 项探针判定回归通过。实际签名 CLI 的错误 ID/ad-hoc 服务控制测试另行通过 1/1，服务均收到零字节；真实隐藏 TTY 验证开发警告在输入前出现且仅一次，签名 CLI 无开发警告，缺服务仍保留 exit 7。本轮未跑 lab 全套；既有 lab 全套结果仍是上一批的历史证据。

失败记录保留：新失败审计合同使保留策略旧断言多出一条 `vault.unlock_failed`，已改为验证该事件及策略/执行记录不变；旧 presence recovery 测试已改成拒绝并使用密码正向轮换。一次未修改的 `restart_revokes_all_sessions` 在连接处返回 ECONNREFUSED，定向复测和最终全套均通过，原因未归因，不宣称修复此启动问题。

M0 复核：`rekey-approval-relay` 没有 lib target，bin 与 integration-test target 均声明 `required-features = ["lab"]`，因此默认构建已经排除，无需再次拆分。

## 2026-10-03 统一发布候选验收

以集成提交 `e1460b0` 建立 `codex/v3-release-acceptance-20261003` 独立工作区，合入 `01ac4c4`、`50d79f3` 和 `05c2cb7` 的安全修复与设备证据，保留回滚、Profile、网关和首次接入功能。V1/V2 已有独立探针通过记录；旧表中的 profile/归因阻塞是首轮历史结果。统一候选的完整测试、双 profile App/daemon、Installer pkg、公证和安装仍以本轮实际结果为准，不沿用旧 ZIP 的产物验收。


2026-10-04：统一候选默认全仓重跑 **1,013 passed / 0 failed / 6 ignored**；Lab 全仓最终重跑仍在进行。两配置 strict Clippy、App/harness 严格编译、十项 Swift 边界模式与机械合同通过。回滚 CLI 测试已允许 stderr 中先出现必要的开发警告，仍检查真实错误码。首次默认/Lab 过期夹具失败、错误断言和独立复验保留，未修改时间边界来掩盖失败。

统一 App 与独立 daemon 使用各自 Developer ID profile；新 Installer 身份签发获用户批准。真实打包发现 `codesign --test-requirement` 缺少文字规则的 `=` 前缀，已最小修复，并加强原 ad-hoc 拒绝夹具，确认进入规则校验而非语法失败。恢复密钥轮换的 App 说明同步为仅接受当前密码。最终 App 公证 `ca513952-e535-4211-9056-701925fc2bd3`、pkg 公证 `232f09e7-a288-4abe-91a5-f47c4696cef5` 均 Accepted；票据装订/校验、严格签名和两类 Gatekeeper 检查通过。产物 hash 和命令结果见 `docs/evidence/v3-release-acceptance-2026-10-04.json`。

真实候选 CLI/daemon 在合成临时库上创建并推进受保护代数。ad-hoc 读/写/删均拒绝；双并发条件更新只有一次成功。旧数据库代数 2 与真实保护上限 3 比较后，在密码认证时进入 `rollback-suspected` 且会话为零；实际 hardened daemon 拒绝 Apple LLDB。真实生产 PolicySigning 在 SE 中建钥/重载成功，不能导出私钥或静默签名。探针范围、失败的 harness 观察及测试项精确清理均记录；这些证据不代替已安装 App 的交互签名、审批或完整 T1–T12。

当前外部依赖：安装须管理员认证；真实 provider 需要本机 App 输入测试 Key，并确认模型与调用预算。此机 provider DNS 返回 `198.18.*` fake-IP，保持 Broker 的公网限制，网络修正等待用户选择。T12 仍须全新 macOS 账户；SMAppService 生命周期、独立人工安全审查、GA 格式冻结与公开发布仍 Pending。

2026-10-04 当前账户进展：此前候选 pkg 已实际安装，收据、三条 CLI 链接、二进制哈希和 Gatekeeper 校验通过。现有默认保险库只读确认格式 v10，保留原数据；另建空白 `.rekey-v3-acceptance-20261004` 目录。用户推迟新账户 T12，真实 GLM 模型指定为 `glm-5.3-flash`，总调用预算上限 500 USD。固定 GLM 模板与 App 选择已实现，15 项网关测试通过；新版 App 公证 Accepted，新版 pkg 因 connectTimeout 正在重试。Clash 的 fake-IP 根因已实证；尚未获得网络修改确认，未修改配置。原验收目录已出现格式 v25 的锁定保险库，保持不动。用户要求改用代码后，另建 `.rekey-v3-cli-acceptance-20261004` 个人库；随机证明与恢复材料仅保存在源码外权限 600 的私有验收目录。生产 PolicySigning.swift 的已签名 helper 已完成 SE 建钥/签署，真实 daemon 安装信任根、激活 GLM Profile 和 `rekey run` 启动/退出撤销均通过；GLM Key 经 stdin 加密保存，尚无真实上游调用。默认最新全仓 1014/0/6、lab 1482/0/6 均通过；两配置 strict Clippy、fmt、all-targets 编译、机械合同和 10 项 pkg 回归通过。新版 pkg 另保留 S3 deadlineExceeded 与 Apple API -1005 断连，改用 Apple 官方 REST API 经既有本机代理上传；不据此宣称安装版 SMAppService 或 T12 完成。

2026-10-04 当前账户补证：新版 GLM pkg 经 Apple 官方 Notary REST API、既有本机代理成功上传，公证 `b03a36c9-0a49-4417-9b61-a3fba49d20bf` Accepted，issues=null；装订/验证、App/pkg Gatekeeper、安装后哈希与三条链接通过。普通 HTTPS 在原 Clash 配置下对真实 GLM 调用返回 200（输入 16、输出 61 token），而相同请求经实际 `rekey run` 返回 502/UPSTREAM_FAILED；OS DNS 仍为 198.18.7.242，生产 `select_public_endpoint` 拒绝该非公网地址。用户要求先解释，保持 Clash 配置不动；此前 DNS 修改提议不是必要前提或既有网络故障的结论。此对照不算 Rekey 的真实 provider 或 T11 验收。
