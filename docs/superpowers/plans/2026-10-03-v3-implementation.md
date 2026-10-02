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
| V1 数据保护钥匙串、访问组、userPresence | 原型已写，环境验收受阻 | `scripts/v3/keychain_probe.swift`；当前无授权 profile，带 entitlement 的 owner 被系统终止，不能认定机制通过或失败 |
| V2 签名 hardened rekeyd 内存访问 | 原型已写，待归因核查 | `scripts/v3/memory_probe.c`；真实临时已解锁 daemon 拒绝 task_for_pid；ad-hoc 对照也拒绝 |
| V3 peer audit token 与动态签名身份 | 原型实测通过 | `scripts/v3/peer_probe.swift`；正确 Team/ID 成功，错误 ID 和 ad-hoc 均零字节；不宣称解决所有内核时序竞态 |
| 原型统一入口与结果报告 | 已实现，审查通过 | `scripts/v3/run.py`；独立审查问题已修复，4 项报告/清理回归测试通过；只用合成数据 |
| M0 lab feature / 默认构建 / 发布和CI分离 | 默认构建验收通过，lab 全量待跑 | 默认/lab all-targets 编译通过，worker 定向 default 148 / lab 51 测试通过；84 文件补丁独立复核通过；根默认全量串行通过，lab 全量待跑 |
| M0 README / spec 状态 / 格式冻结规则 | 已实现，未发布 | README 只列现有入口；35 企业 spec 标 Lab，两份研究稿改 v4；永久不迁移，GA 主版本内冻结格式；编译器源输入物理行 40,371 / 60,754（非有效代码量） |
| M1 SHUTDOWN 全状态 step-up | 待实施 | T2；信号关停与管理员请求分别验证 |
| M1 presence proof 与钥匙串 UI | 等待 V1 环境验证 | 每次获取受 OS userPresence 保护；不在 daemon 强制 Touch ID |
| M1 desktop-reveal step-up / 明文清零 | 待实施 | T2；原 desktop token 不能独自查看明文 |
| M1 生产客户端签名校验 / 等级显示 | 本批验收通过 | 签名 CLI 对错误 ID 同团队/ad-hoc 服务均在发送前拒绝，服务收到零字节；status/UI 展示本地验证结果；同团队 release daemon 的 status/unlock/shutdown 正向通过；仍不代表完整 L1 |
| M1 rollback generation / MAC / 外部计数 | 待实施 | T6；旧库拒绝自动解锁与执行；备份恢复确认 |
| M1 memory hardening / core limit | 部分实现 | daemon 启动设 core limit，Linux 另设 dumpable=0；macOS 独立子进程检查通过；Linux 运行和 mlock 未完成 |
| M1 pkg / LaunchAgent / SMAppService | 待实施 | 签名、公证、安装和重启验收 |
| M1 独立安全审查 | 待完成 | 原型代码审查不等同于产品安全验收 |
| M2 P-256 个人策略签名 / App 模板选择 | 待实施 | Touch ID/SE 属于实现；Ed25519 团队模式保留 |
| M2 模板规范与路径/query渲染 | 领域基础已实现 | 12 个边界测试和独立审查通过；管理员 bindings 不可覆写、封闭参数/query；尚未接入签名、存储、授权和执行链 |
| M2 anthropic/openai/github/generic 模板 | 领域基础已实现 | 四个内置声明与风险默认值测试通过；App 配置入口未实现 |
| M2 Approver / local-presence / 面板 | 待实施 | T10；challenge 与 principal/参数/策略绑定、一次性消费 |
| M3 Profile / 会话生命周期 / rekey run | 待实施 | T9；进程异常退出与 CLI SIGKILL 后 5 秒撤销 |
| M3 gateway / 认证 / SSE / model与预算 | 待实施 | T1/T8；仅 loopback；不可转发入站真实 Key |
| M3 MCP v2 / await_approval / GET | 待实施 | T1/T10；文本内容与二进制正确处理 |
| M3 rekey connect / diff / 备份 | 待实施 | 确认后才写第三方 Agent 配置 |
| M3 活动页 / 审计统计 | 待实施 | 按 Profile/模板显示调用、拒绝、审批、token |
| M3 遮蔽增强 / 编码与压缩限制 | 本批验收通过 | JSON/hex/base64 对齐、禁止压缩头；独立审查的窗口/短秘密问题已关闭；流式跨片回归通过；11 项 decoded source 合流回归通过；真实 TLS streaming 8/8，通过 marker fast path 避免逐字节重复扫描 |
| M3 连续 500 次零交互与真实Agent接入 | 待实施 | T11；真实 Claude Code / Codex 独立证据 |
| M4 新账户 5 分钟接入 | 待实施 | T12；签名 pkg、3 命令、0 JSON |
| M4 格式冻结 / 基线 / GA 发布 | 待实施 | 公开发布需要明确发布授权；本轮默认本地实现与验证 |

## 本机首轮探针记录

本机 macOS 26.5.1，SDK 26.5，使用项目对应 Developer ID Team `C5UWZ934C2`。原始结果：主工作区 `outputs/rekey-v3-20261003/signed-run-1/report.json`。V1 的进程退出码为 -9，缺授权 profile 是环境诊断，尚未取得钥匙串 API 返回码。V2 的 signed 与 ad-hoc 均返回 Mach 5。V3 三个场景的有效身份 / 错误 ID / ad-hoc 结果符合预期。

原型结果不能被描述成整份 v3 已完成，不能提高当前产品的 G1/L1-dev 承诺。

## 当前依赖批次

M0 补丁已冻结并整合；来源 `outputs/rekey-v3-20261003/m0/m0-frozen.patch`，
SHA-256 `57f077ce514ecaeaa57d1750c4909aaf1b97fc0e556fc8be68badba74378e1a9`。
统计口径为 rustc `.d` 源输入去重后的物理行，包含 inline cfg/test 文本；33.55%
是该口径的差异，不能宣传为实际机器码或有效生产代码缩减。

下一批先做不依赖 V1 的 password/recovery 管理修复：Locked SHUTDOWN 校验不解锁、
验证失败不能触发停机、逐次 reveal step-up、Rust 响应体清零所有权。
只读计划位于 `outputs/rekey-v3-20261003/m1-admin-plan.md`。presence 与 L1 承诺继续受 V1/V2 验收约束。

签名正向证据：`outputs/rekey-v3-20261003/production-peer-positive.json`（release
CLI/daemon 的最终签名哈希，Locked/Unlocked 均返回 `verified_signature` 且 `lab_enabled=false`）。
早先 debug 产物在并发 release 编译期间初始化超时，记录保留，不计作通过。
release 临时 vault 的 Swift UIContract 及 80 项 native flow 边界检查通过；未运行真实 GUI 点击。

默认 workspace 全量检查采用 CI 的串行测试设置通过：589 passed / 2 ignored（包含嵌套验收脚本的输出）。默认严格 Clippy、default/lab all-targets 编译、格式和 CLI 依赖合同通过。并发运行时的两个 deadline fixture 失败保留为环境敏感性记录，未增加超时或删除断言。
