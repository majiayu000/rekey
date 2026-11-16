# 2026-11-14：个人版 HTTP 验证与日用门槛

## 决定与范围

采用当前 personal-first Connection 产品路线，暂缓扩展供应商、企业控制面与隔离等级。
近期目标是让个人用户给 Codex 授予有范围、有预算、可撤销的服务调用权限，真实长期 Key 不进入 Agent 配置、上下文和常规输出。
同用户任意代码攻击、任意编码外泄和明确授权的临时凭据不属于上述承诺。

本轮以 `50f900adad707eb3e6cf7c2ff4bc772f75eac7b0` 为源码基线。
工作区修改只涉及测试和验证文档，不改变产品接口、策略格式或凭据存储。
若当前 Connection 主路径仍不能稳定日用，则继续修复有证据的阻塞，不扩大功能范围。

## 旧测试为何退役

旧 `crates/rekey-broker/tests/gateway.rs` 仅在 lab 下编译，仍使用
Profile session、session gateway endpoint 和 `/p/work/...`。
当前 HTTP 服务只路由签名 Connection 的 `/c/CONNECTION/...`。

基线复跑的 18 项测试全部在加载策略时返回 `POLICY_INVALID`。实验性补上
必填的 `derived_credentials: []` 后，策略加载通过，但仍然全部失败：没有
旧 session gateway endpoint，尚未测试到目标 HTTP 行为。
这两次失败不能证明当前 Connection 服务不可用。

决定删除失效的旧测试入口，不添加旧路由兼容层，不用 ignore 掩盖失败。
完整旧用例保存在上述基线的 Git 历史中。这不是把 18 项旧覆盖全部宣布为通过。

## 默认产品的新覆盖

`tests/personal_policy/gateway.rs` 由 `tests/personal_policy.rs` 显式注册，
直接复用个人保险库、P-256 策略签署和真实 Broker fixture。
默认 workspace CI 会运行，无需启用 lab。
HTTP 客户端与 loopback 服务是真实连接；上游为注入的合成 transport，非真实供应商。

| 行为 | 本轮断言 |
|---|---|
| 响应头与认证 | Anthropic / OpenAI 的 429 状态、JSON 正文、content-type、retry-after 保留；set-cookie 过滤；transport 收到一个独立认证槽，普通头不带入站认证 |
| SSE 增量输出 | Anthropic Messages、OpenAI Chat / Responses、GLM Messages / Responses 五条路径；用 channel 阻止上游结束，客户端仍须收到首块；结束后完整 SSE 字节相同 |
| 持久终态 | 用 SQLite 写事务阻止终态提交，HTTP 不得提前结束或交出协议成功终标；提交后 EOF 前须已有 execution.finished |
| 上游流中断 | 已输出前缀后断流，HTTP 正文必须报错，无成功 EOF、无 DONE、无 execution.finished |
| 流式错误与反射 | 上游 429 保留允许头与正文；反射真实凭据时返回不可重试的 RESPONSE_BLOCKED，正文不含凭据 |
| 拒绝路径 | 旧 /p 路由、重复认证头、未签署模型不得到达上游 |

既有默认个人版测试继续负责审批绑定、deny 优先、锁定清除审批窗、IPC/HTTP
共享预算、started 审计失败禁止解密与出站、调用容量与终态所有权。

旧网关测试中下列精确场景没有在本轮逐项重建：Profile owner EOF / session
expiry（旧产品语义已退出）、缓存发布失败、原始 socket 混淆长度和 body deadline、
beta 查询 / 可选头、GET models、终态审计提交失败（本轮验证的是阻塞提交）。
不能从本轮通过推断这些相邻场景全部通过，也不宣称完整 lab runtime 已可用。

## 软件验证

日志保存在本地 `target/acceptance/2026-11-14-connection-http/`。
最终状态在本轮命令结束后记录，不沿用历史全仓通过数字。

- 新增五项默认 HTTP 测试：已通过；使用各协议对应的请求正文纳入默认回归。
- Rust 1.95.0 的默认 workspace check、格式与严格 Clippy：已通过；最终输出见 `final-check.log`、`final-clippy.log`。
- 默认 workspace 回归分段完成：Broker 350 通过 / 0 失败 / 9 忽略（`pinned-workspace-tests.log` 中 Broker 段）；修正 Git fixture 后，其余 workspace 731 通过 / 0 失败 / 5 忽略（`final-remaining-workspace-tests.log`）。合计 1,081 通过 / 0 失败 / 14 忽略；另补跑 Broker doc-tests（0 个用例）。不是把先前失败的单次全仓命令改记为通过。
- lab：workspace 编译和严格 Clippy 已通过；个人版策略 / 网关 14 项在 lab 配置下也通过。不运行完整历史企业运行时。

本机不带显式版本的命令实际使用 Rust 1.99.1，与仓库 / CI 固定的 1.95.0 不同。
1.99 Clippy 的两个既有风格告警不在本轮修改范围；正式软件门槛显式使用
`cargo +1.95.0`，不放宽 lint、不修改无关生产代码。

首次全仓检查另发现 connect 的两个 hook 测试继承真实全局 Git 配置，
`git rev-parse --git-path hooks` 因此指向本机 agent-trace hook 目录，
安全的 O_NOFOLLOW 读取拒绝其 pre-commit 符号链接。测试 fixture 现把
`GIT_CONFIG_GLOBAL=/dev/null` 和 `GIT_CONFIG_NOSYSTEM=true` 传给 CLI，
让它启动的 Git 也使用隔离配置。没有修改用户的 Git 配置或 hook；
不降低产品对符号链接的拒绝要求。

指定的 lab text-stream 组首次为 7 通过 / 1 失败：旧 EXECUTE 的拒绝测试仍
期待内部 `REQUEST_DENIED`，而现行 Agent 接口统一映射为 `DENIED`。
只更新该测试的期望，保留空正文断言，不新增错误别名或修改产品代码。
复跑 8 项全部通过，见 `final-text-stream-after-error-mapping.log`。
因此指定的 lab 个人版 / 流式回归合计 22 项通过；不扩展为完整 lab 验收。

## 安装版观察与下一道门槛

只读检查 `/Applications/Rekey.app`：CLI 报 `0.5.0-alpha.1`；App 的
deep / strict 签名校验成功，Developer ID 签名时间为 2026-10-23 16:13:53。
这不足以证明安装版对应当前源码；本轮未安装、替换、解锁、改写现有保险库或访问真实供应商。

安装版只读 IPC 回执：daemon 为 `0.5.0-alpha.1`、vault27、lab disabled、
`peer_security=verified_signature`、`state=locked`。policy status 表示
`trust_installed=true`、`bundle_persisted=true`、`status=unavailable`；
锁定状态下不可读不等于未安装信任或从未激活策略。
真实调用前需要用户在 App 自行解锁；密码不通过聊天传递。

下一道门槛必须绑定同一份签名产物、源码版本和专用测试保险库，保留旧库：

1. 添加专用测试 Key，审阅固定 origin、模型、预算和读写规则；保留原信任根。
2. 签署激活并读回 policy status；记录密码和系统认证次数。
3. 由产物内 CLI 生成专用 Codex 配置，完成首次模型调用、SSE 与一次工具调用。
4. 对受控资源验证写审批的允许 / 取消、明确 deny、锁定 / 撤销后的拒绝，核对审计。
5. 重开 App、重启 daemon，验证连接与恢复；检查指定日志、配置和产物中无原值及支持编码的 Key。

首次接入目标为两分钟内、密码最多一次、Touch ID 最多两次；设备实测前保持待验证。
未获同一产物的真实 Codex、系统认证和恢复证据前，不提升保护等级或宣布可发布。

## 七天日用记录

从上述门槛通过之日开始计时，记录版本、使用天数、调用成功 / 失败及原因、
审批次数与取消结果、密码 / Touch ID 次数、重启 / 恢复结果和泄露命中。
不创建后台采集服务，不自动收集 Key 或请求正文。

| 日期 / 版本 | 调用成功 / 失败及原因 | 审批 / 认证次数 | 重启恢复 | 泄露检查 | 当日阻塞 |
|---|---|---|---|---|---|
| 待安装验收后开始 | 未测 | 未测 | 未测 | 未测 | 未开始 |

采用条件：七天没有无法解释的授权放行、凭据暴露、数据破坏或重启恢复失败，
日常调用失败均可定位且不需绕过 Rekey。任一安全条件失败即停止扩大使用，
保留证据并优先修复；上游自身失败单独统计。

已验：合成上游下的真实个人版 HTTP 响应、首块和持久终态门控。
没验：当前签名产物的真实 Codex / Touch ID 和七天日用。
相邻情况：lab 历史运行时、原始 socket 边界和真实供应商按上述范围分别保留未验状态。
