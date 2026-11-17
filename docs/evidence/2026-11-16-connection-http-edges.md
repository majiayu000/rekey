# 2026-11-16：个人版 HTTP 边界补测与拒绝语义修正

## 决定与范围

本轮要支撑的决定：[2026-11-14 记录](2026-11-14-connection-http-readiness.md)列为“没有逐项重建”的旧网关场景，
在默认 Connection 路径上是否成立；不成立的是否属于阻塞日用的缺陷。
放弃条件：需要真实设备、真实供应商、发布授权，或需要改变 vault27 / policy8 格式与规则语义的项目不在本轮处理。

源码基线 `50f900adad707eb3e6cf7c2ff4bc772f75eac7b0` 加 2026-11-14 的测试改动。
结论：采用。六类场景已在默认产品上重建；重建过程暴露三处日用缺陷，已修复并有回归。
不提升保护等级，不改变发布状态。

## 重建的场景

`tests/personal_policy/gateway_edges.rs`，由 `tests/personal_policy.rs` 注册，默认 workspace CI 运行。
HTTP 客户端、原始 TCP 字节与 loopback 服务是真实的；上游仍是注入的合成 transport。

| 场景 | 断言 |
|---|---|
| 原始 socket 混淆请求 | 异常 / 重复 Host、Origin、Sec-Fetch-Site、重复或真实认证值、缺占位头、Content-Encoding、Upgrade、固定头不符、非法审批 ID、CL+TE、未签署或重复的透传头、绝对 URI 共 17 种请求头形态，以及 11 种路径 / 查询形态（缺 `/c/`、旧 `/p/`、未知连接、百分号编码段、空段、`..`、尾斜杠、未声明端点、未允许或重复的查询键）全部按固定状态拒绝；不到上游、不写任何审计行、响应不含凭据。随后同一路由的合法请求成功 |
| 认证字节、大小与读超时 | 逗号 / 空格拼接、小写 scheme、非 UTF-8 认证值返回 400；声明或分块正文超过签署的 1 MiB 返回 400；完整请求头超过 16 KiB 返回 431；正文迟迟不到在约 5 秒读超时后返回 400；均无 `execution.started` |
| GET models 与 MIME 参数 | 上游收到空正文且无 content-type；带正文的 GET 返回 400；`application/json; charset=utf-8` 仍被接受 |
| Anthropic beta 查询 | `/v1/messages` 与 `/v1/messages/count_tokens` 带或不带 `?beta=true` 均按原样到达上游；其他查询键、未声明端点带同一键返回 403 |
| 终态审计提交失败 | 用 SQLite 触发器拒绝 `execution.finished`：HTTP 正文报错而非正常结束，无 `[DONE]`、无 finished 行；之后的调用返回 503 `FAULTED`（不可重试），不到上游 |
| 服务文件发布失败 | `service.json` 无法被原子替换时启动失败，不留下任何 Unix socket 或临时文件 |

没有照搬的旧断言：OpenAI 预设没有签署查询白名单，`?beta=true` 在该预设下不是拒绝项，本轮不改规则语义；
Profile owner EOF 与 session expiry 属于已退出的旧产品语义。

## 修复的缺陷

1. **锁定被报成“未配置”。** 锁定会清除生效策略，而 HTTP 入口先查策略再查运行状态，
   于是锁定的保险库返回 `NOT_CONFIGURED` 和“用 request_access 申请”的提示。现在先报告运行状态：
   返回 `LOCKED` 与 `await_unlock` 提示，解锁后原 Connection 直接可用。
2. **暂时不可用被报成 403。** 同一连接第 5 个在途调用（规格写明为可重试的 `AUTHORITY_BUSY`）、
   停机中和故障后的拒绝都返回 403，SDK 会当作权限错误而不重试。现在这类运行状态拒绝统一为 503；
   403 只表示规则、预算或请求内容被拒绝。`AUTHORITY_BUSY`、`DRAINING`、`FAULTED` 增加了针对性的 `next`。
3. **启动失败没有原因。** 默认端口 7787 已被另一个保险库占用时，`rekeyd` 只输出 `ipc unavailable`。
   现在失败为 `SERVICE_PORT_IN_USE`，日志 `service.port_in_use` 带端口号和修改 `service.json` 的提示；
   其他启动 IO 失败在 `rekeyd.command_failed` 中附带系统原因（例如保险库目录过深导致的
   `path must be shorter than SUN_LEN`）；失败的启动会移除已绑定的 socket。

另外删除了 `runtime/gateway.rs` 中恒为空的 Profile 端点计算（绑定记录的策略摘要一直是全零，
`endpoint()` 不可能匹配），lab 的 Profile 会话响应保持 `gateway: null` 不变；
并修正 Rust 1.99 Clippy 新增规则指出的 4 处写法，固定工具链 1.95.0 的结果不受影响。

规格 §6.3、用户指南、运维手册和 CHANGELOG 已在同一提交中同步。

## 软件验证

命令均显式使用仓库固定的 Rust 1.95.0，本机执行，原始输出未入库。

- 修复前：新增的锁定、容量与故障三项按预期失败（`NOT_CONFIGURED`、403、403），修复后通过。
- `cargo fmt --all --check`；默认与 `--features lab` 的 all-targets 严格 Clippy：通过。Rust 1.99.1 的默认配置严格 Clippy 也通过。
- 默认 workspace：Broker 359 通过 / 0 失败 / 9 忽略，其余 731 通过 / 0 失败 / 5 忽略，合计 1,090 / 0 / 14；
  比本轮开工前的 1,081 多出的 9 项即新增测试。
- 一次未通过的运行如实保留：本机同时有其他项目的测试、负载均值超过 100 时，
  其余 workspace 的第一次运行有 5 项失败（CLI `connect` 4 项、vault `usage` 1 项，均为本轮未改动、
  依赖子进程与 10 秒夹具等待的用例）。两个目标单独重跑全部通过，随后不并行其他测试的完整复跑为 731 / 0 / 5。
  上面的合计取自这次复跑，不是把失败的那次改记为通过。
- lab 定向：个人版策略与网关 23、Profile 会话 15、流式 8，共 46 项通过；不代表完整 lab 运行时。
- 真实二进制（debug 构建，临时目录与隔离 HOME）：`scripts/test-cli-add.py`、`scripts/test-human-vault.py`、
  `REKEY_QUICKSTART_REAL=1 scripts/test-agent-quickstart.py`（12 项）通过。
- 端口冲突实测：本机已安装的 Rekey 占用 7787 时，在临时目录新建保险库并启动 debug `rekeyd`，
  得到 `service.port_in_use`（port 7787）与 `SERVICE_PORT_IN_USE`，退出码 5，无残留 socket；
  按提示写入空闲端口后启动成功、`status` 可读、SIGTERM 正常退出。未读取、解锁或改动已安装的保险库。
- 三项机械契约（禁用标识符搜索、CLI 依赖边界）无命中。

已验：真实 HTTP 客户端与原始 TCP 字节下的拒绝状态、错误码与 `next`，以及 debug 二进制的端口冲突报错。
没验：macOS App 对 `SERVICE_PORT_IN_USE` 的界面提示（规格要求在 App 中报警，本轮只改了 daemon 输出）、
真实 SDK（Claude Code / Codex）在 503 下的重试表现、签名安装产物。
相邻情况：IPC 与 MCP 入口的 `LOCKED` 沿用既有测试，本轮未改；Linux 上的 socket 路径上限与端口冲突报错未在本机验证，留给 CI；
旧记录中的 beta 可选头、缓存发布失败后的运行期重试未单独重建。
