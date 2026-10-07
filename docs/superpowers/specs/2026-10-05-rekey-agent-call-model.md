# Rekey Agent 调用模型（0.4 发布线）

**状态**：冻结（Accepted）。2026-10-05 用户授权按本文并行实现；§15 采用推荐值。
**日期**：2026-10-05
**基线**：`origin/main` @ `043a020`（v0.3.0-alpha.1，vault25 / policy6 已冻结）。
**整合边界（2026-10-06）**：继承 `main` @ `0828fca` 的 0.3.0-alpha.2 SSE、首次 HTTP handoff 与认证用量账本优化；当前发布线仍为 0.4.0-alpha.1、vault26 / policy7。0.3 的发布记录和测量只适用于原源码；整合后的软件门禁与性能需要重新验证。
**取代关系**：本文取代 `2026-10-02-rekey-v3-personal-first.md` 中的以下内容：
- §8 Agent 接入（`rekey run`、Agent Profile 会话、网关的 capability 认证）；
- §3.3 中 L2 依赖启动器的部分。

该文其余内容（加密层级、presence、Approver、回滚检测、模板渲染安全规则、发布与格式规则）继续有效。

**用户决定（2026-10-05）**
1. **核心原则**：Rekey 保存密钥，并提供 CLI、MCP 和本机服务；Agent 在需要用密钥时**主动调用 Rekey**，由 Rekey 代为完成操作，Agent 不接触密钥。**Rekey 不启动、不包裹 Agent。**
2. 密钥由用户在 Rekey 的 UI（或 CLI 隐藏输入）中添加，永远不经过 Agent。
3. 以下功能全部纳入：
   - 能力自查与按需请求；
   - Agent 说明书和面向 Agent 的错误信息；
   - 按 host / 路径授权、读写分级；
   - SSH agent；
   - 防泄漏检查；
   - `.env` 迁移；
   - 调用方识别；
   - 预演（dry-run）；
   - OAuth 托管；
   - 短期派生凭证；
   - 插件分发。
4. 永不向后兼容（沿用）。本文的格式变化进入新的 0.4 发布线，0.3 的 vault 需要新建。

---

## 0. 一页摘要

```
 用户 ──(Rekey.app / CLI 隐藏输入)──►  Rekey：保存密钥、连接与规则、审批、审计
                                          ▲      ▲        ▲          ▲
                    rekey CLI ────────────┘      │        │          │
                    rekey-mcp（MCP 工具）────────┘        │          │
                    本机 HTTP 服务（给 Agent 写的代码）───┘          │
                    SSH agent（git push / ssh）──────────────────────┘
                                          ▲
                 Agent（Claude Code / Codex / Cursor / 脚本），照常启动
```

- **Agent 拿到的是调用结果**，不是密钥。所有密钥注入、签名和 OAuth 刷新都在 Rekey 内部完成。
- **本机调用方不再需要令牌**：
  - 授权依据是用户签署的规则：哪个连接、哪个 host、哪些路径、读还是写；
  - 写操作默认需要审批。
- **调用方识别只用于标注**：Rekey 识别调用方是 Claude Code、Codex 还是脚本，用于审计和按调用方定制规则。同用户下这种识别可以被伪造，它不是安全边界（§4.3）。
- **人只在三个时刻出现**：
  1. 添加密钥；
  2. 设定或批准规则；
  3. 审批写操作。

  Agent 缺密钥或缺权限时主动发起请求，App 弹出通知，用户处理后 Agent 继续。
- **开发卫生**：
  - 把项目里的 `.env` 迁进 Rekey；
  - 用真实值精确扫描泄漏，并装 git 提交钩子；
  - 把使用说明写进 `AGENTS.md` / `CLAUDE.md`。

**明确不做**
- `rekey get`。
- `rekey run` / `rekey exec` 这类把密钥或令牌注入 Agent 进程的做法。
- git credential helper。
- Agent 自身连模型用的 Key（Claude Code、Codex 用自己的登录或订阅）。

---

## 1. 背景：0.3 的问题

依据：`origin/main` @ `043a020`。

### 1.1 接入方向相反

- **0.3 的唯一可用路径是由 Rekey 启动 Agent**：
  - `rekey run claude-code --client claude-code -- claude --model ...` 签发 capability，再写入子进程环境变量（`crates/rekey-cli/src/commands/run.rs:166-172`、`:318-341`）。
  - `rekey-mcp` 从 `REKEY_CAPABILITY` 读令牌，缺失时返回 `NEEDS_SESSION`（`crates/rekey-broker/src/bin/rekey-mcp.rs:161`、`:171`）。
  - 网关只接受 `rkc_` 令牌。
- **结果**：用户直接运行 `claude` 时，任何入口都不可用，与原则 1 相反。

### 1.2 授权粒度过死

- 每个 Action 是一个固定的 method + path（允许封闭参数），模板预先展开成大量 Action（GitHub 一次安装 16 个）。
- Agent 调用模板之外的接口只能失败，用户也无法理解"16 个 Action"代表什么。

### 1.3 可以保留的部分（已审查）

- 加密层级、Authority Worker、presence、回滚检测、内存加固。
- 模板路径与查询参数的安全渲染规则（`crates/rekey-domain/src/template.rs`）。
- 出站请求：公网 IP 钉死、禁止重定向、忽略代理、fake-IP 默认拒绝与可选 DoH。
- 响应遮蔽：原始与解码双层，SSE 按块序号投影。
- 预算、用量账本、审计、本机审批（presence + 审阅哈希）。
- 个人策略签名（Secure Enclave P-256）、团队 Ed25519。
- App 的添加 API Key 表单（`apps/macos/Forms.swift:158-184`）。

---

## 2. 用户故事（验收以此为准）

| # | 场景 | 期望 |
|---|---|---|
| U1 | 用户在 App 添加 GitHub PAT，选"只读自动允许，写操作问我" | 不写任何 JSON；之后 Claude Code 直接可用 |
| U2 | Claude Code 想知道自己能用什么 | 调用 `list_capabilities`，返回"github：读允许、写需审批"，不含任何密钥 |
| U3 | Claude Code 读 issue | 直接返回结果，无弹窗 |
| U4 | Claude Code 创建 issue | App 弹出审批，显示完整请求；Touch ID 后执行；Agent 拿到结果 |
| U5 | Codex 需要 Stripe，但没有配置 | Codex 调用 `request_access`，App 弹出"添加 Stripe Key"；用户填写后 Codex 继续 |
| U6 | Agent 写的 Python 脚本调用 OpenAI SDK | 脚本读到的 `OPENAI_API_KEY` 是占位符，请求经本机服务完成 |
| U7 | Agent 执行 `git push` | 经 Rekey SSH agent 签名；推到受保护分支所在的 host 需要审批；私钥不出 Rekey |
| U8 | Agent 不小心把 Key 写进代码并准备提交 | pre-commit 钩子拦截，指出文件和行号，不回显 Key |
| U9 | 用户第一次在老项目里启用 Rekey | `rekey import .env` 把 Key 收进 Rekey，`.env` 改为占位符 |
| U10 | Agent 需要 Google Drive（只支持 OAuth） | 用户在浏览器完成一次授权，之后 Agent 直接调用 |
| U11 | Agent 需要运行 `aws s3 ls` | 拿到 15 分钟、权限收窄的 STS 临时凭证；UI 标明这是派生凭证等级 |
| U12 | 用户想审查今天 Agent 做了什么 | 活动页按调用方 × 连接 × 读写列出调用、拒绝和审批 |
| U13 | Vault 处于锁定状态时 Agent 调用 | 返回 `LOCKED`，App 通知用户解锁；Agent 可以等待后重试 |
| U14 | 安装 | `brew install --cask rekey` 或 pkg；`rekey connect claude-code` 写入 MCP 和说明书；可选 `claude plugin install rekey` |

---

## 3. 概念模型

| 概念 | 定义 |
|---|---|
| **Secret（密钥）** | 加密保存的值：API Key / PAT、OAuth refresh token、SSH 私钥、AWS 根凭证等。沿用现有 credential 存储与版本 |
| **Connection（连接）** | 一个 Secret 加上它允许访问的一个 origin、注入方式和规则集。例如 "github-personal → https://api.github.com，Bearer"。一个 Secret 可以对应多个 Connection |
| **Preset（预设）** | 由现有内置模板演进而来：给定 provider 的 origin、注入方式、默认规则，以及**具名操作**（用于 MCP 工具名和 `rekey call` 子命令） |
| **Rule（规则）** | `(method 类别, 路径模式) → allow / approve / deny`，可以按调用方覆盖（§5） |
| **Caller（调用方）** | 发起调用的程序：claude-code、codex、cursor、script:<可执行文件>、unknown。由 daemon 识别，用于标注（§4.3） |
| **Access Request（访问请求）** | Agent 发起的"需要某个连接或某条规则"的请求，由用户在 App 中处理 |
| **Approval（审批）** | 沿用现有 local-presence 审批：绑定规范化请求哈希、只能使用一次；新增时间窗审批（§5.5） |
| **Grade（等级）** | 每个 Connection 标注一个等级：`T0 代理`（Agent 永不接触）或 `T1 派生`（Agent 进程会拿到短期派生凭证，见 §8.4） |

持久格式：0.4 使用 vault26 / policy7。policy7 在首个预发布前纳入全部本地签名授权字段：`connections` 和 `ssh_keys`；缺失字段直接拒绝，不兼容旧快照。

Profile、capability session、Action 这三个概念**不再暴露给个人用户**：
- Action 仍作为内部的规范化执行单元存在；
- capability 只保留给远程或工作负载调用方（企业储备，§13）。

---

## 4. 安全合同

### 4.1 不变量（替换 v3 §3.4 中对应条目）

- **I1**：任何调用方接口（CLI、MCP、本机服务、SSH agent）都不返回 Secret 明文或其可逆变形。SSH agent 只返回签名。T1 连接的派生凭证除外，见 I10。
- **I2**：Secret 只在 Authority 内部解密，且必须在规则判定和 `execution.started` 审计提交之后；每次请求只解密一次，用后清零。沿用。
- **I3**：管理操作的 step-up 规则沿用 v3：presence 不能签发 7 天授权，不能修改密码或恢复密钥。新增以下管理操作，均属于 A2：
  - 添加 Connection、修改规则、处理访问请求；
  - 导入 `.env`、完成 OAuth 授权；
  - 生成或导入 SSH 私钥；
  - 启用 T1。
- **I4**：客户端对 daemon 的签名校验沿用。新增约束：`rekey-mcp`、SSH agent 套接字和本机服务都由 daemon 自己提供或监听，客户端在向 daemon 发送任何管理证明之前，必须完成校验。
- **I5**：Secret 不进入 argv、env、日志、审计或 JSON 元数据。**取消 v3 的"capability 可以进入子进程 env"这一例外。**
- **I6**：出站只能访问 Connection 声明的 origin；路径必须匹配规则；连接钉在公网 IP 上，禁止重定向。沿用。
- **I7**：fail closed。沿用。
- **I8**：回滚检测。沿用。
- **I9**：命中 `allow` 规则的调用不产生任何人工交互；`approve` 规则一律进入审批；`deny` 直接拒绝。
- **I10**：T1 连接只能签发有效期不超过 60 分钟、权限不大于用户设定范围的派生凭证。UI、`list_capabilities` 和审计都必须标注 T1。T0 连接永远不签发任何凭证。
- **I11**：防泄漏扫描只返回"位置 + 连接名"，不返回匹配内容；只报告完整匹配，不报告部分匹配（§9.3）。

### 4.2 威胁参与者（在 v3 §3.2 基础上修订）

| 代号 | 描述 | 0.4 的立场 |
|---|---|---|
| A1 | 被 prompt 注入、只使用文档化接口的 Agent | 防御：拿不到 Secret；写操作需审批；只能访问规则允许的范围 |
| A2 | 同 uid、可执行任意代码的进程 | 防御范围同 v3：拿不到明文，不能扩大规则，不能自行审批。**能做的事**：在已有 allow 规则内发起调用，与 A1 相同；伪造调用方身份 |
| A3 | A2 并且诱导用户确认 | 部分防御：审批面板由 daemon 生成完整内容 |
| A4 | root、内核、物理取证 | 不防 |
| A5 | 上游返回或变换密钥 | 有限遮蔽，沿用 |
| A6 | 浏览器网页（DNS rebinding、跨站请求本机服务） | 防御：§6.3 的 Host、Origin 与自定义头检查 |

**取消本机令牌的安全论证**
- 0.3 的 capability 在同 uid 下无法阻止 A2：A2 可以读取环境变量或进程参数，也可以自行签发会话（v3 §3.2 已经认定这一点）。
- 因此对本机调用方而言，真正的边界一直是"规则 + 审批 + 密钥不出 Rekey"。
- 去掉令牌不会削弱任何已经宣称的保证，只是去掉了一层不起作用的仪式。

### 4.3 调用方识别

**识别方法**
- **CLI 与 MCP**：daemon 取得对端进程的 audit token（macOS）或 pidfd（Linux），沿进程树向上查找，第一个匹配已知 Agent 签名身份或路径的进程即为调用方。
  - 已知 Agent 表：Claude Code、Codex、Cursor、VS Code 系；
  - 匹配依据：代码签名 Team ID 或标识符，未签名时用可执行文件的真实路径；
  - 找不到时标为 `script:<最近的可执行文件名>`。
- **本机服务**：通过 TCP 对端端口查找所属进程。
  - macOS 用 `proc_pidfdinfo` 扫描，Linux 用 `/proc/net/tcp*` 的 inode；
  - 查找失败时标为 `unknown`。
- **SSH agent**：Unix socket 对端，与 CLI 相同。

**用途**
- 审计标注；
- 活动页分组；
- 规则可以按调用方覆盖，例如"codex 对 github 只读"。

**明确限制**
- 同 uid 进程可以伪造调用方：直接 exec 一个已知 Agent 的二进制，或伪造父进程关系。
- 所以按调用方覆盖规则只能**进一步收紧**，不能放宽：调用方匹配不上时，使用默认规则；匹配时取默认结果与覆盖结果中更严格的一个，覆盖不构成身份认证。
- UI 文案必须写明"调用方识别用于记录，不是身份认证"。

---

## 5. 授权模型

### 5.1 规则语法（封闭）

```json
{
  "connection": "github-personal",
  "origin": "https://api.github.com",
  "rules": [
    {"methods": "read",  "path": "/**",                             "effect": "allow"},
    {"methods": "write", "path": "/repos/{owner}/{repo}/issues",     "effect": "approve"},
    {"methods": "write", "path": "/repos/{owner}/{repo}/pulls/*/merge", "effect": "approve"}
  ],
  "bindings": {"owner": ["majiayu000"], "repo": ["rekey", "*"]},
  "caller_overrides": {"codex": [{"methods": "write", "path": "/**", "effect": "deny"}]},
  "limits": {"requests_per_hour": 600, "max_request_bytes": 1048576, "max_response_bytes": 4194304}
}
```

**method 类别**
- `read` = GET、HEAD。
- `write` = POST、PUT、PATCH、DELETE。
- OPTIONS、CONNECT、TRACE 一律拒绝。
- 也可以列出具体方法，例如 `["POST"]`。
- Preset 可以把某些"语义上是读"的 POST 标为 read，例如 GraphQL 查询或 LLM 推理接口。这种标注必须写在 Preset 里，并签名。

**路径模式**
- 段级匹配：
  - `{name}`：命名段，取值受 `bindings` 约束，`*` 表示任意 slug；
  - `*`：恰好一段 slug；
  - `**`：只能出现在末尾，匹配零到多段 slug。
- 每段都必须满足现有 `slug` 规则：`^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`，不能是 `.` 或 `..`。
- 请求路径不做 percent 解码；出现 `%`、`//`、`\`、`;`、非 ASCII、`.`、`..` 段一律拒绝。这是沿用现有渲染器的规则，扩展到通配。
- 查询串：键名必须满足 `[A-Za-z0-9_.-]{1,64}`，值不超过 1KiB。规范化排序后计入请求哈希。如果 Preset 声明了查询键的白名单，就按白名单执行。

**示例说明**：未匹配的写操作由默认拒绝处理，不添加 `write /** deny`；否则 deny 优先会覆盖示例中的两条 approve。显式 deny 用于必须禁止的具体路径。

**判定顺序**
1. `deny` 优先；
2. 调用方覆盖只取更严格的结果；
3. 其余按"最具体匹配"判定：字面段多者优先，`**` 最低；
4. 同等具体时 `approve` 优先于 `allow`；
5. 没有任何匹配则拒绝。

**请求头与正文**
- 调用方只能设置 Preset 允许的请求头。
- 出站传输默认发送公开的 `User-Agent: rekey/<version>`，满足 GitHub 等服务的必需请求头；它不携带调用方身份或凭据。
- OAuth refresh-token 轮换也属于远程副作用：发出前检查同一个生命周期 gate，取消或超时后无法确认结果时记为 indeterminate，不能记成未执行。缓存命中不打开该 gate。
- 普通 HTTP 的最后一次 `send` / `open_stream` 在既有 lifecycle coordinator 内构造并首次 poll，再交给已准入执行持有；lab capability 调用同时验证原预留 permit，Connection 调用继续由其终态审计持有准入许可。Connection gate 已关闭时在等待 coordinator 前拒绝，锁内仍重新检查；已排队后才关闭的竞态继续受绝对期限及原取消/自然 drain 宽限约束。首次交接后保留自然 drain 宽限和原绝对期限。若 OAuth refresh 已发生副作用，后续 handoff 被拒绝或目标传输在发送前失败仍记为 indeterminate。
- 普通 HTTP 或 OAuth refresh 的未知副作用失败保留内部 `UPSTREAM_FAILED` 与安全 message `upstream request failed`，但 `retryable=false`，不得邀请重放；当前 CALL 与 lab unary EXECUTE 的公开信封继续映射为 `UPSTREAM_ERROR`。终态审计等待超过绝对期限不能把已发生的未知副作用重新标为可重试；OAuth refresh 后的 Authority 忙等可重试错误也必须返回不可重试的未知结果。
  未发生远端副作用的 coordinator 截止或地址预检拒绝保留原可重试合同；响应过大与安全策略拒绝保留各自错误。
- 认证类头（`authorization`、`x-api-key`、`cookie`、`proxy-*`、`host`）一律由 Rekey 控制。
- 正文大小受 `limits` 约束；Preset 可以附带 JSON Schema 作为额外校验，不是必需。

### 5.2 Preset

- 现有内置模板（anthropic、openai、glm、glm-responses、github-pat、generic-bearer）改写为 Preset。每个 Preset 提供：
  - origin、注入方式、固定头；
  - 默认规则：读 allow、写 approve、危险写 deny。例如 GitHub 的仓库删除、组织管理默认 deny；
  - **具名操作**：例如 `github.get_issue` 映射到 `GET /repos/{owner}/{repo}/issues/{number}`，并附参数说明，用于 MCP 工具和 `rekey call`；
  - LLM 类连接的模型白名单和 `max_tokens` 上限（沿用 v3 §8.5）。
- `generic-bearer` 和 `generic-header` 让用户为任意 API 建立 Connection：填 origin 和注入方式，默认规则为"读 approve、写 approve"，用户可以放宽。
- 团队自定义 Preset 沿用 `RKTEMPLATE` 签名包，改为 Preset 格式。

### 5.3 签名与激活

- 规则集属于策略。个人模式下由 App 生成规范化草案，展示完整 diff，用 Secure Enclave 签名后激活。现有 `PERSONAL_POLICY_DRAFT` 流程改为输出规则集。
- 团队模式沿用外部 Ed25519。
- 删除"每次安装展开成 N 个 Action 再逐个签名"的流程。内部执行时，daemon 把一次请求规范化成一个临时 Action 视图，以复用渲染器、审批哈希和执行器。这个视图不持久化，不需要签名。

### 5.4 审批

- 沿用 local-presence：daemon 生成审阅正文（含 method、完整 URL、请求头名、正文），绑定 `RKREVIEW` 哈希，只能使用一次。
- 调用方得到结构化的 `APPROVAL_REQUIRED{request_id, expires_at}`，可以等待或取消。CLI 默认等待（`--no-wait` 可关闭），MCP 返回后由 Agent 调用 `await_approval`。
- HTTP Connection 重提只预留一次审批；同一个批准的并发重提不能同时取得预留。`approval.accepted` 与 `execution.started` 在同一 Authority 事务成功后才消费批准并清除审阅正文。忙、小时额度、日预算或 started 提交拒绝释放预留，尚有效批准可重试；已取消、过期、锁定或策略更新清除的批准不得恢复。两种时钟的审批期限也约束实际 started 提交。

### 5.5 时间窗审批（新增）

- 审批面板提供三个选项：
  1. "只这一次"；
  2. "同一规则 30 分钟内放行"；
  3. "同一规则在本次 vault 解锁期内放行"，最长 8 小时。
- 选项 2、3 在内存中登记一条临时 allow：绑定 Connection、规则 ID 和调用方标注。锁定、规则变更或到期即失效，不持久化。
- 时间窗审批只适用于 effect 为 `approve` 的规则，不能用于 `deny`。

### 5.6 预算与限速

- 沿用现有用量账本：
  - LLM 类连接按 token 结算，日预算是软上限（v3 已说明）；
  - 其他连接按请求数限速（`limits.requests_per_hour`）。
- 超额返回 `BUDGET_EXCEEDED`，附带重置时间。
- HTTP Connection 小时请求额度计数成功持久准入（`execution.started`）；并发预留先占额度，准入拒绝归还，已准入后失败仍计数。access/scan 的防滥用尝试限速保持原合同。
- HTTP Connection 固定最多 120 个全局在途执行、每个 Connection 最多 4 个；调用方标注不产生新容量。许可在 started 前取得，随受监管执行及其终态审计提交移交；HTTP/IPC 断开、流式结束或排队终态尚未提交不能提前释放。终态提交失败关闭后续远程副作用准入。Supervisor 的任务数也固定不超过 120，超限使用现有可重试 `AUTHORITY_BUSY`；不增加持久字段或用户配置。
- 继承的账本优化只改变摘要实现、SQL prepare 复用及已认证记录定位，继续完整认证有序历史后解析 context，不新增持久格式或跳过历史。历史规模基准入口保留；旧 debug 测量与 0.3 优化测量均不能作为当前整合头的时延结果。

---

## 6. 调用接口

### 6.1 共同约定

**请求与输出**
- 所有接口共用一个 daemon 内部入口：`CALL(connection, method, path, query, headers, body, dry_run, caller)`。
- 输出统一为 JSON：`{status, headers, body, body_encoding}`，正文为 text 或 base64。

**错误码（写给 Agent 看）**

每个错误都带 `next` 字段，告诉 Agent 下一步该做什么：

| code | 含义 | `next` 示例 |
|---|---|---|
| `NOT_CONFIGURED` | 没有匹配的 Connection | `调用 request_access(provider="stripe", reason=...)；不要向用户索要 Key` |
| `DENIED` | 规则拒绝 | `该操作被规则 "write /** deny" 禁止；如确有需要，调用 request_access 说明理由` |
| `APPROVAL_REQUIRED` | 需要审批 | `已通知用户；调用 await_approval(request_id)` |
| `LOCKED` | vault 已锁定 | `已通知用户解锁；调用 await_unlock() 后重试` |
| `BUDGET_EXCEEDED` | 预算或限速 | `在 <time> 之后重试` |
| `UPSTREAM_ERROR` | 上游非 2xx | 透传状态码和已遮蔽的正文 |
| `RESPONSE_BLOCKED` | 响应里检测到密钥反射 | `该响应包含凭据回显，已拦截；不要重试同一请求` |

**dry-run**：返回规范化后的完整请求（密钥位置显示为 `«rekey:connection»`）和判定结果（allow / approve / deny 及命中的规则），不解密、不发送、不消耗额度。审计记录为 `call.dry_run`。

### 6.2 CLI

```
rekey list [--json]                                   # 能用什么：连接、具名操作、读写判定、等级
rekey describe github.create_issue                    # 参数、示例、命中的规则
rekey call github.create_issue --owner x --repo y --title "..." [--body-file f] [--dry-run] [--no-wait]
rekey http github POST /repos/x/y/issues --json '{"title":"..."}' [--dry-run]
rekey request github --op create_issue --reason "需要提交 bug"   # 访问请求
rekey await <request_id> [--timeout 120]
rekey scan [paths...] [--staged] [--stdin]            # §9
rekey import .env [--dry-run]                         # §7.3
rekey connect claude-code|codex|cursor [--print]      # §6.5
rekey ssh-agent status                                # §8.1
```

- 调用类命令不需要任何令牌，也不需要 vault 密码。
- 管理类命令（`add`、`connection`、`rule`、`import` 的确认步骤）走 App 或隐藏输入，并附 step-up 证明。
- `rekey http` 是通用入口，仍然完全受规则约束。

### 6.3 本机 HTTP 服务（替代 0.3 网关）

**监听**
- 固定 `127.0.0.1:<port>`，默认 `7787`，可配置，写入 `~/.config/rekey/service.json`。
- 只监听 loopback。启动时如果端口已被占用，直接失败并在 App 中报警，不换端口。

**路由**
- 路由格式为 `/c/<connection>/<path>`，规则判定与 §5 一致。

**入站检查（防 A6）**
- `Host` 必须是 `127.0.0.1:<port>` 或 `localhost:<port>`。
- 带 `Origin` 或浏览器 `Sec-Fetch-Site` 的请求一律拒绝。
- 拒绝 CONNECT、Upgrade、绝对 URI，以及同时出现 CL 和 TE 的请求。

**认证头**
- 不要求令牌。
- 必须显式携带公开占位头 `Authorization: Bearer rekey` 或 `x-api-key: rekey`，让跨站网页无法用无头 GET 触发调用。这是固定公开标记，不是凭据或授权令牌。
  - 入站的 `authorization`、`x-api-key` 一律剥除，不转发；
  - 值只允许是占位符 `rekey`；无头或空值拒绝。出现其他值时返回 400 `REAL_KEY_PRESENTED`，提示"不要把真实 Key 交给程序，请用 rekey import"。
  - 同时出现 `x-api-key` 和 `Authorization` 时，两者都必须是占位符。

**其他行为**
- 流式 SSE、遮蔽、预算、错误透传沿用执行器；SDK 的 `x-stainless-*` 与 Node fetch 的 `Accept-Language` / `Sec-Fetch-Mode` 作为传输元数据剥除，不转发或参与授权。Git smart HTTP 可用 `git -c http.extraHeader="Authorization: Bearer rekey" ...` 携带同一公开标记。
- 调用方识别见 §4.3。
- 端口抢占风险：rekeyd 未运行时，同 uid 进程可以先占用端口，收到的只是占位符和请求正文，拿不到任何 Secret。这一点写入威胁模型。

**SDK 用法示例**
```
OPENAI_BASE_URL=http://127.0.0.1:7787/c/openai-personal/v1
OPENAI_API_KEY=rekey
```

### 6.4 MCP（rekey-mcp v3）

- **启动**：由 Agent 按 `.mcp.json` 启动，不需要任何环境变量。启动后连接 daemon 的 agent socket，daemon 识别调用方（rekey-mcp 的上层进程）。
- **daemon 校验**：rekey-mcp 必须是与 daemon 同一 Team ID 签名的二进制，否则按 `script:` 调用方处理，不享受任何调用方覆盖。

**工具列表**
- `list_capabilities()`：输出与 `rekey list --json` 相同。
- `describe(operation)`。
- `call(operation, args, dry_run?)`：通用调用。另外为每个具名操作生成独立工具，例如 `github_create_issue`，参数 schema 来自 Preset。
  - 工具总数超过 40 时，只暴露通用工具，避免占用 Agent 的上下文。
- `http(connection, method, path, query?, headers?, body?, dry_run?)`。
- `request_access(provider|connection, operation?, reason)`。
- `await_access(request_id, timeout_s≤120)`：等待 App 处理访问请求；使用已有 AWAIT_ACCESS IPC，与 CLI `rekey await` 返回相同状态。
- `await_approval(request_id, timeout_s≤120)`、`cancel_approval(request_id)`。
- `await_unlock(timeout_s≤120)`。

**协议与返回**
- 协议版本协商沿用 0.3（2025-06-18、2025-11-25）。
- 结果优先返回文本或 JSON；二进制返回 base64 并附 MIME 类型。
- 每个工具的 description 都写明"此工具不会返回密钥"。

### 6.5 `rekey connect`

在项目目录或用户级写入以下内容，均需展示**改动前后的 diff**并确认，写入前自动备份；沿用 0.3 的 O_NOFOLLOW 和原子写入：

1. **MCP 配置**
   - Claude Code：`.mcp.json`；
   - Codex：`.codex/config.toml` 中的 `mcp_servers.rekey`；
   - Cursor：`.cursor/mcp.json`。
   - 只写 `command`，不写 env，不写令牌。`command` 使用 `rekey-mcp` 的稳定路径，比如 Homebrew 或 pkg 安装的 `/usr/local/bin/rekey-mcp`，避免把开发机上的绝对路径提交进仓库。
2. **Agent 说明书**：在 `AGENTS.md` 或 `CLAUDE.md` 中写入一个带标记的段落，再次执行时替换而不是追加：

```markdown
<!-- rekey:begin -->
## 使用密钥
- 需要调用外部 API、git push 或使用任何凭据时，使用 Rekey：MCP 工具 `list_capabilities` / `call`，或命令 `rekey list` / `rekey call`。
- 不要向用户索要 API Key，不要读取或写入 .env 中的密钥，不要把密钥写进代码。
- 缺少权限或连接时调用 `request_access` 并说明理由；收到 APPROVAL_REQUIRED 时调用 `await_approval`。
- Agent 写的程序使用 `rekey list` 给出的本机服务地址和占位 Key `rekey`。
<!-- rekey:end -->
```

3. **git 钩子（可选）**：`--with-hooks` 安装 pre-commit 钩子（§9.2）。
4. **SSH（可选）**：`--with-ssh` 在 `~/.ssh/config` 写入 `IdentityAgent` 指向 Rekey 的 SSH agent 套接字，只对选定的 host 生效（§8.1）。

### 6.6 插件分发

- 提供 Claude Code 插件 `rekey`，内容包括：
  - MCP 服务器声明；
  - 一个 skill（内容同 §6.5 的说明书，加常见用法示例）；
  - 两个 slash 命令：`/rekey-list`、`/rekey-request`。
- 插件不包含任何密钥或 daemon 二进制，只引用已安装的 `rekey-mcp`；未安装时，skill 提示用户安装。
- Codex 和 Cursor 通过 `rekey connect` 完成同等配置。

---

## 7. 密钥管理（人这一侧）

### 7.1 添加

- App 的"添加 API Key"表单保留：名称 + 粘贴 Key + 选择 Preset，或填 origin 和注入方式。
- 保存后直接进入"规则"步骤，默认规则来自 Preset，只需一次 Touch ID 签名激活。
- CLI：`rekey add <preset>` 打开 App；在 headless Linux 上使用隐藏 TTY 输入。
- **目标**：从打开 App 到 Agent 可以使用，不超过 1 次密码输入加 1 次 Touch ID（vault 已解锁时只需 Touch ID）。

### 7.2 访问请求流程

1. Agent 调用 `request_access`，daemon 生成 Access Request：
   - 记录调用方标注、provider 或 connection、操作、理由，理由最多 500 字符，作为不可信文本展示；
   - 有效期 10 分钟。
2. App 发送系统通知。用户打开后可以：
   - 添加新 Secret 并选择 Preset；
   - 给现有 Connection 增加或放宽规则；
   - 拒绝。

   前两项走 §5.3 的签名流程。
3. 处理完成后，Agent 的 `await` 返回 `GRANTED` 或 `REJECTED`。
4. 防骚扰：同一调用方 1 分钟内最多 3 个请求，超出返回 `RATE_LIMITED`；用户可以在 App 中屏蔽某个调用方的请求。

### 7.3 `.env` 导入

`rekey import .env [--dry-run]`：

1. **识别**
   - 解析 dotenv 格式。
   - 按变量名和值的特征匹配 Preset，例如 `OPENAI_API_KEY`、`sk-`、`ghp_`、`github_pat_`、`AKIA`。识别不出的列为"未知"。
   - CLI 只打印**变量名和识别结果，不打印值**。
2. **确认（在 App 中）**：用户逐项选择导入、跳过或标记为非密钥。值由 daemon 直接读取文件，不经过 CLI 的标准输出。
3. **导入**：每项建立 Secret 和 Connection（规则取 Preset 默认值）。
4. **改写**：原文件备份为 `.env.rekey-backup`，权限 0600，并提示用户删除或确认已加入 `.gitignore`。新 `.env` 写入：
   - LLM 和 HTTP 类：`<X>_BASE_URL=http://127.0.0.1:7787/c/<connection>/...` 和 `<X>_API_KEY=rekey`；
   - 无法代理的项，例如数据库密码：保留原值，并在报告中标注"未迁移：协议不支持代理"，不静默处理。
5. 全程只做一次 step-up（A2）。

### 7.4 OAuth 托管

- **支持方式**：provider-specific Authorization Code。Google、GitHub、Slack 使用 S256 PKCE；Notion REST 使用 client secret 交换，不宣称其支持 PKCE。端点由四个编译期适配器固定，不接受调用方提供的 token URL。
- **首批 Preset**：Google Drive、Gmail、Calendar，GitHub OAuth App、Slack、Notion。Google 原生 client 与 GitHub OAuth App 使用随机 literal-loopback callback；Slack 使用用户已登记的固定 localhost callback；Notion 使用用户已登记的 HTTP loopback callback，若提供方拒绝该 callback 则提示配置错误，不能假装完成授权。
- **client 凭据**：用户自行提供 client_id / client_secret（存为 Secret），0.4 不内置 Rekey 自有 client。Google 原生 client 的 secret 可选；GitHub OAuth App 和 Notion REST 的 secret 必需；Slack public PKCE client 不发送 secret，且只使用 user scopes。
- **签名绑定**：HTTP Connection 增加 `oauth: {provider, client_id, scopes}`。client identity、所需 scope ceiling 与 HTTP 规则一起签名；未知路径不猜 scope。Notion 的 scopes 表示 Developer Portal capability 提示，并不作为 OAuth scope query 发送。
- **token 处理**：refresh token 与 client secret 加密持久；Google/GitHub/Slack access token 仅在 daemon 内存缓存，到期刷新。GitHub 请求 `offline_access`；Slack 必须启用 rotation。Notion REST 没有文档化 expires_in，且 refresh_token 可为 null，因此其 access token 加密持久，并以实际响应决定是否具备刷新能力。旋转 refresh token 必须原子持久后继续使用。网络/5xx 错误保留 grant，返回可重试上游错误；撤销或 invalid_grant 才返回 `NEEDS_REAUTH` 并通知用户。
- **scope 展示**：只从有限具名操作推导 scope，实际 granted scopes 必须满足已签名操作且不扩大 scope ceiling。Google 按 Drive/Gmail/Calendar 的读写 operation 分开；GitHub 私有仓库 OAuth `repo` 本身含写权限，UI 明示“上游权限较宽，由本机规则收紧”；Slack 首批只开放公共频道信息/历史与本人消息写入；Notion 提示 portal capability 和 page picker grants，不能宣称动态推导上游 scope。
- **凭据 purpose**：`oauth-grant` AAD code 14、`aws-static` AAD code 15；常规 HTTP 凭据准备入口拒绝把其 JSON 载荷作为 token 注入，只能使用专用 OAuth/派生路径。
- 上游依据：[Google native OAuth](https://developers.google.com/identity/protocols/oauth2/native-app)、[GitHub OAuth App](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)、[Slack PKCE](https://docs.slack.dev/authentication/using-pkce/)、[Notion REST token](https://developers.notion.com/reference/create-a-token)。

---

## 8. 签名类与派生类能力

### 8.1 SSH agent（T0）

**套接字与密钥**
- daemon 在 `~/.rekey/ssh-agent.sock`（0600）提供标准 SSH agent 协议。
- 支持的请求：`REQUEST_IDENTITIES`、`SIGN_REQUEST`、扩展 `session-bind@openssh.com`。
- 不支持向 agent 添加或删除密钥，也不支持 lock / unlock。
- 密钥类型：Ed25519、ECDSA P-256。macOS 默认在 Secure Enclave 生成不可导出的 P-256 密钥，签名由硬件完成；不支持 Secure Enclave 的平台使用软件加密密钥。用户可显式选择生成或导入软件密钥（A2），作为 Secret 加密保存；导出私钥的功能不存在。

**签名授权记录**
- SSH 授权是 policy7 的必需字段 `ssh_keys`：`SshKeyConnection {name, credential_id, user_public_key, hosts: [{host, host_key, rule_id, effect}], git_signing}`；`host_key` 是 base64 的完整 SSH 公钥 wire blob。
- `user_public_key` 是必填 base64 SSH wire blob，用户签名绑定。身份枚举只读取此公钥，不解密私钥；Authority 签名前验证公私钥配对。
- 注册 host 公钥只匹配验证过签名的 `session-bind`。已登记 host 按其 effect；未登记公钥或缺少绑定时标为 unknown host，进入 approve。匹配显式 deny 的已登记 host 一律拒绝，时间窗不能覆盖 deny。
- `PersonalPolicyDraftMeta.ssh_keys` 是编辑范围：缺失保留现有已认证的 SSH 授权，显式数组完整替换，`[]` 撤销。签名快照始终包含 `ssh_keys`，不读取旧格式。
- SSH 凭据 kind 的 AAD code：11 `ssh-ed25519`、12 `ssh-p256`、13 `ssh-secure-enclave-p256`。硬件载荷只保存不可导出密钥的引用。HTTP 凭据准备入口拒绝这些类型，签名只在 Authority 内完成。

**规则**
- 按目标 host 授权：依据 `session-bind` 提供的目标主机公钥，匹配用户登记的 `known_hosts` 条目。
  - 示例：`github.com` allow，`prod-bastion` approve，其他 deny。
  - 客户端不支持 `session-bind`（OpenSSH < 8.9）时，视为 unknown host，按 approve 处理。
- git 的签名用途（`ssh-keygen -Y sign`、namespace `git`）单独设规则，默认 allow。

**不能区分的内容**
- SSH agent 看不到 push 的是哪个分支。分支级保护应交给 GitHub 的分支保护规则，Rekey 不做任何宣称。

**接入**：`rekey connect --with-ssh` 为选定的 host 写入 `IdentityAgent`。不修改全局 `SSH_AUTH_SOCK`，以免影响用户其他用途。

### 8.2 HTTPS git（T0）

- HTTPS 方式的 git 操作不使用 credential helper（会泄漏 token，见 §0 明确不做）。
- 建议改用 SSH。确实需要 HTTPS 时，可以配置 `url.<base>.insteadOf` 指向本机服务的 git smart-HTTP 转发：`/c/<github-connection>/...`，由 Rekey 注入 token。
- git smart-HTTP 的 `info/refs` 与 `git-upload-pack` 归为 read，`git-receive-pack` 归为 write。

### 8.3 防泄漏用的真实值

daemon 在内存中持有已解锁的 Secret，用于 §9 的精确匹配。匹配变体沿用响应遮蔽：原始、base64 系列、percent、JSON 转义、hex。

### 8.4 短期派生凭证（T1）

**适用范围**：协议必须由客户端持有凭证的工具。

| 工具 | 机制 | 默认有效期 |
|---|---|---|
| AWS CLI / SDK | `~/.aws/config` 中配置 `credential_process = rekey aws-credentials <connection>`，返回 STS `AssumeRole` 临时凭证，并附带用户设定的 session policy | 15 分钟，最长 60 分钟 |
| kubectl | exec credential plugin，返回短期 token（例如 EKS `get-token` 等价实现，或 ServiceAccount TokenRequest） | 15 分钟 |
| GitHub App 安装令牌 | 只有在用户明确选择时，才把 1 小时安装令牌交给 `gh` 等工具 | 60 分钟 |

**约束**
- T1 需要用户在 App 中逐个 Connection 显式开启（A2）。UI 文案为"Agent 进程会拿到一个 X 分钟有效、权限受限的临时凭证"。
- 每次签发都要经过规则判定（读写分级不适用时，按 approve 或 allow 设置），并记录审计 `credential.derived_issued`，包含调用方、有效期和权限摘要。
- 根凭证（例如 AWS 长期 access key、GitHub App 私钥）永远不交出。
- policy7 必需字段 `derived_credentials` 保存独立签名授权：`{name, credential_id, effect, max_ttl_seconds, target}`，与 HTTP/SSH 共用唯一名称。草案字段缺失保留，显式数组完整替换；普通 HTTP 的 T1 grade 不自动授权返回凭据。
- target 只支持三种：AWS AssumeRole 的固定 role ARN/region/session policy；EKS 的固定 cluster ID/region；GitHub App 的固定 installation ID/repository IDs/permission map。Agent 不可覆盖目标、权限或 TTL。AWS 默认 900 秒、上限 3600；EKS 固定 900 秒；GitHub 安装令牌实际 1 小时。交付前检查实际期限与目标，审计只记公共权限摘要和实际到期时间。
- `DERIVE_CREDENTIAL`（agent IPC 16）只收 connection 和可选 approval_request_id。CLI 将 daemon 已格式化的临时响应原样交给 AWS credential_process、kubectl ExecCredential v1 或显式 GitHub token 消费者；不接受根凭据输入。
- 上游依据：[AWS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)、[EKS get-token](https://github.com/aws/aws-cli/blob/develop/awscli/customizations/eks/get_token.py)、[GitHub installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)。

GitHub App 的根载荷为 `github-app-root-v1`（CredentialKind `github-app-installation`）：只保存 client ID、installation ID 与标准 base64 的 RSA PKCS#1 DER 私钥；仓库 / 权限只在签名目标中保存。该源不能用于普通 HTTP 调用。AWS 根载荷为 `aws-static-v1`；EKS 只接受长期 access key，拒绝带 bootstrap session token 的源，避免将该 token 编码后交给 Agent。EKS token 实际期限为 15 分钟，`ExecCredential.expirationTimestamp` 按官方客户端提前 1 分钟刷新；审计记录实际期限。上游实际过期时间超过签名上限时拒绝，并提示检查本机时钟，不静默扩大 TTL。

---

## 9. 防泄漏

### 9.1 `rekey scan`

- **输入**：文件路径、`--staged`（git 暂存区）或 `--stdin`。大小限制：单文件 10MiB，单次总量 100MiB。
- **处理**：CLI 将每个文件作为一帧经 agent socket 发给 daemon（SCAN 单帧正文上限 10MiB）；CLI 一次批次总量不超过 100MiB。daemon 在 Authority 内对完整文件匹配，避免切块漏掉跨块密钥；只返回位置和连接名。
- **输出**：`[{path, line, column, connection}]`，不含匹配内容。
- **vault 锁定时**：返回 `LOCKED`。钩子模式下默认放行并打印警告；`--strict` 时阻止。
- **防止被当作猜测接口**：
  - 只报告完整匹配；
  - 同一系统用户的本机扫描每分钟共享最多 60 次请求；调用方名称只作记录，改名不能得到新额度；
  - 审计记录扫描次数和命中次数，不记录内容。

### 9.2 git pre-commit 钩子

- `rekey connect --with-hooks` 或 `rekey hooks install` 写入 `.git/hooks/pre-commit`；已有钩子时改为串联，不覆盖。
- 钩子执行 `rekey scan --staged`，命中时阻止提交，并提示：

  > "检测到 github-personal 的密钥出现在 src/x.py:12；请改用 rekey call 或本机服务地址"

### 9.3 Agent 输出扫描（可选）

`rekey scan --stdin` 可以接入 Claude Code 的 PostToolUse hook，在工具输出进入 Agent 上下文前检查是否含有密钥。0.4 只提供文档和示例配置，不自动安装。

---

## 10. 审计与活动

- 每次调用记录：
  - 调用方标注、Connection、method 类别、规范化路径（取值替换为占位）；
  - 判定结果和命中的规则 ID；
  - 审批 ID、状态码、字节数、LLM token 数。
- **不记录**：正文、查询值、头的值。
- 新增事件类型：
  - `call.dry_run`
  - `access_request.created` / `.resolved`
  - `ssh.sign`（目标主机公钥指纹、用途）
  - `credential.derived_issued`
  - `scan.performed`（命中数）
  - `oauth.authorized` / `.refreshed` / `.refresh_failed`
- **活动页**：按调用方 × Connection × 读写分组，显示调用数、拒绝数、审批数、token 用量；支持点击查看最近 50 条。

---

## 11. 移除与变更

| 0.3 能力 | 0.4 处理 |
|---|---|
| `rekey run`、`ipc/owner.rs` 进程跟踪、Profile 会话签发（admin 59）、Agent 的 `PROFILE_INVENTORY`（agent 8） | **删除**。属于 lab 需要的部分，移到工作负载身份路径 |
| Agent Profile（`crates/rekey-domain/src/profile.rs`） | **删除**。功能由 Connection 规则 + 调用方覆盖 + 限额取代 |
| capability token（本机） | 本机接口不再接受也不再要求。`EXECUTE_FIXED_HTTP_ACTION` 保留给 lab 的工作负载和远程调用方 |
| 网关 `/p/<instance>/` + `rkc_` 认证 | 改为 §6.3 的本机服务 |
| 模板展开成 N 个 Action + 个人策略草案 | 改为 Preset + 规则集草案 |
| Seatbelt / netns 的 `agent-run` 和 L2 | **个人版移除**（违反原则 1）。代码移入 lab，作为企业版"受管运行环境"的储备 |
| `rekey setup` / `rekey add` 打开 App | 保留 |
| `rekey connect` | 按 §6.5 重写 |
| 0.3 的 T9（退出 5 秒内吊销）、T11（`rekey run` 500 次）验收 | 作废，由 §12 取代 |

**删除原则**：被取代的代码直接删除，不保留兼容开关（沿用"不向后兼容"）。删除行数必须写进每个里程碑的报告。

---

## 12. 验收矩阵

| ID | 内容 | 方法 |
|---|---|---|
| C1 | I1：所有调用方接口都不返回明文 | 遍历 CLI、MCP、本机服务、SSH agent 的全部操作，响应中不得出现 canary 的任何变体 |
| C2 | I9：allow 不打扰 | 连续 500 次 allow 读调用，UI 交互次数为 0 |
| C3 | 规则语法 | 路径注入（`..`、`%2f`、`//`、`\`、`;`、Unicode 同形字、超长）、未声明的查询键、OPTIONS / CONNECT 一律拒绝且不访问上游；判定顺序表驱动测试覆盖 §5.1 全部优先级 |
| C4 | 调用方覆盖只能收紧 | 伪造调用方（exec 已知二进制、伪造父进程）无法得到比默认更宽的判定 |
| C5 | 本机服务的 A6 防护 | Host 为 `evil.com`、带 Origin、DNS rebinding 模拟、真实 Key 进入入站头（400 且不转发） |
| C6 | 访问请求 | 请求 → App 处理 → `await` 返回；限速；屏蔽；10 分钟过期 |
| C7 | 时间窗审批 | 30 分钟窗口内同规则放行，其他规则不放行；锁定或规则变更后立即失效 |
| C8 | `.env` 导入 | CLI 输出中不出现值；备份 0600；无法代理的项明确报告；导入后 SDK 经本机服务调用成功 |
| C9 | 防泄漏 | 暂存区含 canary（原始、base64、JSON 转义）时阻止提交；不返回匹配内容；部分匹配不报告；限速生效 |
| C10 | SSH agent | 用 OpenSSH 客户端 `git push` 到测试仓库成功；未登记 host 进入审批；私钥无法导出；session-bind 缺失时按 approve |
| C11 | OAuth | 合成 IdP（本地）完成 PKCE 授权与刷新；refresh 失败时返回 `NEEDS_REAUTH`；Agent 侧看不到任何 token |
| C12 | T1 | AWS `credential_process` 返回的凭证有效期不超过设定值且附带 session policy（用模拟 STS）；未开启 T1 的 Connection 拒绝；审计标注 |
| C13 | `rekey connect` | 前后 diff 准确、备份、重复执行幂等（标记段替换）、不写入任何令牌或密钥 |
| C14 | 插件 | 安装插件后 Claude Code 能列出 MCP 工具，skill 可用；未安装 rekey 时给出提示 |
| C15 | 真实 Agent | Claude Code 和 Codex 在不经任何包装的情况下完成 U2–U5（合成上游，加一次真实 GitHub 测试仓库） |
| C16 | 体验 | 已安装用户：添加 GitHub PAT 到 Claude Code 首次成功调用，总时长不超过 2 分钟，密码最多 1 次，Touch ID 最多 2 次 |

现有 P0、fuzz、性能门槛全部保留；新增 fuzz 目标：规则路径匹配器、dotenv 解析器、SSH agent 协议解析器。 性能夹具必须使用签名 Connection 和无令牌 CALL，保留生产 KDF、Authority 队列/IPC 容量、500 次审计、4 MiB 密封、备份干扰、锁定/关停和 soak；旧 capability 的每 Session 四 permit 指标随该模型作废，该 UDS 性能夹具测量实际 IPC 请求处理器容量。默认 CI 必须实际执行测试并生成本次报告，不能将 lab 条件下的零测试视为通过。

---

## 13. 企业演进（只定映射）

| 0.4 抽象 | 企业扩展 |
|---|---|
| 本机调用方（无令牌） | 远程调用方使用工作负载身份 + capability（lab 中已有） |
| 调用方标注 | 企业中变为经过认证的工作负载身份，可以用于放宽规则 |
| Connection 规则 + 签名 | 组织策略签名服务分发 |
| 访问请求 | 路由给组织内的审批人（remote Approver） |
| 时间窗审批 | 受组织策略上限约束 |
| T1 派生凭证 | 企业云账号的联邦访问 |
| 移入 lab 的 Seatbelt / netns | 受管运行环境（CI、开发容器） |

---

## 14. 里程碑

每个里程碑结束都必须发布一个可下载的 0.4 预发布版本，并报告新增行数和删除行数。

| 里程碑 | 内容 | 退出条件 |
|---|---|---|
| **M1 调用核心** | Connection + 规则语法 + 判定器；Preset 改写；daemon `CALL` 入口；CLI `list/describe/call/http`；dry-run；错误码与 `next`；调用方识别；删除 run / Profile / 本机 capability；格式 0.4 | C1、C2、C3、C4 |
| **M2 MCP 与服务** | rekey-mcp v3；本机服务（固定端口、占位 Key）；`rekey connect` 重写 + 说明书；插件 | C5、C13、C14、C15 |
| **M3 人在回路** | 访问请求；`await_unlock`；时间窗审批；App 添加 → 规则一步完成；活动页按调用方分组 | C6、C7、C16 |
| **M4 开发卫生** | `.env` 导入；`rekey scan`；pre-commit 钩子 | C8、C9 |
| **M5 SSH** | SSH agent；host 规则；git smart-HTTP 转发 | C10 |
| **M6 OAuth 与 T1** | OAuth 托管与 4 个 Preset；AWS `credential_process`；kubectl exec plugin；GitHub App 令牌 T1 | C11、C12 |
| **M7 发布** | 0.4.0-alpha.1 正式预发布；文档；独立安全核心审查（规则判定器、本机服务、SSH agent、OAuth、scan） | 全部 C 项；公开下载安装验收 |

**实现约束**
- 优先复用现有模块：渲染器、执行器、遮蔽、审批、用量账本、对端身份。
- 新增 IPC 操作码不超过 12 个。
- 每个里程碑的生产代码净增量目标为不超过 3,000 行，测试另计；超出时先在计划里说明原因。
- 不为 lab 功能新增任何东西。

---

## 15. 已采用的决定（推荐值）

| ID | 问题 | 推荐 |
|---|---|---|
| Q1 | 调用方识别失败（`unknown`）时，是按默认规则处理，还是一律 approve | 按默认规则处理。调用方标注本来就不是安全边界，一律 approve 只会制造确认疲劳 |
| Q2 | 本机服务默认端口 7787 是否合适；是否允许多 vault 多端口 | 默认 7787；每个 vault 一个端口，写入 `service.json` |
| Q3 | Preset 中"语义读"的 POST（GraphQL 查询、LLM 推理）默认按 read 允许 | 是。LLM 推理受预算约束；GraphQL 需要按操作类型区分 query 和 mutation（解析失败按 write 处理） |
| Q4 | SSH 默认密钥位置：Secure Enclave 还是软件加密保存 | 默认 Secure Enclave（不可导出，换机需要重新登记公钥）；可选软件密钥便于迁移 |
| Q5 | OAuth 是否内置 Rekey 自己注册的 client | 0.4 不内置，由用户提供；以后再评估 |
| Q6 | 时间窗上限 8 小时是否合适 | 合适；锁定即失效 |

---

## 16. 冻结后需同步修改的基线

- `CLAUDE.md` / `AGENTS.md`：
  - 架构：去掉 run / Profile；加入 Connection 规则、本机服务、SSH agent、scan；
  - 机械合同：新增"本机调用接口不接受 capability，且不存在 get/export"的检查。
- 威胁模型：加入 §4.2 的 A6、调用方识别限制、T1 等级、端口抢占、scan 的猜测风险。
- `feature-truth-matrix.md`：新增 0.4 各行；把 run / Profile / L2 行标为 Removed 或 Lab。
- `README.md`、用户指南：以"添加 Key → `rekey connect` → Agent 照常使用"为主线重写。
- `2026-10-02-rekey-v3-personal-first.md`：在 §8 和 §3.3 开头注明"已被 2026-10-05 Agent 调用模型取代"。
