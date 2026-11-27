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
- 出站请求：公网 IP 钉死、禁止重定向、忽略代理、fake-IP 时仅用 DoH 解析（0.4 须显式 `REKEY_DOH_URL`；0.5 起未设置时回退到 223.5.5.5、1.1.1.1，见 v3 spec I6）。
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
| **Caller（调用方）** | 发起调用的程序：claude-code、codex、cursor、vscode、script:<可执行文件>、unknown。由 daemon 识别，用于标注（§4.3） |
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
- **I4**：客户端对 daemon 的签名校验沿用。新增约束：`rekey-mcp`、SSH agent 套接字和本机服务都由 daemon 自己提供或监听，客户端在向 daemon 发送任何管理证明之前，必须完成校验。L1-dev 提示的时机以 v3 I4 的 2026-11-17 修订为准：交互式 TTY CLI 在发送任何证明前警告；JSON / 管道模式在命令结束时于 stderr 报告 `L1_DEV_UNVERIFIED_SERVICE`（#87 起）。
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

**识别方法**（2026-11-17 修订：按实现写明）
- **CLI、MCP 与 SSH agent**：daemon 从内核取得 Unix socket 对端的 PID（macOS 取完整 audit token，Linux 取 `SO_PEERCRED` 的 PID），沿父进程链向上最多 32 层，第一个命中已知 Agent 表的进程即为调用方。CLI 与 MCP 每个请求帧识别一次，SSH agent 每个连接识别一次。
  - Linux 不使用 pidfd：PID 复用竞争最多让标注出错，而标注从不授权（见下方“明确限制”）。
  - 已知 Agent 表：Claude Code（`claude-code`）、Codex（`codex`）、Cursor（`cursor`）、VS Code 系（`vscode`，含 Insiders 与 VSCodium）。
  - 匹配依据一：可执行文件的真实路径（macOS `proc_pidpath`、Linux `/proc/<pid>/exe`，符号链接已解析）。文件名（`claude`、`codex`、`cursor`、`cursor-agent`、`code`、`code-insiders`、`codium` 等）、路径中的 macOS app bundle（`Codex.app`、`Cursor.app`、`Visual Studio Code.app`、`VSCodium.app` 等）或版本安装目录（`~/.local/share/claude/versions/<版本>`、`~/.local/share/cursor-agent/versions/<版本>/…`）任一命中即可。原生安装的 Claude Code 文件名是版本号，靠安装目录识别；只看文件名不够。
  - 匹配依据二（仅 macOS）：路径未命中时，按 PID 取该进程的代码签名；Team ID 与标识符前缀同时命中表项，并通过 `anchor apple generic and certificate leaf[subject.OU] = "<Team ID>"` 校验，才算命中。表项：`Q6L2SF6YDW` + `com.anthropic.claude-code`；`2DC432GLL2` + `codex`、`com.openai.codex`；`VDXQ22DGB9`（Cursor，任意标识符）；`UBF8T346G9` + `com.microsoft.VSCode`。系统目录（`/System`、`/bin`、`/sbin`、`/usr/bin`、`/usr/sbin`、`/usr/libexec`）和 Rekey 自身二进制不查签名；结果按 (PID, 真实路径) 缓存在内存中，最多 1024 条。
  - Rekey 自身的二进制（`rekey`、`rekey-mcp`）不参与已知 Agent 匹配，也不作为脚本名。找不到已知 Agent 时标为 `script:<第一个非 Rekey 进程的可执行文件名>`；整条链只有 Rekey 自身时用对端自己的文件名。名字中的控制字符替换为 `_`，整个标注不超过 128 字节，保证审计上下文合法。
  - macOS 上未通过“与 daemon 同一 Team ID 签名”校验的对端 `rekey-mcp` 一律标为 `script:rekey-mcp`，不沿父进程继承 Agent 标注（§6.4）；Linux 无签名可校验，按进程链标注。
- **本机服务**：accept 时、读取请求之前，按 TCP 四元组反查持有客户端 socket 的进程，再按上面的进程链规则标注。
  - macOS：`proc_listpids` 列出同 uid 进程，`proc_pidinfo(PROC_PIDLISTFDS)` 与 `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` 找到本地端为对端地址、远端为服务地址的 TCP socket；
  - Linux：在 `/proc/net/tcp` 与 `/proc/net/tcp6`（IPv4 映射地址按 IPv4 比较）中找到该 socket 的 inode，再扫描 `/proc/<pid>/fd`；
  - 只能看到同 uid 进程；其他用户的客户端、客户端已关闭或查找失败时标为 `unknown`。反查在阻塞线程池执行，不阻塞 accept。
- **SSH agent**：Unix socket 对端，与 CLI 相同，不再固定为 `ssh-agent`。

**用途**
- 审计标注；
- 活动页分组；
- 规则可以按调用方覆盖，例如"codex 对 github 只读"；
- 审批归属与时间窗：一次性审批只能由登记它的同一调用方标注等待、取消和消费，时间窗也按调用方标注生效（§5.5）。HTTP 客户端不再共用 `unknown`；同一进程的重试（例如带 `x-rekey-approval-challenge` 头的重放）标注不变。

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
- **（2026-11-17 修订，0.5 开发线）不协商压缩。** 每个出站请求都恰好带一个 `accept-encoding: identity`：Connection HTTP、LLM 流式与非流式、OAuth token 请求（与 Connection 共用出站传输）、T1 派生请求与 lab source 由出站传输统一设置并丢弃其他取值，mTLS 由其一次性客户端设置。调用方、Preset 与签名 Connection 都不能设置 `accept-encoding` / `content-encoding`（禁止头），本机服务剥除入站 `Accept-Encoding`（§6.3）。上游响应只要带非 `identity` 的 `content-encoding`（含多值与非 UTF-8 值）或 `chunked` 以外的 `transfer-encoding`，就在任何正文字节或允许的响应头交给调用方之前拒绝：返回不可重试的 `RESPONSE_SECURITY_VIOLATION`（Agent 侧 `RESPONSE_BLOCKED`），不解压、不重试；终态审计与反射密钥拒绝相同，记 `execution.indeterminate`，缓冲响应的 reason 为 `response-encoding`，流式与 mTLS 沿用各自既有 reason（`text-stream-failed`、`private-execution-failed`）。遮蔽因此始终作用于未压缩的原始字节。只在 daemon 内按固定格式解析、正文不交给调用方的响应（OAuth token、T1 派生凭证、source 读取）收到压缩正文时解析失败，按各自原错误合同拒绝。
- OAuth refresh-token 轮换也属于远程副作用：发出前检查同一个生命周期 gate，取消或超时后无法确认结果时记为 indeterminate，不能记成未执行。缓存命中不打开该 gate。
- 普通 HTTP 的最后一次 `send` / `open_stream` 在既有 lifecycle coordinator 内构造并首次 poll，再交给已准入执行持有；lab capability 调用同时验证原预留 permit，Connection 调用继续由其终态审计持有准入许可。Connection gate 已关闭时在等待 coordinator 前拒绝，锁内仍重新检查；已排队后才关闭的竞态继续受绝对期限及原取消/自然 drain 宽限约束。首次交接后保留自然 drain 宽限和原绝对期限。若 OAuth refresh 已发生副作用，后续 handoff 被拒绝或目标传输在发送前失败仍记为 indeterminate。
- 普通 HTTP 或 OAuth refresh 的未知副作用失败保留内部 `UPSTREAM_FAILED` 与安全 message `upstream request failed`，但 `retryable=false`，不得邀请重放；当前 CALL 与 lab unary EXECUTE 的公开信封继续映射为 `UPSTREAM_ERROR`。终态审计的可重试错误（包括立即返回的 Authority 忙和等待超过绝对期限）不能把已交接的远端副作用重新标为可重试；OAuth refresh 交接后且无法证明未发生副作用时，refresh 或其持久化失败（含不可重试的锁定、epoch 变化及凭据版本冲突）必须返回不可重试的未知结果；provider 明确撤销或拒绝 grant 的既有 `NEEDS_REAUTH` 保留，并只引导重新授权，不重放 refresh；写入失败审计时出现的 Authority 错误不能使用此业务结果。终态审计本身失败仍保留 Authority 的原错误合同。此类信封的 `error.next` 必须要求核对上游结果，禁止自动重试。
  未发生远端副作用的 coordinator 截止或地址预检拒绝（含其终态审计截止）保留原可重试合同。OAuth refresh 的 transport 也必须保留明确的发送前拒绝分类，不能先折叠成普通上游错误再推断副作用；只有明确未发送时恢复该次交接前的副作用状态。目标传输证明未发送时也仅撤销该目标的交接标记，不能抹去此前真实副作用。redirect、timeout、transport 或响应过大的失败仍不能证明未发送。响应过大与安全策略拒绝保留各自错误。
- 认证类头（`authorization`、`x-api-key`、`cookie`、`proxy-*`、`host`）一律由 Rekey 控制。
- 正文大小受 `limits` 约束；Preset 可以附带 JSON Schema 作为额外校验，不是必需。

### 5.2 Preset

- 现有内置模板（anthropic、openai、glm、glm-responses、github-pat、generic-bearer）改写为 Preset。每个 Preset 提供：
  - origin、注入方式、固定头；
  - 默认规则：读 allow、写 approve、危险写 deny。例如 GitHub 的仓库删除、组织管理默认 deny；
  - **具名操作**：例如 `github.get_issue` 映射到 `GET /repos/{owner}/{repo}/issues/{number}`，并附参数说明，用于 MCP 工具和 `rekey call`；
  - LLM 类连接的模型白名单和 `max_tokens` 上限（沿用 v3 §8.5）。
- **新增内置 Preset（2026-10-22 修订，0.5 开发线）**：`deepseek`、`moonshot` / `moonshot-intl`（`api.moonshot.cn` / `api.moonshot.ai`）、`qwen` / `qwen-intl` / `qwen-us` / `qwen-hk`（百炼兼容模式，北京 / 新加坡 / 弗吉尼亚 / 香港的 Dashscope 域名；Key 按地域签发，不能跨地域）、`openrouter`、`gemini`（OpenAI 兼容端点）为 LLM Preset，地域变体共享 `<provider>.chat` / `<provider>.models` 操作名，Bearer 注入，只声明 `POST <base>/chat/completions`（`ReadSemantics::Fixed`）与模型列表 GET（Qwen 为原生 `/api/v1/models`，其余为 `<base>/models`），同样要求签名的模型白名单与预算。LLM Connection 只放行已声明的操作端点，协议表里有但该预设未声明的路径（如 OpenRouter `/api/v1/responses`）不继承 `/**` 规则，直接拒绝。DeepSeek、Gemini 只认 `max_tokens`，请求带 `max_completion_tokens` 时拒绝，缺省时注入 `max_tokens`；OpenRouter、Moonshot、Qwen 文档推荐 `max_completion_tokens`（Qwen 思考模型中只有它限制思维链，`max_tokens` 只限回答），沿用 OpenAI 规则，缺省注入 `max_completion_tokens`。`stripe` 为只读 Preset：固定 `Stripe-Version`，只允许余额、客户（列表与单个）、扣款与 PaymentIntent 列表的 GET，所有写方法 deny；Stripe 写请求要求表单编码，而具名操作只发送 JSON，写操作需另行设计后再开放。内置 Preset 名单以 `rekey_domain::connection::BUILTIN_PRESETS` / `LLM_PRESETS` 为唯一来源，CLI 直接引用；LLM 协议按上游路径在 `rekey_policy::connection_llm_protocol` 一处判定。
- `generic-bearer` 和 `generic-header` 让用户为任意 API 建立 Connection：填 origin 和注入方式，默认规则为"读 approve、写 approve"，用户可以放宽。
- 团队自定义 Preset 沿用 `RKTEMPLATE` 签名包，改为 Preset 格式。

### 5.3 签名与激活

- 规则集属于策略。个人模式下由 App 生成规范化草案，展示完整 diff，用 Secure Enclave 签名后激活。现有 `PERSONAL_POLICY_DRAFT` 流程改为输出规则集。
- **基础模式（2026-10-21 修订，0.5 开发线）**：个人保险库也可以由 `rekey add <preset>` 在命令行一步完成“保存密钥 → 生成预设 Connection → 签名 → 激活”。签名由随包的 `rekey-policy-sign software-key` 用软件 P-256 私钥完成，私钥是状态目录中当前用户 0600 的 `policy-signer-p256.p8`，同用户进程可读，**不是 Secure Enclave**。CLI 本身仍不链接加密库；激活仍需保险库密码（A2），daemon 照常校验签名与信任根。
  - 信任根仍是每个保险库唯一且不可替换：首次 `rekey add` 在未安装信任时安装软件密钥的信任根；已信任 App Secure Enclave 密钥的保险库拒绝软件签名（`TRUST_MISMATCH`），只能用 `--app` 或新建保险库。
  - 安装的信任算法沿用现有 P-256 标签 `secure-enclave-p256`（该标签只描述曲线与签名编码，`signed.rs` 已声明不证明硬件位置），不新增持久格式。命令行输出与指南必须如实说明“软件签名、基础模式”，不得把基础模式称为 Secure Enclave 或 L1 以上。
  - 基础模式可选“记住解锁”：`rekey unlock --remember <期限>`（≤30 天）复用既有记住此电脑授权（`DESKTOP_REMEMBER`），把解封密钥写入状态目录 0600 文件；rekeyd 启动时若文件有效即调用既有 resume 路径解锁，失效或被删除则保持锁定。这同样是软件保护，不是 Secure Enclave。
  - **（2026-11-17 修订）期限先于密码校验。** `--remember` 只接受 1 秒至 30 天（含两端，即 `DESKTOP_REMEMBER` 的 1,000..=2,592,000,000 ms）。CLI 在读取或发送密码之前校验，越界返回 `USAGE`，不发送 `UNLOCK`，保险库保持锁定，也不写记住文件；Worker 仍按同一范围复核。
  - **（2026-10-22 修订）记住解锁只能解锁。** 该文件同用户进程可读，因此 CLI 以 `DESKTOP_REMEMBER {lifetime_ms, unlock_only: true}` 签发“仅解锁”票据：沿用 84 字节布局，magic 为 `RKDSU001`（App 票据仍为 `RKDSK001`），magic 属于 AEAD AAD，不能改写。由仅解锁票据恢复的 PresenceGrant 只用于 resume 解锁，**不能**作为任何 presence 证明（本机审批、明文查看、关机及其他 step-up）。`unlock_only` 缺省为 false，App 行为不变。修订前由 CLI 写下的 `RKDSK001` 文件不迁移、不重解释，仍具 presence 权限；基础模式用户须重新执行 `rekey unlock --remember` 或 `rekey lock --forget-remembered`。
  - LLM 预设必须签署非空的精确模型白名单与每日额度；CLI 交互时询问一次模型，`--stdin-secrets` 时必须给 `--model`，不猜测默认模型。
- 团队模式沿用外部 Ed25519。
- 删除"每次安装展开成 N 个 Action 再逐个签名"的流程。内部执行时，daemon 把一次请求规范化成一个临时 Action 视图，以复用渲染器、审批哈希和执行器。这个视图不持久化，不需要签名。

### 5.4 审批

- 沿用 local-presence：daemon 生成审阅正文（含 method、完整 URL、请求头名、正文），绑定 `RKREVIEW` 哈希，只能使用一次。
- **（2026-10-22 修订）本机审批的证明**：`APPROVAL_LOCAL_APPROVE/REJECT` 的证明体接受 presence（App）或保险库密码（基础模式 CLI：`rekey approval approve|reject ID --review-sha256 H --password`，隐藏输入或 `--password-stdin`）。恢复密钥不接受。审计 reason_code 分别为 `local-presence` 与 `local-password`；密码失败计入既有解锁失败限速。审阅元数据 `record_type` 为 `rekey.approval.local-review.v1`；审阅正文的 `record_type` 在 Connection/SSH/派生路径为 `rekey.approval.local-review.v1`，lab session 路径为 `rekey.approval.review.v1`，CLI 两者都接受，其余拒绝。校验规则定义在 `rekey-domain`，CLI 与 daemon 测试共用。
- 调用方得到结构化的 `APPROVAL_REQUIRED{request_id, expires_at}`，可以等待或取消。CLI 默认等待（`--no-wait` 可关闭），MCP 返回后由 Agent 调用 `await_approval`。
- HTTP Connection 重提只预留一次审批；同一个批准的并发重提不能同时取得预留。`approval.accepted` 与 `execution.started` 在同一 Authority 事务成功后才消费批准并清除审阅正文。忙、小时额度、日预算或 started 提交拒绝释放预留，尚有效批准可重试；已取消、过期、锁定或策略更新清除的批准不得恢复。两种时钟的审批期限也约束实际 started 提交。
- **（2026-11-17 修订，0.5 开发线）批准前的重提**：只适用于 Connection 调用（Agent CALL、CLI、MCP 与 §6.3 本机服务）。同一调用方标注在用户决定前带该审批 ID（`approval_request_id`，或本机服务的 §6.3 请求头）重提同一规范化请求、同一策略时，返回同一 challenge 的 `APPROVAL_REQUIRED`，不执行、不预留；调用方标注、请求哈希或策略不一致时仍按不匹配拒绝。T1 派生路径（§8.4 `DERIVE_CREDENTIAL`）不变：决定前带审批 ID 重提仍按不匹配拒绝（Agent 收到 `DENIED`，消息为 `request denied: approval-request-mismatch`），调用方应先 `await_approval` 再重提；SSH 签名（§8.1）在 daemon 内等待审批，没有带 ID 的重提。审批与调用方标注的绑定不放宽：`await_approval` / `cancel_approval` 只接受与登记该审批的调用方标注相同的调用方（§4.3），本机服务登记的审批同样如此；标注不同（例如终端里的 curl 与 Claude Code 下的 CLI）按不匹配拒绝。

### 5.5 时间窗审批（新增）

- 审批面板提供三个选项：
  1. "只这一次"；
  2. "同一规则 30 分钟内放行"；
  3. "同一规则在自定义时长内放行"：App 中填写 1–480 分钟，最长 8 小时（daemon 只接受 1–28,800 秒）。（2026-11-17 修订：原文“本次 vault 解锁期内”与实现不符；锁定仍使窗口立即失效，见下条。）
- 选项 2、3 在内存中登记一条临时 allow：绑定 Connection、规则 ID 和调用方标注。锁定、规则变更或到期即失效，不持久化。
- 时间窗审批只适用于 effect 为 `approve` 的规则，不能用于 `deny`。
- **（2026-11-17 修订，0.5 开发线）**：窗口键为（策略摘要、Connection、规则 ID、调用方标注）。同一 Connection 上命中另一条 approve 规则的请求不受该窗口覆盖，仍进入审批。成功激活新的策略版本时显式清空全部时间窗，即使新版本的规则内容不变；同一已生效版本的精确重放不清空。新版本经其他路径生效时（例如激活超时后对账发现已生效），首次窗口查找即丢弃其他策略摘要的窗口。待审批的批准仍按 §5.4 绑定策略摘要，策略变化后不能再被批准或消费。

### 5.6 预算与限速

- 沿用现有用量账本：
  - LLM 类连接按 token 结算，日预算是软上限（v3 已说明）；
  - 其他连接按请求数限速（`limits.requests_per_hour`）。
- 超额返回 `BUDGET_EXCEEDED`，附带重置时间。
- HTTP Connection 小时请求额度计数成功持久准入（`execution.started`）；并发预留先占额度，准入拒绝归还，已准入后失败仍计数。access 请求的防滥用尝试限速保持原合同；SCAN 改用按系统用户计的字节额度（§9.1），超出返回 `RATE_LIMITED`。
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
| `RATE_LIMITED` | 防滥用限速：访问请求过于频繁（§7.2）或 SCAN 字节额度用完（§9.1） | 访问请求：`在 <time> UTC 之后再发起访问请求`；SCAN：`在 <time> UTC 之后重试` |
| `INVALID_INPUT` | 参数不合法（具名操作未定义的参数名写在 message 中，通用 `next` 指向 `describe`）；具名操作被多个 Connection 共享而未指定 connection | `传 connection（可选：qwen, qwen-intl）` |
| `UPSTREAM_ERROR` | 上游非 2xx | 透传状态码和已遮蔽的正文 |
| `RESPONSE_BLOCKED` | 响应里检测到密钥反射，或上游返回了无法遮蔽的压缩编码（§5.1） | `该响应包含凭据回显或无法检查的编码，已拦截；不要重试同一请求` |

**dry-run**：返回规范化后的完整请求（密钥位置显示为 `«rekey:connection»`）和判定结果（allow / approve / deny 及命中的规则），不解密、不发送、不消耗额度。审计记录为 `call.dry_run`。（2026-11-17 修订）`headers` 按 Connection 的注入方式列出认证头，值为 `<前缀>«rekey:<connection>»`，例如 `authorization: Bearer «rekey:github»`、`x-api-key: «rekey:anthropic»`；mTLS Connection 没有认证头。`credential_placeholder` 字段保留。占位只出现在预演输出中，不进入请求哈希与审批审阅。

### 6.2 CLI

```
rekey list [--json]                                   # 能用什么：连接、具名操作及各自的读写判定、等级
rekey describe github.create_issue [--connection c]   # 参数、示例、命中的规则
rekey call github.create_issue [--connection c] --owner x --repo y --title "..." [--body-file f] [--dry-run] [--no-wait]
rekey http github POST /repos/x/y/issues --json '{"title":"..."}' [--dry-run]
rekey request github --op github.create_issue --reason "需要提交 bug"           # 按 provider 请求
rekey request --connection github --op github.create_issue --reason "..."      # 按 connection 请求
rekey await <request_id> [--timeout 120]
rekey scan [paths...] [--staged] [--stdin]            # §9
rekey import .env [--dry-run]                         # §7.3
rekey connect claude-code|codex|cursor [--print]      # §6.5
rekey hooks install|uninstall [--project d] [--print] # §9.2
rekey ssh-agent status                                # §8.1
rekey aws-credentials|kubectl-credentials|github-token <connection> [--no-wait] [--approval ID]  # §8.4
```

- 调用类命令不需要任何令牌，也不需要 vault 密码。
- 管理类命令（`add`、`connection`、`rule`、`import` 的确认步骤）走 App 或隐藏输入，并附 step-up 证明。
- `rekey http` 是通用入口，仍然完全受规则约束。
- **（2026-11-17 修订，0.5 开发线）Connection 选择器**：一个具名操作名可以被多个已启用 Connection 共享（同一 Preset 的多个 Connection，或 §5.2 地域变体共享的 `<provider>.chat`）。`describe` 与 `call` 接受可选 `connection`（CLI `--connection`，MCP 参数 `connection`，IPC `DescribeMeta.connection` 与既有 `CallMeta.connection`）。未指定且操作名命中多个已启用 Connection 时返回 `INVALID_INPUT`，`next` 按签名顺序列出这些 Connection 名并要求传 `connection`；指定的 Connection 不存在或未声明该操作时返回 `NOT_CONFIGURED`。`rekey call` 的 `--connection` 与 `--dry-run`、`--no-wait`、`--query`、`--header`、`--body-file`、`--approval` 一样是保留选项，不作为操作参数。
- **（2026-11-17 修订）读写判定与示例**：
  - `list` 中每个 Connection 的 `read` / `write` 保持原义：对根路径 `/` 的判定。新增可选 `decisions`：每个具名操作一项（`operation`、`method_class`、`effect`、`rule_id`），按该操作自身的 method、路径和读语义，以 `describe` 的示例参数经同一判定器求出（有签名绑定的路径参数在 daemon 内部换成绑定值，见下条）。示例参数不满足该操作或 Connection 的约束时省略该项；OAuth scope 不足、不可调用的操作为 `deny` 且无 `rule_id`。GraphQL 操作的示例不是查询文档，因此列出写判定；查询文档在调用时仍按读判定。
  - `describe` 增加可选 `example_args`、`decision` 与 `matched_rule`（该判定命中的签名规则；无规则命中即 deny 时省略）。示例参数只含必填参数（有签名模型白名单时另加 `model`，取第一个允许值；白名单已在 `llm` 中公开），全部按 schema 生成占位：有 `enum` 取第一个值，整数与数字取 `minimum`（默认 1），布尔为 false，数组与对象为空，字符串为参数名的大写（如 `OWNER`、`TITLE`），schema 的 `pattern` 以转义点加字母数字的固定后缀结尾（如 `\.git$`）时补上该后缀，使示例满足 schema（github-git 的 `repo` 为 `REPO.git`）。示例参数从不包含签名绑定值（§6.4 不公开绑定细节）：路径参数有签名绑定时，daemon 只在内部把该参数换成绑定中第一个非 `*` 值来求 `decision` 与 `decisions`，使判定反映签名规则本身，绑定值不出现在任何发现输出中。因此这类操作的判定只代表绑定范围内的值，按占位原样调用可能命中其他规则或被拒绝。示例值不是授权，参数不同时判定可能不同，以 dry-run 为准。
  - 新增字段都是可选字段，不改变已有字段；判定只用于发现，每次调用都在准入时重新判定。
- `rekey list` 的文本输出在每个具名操作后显示其判定，例如 `github.create_issue  write=Approve`。

### 6.3 本机 HTTP 服务（替代 0.3 网关）

**监听**
- 固定 `127.0.0.1:<port>`，默认 `7787`，可配置。端口保存在所选保险库状态目录的 `<state_dir>/service.json`（默认目录下即 `~/.rekey/service.json`；文件不存在时用 7787，daemon 绑定后以 mode 0600 写回实际端口），不使用 `~/.config/rekey`（2026-11-17 修订，与实现一致）。
- 只监听 loopback。启动时如果端口已被占用，直接失败并在 App 中报警，不换端口。`rekeyd` 的失败输出为 `SERVICE_PORT_IN_USE`，并记录被占用的端口和修改 `service.json` 的提示；失败的启动不留下 Unix socket。
- **启动失败记录（2026-11-17 修订）**：持有 serve 锁的启动尝试失败时，`rekeyd` 在该保险库的 state 目录原子写入 `startup-failure.json`（0600，小于 1 KiB）。字段固定为 `code`（稳定错误码）、`message`（IPC 安全的错误文本）、`next`（修复提示或 `null`）、`port`（仅 `SERVICE_PORT_IN_USE` 时为被占用端口，否则 `null`）和 `at_ms`。记录不含密钥、证明或路径，不属于 vault 格式，不进入备份，rekeyd 不回读；本机服务绑定完成即视为启动成功并删除记录。没有 vault 状态的空目录不写记录，以免挡住之后的 `init`；没拿到 serve 锁的实例（例如已有实例在运行）不写也不删；拿锁前的失败（目录权限、命令行参数、`service.json` 解析）不写。`rekeyd.command_failed` 日志在数值 `code`（退出码）之外带字符串 `error_code`。
- **App 报警**：App 连接失败后启动服务（经 SMAppService，或由 App 启动随包服务）时，只读取这份记录，且只采用 `at_ms` 不早于本次启动尝试的记录，不读取 vault。`SERVICE_PORT_IN_USE` 显示被占用的端口、该目录 `service.json` 的完整路径和写入空闲端口的方法，提供“在 Finder 中显示”和“重试”；`UNSUPPORTED_VAULT_LAYOUT` / `UNSUPPORTED_FORMAT_VERSION` 只显示重建引导（v3 §9.3）；其他错误显示错误码和错误文本，可重试。SMAppService 不提供退出状态，App 启动后最多等约 5 秒，期间服务就绪或出现本次记录即结束；没有本次记录时保留原来的连接错误或进程退出输出。App 不修改 `service.json`，不换端口。

**路由**
- 路由格式为 `/c/<connection>/<path>`，规则判定与 §5 一致。

**入站检查（防 A6）**
- `Host` 必须是 `127.0.0.1:<port>` 或 `localhost:<port>`，逐字节比较：解析到回环地址的其他域名（DNS rebinding，即使端口正确）、大小写不同的 `LOCALHOST`、缺端口或端口不同，都返回 400，不访问上游、不写审计。
- 带 `Origin` 或浏览器 `Sec-Fetch-Site` 的请求一律拒绝。
- 拒绝 CONNECT、Upgrade、绝对 URI，以及同时出现 CL 和 TE 的请求。

**认证头**
- 不要求令牌。
- 必须显式携带公开占位头 `Authorization: Bearer rekey` 或 `x-api-key: rekey`，让跨站网页无法用无头 GET 触发调用。这是固定公开标记，不是凭据或授权令牌。
  - 入站的 `authorization`、`x-api-key` 一律剥除，不转发；
  - 值只允许是占位符 `rekey`；无头或空值拒绝。出现其他值时返回 400 `REAL_KEY_PRESENTED`，提示"不要把真实 Key 交给程序，请用 rekey import"。
  - 同时出现 `x-api-key` 和 `Authorization` 时，两者都必须是占位符。

**其他行为**
- 流式 SSE、遮蔽、预算、错误透传沿用执行器；SDK 的 `x-stainless-*` 与 Node fetch 的 `Accept-Language` / `Sec-Fetch-Mode` 作为传输元数据剥除，不转发或参与授权。入站 `Accept-Encoding` 同样剥除，不能改变出站固定的 `accept-encoding: identity`；上游返回压缩响应时本服务回 502 `RESPONSE_BLOCKED`，不转发其正文或响应头（§5.1）。Git smart HTTP 可用 `git -c http.extraHeader="Authorization: Bearer rekey" ...` 携带同一公开标记。
- **请求正文编码（2026-11-17 修订，0.5 开发线）**：`Pragma` 也作为传输元数据剥除。请求 `Content-Encoding` 只接受 `identity`，以及 `github-git` Connection 的单个 `gzip`（git 会自动压缩超过 1 KiB 的 upload-pack 请求）：本服务在规则判定、审批与出站之前解码恰好一个 gzip 成员并校验其 CRC 与长度，解码后正文仍受该 Connection 的 `max_request_bytes` 约束，上游收到的是未压缩正文、不带 `content-encoding`。其他编码、其他 Connection 的压缩请求、重复的 `Content-Encoding`、格式错误或解码超限的正文返回 400（`INVALID_INPUT` / `INVALID_FRAME` / `REQUEST_TOO_LARGE`），不访问上游、不写审计。详见 §8.2。
- 调用方识别见 §4.3。
- 运行状态拒绝先于 Connection 查找，统一返回 503 和 §6.1 的错误 JSON：锁定为 `LOCKED`（不得因锁定清除了生效策略而报 `NOT_CONFIGURED`），容量超限为可重试的 `AUTHORITY_BUSY`，停机中为 `DRAINING`，终态审计失败后为不可重试的 `FAULTED`。403 只表示规则或请求形态被拒绝，使 SDK 不把暂时不可用当成权限错误。
- **审批与重提（2026-11-17 修订，0.5 开发线）**：命中 approve 规则的请求返回 403 和 §6.1 的 `APPROVAL_REQUIRED` JSON，审批 ID 是 `approval.challenge_id`。本机服务登记的审批绑定该 HTTP 调用方的标注（§4.3、§5.4）。CLI/MCP 的 `await_approval` / `cancel_approval` 只有在调用方标注相同时（例如同在 Claude Code 下运行）才能等待或取消它，标注不同按不匹配拒绝；HTTP 客户端无法确认自己与 CLI 同标注，因此 HTTP 错误的 `next` 不提 `await_approval`，而是要求：用户在 App 收件箱（或 `rekey approval approve`）批准后，用相同的方法、路径、查询、请求头与正文重提一次，并加请求头 `x-rekey-approval-challenge: <approval.challenge_id>`。
  - 该头只关联审批，不是凭据或令牌，不参与请求哈希，也不转发上游；值不是合法审批 ID 时返回 400。
  - 用户决定前带头重提返回同一 challenge 的 `APPROVAL_REQUIRED`，不执行；批准只能使用一次，消费后再带头重提返回 403 且不执行；正文或其他请求内容变化时不匹配，返回 403。
  - 不带头的重提从不消费批准：用户决定前复用同一待审批 challenge，批准后则登记新的审批请求。
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
- `describe(operation, connection?)`。
- `call(operation, connection?, args, dry_run?)`：通用调用。另外为每个具名操作生成独立工具，例如 `github_create_issue`，参数 schema 来自 Preset。
  - 工具总数超过 40 时，只暴露通用工具，避免占用 Agent 的上下文。
  - （2026-11-17 修订）`connection` 是 §6.2 的 Connection 选择器。多个 Connection 共享同一操作名时不生成具名工具（不替 Agent 选择 Connection），Agent 用 `describe` / `call` 传 `connection`；未传时的 `INVALID_INPUT` 的 `next` 列出可选的 Connection 名。`list_capabilities` 与 `describe` 的 `decisions`、`example_args`、`decision`、`matched_rule` 同 §6.2。
- `http(connection, method, path, query?, headers?, body?, dry_run?)`。
- `request_access(provider|connection, operation?, reason)`：provider 的解析、限速与屏蔽见 §7.2。
- `await_access(request_id, timeout_s≤120)`：等待 App 处理访问请求；使用已有 AWAIT_ACCESS IPC，与 CLI `rekey await` 返回相同状态。
- `await_approval(request_id, timeout_s≤120)`、`cancel_approval(request_id)`。
- **（2026-10-23 修订）让 Agent 一次调对**：
  - `list_capabilities` 每个 Connection 增加可选 `llm`（签名的模型白名单、max_tokens 与每日额度），响应增加 `policy_expires_at_ms`。`describe(operation)` 增加该 Connection 的签名 `rules`、本调用方的 `caller_rules`（为空时省略）、`limits`、`llm` 与 `policy_expires_at_ms`。有 `llm` 时，具名操作参数 schema 中的 `model` 属性加上 `enum`（等于签名白名单）。这些都是公开的签名规则，不含 credential_id、密钥或绑定细节；（2026-11-17 修订）§6.2 新增的 `decisions`、`example_args`、`decision` 与 `matched_rule` 同样不含绑定值。
  - 审批 ID：`await_approval`/`cancel_approval` 的 `request_id` 参数取 `APPROVAL_REQUIRED` 错误中的 `approval.challenge_id`，不是错误信封顶层的 `request_id`（后者是本次帧的请求 ID）。`next` 文案、MCP 工具描述、插件 skill 与 `rekey connect` 写入的说明都必须这样写。
  - 上游拒绝原因：出站前因目标解析到非公网地址而拒绝时，返回公开错误码 `UPSTREAM_ADDRESS_BLOCKED`（CLI 退出码与 `UPSTREAM_ERROR` 相同），`next` 说明“目标域名解析到了非公网地址，常见原因是本机代理的 fake-IP DNS；Rekey 不会连接非公网地址”。错误中不回显解析到的 IP。其他出站拒绝原因仍为 `UPSTREAM_ERROR`。
  - 插件 skill、`rekey connect` 说明中出现的 MCP 工具名与 `rekey` 子命令，必须由测试核对确实存在。（2026-11-17）反引号中每个形如工具名的小写标识符都要核对，包括 `call`、`describe` 这类不含下划线的词；只有列出的参数名、字段名和占位 Key 可以例外，反引号中的 `rekey <子命令>` 由 CLI 测试核对。
- `await_unlock(timeout_s≤120)`。
- **（2026-11-26 修订）Codex 实测后的引导**：
  - 每个工具带 MCP `annotations`。`list_capabilities`、`describe`、`await_*` 为 `readOnlyHint=true`；`request_access`、`cancel_approval` 只改本机状态（`destructiveHint=false`、`openWorldHint=false`）；`call`、`http` 为可能写入的外部调用。具名工具在方法为 GET/HEAD 或预设声明了读语义时为只读。标注只影响客户端是否追加提示，签名规则与审批仍由 daemon 执行。
  - `request_access` 结果的 `next` 要求 Agent 先告诉用户在等什么；等一次仍未处理就问用户是否继续等，不轮询到过期。`user_hint` 同时写出 App 收件箱与基础模式的 `rekey access list` / `rekey access resolve`（缺 Key 时先 `rekey add`）。
  - 已完成调用的上游状态为 401/403 时，`UPSTREAM_ERROR` 的 `next` 说明保存的 Key 被上游拒绝（无效、过期、吊销或权限不足），请用户在 Rekey 里更换 Key，`request_access` 解决不了；其他非 2xx 状态的 `next` 不变。CLI `rekey call` 与 MCP 使用同一文案。
  - 基础模式 `rekey approval review ID`：stdout 与 stderr 都是终端且未设 `REKEY_OUTPUT=json` 时输出可读摘要（连接、方法与完整地址、请求头、正文、剩余时间及带 `review_sha256` 的批准/拒绝命令）；App 与管道仍得到 daemon 原样字节的 JSON，摘要只用于阅读，批准仍绑定 `review_sha256`。
  - CLI 连接 socket 收到 EPERM（Agent 沙箱，如 Codex Seatbelt 阻止 Unix socket）时仍为 `IPC_UNAVAILABLE`，但 `next` 说明是沙箱拦截、Rekey 可能正常运行，改用 MCP 工具或请用户放开沙箱的 Unix socket；EACCES 等其他错误保持原文案。

**协议与返回**
- 协议版本协商沿用 0.3（2025-06-18、2025-11-25）。
- 结果优先返回文本或 JSON；二进制返回 base64 并附 MIME 类型。
- 每个工具的 description 都写明"此工具不会返回密钥"。

### 6.5 `rekey connect`

在项目目录或用户级写入以下内容，均需展示**改动前后的 diff**并确认，写入前自动备份；沿用 0.3 的 O_NOFOLLOW 和原子写入。diff 不回显已有文件里的值，只标明已有字段或已有的 Rekey 标记段。

**vault 绑定（2026-11-17 修订）**
- 默认 vault（`~/.rekey`，显式写出同一路径也算）：生成的文件不含本机路径。MCP 配置只有 `command`，说明书和 pre-commit 钩子里的命令是不带 `--state-dir` 的 `rekey`；`rekey-mcp` 与 `rekey` 缺省都使用 `~/.rekey`。
- 其他 vault（`--state-dir` 指向别的目录）：MCP 配置写 `args = ["--state-dir", "<绝对路径>"]`，说明书和钩子使用 `rekey --state-dir '<绝对路径>'`（shell 单引号转义），让 Agent 和扫描连到所选 vault 而不是默认 vault。预览对 MCP 配置、说明书，以及位于 Git 目录之外、可能被提交的钩子目录（例如 `core.hooksPath` 指向仓库内目录）中的钩子提示"文件将包含非默认 vault 的绝对路径，不要提交"。
- 更换 vault 后重新执行 `connect`，原绑定整体替换。

1. **MCP 配置**
   - Claude Code：`.mcp.json`；
   - Codex：`.codex/config.toml` 中的 `mcp_servers.rekey`；
   - Cursor：`.cursor/mcp.json`。
   - （2026-11-26 修订）Codex 的 `mcp_servers.rekey` 另写 `default_tools_approval_mode = "approve"`：写操作的审批由 Rekey 执行，Codex 不再对每次 Rekey 工具调用追加提示。Codex 只在受信任项目中读取 `.codex/config.toml`，`connect codex` 写入后的完成提示要说明信任项目，并说明 Codex 沙箱内 `rekey` 命令连不上 daemon、Agent 应使用 MCP 工具。
   - 不写 env，不写令牌。`command` 固定为 `rekey-mcp`，由客户端按 PATH 找到 Homebrew 或 pkg 安装的稳定位置（如 `/usr/local/bin/rekey-mcp`），不写开发机上的二进制绝对路径；`args` 只在非默认 vault 时出现（见上）。预览时若 PATH 找到的 `rekey-mcp` / `rekey` 不是当前 `rekey` 旁边的同名文件（例如旧安装版遮住了源码构建），或 PATH 中找不到它们，预览给出警告并写明 Agent 实际会启动的路径；写入内容不变。
2. **Agent 说明书**：在 `AGENTS.md` 或 `CLAUDE.md` 中写入一个带标记的段落，再次执行时替换而不是追加。下例为默认 vault；非默认 vault 时其中的 `rekey` 带 `--state-dir`：

```markdown
<!-- rekey:begin -->
## 使用密钥
- 需要调用外部 API、git push 或使用任何凭据时，使用 Rekey：MCP 工具 `list_capabilities` / `call`，或命令 `rekey list` / `rekey call`。
- 不要向用户索要 API Key，不要读取或写入 .env 中的密钥，不要把密钥写进代码。
- 沙箱里 `rekey` 命令连不上 Rekey（Operation not permitted）时改用 MCP 工具。
- 缺少权限或连接时调用 `request_access` 并说明理由，先告诉用户在等什么；等一次仍未处理就问用户是否继续等。上游返回 401/403 说明 Key 无效或权限不足，请用户在 Rekey 里更换 Key，不要用 `request_access`。收到 APPROVAL_REQUIRED 时用错误里的 `approval.challenge_id`（不是顶层 `request_id`）调用 `await_approval`，批准后带同一个 ID 重试原请求。
- Agent 写的程序使用 `rekey list` 给出的本机服务地址和占位 Key `rekey`。
<!-- rekey:end -->
```

3. **git 钩子（可选）**：`--with-hooks` 安装 pre-commit 钩子，与 `rekey hooks install` 使用同一写入逻辑（§9.2）。
4. **SSH（可选）**：`--with-ssh` 在 `~/.ssh/config` 写入 `IdentityAgent` 指向 Rekey 的 SSH agent 套接字，只对选定的 host 生效（§8.1）。（2026-11-17 修订）受管段写在文件开头，使所选 host 的 `IdentityAgent` 先被采用（OpenSSH 取第一次出现的值），并以 `Match all` 结束，原文件开头的全局指令（`Include`、`IdentityFile` 等）仍对所有 host 生效。`--ssh-host` 只接受具体主机名，拒绝通配符、否定、逗号和空白。再次执行替换标记段，标记段之外的内容逐字保留。

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

**（2026-11-17 修订，0.5 开发线）请求的解析、状态与审计**
- **输入**：provider 与 connection 恰好给出一个；理由 1–500 字符；operation 可选，是完整的具名操作名（如 `github.list_issues`）。不合法时返回 `INVALID_INPUT`，`next` 说明这些约束。connection 必须是合法的 Connection 名（slug），可以尚不存在。
- **provider 解析**：provider 是内置 Preset 名（`BUILTIN_PRESETS`）、Preset 家族（Preset 名第一个 `-` 之前的部分，例如 `github` → `github-pat`、`github-git`、`github-oauth`；`qwen` → 四个地域变体），或当前签名策略中某个 Connection 的 Preset（含同样的家族规则）。给出 operation 时只保留声明了该操作的 Preset（`github` + `github.list_issues` → `github-oauth`、`github-pat`）。没有候选时返回 `INVALID_INPUT`：未知 provider 的 `next` 列出全部内置 Preset，并提示其他 API 请求 `generic-bearer` 或 `generic-header`、已有 Connection 可直接传 connection；没有候选声明该操作时，`next` 列出这些 Preset 声明的操作。候选 Preset 随请求保存在内存中，管理端访问请求列表增加可选字段 `presets`。App 的“添加连接”按 App 自身的 Preset 顺序预填第一个属于候选的 Preset（`github` + `github.list_issues` 预填 `github-pat`）；没有可用候选时预填 provider 本身（若 App 支持），否则 `generic-bearer`。
- **完成请求**：按 provider 的请求，任一候选 Preset 的已启用 Connection（给出 operation 时还须声明该操作）即可满足；按 connection 的请求要求该名称的已启用 Connection（及所需操作）。否则拒绝完成，批准请求不能绕过签名授权。
- **顺序**：输入与 provider 解析先于屏蔽检查与限速，无效请求不占用额度；被屏蔽的调用方返回 `DENIED`。`RATE_LIMITED` 不可重试，`next` 给出 1 分钟窗口的重置时间（UTC）。窗口按调用方标注计数；标注可以伪造，限速只防骚扰，不是安全边界。
- **状态**：处理前 `await` 返回 `PENDING`；10 分钟内未处理变为 `EXPIRED`（单调时钟或墙钟任一到期即过期，墙钟回拨同样视为过期）。拒绝并屏蔽（`block_caller`）与 App 的“解除屏蔽”都立即生效；屏蔽列表与访问请求一样只在内存中，daemon 重启后清空。
- **审计**：`access_request.created` / `.resolved` / `.block_changed` 只使用既有字段，不新增持久字段。存在生效签名策略时，行绑定该策略的证据（版本、摘要，`resource_type` 为 `connection`，`resource_id` 为目标名，`parameter_hash` 绑定规范化的 provider、connection 与 operation），并带 Connection 审计上下文：`caller` 为调用方标注；`connection` 为请求的 connection 或 provider，单独的屏蔽变更为固定的 `access-requests`；operation 可在请求的 Connection 或候选 Preset 中解析时，`method_class` 与 `normalized_path` 为该操作的读写分类与声明路径模式，否则为 read 与 `/`；`rule_id` 为空。reason_code：created 为 `provider-request` 或 `connection-request`，resolved 为 `granted` 或 `rejected`，block_changed 为 `blocked` 或 `unblocked`；拒绝并屏蔽同时写入 resolved 与 block_changed 两行。created、resolved 与随拒绝写入的 block_changed 以访问请求 ID 为 `request_id`，单独的屏蔽变更使用新的关联 ID。没有生效签名策略时（例如首次使用）没有可绑定的策略证据，这些行只记录事件、reason_code 与 `request_id`，不伪造策略证据；调用方标注不满足审计上下文的格式约束时同样省略上下文。理由文本是不可信输入，从不写入审计。这些行记录的是访问请求，不是 Connection 调用：上下文中的 `connection` 可以是 provider 名或固定的 `access-requests`，与真实 Connection 名共用命名空间；无法解析操作时的 read 与 `/` 只是审计格式要求的占位，不表示读请求。读取审计的一方须按事件类型区分，App 活动页不收录这些行（§10）。

### 7.3 `.env` 导入

`rekey import .env [--dry-run]`：

1. **识别**
   - 解析 dotenv 格式。
   - 按变量名和值的特征匹配 Preset，例如 `OPENAI_API_KEY`、`sk-`、`ghp_`、`github_pat_`。`preset_hint` 只给 App 能加载的 Preset 名，GitHub 为 `github-pat`。
   - 无法代理的项在 `unsupported_protocol` 中标出原因：`aws`（以 `AWS_` 开头、以 `_KEY`、`_TOKEN`、`_SECRET` 或 `_PAT` 结尾的变量名，`AWS_ACCESS_KEY_ID`，或 `AKIA` 开头的值；SigV4 逐请求签名，没有可注入的请求头）、`database`（`DATABASE_URL`、`*_DATABASE_URL`，或 `postgres://`、`postgresql://`、`mysql://`、`mariadb://`、`mongodb://`、`mongodb+srv://`、`redis://`、`rediss://`、`amqp://`、`amqps://` 连接串）、`password`（`PASSWORD`、`*_PASSWORD`、`*_PASSWD`、`*_PASS`、`*_PWD`）。先匹配 Preset，两类都不中的列为"未知"。daemon 拒绝导入或改写 `unsupported_protocol` 项，base URL 变量也不能覆盖它们。
   - CLI 只打印**变量名和识别结果，不打印值**。
2. **确认（在 App 中）**：用户逐项选择导入、跳过或标记为非密钥；无法代理的项只能跳过或标记为非密钥。跳过和非密钥的行都不导入；除非改写把它用作第 4 点的 base URL 变量，都原样保留。回执分开列出：无法代理的标"未迁移：协议不支持代理"，跳过的密钥仍以明文留在文件中，非密钥的只说明已保留，被改写替换的行列为"已替换为本机服务地址"。"非密钥"只是本次导入中的选择，不写入保险库。值由 daemon 直接读取文件，不经过 CLI 的标准输出。
3. **导入**：每项建立 Secret 和 Connection（规则取 Preset 默认值）。签署的是完整策略快照，有效期默认沿用当前已签署策略的有效期（与策略编辑页一致），没有未过期的基线时默认 24 小时；因此导入默认不改变其余已签署 Connection 的有效期。
4. **改写**：原文件备份为 `.env.rekey-backup`，权限 0600，并提示用户删除或确认已加入 `.gitignore`。改写回执带 `backup_git`，由 CLI 判断：备份所在目录或其上级有 `.git` 时运行 `git check-ignore --no-index`（不读取 index），结果为 `ignored` 或 `not-ignored`；不在仓库中为 `no-repository`；git 无法运行、拒绝该仓库或 5 秒内没有结果为 `unknown`。CLI 只运行 PATH 里第一个绝对路径目录下可执行的 `git`；macOS 上它是 `/usr/bin/git`（xcode-select 转发器）时，只有 `xcode-select -p` 选中的开发者目录里有 git 才运行，否则直接为 `unknown`，因为没有开发者工具时转发器会弹出安装对话框并以 1 退出，会被误读成 `not-ignored`。5 秒期限同时覆盖这两步。App 按此提示删除备份，或把它加入 `.gitignore`。新 `.env` 写入：
   - LLM 和 HTTP 类：`<X>_BASE_URL=http://127.0.0.1:7787/c/<connection>/...` 和 `<X>_API_KEY=rekey`，地址用本机服务实际监听的端口和 Preset 的 SDK 路径后缀。App 的默认变量名去掉 `_API_KEY`、`_AUTH_TOKEN`、`_KEY` 或 `_TOKEN` 后缀再加 `_BASE_URL`（`OPENAI_API_KEY` → `OPENAI_BASE_URL`，`ANTHROPIC_AUTH_TOKEN` → `ANTHROPIC_BASE_URL`，即官方 SDK 读取的变量）；没有这些后缀，或该名字已是选中项、无法代理的项、未支持的行或另一项的变量时，用 `<变量名>_BASE_URL`。签署前可以修改。该名字已是文件中跳过或标为非密钥的行（常见的是已有的 `OPENAI_BASE_URL` 或 `ANTHROPIC_BASE_URL`）时，默认仍用它，因为 SDK 读的是它：改写原位替换这一行，原值只留在备份中。App 在审阅中逐行标出这种替换，回执列为"已替换为本机服务地址"，不列为跳过或非密钥；要保留原行就改用其他变量名。不合法或重复的变量名，以及导入的密钥、无法代理的项和未支持的行，都不能作 base URL 变量：daemon 拒绝改写，App 在签署前就不允许这样提交；
   - 无法代理的项，例如数据库密码：保留原值，并在报告中标注"未迁移：协议不支持代理"，不静默处理。
5. **认证复用（2026-11-18 修订）**：同一导入流程共用一个系统认证 context，首次认证后固定复用 10 秒、不滑动（与策略激活相同），写入密钥、签署策略与改写文件在窗口内不再弹窗；审阅签署草案超过 10 秒时再认证一次。不为减少弹窗而放宽复用窗口；实际弹窗次数在真机验收中记录。

### 7.4 OAuth 托管

- **支持方式**：provider-specific Authorization Code。Google、GitHub、Slack 使用 S256 PKCE；Notion REST 使用 client secret 交换，不宣称其支持 PKCE。端点由四个编译期适配器固定，不接受调用方提供的 token URL。
- **首批 Preset**：Google Drive、Gmail、Calendar，GitHub OAuth App、Slack、Notion。Google 原生 client 与 GitHub OAuth App 使用随机 literal-loopback callback；Slack 使用用户已登记的固定 localhost callback；Notion 使用用户已登记的 HTTP loopback callback，若提供方拒绝该 callback 则提示配置错误，不能假装完成授权。
- **client 凭据**：用户自行提供 client_id / client_secret（存为 Secret），0.4 不内置 Rekey 自有 client。Google 原生 client 的 secret 可选；GitHub OAuth App 和 Notion REST 的 secret 必需；Slack public PKCE client 不发送 secret，且只使用 user scopes。
- **签名绑定**：HTTP Connection 增加 `oauth: {provider, client_id, scopes}`。client identity、所需 scope ceiling 与 HTTP 规则一起签名；未知路径不猜 scope。Notion 的 scopes 表示 Developer Portal capability 提示，并不作为 OAuth scope query 发送。
- **token 处理**：refresh token 与 client secret 加密持久；Google/GitHub/Slack access token 仅在 daemon 内存缓存，到期刷新。GitHub 请求 `offline_access`；Slack 必须启用 rotation。Notion REST 没有文档化 expires_in，且 refresh_token 可为 null，因此其 access token 加密持久，并以实际响应决定是否具备刷新能力。旋转 refresh token 必须原子持久后继续使用。网络/5xx 错误保留 grant；refresh 已交接且结果未知时返回不可重试上游错误。provider 明确撤销或 invalid_grant 才返回 `NEEDS_REAUTH` 并通知用户重新授权。daemon 在内存中按凭据记住被拒绝的 grant 版本：同一版本的后续调用直接返回 `NEEDS_REAUTH`，不再把 refresh token 和 client secret 发给 provider，并照常写同一条拒绝审计。浏览器授权回调或 `CREDENTIAL_ROTATE` 写入新版本、撤销使凭据不可用后，这一记忆不再适用；锁定、解锁和策略变更不清除它（其中不含密钥）；daemon 重启后丢失，下一次调用会再向 provider 请求一次。它不新增 vault、策略或审计字段。该拒绝记为 `oauth.refresh_failed`，reason `oauth-needs-reauth`；网络、5xx、超时等其它刷新失败记为 `oauth-refresh-failed`，不提示重新授权。App 活动页读当日（UTC）审计快照：某连接所用凭据最新的 OAuth 记录是这种拒绝、其后没有同一凭据的 `oauth.authorized` / `.refreshed` 时，标出“需重新授权”并提供打开浏览器授权页的入口；刷新失败和浏览器授权失败不会清除这一提示。审计行和页面都不含 token 或 provider 响应。grant 里没有 refresh token 时（从未授权，或 Notion 无刷新能力）返回的 `NEEDS_REAUTH` 不写审计，App 不据此标记。
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
- git 的签名用途（`ssh-keygen -Y sign`、namespace `git`）单独设规则，默认 allow。App 新建 SSH 授权时按此默认填入 allow，签署前可改为 approve 或 deny。

**不能区分的内容**
- SSH agent 看不到 push 的是哪个分支。分支级保护应交给 GitHub 的分支保护规则，Rekey 不做任何宣称。

**接入**：`rekey connect --with-ssh` 为选定的 host 写入 `IdentityAgent`。不修改全局 `SSH_AUTH_SOCK`，以免影响用户其他用途；受管段以 `Match all` 结束，其他 host 的配置不变（§6.5）。

### 8.2 HTTPS git（T0）

- HTTPS 方式的 git 操作不使用 credential helper（会泄漏 token，见 §0 明确不做）。
- 建议改用 SSH。确实需要 HTTPS 时，可以配置 `url.<base>.insteadOf` 指向本机服务的 git smart-HTTP 转发：`/c/<github-connection>/...`，由 Rekey 注入 token。
- git smart-HTTP 的 `info/refs` 与 `git-upload-pack` 归为 read，`git-receive-pack` 归为 write。
- **真实 git 客户端（2026-11-17 修订，0.5 开发线）**：`github-git` Preset 只允许 `content-type`、`accept` 与 `git-protocol` 三个调用方请求头，查询键只有 `service`。本机服务对 git 默认发出的头按以下方式处理：`Authorization: Bearer rekey`（`http.extraHeader`）是公开标记；`User-Agent`、`Accept`、`Accept-Encoding`、`Accept-Language`、`Pragma` 作为传输元数据剥除；`Git-Protocol: version=2` 是签名允许的头，原样转发，使 v2 的 ref-prefix 过滤生效（v0 会通告全部 ref，可能超过响应上限）；`Content-Encoding: gzip` 按 §6.3 解码一次。推送时 git 回退到 v0、不发送 `Git-Protocol`；请求正文超过 `http.postBuffer` 时 git 改用 chunked 传输，本服务照常按 1 MiB 默认上限计数，超限即拒绝，不宣称无限仓库传输。修订前签署的 `github-git` Connection 不含 `git-protocol`，git v2 请求会因未签名请求头在出站前被拒，需要重新签署，或临时以 `git -c protocol.version=0` 使用 v0。
- 验收：真实 git 客户端经本机服务，对注入传输后的合成上游 `git http-backend` 完成 clone（含 gzip 的 upload-pack 请求）、未签名放行时被拒绝的 push、签名放行后的 push 与增量 fetch，并检查上游只收到 `accept-encoding: identity`、Basic 凭据与 upload-pack 上的 `git-protocol`，未收到入站认证头和传输元数据；不含 `git-protocol` 的旧签名 Connection 拒绝 v2、接受 v0。这是合成上游的软件证据，不代替真实 GitHub 仓库验收。

### 8.3 防泄漏用的真实值

vault 解锁后，§9 的扫描在 Authority 内逐次解密生效签名规则引用的凭据并做精确匹配（范围见 §9.1），明文不离开 Authority 线程。匹配变体沿用响应遮蔽：原始、base64 系列、percent、JSON 转义、hex。

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
- **（2026-11-17 修订）T1 入口默认等待本机审批。** `credential_process` 与 exec plugin 的固定命令行传不了 `--approval`，因此 `rekey aws-credentials`、`rekey kubectl-credentials`、`rekey github-token` 与 `rekey call` 语义相同：`DERIVE_CREDENTIAL` 返回带 challenge 的 `APPROVAL_REQUIRED` 时，经 `AWAIT_APPROVAL` 最长等待 120 秒；只有状态为 approved 才用同一 approval ID 重试一次。拒绝（cancelled）、过期、已消费或等待超时都返回原 `APPROVAL_REQUIRED`，不再签发；重试仍被拒绝时直接返回该错误，不再等待第二次。`--no-wait` 保留立即返回；显式 `--approval ID` 直接用该批准签发。stdout 只有 credential_process JSON、ExecCredential 或令牌；进度与错误写 stderr：终端（人类输出）显示等待提示，管道与 `REKEY_OUTPUT=json` 仍只有一行 JSON 错误。不新增 opcode、持久字段或审批类型。
- 上游依据：[AWS AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html)、[EKS get-token](https://github.com/aws/aws-cli/blob/develop/awscli/customizations/eks/get_token.py)、[GitHub installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)。

GitHub App 的根载荷为 `github-app-root-v1`（CredentialKind `github-app-installation`）：只保存 client ID、installation ID 与标准 base64 的 RSA PKCS#1 DER 私钥；仓库 / 权限只在签名目标中保存。该源不能用于普通 HTTP 调用。AWS 根载荷为 `aws-static-v1`；EKS 只接受长期 access key，拒绝带 bootstrap session token 的源，避免将该 token 编码后交给 Agent。EKS token 实际期限为 15 分钟，`ExecCredential.expirationTimestamp` 按官方客户端提前 1 分钟刷新；审计记录实际期限。上游实际过期时间超过签名上限时拒绝，并提示检查本机时钟，不静默扩大 TTL。

---

## 9. 防泄漏

### 9.1 `rekey scan`

- **输入**：文件路径、`--staged`（git 暂存区）或 `--stdin`。`--staged` 扫描暂存区中新增、修改、改名或复制（取目标路径）以及类型变化（例如符号链接换成普通文件）的条目；子模块指针（gitlink，模式 160000）只是一个提交 ID，本仓库里没有它的内容，不作为扫描输入（2026-11-17 修订）。不带参数时扫描当前 Git 仓库里 `git ls-files --cached --others --exclude-standard` 列出的文件，即已跟踪文件加未被 ignore 规则排除的新文件；显式给出的目录递归扫描其中全部普通文件（包括 `.git`、`node_modules`），只跳过符号链接。大小限制：单文件 10MiB，单次总量 100MiB。
- **处理**：CLI 将每个文件作为一帧经 agent socket 发给 daemon（SCAN 单帧正文上限 10MiB）；CLI 一次批次总量不超过 100MiB。daemon 在 Authority 内对完整文件匹配，避免切块漏掉跨块密钥；只返回位置和连接名。
- **扫描范围**：生效签名策略中已启用 Connection、SSH key 与 T1 授权引用的凭据。禁用的 Connection、只导入而未被签署规则引用的凭据不参与。引用的凭据已吊销、不存在或不支持扫描时跳过并计数（SCAN 响应 `unavailable_credentials`），其余照常扫描；解密或完整性失败仍整体失败。
- **输出**：stdout 为 `[{path, line, column, connection}]`，不含匹配内容；有命中时以 `LEAK_DETECTED`（退出码 4）结束。终端模式另在 stderr 逐条打印 §9.2 的中文提示，JSON 模式只输出 JSON。跳过凭据、跳过超限暂存文件和无法扫描的警告写到 stderr：终端模式为中文文本，JSON 模式为一行 `{"warnings":[...],"code","message","next"}`。
- **无法扫描时**：daemon 未运行（`IPC_UNAVAILABLE`）、没有生效的签名策略（未签署或已过期，均为 `NOT_CONFIGURED`）、`LOCKED`、额度用完（`RATE_LIMITED`）。钩子模式（`--staged`）默认打印中文警告并放行，已扫描文件中的命中照样阻止；某个暂存文件超过 10MiB 时只跳过该文件并警告。`--strict` 时这些情况都阻止提交。其它错误（单批超过 100MiB、`FAULTED`、`AUTHORITY_BUSY` 等）一律阻止；非钩子模式按普通错误退出。
- **防止被当作猜测接口**：
  - 只报告完整匹配；
  - 同一系统用户（内核验证的对端 UID）的 SCAN 共享每分钟 600MiB 的字节额度：固定 60 秒窗口，从窗口内第一帧开始计；锁定或没有生效策略时的帧不计入；超出时整帧拒绝且不计入，返回 `RATE_LIMITED`，`next` 给出窗口重置的 UTC 时间。单帧 10MiB、单批 100MiB 上限不变。调用方标注不参与额度，改名或换调用方不能得到新额度。额度只在 daemon 进程内存中，daemon 重启后重新计；
  - 审计记录扫描次数和命中次数，不记录内容。

### 9.2 git pre-commit 钩子

- `rekey connect --with-hooks` 或 `rekey hooks install` 写入 Git 实际使用的 pre-commit 钩子（`git rev-parse --git-path hooks`，含 `core.hooksPath`）；已有钩子时改为串联，不覆盖。与 §6.5 相同：先预览，TTY 确认，写前备份，O_NOFOLLOW 原子发布。
- **串联方式（2026-11-17 修订）**：
  - 没有钩子（或钩子为空、只有一行 `#!/bin/sh`）：写入 Rekey 管理的 `#!/bin/sh` 包装脚本。
  - 可执行的 sh 系文本钩子（shebang 为 sh、bash、dash、ash、ksh、mksh 或 zsh，可经 `env`）：把标记段插在 shebang 之后。扫描先于原内容执行，原钩子以 `exit` 或 `exec` 结束也不会跳过扫描；`$0` 和文件位置不变，依赖 `$0` 的钩子管理器照常工作。
  - 其他钩子（python 等其他解释器、二进制、没有可执行位）：原钩子原样移到同目录的 `pre-commit.rekey-chained`（保留权限位），pre-commit 换成包装脚本。扫描通过后包装脚本以相同参数和标准输入 `exec` 原钩子；原钩子不可执行时不运行，与 Git 忽略它的行为一致。`pre-commit.rekey-chained` 已存在且内容不同，或存在该文件却没有 Rekey 包装脚本时，拒绝写入。
  - 扫描行是 `rekey scan --staged </dev/null || exit $?`（非默认 vault 带 `--state-dir`，见 §6.5）。扫描不读取钩子的标准输入；非零退出阻止提交。
  - 旧版本追加在文件末尾的标记段，重新安装时移到 shebang 之后；若原钩子不是 sh 脚本，则去掉该段后改为串联。
- 再次安装幂等。`rekey hooks uninstall` 撤销安装：插入的标记段被移除，原字节和权限恢复；串联的原钩子从 `pre-commit.rekey-chained` 原子改名回 pre-commit；Rekey 自己创建的钩子直接删除。
- 钩子执行 `rekey scan --staged`，命中时总是阻止提交，终端模式下每条命中提示一行：

  > "检测到 github-personal 的密钥出现在 src/x.py:12；请改用 rekey call 或本机服务地址"

- 无法扫描（§9.1）时默认打印警告并放行，例如"Rekey 保险库已锁定，2 个暂存文件没有做密钥扫描；提交照常进行。"；钩子命令加 `--strict` 后阻止提交。

### 9.3 Agent 输出扫描（可选）

`rekey scan --stdin` 可以接入 Claude Code 的 PostToolUse hook，检查工具输入与输出中是否含有密钥。只提供文档和示例配置（用户指南"防泄漏"一节），不自动安装。PostToolUse 在工具执行后运行：示例命中时用 `updatedToolOutput` 把 Bash 输出替换为占位文本再交给 Claude；其它工具的输出结构不同，示例只附加提示，Claude 仍会看到原输出。`--stdin` 不属于钩子模式：锁定、额度用完或 daemon 未运行时按普通错误退出，示例把这种情况报告为"未扫描"的非阻断 hook 错误。

---

## 10. 审计与活动

- 每次调用记录：
  - 调用方标注、Connection、method 类别、规范化路径（取值替换为占位）；
  - 判定结果和命中的规则 ID；
  - 审批 ID、状态码、LLM token 数。
- **（2026-11-17 修订）** 每次调用的请求 / 响应字节数不再是 0.5 的要求：已发布的 0.4 和 0.5 开发线都不记录这两项，0.5 的审计格式（vault27）已冻结，补字段属于格式变更。需要时须另行规划后续发布线，并先修订本 SPEC。
- **不记录**：正文、查询值、头的值。
- 执行审计的 `request_id` 由 daemon 为每次执行生成。Agent 帧里的 `request_id` 只做传输关联（错误信封回显它），重复使用既不得合并两次执行的审计配对，也不得触发 `one_execution_started_per_request` 唯一约束而使运行时故障。（2026-11-24 修订，0.5 开发线）该执行 ID 返回给调用方，供其在审计中定位：Agent CALL 受理执行后，成功响应元数据（`CallResponseMetadata`，含上游非 2xx）与错误信封各带可选字段 `execution_id`；准入前即被拒的调用不带，`APPROVAL_REQUIRED` 也不带（批准后的重提是新的执行）。本机服务的请求 ID 就是执行 ID：错误信封的 `request_id` 即是，转发上游的响应（含流式）带 `x-rekey-request-id` 头，覆盖上游的同名头。CLI 输出的 JSON 与错误、MCP 的 `structuredContent` 原样给出 `execution_id`。带该 ID 的调用若有审计行，均以它为 `request_id`；在执行器写入 `execution.started` 之前被拒的调用可能没有审计行。两个字段都是可选新增，帧 `request_id` 的含义不变。
- 新增事件类型：
  - `call.dry_run`
  - `access_request.created` / `.resolved` / `.block_changed`（字段与上下文见 §7.2）
  - `ssh.sign`（目标主机公钥指纹、用途）。**（2026-11-17 修订）** 沿用现有 `reason_code` 字段，不改审计格式：`ssh-sign;use=<auth|git|unknown>;host_key=<SHA256:指纹|none>`。指纹是 session-bind 签名已验证的 host 公钥 wire blob 的 SHA-256，按 OpenSSH `SHA256:` 无填充 base64 书写，未登记 host 同样记录；未绑定或仅有未验证 hostbound 名称时为 `none`。用途来自签名载荷：用户认证为 auth，`SSHSIG` git namespace 为 git，其余为 unknown。同一签名的 `execution.started` / `execution.finished` 仍为 `ssh-sign`。
  - `credential.derived_issued`
  - `scan.performed`（命中数）
  - `oauth.authorized` / `.refreshed` / `.refresh_failed`
- **活动页**：按调用方 × Connection × 读写分组，显示调用数、拒绝数、审批数、token 用量；支持点击查看最近 50 条。（2026-11-17 修订）`access_request.*` 行不是调用，即使带 Connection 审计上下文（§7.2）也不进入活动页分组。

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

**删除原则**：被取代的代码直接删除，不保留兼容开关（沿用"不向后兼容"）。删除行数必须写进每个里程碑的报告。（2026-11-17：实际没有按里程碑产出这份报告，所有者已豁免，见 §14。）

**（2026-11-17 修订）默认构建不编入 Profile 会话。** 上表第一行属于 lab 储备的代码保留在 lab，不进默认构建：`ipc/owner.rs`、`ipc/admin/profile.rs`、`runtime/profile/{issue,inventory}.rs`、`session/profile.rs` 及其分派只在 `--features lab` 下编译，默认构建没有运行时开关。默认 daemon 对 admin 58 `PROFILE_GET`、59 `PROFILE_SESSION_CREATE`、12 `SESSION_CREATE`、13 `SESSION_REVOKE` 与 agent 8 `PROFILE_INVENTORY` 一律返回 `INVALID_FRAME`，锁定与解锁状态相同，在取得协调锁、访问 Authority 或写审计之前拒绝。签名 policy8 快照中的 `profiles` 仍按原规则在激活时校验，格式不变。admin 60 自 0.4 起是默认的 Connection 列表（`rekey connection list` 与 App 使用），不是 Profile 接口，继续可用；其常量于 2026-11-19 由历史名 `PROFILE_LIST` 改为 `CONNECTION_LIST`，操作码与线格式不变。

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
| C12 | T1 | AWS `credential_process` 返回的凭证有效期不超过设定值且附带 session policy（用模拟 STS）；未开启 T1 的 Connection 拒绝；审计标注；approve 授权下固定命令行等待本机审批、批准后同 ID 只签发一次，拒绝或 `--no-wait` 不访问 STS（模拟 STS 与合成审批） |
| C13 | `rekey connect` | 前后 diff 准确、备份、重复执行幂等（标记段替换）、不写入任何令牌或密钥；默认 vault 不写本机绝对路径，非默认 vault 在预览中警告；已有 pre-commit 钩子以 exit/exec 结束或不是 sh 脚本时，串联后扫描仍先执行，卸载恢复原钩子；`--with-ssh` 只改变选定 host 的 `IdentityAgent`（2026-11-17） |
| C14 | 插件 | 安装插件后 Claude Code 能列出 MCP 工具，skill 可用；未安装 rekey 时给出提示 |
| C15 | 真实 Agent | Claude Code 和 Codex 在不经任何包装的情况下完成 U2–U5（合成上游，加一次真实 GitHub 测试仓库） |
| C16 | 体验 | 已安装用户：添加 GitHub PAT 到 Claude Code 首次成功调用，总时长不超过 2 分钟，密码最多 1 次，Touch ID 最多 2 次 |

C1 的默认构建回归是 `crates/rekey-broker/tests/c1_canary_sweep.rs`：同一个已激活的签名 Connection 以 canary 为凭据，遍历 CLI（发现、调用、`http`、dry-run、访问请求与等待、`scan`、`ssh-agent status`、`connect --print`、JSON 与面向人的错误）、MCP 工具（含错误与 JSON-RPC 解析错误）、本机服务路由（成功、拒绝、错误）与 SSH agent 身份列表，合成上游以原值、base64/base64url、hex、percent 与 JSON 转义反射 canary；任何输出及其 JSON/percent 解码结果都不得含这些形式，SSH 密钥以已知合成种子导入，种子与私钥字节同样不得出现。（2026-11-19 补充）同文件第二项回归覆盖其余路径，每条路径持有各自的合成根材料，所有形式在所有到达该路径的调用方上都被拒绝：LLM 流式经本机服务（Messages 与 Chat 两种协议；密钥在单个 delta、跨 delta、跨传输分块、在已放出的输出之后到达，以及 base64、unicode 转义、percent、错误状态与响应头反射；同时检查 SDK 拼接后的 delta 文本，被截断的流不得以成功终止帧结束）；T1 经 `rekey aws-credentials`、`kubectl-credentials`、`github-token` 与 agent 套接字（allow、deny、`--no-wait` 审批，AWS 另有经本机审阅与在场决定后的 `--approval` 重试；STS 错误回显根密钥，或把根密钥、其 base64、根 key ID 当作临时值返回，都不得签发；EKS 令牌在本机预签名、不访问上游，按设计携带 access key ID，只拒绝其根 secret；GitHub App 私钥 DER 及其 base64 与交换用的 App JWT 都是根材料，回显它们的错误、把它们当作安装令牌返回，都不得签发；App JWT 每次交换重新签署，回显用的是被应答请求自己的 JWT）；需审批的 SSH 签名（session bind 后的签名在审阅与决定后返回签名或失败）；OAuth Connection 经本机服务、CLI 与 MCP（反射 access、refresh 与 client secret，以及回显 refresh 与 client secret 的 `invalid_grant` 只表现为 `NEEDS_REAUTH`）。在场票据同样不得出现在输出里。Agent 有意收到 T1 临时值，因此只拒绝其根材料；多层编码不在遮蔽范围内（威胁模型 A5）：实测上游把私钥 PEM 再做一次 base64 作为安装令牌返回时会被签发，PEM 原文与单层 base64 则被拒绝；GitHub 本身不持有该私钥。GitHub App 部分与原有 GitHub App 测试一样只在默认构建运行（需要系统 OpenSSL 生成合成 RSA 密钥），lab 接口仍不在这项测试内。

现有 P0、fuzz、性能门槛全部保留；新增 fuzz 目标：规则路径匹配器、dotenv 解析器、SSH agent 协议解析器，另有完整值泄漏扫描 `secret_scan`；每个目标都提交只含合成数据的种子语料（`fuzz/corpus/<target>/`，见 [fuzzing](../../fuzzing.md)）。

发布二进制级 P0 门槛按本模型重写，默认 CI 两个平台都实际运行，只用发布版 `rekey`、`rekeyd`、`rekey-policy-sign`：基础模式软件签名器（`rekey-policy-sign software-key`，0600 文件，不是 Secure Enclave）安装 trust 并签名 Connection，Agent 侧只做无令牌 CALL。证明和凭据只经 stdin 传递，不进 argv、环境变量或日志。允许的调用指向 `https://localhost`：`execution.started` 提交后，生产上游筛查拒绝回环地址，恰好一条 `execution.blocked(private-address)`，不需要网络，也不放宽筛查。`scripts/p0-acceptance.sh` 覆盖 init/serve、错误与正确解锁、凭据增改吊销、trust 安装、签名激活、无令牌发现、dry-run、签名 deny 与默认 deny、allow 调用、密码批准的一次性审批、重签停用、Agent 连接洪泛下锁定解锁、备份重叠拒绝、备份、关停、错误与正确证明的恢复、恢复后的签名 Connection、审计配对和磁盘 canary。`scripts/p0-crash-recovery.sh` 覆盖帧 `request_id` 复用、终态审计被扣住时 SIGKILL 后重启恰好补一条 `execution.indeterminate(abandoned-on-restart)` 且保留授权证据、重启后锁定且签名 Connection 仍生效、空闲时 SIGKILL 不追加终态、待批审批不在重启后复活。公网上游成功调用（`execution.finished`）只在 `REKEY_ACCEPTANCE_PUBLIC_UPSTREAM=1` 时运行，需要联网，默认关闭；上游已收到请求后再 SIGKILL 的场景不在发布二进制门槛内，因为发布二进制按设计拒绝本地夹具，公网上游又不确定。

性能夹具必须使用签名 Connection 和无令牌 CALL，保留生产 KDF、Authority 队列/IPC 容量、500 次审计、4 MiB 密封、备份干扰、锁定/关停和 soak；旧 capability 的每 Session 四 permit 指标随该模型作废，该 UDS 性能夹具测量实际 IPC 请求处理器容量。默认 CI 必须实际执行测试并生成本次报告，不能将 lab 条件下的零测试视为通过。

（2026-11-17 修订）只依赖默认操作码或命令的用例不得放在 lab 门控文件里：真实 socket 上锁定与解锁两态的 A2 `SHUTDOWN` 证明、默认入口拒绝 lab 线协议入口及 §11 所列 Profile/会话操作码（`crates/rekey-broker/tests/default_admin_ipc.rs`），以及 `rollback-confirm` 与离线恢复的 CLI/IPC 端到端（`tests/rollback_cli.rs` 首个用例，按 stderr JSON 信封的 `code` 断言）由默认 `cargo test --workspace` 执行。需要 lab capability 会话的用例留在 lab。

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

**执行记录与豁免（2026-11-17 所有者决定）**：M1–M7 没有分别发布预发布版本（只有汇总的 0.4.0-alpha.1 于 2026-10-08 公开预发布），也没有按里程碑产出生产代码和测试代码的新增 / 删除行数报告。所有者于 2026-11-17 豁免这两项，不追补。因此 §11 的删除行数报告和下方“每个里程碑生产代码净增量不超过 3,000 行”的目标都没有被证明。

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
- 每个里程碑的生产代码净增量目标为不超过 3,000 行，测试另计；超出时先在计划里说明原因。（2026-11-17：没有按里程碑统计，该目标未被证明；行数报告已按本节开头的记录豁免。）
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
