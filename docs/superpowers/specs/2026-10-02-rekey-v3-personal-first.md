# Rekey v3：个人优先的 Agent 密钥执行产品

**状态**：方向已确认，**尚未冻结**。§13 列出的三个 M1 技术验证项完成并记录结果后冻结。2026-10-03 用户已授权并行实现；先交付 V1–V3 独立安全原型。验证结论尚未确定时，不将 L1/A2 安全承诺视为已成立；本文暂不替代现有产品基线。

**修订记录**
- 2026-10-02 初稿。
- 2026-10-02 修订一，依据用户决定：
  - 坚持不向后兼容，GA 之后也不做格式迁移。
  - 先做个人开发者，但企业方向确定要做，因此企业相关能力只"暂缓"，不永久冻结。
  - 删除 XPC 改造和 Secure Enclave UPP 协议。改为在现有 step-up 机制上加 Touch ID 快捷方式，并引入可插拔的 Approver。
  - 写明"Agent 调用默认不打扰用户"。

**基线**：`origin/main` @ `4cdb531`（vault format 21）。分支 `ci/macos-developer-id` 落后 main 4 个提交，本文不以它为依据。

**依据**：§1 所列代码事实均已在 `origin/main` 上核实；推断一律标注【推断】。

---

## 0. 一页摘要

**产品一句话**

> 开发者把 API Key 交给 Rekey 后，就可以放心让 Claude Code / Codex / Cursor 使用。Agent 能用，但拿不走；能做什么由你事先划定；越界或不可逆的动作才需要你确认。

**交互原则：人只在两个时刻出现**

1. 划定范围时：创建 Agent Profile、选择模板能力。
2. 越过范围或执行不可逆动作时：审批。

授权范围内的 Agent 调用**永远不弹窗**。用户每天通常只需确认 0–2 次：开机后解锁一次，偶尔查看明文或修改授权。

**v3 不变的部分**（经审查是扎实的，见 §1.2）
- 加密层级：Argon2id → VRK → DEK → payload，84 字节 AAD。
- 单个 Authority Worker 独占数据库和密钥。
- 固定 Action、capability token、默认拒绝、出站 IP 钉死、响应遮蔽。
- 现有的 step-up 证明和审批（审批绑定参数哈希、只能用一次）。

**v3 改变的五件事**

1. **补洞**：修补同用户恶意代码的三条攻击路径。
   - 查看明文必须重新验证。
   - 钥匙串里的那一项要求用户在场。
   - `SHUTDOWN` 必须带证明。
   - 客户端校验 daemon 的代码签名。
   - 签名的 daemon 启用 hardened runtime。
   - 不改造 IPC 通道。
2. **个人模式免外部签名器**：策略签名密钥放在 Secure Enclave，在 App 内勾选模板，然后按 Touch ID 激活。
3. **Provider 模板代替手写 JSON**：允许使用受约束的路径参数和查询参数。
4. **`rekey run` 和本机 LLM 网关**：SDK 通过 base URL 接入；Agent 拿到的"API Key"实际是 capability。
5. **可插拔的 Approver，加上范围收缩**：
   - 先做本机 Touch ID 审批人；企业阶段再加远程审批人和身份提供方，策略写法不变。
   - 企业相关代码移入 `lab`，不进入默认构建，企业阶段再启用。

**成功标准**
- 新用户从安装到"Claude Code 通过 Rekey 调用 Anthropic 和 GitHub"：不超过 5 分钟、3 条命令、0 个手写 JSON。
- 每条安全承诺都有对应的攻击测试（§10）。

---

## 1. 背景：现状与证据

### 1.1 规模（`origin/main` @ `4cdb531`）

| 指标 | 数值 |
|---|---|
| Rust 源码 | 约 10.3 万行（broker 5.3 万、vault 2.3 万、cli 9.2k、policy 7.9k、approval-relay 4.8k、domain 3.9k、connector 1.5k） |
| 其他代码 | Swift 1.8k 行；Python 脚本 8.9k 行 |
| 文档 | 1.87 万行；66 份 spec |
| Vault 格式 | v21，旧状态一律拒绝 |
| 公开发布 | 仅 `v2.0.0-alpha.2`（format v9，只有 CLI，不含 Rekey.app） |
| 最近一个月 | 仅 #59 一个提交就新增 5.4 万行 |

结论：**功能面的增长远快于交付面**。用户能下载到的版本，比开发中的格式落后 12 个版本。

### 1.2 保留：已审查的强项（均在源码中核实）

- **加密**
  - Argon2id 参数 64MiB/3/4，有上限。
  - 随机 96 位 nonce，调用方无法指定。
  - 84 字节 AAD 绑定 vault、对象、版本和用途。
  - 密钥类型不可 Clone，Debug 输出脱敏，用后清零。
- **存储**：SQLite 文件 0600、`secure_delete`、`trusted_schema=OFF`，并校验符号链接和属主。
- **Capability**
  - 32 字节 OsRng 生成，只存 SHA-256，常量时间比较。
  - 绑定 `action@version`；TTL 不超过 24 小时；先预占次数再执行。
- **出站请求**
  - 全部解析结果必须是公网地址，并把连接钉在解析出的 IP 上。
  - 禁止重定向，忽略代理环境变量，筛查 IPv6 中内嵌的 IPv4 地址。
  - 响应超过上限直接失败。
- **策略**：默认拒绝，forbid 优先；审批绑定 JCS 参数哈希，只能使用一次。
- **隔离**
  - Linux：`linux-netns-v1`。
  - macOS：实验性的 `macos-seatbelt-v1`。
- **签名构建**：`scripts/build-macos-ui.sh` 已使用 `--options runtime`（hardened runtime）。

### 1.3 必须修复的安全问题（`origin/main` 中仍然存在）

| # | 问题 | 证据 | 影响 |
|---|---|---|---|
| S1 | admin.sock 只检查对端 uid 是否等于自身 uid | `runtime/connections.rs:118-122` | 同一用户下，Agent 和管理员无法区分 |
| S2 | `LOCK` 不需要证明；锁定后 `SHUTDOWN` 也可以不带证明 | `ipc/admin.rs:816-830` | 【推断】Agent 可以先锁定再关停 daemon，然后抢先绑定一个假的 admin.sock，截获用户下一次输入的主密码。客户端无法认证服务端 |
| S3 | 7 天免密授权的 key 存入登录钥匙串时，没有设置 `SecAccessControl`，也不要求用户在场 | `apps/macos/Model.swift:25-37` | 7 天内，只要拿到这一项，就能 `desktop-resume` 再 `desktop-reveal`，得到全部明文 |
| S4 | 数据库和备份都没有单调递增的代数 | `authority/backup.rs`；store 中没有 generation 字段 | 整库回滚会让已撤销的凭据和旧密码重新生效 |
| S5 | 遮蔽只覆盖有限的几种编码 | `executor/sealing.rs` | 缺 JSON `\uXXXX`、hex、非对齐 base64；【推断】允许 `accept-encoding` 时，gzip 压缩的内容不会被扫描 |
| S6 | 没有 `RLIMIT_CORE`、`PR_SET_DUMPABLE`、mlock | 全仓库搜索无结果 | Linux 上若 `ptrace_scope=0`，同用户进程可以读取 daemon 内存 |

### 1.4 必须修复的体验问题

- **接入成本过高**：首次接入需要 11–13 条命令、约 5 个手写 JSON、4–5 次输入密码，涉及约 12 个概念。外部签名器只有一个依赖 Homebrew openssl@3 的源码脚本。
- **Action 粒度太细**：每个 Action 只能是一个固定的 path，不允许查询串，于是"使用 GitHub API"会变成 N 个 Action。
- **LLM SDK 无法接入**：main 上的 NET-07 只提供专用的 Anthropic 纯文本流，不支持 tools 和 thinking，SDK 无法通过 base URL 接入。
- **`rekey-mcp` 不可用**：没有进入发布包，只验证过 Codex，返回 base64 正文。

### 1.5 市场事实（2026-10 调研，来源见附录 A）

- **已经商品化**：
  - 占位符换真 key 的代理：Infisical Agent Vault、OneCLI、Anthropic Managed Agents vaults、AWS AgentCore、Tailscale Aperture。
  - OAuth token 托管：Arcade、Composio。
  - 企业 Agent 身份：Entra Agent ID、Okta XAA / ID-JAG。
- **仍有空位**：
  - 固定动作加参数级授权，而不是按 host 放行。
  - 不依赖 MITM 证书的本机信任模型。
  - 绑定参数的人工审批。
  - 作为 MCP 授权和 RFC 8693 落地点的本机组件。

---

## 2. 产品定义

### 2.1 目标用户与阶段

| 阶段 | 用户 | 本文是否覆盖 |
|---|---|---|
| v3（本文） | **个人开发者**：macOS 上的 Claude Code / Codex / Cursor 用户，持有 LLM Key、GitHub PAT 和若干 SaaS Key | 是 |
| v3.x | 小团队：共享模板，Linux CI runner 上的 Agent | 只预留接口 |
| v4 | **企业**：远程审批、组织身份、集中策略分发、审计投递 | 只规定演进路径（§12），不实现 |

企业方向是确定的。因此 v3 的每个核心抽象都必须能原样延伸到企业阶段，详见 §12 的映射表；不允许为个人模式设计企业阶段必须推翻的机制。

### 2.2 核心任务

> 让 Agent 用我的 Key 做我允许的事；Key 永远不进入 Agent 的进程、上下文、日志或文件；越界的事交由审批人决定（个人阶段的审批人就是我自己）。

### 2.3 定位

**Rekey 不是：**
- 密码管理器：不做浏览器填充、家庭共享、手机同步。
- 通用 Secret Manager：不和 Vault / Infisical 比存储能力。
- MITM 代理：不安装系统 CA。

**Rekey 是：**
- 本机（以及将来每台主机上）的"Agent 动作授权 + 凭据执行"数据面。

### 2.4 v3 非目标

- Windows。
- 任意 HTTP 代理或 TCP 透传。
- 自动生成"允许一切"的策略。
- 由 LLM 做授权决定。
- 旧格式迁移（永久不做，见 §9.3）。
- 多租户、SSO/SCIM、HA、远程控制面、SIEM/WORM：属于 v4，v3 不实现，但不得堵死演进路径。

---

## 3. 安全合同

### 3.1 资产

- 凭据明文。
- VRK / DEK。
- 主密码与恢复密钥。
- 7 天授权密钥 K。
- 策略签名私钥。
- 审计完整性。

### 3.2 威胁参与者

| 代号 | 描述 | v3 是否防御 |
|---|---|---|
| A1 | 被 prompt 注入、只能调用文档化 Agent 接口的 Agent | 是，所有等级 |
| A2 | 与用户同 uid、可执行任意代码的进程，无 root，也无用户的物理在场 | 是。仅限 L1，即 macOS 签名安装，见 §3.3 |
| A3 | A2，并且诱导用户点击确认 | 部分：确认界面由 daemon 根据规范请求生成（§6.4），但无法完全防御 |
| A4 | root、内核漏洞、物理取证、恶意管理员 | 否 |
| A5 | 已授权的上游自己返回或变换密钥 | 部分：遮蔽有限几种编码，变换后的形式不防 |

A2 针对的是"拿到明文或扩大权限"。A2 能做的事被限定为两类：
- 锁定 vault；
- 在已有 Profile 范围内签发 capability，这与 Agent 本身已有的权限等价。

### 3.3 保护等级（产品界面必须展示当前等级）

| 等级 | 条件 | 可以对外宣称 |
|---|---|---|
| L0 Stored | 只保存，不交给 Agent 使用 | "Key 已加密保存" |
| L1-dev | 未签名的源码构建，或 Linux 用户级安装 | 只对 A1 成立："Agent 接口拿不到 Key" |
| L1 | 签名、启用 hardened runtime 的 rekeyd 和 Rekey.app；满足 §6 的服务端校验 | 对 A1、A2 成立："Agent 进程拿不到 Key 明文；越权需要审批" |
| L2 | L1 加上 `rekey run --isolate`（Seatbelt / netns），并配置 `deny-other-egress` | 在 L1 基础上，Agent 无法绕过 Rekey 访问网络和受保护文件 |

现有 G1 对应 L1-dev，现有 G2（Linux reference）对应 L2。

### 3.4 不变量（每条都对应 §10 的攻击测试）

- **I1**：Agent 接口（agent.sock、网关、MCP）没有任何返回凭据明文的操作。
- **I2**：凭据只在 Authority 内部解密，且必须在授权和 `execution.started` 审计提交之后；每个请求只解密一次，用后清零。
- **I3**：以下操作每次都需要 step-up 证明（§6.2 的 A2 级）：查看明文、修改授权范围、激活策略、签发 7 天授权、备份导出与恢复、修改密码、VRK 轮换、`SHUTDOWN`。
  - 证明形式是密码、恢复密钥或 presence key 三者之一。
  - 唯一例外是 `LOCK`，任何人都可以锁定。
- **I4**：客户端发送密码或 presence key 之前，必须确认对端是签名的 rekeyd。L1-dev 下无法确认，界面必须提示。
- **I5**：秘密不进入 argv、env、日志、审计或 JSON 元数据。capability 进入 `rekey run` 子进程的 env 是例外，见 §8.2。
- **I6**：出站请求只能去往 Action 或模板声明的 origin；解析结果必须是公网 IP，连接钉在该 IP 上，禁止重定向。
- **I7**：未知状态、审计写入失败、策略错误一律拒绝（fail closed）。
- **I8**：Vault 状态带单调代数。回滚到更旧的代数会被检测到，并拒绝自动解锁（§5.4）。
- **I9**：授权范围内的 Agent 调用不触发任何人工交互；只有策略中的 `require-approval` 规则会进入审批（§6.3）。

---

## 4. 目标架构

```
                     用户（Touch ID / 密码）
                              │
                     ┌────────▼────────┐  签名 + hardened runtime
                     │    Rekey.app    │  presence key 只由它读取
                     └────────┬────────┘
                              │ admin.sock（Unix socket，0600）
   rekey CLI ─────────────────┤ 客户端连接后校验对端代码签名（§6.5）
  （签名构建同样校验）        ▼
                  ┌───────────────────────┐  launchd / systemd user
                  │        rekeyd         │  签名 + hardened runtime
                  │  Authority Worker     │  VRK 只存在于此进程
                  │  Policy + Approver    │
                  │  Executor / Sealer    │
                  └───┬─────────────┬─────┘
          agent.sock  │             │  127.0.0.1:<port> 网关（§8.5）
       （MCP / CLI）  │             │  以 capability 作为 x-api-key / Bearer
                      ▼             ▼
       Agent（Claude Code / Codex / Cursor，可运行在 rekey run 的沙箱内）
```

与初稿的区别：**不引入 XPC**。两个 Unix socket 和现有的 IPC 帧格式保持不变。新增的只有三样：
- 客户端对服务端的签名校验；
- presence key 证明类型；
- 网关。

---

## 5. 模块规格：Vault 与密钥

### 5.1 不变的部分

格式层级、AAD、KDF 参数、Authority 单所有者、VRK/DEK 轮换（main 已实现）。

### 5.2 Presence key（修复 S3，替代 2026-09-15 的 7 天授权合同）

**生成与存储**
- 现有 7 天授权的随机 256 位密钥 K，重新定义为 **presence key**。
- K 存入数据保护钥匙串，属性如下：
  - `kSecUseDataProtectionKeychain = true`
  - `kSecAttrAccessGroup = <TeamID>.com.rekey`
  - `SecAccessControlCreateWithFlags(kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence)`
- 结果：**每次读取 K 都由系统要求 Touch ID**，指纹不可用时回退到 macOS 登录密码。Rekey 不需要自己实现在场验证协议。

**K 的两种用途**
1. 开机或重启后恢复解锁：沿用现有 `desktop-resume`，读取 K 时按一次 Touch ID。
2. 作为 step-up 证明，新增 proof kind `presence`。
   - daemon 在签发或恢复授权时，在内存中保存 `SHA-256(K)`。
   - 收到证明后做常量时间比较。
   - 授权到期或被撤销后，此类证明立即失效，回退到密码。

**有效期与撤销**
- 有效期仍为签发后固定 7 天，不续期。
- 撤销条件不变：手动锁定、空闲锁定、修改密码、恢复密钥轮换、故障。

**连续操作**
- App 使用 `LAContext.touchIDAuthenticationAllowableReuseDuration = 10s`，避免连续几个操作重复按指纹。
- 复用时长不超过 10 秒。

**桌面令牌的权限收缩**
- 删除"持有 desktop token 即可查看明文"的能力。
- `desktop-reveal` 改为每次都必须带 step-up 证明（I3）。

**M1 验证项 V1（必须通过）**
- 一个同用户的未签名进程，对该钥匙串项调用 `SecItemCopyMatching`，必须失败或触发系统认证弹窗。
- 如果不满足，L1 的 A2 承诺不成立，本节需要重新设计。

### 5.3 管理会话

解锁后签发的内存管理会话只允许 A0 和 A1 级操作（§6.2）。

### 5.4 回滚检测（I8）

**计数与校验**
- Vault header 增加 `generation: u64`。凭据、策略、包装层的每次变更提交都加 1。
- 用 VRK 派生的 MAC 绑定 generation。
- `max_seen_generation` 同时记录在钥匙串（Team ID 访问组；只存计数，不存秘密）和 `state/generation` 文件中。

**回滚处理**
- 解锁时如果 `db.generation < max_seen_generation`，进入 `ROLLBACK_SUSPECTED` 状态：
  - 拒绝自动解锁，拒绝执行 Action；
  - 用户用 step-up 证明确认"我在恢复旧备份"之后才重置。
- 备份恢复走同一条确认路径。

**防护边界**：这是 L1 级别的防护。同用户进程可以改文件，但无法改钥匙串里那份计数。

### 5.5 内存加固（修复 S6）

- **Linux**
  - `prctl(PR_SET_DUMPABLE, 0)`、`setrlimit(RLIMIT_CORE, 0)`。
  - 对 VRK/DEK 缓冲区 `mlock`；失败只告警，不阻塞。
- **macOS**：依赖 hardened runtime，并设置 `RLIMIT_CORE=0`。
- **明文查看响应**：改用 `Zeroizing<Vec<u8>>`，替换 `ipc/admin.rs` 中的 `to_vec()`。

**M1 验证项 V2（必须通过）**
- 在签名、启用 hardened runtime 的 rekeyd 上，同用户进程执行 `task_for_pid` 或 `lldb -p` 必须失败。
- 需要同时记录未签名构建作为对照组的结果。

---

## 6. 模块规格：人工确认、Approver 与管理通道

### 6.1 原则

- 授权范围内的 Agent 调用**不弹窗**（I9）。
- 人工确认分两类，二者使用不同机制，不得混用：
  - **管理确认**：管理员修改系统本身，走 step-up（§6.2）。
  - **审批**：Agent 越过常规范围，执行策略标注为 `require-approval` 的动作，走 Approver（§6.3）。

### 6.2 管理操作分级

| 级别 | 操作 | 要求 |
|---|---|---|
| A0 | `LOCK`、status、元数据列表、审计查询 | 同 uid（Linux），或已通过服务端校验的客户端 |
| A1 | 添加凭据（只写不读）；在已激活的 Profile 内签发会话 | 管理会话 |
| A2 | 查看/复制明文、增删改 Action/模板/Profile、激活策略、安装信任根、签发 7 天授权、备份导出/恢复、改密码、VRK 轮换、`SHUTDOWN` | 每次都需要 step-up 证明：`password`、`recovery` 或 `presence`（§5.2） |

**修复 S2**：`SHUTDOWN` 在任何状态下都属于 A2。

**CLI 的密码输入**
- 保留通过 TTY 隐藏输入和 `--password-stdin` 两种方式。
- 签名构建在发送密码之前必须完成 §6.5 的服务端校验。

### 6.3 Approver 抽象

审批的规则与绑定方式保持现状：一个审批请求即一个 challenge，绑定 principal、Action、资源、规范参数哈希、策略摘要和过期时间，并且只能使用一次。

v3 只把"由谁批准"抽象出来。策略规则增加 `approver` 字段：

```json
{"effect": "require-approval", "approver": {"kind": "local-presence"}}
{"effect": "require-approval", "approver": {"kind": "ed25519", "keys": ["<approver public key>"], "threshold": 2}}
```

| kind | 阶段 | 批准方式 |
|---|---|---|
| `local-presence` | **v3 新增** | Rekey.app 收到待审批事项后发出系统通知。用户打开审批面板，核对 daemon 生成的内容，然后按 Touch ID，由 App 发送 presence 证明。daemon 收到后为该 challenge 签发一个本地授权（grant）。不支持 `threshold > 1` |
| `ed25519` | 现有 | 外部审批人签发 grant，沿用现有的单人/双人审批和时间窗 |
| `remote` | v4 预留 | 远程审批人，经过 relay、Slack 或身份提供方。v3 只保留枚举值，对应能力在 `lab` 中 |

**Agent 侧流程**
- **CLI / MCP**
  1. 调用返回 `APPROVAL_REQUIRED{challenge_id, expires_at}`。
  2. MCP tool 可以调用 `await_approval(challenge_id)`，最多长轮询 120 秒。
  3. 批准后，Agent 带 `challenge_id` 重新执行，消耗掉这次本地授权。
- **网关（LLM 调用）**：不支持审批，命中 `require-approval` 一律返回 403。LLM 模板默认不包含此类规则。

**防自批**
- `local-presence` 授权只能通过 A2 级管理操作签发，Agent 接口无法签发。
- 本地授权只能由发起该 challenge 的 principal 消耗。

### 6.4 审批与确认面板（应对 A3）

**面板内容**
- 所有显示内容由 daemon 根据规范化请求生成，包括：
  - 动作名称；
  - 目标资源的可读名称；
  - 完整参数，较长时可展开；
  - 策略变更时的完整 diff。
- 发起方提供的任何自由文本都不得出现在标题区。

**交互约束**
- 默认焦点在"拒绝"。
- 同一个 challenge 只能确认一次。

### 6.5 服务端身份校验（I4，修复 S2 中的伪造 socket 路径）

**macOS 签名构建**
1. 客户端连接 admin.sock 后，通过 `getsockopt(LOCAL_PEERTOKEN)` 取得对端的 audit token。
2. 通过公开 API `SecCodeCopyGuestWithAttributes` 和 `kSecGuestAttributeAudit` 将 audit token 解析为对端代码对象，再用 `SecCodeCheckValidity` 校验 Apple 签名信任链、Team ID 及标识符 `com.rekey.rekeyd`。SDK 中没有公开的 `SecCodeCreateWithAuditToken` API。
3. 校验失败时拒绝发送任何证明，并提示"可能存在伪造的 Rekey 服务"。

**Linux 及未签名构建**：无法做此校验，等级标为 L1-dev，界面需要提示。

**M1 验证项 V3**
- 确认 `LOCAL_PEERTOKEN` 在 Unix socket 上可用。
- 如果不可用，评估 `LOCAL_PEERPID` 加公开的 `SecCodeCopyGuestWithAttributes` / `kSecGuestAttributePid`，并记录 pid 复用的竞态风险。当前签名客户端遇到 audit-token 查询或签名验证失败直接拒绝，不自动降级。

**已知边界**：audit token 的签名查询只证明观测时身份，不证明 socket FD 独占，也不消除查询前 PID 复用、FD 转交或查询后 exec 的全部竞态。V3 的正负对照通过不能独自建立完整 L1/A2 承诺。

**daemon 不校验客户端**。A2 操作已经必须携带证明；A0/A1 操作对 A2 威胁者开放，不会扩大其权限，见 §3.2。

---

## 7. 模块规格：个人策略模式与 Provider 模板

### 7.1 个人策略签名

**两种模式**
- **个人模式**
  - `rekey setup` 时在 Secure Enclave 中生成 P-256 `policy-signing` 密钥，属性为 `.privateKeyUsage | .userPresence`，不可导出。
  - 信任根类型新增 `secure-enclave-p256`。
  - 签名流程在 App 内完成：模板勾选 → 生成规范策略 → 展示 diff → Touch ID 签名 → 激活。
- **团队模式**：沿用外部 Ed25519 签名器。

**模式选择**
- 初始化时二选一，之后不可更改，沿用"信任根不可变"的规则。
- 个人用户如果之后转为团队模式，需要新建 vault（与"不向后兼容"一致），并重新导入凭据。

**签名的作用**：策略签名证明"这份策略由信任根持有者批准"。在 v4 中，这个持有者就是组织的策略签名服务，见 §12。

**M2 编码与存储合同**
- `init --mode personal|team` 显式固定模式；初始 policy state 即认证该值，后续没有修改入口。
  personal 只允许 `secure-enclave-p256`，team 只允许 `ed25519`；模式、完整公钥与算法都进入持久化 seal。
  未安装信任根时仍保留已选模式；锁定状态不把未验证数据库值作为可信模式返回。
- P-256 公钥为 65 字节未压缩点 `04 || X || Y` 的小写 hex；签名为 ASN.1 DER ECDSA 的 canonical base64url-no-pad。
  策略签名输入保持 `RKPOLICY\0\x01 || JCS(unsigned envelope)`，两端对完整输入使用 ECDSA/SHA-256，不额外预哈希。
  外部审批人的 Ed25519 算法与这项策略信任根扩展分开；团队模板包继续只接受 Ed25519。
- `secure-enclave-p256` 指受支持的 App 创建路径；公钥与签名本身不能证明硬件来源。
  备份包含已签策略、公钥和模式，不含 SE 私钥；换设备后仍能验证旧策略，重新个人签名需要新建 vault。
- 个人草稿由 daemon 从已认证、仍启用的模板 Action 版本生成，输入为 principal、所选版本与到期时间。
  每份草稿是完整策略替换：差异展示包含所有删除、变更及新增，不能隐式保留未选择的授权。
  daemon 返回精确签名字节；App 审阅后只签该内存快照，不自行实现 JCS，不按文件路径重读。
  local-presence 尚未接线时，生成器遇到 require-approval 必须拒绝，不能降低为 allow。
  只读 admin opcode `54` 接收显式 `principal_id / actions / expires_at_ms`；空 actions 表示撤销全部授权。
  响应 metadata 包含已验证的 vault/trust、公钥、前后版本、policy digest、完整字段差异及所选 Action 定义，
  body 为精确签名字节。metadata 与签名策略各守 64 KiB 上限；超限拒绝，不截断审阅内容。
  CLI 仅将 metadata 与 UTF-8 签名字节封装为 JSON 供 App 读取；不参与签名或规范化。
  激活时再次检查引用的 Action 版本仍启用；策略版本已变化时要求重新生成与审阅，不自动重签。
  JCS 规范化若改变版本、到期时间或 Action 版本的整数值，草稿生成失败，不静默舍入。

### 7.2 Provider 模板格式

模板是带签名的声明文件。Rekey 内置一组；团队模式可以导入自定义模板，导入时需要签名。

```json
{
  "template": "github-pat@1",
  "display": "GitHub（个人访问令牌）",
  "credential": {"kind": "opaque-token", "inject": {"header": "authorization", "prefix": "Bearer "}},
  "origin": "https://api.github.com",
  "fixed_headers": {"accept": "application/vnd.github+json", "x-github-api-version": "2022-11-28"},
  "bindings": {
    "owner": {"type": "slug", "max": 39},
    "repo":  {"type": "slug", "max": 100}
  },
  "capabilities": [
    {"id": "read-repo", "risk": "low", "actions": [
      {"method": "GET", "path": "/repos/{owner}/{repo}"},
      {"method": "GET", "path": "/repos/{owner}/{repo}/issues",
       "query": {"state": "enum:open,closed,all", "per_page": "int:1..100", "page": "int:1..1000"}},
      {"method": "GET", "path": "/repos/{owner}/{repo}/pulls/{number}", "params": {"number": "int:1..2147483647"}}
    ]},
    {"id": "create-issue", "risk": "medium", "actions": [
      {"method": "POST", "path": "/repos/{owner}/{repo}/issues", "body_schema": "schemas/github-create-issue.json"}
    ]},
    {"id": "merge-pr", "risk": "high", "default_rule": "require-approval", "actions": [
      {"method": "PUT", "path": "/repos/{owner}/{repo}/pulls/{number}/merge", "params": {"number": "int:1..2147483647"}}
    ]}
  ]
}
```

这里放宽了原来"每个 Action 的 path 完全固定"的合同，但限定在以下封闭类型之内：

- **`bindings`**
  - 安装模板时由管理员填写；可以填多组，每组展开成独立的 Action。
  - Agent 不可修改。
- **`params`**
  - 由 Agent 每次调用时提供。
  - 只允许 `int:a..b`、`enum:...`、`slug` 三种类型。`slug` 必须匹配 `^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$`，且不能是 `.` 或 `..`。
  - 渲染时逐段校验后再拼接，不做 percent 解码；出现 `/`、`%`、`?`、`#` 一律拒绝。
- **`query`**
  - 键为封闭集合，取值规则与 `params` 相同；未声明的键一律拒绝。
  - 规范化排序后计入参数哈希，从而绑定到审批。
- **风险默认值**：`low` 和 `medium` 默认 `allow`（用户可以修改），`high` 默认 `require-approval`，approver 为 `local-presence`。
- **不支持通配符**：整个格式中不存在"任意 path"的写法。

#### M2 接线合同（GA 前固定）

- 安装将每组管理员 bindings 与所选 capability 的每个 action 展开成独立版本的 Action。
  物化结果只保留参数占位符；管理员 bindings 已成为固定路径段，调用者不能再次传入或覆盖。
  origin、method、注入方式与固定头各有一个权威值；持久化的 target 是 fixed path 或封闭的模板 target，
  不用假路径占位，也不同时维护两份可分歧的目标。反序列化时仍验证 target 的封闭语法。
- 内置声明和内嵌 schema 随发布物一起认证，来源是发布物的代码签名；这不宣称存在额外的 manifest 签名。
  团队自定义模板使用 vault 已安装的 Ed25519 策略信任根验证以下包，验签前不能绑定或安装：
  `{format_version:1, signer_id, template:<声明>, schemas:{<引用>:<JSON Schema>}, signature}`。
  签名输入是 `RKTEMPLATE\0\x01` 加除 signature 外整个对象的 JCS 字节；signature 使用无 padding 的 base64url。
  该域与策略、challenge、grant 分离，signer_id 必须匹配信任根。包上限沿用 64 KiB；重复 JSON 键拒绝。
- body_schema 只引用包中受签名约束的 schema 或内置 schema；不读取调用者文件路径、不下载 URL。
  缺失引用、不可用 schema、远程 schema 引用都拒绝。首个内置资源为 GitHub create-issue schema。
  Action 的来源摘要绑定声明及 schema 内容；包验签、物化和实际执行各自的完成状态单独记录。
- Action 持久化记录必须有内容认证：沿用 VRK 保护的空明文 AEAD seal，使用独立 AAD purpose，
  覆盖完整执行定义、目标规则、来源摘要、schema、版本与状态。创建、退役、禁用在同一审计事务中更新 seal；
  读取或执行前验证，VRK 轮换时重新封存，备份和恢复保留并校验。来源摘要本身不是防篡改认证。
  这项改动进入 GA 前格式草案；旧库一律拒绝，不做迁移。
- 存储形状固定为 `ActionTarget::Fixed { path }` 或 `ActionTarget::Template { target, fixed_headers, body_schema, source, default_policy }`。
  `target` 复用已验证的封闭路径规则；schema 是解析后的本地 JSON Schema 文档；source 记录模板/能力/action 索引、
  来源摘要及可选团队 signer。origin/method/auth 仍只有 Action 自身一份；不复制整个模板或物化对象。
  固定 Action 创建命令仍可接受 exact_path，并只构造 Fixed；Template 只能由认证包的安装入口产生。
- prepare-approval 和 execute 共用一次 render/canonicalize 路径。规范哈希含标准化 params、排序 query 与
  渲染后的 path；HTTP 只消费该规范结果。固定头不能被每次调用的头覆盖。
- 管理 IPC 52 为 TEMPLATE_CATALOG，53 为 TEMPLATE_INSTALL。source 是闭合的 anthropic、openai、
  github-pat、generic-bearer（带 typed origin 与固定 method/path 数组）或 signed-package；包字节只走 body。
  目录返回认证后的声明、摘要及 signer；安装再次认证，不把目录结果作为授权票据。
  安装 metadata 包含已有 credential_id、多组 bindings、所选 capabilities、name_prefix 和现有 Action 请求/响应限制；
  body 复用 proof+package 编码。一次证明后生成所有新 Action，与逐条 action.created 审计在同一事务提交。
  每条响应包含 binding_index 和完整 Action，能力/action 索引取 Action 的来源字段，不存第二份安装状态。
  提交前检查响应与完整 ACTION_LIST 均能装入 64 KiB metadata；过期且尚未开始 commit 时整批回滚。
  已开始 commit 后响应超时可能意味着整批已提交，客户端不能自动重试安装。
  App 将用户确认的 compact JSON 保存在内存，通过匿名 stdin 与逐次证明一次交给 CLI；
  不创建确认后再按路径读取的模板请求文件。CLI 的显式文件输入仍供手工使用。
  执行和 prepare-approval metadata 的 params/query 是字符串映射，省略表示空；fixed target 不接受非空映射。

### 7.3 首批内置模板（M2 交付）

| 模板 | 覆盖范围 |
|---|---|
| `anthropic@1` | `/v1/messages`（含流式、tools、thinking）、`/v1/messages/count_tokens`、`/v1/models` |
| `openai@1` | `/v1/chat/completions`、`/v1/responses`、`/v1/embeddings`、`/v1/models` |
| `github-pat@1` | 上面的示例，再加 comments、labels、contents 的只读接口 |
| `generic-bearer@1` | 用户自填 origin，加 1–20 条固定的 method+path，不带参数；作为兜底 |

GitHub App、Vault、Keycloak 等现有 connector 保留为"高级"类型，不出现在首页。

---

## 8. 模块规格：Agent 接入

### 8.1 Agent Profile

```json
{
  "profile": "claude-code",
  "principal_id": "<稳定 UUID>",
  "grants": ["anthropic@1:messages", "github-pat@1:read-repo", "github-pat@1:create-issue"],
  "session": {"ttl": "12h", "max_uses": 5000},
  "budget": {"anthropic@1": {"max_requests_per_day": 2000, "max_output_tokens_per_day": 2000000}},
  "isolation": "none | seatbelt | netns",
  "egress": "allow | deny-other"
}
```

- 创建或修改 Profile 属于 A2 操作。策略由 §7.1 的流程自动生成并签名。
- 策略绑定稳定的 `principal_id`（main 已支持 `--principal`），续签会话不需要重新签策略。
- 演进到 v4 时，`principal_id` 由工作负载身份映射得到，而不是本地生成，见 §12。

### 8.2 `rekey run`

```bash
rekey run claude-code -- claude
```

1. CLI 请求按 Profile 签发会话。这是 A1 操作，需要 vault 已解锁，**不弹窗**。如果 Profile 设置了 `confirm_each_run: true`，则升级为 A2。
2. 向子进程注入以下环境变量：
   - `ANTHROPIC_BASE_URL=http://127.0.0.1:<port>/p/anthropic`
   - `ANTHROPIC_API_KEY=rkc_<capability>`
   - `OPENAI_BASE_URL` / `OPENAI_API_KEY`，规则同上
   - `REKEY_AGENT_SOCKET`、`REKEY_CAPABILITY`
3. 子进程退出（包括异常退出）时，CLI 吊销会话。
   - CLI 本身被 SIGKILL 时，daemon 检测到父进程消失后吊销（macOS 用 `kqueue NOTE_EXIT`，Linux 用 pidfd），TTL 作为兜底。
4. 当 `isolation ≠ none` 时，复用 main 已有的 `agent-run`。
   - Seatbelt 配置需要新增出站规则，允许连接 `127.0.0.1:<port>` 和 agent.sock。
   - `egress: deny-other` 才达到 L2，界面要提示这会影响 npm、git 等工具。

**I5 的例外说明**：capability 会进入子进程环境变量。它是短期、有范围、可吊销的令牌，不是凭据本身；泄露后的影响以 Profile 的授权范围和预算为上限。

### 8.3 `rekey connect`

```bash
rekey connect claude-code   # 同样支持 codex | cursor
```

- 写入目标 Agent 的 MCP 配置（`rekey-mcp`）和网关环境变量。
- **写入前展示 diff，经用户确认后才写，并备份原文件。** 此规则覆盖 2026-10-01 中"不自动修改第三方 Agent 配置"的限制。
- `--print` 只打印，不写入。

### 8.4 rekey-mcp v2

- 通过 initialize 协商支持 MCP `2025-06-18`、`2025-11-25` 及后续版本。
- 每个已授权的模板能力暴露为一个 tool，输入 schema 由 params、query、body_schema 合成。
- 返回内容：`text/*` 和 `application/json` 直接返回文本，其他类型返回 base64 并附 MIME 类型。支持 GET。
- 另外提供 `await_approval` tool（§6.3）。
- 没有会话时返回 `NEEDS_SESSION`，提示用户运行 `rekey run`。

### 8.5 本机网关

**启用与监听**
- 默认关闭。Profile 第一次引用 LLM 模板时，在 A2 确认中一并开启。
- 只监听 `127.0.0.1`，端口记录在 `state/gateway.port`。

**路由**
- 格式为 `/p/<template-instance>/<模板声明的 path>`。
- 其他 path 一律返回 404，不访问上游。

**入站认证**
- 接受 `x-api-key` 或 `authorization: Bearer`，值必须是 `rkc_` capability；否则返回 401，**也不转发**客户端带来的真实 key。
- `Host` 必须是 `127.0.0.1:<port>` 或 `localhost:<port>`。
- 带 `Origin` 头的请求一律拒绝。

**请求处理**
- 剥除所有客户端认证头，重写 `Host`，注入凭据。
- 只转发模板声明的头，例如 `anthropic-version`、`anthropic-beta`。

**LLM 放宽**（覆盖 NET-07 的纯文本限制）
- 请求体整体透传，tools 和 thinking 一并放行。
- 强制三项限制：
  - `model` 必须在 Profile 白名单内；
  - `max_tokens` 不超过上限；
  - 预算按响应的 `usage` 累计，超出后拒绝新请求。

**流式与遮蔽**
- SSE 原样转发，复用 NET-07 的增量遮蔽器。新增 JSON Unicode 解码后，窗口扩大到 `6 * max_needle_len + 5`，保留跨分片六字节转义及未完成转义的上下文。
- 对两层分别遮蔽：原始 SSE 字节，以及 JSON 解码后的文本。
- 强制 `accept-encoding: identity`。

**审计**：每个请求记录 `execution.started` 和 `execution.finished`，只记元数据（模型、token 数、状态码）。

**说明**：网关是 v3 唯一新增的网络监听。理由是 base URL 是 SDK 生态唯一通用的接入方式。

---

## 9. 审计、可见性与发布

### 9.1 用量视图

App 新增"活动"页，按 Profile 和模板能力汇总：
- 调用次数；
- 拒绝次数；
- 审批次数；
- LLM token 用量。

数据来自现有审计表，不新增存储内容。

### 9.2 遮蔽增强（修复 S5）

- **新增编码变体**
  - JSON `\uXXXX`：先解码再匹配。
  - hex：大写和小写两种。
  - base64：三种对齐偏移。
- **长度下限**：长度小于 16 字节的秘密，添加时给出警告。嵌入 base64 的三种对齐检测保证限于至少 16 字节的秘密；更短的秘密保留原始值、完整编码、hex、percent 和 JSON 转义检测，不能宣称任意嵌入编码都可识别。避免把一个字符的部分编码扩展为误封大量正常响应的检测片段。
- **禁止的头**：`accept-encoding`、`content-encoding` 加入 Action 的禁止头列表。

### 9.3 发布与格式（不向后兼容）

**发布物**
- 签名并公证的 `Rekey.pkg`：
  - 包含 `/Applications/Rekey.app`；
  - CLI 链接到 `/usr/local/bin`；
  - 通过 SMAppService 注册 LaunchAgent。
- Homebrew cask。
- Linux：`.tar.gz` 加 systemd user unit，等级为 L1-dev。

**格式规则：永久不迁移**
- 任何格式变化都要求新建 state 目录。旧 state 和旧备份一律拒绝，绝不读取、迁移或覆盖。此规则对 GA 之后同样有效。
- 用户的代价：升级跨越格式版本时，需要重新初始化并重新添加 Key。为了控制这个代价：
  - **格式变化只允许出现在主版本**（v3 → v4）。同一主版本内的次版本和补丁版本不得改格式；需要改格式的功能推迟到下一个主版本。
  - 发布说明首行标明"需要重新初始化：是/否"。
  - App 检测到旧格式时，显示只读提示和重建引导。不读取旧库内容，也不提供迁移。
- 当前基础格式为 v21；完成上述必要存储改动后的最终草案在 v3.0 GA 时冻结为 v3 格式。GA 前每次改变实际格式同样拒绝旧库，不做迁移。

**节奏**：每个里程碑结束必须有可下载的版本。feature-truth-matrix 的 `Release` 列作为门槛：上一项没有进入发布包，不开始下一个里程碑。

---

## 10. 验证矩阵（在签名产物上运行）

| ID | 对应 | 攻击测试 |
|---|---|---|
| T1 | I1 | 遍历 agent.sock 的 opcode、网关全部路由、MCP tools，响应中不得出现 canary 的任何编码变体 |
| T2 | I3 | 同用户未签名进程连接 admin.sock：A0/A1 成功；A2（查看明文、`SHUTDOWN`、激活策略）在无证明、错误证明、过期 presence 时均被拒绝 |
| T3 | I4 | 杀掉 daemon，由伪造进程绑定 admin.sock：App 和签名 CLI 拒绝发送密码或 presence，并报警（依赖 V3） |
| T4 | 5.2 | 未签名进程读取 presence key 失败或触发系统认证（V1）；7 天到期或锁定后，presence 证明被拒绝 |
| T5 | 5.5 | 对签名 rekeyd 执行 `task_for_pid` 或 `lldb -p` 失败（V2）；Linux 上 `PR_SET_DUMPABLE=0` 生效 |
| T6 | I8 | 换成旧数据库后进入 `ROLLBACK_SUSPECTED`，不执行任何 Action |
| T7 | 7.2 | 路径参数中出现 `..`、`%2f`、`/`、超长值、Unicode 同形字，或使用未声明的 query 键：一律拒绝，且不访问上游 |
| T8 | 8.5 | 网关以下请求均被拒绝：非 `rkc_` key（返回 401 且不转发）、Host 为 `evil.com`、带 Origin、model 不在白名单、预算耗尽。此外，跨 SSE 分片的秘密被遮蔽，gzip 无法协商 |
| T9 | 8.2 | 子进程退出、CLI 被 SIGKILL 后，会话在 5 秒内被吊销 |
| T10 | 6.3/6.4 | Agent 无法通过任何 Agent 接口签发或消耗他人的本地审批授权；审批面板内容只来自 daemon 的规范请求 |
| T11 | I9 | `rekey run` 下连续 500 次授权范围内的调用，不产生任何 UI 交互 |
| T12 | 体验 | 在全新 macOS 账户上：安装 pkg → `rekey setup` → `rekey add anthropic` → `rekey run claude-code -- claude`，总计不超过 5 分钟，3 条命令，0 个 JSON |

现有的 P0 合同测试、fuzz 和性能门槛全部保留。

---

## 11. 范围：默认构建与 `lab`

**原则**
- 不删除已经通过验收的代码。
- 不进入 v3 的能力移入 `lab` cargo feature：
  - 不进入默认构建、发布包和首页文档；
  - 测试保留，CI 每周运行一次。
- 此处隔离实际执行、网络访问、命令入口和可选依赖；共享的纯模型、wire 编码及已有存储 schema 保留，避免仅为 feature 隔离改变 vault 格式。默认入口必须拒绝 `lab` 专属操作。
- `lab` 是企业阶段的**储备**，不是废弃区。v4 时按 §12 的映射逐项重新评估、启用。

| 处理 | 对象 |
|---|---|
| 默认构建 | Authority / vault / 加密、密码与恢复生命周期、VRK/DEK 轮换、审计查询/导出/清理、备份恢复、opaque-token、固定 HTTP Action 与模板、capability/session、策略引擎、审批（`local-presence` + `ed25519`）、`agent-run`（Seatbelt/netns）、NET-07 流式（并入网关）、rekey-mcp、GitHub App connector |
| `lab`（企业储备） | 工作负载身份（OIDC/SPIFFE/K8s/GHA JWKS）、`rekey-approval-relay`、远程审批收件箱、controlplane、identity-directory、oidc-admin、审计投递与 S3 归档、Keycloak 交换、Vault 各类 source、AWS/GCP/Azure/1Password/PKCS#11/macOS Keychain source、插件注册与 cgroup、指标、standby/DR |
| 文档 | 上述 spec 加状态头 `Status: Lab (v3 scope; enterprise reserve)`。`enterprise-architecture-v2.md` 和 `oss-enterprise-boundary.md` 标为 v4 研究稿，并修正其中描述 v1 的过时内容。README 按 §14.1 重写 |

【推断】默认构建的代码量可以减少约 30–40%。M0 需要实测并报告。

---

## 12. 企业演进路径（v4，只定映射，不实现）

v3 的每个核心抽象在 v4 中**只扩展、不推翻**：

| v3 抽象 | v4 扩展 | `lab` 中可复用的部分 |
|---|---|---|
| Approver（`local-presence`、`ed25519`） | 新增 `remote`：审批人由组织目录决定，通知走 Slack / 邮件 / 身份提供方；策略写法不变 | approval-relay、remote-approval-inbox、identity-directory |
| Profile 的 `principal_id` | 由工作负载身份映射：CI 的 OIDC、K8s SA、SPIFFE。无人值守的 Agent 不依赖 Touch ID | workload identity、GHA JWKS |
| 策略信任根（`secure-enclave-p256` / `ed25519`） | 组织策略签名服务（KMS/HSM）；各主机只验签 | vault-transit / pkcs11 signer |
| 本机 rekeyd | 每台主机一个数据面；控制面分发签名策略和模板，**控制面永不接触凭据** | controlplane |
| 本机审计 | 投递到 SIEM / 对象存储，数据面仍然 fail closed | audit-delivery、s3-audit-archive |
| 内置 vault | 外部 source 作为凭据来源，内置 vault 仍是默认选项 | 各云和 Vault source |
| L1（用户在场） | 服务器上的等价物：L2 隔离加工作负载身份。"人"的角色由 Approver 承担 | netns / seatbelt |

**禁止事项**：v3 不得引入只在 macOS 上、只有一个用户、需要人在场时才成立的**核心**抽象。Touch ID 只是 `presence` 证明和 `local-presence` Approver 的一种实现，不是协议的必需部分。

---

## 13. 决策与待验证项

### 13.1 已确认（2026-10-02）

| ID | 决策 |
|---|---|
| D1 | v3 以个人开发者为首发用户；企业方向确定要做，企业能力进入 `lab` 储备，见 §12 |
| D2 | **永不向后兼容**；GA 之后也不做格式迁移；格式只在主版本变化（§9.3） |
| D3 | 允许模板中的受约束路径参数和查询参数（§7.2） |
| D4 | 新增 loopback 网关；LLM 请求体透传，tools/thinking 放行（§8.5） |
| D5 | `rekey connect` 经确认后写入第三方配置，写入前展示 diff 并备份（§8.3） |
| D6 | 不做 XPC。保留 Unix socket，加客户端对服务端的签名校验（§6.5） |
| D7 | presence key 使用数据保护钥匙串加 `.userPresence`；Secure Enclave 只用于个人策略签名（§5.2、§7.1） |
| D8 | `lab` 代码留在主仓库，用 feature 隔离 |

### 13.2 M1 技术验证项（冻结前必须完成）

| ID | 验证内容 | 失败时的处理 |
|---|---|---|
| V1 | 带 `.userPresence` 和访问组的钥匙串项，同用户未签名进程无法静默读取 | 改为由 Secure Enclave 密钥包装 K，重写 §5.2 |
| V2 | 签名并启用 hardened runtime 的 rekeyd，同用户进程无法 `task_for_pid` | L1 的 A2 承诺降级，§3.3 改写 |
| V3 | `LOCAL_PEERTOKEN` 可以在 Unix socket 上取得对端 audit token | 退回 PID 方案并记录竞态风险 |

V1、V2 和 V3 在 M1 第一周以原型形式完成，结论写回本文后再冻结。环境或签名权限缺失应记录为未完成验证，不得记为通过或机制失效。

---

## 14. 里程碑

| 里程碑 | 内容 | 退出条件 |
|---|---|---|
| **M0 收敛**（1 周） | 合并到 main；拆分 `lab` feature；加状态头；重写 README；`SHUTDOWN` 改为 A2 | 默认 feature 下 `cargo test --workspace` 通过；提交默认构建的行数报告 |
| **M1 补洞**（约 1.5 周） | V1–V3 原型；presence key；查看明文需要 step-up；服务端签名校验；回滚代数；内存加固；pkg + SMAppService | T2–T6 在签名公证产物上通过；**独立人工安全审查**完成（项目验收目标；SEC-11 本身要求独立、与风险相称的复核） |
| **M2 模板与个人策略**（3 周） | Secure Enclave 策略签名；模板格式与渲染器；4 个内置模板；App 中的模板勾选界面；`local-presence` Approver 与审批面板 | T7、T10 通过；从零配置 GitHub PAT 不需要写 JSON |
| **M3 Agent 接入**（3 周） | Agent Profile；`rekey run`；网关（含 SSE 遮蔽和预算）；rekey-mcp v2；`rekey connect` | T1、T8、T9、T11 通过；用一次性测试 Key 完成 Claude Code 和 Codex 的真实接入 |
| **M4 GA**（2 周） | 冻结 v3 格式；完成文档；发布 v3.0.0 | 公开下载的 pkg 在全新机器上跑通 T12；feature-truth-matrix 的 `Release` 列与实际产物一致 |

### 14.1 README 首屏规范（M0）

依次包含：
1. 一句话介绍；
2. 安装方式（pkg / brew）；
3. 三条命令；
4. 保护等级 L0/L1/L2 表（5 行以内）；
5. 延伸阅读链接。

Release run ID、format 版本、G1/G2 的历史说明、DNS 排障等内容一律移出首屏。

---

## 15. 冻结后需同步修改的基线（先改 spec，再改代码）

- **`CLAUDE.md`**
  - 架构部分加入网关和服务端校验；Key Design Decisions 部分加入 presence 证明和 Approver。
  - 机械合同中的 secret-read grep 改为只针对 Agent 接口，并新增测试：Admin 查看明文必须带 step-up 证明。
  - 兼容性规则写明"永不迁移；格式只在主版本变化"。
- **`threat-model-v2.md` → v3**
  - G1/G2 改为 L0/L1-dev/L1/L2。
  - 写入 A1–A5。
  - 写明 capability 进入 env 的例外，以及 A3 的残余风险。
- **`feature-truth-matrix.md`**：新增 v3 各行；`lab` 中的行标为 `Lab`。
- **`2026-08-28-credential-authority-v2-foundation.md`**：更新 Action 格式（模板参数）、网关、presence 证明、Approver 字段。
- **`2026-09-14-native-admin-ui.md`**：7 天授权和查看明文的条款由本文 §5.2 取代。

---

## 附录 A：市场调研来源（2026-10-02 检索；星数和融资额来自二手报道，未核对一手资料）

- Infisical Agent Vault：https://github.com/Infisical/agent-vault · Agent Proxy：https://infisical.com/blog/agent-proxy
- OneCLI：https://github.com/onecli/onecli
- Anthropic Managed Agents vaults：https://platform.claude.com/docs/managed-agents/vaults
- AWS AgentCore Identity：https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-outbound-auth.html
- Tailscale Aperture：https://tailscale.com/docs/aperture/what-is-aperture
- Arcade（$60M A 轮）：https://siliconangle.com/2026/06/15/ai-agent-authorization-startup-arcade-nabs-60m-investment/
- 1Password Unified Access：https://1password.com/press/2026/mar/1password-unified-access
- Bitwarden Agent Access SDK：https://bitwarden.com/blog/shadow-ai-agents-how-to-secure-credential-access-with-agent-access-sdk/
- Okta XAA / ID-JAG：https://nirmata.com/2026/08/18/okta-cross-app-access-xaa-id-jag/
- Microsoft Entra Agent ID：https://learn.microsoft.com/en-us/entra/agent-id/whats-new-agent-id
- MCP 授权 2026-07-28：https://ssojet.com/blog/mcp-authorization-spec-2026-07-28-what-changed
- OWASP Agentic Top 10（ASI03）：https://goteleport.com/blog/owasp-top-10-agentic-applications
- NIST NCCoE Agent 身份：https://www.nccoe.nist.gov/projects/software-and-ai-agent-identity-and-authorization
