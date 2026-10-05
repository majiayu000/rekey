# Rekey v3：个人优先的 Agent 密钥执行产品

**状态**：§13 的 V1–V3 有界设备结论已记录，技术选择于2026-10-04冻结；**vault25 / policy6 于2026-10-05冻结，公开发布尚未完成**。2026-10-05 用户授权停止加功能、完成安全核心审查、合并及发布 alpha，并暂缓新版 App 交互与登录项真机验收；T12继续暂缓。未测项目仍未验证，不提升L1/L2宣称。源码、软件与设备结果分别见实施清单及产品基线。

**修订记录**
- 2026-10-05：将持久格式冻结提前到首个 v3 alpha 发布前；停止功能扩展，转入一周自用反馈。新版 App 三项真机验收由用户暂缓，不作为此次 alpha 的合并/发布阻塞，仍保留未验证状态。
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
| L2 | L1 加上按签名 Profile 的 `isolation: seatbelt|netns` 启动 `rekey run`，并配置 `egress: deny-other` | 在 L1 基础上，Agent 无法绕过 Rekey 访问网络和受保护文件 |

现有 G1 对应 L1-dev，现有 G2（Linux reference）对应有界拓扑中的隔离保证。V1/V2 与受保护锚设备验收完成前，当前开发构建即使已校验服务签名，也只显示已确认的 L1-dev 下限；Locked 且无会话时显示 L0，未知/故障状态不宣称等级。L2 必须依据实际启动与隔离验收，不能由 Profile 中的隔离声明自动推断。

### 3.4 不变量（每条都对应 §10 的攻击测试）

- **I1**：Agent 接口（agent.sock、网关、MCP）没有任何返回凭据明文的操作。
- **I2**：凭据只在 Authority 内部解密，且必须在授权和 `execution.started` 审计提交之后；每个请求只解密一次，用后清零。
- **I3**：以下操作每次都需要 step-up 证明（§6.2 的 A2 级）：查看明文、修改授权范围、激活策略、签发 7 天授权、备份导出与恢复、修改密码、恢复密钥轮换、VRK 轮换、`SHUTDOWN`。
  - 通常接受密码、恢复密钥或 presence key。签发 7 天授权与修改密码只接受密码或恢复密钥；恢复密钥轮换沿用仅接受当前密码的合同。这三项操作不得使用 presence，避免把临时授权续期或变成永久解锁因子。
  - 已解锁时的 step-up 验证与 unlock、锁定状态的 shutdown 共用现有失败计数和指数退避；切换操作不能绕过限速。只有成功的密码或恢复密钥证明清零计数，presence 成功不清零，避免用临时 K 维持密码猜测。
  - 唯一例外是 `LOCK`，任何人都可以锁定。
- **I4**：客户端发送密码或 presence key 之前，必须确认对端是签名的 rekeyd。L1-dev 下无法确认，CLI 在交互式秘密输入前、App 在证明输入或认证控件旁提示；自动化 CLI 在发送证明前向 stderr 提示，不改变 stdout 的数据格式。
- **I5**：秘密不进入 argv、env、日志、审计或 JSON 元数据。capability 进入 `rekey run` 子进程的 env 是例外，见 §8.2。
- **I6**：出站请求只能去往 Action 或模板声明的 origin；解析结果必须是公网 IP，连接钉在该 IP 上，禁止重定向。
  DoH 默认关闭。仅当管理员为 daemon 显式设置 `REKEY_DOH_URL`，且系统 DNS 对域名只返回
  `198.18.0.0/15` 虚拟地址时，才向所选 HTTPS JSON DoH 服务查询 A/AAAA。
  未配置时明确拒绝 fake-IP，不隐式向第三方发送域名。解析服务收到目标域名；配置代表信任该服务。
  DoH 服务本身也须解析为公网地址并固定连接，使用正常 TLS 验证、无重定向和无代理环境；
  查询只发送域名，不发送 provider 凭据，受原请求总期限与 64 KiB 响应上限约束。
  DoH 不可用或返回非公网地址即失败，不连接虚拟地址；IP 字面量与其它非公网系统答案仍直接拒绝。
  上游 URL/Host/TLS SNI 保留原域名，但不承诺所有 TUN 的域名分流规则都能匹配固定 IP 连接。
  DoH 是可选解析能力，不提供代理出口；所选解析服务及目标服务的网络可达性须另行验证。
  显式私有 Vault 来源不使用此路径。
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
   - K 是可重复使用的 bearer 证明；内存 hash 不使泄露的 K 不可重放。challenge nonce 只防止旧 grant 被重用或挪到其他请求。
   - verifier 仅在成功签发或恢复后发布，固定原到期时间并同时检查单调时钟；普通密码解锁不从磁盘恢复此 verifier。

**有效期与撤销**
- 有效期仍为签发后固定 7 天，不续期。
- 重新签发必须重新提交密码或恢复密钥；现有 K 不能用于签发替代 K。拒绝此类请求不撤销或延长原票据。
- 撤销条件不变：手动锁定、空闲锁定、修改密码、恢复密钥轮换、故障。
- 后台状态查询不刷新空闲期限；已到期的锁定等待当前状态查询完成后重新检查活动，不因查询占用协调锁而放弃。

**连续操作**
- App 为同一保险库复用成功读取时的 `LAContext`，避免连续几个操作重复按指纹；不缓存 K。
- 使用单调时钟固定限制复用窗口为首次成功读取后 10 秒，后续读取不续期。失败、保险库切换、保存新 K、锁定或清理管理会话时作废；过期后创建新 context，不接受最近设备解锁作为新窗口的预认证。
- 同一次“签署并激活”中，读取 K 与 Secure Enclave 策略签名共用该操作内的认证 context，避免各弹一次认证。复用同样遵守固定十秒窗口，不缓存 K 或签名，不改变逐次证明与精确字节签名；操作结束或任一步取消、失败时作废该 context。

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
- Vault header 增加 `generation: u64` 和 `generation_mac`。新 vault 从 1 开始；以固定 8-byte 大端 BLOB 保存，拒绝 0、畸形值和溢出。此次仍在未发布格式25内定稿，不迁移旧 schema。
- 由 VRK 经 HKDF-SHA256 派生专用 key，以 HMAC-SHA256 绑定域、vault ID、格式版本与代数；先验证 MAC 和既有内容封印，再信任代数或更新外部锚。MAC 不替代凭据、Action、策略和账本封印。
- 凭据增/转/撤、Action/模板批量增改禁用、信任根/策略与审计保留设置的实际变更、密码/恢复包装层、DEK/VRK 轮换，每个成功业务事务恰好加 1；无变化的幂等返回、失败、普通查询/审计和 Agent 执行不加。批量事务只加一次，VRK 轮换用新 VRK 认证新代数。
- 业务、审计和条件代数更新在同一个 SQLite 事务内。外部 `max_seen_generation` 是已保留的 high-water，记录于受保护钥匙串及 `state/generation`；它可能因中断领先 DB，绝不能降低。
- 最终 DB COMMIT 前，先持久推进受保护锚，再原子替换/fsync 文件锚；两者成功才提交。锚推进后遇到提交失败、期限届满或不确定结果，保留真实错误并 fault，不回退锚或继续准入。重启时较高锚阻止自动解锁。此顺序允许安全侧误报，不声称跨介质原子提交或硬件单调计数器。
- 生产受保护锚还必须保证同一 vault 跨 state-dir 的并发写者不能分叉或降低 high-water；只靠同用户可删除的 flock 文件不满足 L1。平台实现及签名权限需独立验收，未验证前不得把文件检查称为 L1 防回滚。

**回滚处理与备份恢复**
- 解包候选 VRK 后，认证 `db.generation < max_seen_generation` 时进入不持有 VRK 的 `ROLLBACK_SUSPECTED`：清除临时授权、拒绝自动解锁及 Action；重启或 lock 不清除该条件。
- 单独的恢复确认绑定 vault ID、所显示的源代数及 high-water，验证源备份的密码/恢复因子和完整内容封印；普通 unlock、presence key 或 desktop token 不作为恢复确认。错误/取消证明不写 DB 或锚。
- 确认将所选快照重新定代为 `max(db.generation, high-water)+1`，按同一提交顺序认证并记录恢复审计，之后保持 Locked。这里的“重置”只指解除疑似状态，绝不降低历史计数。
- 离线 restore 复用该确认语义，先完整验证 staging，再重新定代、持久安装；锚已推进后的失败清理不删除/降低锚，残留 incomplete marker 阻止启动。备份记录真实 snapshot generation，导出本身不增加代数。
- 缺失锚与权限拒绝/服务不可用必须区分；已有 vault 不静默重建。新机器确认会明确显示“历史不可用”，从源代数/剩余有效锚的最大值加 1 建立新基线，不能声称恢复了丢失历史。

**防护边界**：L1 依赖受保护计数项的读取、更新、删除/重建权限和并发语义验收；L1-dev 文件可被同用户回滚，只提供较弱检测。该机制检测带旧 header 的整库回滚，generation MAC 不单独检测保留新 header 后替换旧的合法行，也不防 root 或钥匙串整体回滚。Agent 执行不推进代数：最后一次管理变更后的合法旧快照可重置随后累积的用量，不承诺防本机状态回滚的预算封顶。恢复验证旧备份的有效因子，不宣称令已泄露的旧因子失效。

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
| A2 | 查看/复制明文、增删改 Action/模板/Profile、激活策略、安装信任根、签发 7 天授权、备份导出/恢复、改密码、恢复密钥轮换、VRK 轮换、`SHUTDOWN` | 每次都需要 step-up 证明；`presence` 不适用于签发 7 天授权、改密码和恢复密钥轮换（I3、§5.2），解密因子要求仍按下文执行 |

Profile 会话签发的“管理会话”专指 daemon 当前已认证的 Unlocked 生命周期：与 §3.2 已允许的 A2 能力一致，只能按已激活签名 Profile 的固定范围签发，不要求新 CLI 从 App 取得或落盘管理 token。该窄入口不允许添加凭据或执行 A2；添加凭据仍需原有独立内存管理 token。Locked/过期/不存在的 Profile 返回错误，不触发后台认证。

**修复 S2**：`SHUTDOWN` 在任何状态下都属于 A2。

step-up 授权与解密材料分开：`presence` 只在当前已解锁且本次运行已建立有效 verifier 时可用。
锁定状态的 shutdown 仍需 password/recovery；离线 restore 仍需源备份的解密因子，VRK 轮换仍需密码与恢复密钥重包新根。
新增证明类型不能替代这些密钥材料，也不能作为一般 unlock 的第三种 wrapper。

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

#### M2 审批格式接线合同（GA 前固定）

- `PolicyRule.approver` 是唯一审批人来源；同规则的 `approval` 只保留 `mode`、`max_uses` 和可选 `max_window_ms`。`require-approval` 必须同时提供两者，permit/forbid 均不得携带。旧 `approver_ids`/`quorum` 不再作为规则字段。
- `local-presence` 只接受 `kind`，只支持 one-time、max_uses=1、无时间窗。`ed25519.keys` 为 1–32 个不重复的规范小写十六进制 Ed25519 公钥，必须各自唯一对应已验签 snapshot 的审批人注册表；threshold 保留 1–2 且不大于 key 数。内部 ID 从该注册表派生，不增加第二套可编辑映射。remote 默认不能解码；lab 中可解码但无实现时验证与执行均拒绝。
- challenge/pending 使用同一 `approver`，完整字段参与来源签名和上下文比较；Ed25519 keys 排序输出。当前集成目标为 snapshot format6（本机审批阶段曾升为4），challenge/envelope/pending record 为 v2，challenge 签名域为 `RKCHALLENGE\0\x02`。旧格式全部拒绝，不迁移。外层 policy envelope 和 `RKPOLICY\0\x01`、外部 grant format1/`RKAPPROVAL\0\x01` 保持，因为其结构和已签上下文未改变；外部 grant 只能走 Ed25519 分支。
- 本机审批阶段将 vault format23 升为24；回滚 generation/MAC 后当前目标为25。旧库和备份在 bootstrap 拒绝，不等到 unlock 才报告策略完整性错误。lab relay 配置升为 3，审批目标增加 publicKey，以公钥匹配新 challenge；不因此实现 remote approver。
- 个人模板的高风险能力只有在本地批准、一次消费、重试和取消的完整链路验收后才开放；中间批次明确拒绝，不能降为 permit。外部签名 CLI 保留其现有单人 one-time、最长 60 秒边界。

#### M2 本机审批运行时合同

- 本机批准与拒绝分别是 A2 管理操作，必须使用 Presence proof。IPC admin55 返回完整 daemon review（正文走 body），56/57 批准/拒绝时绑定 challenge ID 和 review SHA256；Agent6/7 仅等待/取消本人会话的 challenge，不接受证明或签发参数。
- review 含完整 challenge、可信 Action 名称、origin/method 和同一次规范化产生的 target/params/query/body/content-type/headers，哈希覆盖全部内容与独立 `RKREVIEW\0\x01` 域。禁止凭据注入值、capability、K 或调用者自拟标题；超过既有 body 上限时在发布 pending 前拒绝，不截断。
- 生命周期为 Pending、Approved、Consumed、Cancelled、Expired，授权仅在内存。批准、消费、取消、锁定和策略变更由现有生命周期协调器排序；消费绑定完整上下文和原始 session，一次消费后即使审计或上游失败也不恢复。
- 首次进入本机等待、复用相同 pending 和本机 prepare 成功均归还本次预留调用次数。等待/查询不占执行名额、不扣次数。最后一次调用仍在处理中时，额外并发请求暂时返回 AUTHORITY_BUSY；实际耗尽后保留原耗尽错误。外部 Ed25519 的实际扣次与消费规则保持。
- Authority 在同一命令中验证 Presence 并持久提交决定审计，提交前检查双时钟期限。Broker 在成功后再核对状态、策略和期限才发布 grant；允许已经审计的决定因到期而不产生 grant，禁止审计失败后发布。
- 同一 challenge 重复批准仍需有效 Presence，但不再生成 grant、延长期限或重复决定审计。已入队且结果不确定的批准令 challenge 终态 Cancelled，不自动重试；已发布 Approved 后仅响应丢失则保留 Approved，查询可确认结果。单纯证明错误保留 Pending。
- `APPROVAL_REQUIRED`，ERROR envelope 携带结构化 challenge_id/expires_at_ms。流式只在尚未 Admitted 前返回此 ERROR；开始流后保留原 terminal 协议。Agent 带 local challenge ID 重试，不可同时提交外部 grants，其他审批类型不能忽略该 ID。
- await 最多120秒并受会话/challenge原双时钟截止限制，未获决定时返回 Pending，连接断开只结束等待。App 只审阅 daemon 正文，默认拒绝焦点，明确点击后才读取受保护 K；通知和轮询不得触发系统认证。

**Agent 侧流程**
- **CLI / MCP**
  1. 调用返回 `APPROVAL_REQUIRED{challenge_id, expires_at}`。
  2. MCP tool 可以调用 `await_approval(challenge_id)`，最多长轮询 120 秒。
  3. 批准后，Agent 带 `challenge_id` 重新执行，消耗掉这次本地授权。
- **网关（LLM 调用）**：命中 `require-approval` 返回含 challenge 的审批错误，按 §8.5 显式重提并消费已批准请求；不后台等待批准后自动代发。LLM 模板仍默认 allow。

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
- 个人草稿由 daemon 从已认证、仍启用的模板 Action 版本生成，输入为完整 Profile 数组、已验证策略摘要与到期时间。
  每份草稿是完整策略替换：差异展示包含所有删除、变更及新增，不能隐式保留未选择的授权。
  daemon 返回精确签名字节；App 审阅后只签该内存快照，不自行实现 JCS，不按文件路径重读。
  require-approval 使用已接线的 local-presence 一次审批，不能隐式降低为 allow。
  只读 admin opcode `54` 接收 `profiles / expected_policy_sha256 / expires_at_ms`；空 profiles 表示撤销全部授权。
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
- 请求 body 中每个原始 JSON number 在解析和 JCS 编码后必须保持精确十进制数值；例如 1.0、1e0 可规范为1，但超出精度的大整数、被舍入的小数与非零下溢不得静默接受。数值保真在唯一 canonicalize 边界、计算参数哈希之前检查；数字字符串不受影响。失败沿 InvalidParameters 拒绝，防止实际发送的原始 body 与审批哈希/审阅内容分离。
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
| `glm@1` | 固定 `https://open.bigmodel.cn/api/anthropic/v1/messages`，使用 Anthropic Messages 协议（含流式、tools、thinking）；仅声明 messages，不假定支持 count-tokens 或 models |
| `glm-responses@1` | 固定 `https://open.bigmodel.cn/api/v1/responses`，Bearer 注入，仅声明 OpenAI Responses 能力；用于 Codex，不开放存储查询、删除或任意 endpoint |
| `openai@1` | `/v1/chat/completions`、`/v1/responses`、`/v1/embeddings`、`/v1/models` |
| `github-pat@1` | 上面的示例，再加 comments、labels、contents 的只读接口 |
| `generic-bearer@1` | 用户自填 origin，加 1–20 条固定的 method+path，不带参数；作为兜底 |

GitHub App、Vault、Keycloak 等现有 connector 保留为"高级"类型，不出现在首页。

---

## 8. 模块规格：Agent 接入

### 8.1 Agent Profile

```json
{
  "name": "claude-code",
  "principal_id": "<稳定 UUID>",
  "grants": [{
    "instance": "anthropic",
    "capabilities": [{"capability": "messages", "rule": "template-default", "actions": [{"action_id": "<Action UUID>", "version": 1}]}]
  }],
  "session": {"ttl_ms": 43200000, "max_uses": 5000},
  "confirm_each_run": false,
  "llm_limits": [{
    "instance": "anthropic", "models": ["<允许的模型 ID>"],
    "max_output_tokens_per_request": 4096,
    "max_requests_per_day": 2000, "max_output_tokens_per_day": 2000000
  }],
  "isolation": "none",
  "egress": "allow"
}
```

- 创建或修改 Profile 属于 A2 操作。策略由 §7.1 的流程自动生成并签名。
- 策略绑定稳定的 `principal_id`（main 已支持 `--principal`），续签会话不需要重新签策略。
- 演进到 v4 时，`principal_id` 由工作负载身份映射得到，而不是本地生成，见 §12。

#### M3 实现合同（GA 前固定）

Profile 进入唯一签名 `PolicySnapshot` 的必填 `profiles`；个人规则选择补齐后的快照格式为6。用量与回滚存储的开发中 vault 格式为25，旧格式拒绝，不迁移。每个 Profile 内嵌稳定实例 slug → capability → 精确 ActionVersionRef 的映射，不另建实例目录或 Profile 数据库。激活时用认证后的 Action 行核对能力及共同的 credential/template/source digest。

个人草案 opcode54 以完整 `profiles`、到期时间和 `expected_policy_sha256` 为输入，替换旧 principal/actions 输入；空 Profile 数组撤销全部授权。daemon 在既有协调锁内核对认证持久策略摘要，失配返回 `POLICY_VERSION_CONFLICT`，过期策略仍可作为续期编辑基线。只读 opcode60 返回完整 Profile 列表与该摘要/到期时间，只有从未存在策略才返回空列表和 null；Locked/完整性错误不伪装为空。CLI 通过 `profile list` 读取，`policy draft --profiles-stdin` 提交；App 编辑完整数组，复用现有差异审阅、精确字节签名及激活。

每个 `ProfileCapabilityGrant` 必须显式包含 `rule: template-default | allow | require-approval`，不为缺字段提供旧格式回退。它是个人草案的基线选择：template-default 从认证后的 Action 默认值取值；allow 生成 Permit；require-approval 生成本机一次审批。App 在现有能力选择处展示风险、默认规则与明确选择，仍走完整草案、全量差异、逐字节签名及激活。生成器按 principal + 精确 ActionVersionRef 处理选择；同一主体在多个 Profile 中对同一操作的冲突基线拒绝，不同主体互不影响。

该选择不成为第二个授权器，也不改变完整替换合同：生成个人新策略时，不自动合并或保留 previous 的额外规则，全部删除/变化继续进入差异供明确签名。团队已有 Forbid、参数限制和外部 Ed25519 审批规则保持合法；所有执行继续由现有 evaluator 按 Forbid、RequireApproval、Permit 的优先级决定，Profile 中的 allow 不是绕过这些规则的许可。

会话上限使用 `ttl_ms`、`max_uses`，并签入 `confirm_each_run`。LLM 实例必须同时签入非空模型白名单、单次最大输出、每日请求数和每日输出 token 上限；同 principal/实例的多个 Profile 必须保持映射与预算一致，不同 principal 可使用同名实例的独立映射。修改这些字段继续使用完整草案、差异、签名和激活流程。

用量初版保留单一请求账本和一个认证集合根，不维护第二份汇总计数；代价是全集合校验成本随历史增长。请求与 `execution.started` 同事务记账，终态只结算一次。崩溃遗留的未结算请求在恢复准入前按已记录上限保守结算。内容认证与整库防回滚分开验收，后者仍依赖 §5.4 的外部锚。

### 8.2 `rekey run`

```bash
rekey run claude-code --client claude-code -- claude
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

隔离入口继续由 CLI 持有 owner/control，复用 sibling `rekeyd` 的平台 launcher，从首个不可信指令前安装沙箱。已实现的平台组合才可启动；`none+allow`、macOS `seatbelt+deny-other`、Linux `netns+deny-other` 分别验收，跨平台或未实现组合明确拒绝，不重试为裸进程。L2 只描述本次实际隔离的子树，Admin59 签发本身不是沙箱证明。

正常控制失效时，CLI 向隔离 helper 发 SIGTERM，并有界等待直接 Agent 被终止/回收以及私有临时目录清理；终端 Ctrl-C 给 helper 的 SIGINT 复用同一清理路径。超时可终止 helper，但必须报告清理未确认，不显示已停止 Agent。helper 的正常退出码143仅在该清理路径和 signal handler 恢复均成功后作为内部确认；被信号杀死不算确认。此合同不承诺终止所有后代；CLI/helper 被 SIGKILL 的边界仍以 T9 capability 撤销和存活后代的既有沙箱约束验收，不冒充清理成功。

隔离子树的工作目录为本次显式项目目录，允许该项目内读写；HOME/TMPDIR 使用私有临时目录。项目不得与 state/端点目录重叠，不放行项目外用户配置、Keychain 或其他服务 socket；项目内原有秘密属于用户授予的项目材料。继承标准输入/输出/错误的文件、pipe、TTY/null，拒绝 socket stdio，关闭其余 FD，并新建 terminal session 防止控制原宿主终端。平台 launcher 保留固定必要环境及本次 SDK 路由，清除代理、SSH socket、动态加载和其他账号环境；不为客户端兼容而放开整个 HOME。

macOS 仅允许精确 agent.sock 和可信59端口的 `127.0.0.1` TCP；其他 IP/UDP/UDS/Mach 默认拒绝。Linux 的独立网络 namespace 不能直接访问宿主 loopback，也不隔离工作目录中宿主可创建的 pathname Unix socket。工作目录读写 bind 无法单独满足 deny-other；该保证未补齐前，新 Profile netns 启动明确不可用，既有 agent-run 仍按其已验证的较窄合同使用。未来 Linux SDK 还要求同一 Gateway 的固定 UDS 与 namespace 内精确端口桥，复用同一执行链，不允许任意目的地转发。端点目录须与 state 分离，沿用既有 agent-runtime-dir 部署；默认拓扑未分离时拒绝隔离，不借此扩大 state 读取权限。Seatbelt 仅按实际验证的 macOS build/arch 报告，工具缺失或规则/依赖不足保留真实失败。

进程监视在发布 capability 前固定一次 OS 报告的 peer 身份，之后不得重选 owner。Linux 使用 `SO_PEERPIDFD`，旧内核缺此接口时明确拒绝；macOS 注册 `NOTE_EXIT` 后用原 audit token 的公开 Security 动态查询复核代际与存活。macOS 的 peer 身份可能随注册前的 FD 移交/写入变化，不能宣称还原最初 connector；正常 `run` 在签发完成前不启动 child，并保持控制 FD 的 CLOEXEC。注册后的 owner 死亡和控制连接 EOF 均独立触发撤销，T9 仍由真实 CLI 端到端验证。

Profile 的 session.created 已提交后，后续存活检查或响应准备失败须先撤销内存会话，再提交 session.revoked 后返回原错误；撤销审计失败则 fault 并返回审计错误。控制连接拿到 guard 后继续负责写入失败和 owner/EOF 的撤销。

**I5 的例外说明**：capability 会进入子进程环境变量。它是短期、有范围、可吊销的令牌，不是凭据本身；泄露后的影响受 Profile 授权范围、单请求上限与软日预算约束，不承诺硬费用封顶。

Profile 用尽调用额度后，拒绝新执行和发现，但不把“额度耗尽”当作控制连接撤销：必须让已经准入的最后一次响应完整交付。条目保留到 owner/control 关闭、显式撤销或 TTL 到期；普通手工会话继续使用原有清理语义。

`glm@1` 作为固定部署的 Anthropic Messages 实例使用现有 `anthropic` gateway provider。SDK 路径 `/v1/messages`（可选 `beta=true`）只映射到该模板认证的 `/api/anthropic/v1/messages`；不允许请求携带 origin 或任意前缀。仍校验模板摘要、固定域名、路径、凭据注入、模型白名单和预算。App 接入页可明确选择 Anthropic 或 GLM，选择变化丢弃未提交表单与能力选择。GLM 的协议兼容依据 [智谱官方文档](https://docs.bigmodel.cn/cn/guide/develop/claude/introduction)，真实服务响应仍需另行验收。

`glm-responses@1` 使用现有 `openai` gateway provider；SDK 的 `/v1/responses` 只映射到该模板认证的 `/api/v1/responses`。其 Bearer 注入与 `glm@1` 的 x-api-key 分开声明，模板摘要、模型、用量和原始 SSE 仍走同一准入和结算边界。App 可明确选择 GLM 的 Claude Code 或 Codex 接入；不需要用户编写 manifest 或 JSON。依据 [智谱 Responses 官方文档](https://docs.bigmodel.cn/cn/guide/develop/responses/introduction)，流式结束可没有 `[DONE]`；真实 GLM 也已观测到完整终帧后附加该标记。只允许 `response.completed` / `response.incomplete` 之后出现单个 `[DONE]`，提前、重复或终帧后的其它数据仍拒绝。终帧必须等 EOF 与结算后才能释放，秘密遮蔽保持原合同。

SDK endpoint 只从已认证 admin 连接的 opcode59 成功 body 取得。`ProfileSessionCreatedResponse` 必填 `gateway`：非 LLM 为 null；LLM 监听可用时为 `{port, instances:[{instance, provider}]}`，provider 为闭合 `anthropic` / `openai`。LLM 监听不可用时也返回 null，SDK run 以现有启动不可用错误拒绝启动，不自动重试；MCP 本身不依赖 HTTP endpoint。端口必须当前已绑定且非零，实例映射须恰好覆盖该 Profile 的 LLM 实例；响应与完整 Profile、策略摘要在同一协调点绑定。CLI 固定构造 loopback URL，Anthropic 使用 `/p/<instance>`，OpenAI 使用 `/p/<instance>/v1`；不接受任意 origin，也不读取端口文件后发送 capability。同 provider 多实例无法映射到一个 SDK 环境变量时，run 明确拒绝启动并提示拆分 Profile，不猜选第一个。Agent IPC 内部 capability 保持原值，仅 HTTP SDK 环境的 API key 添加一次 `rkc_` 前缀。

客户端适配必须显式选择 `run <profile> --client claude-code|codex -- <command> [args]`，不从 executable basename 猜测；缺省仍是上述通用 SDK 环境。适配不扩大签名 Profile 权限，不写客户端配置或令牌文件：
- Claude Code 模式要求一个 Anthropic endpoint，使用 `ANTHROPIC_AUTH_TOKEN=rkc_<capability>`，移除本次环境中的 `ANTHROPIC_API_KEY`、custom headers 和已声明的 Bedrock/Vertex/Foundry 路由选择，避免 API key 首次确认与双鉴权。不得自动启用 `CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST` 来绕过客户端受管理模型约束；已有客户端设置/组织策略的优先级仍存在，当前软件检查不等于所有客户端配置下的零交互验收。
- Codex 模式要求一个 OpenAI endpoint，使用本次 session UUID 派生的公开临时 provider 名。通过启动 argv 的固定 `-c` 设置 name、可信 base_url、env_key=OPENAI_API_KEY、requires_openai_auth=false、wire_api=responses、supports_websockets=false；capability 只在 env。使用本次 provider 名避免 Codex 配置深合并残留旧同名 provider 的 header 或 auth 字段，不新增注册表或持久配置。
- Codex 固定覆盖置于用户参数尾、首个字面 `--` 之前，保持后续 prompt 原样；明确拒绝适配模式中与本机网关冲突的 `--oss`、`--local-provider`、`--remote` 选择。仅从首个字面 `--` 前移除独立的 `--no-daemon` 参数，再在程序后的根参数位置放置一个 `--no-daemon`，使能力令牌留在本次子进程，避免复用已有共享 daemon；`--` 后的 prompt 原样保留。不自动绕过外部受管理策略，客户端拒绝配置时保留其退出状态。

### 8.3 `rekey connect`

```bash
rekey connect claude-code   # 同样支持 codex | cursor
```

- 写入目标 Agent 的 MCP 配置（`rekey-mcp`），并给出对应 `run --client` 启动指引。SDK 动态 endpoint 与运行时 key 引用由 §8.2 的显式启动适配绑定，不向配置文件写入会过期的端口，也不假设 `${ENV}` 会展开；capability 值不落盘。Codex 当前忽略项目层的 provider 配置，故不把该文件冒充 SDK 路由已生效。Cursor 本批仅支持 MCP：其官方 BYOK 经服务端构造请求，不能将用户本机 loopback 网关冒充可用的远端地址。
- **写入前展示 diff，经用户确认后才写，并备份原文件。** 此规则覆盖 2026-10-01 中"不自动修改第三方 Agent 配置"的限制。
- diff 同时展示原有字段与替换后的 Rekey 子树，包括将删除的字段。原有值隐藏，避免输出已有凭据；不展示无关配置。`--print` 仍只打印公开的新增片段。
- `--print` 只打印，不写入。

### 8.4 rekey-mcp v2

- 通过 initialize 协商支持 MCP `2025-06-18`、`2025-11-25` 及后续版本。
- 每个已授权的模板能力暴露为一个 tool，输入 schema 由 params、query、body_schema 合成。
- 返回内容：`text/*` 和 `application/json` 直接返回文本，其他类型返回 base64 并附 MIME 类型。支持 GET。
- 另外提供 `await_approval` 和 `cancel_approval` tool（§6.3），只通过 Agent socket 查询或取消调用者自己的 challenge，不执行管理批准，不自动重发原动作。
- MCP 动作参数为 `{params, query, body, approval_challenge?}`；同一能力包含多个 Action 时，额外要求闭合的 `operation`（已认证 source.action_index 的十进制字符串），选择对应的精确版本与输入 schema，单 Action 不接受该字段。控制字段只进 IPC metadata，`body` 单独编码；GET 不接受 body 并发送零字节。批准后由 Agent 显式带同一 `approval_challenge` 重新提交原请求；完整上下文仍由 daemon 复核。
- `APPROVAL_REQUIRED` 的 challenge ID 和期限同时放入文本 JSON 与 `structuredContent`；await/cancel 返回同一 daemon 状态与期限。未实现的协议版本只协商到最高已实现版本，不声称支持未来协议。
- 没有会话时返回 `NEEDS_SESSION`，提示用户运行 `rekey run`。
- 无参数 MCP 从 `REKEY_CAPABILITY` / `REKEY_AGENT_SOCKET` 接入；Agent opcode8 只读发现当前签名 Profile 的公开 Action 投影，不消费调用次数。每次 list/动作调用刷新发现，后续执行仍独立准入；审批等待/取消保留自己的 owner 校验。多 Action 能力用最小 source index 对应 Action ref 作为现有 `rekey.<id>.v<version>` 工具名，title 显示实例/能力。不再读取 manifest/session token 文件。

### 8.5 本机网关

**启用与监听**
- 默认关闭。Profile 第一次引用 LLM 模板时，在 A2 确认中一并开启。
- 唯一启用来源是当前已验证、有效的签名策略引用受支持 LLM Profile，不增加持久 enable 配置。只监听 `127.0.0.1:0`，实际端口以原子替换、0600 写入 `state/gateway.port`，该文件仅作公开发现缓存，不作为令牌发送目的地的可信来源。
- 激活或解锁重载完成既有策略事务后协调监听；bind 失败保留“策略已提交”的事实，endpoint 不可用，LLM run 拒绝启动，不自动重新签名。锁定、策略撤回/到期、故障和停止关闭 listener 并清理端口缓存；已准入请求继续由原 Supervisor 收口。

**路由**
- 格式为 `/p/<template-instance>/<模板声明的 path>`。
- 其他 path 一律返回 404，不访问上游。

**入站认证**
- 接受 `x-api-key` 或 `authorization: Bearer`，值必须是 `rkc_` capability；否则返回 401，**也不转发**客户端带来的真实 key。
- `Host` 必须恰一个，值为 `127.0.0.1:<实际port>` 或 `localhost:<实际port>`。重复/同时出现的两种认证头、非 ASCII 或非 `rkc_` 令牌拒绝，不猜测选择一个。
- 带 `Origin` 头的请求一律拒绝。

**请求处理**
- 剥除所有客户端认证头，重写 `Host`，注入凭据。
- 只转发已认证 Action 声明的额外头。固定头由 executor 注入；客户端同值可剥除后继续，异值拒绝。当前内置 Anthropic 只有固定 `anthropic-version`；`anthropic-beta` 仅在既有安装合同明确允许并登记为 Action extra header 时可转发，不在网关私增许可。
- HTTP 适配器复用同一次执行准入、规范正文、审批、预算和遮蔽，不另解析或改写 model/max/stream。严格路由到签名实例的精确 method/path；拒绝编码近似路径、query、绝对 URI、CONNECT/Upgrade、压缩请求及歧义长度，头部、连接、正文和读取时间有界。
- 可选 `x-rekey-approval-challenge` 仅接受一个 UUID，用于用户批准后的显式重提，交原审批复核并在上游前剥除。SDK 首次收到 `APPROVAL_REQUIRED`，网关不自动等待或重试。首字节前沿现有安全错误返回：认证401、路由404、格式400、策略/预算/审批403、锁定或服务故障503、上游502。
- 流式响应在首个经过检查的 chunk 到达后才发200/SSE头，保持原事件字节；Supervisor 持有执行与唯一结算。终态失败、超时或丢失终态在已发头后中止正文，不伪造完成帧或向 SSE 插入普通 JSON 错误。客户端断开不移交或重复结算权限。
- 流式请求收到非200上游响应时，先按 Action 大小上限读取完整错误正文，对正文与全部头执行相同秘密遮蔽，并提交终态审计；随后以普通 HTTP 响应返回原状态码、正文和声明允许的头（含 `retry-after`）。遮蔽、大小、传输或审计失败继续拒绝，不能提前发送上游错误正文。App 的 LLM 接入声明允许 `retry-after`。
- HTTP socket 写入持续30秒没有进展即关闭该连接。读入或上游事件不能重置写入期限；关闭只释放 HTTP 接收方，执行与结算仍由 Supervisor 收口。

**LLM 放宽**（覆盖 NET-07 的纯文本限制）
- 请求体整体透传，tools 和 thinking 一并放行。
- 强制三项限制：
  - `model` 必须在 Profile 白名单内；
  - 生成输出上限按实际接口字段校验：Messages `max_tokens`、Responses `max_output_tokens`、Chat `max_completion_tokens` 或 `max_tokens`（二者互斥），必须是正整数且不超过 Profile 上限。缺省时，共同规范化入口只补这一字段；Chat 默认补 `max_completion_tokens`。其余 body 原始内容保留，上游发送、策略哈希和审批展示使用同一有效 body；较小的显式值不会扩大。
  - Chat 只接受缺省 `n` 或整数 `n=1`；Responses 只接受缺省或 `background:false`。这样每请求上限能界定生成输出，拒绝未覆盖的多 choice 或后台执行。
  - 预算按响应的 `usage` 累计，超出后拒绝新请求。
  - 日预算按稳定 principal、模板实例和 UTC 日期持久聚合，续签 capability 与 daemon 重启不能重置。
  - 生成请求的 `usage` 缺失、格式错误或流中断时，按本次请求已校验的最大输出 token 数结算，并记为 indeterminate；不能按零消耗处理。有效累计 usage 只结算一次，不将流中的多次累计值相加。
  - 达到已结算预算后拒绝新请求；已在途请求可能造成有界超额，这不是硬费用封顶。模型与预算在共同执行准入检查，不能改走 agent.sock/MCP 绕过。

**流式与遮蔽**
- SSE 原样转发，复用 NET-07 的增量遮蔽器。新增 JSON Unicode 解码后，窗口扩大到 `6 * max_needle_len + 5`，保留跨分片六字节转义及未完成转义的上下文。
- 对两层分别遮蔽：原始 SSE 字节，以及 JSON 解码后的文本。
- Anthropic 多文本块按 block index 拼装的最终文本也须遮蔽，不能仅检查事件到达顺序；保留原始事件与 tools/thinking，投影占用计入现有响应大小上限。
- 首个安全 chunk 之前的执行失败保留原错误码与 retryable；安全拒绝不能转成可重试的上游失败。首 chunk 之后仍中止正文，不插入错误 JSON 或伪造完成。
- 强制 `accept-encoding: identity`。

**审计**：每个请求记录 `execution.started` 和 `execution.finished`，只记元数据（模型、token 数、状态码）。

**说明**：网关是 v3 唯一新增的网络监听。理由是 base URL 是 SDK 生态唯一通用的接入方式。

---

实际 Claude Code 的 Anthropic beta SDK 使用 `?beta=true`。内置 `anthropic@1` 的 messages 与 count-tokens 在现可选 query 模型中声明 `beta: enum:true`；普通请求仍可省略，models 不扩大。HTTP adapter 只接受空 query 或该精确字面键值，并仅映射到声明它的 Action；重复、转义、其他键/值继续拒绝。beta 值进入既有 renderer、规范请求/审批哈希及真实上游目标，不静默删除，也不无条件给普通请求添加。`anthropic-beta` 头仍遵守管理员注册的 allowed_extra_headers；不自动把客户端随版本变化的实验特性扩大为内置信任。

## 9. 审计、可见性与发布

### 9.1 用量视图

App 新增"活动"页，按 Profile 和模板能力汇总：
- 调用次数；
- 拒绝次数；
- 审批次数；
- LLM token 用量。

数据来自现有审计表，不新增统计存储；允许补齐现有审计记录的请求元数据。可选 `request_context` 只含已认证的 `profile_name`、签发时 `policy_sha256`、`instance_slug`、`capability` 和经过共同入口校验的 `model`，不保存请求正文、参数、提示词或令牌。历史 Profile 按策略摘要与名称识别，不从当前配置猜测归属；普通事件没有此上下文。

该上下文贯穿拒绝、审批、执行和既有两条崩溃恢复链。现审计表的 JSON 元数据列在未发布的格式25内定稿为 `metadata_json`，包含闭合的 `request_context` 与 `usage`，旧 schema 摘要直接拒绝，不迁移。用量账本认证与一次结算合同不变。成功执行保留 started/finished，拒绝和异常保留 blocked/indeterminate，不为统计补造成功事件。

活动页默认统计今日 UTC、截至刷新时的稳定审计快照：只将 started 计为执行准入，blocked 计为执行拒绝，唯一 approval.requested 计为触发审批；批准等待本身不是拒绝。输出 token 只从一次结算的终态累计，实测值与按上限计入的值分开。准入与拒绝不是互斥指标；跨午夜的完成记录按终态时间展示，预算仍按请求准入的 UTC 日记账。

沿现有 audit list 的4MiB body和稳定分页读取，按完整记录字节预算给出正确 cursor，不截字段或跳记录。只有翻页完成后才展示该快照内完整的已保留记录汇总；未加载完、快照过期或历史被清理都明确显示，不能冒充全部请求总数。

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
  - 内嵌独立 `com.rekey.rekeyd` daemon bundle 与其 Developer ID provisioning profile，使 daemon 可使用受保护计数项的 keychain access group；App 保留自己的 profile。该结构只承载签名与授权，不引入 XPC 通信；
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
- 历史基础格式为 v21；以 `5de61bf` 的实际布局冻结 vault / backup format25 与 policy snapshot6，自首个 `v3.0.0-alpha.1` 起覆盖所有 v3 预发布、GA、次版本和补丁版本。不能在相同格式号下改变读取、恢复或签名验证所依赖的布局/规范化语义；`lab` 也受此约束。需要不兼容持久格式的改动推迟到 v4，不做迁移、双读或回填。
- 格式冻结是维护约束，不是安全等级、设备验收或公开发布已经完成的证明。后续仅处理发布阻塞和已证实的安全/正确性问题；首次设置与客户端推断等体验改动先收集一周实际记录，再决定最小修正。

**节奏**：用户于 2026-10-05 授权合并及发布 `v3.0.0-alpha.1`，新版 App 三项真机验收和 T12 暂缓。 PR #62 已合并；alpha.1 的 macOS 发布构建因 Swift 排序表达式类型检查超时失败，保留该不可变 tag，alpha.2 已完成签名、公证，但安装验收将归档专用 Python 工具误作为 App 要求；alpha.3 同样完成签名、公证和安装后的 P0，但后续 MCP 检查仍调用已删除的 v2 manifest 接口；保留三个未发布 tag，以 `v3.0.0-alpha.4` 修正 Profile 发现验收后继续发布，格式不变。源码、软件测试、签名设备验收和公开发布分别记录；feature-truth-matrix 的 `Release` 列仅在真实发布包下载验收后填写，不能用本地构建代替。[发布与一周自用记录](../../v3-release-and-dogfood.md)列出实际门槛和每日模板。

macOS pkg 的功能验收只使用实际安装的原生工具；归档专用 Python 工具的检查留在 tar.gz 入口。共享行为和服务验收不省略，不使用源码构建替代已下载的包。 macOS 服务验收直接执行安装 bundle 内的 daemon，保留独立 provisioning profile；开发 fixture 仍用临时路径。MCP 验收安装合成模板、激活签名 Profile，通过已安装的 `rekey run` 启动无参数 `rekey-mcp`，验证真实 Profile Action 与审批工具发现；不写 capability/manifest 文件，也不执行上游请求。

---

### 9.4 三命令入口（macOS 安装版）

- `rekey setup` 与 `rekey add anthropic` 只打开 `/Applications/Rekey.app` 的固定 `rekey://setup` / `rekey://add/anthropic` 页面。URL 不接受 query、fragment、证明、路径或任意 provider；CLI exit 0 只表示系统已接受打开请求，完成以 App 显示为准。
- 此入口使用默认 state-dir；非默认 state-dir 或不适用的 socket/session 参数明确拒绝，不忽略。运行中的 App 同样接收固定路由。路由只选页面，不自动执行初始化、保存、注册服务、签名或激活。
- Setup 复用个人/团队选择、初始化、离线保存恢复密钥确认、显式启用服务及已认证状态检查。个人模式再显式建立既有 SE trust；团队模式保留外部签署。重复打开不重建已有 vault 或 trust，不缓存跨步骤密码。
- Anthropic 接入展示“保存凭据”和“授予权限”两个阶段：A1 保存获得真实 credential ID，逐次 A2 安装用户选择的模板 capabilities，再用现有完整 Profile 草稿、差异审阅和 SE 精确字节签名。此次安装显式展示并授权 `anthropic-beta` header，不改变模板全局默认。
- 模型白名单为用户明确确认的精确 ID；第三条命令携带同一 `--model`。会话、单次/每日预算和策略到期可见且需确认；Claude 初始单次建议 32768 以覆盖本次实测 32000 请求，不静默扩大已有授权。默认不启用 L2。
- 已有 Profile 完整保留；重名需明确编辑或另名，旧 principal 不改变。基线漂移重新加载并审阅，不自动合并/重签。保存、安装和激活为现有分步事务；取消或失败保留已完成阶段，不后台重试或自动删除。
- 切工作区、锁定、关闭页面、版本变化使在途结果失效；系统认证完成后仍核对 vault/trust/version。用户不需要编写 JSON；完整 Action 和签名差异仍可展开审查。

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
| T12 | 体验 | 在全新 macOS 账户上：安装 pkg → `rekey setup` → `rekey add anthropic` → `rekey run claude-code --client claude-code -- claude --model <已确认的模型>`，总计不超过 5 分钟，3 条命令，0 个 JSON |

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
| V2 | Apple签名的lldb可附加同签名普通rekeyd，而hardened runtime对照拒绝附加；`task_for_pid`只作辅助 | L1 的 A2 承诺降级，§3.3 改写 |
| V3 | `LOCAL_PEERTOKEN` 可以在 Unix socket 上取得对端 audit token | 退回 PID 方案并记录竞态风险 |

2026-10-04结论：V1在有效Developer ID profile下，owner交互读取通过，ad-hoc/静默读取拒绝，见[设备记录](../../evidence/v3-review-v1-presence-2026-10-03.json)；V2的Apple lldb同签名正负对照通过，见[对照记录](../../evidence/v3-review-v2-lldb-2026-10-03.json)；V3取得32字节audit token、不回退PID，合法身份收到30字节合成canary，错误ID/ad-hoc均收到零字节，摘要见[统一证据](../../evidence/v3-release-acceptance-2026-10-04.json)。这些结果冻结技术选择，不冻结GA格式，不替代完整签名产品攻击矩阵与人工安全审查。早先缺profile和不充分的task-port对照继续保留为失败/未确定记录。

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
