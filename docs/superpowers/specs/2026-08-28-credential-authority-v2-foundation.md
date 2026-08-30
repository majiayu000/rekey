# Rekey Credential Authority v2 Foundation 实施规格

状态：Implemented as G1 development candidate; release gates remain open
日期：2026-08-28
范围：P0 本地 Credential Authority、Broker、Admin/Agent IPC、固定 HTTP Action 纵向切片
架构类型：安全敏感的长运行 Runtime + 本地服务 + CLI
兼容策略：Breaking rewrite，不兼容 v1 数据、命令、端口、数据库或代理行为
相关基线：[北极星](../../product-foundation/north-star-and-positioning.md) · [威胁模型](../../product-foundation/threat-model-v2.md) · [企业架构](../../product-foundation/enterprise-architecture-v2.md) · [开源商业边界](../../product-foundation/oss-enterprise-boundary.md)

## 1. Objective

实现 Rekey 第一方、开源、零外部 Vault 依赖的 Credential Authority 基础。用户可以初始化本地 Vault、解锁 Broker、保存和轮换机器凭据、声明一个目标固定的 HTTP Action、向 Agent 发放短期 Capability，并让 Agent 在完全不知道真实凭据值的情况下完成一次受约束上游请求。

P0 的核心证明不是“数据库已加密”，而是同时满足：

1. Broker 是解密材料、Credential mutation 和上游凭据效果的唯一状态所有者。
2. CLI、Dashboard、Agent、MCP Server 和 Connector 都不能直接打开 Vault。
3. Agent/Runtime wire protocol 没有 Secret 读取、导出、任意 URL 或任意认证 Header 能力。
4. 密码、恢复密钥、VRK、DEK 和上游 Secret 不进入 argv、环境变量、普通文件、错误、日志或审计。
5. 凭据只有在 Capability、Action 和执行约束全部通过后才被解密。
6. P0 明确只达到 G1；G2 需要后续独立 OS 用户或沙箱、文件和网络隔离。

## 2. Locked Decisions

以下决定在本规格中锁定，实施中不得自行重新打开：

| Decision | Choice | Reason |
| --- | --- | --- |
| 产品所有权 | Rekey 自带 Credential Authority | 零依赖采用和端到端安全合同属于产品核心 |
| 状态所有者 | Broker Runtime 唯一拥有 SQLite connection、VRK、DEK 解析和 mutation | 消除 CLI/Web/Proxy 多写者和秘密扩散 |
| 外部 Vault | 不进入 P0；不是运行前置条件 | 先证明第一方内置路径 |
| 密码学 | Argon2id + AES-256-GCM + HKDF-SHA-256，使用成熟 crate | 不自创算法；保留未来算法版本 |
| 密钥层级 | password/recovery KEK -> VRK -> per-version DEK -> payload | 支持换密码、恢复、版本轮换和密码学删除 |
| 持久化 | 单一 SQLite 文件，WAL + synchronous=FULL | 本地单写者、事务和崩溃恢复足够 |
| IPC | 两个 Unix Domain Socket，长度前缀二进制 frame + JSON metadata + raw body | 管理/Agent 权限分离；避免 Secret 被 JSON/base64 复制 |
| Agent API | Capability + Action Execute；无 read/export Secret | 权能使用不等于权能转移 |
| Admin API | 敏感 mutation 每次要求 step-up unlock proof | 同用户 P0 中降低误调用和横向滥用 |
| HTTP Action | Admin 固定 HTTPS origin、method、exact path 和 auth slot | 禁止 `credential + arbitrary URL` confused deputy |
| 响应 | P0 缓冲响应，做大小限制、Header allowlist 和精确 Secret sealing | 先得到可验证闭环；流式响应后置 |
| 兼容 | 删除 v1 路径，不写迁移器、alias 或 shim | 用户明确允许 breaking rewrite |
| UI/MITM | P0 删除 Dashboard、系统 CA、透明 MITM 和 passthrough | 缩小可信计算基和攻击面 |
| 平台 | P0 支持 macOS 与 Linux；Windows 显式 unsupported | UDS/peer credential/权限合同先收敛 |

## 3. Current Evidence

| Area | Current evidence | Implication |
| --- | --- | --- |
| Entrypoints | `rekey-cli` 的 add/store/request/list/remove/rotate 直接打开 Vault | 所有运行期命令改为 IPC client；只保留 init/restore 的离线独占例外 |
| Secret API | `rekey-vault::secrets` 公开 `get_secret_value` 和 `get_credential_fields` | 删除并用 opaque cross-crate `PreparedCredential` 替代；字段和构造器不公开 |
| Key ownership | `ProxyServer` 长期持有 `Arc<MasterKey>` | 改为 Authority worker 独占 VRK；网络任务不能持有 root key |
| Password transport | daemon child 通过 `REKEY_PASSWORD` 环境变量收到密码 | 删除 daemon 模式；serve 永远 locked 启动，unlock 通过 Admin IPC |
| Storage | password-derived key 直接加密 JSON HashMap；无 envelope/AAD/version | 完整重写 schema 和 crypto module |
| Request path | `rekey request <name> <arbitrary-url>` 和 `/proxy/{provider}/{path}` | 删除；Agent 只能调用 Admin 预注册 ActionId |
| Proxy behavior | 未匹配 host 透明 passthrough；系统 CA + MITM | 从 P0 workspace 删除 CA/Web/Proxy 旧运行路径 |
| Web | `rekey-web` 直接打开 SQLite 并查询 secrets/audit | 删除 P0 Dashboard；后续 UI 只能调用 Admin API |
| Errors | library 大量使用 `anyhow`; warning 后继续审计失败 | library 使用 typed error；关键审计失败阻止执行 |
| Tests | 现有 integration 明确断言 raw secret getter | 删除旧测试，改为“无法读取 Secret”的合同测试 |
| Legacy docs | 2026-04-01 设计描述 single-process/single-port/MITM | 标记 superseded，不作为 v2 行为来源 |

当前工程属于“边界删除 + 边界重建”，不是增量扩展。现有 AES、Argon2、rusqlite、Tokio、Reqwest 依赖可以复用；现有状态所有权、公开 API 和运行时结构不复用。

## 4. Reference Models Considered

| Reference | Borrow | Do not copy | Source |
| --- | --- | --- | --- |
| 1Password SSH Agent | 客户端请求操作而不是读取私钥；授权与 key use 分离 | 密码库 UI、浏览器扩展、账户订阅和消费者同步 | [SSH Agent](https://www.1password.dev/ssh/agent) |
| OpenBao | Seal/unseal、根密钥包装、租约和动态凭据的边界经验 | 通用 secrets engine、插件生态、Raft/HA、Vault API 兼容 | [OpenBao](https://openbao.org/docs/next/what-is-openbao/) |
| RFC 9106 | Argon2id、16-byte salt、64 MiB/3-pass 低内存推荐配置 | 2 GiB 默认配置和服务端并发认证复杂度 | [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html) |
| NIST SP 800-38D | AES-GCM AAD 和 IV 唯一性要求 | 自行实现 AES/GHASH 或宣称 FIPS validation | [NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final) |
| SQLite WAL | 原子事务、单写者、WAL 文件作为持久状态的一部分 | 网络文件系统、NORMAL durability、跨节点复制 | [SQLite WAL](https://www.sqlite.org/wal.html) |
| secrecy/zeroize | 显式 expose、默认禁止 Serialize、Drop zeroize | 把 zeroize 宣称为 mlock、进程转储或内核防护 | [secrecy](https://docs.rs/secrecy/latest/secrecy/) |
| Tokio/Tower 思路 | Runtime 拥有生命周期；transport error 只在边界映射 | 自定义 executor、无必要的 middleware 泛型和 `poll_ready` 复杂度 | [Tokio Runtime](https://docs.rs/tokio/latest/tokio/runtime/) |
| rustls 风格 | 安全配置完整验证后构造；危险能力显式隔离 | TLS 状态机和 type-state 复杂度复制到普通 CRUD | [rustls](https://docs.rs/rustls/latest/rustls/) |

## 5. Chosen Shape

主要状态所有权模型：

> `AuthorityWorker` 是唯一持有 SQLite write connection、解锁后的 VRK 和 Credential mutation 权限的服务实例；其他组件只能发送 typed command，网络 Executor 最多短暂消费一次 opaque `PreparedCredential`。该类型因 Executor 位于独立 crate 而公开，但字段和构造器不公开，Agent IPC 无法获得。

~~~text
product/app
  rekey CLI
  process bootstrap
  human-readable diagnostics

core/domain
  typed IDs
  Credential/Version/Action/Capability models
  invariants and typed errors
  no IO, Tokio, HTTP, SQLite, env, filesystem

runtime/application
  BrokerRuntime
  AuthorityWorker state machine
  SessionRegistry
  AdminService
  AgentService
  ActionExecutor
  shutdown/lock/drain lifecycle

adapters/backends
  SQLiteRecordStore
  PasswordKeyWrapper
  RecoveryKeyWrapper
  UnixAdminTransport
  UnixAgentTransport
  ReqwestUpstreamTransport
  SystemClock / SecureRandom

plugins/components
  none in P0
  future CredentialSource and OperationProvider are not created yet

testing/headless
  tempdir SQLite (real pragmas and durable semantics)
  bounded real durations / SecureRandom
  FakeUpstreamTransport
  IPC harness
  secret canary and compile-time negative assertions
~~~

## 6. Trust Boundaries

~~~text
Human/Admin process
  | hidden TTY input
  | Admin IPC: mutate, unlock, session creation
  v
+--------------------- Broker trust boundary ----------------------+
| AdminService -> AuthorityHandle -> AuthorityWorker               |
|                       | SQLite + VRK                             |
| AgentService -> SessionRegistry -> ActionExecutor                |
|                                      | PreparedCredential        |
|                                      v                           |
|                              fixed upstream HTTPS                |
+------------------------------------------------------------------+
  ^                                      |
  | Agent IPC: capability + ActionId      | sanitized response
  |
Agent/harness/subprocesses
~~~

P0 信任假设：

- Broker、宿主用户、宿主内核、Rust 依赖、SQLite 和 TLS implementation 可信。
- Agent 不可信，但 P0 默认与 Broker 同一 OS 用户，因此只声明 G1。
- Admin 输入发生在 Agent 不控制的终端。若 Agent 能键盘记录、ptrace 或读取同用户进程内存，P0 不提供 G2。
- 磁盘离线攻击者可以读取数据库和 metadata，但没有 password/recovery material 时不能解密 Credential payload。

## 7. Workspace And File Ownership

P0 目标 workspace：

~~~text
crates/
  rekey-domain/
    src/ids.rs
    src/credential.rs
    src/action.rs
    src/capability.rs
    src/error.rs
    src/lib.rs

  rekey-vault/
    src/authority.rs
    src/command.rs
    src/crypto/aad.rs
    src/crypto/aead.rs
    src/crypto/kdf.rs
    src/crypto/keys.rs
    src/crypto/mod.rs
    src/model.rs
    src/store/mod.rs
    src/store/sqlite.rs
    src/store/schema.rs
    src/secret.rs
    src/lib.rs

  rekey-broker/
    src/runtime.rs
    src/admin_service.rs
    src/agent_service.rs
    src/session.rs
    src/action_registry.rs
    src/executor.rs
    src/upstream.rs
    src/ipc/frame.rs
    src/ipc/admin.rs
    src/ipc/agent.rs
    src/ipc/peer.rs
    src/ipc/mod.rs
    src/audit.rs
    src/lib.rs

  rekey-cli/
    src/commands/init.rs
    src/commands/serve.rs
    src/commands/unlock.rs
    src/commands/lock.rs
    src/commands/credential.rs
    src/commands/action.rs
    src/commands/session.rs
    src/commands/execute.rs
    src/commands/backup.rs
    src/commands/restore.rs
    src/commands/status.rs
    src/commands/shutdown.rs
    src/commands/mod.rs
    src/client.rs
    src/config.rs
    src/main.rs

tests/
  authority_blackbox.rs
  broker_ipc.rs
  fixed_http_action.rs
  secret_canary.rs
~~~

P0 删除：

- `crates/rekey-ca/`
- `crates/rekey-web/`
- `crates/rekey-proxy/`
- 旧 `rekey-vault/src/{audit,crypto,db,providers,rules,secrets}.rs`
- 旧 CLI `cmd_add`、`cmd_store`、`cmd_request`、`cmd_env`、`cmd_dashboard`、`cmd_start` 等直接状态路径
- 旧 `tests/integration.rs`

不创建 archive、legacy、compat 或 v1 module；历史由 Git 保存。

## 8. Domain Model

### 8.1 Typed IDs

所有 ID 使用 128-bit 随机 UUID v4 的 16-byte canonical binary form。领域层使用 newtype，禁止交叉传错：

~~~rust
pub struct VaultId(Uuid);
pub struct CredentialId(Uuid);
pub struct ActionId(Uuid);
pub struct SessionId(Uuid);
pub struct RequestId(Uuid);
pub struct WrapperId(Uuid);
~~~

要求：

- `Display` 输出小写 hyphenated UUID。
- `FromStr` 严格解析 canonical UUID，不接受空值或隐式截断。
- SQLite 存储 16-byte BLOB，不存随机字符串。
- Agent request 只能引用 ID，不能通过 label 模糊查找。

### 8.2 Credential

~~~rust
pub struct CredentialMetadata {
    pub id: CredentialId,
    pub label: CredentialLabel,
    pub kind: CredentialKind,
    pub state: CredentialState,
    pub current_version: u64,
    pub created_at: Timestamp,
    pub updated_at: Timestamp,
}

pub enum CredentialKind {
    OpaqueToken,
    GitHubAppInstallation,
}

pub enum CredentialState {
    Active,
    Revoked,
}
~~~

P0 只实现 `OpaqueToken`。P2.1 新增独立的 `GitHubAppInstallation` kind；它不是
`OpaqueToken` 的 payload 约定。kind 必须进入 credential payload AAD，generic add/rotate
只能创建或轮换 `OpaqueToken`，不能创建、覆盖或降级 GitHub App credential。Basic Auth、
OAuth Refresh Token、SSH key 和多字段自定义 Header 在类型和安全语义明确后进入后续版本；
不再用 `HashMap<String, String>` 表示任意秘密。

`CredentialLabel`：

- UTF-8，1–128 Unicode scalar values。
- 去除首尾空白后不能为空。
- 不允许 control character、换行、NUL。
- 仅用于管理员显示，不进入 Agent authorization。
- P0 明文存储；文档明确 metadata confidentiality 不在 P0 保证内。

### 8.3 CredentialVersion

~~~rust
pub struct CredentialVersionMetadata {
    pub credential_id: CredentialId,
    pub version: u64,
    pub state: VersionState,
    pub created_at: Timestamp,
    pub aad_version: u16,
    pub crypto_suite: CryptoSuite,
}

pub enum VersionState {
    Active,
    Retired,
    Revoked,
}
~~~

规则：

- version 从 1 开始、只增不减。
- 每次 rotate 创建新行、新 DEK、新 nonce；旧版本变成 `Retired`。
- revoke Credential 会阻止所有版本继续生成 Lease。
- P0 不提供 hard delete；避免破坏审计引用和制造错误的安全删除承诺。
- 当前版本更新和旧版本 retirement 在一个 SQLite transaction 内完成。

### 8.4 FixedHttpAction

~~~rust
pub struct FixedHttpAction {
    pub id: ActionId,
    pub name: ActionName,
    pub version: u64,
    pub enabled: bool,
    pub credential_id: CredentialId,
    pub origin: HttpsOrigin,
    pub method: FixedMethod,
    pub exact_path: ExactPath,
    pub auth: HeaderCredentialUse,
    pub request_policy: RequestPolicy,
    pub response_policy: ResponsePolicy,
}

pub struct HeaderCredentialUse {
    pub header_name: HeaderName,
    pub prefix: HeaderPrefix,
}
~~~

约束：

- origin 必须是 `https://host[:port]`，无 userinfo、query、fragment 和 path。
- method P0 支持 GET、POST、PUT、PATCH、DELETE；不能由 Agent 覆盖。
- path 必须以 `/` 开头且是 exact path；不能包含 scheme、host、`..` 或 percent-encoded path separator。
- auth header 由 Admin 定义，默认只允许 `authorization`、`x-api-key` 和显式 allowlist；拒绝 hop-by-hop、host、cookie、content-length。
- prefix 只能是空串或可打印 ASCII + 单个尾随空格，最大 32 bytes；不能包含 CR/LF/NUL。
- redirect 永远 disabled。
- Action mutation 创建新 version；已有 session 固定 Action version。

### 8.5 Capability Session

~~~rust
pub struct SessionGrant {
    pub id: SessionId,
    pub allowed_actions: NonEmptySet<ActionVersionRef>,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub max_uses: u32,
}
~~~

Capability token：

- 32 random bytes，base64url-no-pad 传输。
- base64url token 可能以 `-` 开头；CLI 的 `--capability TOKEN` 必须把这种值作为参数值，
  不能误解析为 flag。单独的 `-` 保留为从 stdin 读取 token 的显式入口。
- Broker 内只保存 SHA-256(token) 和 SessionGrant；比较使用 constant-time equality。
- 最大 TTL P0 为 24h，默认 1h。
- `max_uses` 范围 1–10,000，默认 100。
- restart、lock、shutdown 立即撤销所有 session。
- 每个 Agent request 必须包含 token、ActionId、Action version、RequestId。
- token 是短期权能，允许交给 Agent；它不能用于 Admin API 或读取 Secret。

## 9. Cryptographic Design

### 9.1 CryptoSuite v1

~~~text
suite_id              = "rkca-aes256gcm-argon2id-hkdfsha256-v1"
password KDF          = Argon2id v=0x13
memory                = 65536 KiB
iterations            = 3
parallelism           = 4
salt                   = 16 random bytes
KEK/VRK/DEK length     = 32 bytes
AEAD                  = AES-256-GCM
AEAD nonce             = 12 random bytes
AEAD tag               = 16 bytes (crate output included in ciphertext)
recovery KDF           = HKDF-SHA-256
token hash             = SHA-256
random source          = OS CSPRNG
~~~

Argon2 parameters来自 RFC 9106 的 64 MiB second recommended profile。参数完整持久化到 wrapper row，未来可以新增 wrapper 重新包装 VRK；不能在打开旧 row 时用编译期默认覆盖持久化参数。读取持久化参数时必须校验上下限（memory 8 KiB..=256 MiB，iterations 1..=16，parallelism 1..=8）；越界视为 `StorageIntegrityFailed`，不得交给 Argon2 实现去分配极端内存。

持久化的密码格式标识是必须在打开 vault 时一次验证的可信边界，不得等到某条记录被解密时才检查。打开顺序是 SQLite `quick_check`、受控的必需表 layout probe、全表 discriminator 校验、header/schema digest 校验；空库或缺表是 `UnsupportedVaultLayout`，SQLite 完整性、已违反当前 schema CHECK 的 discriminator 或 discriminator query 失败是 `StorageIntegrityFailed`。`vault_header.crypto_suite` 和每条 `credential_versions.crypto_suite` 必须是 text 且精确为上述 suite ID，`credential_versions.aad_version` 必须是 integer 1，每条 password/recovery wrapper 的 `kdf_algorithm` 必须是 text 且分别为 `argon2id` / `hkdf-sha256`。NULL、错误 SQLite storage class 和未知值都必须用 null-safe comparison 失败；不得依赖 `!=` / `NOT` 的 NULL 三值逻辑。任一 active、disabled、retired 或 revoked row 出现未知 suite、algorithm 或 version，整个 vault 必须 fail closed：未先被 schema integrity 拒绝的值以 `UnsupportedFormatVersion` 拒绝；不得把未知值按当前 suite 重新解释。

### 9.2 Key Hierarchy

~~~text
Password
  + password_salt + persisted Argon2 params
  -> Password KEK

RecoveryKey (32 random bytes)
  + recovery_salt + info="rekey/recovery-kek/v1"
  -> Recovery KEK

Password KEK  --AES-GCM--> wrapped VRK row A
Recovery KEK  --AES-GCM--> wrapped VRK row B

VRK --AES-GCM--> wrapped DEK per CredentialVersion
DEK --AES-GCM--> encrypted OpaqueToken payload
~~~

`rekey init`：

1. 创建空 state directory 并持有 exclusive bootstrap lock。
2. 生成 VaultId、VRK、password salt、recovery key、recovery salt。
3. 派生两个 KEK。
4. 用独立 nonce 分别包装同一个 VRK。
5. 在单 transaction 中写入 header 和两个 wrapper。
6. 重新读取并分别验证两个 wrapper 都能恢复同一 VRK。
7. commit 后 zeroize VRK、KEK 和 password input。
8. 只在交互 TTY 显示 recovery key 一次；要求用户确认已保存最后 6 个字符。确认失败视为 init 失败：丢弃本次写入的 vault 文件（含已 commit 的 SQLite），不得留下可启动的 vault。`--password-stdin` 自动化路径跳过 TTY 确认，调用方必须自行离线保存 recovery key。

若任何步骤失败（含确认失败），不得留下可 `serve` 的半初始化或已初始化目录。

### 9.3 AAD Canonical Encoding

禁止使用 JSON、Debug string 或字段拼接作为 AAD。`AadV1` 使用固定顺序、固定宽度、big-endian binary encoding：

~~~text
magic               4 bytes  "RKAD"
aad_version         u16      1
purpose             u16      1=wrap-vrk, 2=wrap-dek, 3=credential-payload, 4=vault-integrity
vault_id            16 bytes
object_id           16 bytes WrapperId or CredentialId
object_version      u64
credential_kind     u16      0 for non-credential purpose
crypto_suite_id     u16      1
constraints_hash    32 bytes SHA-256(canonical constraint bytes), zero for P0 payload
~~~

总长度固定 84 bytes。encoder 是纯函数，使用 golden byte vector 和 property test。任何字段变化都会导致 AEAD authentication failure。

用途映射：

- wrap-vrk：object_id=WrapperId，object_version=1。
- wrap-dek：object_id=CredentialId，object_version=CredentialVersion。
- credential-payload：同 CredentialId/version，kind=OpaqueToken。

### 9.4 Nonce Strategy

- 每次 AEAD 操作从 OS CSPRNG 生成新的 96-bit nonce。
- 同一 CredentialVersion 的 payload 使用唯一新 DEK，降低 payload nonce 重用后果。
- VRK 会包装多个 DEK，因此 wrapper nonce 唯一性必须由 random source 和测试保证。
- nonce 与 ciphertext 持久化；不得从时间戳、UUID、计数器复用或截断产生。
- CSPRNG failure 是 fatal `EntropyUnavailable`，不降级。
- 不允许调用者传入 nonce；只有 crypto adapter 可以生成。

### 9.5 Recovery Key Encoding

- 原始 32 bytes random key。
- 显示为分组 uppercase base32，附加 4-byte checksum，格式版本前缀 `RKREC1-`。
- parser 忽略 ASCII `-` 和空格，但严格检查版本、长度和 checksum。
- recovery key 不写数据库、配置、日志或 telemetry；数据库只存 salt 和 wrapped VRK。
- `recover` 成功后立即创建新 password wrapper，并禁用旧 password wrapper；recovery wrapper 默认保持有效。

### 9.6 Secret Memory Types

~~~rust
pub struct RootKey(SecretBox<[u8; 32]>);
pub struct DataKey(SecretBox<[u8; 32]>);
pub struct SecretInput(SecretBox<[u8]>);

pub struct PreparedCredential {
    bytes: Zeroizing<Vec<u8>>,
    credential_id: CredentialId,
    version: u64,
}
~~~

要求：

- 不实现 `Clone`、`Copy`、`Serialize`、`Display`。
- `PreparedCredential` 只为 `rekey-vault` → `rekey-broker` trust boundary
  公开；字段与构造器保持非公开，只暴露 consume-once closure。
- `Debug` 只输出类型名和 `[REDACTED]`，不输出长度或 prefix。
- Secret buffer 在分配时预设准确 capacity，避免 reallocation copies。
- 暴露 Secret 只能出现在 crypto 或 executor 的最小 lexical scope。
- compile-time negative assertion 验证 Secret 类型未实现禁止 trait。
- 文档明确 zeroize 不能清理寄存器、内核 socket buffer、allocator 历史副本或进程转储；P0 不宣称 mlock。

## 10. Persistent Storage

### 10.1 State Directory

~~~text
~/.rekey/
  vault.sqlite3       mode 0600
  vault.sqlite3-wal   mode 0600 when present
  vault.sqlite3-shm   mode 0600 when present
  broker.lock         mode 0600
  runtime/            mode 0700
    admin.sock        mode 0600
    agent.sock        mode 0600 in P0
~~~

state directory mode 0700。启动时发现 group/world permission 更宽，返回 `InsecureStatePermissions`，不自动 chmod 掩盖管理员错误。

P0 不读取 v1 `vault.db`。若 `~/.rekey` 非空但不存在合法 v2 header，`init` 返回 `StateDirectoryNotEmpty`；`serve` 返回 `UnsupportedVaultLayout`。不自动删除、迁移或覆盖现有数据。

### 10.2 SQLite Connection Contract

AuthorityWorker 持有唯一 read/write connection。配置必须逐项验证返回值：

~~~sql
PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA synchronous = FULL;
PRAGMA trusted_schema = OFF;
PRAGMA secure_delete = ON;
PRAGMA busy_timeout = 5000;
~~~

说明：

- WAL、SHM 和主数据库共同构成持久状态；备份不能直接 `cp vault.sqlite3`。
- `synchronous=FULL` 用于凭据 mutation 和审计 durability。
- `secure_delete=ON` 只作为纵深防御；不宣称能抵御 SSD wear leveling 或所有 forensic recovery。
- 不允许其他进程打开 SQLite；Admin/Web 读取也通过 AuthorityWorker。
- 每次启动运行 `PRAGMA quick_check`；失败后保持 Locked 并返回 `StorageIntegrityFailed`。

### 10.3 Schema v4

~~~sql
CREATE TABLE vault_header (
    singleton          INTEGER PRIMARY KEY CHECK (singleton = 1),
    format_version     INTEGER NOT NULL CHECK (format_version = 4),
    vault_id           BLOB NOT NULL CHECK (length(vault_id) = 16),
    crypto_suite       TEXT NOT NULL CHECK (crypto_suite = 'rkca-aes256gcm-argon2id-hkdfsha256-v1'),
    created_at_ms      INTEGER NOT NULL,
    schema_digest      BLOB NOT NULL CHECK (length(schema_digest) = 32),
    integrity_nonce    BLOB NOT NULL CHECK (length(integrity_nonce) = 12),
    integrity_ciphertext BLOB NOT NULL
) STRICT;

CREATE TABLE key_wrappers (
    wrapper_id         BLOB PRIMARY KEY CHECK (length(wrapper_id) = 16),
    wrapper_kind       TEXT NOT NULL CHECK (wrapper_kind IN ('password', 'recovery')),
    state              TEXT NOT NULL CHECK (state IN ('active', 'disabled')),
    kdf_algorithm      TEXT NOT NULL CHECK (
        (wrapper_kind = 'password' AND kdf_algorithm = 'argon2id') OR
        (wrapper_kind = 'recovery' AND kdf_algorithm = 'hkdf-sha256')
    ),
    kdf_params_json    TEXT NOT NULL,
    salt               BLOB NOT NULL,
    nonce              BLOB NOT NULL CHECK (length(nonce) = 12),
    wrapped_vrk        BLOB NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    disabled_at_ms     INTEGER
) STRICT;

CREATE UNIQUE INDEX one_active_password_wrapper
ON key_wrappers(wrapper_kind) WHERE wrapper_kind = 'password' AND state = 'active';

CREATE TABLE credentials (
    credential_id      BLOB PRIMARY KEY CHECK (length(credential_id) = 16),
    label              TEXT NOT NULL UNIQUE,
    kind               TEXT NOT NULL CHECK (kind IN ('opaque-token', 'github-app-installation')),
    state              TEXT NOT NULL CHECK (state IN ('active', 'revoked')),
    current_version    INTEGER NOT NULL CHECK (current_version >= 1),
    created_at_ms      INTEGER NOT NULL,
    updated_at_ms      INTEGER NOT NULL,
    revoked_at_ms      INTEGER
) STRICT;

CREATE TABLE credential_versions (
    credential_id      BLOB NOT NULL REFERENCES credentials(credential_id),
    version            INTEGER NOT NULL CHECK (version >= 1),
    state              TEXT NOT NULL CHECK (state IN ('active', 'retired', 'revoked')),
    aad_version        INTEGER NOT NULL CHECK (aad_version = 1),
    crypto_suite       TEXT NOT NULL CHECK (crypto_suite = 'rkca-aes256gcm-argon2id-hkdfsha256-v1'),
    dek_nonce          BLOB NOT NULL CHECK (length(dek_nonce) = 12),
    wrapped_dek        BLOB NOT NULL,
    payload_nonce      BLOB NOT NULL CHECK (length(payload_nonce) = 12),
    encrypted_payload  BLOB NOT NULL,
    created_at_ms      INTEGER NOT NULL,
    retired_at_ms      INTEGER,
    PRIMARY KEY (credential_id, version)
) STRICT;

CREATE UNIQUE INDEX one_active_version_per_credential
ON credential_versions(credential_id) WHERE state = 'active';

CREATE TABLE actions (
    action_id           BLOB NOT NULL CHECK (length(action_id) = 16),
    version             INTEGER NOT NULL CHECK (version >= 1),
    name                TEXT NOT NULL,
    state               TEXT NOT NULL CHECK (state IN ('active', 'retired', 'disabled')),
    credential_id       BLOB NOT NULL REFERENCES credentials(credential_id),
    origin              TEXT NOT NULL,
    method              TEXT NOT NULL,
    exact_path          TEXT NOT NULL,
    auth_header         TEXT NOT NULL,
    auth_prefix         TEXT NOT NULL,
    request_max_bytes   INTEGER NOT NULL,
    response_max_bytes  INTEGER NOT NULL,
    timeout_ms          INTEGER NOT NULL,
    created_at_ms       INTEGER NOT NULL,
    PRIMARY KEY (action_id, version)
) STRICT;

CREATE UNIQUE INDEX one_active_action_version
ON actions(action_id) WHERE state = 'active';

CREATE TABLE audit_events (
    sequence            INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            BLOB NOT NULL UNIQUE CHECK (length(event_id) = 16),
    request_id          BLOB CHECK (request_id IS NULL OR length(request_id) = 16),
    session_id          BLOB CHECK (session_id IS NULL OR length(session_id) = 16),
    action_id           BLOB CHECK (action_id IS NULL OR length(action_id) = 16),
    action_version      INTEGER,
    credential_id       BLOB CHECK (credential_id IS NULL OR length(credential_id) = 16),
    credential_version  INTEGER,
    principal_id        BLOB CHECK (principal_id IS NULL OR length(principal_id) = 16),
    policy_version      INTEGER,
    policy_digest       BLOB CHECK (policy_digest IS NULL OR length(policy_digest) = 32),
    policy_rule_id      BLOB CHECK (policy_rule_id IS NULL OR length(policy_rule_id) = 16),
    resource_type       TEXT,
    resource_id         TEXT,
    parameter_hash      BLOB CHECK (parameter_hash IS NULL OR length(parameter_hash) = 32),
    event_type          TEXT NOT NULL,
    outcome             TEXT NOT NULL,
    reason_code         TEXT NOT NULL,
    upstream_status     INTEGER,
    latency_ms          INTEGER,
    created_at_ms       INTEGER NOT NULL,
    CHECK (
        (principal_id IS NULL AND policy_version IS NULL AND policy_digest IS NULL
            AND policy_rule_id IS NULL AND resource_type IS NULL
            AND resource_id IS NULL AND parameter_hash IS NULL)
        OR
        (principal_id IS NOT NULL AND policy_version >= 1 AND policy_digest IS NOT NULL
            AND resource_type IS NOT NULL AND resource_id IS NOT NULL
            AND parameter_hash IS NOT NULL)
    )
) STRICT;

CREATE UNIQUE INDEX one_execution_started_per_request
ON audit_events(request_id) WHERE event_type = 'execution.started';

CREATE UNIQUE INDEX one_execution_terminal_per_request
ON audit_events(request_id)
WHERE event_type IN ('execution.finished', 'execution.blocked');
~~~

schema SQL 是唯一来源；`schema_digest` 是规范化 schema 文件的 SHA-256，用于发现意外 schema drift，不作为恶意管理员防篡改证明。

### 10.4 Transaction Invariants

- add Credential：insert credentials + version 1 + audit event，一个 transaction。
- rotate：insert N+1 + retire N + update current_version + audit，一个 transaction。
- revoke 的 SQLite transaction 只原子提交 credential state、active version state 和 audit。commit 后、Admin 成功响应前，Broker 同步失效所有引用该 Credential 的内存 session；若内存失效失败，Broker 进入 Faulted。两类状态不能伪装成同一数据库事务。即使 session 清理发生故障，每次 Lease 解析仍重新检查持久化 credential state，因此已撤销 Credential 不能产生新 Lease；已经发出的 in-flight Lease 只运行到原有 deadline，P0 不承诺远程撤回已发出的上游请求。
- action create/update：新 version + retire 旧 version + audit，一个 transaction。
- capability session 不持久化；Broker restart 全部失效。
- execution started audit commit 成功后才能请求 Credential Lease 和调用上游。
- execution finished audit 失败时不把上游成功伪装成 Rekey 成功；返回 `AuditCommitFailedAfterExecution` 并产生 stderr fatal diagnostic。

## 11. Authority Runtime

### 11.1 Worker Model

`AuthorityWorker` 运行在专用 blocking thread，独占：

- `rusqlite::Connection`
- `AuthorityState`
- VRK
- unlock rate limiter
- schema and integrity status

Tokio tasks 只持有 cloneable `AuthorityHandle`，内部是 bounded MPSC sender。每个 command 带 oneshot reply。队列默认 128；队列满返回 `AuthorityBusy`，不能无限积压包含 SecretInput 的请求。

### 11.2 State Machine

BrokerRuntime 是 idle / explicit lock / shutdown 的唯一协调者。AuthorityWorker 只持有密码学状态（Locked / Unlocked / Faulted），不单独决定 Session 命运。

~~~text
Worker:
  Uninitialized
    init offline -> Locked
  Locked
    unlock success -> Unlocked
    unlock failure -> Locked + backoff
    shutdown -> Stopped
  Unlocked
    broker drain complete -> Locked (VRK zeroized)
    integrity/crypto fatal -> Faulted
  Faulted
    reject all except status/shutdown
    -> Stopped

Broker:
  Locked (startup default; session registry closed)
    unlock success -> Running
    shutdown -> ShuttingDown -> Stopped
  Running
    idle timeout / explicit lock -> Draining -> Locked
    shutdown -> ShuttingDown -> Stopped
  Draining
    single coordinator (idle / explicit lock / shutdown share one mutex)
    1. set phase Draining; refuse SessionCreate, unlock, credential/action
       mutations, and new execute (no new execution.started)
    2. close the session registry and revoke every Session (tokens never
       resurrect after a later unlock)
    3. already-admitted executions continue to their existing deadline
    4. wait in-flight executions (cap = Action timeout hard max, 120s)
    5. if any remain, signal cancel; execute's async abandoned branch must
       commit a terminal audit before returning
    6. wait until every started row has a committed terminal event;
       wait_idle must return Result. Timeout with pending terminals, or a
       swallowed commit error, is not success.
    7. if in-flight executions remain after cancel, lock/shutdown must not
       proceed. If terminals failed to commit, lock may still zeroize VRK
       but must return AuditCommitFailed (not a successful lock). Shutdown
       must not stop the Authority worker while terminal rows are still
       queued.
    8. then worker lock (zeroize VRK) and enter Locked; registry stays closed
  ShuttingDown
    same drain as above, then stop the worker; never return to Running
~~~

The retained cancellation value belongs only to the current Running-to-Draining
epoch. It must remain set while that drain still has an in-flight execution, but
after the drain proves in-flight is zero and successfully enters Locked, the
transition must synchronously reset the retained value even when no cancellation
receiver exists. A later unlock starts a fresh Running epoch whose newly admitted
executions observe cancellation as false; a busy drain that remains Draining must
not reset it.

`SessionRegistry::begin` 为每一次执行返回 RAII permit；Drop 必须释放并发槽，不能依赖成功路径上的手工 `finish()`。创建 Session 与 `close_and_revoke_all` 必须共享同一把 registry 锁，避免 revoke 之后再 mint。

一旦 `execution.started` 提交成功：同一内部 audit ID 必须恰好有一个 terminal 事件（`execution.finished` 或 `execution.blocked`）。terminal 必须在第一次 await 前把唯一提交所有权同步转移给独立 audit worker；调用任务随后被取消也不能取消该 durable commit，`StartedGuard::drop` 也不能再次提交 terminal。worker 的 commit error 或未排空状态必须由 tracker 阻止后续 lock/shutdown 被报告为成功。只有尚未转移 terminal 所有权的 Drop/panic 路径才提交 `blocked/abandoned`；worker 在 Authority shutdown 之前必须排空。进程重启后内存 Session 全部作废；启动时扫描无 terminal 的 started，**追加** `execution.blocked(abandoned-on-restart)`，不改写原 started 行。

状态转换不通过多个 `Arc<RwLock<MasterKey>>` 或单独的 `AtomicBool draining` 隐式完成。

### 11.3 Idle Lock

- 默认 idle timeout 15 minutes，可在 startup config 设置 1–120 minutes。
- 成功的 Admin command 或 Agent execution completion 更新 worker activity；Broker 读取该时钟并走与 explicit lock 相同的 Draining 路径。
- 正在执行的 Action 不被 idle timer 中途清除 credential：进入 Draining 后不接受新请求，但已获得 permit 的请求继续到其既有 deadline，然后才 zeroize VRK。
- 上游 Action P0 最大 timeout 120 seconds；Draining 等待上限与此相同。
- 显式 lock 等待 in-flight 到其既有 deadline，不生成新重试；完成后 zeroize。

### 11.4 Unlock Rate Limiting

- 前 3 次失败无额外延迟。
- 第 4 次开始指数 backoff，1s、2s、4s，最大 30s。
- 成功 unlock 清零失败计数。
- 返回统一 `InvalidUnlockCredential`，不泄漏 wrapper 是否存在或 AEAD 失败细节。
- 进程重启会重置内存计数；P0 不声称抵御本地高速离线或反复重启攻击，安全仍依赖 Argon2id 和强密码。

## 12. IPC Contract

### 12.1 Endpoints

| Endpoint | Socket | Purpose | Peer rule |
| --- | --- | --- | --- |
| Admin | `runtime/admin.sock` | unlock、Credential/Action/session、backup、lock、shutdown | UID 必须等于 state owner；mutation 另需 step-up proof |
| Agent | `runtime/agent.sock` | execute fixed Action、status subset | UID allowlist + valid Capability |

P0 两个 socket 都是 mode 0600。Linux 使用 `SO_PEERCRED`，macOS 使用 `getpeereid` 获取 peer UID；失败时拒绝，不使用客户端自报 UID。

P1 Linux G2 reference deployment keeps the Admin endpoint under the private
state runtime directory, but may place the Agent endpoint in a separate runtime
directory that is the only Broker path mounted into the Agent sandbox. Its
contract is deliberately small:

- no flags keeps the P0 topology, mode 0600, and current Broker UID as the only
  allowed Agent peer;
- an isolated Agent endpoint requires an explicit non-empty Agent UID allowlist;
- its resolved path must be disjoint from the resolved state tree: relative
  paths, `..`, symlink aliases, descendants, and ancestors that overlap the
  state tree are rejected before directory permissions are changed;
- optional group sharing uses a Broker-owned directory at mode 0770 and a
  socket at mode 0660; mode 0666 is forbidden;
- peer identity always comes from `SO_PEERCRED`; a claimed UID in an IPC frame
  is never accepted;
- directory ownership, group assignment, permission application, or an empty
  allowlist failure aborts startup rather than falling back to the P0 endpoint;
- the Agent sandbox never receives the state directory, Admin socket, Docker
  socket, or unrestricted egress.

The reference attack harness runs the Broker as a non-root Linux UID and an
Agent attacker as root in a separate container with all capabilities dropped,
`no-new-privileges`, a read-only root filesystem, separate PID/mount/network
namespaces, and an internal-only network. It must prove state/Admin/Docker
socket denial, peer-UID denial, direct-egress denial, and one real capability-
authorized execution. Passing this harness establishes only the documented
container/namespace G2 reference boundary; it does not claim resistance to a
Docker daemon, Linux kernel, VM host, or container-runtime compromise.

### 12.2 Frame v1

~~~text
magic          4 bytes  "RKIP"
version        u16      1
channel        u8       1=admin, 2=agent
flags          u8
message_type   u16
reserved       u16      must be zero
request_id     16 bytes
metadata_len   u32 big-endian
body_len       u32 big-endian
metadata       UTF-8 JSON, no secret fields
body           raw bytes
~~~

限制：

- metadata <= 64 KiB。
- Admin secret body <= 64 KiB。
- Agent request body <= Action `request_max_bytes` 且全局 <= 1 MiB。
- response body <= Action `response_max_bytes` 且全局 <= 4 MiB。
- P0 `flags` 必须为 zero；任何非 zero flag 都按 unknown frame 处理。
- unknown version/type、nonzero reserved、长度溢出、truncated frame、额外尾随数据全部显式拒绝并关闭连接。
- 每个连接同一时间最多一个 in-flight frame；P0 不做 multiplexing。
- socket 上接收请求帧、发送响应帧的单次 IO inactivity deadline 为 30s；它不等于
  Broker 处理请求的总时限。CLI 等待 Execute、lock/shutdown、backup 的响应上限分别为
  130s、130s、300s，覆盖 120s Action hard max、125s central stop deadline 和大文件
  流式备份，同时仍保持有界等待。
- 客户端只接受与请求完全相同的 `channel` 和 `request_id`；ErrorEnvelope 的
  `request_id` 还必须与 frame header 相同。任何错配都返回 `INVALID_FRAME`。
- 客户端必须在分配 response buffer 之前执行 64 KiB metadata / 4 MiB body
  上限检查。Error response 的 body 必须为空。
- Frame `request_id` 只用于该连接上的请求/响应关联，是不可信的客户端输入；
  每次 Execute 进入 Broker 后必须生成新的内部 execution audit ID。客户端提供
  的 ID 不得写入 audit，也不得参与 started/terminal 配对或重启 reconciliation。
- 所有 typed metadata DTO 使用 strict JSON object；unknown field 必须拒绝，
  不能由 serde 默认忽略。Broker 序列化 response 失败必须显式失败，不能降级成 `{}`。

### 12.3 Admin Messages

| Message | Locked allowed | Step-up proof | Secret body | Response |
| --- | --- | --- | --- | --- |
| Status | yes | no | none | redacted runtime status |
| UnlockPassword | yes | password body | password | unlocked/invalid |
| UnlockRecovery | yes | recovery body | recovery key | unlocked/invalid |
| CredentialAdd | no | password/recovery | token body | CredentialMetadata |
| CredentialList | no | no | none | metadata only |
| CredentialRotate | no | password/recovery | token body | new version metadata |
| CredentialRevoke | no | password/recovery | none | revoked metadata |
| ActionCreate/Update/Disable | no | password/recovery | none | Action metadata |
| SessionCreate/Revoke | no | password/recovery | none | capability token once / receipt |
| Backup | no | password/recovery | none | backup receipt |
| Lock | yes | no | none | locked/draining receipt |
| Shutdown | yes | password/recovery when unlocked | proof body | receipt |

Step-up password/recovery proof 只在 AuthorityWorker 内派生 KEK 并验证 wrapper，成功后立即 zeroize；不能因为 Broker 已 Unlocked 就跳过敏感 mutation 的人类证明。

### 12.4 Agent Messages

P0 只有：

~~~text
ExecuteFixedHttpAction {
  capability_token,
  action_id,
  action_version,
  content_type,
  extra_headers,
  body
}
~~~

`extra_headers` 只能携带该 Action request policy allowlist 内的普通 Header；出现 allowlist 之外或禁止列表内的 Header 时拒绝整个请求，不做静默剥离。

Agent 不能提供：

- URL、origin、host、port、method 或 path。
- Authorization、Proxy-Authorization、Cookie、Host、Content-Length。
- CredentialId、CredentialVersion、Header name、prefix。
- redirect policy、timeout、DNS override、proxy setting。
- 任意文件路径让 Broker 读取 body。

### 12.5 IPC Error Envelope

~~~json
{
  "request_id": "uuid",
  "code": "ACTION_DENIED",
  "message": "action is not allowed for this session",
  "retryable": false
}
~~~

Agent error 只使用稳定 code 和安全 message，不包含 SQLite、crypto、path、secret label 或内部 source chain。Admin CLI 可以在本地 debug mode 显示 redacted source category，但不能打印 Secret 或 unlock material。

## 13. CLI Contract

P0 命令：

~~~text
rekey init [--state-dir PATH]
rekey serve [--state-dir PATH] [--idle-lock 15m]
rekey unlock [--recovery]
rekey lock
rekey status

rekey credential add LABEL
rekey credential list
rekey credential rotate CREDENTIAL_ID
rekey credential revoke CREDENTIAL_ID

rekey action create --file ACTION.json
rekey action update ACTION_ID --file ACTION.json
rekey action list
rekey action disable ACTION_ID

rekey session create --action ACTION_ID@VERSION --ttl 1h --max-uses 100
rekey session revoke SESSION_ID

rekey execute ACTION_ID@VERSION --capability TOKEN [--body-file FILE]

rekey backup --output FILE.rkbackup
rekey restore --input FILE.rkbackup --state-dir EMPTY_PATH --sha256 HEX
rekey shutdown
~~~

输入规则：

- password、recovery key、Credential value 默认使用 hidden TTY prompt。
- 自动化场景仅允许显式 `--password-stdin` / `--secret-stdin`，不提供值参数和环境变量。
- `--body-file` 只在 Agent CLI 进程读取普通 Action body；Broker 不接受文件路径。
- Capability 可以通过参数或 stdin 传递，因为它是短期 Agent 权能；CLI 帮助明确 shell history 风险并推荐 stdin。
- `serve` 前台运行，locked 启动。P0 没有 `--daemon`；systemd/launchd integration 进入 P1。

退出码：

| Code | Meaning |
| --- | --- |
| 0 | success |
| 2 | invalid CLI/config/input |
| 3 | authentication/unlock failure |
| 4 | policy/capability/action denied |
| 5 | storage/crypto/integrity failure |
| 6 | upstream failure |
| 7 | IPC/runtime unavailable |
| 8 | response security violation |

## 14. Action Execution Pipeline

固定顺序，不允许实现者调换：

1. **Frame validation**：验证 magic、version、长度和 channel。
2. **Peer authentication**：读取 OS peer credential。
3. **Capability authentication**：hash token、constant-time lookup、TTL、uses、channel。
4. **Action pinning**：按 `(ActionId, version)` 读取不可变 Action；disabled/retired 对新 session 拒绝。
5. **Request validation**：content-type、body size、允许 Header、UTF-8/JSON 要求按 Action 执行。
6. **ExecutionStarted audit**：commit 后才继续。
7. **Credential eligibility**：Credential 和固定 version 必须 active，Action binding 一致。
8. **Prepare credential**：AuthorityWorker 解包 DEK、解密 payload，构造 opaque cross-crate PreparedCredential。
9. **Build upstream request**：使用 server-owned origin/method/path；清除全部敏感 Header后唯一设置 auth header。
10. **Resolve/connect**：仅 HTTPS；禁止 redirect；限制 connect/request timeout；不使用系统 HTTP proxy env。
11. **Receive bounded response**：超过 limit 立即失败，不截断后返回成功。
12. **Secret sealing**：扫描 payload secret、完整 auth header、base64 standard/url 和 percent-encoded direct variants。
13. **Response filtering**：只返回 allowlisted Header；默认移除 Set-Cookie、WWW-Authenticate、Proxy-Authenticate、Authentication-Info。
14. **ExecutionFinished audit**：记录 outcome、status、latency、CredentialRef/version，不记录内容。
15. **Capability accounting**：原子递减 use count；耗尽后撤销。
16. **Cleanup**：PreparedCredential 和构造出的 auth buffer zeroize。

P0 不自动 retry。任何 retry 必须在未来重新经过 deadline、Capability use 和幂等语义设计。

## 15. Upstream Security Contract

`ReqwestUpstreamTransport` 分两层，生产路径两层都走：

1. **Screen**：DNS resolve + public-unicast allow contract。IPv4 必须是排除专用、保留、文档、multicast 后的公网 unicast。IPv6 默认拒绝，原生地址只允许 IANA IPv6 Global Unicast registry 在 2025-10-10 标记 `ALLOCATED` 的前缀：`2001::/23` 内的明确 global exceptions，`2001:200::/23`、`2001:400::/23`、`2001:600::/23`、`2001:800::/22`、`2001:c00::/23`、`2001:e00::/23`、`2001:1200::/23`、`2001:1400::/22`、`2001:1800::/23`、`2001:1a00::/23`、`2001:1c00::/22`、`2001:2000::/19`、`2001:4000::/23` 至 `2001:4c00::/23` 的已列出 /23、`2001:5000::/20`、`2001:8000::/19`、`2001:a000::/20`、`2001:b000::/20`、`2003::/18`、`2400::/12`、`2410::/12`、`2600::/12`、`2610::/23`、`2620::/23`、`2630::/12`、`2800::/12`、`2a00::/12`、`2a10::/12` 和 `2c00::/12`。`2001::/23` 的 global exceptions 只是 `2001:1::1..3` anycast、`2001:3::/32` AMT、`2001:4:112::/48` AS112、`2001:20::/28` ORCHIDv2 和 `2001:30::/28` DETs；Teredo、benchmarking 和其他保留地址拒绝。`2001:db8::/32`、`3fff::/20`、`2d00::/8`、`2e00::/7`、`3000::/5` 到 `3ffe::/16` 的 IANA reserved/legacy 范围全部拒绝；新 IANA 分配在 spec 和实现显式升级前仍拒绝。另外只允许经内嵌 IPv4 再次通过同一 IPv4 public-unicast 校验的 IPv4-mapped、well-known NAT64 `64:ff9b::/96` 和 6to4 `2002::/16`。DNS 混合答案只要含任一未允许地址就视为 rebinding 并整组拒绝；只从全部通过后的同一组结果选择和 pin 一个 `ScreenedEndpoint`。
2. **Send**：rustls TLS；SNI / URL host / HTTP Host 来自同一 Action；`.resolve` pin 到已筛选地址；redirect policy `none`，**任何 3xx 都映射为 `Blocked("redirect")`**，即使 client 把 3xx 当成最终响应；不读取 `HTTP_PROXY`、`HTTPS_PROXY`、`ALL_PROXY`、`NO_PROXY`；connect timeout <= 10s，总 timeout <= Action timeout 且 <= 120s；超过 response limit 立即失败，不截断成功；不持久化 Cookie；不得缓存 Authorization Header 或完整 RequestBuilder。

Agent 输入 fake 的契约测试仍使用 injected `UpstreamTransport`。第 2 层的 TLS/SNI/redirect/size/read-error 测试使用本地 HTTPS fixture **和注入的 `ScreenedEndpoint`**，不得放宽第 1 层私网规则。

## 16. Backup And Restore

### 16.1 Backup

- 只能由 Unlocked Broker 在 Admin step-up 后执行。
- 使用 SQLite Online Backup API 获取一致快照，不直接复制主 DB。
- 输出只包含 SQLite ciphertext、wrapped keys 和 metadata，不包含 VRK/DEK/plaintext。
- final output 必须在 canonical state tree 之外；相对路径、直接子路径和通过 symlink alias 指回 state tree 的路径一律在 open 前拒绝。SQLite Online Backup 只写 state tree 内的保护性内部 snapshot；不得在 external sibling 生成可预测 tmp。内部 snapshot 是 Rekey 保留路径，必须 create-new + no-follow 打开；它在释放审计前不得离开 protected tree。
- 内部 snapshot fsync 后，必须在任何 external byte 写入前先持久提交 `backup.release_authorized`。该事件是安全边界证据，表示 Authority 已授权一次 ciphertext backup 释放，不表示调用者已收到 receipt。然后以 create-new + no-follow 直接打开 final output，立即对已打开 fd 执行 `fchmod(0600)` 并以 `fstat` 验证，不依赖 umask。用固定大小 buffer 从内部 snapshot 流式复制并同时计算 SHA-256，fsync final 和父目录。backup/restore 不得为 hash 或 copy 将整个文件读入内存。
- final output 在 file fsync + 父目录 fsync + `backup.created` 成功提交前不是成功 backup。external final 一旦 create-new 成功，任何后续普通失败都不得再通过 pathname 自动 unlink，因为 inode 校验与 pathname unlink 无法原子绑定，自动清理可删除替换后的非 Rekey 文件。失败不返回 receipt，只清理 protected internal snapshot；内部清理无法持久化时 Authority 进入 Faulted。跨 SQLite 与 filesystem 不声称原子性：`backup.release_authorized` 之后的失败或 SIGKILL 可能留下 partial 或 complete external file，但必定有先行 release audit，且没有 `backup.created` 或 receipt 成功声明。调用方只能信任已获得 receipt 且 SHA-256 匹配的 artifact；其他遗留文件必须视为未成功、由人工处置的 authorized artifact。
- backup receipt 只在上述成功点后返回，包含 vault_id、format_version、created_at、SHA-256，不含路径外的敏感数据。

### 16.2 Restore

- restore 是离线 bootstrap operation；Broker 必须未运行，目标 state-dir 必须为空。
- 调用方必须提供 backup receipt 的 SHA-256（64 hex）；缺失、格式错误或 mismatch 都失败，不得安装。
- 验证 SQLite quick_check、schema_digest、format_version、至少一个 wrapper 行、VRK 解包、header 内 encrypted integrity record，以及 **每一条** `credential_versions` payload。不能只检查数据库结构或只解密第一条 Credential。
- 在写 staging 前先持久化 incomplete marker；Broker 见到 marker 必须拒绝启动。输入以固定大小 buffer 流式复制到 staging 并同时计算 SHA-256，对 staging 完成上述验证与 `restore.completed` 提交，fsync 文件，rename 到 `vault.sqlite3`，再 fsync 父目录。
- 只有安装文件已持久化后才能删除 marker 并再次 fsync 父目录；这是 restore 成功点。成功点之前的失败必须删除 staging、installed DB 及 SQLite sidecar，并持久化清理；无法证明清理完成时必须保留 marker，确保不留下可启动的半恢复 vault。后续 restore 只能在取得 offline lock 后清理该 marker 所标记的已中断内部 artifact，不得删除未知文件。
- 只恢复 format version 4；不支持 v1/v2/v3 或未来未知版本。

## 17. Error Taxonomy

### 17.1 Domain Errors

`rekey-domain` 使用 `thiserror` 定义稳定、非穷尽错误：

~~~text
InvalidId
InvalidCredentialLabel
InvalidActionDefinition
InvalidCapability
CapabilityExpired
CapabilityExhausted
ActionNotAllowed
CredentialRevoked
ActionDisabled
RequestTooLarge
ResponseTooLarge
~~~

### 17.2 Authority Errors

~~~text
NotInitialized
AlreadyInitialized
Locked
Draining
Faulted
InvalidUnlockCredential
UnlockRateLimited
EntropyUnavailable
CryptoFailure
AuthenticationFailed
StorageUnavailable
StorageIntegrityFailed
UnsupportedVaultLayout
UnsupportedFormatVersion
InsecureStatePermissions
CredentialNotFound
CredentialConflict
CredentialRevoked
ActionNotFound
AuthorityBusy
AuditCommitFailed
BackupFailed
RestoreFailed
~~~

### 17.3 Mapping Rules

- library 公共 API 不返回 `anyhow::Error`。
- adapter source error 只保留在内部 `source()` chain；Display 经过 redaction。
- crypto authentication failure 映射为 `CryptoFailure` 或 `InvalidUnlockCredential`，不输出 nonce/ciphertext/AAD。
- Agent 不区分 Credential missing、revoked 或 decrypt failure，统一 `CREDENTIAL_UNAVAILABLE`。
- storage、audit、crypto、identity 未知错误全部 fail closed。
- 禁止 warning + fallback、默认值 client、透明 passthrough 或无审计继续执行。

## 18. Audit And Observability

### 18.1 Audit Events

P0 event types：

~~~text
vault.initialized
vault.unlocked
vault.unlock_failed
vault.locked
credential.created
credential.rotated
credential.revoked
action.created
action.updated
action.disabled
session.created
session.revoked
execution.started
execution.finished
execution.blocked
backup.release_authorized
backup.created
restore.completed
runtime.faulted
~~~

每次执行的内部 audit ID 由 Broker 生成。数据库必须拒绝同一内部 ID 的第二条
`execution.started` 或第二条 terminal（`execution.finished` /
`execution.blocked`）；重启 reconciliation 只按该内部 ID 配对。Agent 重用
frame `request_id` 不得合并两次执行的审计生命周期。

禁止字段：

- password/recovery/VRK/DEK/Secret/Capability token。
- Authorization/Cookie。
- request/response body。
- Secret prefix、suffix、length、hash 或可用于 offline guess 的派生值。
- raw SQLite/crypto error string。

允许字段：

- IDs、Action version、Credential version。
- event/outcome/reason code。
- upstream status、latency、byte counts。
- runtime version、format version。

### 18.2 Runtime Events

P0 只要求以下 JSONL 结构化事件，不启动 metrics listener，也不建立
counter registry：`runtime.starting`、`runtime.stopped`、
`runtime.listener_fault`、`runtime.idle_check_deferred`、
`runtime.idle_check_fault`、`runtime.idle_lock_deferred`、
`runtime.idle_lock_fault`、`runtime.fault_drain_failed`、
`runtime.fault_shutdown_failed`、`authority.state`、
`rekeyd.command_failed`。事件只携带 stable code、channel、state、reason、
outcome、runtime/format version 等允许字段。

queue depth、unlock failure counter、session gauge、execution/storage latency、
sealing counter 进入 P1 observability spec；在真实运维消费者和字段预算确定
前不为这些指标预建 registry 或远程 listener。`scripts/p0-runtime-faults.sh`
必须逐行解析真实 release 进程 JSONL，确认 listener fault 导致非零退出且日志
不存在 secret canary。

## 19. Configuration

startup config 只允许：

~~~text
state_dir
admin_socket_path (derived under state_dir by default)
agent_socket_path (derived under state_dir by default)
idle_lock_duration
authority_queue_capacity
max_connections
log_level
~~~

来源优先级：CLI flags > config file > compiled defaults。P0 不从环境读取 password、Secret 或上游 credential；普通非秘密配置环境变量也先不实现，避免隐藏第二来源。

配置在 Broker 创建任何 socket 前完整验证。未知字段是错误，不忽略。

## 20. Compatibility And Deletion Plan

用户明确要求不考虑向后兼容，因此本表全部以删除收敛，不设置保留期限：

| Old path | Classification | Required action | Verification |
| --- | --- | --- | --- |
| v1 `vault.db` schema | obsolete source of truth | 不读取、不迁移；v2 init 对非空目录失败 | `legacy_vault_rejected` |
| `get_secret_value*` | unsafe public API | 删除，不提供替代 raw getter | compile search + `no_secret_export_api` |
| CLI direct SQLite | boundary violation | 删除 rusqlite/rekey-vault direct dependency | dependency check + `cli_uses_ipc_only` |
| `REKEY_PASSWORD` | secret transport violation | 删除所有 password env 读取/写入 | `daemon_environment_contains_no_password` |
| `rekey request name url` | confused deputy | 删除命令 | CLI snapshot test |
| `/proxy/{provider}/{path}` | arbitrary path surface | 删除 route | agent IPC contract test |
| MITM/system CA | out of P0 trust boundary | 删除 CA 和 proxy crates | workspace member assertion |
| unmatched TCP passthrough | unsafe fallback | 删除 | network deny test |
| Dashboard direct DB | second state owner | 删除 Web crate | workspace/dependency assertion |
| provider presets/rules | mixed policy/store model | 删除；用 FixedHttpAction | schema and CLI tests |
| single-port HTTP surface | mixed trust channel | 删除；使用 two UDS | socket isolation test |
| old integration tests | validate unsafe behavior | 删除并重写 | test inventory assertion |

旧 2026-04-01 spec/plan 保留为历史证据，但文件顶部后续应标记 `Superseded by Credential Authority v2 Foundation`；不从旧文档复制行为。

## 21. Boundary Contracts

| Contract | Owner | Allowed dependencies | Forbidden dependencies | Tests |
| --- | --- | --- | --- | --- |
| Domain invariants | rekey-domain | serde、uuid、thiserror | IO、Tokio、HTTP、SQLite、env | `cargo test -p rekey-domain` |
| Root state ownership | AuthorityWorker | domain、crypto、record store、clock/RNG | CLI/Web/Agent direct DB；`Arc<RootKey>` | `authority_single_owner` |
| Crypto | rekey-vault crypto | aes-gcm、argon2、hkdf、sha2、secrecy/zeroize | caller nonce、custom cipher、logging | `cargo test -p rekey-vault --test crypto_contract` |
| Storage | SQLiteRecordStore | rusqlite、domain records | plaintext Secret、multiple process access | `cargo test -p rekey-vault --test storage_contract` |
| Lifecycle | AuthorityWorker 状态机（BrokerRuntime 只编排 drain/shutdown，不自持状态） | Tokio channels、clock | hidden globals、silent auto-unlock | `cargo test -p rekey-vault --test lifecycle_contract` |
| Admin IPC | AdminService | frame、peer UID、AuthorityHandle | Agent capability as admin proof、DB access | `cargo test -p rekey-broker --test admin_ipc` |
| Agent IPC | AgentService | frame、session、executor | Secret read/export、URL/method/auth inputs | `cargo test -p rekey-broker --test agent_ipc` |
| Session | SessionRegistry | CSPRNG、SHA-256、clock | persistent long-term token、Vault token | `cargo test -p rekey-broker --test session_contract` |
| Execution | ActionExecutor | pinned Action、prepared credential、upstream | arbitrary origin、redirect、env proxy | `cargo test -p rekey-broker --test execution_contract` |
| Audit | 事件由 rekey-broker 执行管线构造（`src/audit.rs`），持久化只经 AuthorityWorker 事务提交 | typed events、SQLite | Secret/content/default warning fallback | `cargo test -p rekey-broker --test audit_contract` |
| CLI | rekey-cli | IPC client、TTY input、diagnostics | rusqlite、aes-gcm、raw Vault API | `cargo test -p rekey-cli --test cli_blackbox` |
| Backup/restore | AuthorityWorker + offline bootstrap | SQLite Backup API、filesystem adapter | `cp` live DB、plaintext export、v1 restore | `cargo test -p rekey-vault --test backup_restore` |

## 22. Implementation Sequence

严格串行完成；前一阶段合同未通过不得开始下一阶段。

### P0.1 Delete Unsafe Topology

工作：

- 调整 root workspace 为 domain/vault/broker/cli。
- 删除 CA/Web/Proxy 和旧 CLI/测试路径。
- 创建空 crate 边界和 typed error skeleton。

完成条件：

- workspace 不包含旧 crates。
- CLI 不依赖 rusqlite、aes-gcm、argon2 或 reqwest。
- `rg` 找不到 `REKEY_PASSWORD`、`get_secret_value`、`/proxy/`、passthrough。

验证：

~~~bash
cargo check --workspace
cargo test --workspace
rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests
~~~

最后一条必须无匹配；CI 用 wrapper script 将无匹配视为成功。

### P0.2 Domain And Crypto Foundation

工作：typed IDs、Credential/Action/Capability、Secret types、KDF、HKDF、AEAD、AadV1、recovery encoding。

完成条件：

- golden AAD vectors 固定。
- wrong key/AAD/nonce/ciphertext 全部认证失败。
- Secret types 无 Clone/Serialize/Display。
- Argon parameters 按 wrapper record 使用。

验证：

~~~bash
cargo test -p rekey-domain
cargo test -p rekey-vault --test crypto_contract
cargo test -p rekey-vault --test secret_type_contract
~~~

### P0.3 SQLite Store And Offline Bootstrap

工作：schema、permissions、connection pragmas、init、backup、restore、integrity checks。

完成条件：

- init 双 wrapper roundtrip。
- nonempty/v1 directory 明确拒绝。
- transaction failure 不留部分 Credential。
- backup/restore 只处理 v3 ciphertext。

验证：

~~~bash
cargo test -p rekey-vault --test storage_contract
cargo test -p rekey-vault --test bootstrap_contract
cargo test -p rekey-vault --test backup_restore
~~~

### P0.4 Authority Worker

工作：bounded command queue、state machine、unlock/backoff、Credential CRUD、Action persistence、audit。

完成条件：

- SQLite/VRK 只存在于 worker。
- locked/draining/faulted 行为全覆盖。
- rotate/revoke invariants 事务化。
- audit critical failure fail closed。

验证：

~~~bash
cargo test -p rekey-vault --test authority_contract
cargo test -p rekey-vault --test lifecycle_contract
cargo test -p rekey-vault --test fault_injection
~~~

### P0.5 Admin And Agent IPC

工作：frame codec、peer credential、two sockets、AdminService、SessionRegistry、AgentService。

完成条件：

- malformed/oversized/unknown frame 全拒绝。
- Agent socket 无 Admin message。
- mutation 要求 step-up proof。
- capability replay/expiry/use count 正确。

验证：

~~~bash
cargo test -p rekey-broker --test frame_fuzz_vectors
cargo test -p rekey-broker --test admin_ipc
cargo test -p rekey-broker --test agent_ipc
cargo test -p rekey-broker --test session_contract
~~~

### P0.6 Fixed HTTP Action Vertical Slice

工作：Action validation、Reqwest transport、header replacement、bounded response、secret sealing、audit。

完成条件：

- Agent 无法改变 origin/method/path/auth。
- redirect/private IP/duplicate auth 拒绝。
- reflected secret 阻断。
- 成功响应不含 Secret。

验证：

~~~bash
cargo test -p rekey-broker --test execution_contract
cargo test -p rekey-broker --test adversarial_http
cargo test -p rekey-broker --test reflected_secret
~~~

### P0.7 CLI Blackbox And Release Gate

工作：所有 CLI 命令、hidden input、exit codes、diagnostics、完整 E2E。

完成条件：

- 从 init 到 execute 的 tempdir E2E 通过。
- release `rekey` 子进程面对恶意 Unix Socket Broker 时，错 channel、错
  request id、超限 response、伪造 ErrorEnvelope 全部 fail closed。
- env/argv/log/audit/response secret canary 全无泄漏。
- 文档安全等级显示 G1，不声称 G2。

验证：

~~~bash
cargo fmt --all --check
cargo check --workspace
cargo test --workspace
cargo test -p rekey-cli --test cli_blackbox
cargo test -p rekey-cli --test malicious_broker
cargo test --test authority_blackbox
cargo test --test secret_canary
scripts/p0-acceptance.sh
scripts/p0-runtime-faults.sh
~~~

### P1

| Work | Done when | Verification |
| --- | --- | --- |
| Linux G2 launcher | Agent 独立 UID/namespace，不能读 socket/DB/ptrace/直连 | `scripts/p1-linux-g2.sh`（Linux Docker gate） |
| Typed parameter policy | Action 参数 canonicalization + default deny | `cargo test -p rekey-policy` |
| Chunk-boundary response sealing | bounded buffered response 中跨 HTTP/TLS chunk 的 secret variant 在任何 Agent response frame/body 写出前被拒绝 | `scripts/p1-streaming-sealing.sh` |
| launchd | locked boot、受保护 unlock、central stop、locked restart | `scripts/p1-service-manager.sh`（macOS required） |
| systemd | 同一真实 native-manager gate 已实现；required Ubuntu job 产生通过证据前只称 CI gate implemented, not run | `scripts/p1-service-manager.sh`（`ubuntu-latest` PID 1 systemd required） |

Chunk-boundary sealing 的 release-process gate 必须运行真实 `rekey` CLI、独立
BrokerRuntime 进程、Admin/Agent 双 UDS、SQLite audit 和 local CA/TLS upstream。
upstream 使用 HTTP/1.1 chunked encoding，并把实际注入的 Credential 之 raw、base64、
base64url、percent-encoded variant 分隔在不同 HTTP chunk 且通过多次 TLS write 发送。
每个 reflection 必须返回 exit 8，stdout、stderr、audit、runtime log 均无 canary；
`execution.started` 必须恰有一个 `execution.blocked(reflected-secret)` terminal，不能有
`execution.finished` 或 orphan。Clean chunked response 必须完整成功；oversize 和
mid-stream close 必须返回 upstream/size failure，且 Agent 不得收到 partial body。
失败路径还必须用透明单连接 Agent UDS proxy 捕获完整 broker-to-client response（不得
持久化 capability request），并证明响应恰为一个 Agent channel Frame v1 ERROR：
`body_len=0`、metadata code 匹配、总长度严格等于 `36 + metadata_len`，无 trailing
bytes 或 partial upstream body。capture 文件同样必须通过 canary/partial 扫描。
fixture 只能注入 screened endpoint 和 test CA，不能放宽生产 private-IP screening。

#### P1.1 Typed Authorization Kernel

第一批 P1 只实现本地、会话级、JSON typed、内存 policy snapshot；它不包含
Cedar、签名或持久化 snapshot、Approval、Connector、Control plane 或可复用
human/workload identity。

- Broker 在 `SessionCreate` 时生成 `PrincipalId`，并把
  `tenant_id + principal_id + session_id` 存入 server-owned session；Agent 不得
  自报 Principal。
- Admin 通过独立 Admin UDS 和 step-up proof 原子激活一个最大 64 KiB 的
  snapshot。Snapshot 只存在于 Broker 内存；lock、shutdown 或进程重启后清空，
  无 active snapshot 时全部 Action 默认拒绝。
- Snapshot 包含非零单调 `PolicyVersion`、expiry、Action version 到固定
  `ResourceRef + JSON Schema` 的唯一 binding，以及 exact-principal rules。
  Empty snapshot 合法且表示 deny-all。
- 首个 evaluator 是内置 total function：匹配 rule 中任何 `forbid` 优先拒绝；
  否则确定性选择匹配 permit；无 permit 或任何 evaluator error 均拒绝。P1.1
  不引入 evaluator trait 或 Cedar policy language。
- 非空 Agent body 只接受 JSON；duplicate key、invalid UTF-8、trailing data、
  非 JSON content type 和 schema failure 全部拒绝。Extra Header lowercase 后排序，
  duplicate/collision 拒绝。Body、normalized content type 和 Headers 使用 RFC 8785
  canonical JSON；hash 额外绑定 Action version、schema 和 Resource。
- Rule parameter scope 只有 `any_validated` 和 `exact_hash`。前者仍要求绑定 schema
  已通过；后者要求 canonical SHA-256 精确相等。不支持 glob、regex、wildcard
  principal、条件表达式、imports 或 obligations。
- Capability 认证、Action pinning、snapshot pinning、schema/canonicalization、policy
  evaluation 和 denied audit 全部发生在 `ExecutionStarted` 与任何 credential effect
  之前。一次请求固定同一个 snapshot version/digest，不混用并发激活的新版本。
- 到达 evaluator 的 Execution audit 必须记录 principal、policy version/digest、
  determining rule（无匹配 rule 时为 NULL）、resource 和 parameter hash；不得记录
  schema 或 canonical/request body。`policy-missing`、`action-unbound` 和参数无法
  canonicalize 等 evaluator 前拒绝没有并不存在的完整 authorization evidence，只以
  明确 reason code 记录。该 policy breaking schema change 先将 durable format bump 到 3；
  旧非空状态明确拒绝，不迁移或覆盖。
- Snapshot activation 先完整验证并提交无秘密 audit，再一次 swap；失败保留旧
  snapshot。Lock/restart 后必须重新激活。

验证命令：

~~~bash
cargo test -p rekey-policy
cargo test --test policy_e2e
~~~

真实 P1 acceptance 使用 release `rekey`、真实 BrokerRuntime 双 UDS、真实 SQLite，
以及仅为本地 CA/TLS 注入 transport 的 release fixture，证明 missing/no-match/forbid/
expired/ambiguous input 在 upstream 与 credential effect 前拒绝，并至少完成一次
policy-permitted 的本地 TLS upstream 调用。产品 `rekeyd serve` 参数解析和生产
transport wiring 由 `scripts/p0-acceptance.sh` 独立覆盖；fixture 不得被描述为产品
daemon，也不得进入生产 `rekeyd` 路径。

#### P1.2 Runtime-Owned Execution And Native Stop

Agent connection 不拥有 Action effect。`ActionExecutor::admit` 只执行 capability、固定
Action/policy/parameter 校验并 durable commit `execution.started`，随后返回
`AdmittedExecution`；后者持有 Session permit、terminal guard、Credential/upstream
effect 所需对象，并由 `AdmittedExecution::run` 完成 effect 与唯一 terminal audit。
`ExecutionSupervisor` 是 BrokerRuntime 的单用途 child：mpsc 接收 `ExecuteRequest`，
自己的 `JoinSet` 持有每个 admit/run task，结果通过 oneshot 返回 Agent connection。
connection 丢弃 response receiver 只丢客户端响应，不能取消 supervisor-owned task。
P2.1 GitHub remote-token effect 位于 `AdmittedExecution` ownership 内，不得重新绑定到
connection lifetime。Agent connection 丢失 response receiver 后，已经开始的 GitHub
effect 仍由 supervisor-owned task 持有到该 Action 的单一总 deadline；对已捕获 token
按 §P2.1 完成有界 revoke attempt、revoke audit 和唯一 terminal，不得承诺 deadline
耗尽后的绝对远程清理。

Admin Shutdown、SIGTERM、SIGINT、listener/idle/execution-supervisor fault 必须进入同一个 central stop router，
且不可逆 stop 只由一次 lifecycle coordinator owner 执行。Admin 在 Locked 时不需要
proof；在 Running 时先验证 proof，失败必须保持服务可用。进入不可逆 stop 后立即关闭
Session admission、撤销 token、关闭 execution submission、通知 partial frame reader 与
response waiter 退出，但 supervisor-owned admitted task 继续。stop 聚合第一个错误而不
早退：等待 ordinary execution、必要时 lifecycle cancel、等待 supervisor、使用绝对
deadline 等 terminal tracker、lock/清空 policy、Authority shutdown、发布 shutdown
notice、回收双 UDS connection/idle tasks、关闭 Authority sender，再 bounded join
terminal task 与 Authority thread。任何 coordinate/inner/join 失败仍必须发布 notice 并
使 `rekeyd` 非零退出；不能在 lock 与 shutdown 之间释放 coordinator 让 Admin unlock。

Stop source selection must synchronously close the single GitHub remote-effect
admission gate before any Authority await. After the durable connector-authorized
audit and before JWT signing or exchange, `run_github` atomically tries that same
gate. A try-begin ordered after closure commits one blocked terminal and performs
no exchange; a try-begin ordered before closure owns the already-begun effect and
continues under its existing bounded cleanup contract. A rejected Admin Shutdown
may reopen the gate only while the same coordinator still proves the Broker is
Running.

生产 action timeout hard max 为 120 秒。central stop 只有一个绝对 deadline：当前
`drain_timeout` 加 5 秒 terminal/finalize grace，production 约 125 秒；所有 execution、
terminal、connection、supervisor、Authority join 共享该 deadline，不能逐层重置。
native manager hard ceiling 取 130 秒，只给 125 秒应用 deadline 少量调度余量；无
in-flight 的 manager acceptance SLA 仍是 15 秒，130 秒不能被当成 clean-stop SLA。

Agent/Admin frame read 必须监听 shutdown notice，所以 1 byte RKIP half-frame 不能拖住
stop。Admin Shutdown connection 必须在 central stop 返回后收到一个完整 CLI response；
其他 response waiter 可以随 notice 关闭。Terminal tracker 提供
`wait_idle_until(absolute_deadline)`，sticky failure 在 pending 已清零后仍返回错误。

launchd generator 只产生当前 GUI user LaunchAgent；systemd generator 必须从本机 passwd
database 验证显式 `--run-as-user` 存在且 UID 非 0，并在 unit 中将 `$` 转义为 `$$`。
模板不得包含 password、secret env 或自动 unlock，启动/重启始终 Locked。真实 gate
使用 release `rekey` 与安装到临时路径的 release BrokerRuntime local-CA/TLS fixture、临时
真实 state、双 UDS 与 SQLite；production `rekeyd` 的 public HTTPS wiring 仍由 P0 gate
独立覆盖。它必须覆盖：half-frame；signal 发生时 slow ordinary execution 已有 started 且
client 可断连，最终仍恰一 terminal；sticky terminal audit failure 非零并由重启
reconcile orphan；unlock race 后最后事件仍为 signal lock；Admin Shutdown CLI response；
launchd/systemd locked boot、clean stop、restart 仍 Locked。cleanup 的 manager query、
launchctl/systemctl、TERM、KILL 与 child wait 全部 bounded，只有进程退出后才 wait/remove
unit。macOS 本机跑临时 `gui/$UID` label；普通 required `ubuntu-latest` 必须先硬断言
PID 1 是 systemd，不满足直接失败，不能把 exit 77 转绿。在 `security-gate` required Ubuntu
job 产生通过证据前，systemd Feature Truth 只能写 “CI gate implemented, not run”。

任一 execution child `JoinError` 必须立即关闭 supervisor admission、停止 spawn 并让
supervisor 返回错误；supervisor actor 自身 panic、异常或意外 clean exit 也必须由 runtime
root select 视作 fault。若 root 已取得 actor 的 completed `JoinHandle` result，central stop
必须消费该 result，不能再次 poll 已完成的 handle。真实 panic transport 验收必须证明随后
请求不再产生 `execution.started`、原 started 恰一 terminal、`serve` 非零且 joins bounded。

### P2

#### P2.1 GitHub App Installation 内置凭据动作

新增 typed credential kind 的 breaking schema change 将 durable format bump 到 4；旧非空
state dir 继续明确拒绝，不提供迁移或兼容读取。

首个 P2 垂直切片是一个封闭的 GitHub App Installation profile，不创建通用
connector registry、provider SDK、控制面或 Agent 可调用的签名/换票接口：

- Admin 使用现有 Credential mutation trust boundary 保存一个版本化、拒绝未知字段的
  `github-app-installation-v1` payload。payload 包含 base64 编码的 PKCS#1 DER RSA
  private key、GitHub
  client ID、app ID、installation ID 和唯一 repository ID；整个 payload 作为现有
  `GitHubAppInstallation` CredentialVersion 信封加密，kind 必须进入 AAD，明文不得进入
  metadata、argv、环境变量或 audit。Admin `add-github-app` 必须在 Authority 持久化之前
  完成拒绝未知字段、非零 ID、client ID 和 PKCS#1 RSA key 的完整验证；generic add 固定
  创建 `OpaqueToken`。P2.1 不提供 GitHub profile rotation，generic rotate 遇到
  `GitHubAppInstallation` 必须明确拒绝，不能把它改成 opaque payload。
- `add-github-app --file` 以 64 KiB 上限直接读入 zeroizing buffer，不能先通过
  `std::fs::read` 创建普通 `Vec`。Admin 收到 add 后先以现有 Authority step-up 验证 proof，
  验证通过才允许 base64/RSA profile 解析，最后由 credential mutation 再次验证 proof 并
  原子持久化；错误 proof 不能触发昂贵的 RSA parse。CLI profile buffer 一次预分配
  `limit+1`，proof+secret IPC body 按 `1+4+proof.len+4+secret.len` 一次精确预分配；编码与
  bounded read 不能通过 reallocation 留下旧 heap 副本。
- Agent API 不变，仍只有 `ExecuteFixedHttpAction`。只有 action 精确等于
  `GET https://api.github.com/installation/repositories`、无 Agent body/content-type/
  extra headers、认证槽为 `authorization: Bearer ` 时，Broker 才把该 payload 解释为
  GitHub App profile；任何偏差默认拒绝，绝不回退为普通 token 请求。
- Broker 在一次 execution 内解析 PKCS#1 key，在内存中签 RS256 JWT。JWT 的 `iss`
  固定为 client ID，`iat` 为当前时间减 60 秒，`exp` 不超过 9 分钟；随后固定调用
  `POST /app/installations/{installation_id}/access_tokens`，body 只允许一个
  `repository_ids` 项和 `permissions.metadata=read`。RSA signer 必须在 drop 时清零其
  私钥表示；JWT signing input、signature encoding 与输出都是 zeroizing 临时值。
- exchange、resource 和 revoke 三段请求都必须携带固定
  `User-Agent: rekey/<package-version>`、固定 Accept 和 API version；fixture 对三段精确
  断言，缺失或变化即失败。
- Exchange 必须返回唯一 token、`permissions` 精确只有 `metadata=read` 且
  `repository_selection=selected`，否则 fail closed。Broker 用该 token 调用固定
  `GET /installation/repositories`，并验证成功响应只包含配置的 repository ID。Agent
  只能收到 Broker 按 allowlist 重建的 `total_count` 和 repository `id`；provider 原始
  JSON 字段与响应头不得透传，不能依赖有限的 secret encoding 枚举来阻止字段逃逸。
- Exchange response body 在检查 HTTP status 或完整 schema 前即进入 zeroizing buffer。
  Broker 先对有界 body 做 best-effort token probe，再检查 status/schema：支持首个 JSON
  value 后有 trailing garbage，以及常见的重复 `token` 字段；捕获到的 token 即使来自
  500 或畸形 response 也进入 revoke。probe 最多捕获 4 个不同的简单 ASCII GitHub token，
  并在总 cleanup deadline 内逐个 revoke；超过捕获上限、转义 token、网络层响应不确定性
  或 deadline 耗尽时无法承诺绝对远程清理，必须 fail closed 且不得声称已全部 revoke。
  token probe 只能受已经验证的 response body 上限约束，不得假设 installation token 的
  固定长度；local acceptance 必须覆盖 GitHub 约 520 字符的 stateless `ghs_` token。
- 无论 resource request 成功或失败，Broker 都立即调用固定
  `DELETE /installation/token`。只有 revoke 返回 204 且 resource response 通过原有
  bounded-body、redirect 和 secret-sealing 检查后，Agent 才能收到成功；revoke 失败
  时丢弃已取得的 resource response 并以 terminal blocked 收口。
- JWT/exchange 网络 effect 开始后，drain cancellation 不得 drop 该 execution future；
  session in-flight permit 保持到 revoke 和 revoke audit 完成。若超过 drain deadline，
  lock/shutdown 返回 busy 并保持 fail closed，不能通过提前释放 permit 遗留远程 token。
- Action 的 `timeout_ms` 是整个 GitHub effect 的单一总 deadline，不是每阶段各自可用的
  timeout。绝对 deadline 从 supervisor 开始 admission 时锚定，不能在 credential prepare、
  connector-authorized audit 或进入 `execute_effect` 后重新获得完整 timeout。GitHub action
  最小 2 秒；总 deadline 最后 500ms 固定保留给 cleanup。
  exchange/resource 每次只获得 business deadline 的剩余时间，revoke 只获得总 deadline
  的剩余时间；Broker 自己也对 transport future 套同一剩余时间，确保不依赖 transport
  是否遵守 request timeout。超过 business deadline 后不得再开始 resource，但已捕获
  token 仍应使用预留 cleanup budget 尝试 revoke；整个 effect 必须在总 deadline 内有界。
- private key、JWT、installation token 及其编码变体都属于敏感中间值。base64 解码从
  `decode_len` 预分配的 zeroizing output 开始，late decode error 也清零；Rekey 自己创建的
  upstream response accumulator 从第一个字节起就是 zeroizing buffer，timeout、oversize、
  truncated 和 sealing failure 的 partial/full body 都在 drop 时清零，只有通过 sealing 的
  clean body 才能 move 给 Agent。accumulator 在读取前一次预分配 `response_max_bytes`；
  产品上限为每个 response 4 MiB，这是为避免 secret-bearing reallocation 接受的有界内存
  tradeoff。该清零声明只覆盖 Rekey-owned buffers，不声称控制
  reqwest `HeaderValue`、TLS 实现或操作系统内部可能产生的副本。敏感值同时进入 response
  sealing needles；不得出现在 Agent frame、日志、SQLite 或错误文本。Audit 只记录
  credential/action/request 的现有 typed ID，以及
  app/installation/repository ID 的 SHA-256 commitment、阶段和稳定结果码。
- 生产请求继续使用 public-IP screening、固定 SNI、禁 proxy/redirect 和 bounded
  response。真实本地 acceptance 只允许通过 test-only `ScreenedEndpoint` 与本地 CA
  注入，不得放宽生产私网规则。

本地 acceptance 必须使用 release `rekey`、release `rekeyd` 的 init/backup/restore 路径、
独立 release BrokerRuntime fixture、真实双 UDS、SQLite 与本地 CA/TLS mock GitHub，验证
JWT 签名和 claims、exchange 的 repository/permission scope、
resource 调用、成功/失败后的 revoke、每个 request_id 的非空且严格有序 audit chain；
捕获到 token 的 chain 必须是 started→authorized→token-revoked→terminal，确定未观察到
token 的 exchange failure 必须是 started→authorized→terminal 且单独计数，不能以空集合
通过。还必须验证全盘 canary，以及 GitHub typed credential 经
backup→restore→再次真实三段执行仍可用。
真正的 `github.com` live E2E 需要用户提供 GitHub App、installation 和 test repository；
在取得该证据前只能声明 local black-box verified，P2.1 provider profile 不得标记
`Field Validated`，也不得声称 live GitHub interoperability 已验证。

| Work | Done when | Verification |
| --- | --- | --- |
| GitHub App Installation | 内置封闭 profile，不改变 Agent API；local TLS 三段链和 revoke/canary 通过 | `./scripts/p2-github-app.sh` |
| External CredentialSource | GitHub live E2E 后再抽象；P2.1 不创建 registry/SDK | user-provided GitHub App fixture |
| Enterprise multi-tenant | tenant 进入所有 key/query/session/audit | `cargo test -p rekey-control --test tenant_isolation` |
| HA/DR | 明确 RPO/RTO、恢复和 split-brain 行为 | `./scripts/verify_dr_drill.sh --report artifacts/dr/latest.json` |

#### Deferred：OS key wrapper

OS Keychain、Secret Service、TPM 或 Secure Enclave wrapper 当前不进入 P1/P2 完成范围。
在“仍要求 password/recovery step-up、禁止自动解锁”的合同下，它只增加额外一条 VRK unwrap
路径和跨存储原子性、备份恢复、平台测试负担，却没有形成明确的用户流程收益。只有真实用户
需求接受“平台 user-presence 可以独立构成一次 step-up”时才重新设计；届时先做单一平台、
不可导出/用户在场的 closed wrapper 和真实签名二进制 E2E，不引入 1Password、OpenBao 或
其他付费/外部服务作为 Community 运行前置条件。

## 23. Validation Matrix

| Security property | Unit | Contract | Integration | Adversarial |
| --- | --- | --- | --- | --- |
| Password KDF | parameter/golden | wrapper roundtrip | init/unlock | wrong/replay/backoff |
| Envelope encryption | AAD/AEAD vectors | key hierarchy | rotate/recover | ciphertext/AAD swap |
| Secret types | trait assertions | expose scope review | canary | log/error/response scan |
| SQLite | schema/invariants | transaction fault | crash/reopen | corrupt/WAL/permission |
| Authority lifecycle | state transitions | command queue | lock/drain/restart | race/fault injection |
| Admin IPC | frame parser | peer/proof matrix | CLI admin | Agent-to-admin attempts |
| Agent IPC | frame parser | message allowlist | execute | arbitrary URL/auth/message type |
| Capability | TTL/use/hash | session matrix | restart revoke | replay/cross-action |
| HTTP Action | validation | transport fake | TLS upstream | SSRF/redirect/reflection |
| Backup/restore | streaming hash/format | online snapshot/marker cleanup | real `rekeyd` backup/restore | audit fault/SIGKILL/bounded RSS via `scripts/p0-durability.sh` |
| Audit | event schema | no-secret fields | execution sequence | write failure/canary |

额外机械检查：

~~~bash
cargo tree -p rekey-cli
# must not contain rusqlite, aes-gcm, argon2

rg -n 'std::env::var\("REKEY_PASSWORD"|\.env\("REKEY_PASSWORD"' crates tests
# no matches

rg -n 'get_secret|read_secret|export_secret' crates/rekey-domain crates/rekey-broker crates/rekey-cli
# no public product path; test names/comments may be excluded by wrapper

rg -n 'Authorization|Cookie|password|recovery|secret' target/test-logs test-artifacts
# canary harness interprets only approved redacted occurrences
~~~

## 24. Performance And Resource Limits

P0 目标不是 benchmark parity，而是有界行为：

| Resource | Limit |
| --- | --- |
| Authority command queue | 128 |
| Broker simultaneous IPC connections | 128 default: 120 Agent + 8 Admin reserved; one channel cannot consume the other's capacity |
| Per-session concurrent executions | 4 default |
| Admin metadata | 64 KiB |
| Credential input | 64 KiB |
| Agent request body | Action limit, max 1 MiB |
| Agent response body | Action limit, max 4 MiB |
| Upstream timeout | max 120s |
| IPC frame IO inactivity / CLI long-operation response | 30s / Execute 130s, lock/shutdown 130s, backup 300s |
| Argon memory | 64 MiB per derivation |
| Unlock derivations | serialized in AuthorityWorker |

超限必须显式错误，不能截断、drop、warning 或无限排队。

## 25. Security Review Checklist

每次涉及以下文件或 contract 的 PR 必须人工安全评审：

- crypto、AAD、key wrapper、Secret types。
- schema、transaction、backup/restore。
- IPC frame、peer credential、step-up proof。
- session token、Capability accounting。
- upstream request construction、DNS、redirect、Header。
- response sealing、error redaction、audit。

Review 必问：

1. 是否新增了 Secret 的 Clone、String、Serialize、Debug 或长期 buffer？
2. 是否在 allow 前触发了 credential effect？
3. 是否让 Agent 控制 origin、auth、path、method、redirect 或 file path？
4. 是否出现新的状态写者或直接 SQLite consumer？
5. 错误是否可能 warning 后继续？
6. audit failure 是否可能产生“上游成功但 Rekey 无证据仍返回成功”？
7. crash、cancel、timeout、queue full 时 Secret 是否被清理？
8. 测试是否包含失败和攻击路径，而不只 roundtrip？

## 26. Non-Goals

- 不兼容、读取或迁移 v1 Vault。
- 不保留旧 CLI alias、旧 HTTP route、旧端口或旧数据库 schema。
- 不做 MITM、系统 CA、透明代理或 passthrough。
- 不做 Dashboard 或浏览器 UI。
- 不做通用密码管理器、浏览器自动填充、个人密码同步。
- 不接 1Password、OpenBao、Vault、Infisical 或云 Secret Manager。
- 不做多租户、SSO、SCIM、企业控制面、HA 或多区域。
- 除 P2.1 封闭的 GitHub App Installation 换票外，不实现通用 OAuth、SSH、HSM、
  动态数据库 Secret 或任意 provider operation。
- 不支持 Windows。
- 不承诺默认拓扑或通用 release 达到 G2、FIPS validation、mlock、防宿主 root 或防内核取证；
  P1 只证明有界 Linux container/namespace G2 reference boundary。
- 不支持 Agent-visible 流式 request/response、SSE passthrough、frame v2、自动
  retry、redirect 或 arbitrary HTTP proxy。P1 chunk-boundary sealing 仍先在 Action
  `response_max_bytes` 和 4 MiB 全局上限内完整缓冲 upstream response，再扫描 raw、
  base64、base64url 和 percent-encoded secret variants；它验证 HTTP chunk 与 TLS write
  边界不能绕过 sealing，但不声称边读边扫描或在 upstream EOF 前提前终止。

## 27. Resolved And Open Questions

### Resolved

- 内置 Store 是第一方核心，不是 fallback adapter。
- P0 使用 envelope encryption 和两个基础 wrapper。
- P0 以 SQLite 为唯一 durable store。
- P0 用两个 UDS 分离 Admin/Agent。
- P0 不做 daemon background 模式。
- P0 用 FixedHttpAction 证明纵向闭环。
- P0 默认拓扑明确为 G1；P1 已落地有界 Linux container/namespace G2 reference，不升级
  一般产品声明。
- 不做任何 v1 compatibility 或 migration。
- P1.1 使用内置 typed default-deny evaluator；不引入 Cedar 或 evaluator abstraction。
- 产品名为 Rekey，仓库许可证为 MIT。

### Open But Non-Blocking For P0.1–P2.1

1. P2.1 已选择 GitHub App Installation 作为第一个内置 provider profile；P0 contract
   仍使用 provider-neutral FixedHttpAction。
2. recovery key 是否在 P1 增加 threshold split；P0 使用单一 recovery key。

## 28. Readiness

本规格完整到可以严格按 P0.1–P0.7 顺序实施 `Credential Authority v2 Foundation`。它已经给出状态所有者、删除范围、密码学层级、AAD、schema、IPC frame、CLI、错误、生命周期、验证命令和非目标。

P0、P1 typed authorization/runtime ownership/sealing/service-manager、Linux G2 reference 和
P2.1 local black-box 实现已经存在；systemd required-job 已由
[security-gate run 33345442076](https://github.com/majiayu000/rekey/actions/runs/33345442076)
的 Ubuntu P0 在 systemd PID 1 和非 root service account 下通过，GitHub live E2E 尚无通过证据。
当前默认拓扑仍定位为 **G1 开发候选**，不是 G1 安全发布候选。独立密码学、IPC 边界和
audit/failure-semantics 人工审查尚未进行。因此当前仓库不能声称 Security Baseline Complete、
通用 G2、生产就绪或优于 1Password/OpenBao/Aperture 等完整产品。功能是否“可用”只以
`docs/product-foundation/feature-truth-matrix.md` 为准。

实现过程中如果发现 spec 与可验证事实冲突，必须先修改本 spec 和相关基线，再修改代码；不得用临时兼容层或 warning fallback 绕过合同。
