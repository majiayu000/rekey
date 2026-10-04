# Rekey v4 企业架构研究稿

状态：v4 企业研究稿（v3 默认构建不启用；非当前行为合同）  
日期：2026-08-28  
范围：状态所有权、边界、合同、部署、breaking deletion、验证与阶段路线  
相关文档：[v3 个人优先规格](../superpowers/specs/2026-10-02-rekey-v3-personal-first.md) · [威胁模型](./threat-model-v2.md) · [开源与商业边界](./oss-enterprise-boundary.md)

## 1. Objective

构建一个跨 Agent、跨云、跨协议的执行时授权平台。系统在真实凭据不进入 Agent 边界和 SaaS 控制面的前提下，验证人类委托、Agent 身份、工作负载身份、任务上下文和具体动作参数；对动作执行确定性策略、必要的参数绑定审批、即时凭据解析、受控上游调用和可验证审计。

架构首先服务 Coding Agent，但领域模型不得绑定 Codex、Claude、MCP 或某个云。

## 2. Chosen Shape

项目形态：安全敏感的 API/Agent Gateway，加上企业控制面、客户侧分布式数据面和本地开发者工具。

主要状态所有权模型：

> Rekey Broker 服务实例是运行时权能、解密材料和 Credential mutation 的唯一所有者；控制面拥有版本化 desired state；每个请求固定不可变策略快照；所有授权和执行结果写入 append-only decision event log。

不允许 CLI、Dashboard、Agent、Connector、数据库行、缓存和本地配置同时成为同一策略或 Credential 状态的权威来源。

## 3. 当前代码依据（2026-10-03）

旧稿中的 v1 代理架构已经删除，不能再作为重构起点。当前基线为
`origin/main@4cdb531`；v3 开发和验收状态见
[唯一实施清单](../superpowers/plans/2026-10-03-v3-implementation.md)。

| Area | Evidence | Implication |
| --- | --- | --- |
| Entrypoints | `rekey-cli` 是纯 IPC 客户端；`rekeyd` 拥有服务与离线 bootstrap | CLI 不读取 SQLite 或派生密钥 |
| State owner | `rekey-vault::AuthorityWorker` 单独拥有数据库连接和 VRK | 凭据变更必须走 Authority |
| Data plane | 独立 admin.sock / agent.sock、固定 HTTP Action、capability session | 没有系统 CA、MITM 或透明代理 |
| Domain | `rekey-domain`、`rekey-policy`、`rekey-connector` 提供纯模型与确定性策略 | 不需要重建 v1 secrets/rules 模型 |
| Enterprise | 已实现的企业运行入口在 v3 收入默认关闭的 `lab` | v4 按风险和验收证据逐项启用，不能将研究稿视为当前可用性 |
| Verification | 当前和历史检查分别记录于 Feature Truth Matrix | 研究路线不证明生产就绪或同 uid 攻击防护 |

## 4. Reference Models Considered

| Reference | Borrow | Do not copy | Source |
| --- | --- | --- | --- |
| Tailscale Aperture | 网络身份继承、默认拒绝、Connector discovery/invocation 双重授权、统一 Gateway | 不依赖 tailnet；不复制模型 Token 转售、Projects 和 Tailscale 专属控制面 | [Aperture](https://tailscale.com/docs/aperture) |
| Aembit | human + workload blended identity、即时短期访问、跨云工作负载身份 | 不重建完整通用 Workload IAM 和现有企业销售复杂度 | [Aembit](https://docs.aembit.io/get-started/use-cases/ai-agents) |
| AWS AgentCore | workload token、credential provider、Gateway 与云 IAM | 不绑定 AWS 托管 runtime 或 IAM 专属对象 | [AgentCore](https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/obtain-credentials.html) |
| Microsoft Entra Agent ID | attended/unattended identity、agent blueprint、独立 Agent service principal | 不复制 Entra directory 和 Azure RBAC | [Agent ID](https://learn.microsoft.com/en-us/azure/foundry/agents/concepts/agent-identity) |
| Infisical Agent Vault | Agent 不持有真实凭据、KEK/DEK、网络和资源防护 | 不把外部 Infisical 或通用 MITM 变成 Rekey 运行前置条件 | [Security](https://docs.agent-vault.dev/learn/security) |
| OpenBao | 信封/Seal 思路、租约、动态凭据、ACL 和恢复运维经验 | 不复制通用 secrets engine、插件生态、Raft/HA 和 Vault 兼容复杂度 | [OpenBao](https://openbao.org/docs/next/what-is-openbao/) |
| KeyFence | host/path/method/body/rate/budget capability | 不复制尚未验证的全部规则语义；采用统一 Action Schema | [KeyFence](https://github.com/atgreen/keyfence) |
| Outpost | 反向代理优先、无系统 CA、Capability-first | 不把敏感写方法一律等价；动作风险由 Connector 语义决定 | [Outpost](https://github.com/sausin/outpost) |
| 1Password SSH Agent | 私钥不导出，只提供签名操作和用户批准 | 不把密码管理器、浏览器扩展和 Vault UI 变成 Rekey 产品范围 | [SSH Agent](https://www.1password.dev/ssh/agent) |
| Cedar | principal/action/resource/context、default-deny、forbid、schema validation、Rust 实现 | 不接受 policy evaluation error 被忽略后造成意外允许；激活前必须完整验证 | [Cedar](https://docs.cedarpolicy.com/) |
| SPIFFE | 跨环境工作负载身份、短期 SVID、无需 bootstrap secret 的 Workload API | 不要求所有客户部署 SPIRE；它只是 identity adapter 之一 | [SPIFFE](https://spiffe.io/docs/latest/spiffe-specs/) |

## 5. Boundary Map

~~~text
product/app
  rekey CLI
  local launcher
  admin web console
  public control API

core/domain
  identity tuple
  action schema
  policy decision
  approval grant
  credential reference
  credential metadata and version invariants
  authorized credential use
  audit event
  typed errors

runtime/application
  control-plane service
  gateway data-plane runtime
  edge/launcher runtime
  policy snapshot manager
  decision pipeline
  credential authority lifecycle
  unlock/lock and credential lease lifecycle

adapters/backends
  first-party encrypted SQLite credential store
  password/recovery/OS/KMS key wrappers
  OIDC/SAML/SCIM
  SPIFFE/cloud/Kubernetes/Tailscale/local peer identity
  optional 1Password/Vault/Infisical/cloud credential sources
  KMS/HSM/TPM/Secure Enclave operation providers
  HTTP/MCP/OAuth/SSH/cloud signing transports
  Postgres/SQLite/object storage/Kafka/SIEM

plugins/components
  connector SDK
  provider manifests
  action/response schemas
  identity providers
  optional external credential sources and operation providers
  approval providers

testing/headless
  deterministic policy harness
  fake identity/vault/upstream
  connector contract suite
  adversarial agent sandbox
  multi-tenant isolation suite
  replay/fault/fuzz harness
~~~

## 6. Logical Components

### 6.1 Rekey Domain

纯 Rust 领域模型，不依赖：

- Tokio。
- Axum/Hyper/Reqwest。
- 数据库。
- 文件系统或环境变量。
- Cedar evaluator 的具体 API。
- OAuth、SPIFFE、Vault SDK。

主要类型：

~~~text
TenantId
HumanIdentity
AgentIdentity
WorkloadIdentity
DelegationContext
TaskContext
PrincipalTuple
ConnectorId
ActionId
ResourceRef
CanonicalParameters
PolicyVersion
Decision
ApprovalRequirement
ApprovalGrant
CredentialRef
DecisionEvent
ExecutionEvent
DomainError
~~~

### 6.2 Policy Engine

职责：

- 将规范化 Action 转为授权查询。
- 评估 permit、forbid 和 require_approval。
- 激活前验证 schema、实体和策略。
- 返回 decision、reason codes、determining policies 和 obligations。
- 不执行 IO，不读取 Vault，不发出上游请求。

当前 P1.1 已选择内置 typed default-deny evaluator，直接实现精确
principal/action/resource/parameter 匹配和原子 snapshot 激活；本阶段不引入 Cedar、
`PolicyEvaluator` abstraction、AuthZEN、OPA 或外部 PDP。未来若真实企业需求要求第二种
evaluator，先以独立实施规格定义合同和攻击测试。

关键合同：

~~~text
evaluate(snapshot, authorization_request) -> DecisionBundle
~~~

任何 evaluator error 都映射为 deny/error，不允许使用 skip-on-error 产生宽松结果。

### 6.3 Control Plane

职责：

- Tenant、组织、用户、Agent blueprint 和工作负载注册。
- Connector catalog、CredentialRef metadata 和 policy desired state。
- 策略编译、验证、签名、版本发布和回滚。
- Gateway fleet 注册、健康和配置分发。
- Approval workflow。
- 审计索引、查询、导出和合规证据。
- Enterprise license 和能力开关。

控制面默认只存 CredentialRef 和 provider metadata，不存真实秘密。

### 6.4 Gateway Data Plane

职责：

- 验证 Agent session 和 workload attestation。
- 规范化协议请求为 Action。
- 固定策略快照。
- 执行本地授权。
- 验证或请求批准。
- allow 后解析 CredentialRef。
- 通过 Connector 构造上游调用。
- 执行响应过滤、Secret Sealing 和审计。

Gateway 不允许 Agent 调用管理 API。管理监听器和数据监听器必须分离端口、证书和路由。

### 6.5 Edge/Launcher

职责：

- rekey run 启动 Agent。
- 建立本地工作负载身份和会话。
- 注入无秘密 Capability 和固定 Gateway endpoint。
- 配置沙箱 egress。
- 必要时注入每会话 CA，而非系统 CA。
- Agent 退出时撤销会话并清理临时资源。

Edge 不持有企业长期凭据。

### 6.6 Connector

每个 Connector 必须声明：

- 固定 upstream origin。
- 可用 Actions。
- Resource schema。
- Parameter schema 和 canonicalization。
- 风险类别和默认审批要求。
- Credential slots 和允许的 auth scheme。
- 请求构造和 Header 清理。
- redirect、DNS、IP 和 body 限制。
- response schema、敏感字段和 Secret Sealing 行为。
- lifecycle、错误和契约测试。

Connector 不是任意代码逃生口。生产 Connector 需要签名、版本固定、权限声明和独立进程或 WASM 隔离评估。

### 6.7 Credential Authority

Credential Authority 是 Rekey 的第一方核心能力，不是必须由外部 Vault 实现的薄适配层。它拥有：

- Credential metadata、版本、状态、使用约束和加密记录。
- Vault Root Key、包装后的 DEK 和运行时 SecretLease。
- init、unlock、lock、store、rotate、revoke、backup 和 restore 生命周期。
- allow 后的 inject、sign、exchange 和 execute 凭据效果。

公开 Agent/Runtime 合同只有受约束操作：

~~~text
execute(action_request, capability) -> sanitized_result
sign(action_request, capability, digest) -> signature
exchange(action_request, capability) -> short_lived_result
~~~

管理合同只通过独立 Admin API 暴露：

~~~text
initialize(unlock_method) -> recovery_material
unlock(unlock_proof) -> vault_session
store(metadata, secret_input) -> credential_ref
rotate(credential_ref, secret_input) -> credential_version
revoke(credential_ref | version)
backup(destination) -> encrypted_backup_receipt
restore(encrypted_backup, authorization) -> restore_receipt
lock()
~~~

Agent API 永远不存在 `get_secret`、`read_secret` 或 `export_secret`。CLI 和 Dashboard 也不能直接打开数据库；它们是 Admin API 客户端。

#### 6.7.1 第一方内置存储

Community 默认使用版本化 SQLite 加密记录：

~~~text
UnlockMethod -> KEK -> wrapped Vault Root Key
Vault Root Key -> wrapped per-credential DEK
DEK -> AEAD(CredentialVersion, bound metadata as AAD)
~~~

首版采用 Argon2id 和 AES-256-GCM 的成熟实现，保留算法和参数版本字段。密码修改只重新包装 VRK；Credential 轮换创建不可变新版本，不原地覆盖唯一版本。OS Keychain、TPM、Secure Enclave 或企业 KMS 可以增加 KEK wrapper，但不成为默认安装依赖。

#### 6.7.2 可选外部提供者

外部系统分为两类：

~~~text
CredentialSource
  materialize(credential_ref, authorized_context) -> SecretLease

OperationProvider
  sign(credential_ref, authorized_sign_request) -> Signature
  exchange(credential_ref, authorized_token_request) -> ShortLivedCredential
  revoke(lease_id)
~~~

它们只运行在 Broker 信任边界内，用于兼容客户已有 Vault 或获得动态凭据、HSM 和不可导出操作能力。它们不是 Community、内置 Store 或 G2 路径的强制依赖。

凭据使用优先级：

1. sign 或 exchange，不导出根秘密。
2. 动态短期凭据。
3. Broker 内解析长期静态秘密。
4. 禁止把秘密返回 Agent。

## 7. Identity Model

### 7.1 Principal Tuple

~~~text
tenant
human subject, optional
agent blueprint
agent instance
workload identity
task/run
delegation chain
session
~~~

### 7.2 Attended Agent

用户与 Agent 共同参与：

- 用户通过 OIDC/SAML 登录。
- Agent workload 通过本地 peer credential、SPIFFE、Kubernetes、云身份或 mTLS 证明。
- 授权同时评估用户权限和 Agent 权限。
- Agent 权限不能大于用户委托和 Agent blueprint 的交集。

### 7.3 Unattended Agent

没有在线用户：

- Agent 使用独立 workload identity。
- 必须有 owner、purpose、environment、expiry 和 sponsor。
- 高风险动作通过预授权策略或异步审批。
- 禁止借用某个人的长期 Refresh Token 作为默认身份。

### 7.4 禁止的身份来源

- Agent 自报 Header。
- 未验证 JWT claims。
- 可被 Agent 修改的环境变量或配置文件。
- 单纯 IP 地址。
- 共享长期 API Token。

## 8. Normalized Action Contract

~~~json
{
  "principal": {
    "tenant": "t_acme",
    "human": "user_alice",
    "agent": "codex",
    "agent_instance": "a_123",
    "workload": "spiffe://acme.dev/agent/a_123",
    "task": "run_456"
  },
  "action": "github.issue.create",
  "resource": {
    "type": "github.repository",
    "id": "acme/rekey"
  },
  "context": {
    "environment": "development",
    "repository": "acme/rekey",
    "source_revision": "sha256:...",
    "policy_version": "pv_19"
  },
  "parameters": {
    "canonical_hash": "sha256:...",
    "schema_version": "github.issue.create/v1"
  }
}
~~~

原始 HTTP body 不直接成为策略语言。Connector 必须先解析、验证和规范化，避免路径编码、重复 Header、JSON key 顺序、Unicode 或 query 表示差异造成策略绕过。

## 9. Request Lifecycle

1. **Accept**：数据监听器接受受支持协议请求。
2. **Authenticate**：验证 session token 与 workload proof。
3. **Resolve principal**：合成人、Agent、workload、task 和 delegation。
4. **Normalize**：Connector 将请求转换为标准 Action、Resource 和 CanonicalParameters。
5. **Pin snapshot**：固定一个已验证、未过期的 PolicySnapshot。
6. **Evaluate**：返回 deny、allow 或 require_approval。
7. **Approve**：需要时获得参数绑定 ApprovalGrant，并重新确认 snapshot 和参数。
8. **Resolve credential**：最终 allow 后才获取 SecretLease、签名或短期 Token。
9. **Execute**：Connector 构造唯一上游请求；禁止任意 redirect。
10. **Filter response**：应用 response schema、Header policy、size limit 和 Secret Sealing。
11. **Commit evidence**：写入 DecisionEvent 和 ExecutionEvent。
12. **Cleanup**：zeroize、撤销一次性 lease、递减 Capability uses。

请求从第 4 步到第 10 步必须共享同一个 canonical action 和 policy version，防止 TOCTOU。

## 10. State And Source Of Truth

| Contract | Source of truth | Consumers | 禁止的第二来源 |
| --- | --- | --- | --- |
| Tenant/organization | Control plane transactional DB | UI、API、policy compiler | Gateway 本地手改租户配置 |
| Agent blueprint | Control plane versioned object | identity、policy、audit | Agent 自报 metadata |
| Policy desired state | Control plane versioned policy set | compiler | Dashboard 临时状态 |
| Active policy | 已签名 PolicySnapshot | Gateway evaluator | 运行时直接查多张可变表 |
| Connector schema | 版本化签名 Connector package | compiler、Gateway、docs | README 手写复制 |
| Credential value | 内置 Credential Authority 默认存储；可选外部 CredentialSource/OperationProvider | customer Broker only | 控制面数据库、CLI、Dashboard、Agent、Connector |
| Credential metadata/version | Credential Authority；企业 desired metadata 可由 Control plane 发布 | Admin UI、policy、Broker | Connector 私有隐藏配置、CLI 本地副本 |
| Vault key hierarchy | Credential Authority versioned key records | Broker unlock/runtime | 环境变量、argv、Agent filesystem、SaaS 控制面 |
| Session/Capability | 数据面 session store | Gateway/Edge | JWT 内无限期自包含权限 |
| Approval | append-only ApprovalGrant | Gateway、audit | UI 内存状态 |
| Decision evidence | append-only event log | audit/index/export | 普通应用日志 |
| Search projection | 可重建索引 | Dashboard/SIEM | 作为授权权威 |

## 11. Boundary Contracts

| Contract | Owner | Allowed dependencies | Forbidden dependencies | Tests |
| --- | --- | --- | --- | --- |
| Domain state | rekey-domain | serde-compatible values、typed IDs | IO、Tokio、HTTP、DB、env | domain_no_io、serialization_roundtrip |
| Policy decision | rekey-policy | domain、evaluator adapter | Vault、network、control DB | default_deny_matrix、policy_schema_validation |
| Snapshot lifecycle | control compiler + gateway snapshot manager | signature、clock、storage adapter | Agent mutation、partial activation | snapshot_atomic_swap、expired_snapshot_denied |
| Identity | identity runtime | OIDC/SPIFFE/cloud/local adapters | client-supplied identity Header | forged_identity_denied |
| Session | gateway session owner | secure RNG、clock、channel binding | reusable long-term bearer | replay_and_cross_agent_suite |
| Credential Authority state | Broker credential authority | crypto、record store、key wrapper | CLI/Dashboard/Agent 直接 DB、环境变量传密码 | authority_contract、admin_api_isolation |
| Credential effects | Broker executor + optional provider | built-in store、Vault/KMS/HSM SDK | domain/policy/Agent returning secret | credential_after_allow_only、no_secret_export_api |
| Connector effects | connector runtime | domain、HTTP/MCP transport | arbitrary origin、raw policy DB | connector_contract_suite |
| Approval | approval service | domain、identity、event log | natural-language-only grant | approval_parameter_binding |
| Audit | append-only event writer | domain events、outbox/export adapters | secret values、request/response bodies by default | audit_canary_absent、event_chain_valid |
| Error mapping | app/transport boundary | typed domain/runtime errors | warning plus unsafe fallback | error_response_matrix、fail_closed |
| Observability | runtime emitters + exporter adapters | tracing/metrics | credential formatting、content default | telemetry_redaction_suite |
| CLI | product/app | Admin/Agent client APIs | direct DB/Vault mutation、daemon password env | cli_blackbox、daemon_environment_contains_no_password |

## 12. Error Policy

### Domain errors

稳定、可匹配的类型：

- InvalidIdentity
- InvalidAction
- InvalidParameters
- PolicyDenied
- PolicyInvalid
- PolicyUnavailable
- ApprovalRequired
- ApprovalInvalid
- CredentialUnavailable
- ConnectorUnsupported
- UpstreamRejected
- ResponsePolicyViolation
- AuditCommitFailed

### Boundary mapping

- Domain crate 不返回 anyhow。
- Adapter 保留来源错误但去除秘密。
- Gateway 把错误映射为明确 HTTP/MCP error。
- CLI 负责用户可读诊断和退出码。
- 不允许 error 转 warning 后透明 passthrough。
- 重试必须由 typed retry classification 驱动，且不得跨授权边界或跟随新目标。

## 13. Configuration Lifecycle

| 阶段 | 内容 | Owner | 变更方式 |
| --- | --- | --- | --- |
| Build-time | feature flags、FIPS/crypto backend、enterprise modules | release build | 新构建 |
| Startup-time | listen address、control endpoint、trust roots、storage adapter | runtime bootstrap | 重启 |
| Runtime | signed policy、connector packages、tenant routes、limits | snapshot manager | 原子验证和切换 |
| Per-session | Agent identity、task、Capability、sandbox | edge/gateway | session create/revoke |
| Per-request | canonical action、approval、credential lease | request pipeline | 请求生命周期 |

所有 runtime 配置先完整验证，再作为一个版本原子激活；不能逐字段热更新。

## 14. Deployment Modes

### 14.1 Community Local Compatibility

- 单机 CLI 和本地 Gateway。
- 第一方内置 Credential Authority 和 SQLite 加密存储，零外部账户、零外部 Vault 依赖。
- 密码与恢复密钥是基础解锁方式；OS Keychain/TPM/Secure Enclave 是可选便利与加固方式。
- 同一 `rekey` 二进制运行 Admin Client、Agent Client 和 Broker 角色，但 Broker 使用独立进程、文件权限和 IPC。
- 显式 Reverse proxy / 固定 Action 数据面；不包含 MITM、系统 CA 或透明代理。未来若重新评估网络拦截模式，只能作为显式降级且不得标注 G2（见威胁模型 7.3）。
- 默认 G1；只有启用受验证沙箱和强制 egress 后才标记 G2。

### 14.2 Customer-Hosted Data Plane + Managed Control Plane

- 企业首选。
- Gateway 在客户 VPC、Kubernetes 或数据中心。
- 控制面分发签名策略和 Connector。
- 客户可使用 Rekey 内置 Credential Authority，也可接入已有 Vault/KMS/HSM；秘密只存在于客户 Broker 信任边界。
- 审计可只发送 metadata，正文不离开客户环境。

### 14.3 Fully Self-Hosted Enterprise

- Control plane、Gateway、数据库、对象存储和审计全部客户托管。
- 离线 license、升级包和支持。
- 适合受监管和 air-gapped 环境。

### 14.4 Embedded/SDK

- Agent 平台将 open data plane 作为 sidecar、daemon 或 library 使用。
- 必须保持同样的 identity/action/policy/audit 合同。
- 嵌入不能绕过 Connector 和 credential boundary。

## 15. Proposed Rust Workspace Boundaries

先按逻辑边界实现，只有在 API 稳定、效果隔离或独立测试确有价值时拆 crate。

建议最终形态：

~~~text
crates/
  rekey-domain          pure models, invariants, typed errors
  rekey-policy          evaluator facade, schema, snapshot
  rekey-gateway         request pipeline and data-plane lifecycle
  rekey-identity        identity adapter contracts and selected adapters
  rekey-credentials     credential provider contracts and selected adapters
  rekey-connectors      connector SDK, registry, common connectors
  rekey-audit           append-only events, outbox, export contracts
  rekey-edge            local launcher and sandbox integration
  rekey-control         control-plane application services
  rekey-cli             thin CLI
~~~

上述是 v4 候选边界，不是创建新 crate 的要求。当前 domain/policy/vault/broker/cli/connector
分工已经存在；v1 proxy、CA 和 Web 直读数据库均已删除。v4 应复用这些模块，
仅在具体交付需要独立生命周期时再拆分。

## 16. v2 Breaking Deletion 历史记录

以下是 v2 已执行的删除边界，不是当前待实现清单。v3 继续永久不迁移，同一 GA 主版本内冻结格式：

| Current path | 分类 | Action | Verification |
| --- | --- | --- | --- |
| `rekey request name url` | confused deputy | 删除 | CLI snapshot 无该命令 |
| 系统全局 CA、MITM、passthrough | unsafe topology | 删除 rekey-ca/rekey-proxy | workspace member assertion |
| 单端口 dashboard + proxy | mixed trust channel | 删除；改为 Admin/Agent UDS | broker_ipc |
| v1 SQLite secrets/rules | obsolete source of truth | 不读取、不迁移；非空旧目录明确拒绝 | legacy_vault_rejected |
| raw Secret getters | unsafe public API | 删除且无替代 raw getter | no_secret_export_api |
| provider presets/rules | mixed policy/store | 删除；使用 FixedHttpAction | action_contract |
| Web 直读 SQLite | second state owner | 删除 rekey-web | dependency assertion |
| daemon `REKEY_PASSWORD` | secret transport violation | 删除 daemon path | daemon_environment_contains_no_password |

## 17. P0/P1/P2 Roadmap

以下是架构路线图，不是当前完成状态。P0、typed policy、bounded Linux G2 reference、
chunk-boundary sealing、native service-manager 和封闭 GitHub App profile 已有实现；其实际
命令和证据以 [Feature Truth Matrix](feature-truth-matrix.md) 为准。仍引用
`rekey-edge`、`rekey-e2e`、`rekey-credentials`、`rekey-connectors`、`rekey-identity` 或
`rekey-control` 的行是未来目标合同，这些 crate 当前不存在。

| Priority | Work | Modules | Done when | Verification |
| --- | --- | --- | --- | --- |
| P0 | 安全合同与攻击语料 | docs、workspace tests | G1 条件、fail-closed 与 secret canary 语料可运行 | cargo test --test secret_canary |
| P0 | Credential Authority v2 合同 | rekey-vault | 状态所有权、禁止 API、加密层级和 typed errors 固定 | cargo test -p rekey-vault --test authority_contract |
| P0 | Envelope 与 clean v2 bootstrap | rekey-vault storage/crypto/bootstrap | VRK/DEK/AAD、轮换、恢复、旧目录拒绝通过 | cargo test -p rekey-vault --test bootstrap_contract |
| P0 | Broker Admin/Agent IPC | rekey-cli、rekey-broker | CLI 不直读 DB；Agent 无管理和导出能力；密码不进 env | cargo test --test broker_ipc |
| P0 | Domain 模型 | rekey-domain | 无 IO、typed IDs、typed errors | cargo test -p rekey-domain |
| P0 | Fixed HTTP Action 纵向切片 | rekey-broker | authorize-before-secret、bounded response、secret sealing | cargo test -p rekey-broker --test execution_contract |
| P0 | 管理/数据面拆分 | rekey-broker 两个 UDS | Agent socket 无管理消息 | cargo test -p rekey-broker --test agent_ipc |
| P1 | Policy snapshot 和 default-deny | rekey-policy | schema 验证、参数规范化、原子切换 | cargo test -p rekey-policy |
| P1 | Streaming response sealing | rekey-broker | 跨 chunk secret variant 可检测并终止 | cargo test -p rekey-broker --test streaming_sealing |
| P1 | 本地 G2 参考部署 | rekey-edge、rekey-e2e | 至少 Linux 强隔离证明 | cargo test -p rekey-e2e --test linux_g2 |
| P1 | Credential use effects | rekey-credentials | inject/sign/exchange/lease/revoke 契约通过 | cargo test -p rekey-credentials --test effect_contract |
| P1 | Connector SDK | rekey-connectors | GitHub/LLM/generic HTTP 使用统一 schema | cargo test -p rekey-connectors --test contract |
| P1 | Human+Agent+workload identity | rekey-identity | attended/unattended 和伪造测试通过 | cargo test -p rekey-identity |
| P1 | Approval | control、gateway | 精确参数绑定、过期和重放拒绝 | cargo test --workspace approval_parameter_binding |
| P1 | Customer data plane | control、gateway | 签名策略同步、控制面无秘密 | cargo test -p rekey-e2e --test remote_gateway |
| P2 | Enterprise control | rekey-control | SSO/SCIM、fleet、SIEM、HA 合同 | cargo test -p rekey-control |
| P2 | 可选外部 Credential Providers | rekey-credentials | 至少一个真实企业系统通过 provider contract；不影响内置路径 | cargo test -p rekey-credentials --test external_provider_contract |
| P2 | 多区域与 DR | control deployment | RPO/RTO 演练通过 | enterprise disaster-recovery runbook |
| P2 | Connector 隔离 | connector runtime | 插件故障/恶意不破坏 gateway | cargo test -p rekey-e2e --test connector_isolation |

## 18. Validation Matrix

| Contract | Unit | Contract | Integration | Adversarial/E2E |
| --- | --- | --- | --- | --- |
| Action normalization | golden/fuzz | Connector vectors | HTTP/MCP equivalence | encoding ambiguity |
| Identity | claims and tuple | adapter matrix | OIDC/SPIFFE/local | forged/cross-agent |
| Policy | allow/deny/forbid | snapshot compatibility | policy rollout | invalid/expired/rollback |
| Approval | hash and TTL | provider contract | end-to-end write | replay/TOCTOU |
| Credential | secret lifecycle | provider contract | real test vault | env/log/process canary |
| Built-in authority | key hierarchy and versions | Admin/Agent API separation | clean bootstrap/backup/restore | ciphertext swap/unauthenticated metadata rewrite/wrong unlock；旧认证状态 replay 需外部 monotonic anchor |
| Gateway | pipeline | transport contract | streaming upstream | SSRF/redirect/reflection |
| Audit | event schema | exporter contract | query/rebuild | tamper/cross-tenant |
| Lifecycle | init/shutdown | adapter cleanup | rolling upgrade | crash/recovery |

## 19. Observability

允许默认记录：

- tenant、agent blueprint、workload、task。
- Connector、Action、Resource。
- decision、reason、policy version。
- approval ID 和 approver identity。
- credential reference 和 lease type，不含值。
- latency、status、bytes、rate/budget。
- Gateway/Connector version。

默认禁止：

- Authorization/Cookie。
- secret value 或可逆片段。
- Prompt。
- request/response body。
- 原始 OAuth token。
- Vault bootstrap credential。

事件应使用可演进 schema；搜索索引可以重建；关键审计采用 hash chain、WORM 或客户 SIEM 保留策略。

## 20. Non-Goals

- 不重建通用 IdP、PAM、通用 Vault、消费者密码管理器、网络或沙箱平台；内置 Credential Authority 只服务 Rekey Action 执行。
- 不用 LLM 取代确定性授权。
- 不把所有 HTTP 流量都纳入监控。
- 不默认记录内容。
- 不允许 Connector 以插件名义绕过策略和 origin 限制。
- 不在 v2 初期实现全平台、全云、全协议。
- 不保证对宿主内核、Hypervisor、Vault 或 Broker 完全攻陷仍保密。

## 21. P0 Decisions And Remaining Questions

P0/P1.1 已锁定 schema v5 和 binary AAD、单一 recovery key、macOS/Linux 双 UDS、
默认 G1、内置 typed evaluator、内存短期 Capability、audit fail-closed、
FixedHttpAction，以及首个封闭 GitHub App profile。Linux container/namespace recipe 已提供
有界 G2 reference，但不升级默认拓扑。完整 wire、crypto 和 failure-semantics 合同以
[Credential Authority v2 Foundation](../superpowers/specs/2026-08-28-credential-authority-v2-foundation.md)
为准。

可以暂缓：

- 首个公开版本的完整功能列表。
- 高级风险图和异常检测。
- Windows。
- 多区域 active-active。
- 第一个外部 Vault/Secret Manager 集成及其发布时间。
- Control plane 首版服务拆分、Kafka 或多区域事件基础设施。
- 产品更名和许可证不阻塞本地安全内核实现，但阻塞公开品牌发布。

## 22. Implementation Entry Gate

不能从本架构文档直接展开所有 v2 开发。以下入口门槛中，P0 规格、clean bootstrap、
合同测试、纵向切片和第二阶段条件已有实现证据；独立 crypto/IPC/audit 人工安全评审仍是
合并与安全发布前的未完成门槛：

1. **P0 实施规格**：锁定 Vault v2 schema、加密 envelope、AAD canonical encoding、Admin/Agent IPC、错误类型和 breaking deletion 清单。
2. **Clean bootstrap**：v2 不读取或迁移 `~/.rekey/vault.db`；目标目录非空时明确拒绝，不自动删除用户数据。
3. **先失败的合同测试**：先增加 `authority_contract`、`bootstrap_contract`、`legacy_vault_rejected`、`broker_ipc`、`daemon_environment_contains_no_password` 和 `no_secret_export_api`。
4. **单一纵向切片**：只实现本地单用户、内置 Store、一个类型化 Action、Broker Admin/Agent IPC 和 G1 安全声明；不同时创建企业控制面、外部 Vault 或插件系统。
5. **安全审查门**：认证、凭据、加密、存储、IPC 和日志改动在合并前进行人工安全评审，并运行 `cargo check --workspace`、目标测试、`cargo test --workspace` 和 `cargo fmt --all --check`。
6. **第二阶段条件**：只有纵向切片证明 Agent 无 Secret API、CLI 不直读数据库、密码不进 env、旧目录被明确拒绝且未被修改后，才进入 Policy、Connector 和 Linux G2 扩展。

建议第一个实施 spec 的范围名称：`Credential Authority v2 Foundation`。它不包含企业 HA、多租户、外部 Vault、完整 Connector SDK、Windows 或公开版本包装。

## 23. Readiness

本架构基线已经锁定内置 Credential Authority 的产品所有权、状态所有者、禁止接口、加密层级、部署位置和 breaking rewrite 方向；详细实施合同见 [Credential Authority v2 Foundation](../superpowers/specs/2026-08-28-credential-authority-v2-foundation.md)。当前提交已经通过 required macOS/Ubuntu CI、原生 launchd/systemd、release-process P0、P1 policy/sealing、有界 Linux G2-reference、P2.1 local GitHub App，以及一次真实 `github.com` GitHub App 验证；实际状态以 [Feature Truth Matrix](feature-truth-matrix.md) 为准。这些证据仍不足以声称生产就绪、默认拓扑达到 G2，或等价于 Aperture、Aembit、AgentCore 等完整产品。
