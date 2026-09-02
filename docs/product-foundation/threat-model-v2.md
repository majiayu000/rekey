# Rekey v2 威胁模型与“Agent 不得获得密钥”安全合同

状态：基线草案 v2

日期：2026-08-28

范围：资产、攻击者、信任边界、部署等级、安全保证、限制与验证
相关文档：[功能事实矩阵](./feature-truth-matrix.md) · [P0 实施规格](../superpowers/specs/2026-08-28-credential-authority-v2-foundation.md)

## 1. 核心结论

可以让 Agent 在使用 API、MCP、SSH 或其他受保护资源时完全拿不到真实密钥，但这个保证必须建立在明确的系统边界上。

正确的安全合同是：

> 在强隔离部署中，Agent、Agent harness、Agent 启动的子进程、Agent 可读文件系统以及 Agent 所在网络命名空间，永远不会接收、读取或导出真实凭据。真实凭据只在独立可信的 Rekey 数据面或外部密码学设备中短暂解析，并在授权通过后直接用于一次受约束的上游操作。

这个保证不意味着秘密在整个系统中从未出现：

- 对 Bearer Token、API Key、Basic Auth 等可导出凭据，明文会短暂存在于可信 Broker 内存和 Broker 到上游的 TLS 请求构造过程中。
- 对 SSH 私钥、HSM 密钥、云签名身份等不可导出凭据，Broker 可以只请求签名或 Token Exchange，连 Broker 也不获得原始私钥。
- Agent 只持有无秘密价值、短期、可撤销、受会话约束的 Capability。

如果 Broker 与 Agent 运行在同一 OS 用户下，Agent 拥有完整 Shell，且没有文件、进程和网络隔离，则只能降低误泄漏，不能声称恶意 Agent 永远拿不到秘密。

## 2. “Agent”安全边界的定义

本威胁模型中的 Agent 不是只指 LLM。

不可信 Agent 边界包括：

- 模型及其上下文。
- Agent harness 和插件。
- MCP Client。
- Agent 生成或修改的代码。
- Agent 启动的 shell、curl、git、SDK、编译器、测试和任意子进程。
- Agent 可访问的环境变量、argv、文件、IPC、日志和进程信息。
- Agent 容器或沙箱中的 root。
- Agent 能访问的网络。
- 来自网页、Issue、README、工具输出和依赖的恶意指令。

只要其中任意组件能读取真实凭据，就不满足强隔离保证。

## 3. 保护资产

| 资产 | 安全目标 |
| --- | --- |
| 长期 API Key、PAT、密码、Refresh Token | 不进入 Agent 边界；可轮换；不可被重定向 |
| Vault Root Key、包装密钥和恢复材料 | 不持久化明文；不进入 Agent、CLI 参数、环境变量或普通日志 |
| Credential ciphertext、版本和元数据 | 防未认证篡改和跨记录替换；不保证旧的已认证状态 freshness；可备份和恢复 |
| 私钥和签名密钥 | 尽量不可导出；签名需策略和批准 |
| 外部 Vault bootstrap credential | 仅存在于 Broker 信任边界 |
| 用户委托 | 不能被扩大、转移、重放或跨任务使用 |
| Agent/工作负载身份 | 不能由 Agent 自报或伪造 |
| 策略 | 不可被 Agent 修改；版本可验证 |
| 审批 | 与精确动作和参数绑定；不可重放 |
| 审计证据 | 完整、按租户隔离、可验证、默认无正文秘密 |
| CA、mTLS、签名配置 | 不可被 Agent 读取或替换 |
| 多租户边界 | 一个租户不能发现或使用另一租户的身份、策略和凭据 |

## 4. 威胁参与者

1. 被 Prompt Injection 劫持的 Agent。
2. 主动恶意的 Agent harness、MCP Server 或插件。
3. Agent 生成并执行的恶意代码。
4. 同一主机上的低权限恶意进程。
5. 拥有 Agent 容器 root、但没有宿主 root 的攻击者。
6. 恶意或被攻陷的上游 API。
7. 被攻陷的 Rekey 数据面、控制面或 Connector。
8. 恶意租户管理员或被盗企业账户。
9. 网络攻击者、DNS 攻击者和供应链攻击者。

宿主内核、Hypervisor、HSM 和外部 Vault 的完全攻陷属于残余风险，不在“Agent 无法获得密钥”的直接保证内，但必须进入企业风险说明和纵深防御。

## 5. 信任组件

### 强隔离模式中的可信组件

- Rekey Gateway/Broker 数据面。
- Rekey 内置 Credential Authority 及其第一方加密存储实现。
- 数据面加载的已验证策略快照。
- 身份证明适配器。
- 可选外部 Vault、KMS、HSM、TPM、Secure Enclave 或密码管理器。
- 宿主内核、Hypervisor 或容器隔离边界。
- 数据面到上游的 TLS 实现。
- 审批签发组件。

### 不可信组件

- Agent 及其所有后代进程。
- Agent 提供的任何身份 Header。
- Agent 提供的目标 URL、Host、路径、Header 和请求体。
- 工具描述、MCP metadata、OpenAPI 文档和网页内容。
- 上游响应正文和 Header。
- 可选 LLM 风险分类器的 allow 结果。

## 6. 安全保证等级

| 等级 | 名称 | 能保证什么 | 不能保证什么 |
| --- | --- | --- | --- |
| G0 | 存储卫生 | 密钥不写入代码仓库和普通配置文件 | Agent 运行时仍可能拿到密钥 |
| G1 | 上下文隔离 | 密钥不进入 Prompt；配置使用引用 | Agent 进程、MCP Server 或子进程可能从 env/文件读取 |
| G2 | Broker 隔离 | Agent 进程和网络都无法读取、重定向或绕过 Broker 获得密钥 | 不抵御宿主内核、Broker、Vault 或上游完全攻陷 |
| G3 | 不可导出操作 | 私钥或根身份连 Broker 也不能导出，只能签名、兑换或执行 | 只适用于支持 HSM、SSH Agent、STS、OAuth 等协议的资源 |

公开宣传“Agent 拿不到真实密钥”至少需要 G2。对于 SSH、云身份和签名场景，应优先达到 G3。

## 7. 推荐的无密钥执行路径

### 7.1 MCP 或类型化 Action，最强首选

~~~text
Agent
  │  action + parameters + rkcap session token
  ▼
Rekey Gateway
  │  验证 user + agent + workload + task
  │  规范化参数
  │  固定 policy version
  │  allow / deny / require approval
  │  allow 后才解析 credential reference
  ▼
Credential Provider / HSM / OAuth
  │
  ▼
Connector 构造固定上游请求
  │
  ▼
上游服务
  │
  ▼
响应 schema、Header 和 secret sealing
  │
  ▼
Agent 仅看到允许返回的数据
~~~

Agent 不能控制 Authorization Header、真实目标 origin、重定向行为或凭据解析。

### 7.2 显式 Reverse Proxy，兼容任意 HTTP

Agent 请求 Rekey 提供的固定 Connector endpoint。Gateway 根据 Connector 配置决定真实 origin，移除客户端 Authorization、Cookie 和敏感 Header，再按策略构造上游请求。

此模式必须：

- 禁止 Agent 指定任意上游 URL。
- 禁止自动跟随 redirect。
- Host、SNI、DNS 解析结果和连接 IP 一致验证。
- 私网、link-local、metadata endpoint 默认拒绝。
- 解析与连接之间防止 DNS rebinding。
- 请求 Header 使用替换语义，不允许重复 credential header。
- 对 method/path/query/body/content-type/size 做约束。

### 7.3 非 v2 P0：未来若评估网络拦截模式

v2 P0 删除透明 MITM、系统 CA 和任意 TCP passthrough，不提供旧代理兼容路径。未来只有出现不能接入显式 Action/Connector、且有真实设计伙伴证据的场景时，才重新评估网络拦截模式。它只有在 Agent 所在容器、VM 或网络命名空间无法绕过 egress gateway 时才可能达到 G2。

要求：

- 每个 Agent 会话独立 CA 或受控短期 CA。
- CA 只注入该沙箱，不写入系统全局信任库。
- Agent 无法读取 CA 私钥。
- 宿主防火墙或 Hypervisor 强制所有目标流量经过数据面。
- 未匹配目标默认拒绝，而不是透明 passthrough。
- 证书、SNI、Host 和策略目标必须一致。

本地同用户、系统 CA、自由 egress 的 MITM 最多只能标记为 G1，不能作为 v2 安全承诺或默认发布路径。

## 8. 凭据生命周期

### 8.1 内置 Credential Authority 的密钥层级

内置实现采用信封加密，不允许由用户密码直接长期加密所有 Credential：

~~~text
password / recovery key / OS keystore / enterprise KMS
  -> Key Encryption Key (KEK)
  -> wraps Vault Root Key (VRK)
  -> wraps per-credential Data Encryption Key (DEK)
  -> encrypts one immutable CredentialVersion
~~~

首个实现继续使用经过维护的 Argon2id 和 AES-256-GCM 库，不自行设计密码学算法。每个 CredentialVersion 使用独立随机 nonce，并以 vault、tenant、credential、version、type、provider 和约束元数据作为 AAD，防止密文跨记录替换。

当前 Foundation 在初始化时创建 password 和 recovery 两个 VRK wrapper；recovery key 只用于解锁、显式 Admin step-up 或验证离线 backup restore，不修改密码或替换 wrapper。未来若单独实现修改密码或新增恢复方式，只应重新包装 VRK。轮换单个凭据生成新版本和新 DEK；旧版本按保留策略撤销或密码学删除，不允许原地覆盖唯一可恢复版本。

### 8.2 解锁与运行时生命周期

1. `rekey init` 生成随机 VRK、恢复材料和版本化加密格式。
2. 密码只用于派生 KEK；不得通过 argv、环境变量、普通文件或日志传递给守护进程。
3. Broker 通过受保护的本地 IPC、TTY 或平台安全 UI 完成解锁；错误密码必须在解锁阶段明确失败。
4. Broker 是解密材料和 Credential mutation 的唯一状态所有者。CLI、Dashboard、Agent、MCP Server 和 Connector 不直接打开 Vault 数据库。
5. 自动锁定、显式锁定、退出和崩溃恢复必须清理 VRK、DEK、SecretBuffer 和未使用 Lease。
6. OS Keychain、TPM、Secure Enclave、KMS 和 HSM 是可选 KEK wrapper 或不可导出操作提供者，不是 Community 运行的前置依赖。

### 8.3 每次 Action 的使用生命周期

1. 策略只引用 CredentialRef，不包含真实值。
2. 收到请求后先完成身份、Action 规范化、策略和批准验证。
3. 只有最终 allow 后才请求 Credential Authority 生成 SecretLease、签名或短期 Token。
4. 凭据在最小作用域内进入 SecretBuffer，不实现 Debug、Clone、Serialize 或日志格式化。
5. 请求构造结束后立即 zeroize；连接池和重试不得隐式复制秘密。
6. 审计只记录 CredentialRef、版本和用途，不记录值。
7. 会话结束后撤销 Capability；动态凭据按用途立即失效或等待短 TTL。
8. 长期凭据轮换不要求重启 Agent。

### 8.4 禁止的接口

Agent 数据面和公开 Runtime 接口永久禁止：

- `get_secret`、`read_secret`、`export_secret` 或等价原始值返回接口。
- 接收 `credential_ref + arbitrary_url` 的通用请求接口。
- 将 Secret 注入 Agent 的 env、argv、临时文件、配置文件或 stdin。
- 让 Agent 获得 Vault 数据库路径、VRK、KEK、外部 Vault Token 或管理 IPC。

管理面可以支持人工确认后的加密备份、恢复和未来格式升级，但不得复用 Agent 数据面通道，也不能把明文导出作为正常工作流。v2 P0 不读取、迁移或覆盖 v1 Vault。

## 9. Capability 与批准模型

Agent 获得的 Capability 不是真实上游凭据。

首版建议使用：

- 不透明随机 Token。
- 服务器端会话记录。
- 短 TTL。
- 明确 tenant、human、agent、workload、task 和 audience。
- 可立即撤销。
- 绑定数据面实例或 mTLS 通道。
- 不作为 Vault API Token。

批准必须绑定：

~~~text
tenant
principal tuple
connector
operation
resource
canonical parameter hash
policy version
expiry
max uses
approver
~~~

参数变化、策略变化、身份变化或超时后必须重新授权。批准不能只绑定自然语言说明。

## 10. 响应方向保护

仅保护出站注入不足以保证秘密不回到 Agent。恶意或错误上游可能反射 Authorization、Cookie、Token 或签名材料。

数据面必须：

- 删除 hop-by-hop Header。
- 默认删除 Set-Cookie、WWW-Authenticate 中敏感值和上游调试认证 Header。
- 在流式响应中跨 chunk 检测本次注入秘密的精确字节和常见编码变体。
- 命中后中止或结构化脱敏，产生高优先级安全事件。
- 对类型化 Connector 使用响应 schema 和字段 allowlist。
- 限制响应体大小；超限明确报错，不能截断后返回 200。
- 禁止把完整响应写入审计。

当前 Secret Sealing 检测 raw、base64、base64url、percent-encoded 和跨 chunk
反射。它不保证识别任意压缩、加密、哈希派生、拆分或业务自定义编码，因此类型化
Action 和最小响应 schema 比通用透明代理更强。任何新增 canonicalization 规则都必须
配套攻击测试。

## 11. 主要攻击与控制

| 攻击 | 必需控制 | 计划验证 |
| --- | --- | --- |
| Agent 读取 env/argv | Agent 环境只含占位符和 Capability；Vault Token 只在 Broker | agent_env_contains_no_secret |
| 主密码经 daemon 环境泄漏 | 受保护 IPC/TTY 解锁；禁止 `REKEY_PASSWORD` 传递 | daemon_environment_contains_no_password |
| Agent 读取 Broker 进程内存 | 独立 OS 用户/VM；禁止 ptrace；不同 PID namespace | agent_cannot_ptrace_broker |
| Agent 读取 Vault/SQLite/CA | 文件所有权和 namespace 隔离；Agent 无挂载 | agent_cannot_read_broker_state |
| 密文跨 Credential/版本替换 | AEAD AAD 绑定完整记录身份和版本 | ciphertext_record_swap_rejected |
| Vault 未认证篡改/跨记录复制 | Credential lifecycle seal 与 AAD identity binding | credential_state_tamper_rejected |
| 旧的已认证 Credential record/subgraph replay | G1 不防 freshness replay；G2 阻止 Agent 访问状态，企业版需数据库外单调锚点或远程透明日志 | G1 明示限制；企业 gate 待设计 |
| 重启绕过密码尝试限速 | 当前 backoff 为进程内状态，重启后重置；G1 Alpha 明示接受，不把重启视为认证防线 | lifecycle_contract + 用户文档限制 |
| 未授权管理 IPC | 独立 socket/pipe、peer identity、权限和 capability | agent_cannot_call_admin_api |
| 备份或恢复泄密 | 只输出版本化密文；恢复先验证完整性和所有权 | backup_restore_no_plaintext |
| 修改 host/path/policy 导流 | 策略只读签名快照；管理面独立；目标固定 | tampered_policy_rejected |
| 任意 URL confused deputy | Connector 固定 origin；无通用 credential+URL API | arbitrary_origin_denied |
| DNS rebinding/SSRF | 解析固定、IP 验证、私网策略、redirect 禁止 | dns_rebinding_denied |
| 重复 Authorization Header | 先移除全部敏感 Header，再唯一设置 | duplicate_auth_header_replaced |
| 上游重定向到攻击域 | 不自动跟随；每一跳重新授权 | credential_redirect_denied |
| 上游反射秘密 | 流式 secret sealing 和响应 schema | reflected_secret_blocked |
| Agent 绕过代理直连 | 宿主/Hypervisor egress deny-by-default | direct_egress_denied |
| 调用 Vault API | Vault endpoint 不可路由；Broker 身份不可读 | vault_unreachable_from_agent |
| Capability 重放 | audience/channel/task/TTL/use-count 绑定 | capability_replay_denied |
| 跨 Agent 使用 | 绑定 workload attestation 和 session | cross_agent_token_denied |
| 审批后改参数 | canonical parameter hash | approval_parameter_tamper_denied |
| 策略服务离线 | 有效快照内按策略运行；过期后拒绝 | expired_policy_fails_closed |
| 审计失败后继续高危写入 | 高风险动作将关键审计写入视为提交条件 | critical_audit_failure_denies |
| 多租户混淆 | tenant 进入每个主键、缓存键和授权查询 | cross_tenant_isolation_suite |
| 日志泄漏 | Secret 类型不可格式化；结构化日志字段 allowlist | log_canary_absent |
| Agent 容器 root | Broker 在容器外；宿主强制网络 | container_root_cannot_escape |
| 控制面被攻陷 | 控制面无真实秘密；策略签名、数据面限制 | forged_control_policy_rejected |

## 12. 1Password 和外部 Vault 的参考价值与边界

### 12.1 应借鉴的模式

1Password SSH Agent 的核心模式非常适合 Rekey：客户端只能请求签名，私钥不会离开 1Password 应用，且使用需要授权。这是 G3 的典型实现。

1Password Agentic Autofill 也值得参考：用户批准后，凭据经端到端加密通道送到可信浏览器扩展并直接填入目标页面；Agent 不直接处理秘密。

可以形成两类可选 Rekey Adapter：

- Secret Resolver Adapter：Broker 从 1Password Connect/SDK 解析 API Key。
- Operation Provider Adapter：像 SSH Agent 一样只执行签名、登录或授权动作，不返回秘密。

### 12.2 不满足 G2 的用法

- 在 Agent 进程中调用 op read。
- 用 op run 把秘密注入 Agent 或 Agent 可控制的 MCP Server 环境。
- 把 OP_SERVICE_ACCOUNT_TOKEN 放入 Agent 环境。
- 让 Agent 直接访问 1Password Connect 或 SDK。
- 把任何外部 Vault 变成 Rekey Community、内置 Store 或 G2 安全路径的强制依赖。

1Password 官方文档确认 op run 会把秘密提供给子进程环境；其 SDK 教程也明确警告直接向 AI 模型暴露原始凭据有显著风险。

来源：

- [1Password SSH Agent](https://www.1password.dev/ssh/agent)
- [1Password Agentic Autofill](https://www.1password.dev/agentic-autofill)
- [1Password Connect](https://www.1password.dev/connect)
- [1Password CLI Secret Loading](https://developer.1password.com/docs/cli/secrets-scripts)
- [1Password AI Agent SDK Tutorial](https://www.1password.dev/sdks/ai-agent)

## 13. 错误策略

| 错误 | 行为 |
| --- | --- |
| 身份缺失或验证失败 | 拒绝，401/403 |
| 策略缺失、无匹配或 evaluator error | 拒绝，记录决策原因 |
| 策略快照过期或签名失败 | 拒绝 |
| 凭据无法解析 | 拒绝，502/503；不得无凭据重试 |
| Vault 未解锁、完整性失败或版本不兼容 | 拒绝；不得静默创建新 Vault 或跳过损坏记录 |
| 密钥包装、备份恢复或格式升级失败 | 保留原版本并拒绝提交；不得部分成功 |
| 审批服务不可用 | 需要批准的动作拒绝 |
| 审计普通指标失败 | 可按策略继续低风险读；显式 diagnostic |
| 审计提交失败且动作是高风险写 | 拒绝或使用事务性 outbox 后执行 |
| 响应超过限制 | 明确 502/413；不得成功截断 |
| Secret Sealing 命中 | 中止/脱敏，记录安全事件 |
| Connector 不支持某认证类型 | 显式 unsupported，不回退到裸请求 |

## 14. 残余风险和不可能保证

以下情况不能承诺 Agent 永远拿不到秘密：

- Agent 拥有宿主 root、内核或 Hypervisor 控制权。
- Agent 与 Broker 同用户运行且能 ptrace、读文件或修改网络。
- Agent 可以绕过 Gateway 直接访问 Vault 或上游。
- Broker、Vault、HSM、密码管理器或上游服务被完全攻陷。
- 用户主动要求把秘密返回 Agent。
- 上游通过任意变换、侧信道或业务数据编码秘密，而 Connector 没有响应 schema。
- 第三方 CLI 协议只能通过环境变量接收秘密，且该 CLI 属于 Agent 可控边界。

产品必须展示当前部署等级和未满足条件，不能把 G1 标为 G2。

## 15. 验证矩阵

以下为 v2 实现后的强制验证名称。P0 行与 [P0 实施规格](../superpowers/specs/2026-08-28-credential-authority-v2-foundation.md)的验证命令一致；P1 及之后行的 crate 命名以各自未来实施 spec 为准。

| 阶段 | 层级 | 测试 | 通过条件 |
| --- | --- | --- | --- |
| P0 | 内置 Credential Authority | cargo test -p rekey-vault --test authority_contract | envelope、AAD、轮换、锁定、恢复和零化合同通过 |
| P0 | Clean bootstrap | cargo test -p rekey-vault --test bootstrap_contract | 全新 v2 初始化成功；非空目录和 v1 布局明确拒绝且不修改原始数据 |
| P0 | Broker IPC | cargo test --test broker_ipc | Agent 不能调用管理 API、读取或导出 Secret |
| P0 | 数据面对抗 | cargo test -p rekey-broker --test adversarial_http | 表中 P0 范围攻击用例拒绝或安全执行 |
| P0 | 反射秘密 | cargo test -p rekey-broker --test reflected_secret | 缓冲响应中的注入秘密及编码变体被阻断 |
| P0 | 日志 | cargo test --test secret_canary | 所有日志、错误和审计中不存在 canary |
| P0 | 故障注入 | cargo test -p rekey-vault --test fault_injection | storage/audit/crypto 故障按合同 fail closed |
| P1 | 策略引擎 | cargo test -p rekey-policy | default-deny、forbid、schema、参数哈希和错误矩阵全通过 |
| P1 | Linux 隔离 | cargo test -p rekey-e2e --test linux_g2 | Agent root 仍不能读 Broker/Vault 或直连 |
| P1 | 流式响应 | cargo test -p rekey-broker --test streaming_sealing | 跨 chunk 反射可检测并中止 |
| P1+ | macOS 隔离 | cargo test -p rekey-e2e --test macos_sandbox | Agent 子进程无秘密、无全局 CA、无旁路 |
| P1+ | Connector 契约 | cargo test -p rekey-connectors --test contract | origin、Header、redirect、body、response 策略一致 |
| P1+ | Fuzz | cargo fuzz run action_normalization | 规范化无解析分歧、panic 或策略绕过 |
| P2 | 多租户 | cargo test -p rekey-control --test tenant_isolation | 跨租户读取、缓存和 token 全拒绝 |

上表里标为 P0 且 crate 已存在的命令（`authority_contract`、`bootstrap_contract`、`broker_ipc`、`adversarial_http`、`reflected_secret`、`secret_canary`、`fault_injection`）已经在本仓库实现，并以 `docs/product-foundation/feature-truth-matrix.md` 为是否“通过”的唯一状态源。P1 typed policy、bounded Linux G2 reference、chunk-boundary sealing 和 native service-manager，以及 P2.1 GitHub App local profile 已有对应实现和门槛；通用 Connector SDK、fuzz、macOS G2、企业多租户 control plane 与 HA/DR 仍是计划合同，不能视为已经通过。

## 16. 已锁定与待决事项

### 已锁定

- 强安全承诺要求 G2。
- Agent 边界包含所有子进程和工具。
- Agent 不获得 Vault 访问能力。
- 内置 Credential Authority 是第一方默认实现，外部 Vault 不构成运行前置条件。
- Broker 是解密凭据和 Credential mutation 的唯一状态所有者。
- Agent/Runtime 公共 API 永远不提供 Secret 读取或导出。
- 内置存储使用版本化信封加密；密码、恢复密钥和平台/KMS 只包装 VRK。
- 凭据在授权完成后才解析。
- 强模式 egress 默认拒绝。
- 类型化 Action 优先于透明 MITM。
- 响应方向必须防止凭据反射。

### 当前范围已锁定

- Linux container/namespace recipe 是首个有界 G2 reference；默认部署仍为 G1。
- macOS 当前只承诺 G1，不提供通用强隔离保证。
- Capability 是双 UDS 上的内存短期 bearer token，不持久化、不复制，重启即失效。
- Audit 使用本地 SQLite/WAL fail-closed；尚未设计 enterprise outbox。
- Secret Sealing 命中即中止并返回空 Agent error response，不做脱敏回退。
- 本地恢复材料使用单一 recovery key。
- recovery key 当前只用于解锁、显式 Admin step-up 或验证 backup restore；Foundation 不提供密码修改、重置或 wrapper 替换。
- idle lock、central stop 和 in-flight drain 行为由 Foundation spec 锁定并已有攻击测试。

### 未来范围待决

- 通用 G2 产品部署最终采用 native namespace、gVisor、Firecracker 或其他隔离边界。
- macOS 强隔离是否采用 Seatbelt、Virtualization.framework 或独立虚拟机。
- 跨主机 Gateway/Agent 是否要求双向 mTLS 或 DPoP。
- 集群 Capability 的持久化、复制和撤销模型。
- 企业审计采用事务性 outbox、WORM 或客户 SIEM 的具体合同。

## 17. Readiness

本威胁模型已经锁定内置 Credential Authority 的密钥层级、状态所有权和禁止接口。当前 P0/P1/P2.1 local gates 的实际状态以 Feature Truth Matrix 为准；required systemd gate 和一次真实 `github.com` GitHub App provider 验证已经完成。默认同用户拓扑仍只有 G1，有界 Linux container/namespace recipe 的 G2 证据不能外推为通用产品保证；单一 GitHub provider/host 证据也不能外推为通用 Connector 保证。在独立 crypto、IPC 边界和 audit/failure-semantics 人工审查完成前，不能对外声称恶意 Agent 在所有部署中永远无法获得或重定向密钥。
