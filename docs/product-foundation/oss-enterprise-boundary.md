# Rekey 开源、商业版本与企业化边界

状态：v4 商业研究稿（v3 个人优先；非发布承诺）  
日期：2026-08-28  
范围：Community、Cloud、Enterprise 的价值边界、许可证原则、商业模式、发布与决策  
相关文档：[v3 个人优先规格](../superpowers/specs/2026-10-02-rekey-v3-personal-first.md) · [威胁模型](./threat-model-v2.md) · [企业架构](./enterprise-architecture-v2.md) · [P0 实施规格](../superpowers/specs/2026-08-28-credential-authority-v2-foundation.md)

## 1. 结论

推荐采用：

> 开放数据面和安全核心，商业化集中控制、规模治理、托管运营、合规能力与企业支持。

开源版本必须足够安全、足够完整，能够在个人、小团队和单组织环境真实使用。安全正确性不能成为付费墙，否则开源无法建立信任，企业客户也无法先验证后采购。

企业付费的理由应是：

- 管理大量 Agent、Gateway、用户、策略和环境。
- 与现有 IdP、Vault、SIEM、审批和合规系统集成。
- 获得 HA、灾备、数据驻留、长期证据和安全支持。
- 降低自建控制面的运维和事故责任。

Community 不依赖 1Password、OpenBao、Vault、Infisical 或任何商业账户。内置 Credential Authority 是开源安全核心和默认凭据来源；外部系统只在客户已有资产或需要动态凭据、KMS/HSM 时作为可选集成。

## 2. 开源承诺

Community 必须永久包含：

1. 完整可用的数据面。
2. Agent 不获得真实密钥的 G2 实现能力。
3. 默认拒绝和所有 fail-closed 行为。
4. Action Schema、策略执行、参数约束和基础批准。
5. HTTP 和 MCP 核心协议支持。
6. Connector SDK、签名格式和契约测试。
7. 基础身份适配器和 OIDC。
8. 基础审计、导出和零内容留存。
9. 第一方内置 Credential Authority、版本化信封加密、轮换、锁定和加密备份恢复。
10. Credential Source/Operation Provider 开放合同；首个公开版本不强制实现外部 Vault。
11. Docker、Helm 或等价自托管方式。
12. 威胁模型、攻击测试和安全修复。
13. 本地 CLI、Gateway 和参考沙箱部署。

不得把以下内容变成商业专属：

- 安全漏洞修复。
- 加密、密钥零化和秘密日志清理。
- 内置 Credential Authority 的基本初始化、解锁、轮换、备份和恢复。
- default-deny。
- SSRF、DNS rebinding、redirect 和 Header 防护。
- 多租户隔离修复。
- response secret sealing 基础能力。
- 策略验证。
- Connector 安全契约。
- 漏洞披露和安全公告。

## 3. 产品分层

| 能力 | Community OSS | Team/Cloud | Enterprise |
| --- | --- | --- | --- |
| 本地 CLI 和 Agent launcher | 完整 | 完整 | 完整 |
| 开放 Gateway 数据面 | 完整 | 托管/客户侧 | 客户侧/自托管 |
| HTTP/MCP 核心 | 完整 | 完整 | 完整 |
| Action Schema 和策略引擎 | 完整 | 托管策略管理 | 企业策略包和外部 PDP |
| 基础 OIDC | 包含 | 包含 | 包含 |
| SAML、SCIM、LDAP | 可社区扩展 | 可选 | 商业支持 |
| 单组织 RBAC | 包含 | 包含 | 包含 |
| 多组织、组织层级、自定义角色 | — | 有限 | 完整 |
| 基础审批 | 本地/单组织 | 团队审批 | ServiceNow/Jira、多级、职责分离 |
| 内置 Credential Authority | 完整、第一方默认 | 托管配置/团队治理 | HA、KMS/HSM、恢复治理和认证支持 |
| Credential Provider 接口 | 完整 | 完整 | 完整 |
| 外部 Vault adapters | 可选社区集成 | 托管配置 | 企业认证和支持矩阵 |
| 常用 Connectors | 开源 | 托管 OAuth | 认证 Connector、私有 Connector |
| Gateway fleet | 手工/GitOps | 托管 | 大规模、多区域、策略分批 |
| 审计 | 基础查询和导出 | 较长保留 | 自定义保留、WORM、SIEM |
| 风险图和 Agent inventory | 基础 | 团队视图 | 企业发现、访问图和治理 |
| HA/DR | 社区自行搭建 | SaaS 托管 | 商业 HA、DR、演练 |
| KMS/HSM/BYOK | 接口开放 | 部分 | 完整支持和认证 |
| 数据驻留/air-gap | 自行部署 | 区域选项 | 专属区域、离线包 |
| SLA 和安全支持 | 社区 | 标准支持 | 约定 SLA、命名支持、事故响应 |
| 合规证据 | 基础事件 | 标准报告 | SOC 2/ISO 映射、证据包 |

表中“商业支持”不等于协议实现必须闭源。开放标准、数据面互操作和安全核心应保持开放；收费点可以是经认证的集成、管理体验、规模、运营和支持。

## 4. 推荐的代码所有权边界

~~~text
public repository
  domain models
  action schema
  policy engine facade
  gateway data plane
  edge/launcher
  connector SDK
  common connectors
  built-in credential authority
  encrypted record format and clean bootstrap
  password/recovery unlock and local key wrappers
  credential provider SDK
  optional common vault adapters
  base audit
  CLI
  threat model and adversarial tests
  protocol specifications

commercial modules or separate repository
  hosted control-plane operations
  enterprise fleet orchestration
  multi-node credential availability and recovery operations
  SCIM/LDAP enterprise administration
  multi-org hierarchy
  advanced approval workflow
  long-retention audit and compliance packs
  SIEM enterprise packages
  risk/access graph
  managed OAuth applications
  enterprise connector certification
  license/SLA/support tooling
~~~

控制面领域合同和 wire protocol 仍需公开，避免开放数据面被单一闭源服务锁死。商业实现可以收费，但客户应能验证数据面接收了什么策略、发出了什么证据。

## 5. 许可证原则

### 5.1 当前事实

当前仓库声明 MIT。已经公开的 MIT 版本所授予的权利不能撤回。

### 5.2 可选方案

#### 方案 A：保持 MIT Core + 商业 Enterprise

优点：

- 采用门槛最低。
- 与 Infisical Agent Vault 当前模式相近。
- 适合嵌入 Agent runtime、IDE 和云平台。

风险：

- 竞争者可以直接托管或 fork 核心。
- 需要依靠控制面、品牌、Connector、运营和企业关系形成壁垒。

#### 方案 B：Apache-2.0 Core + 商业 Enterprise

优点：

- 对企业更明确的专利授权。
- 保持宽松开源和生态嵌入。
- 适合作为协议和数据面基础设施。

风险：

- 同样不能阻止托管竞争。
- 已有 MIT 历史仍保留原许可。

#### 方案 C：AGPL Core + 商业双许可

优点：

- 对闭源托管 fork 有更强约束。
- 可以销售商业例外许可。

风险：

- 部分企业、平台和嵌入式集成会回避 AGPL。
- 法务、贡献者协议和双许可管理更复杂。

### 5.3 当前建议

在没有外部贡献者和公开品牌投入前完成律师评估。产品策略上优先考虑 Apache-2.0 或保持 MIT 的开放数据面，加独立商业控制面。

不建议使用自定义“伪开源”许可证后仍宣传为 Open Source。若采用 source-available，应明确用词。

## 6. 收费产品形态

### 6.1 Rekey Cloud

托管控制面，客户可以选择：

- SaaS 数据面。
- 客户 VPC/Kubernetes 数据面。
- 本地 Edge + 云控制面。

Cloud 默认只看到：

- identity metadata。
- policy metadata。
- decision/execution metadata。
- usage 和 health。

Cloud 默认看不到：

- 真实秘密。
- Prompt。
- request/response body。
- 客户 Vault token。

用户使用内置 Credential Authority 时，Credential ciphertext 和解锁能力默认留在客户数据面。未来若提供托管 Vault，必须作为独立、明确选择的产品和威胁模型，不能悄悄改变“控制面无秘密”的默认合同。

### 6.2 Enterprise Self-Hosted

适合金融、医疗、政府、研发和受监管客户：

- 控制面和数据面全部部署在客户环境。
- 离线许可证。
- KMS/HSM/BYOK。
- 内置 Credential Authority 的 HA、备份恢复演练、密钥包装策略和轮换治理。
- 私有 Connector registry。
- 审计和升级包。
- 命名支持、安全公告和长期维护版本。

### 6.3 Commercial Support

即使客户只使用 OSS，也可以购买：

- 架构评审。
- Connector 开发和认证。
- 部署、恢复和升级服务。
- 安全加固。
- 版本升级。
- 事故响应。
- 定制支持。

这为产品早期提供比完整 SaaS 更快的收入路径。

## 7. 定价假设

定价尚未验证，以下仅作为访谈和 Pilot 的实验起点。

### Team

- 按 workspace 或 protected gateway 收费。
- 建议测试 99–299 美元/月。
- 包含一定活跃用户、Gateway 和事件保留。
- 不按每次工具调用收费，避免客户因成本降低安全覆盖。

### Enterprise

- 年度平台费 + 活跃受保护 workload/Agent 档位。
- Pilot 可测试 10k–25k 美元。
- 成熟合同可测试 30k–100k+ 美元。
- 价格由部署方式、支持、数据驻留、Gateway 数量、保留和合规要求调整。

### 不推荐

- 对每个短生命周期 Agent 实例逐个计费。
- 对每个拒绝请求计费。
- 将基本安全修复绑定高价套餐。
- 让客户为了降低账单而绕过 Gateway。

## 8. 开源到企业的转化机制

~~~text
开发者本地使用
  ↓
团队共享策略和 Connector
  ↓
需要身份归属、撤销和审批
  ↓
需要集中 Gateway fleet 和审计
  ↓
安全/IAM/平台团队介入
  ↓
需要 SSO/SCIM/SIEM/HA/支持
  ↓
Team Cloud 或 Enterprise
~~~

转化应由真实规模和治理需求触发，而不是故意让 OSS 难用。

## 9. 初期 Go-To-Market

### 9.1 公开内容

- “Agent 完全拿不到密钥”的攻击演示。
- 与 env、op run、Vault fetch、普通 MITM 的安全等级对比。
- Codex/Claude + GitHub 的五分钟 quickstart。
- 恶意 README/Issue Prompt Injection 尝试盗取 PAT 的失败演示。
- 完整 Threat Model。
- 可复现的 attack lab。
- Connector 开发教程。
- 真实限制和不支持列表。

### 9.2 社区入口

- GitHub issues/discussions。
- Discord/Slack。
- Connector request 模板。
- Security advisory 和 disclosure 流程。
- 公开 roadmap 与 compatibility matrix。
- 与 sandbox、Vault、MCP Gateway 项目合作。

### 9.3 企业入口

- 设计伙伴计划。
- Platform/AppSec/IAM 技术评审。
- 付费架构和安全 Pilot。
- 客户侧 Gateway 参考部署。
- GitHub、AWS、Jira 或 ServiceNow 的具体高风险场景。

## 10. 设计伙伴计划

### 入选条件

- 至少 10 个 Agent 或自动化 workflow。
- 至少一个写权限或生产权限场景。
- 当前使用长期 Secret、PAT、云密钥或共享 OAuth。
- 有工程负责人和安全负责人。
- 愿意提供匿名化攻击/审计需求。
- 愿意每两周反馈一次。

### Rekey 提供

- 部署协助。
- Connector 和策略共同设计。
- 威胁模型评审。
- 早期支持。
- 路线图影响力。

### 客户提供

- 真实工作流和失败案例。
- 采购与安全评审路径。
- 使用数据和可公开/匿名案例。
- 付费 Pilot 或明确付费门槛。

### 退出标准

设计伙伴不是无限免费定制。出现以下情况应停止：

- 没有真实生产或准生产计划。
- 无法接触买方。
- 每个需求都只适用于一家客户。
- 不愿运行或评估安全边界。
- 六到八周内没有持续使用。

## 11. 发布原则

用户已决定暂不优先锁定首个公开版本的完整功能列表。当前只锁定发布规则：

1. 不发布无法清楚标注 G1/G2 的部署。
2. 不以新增 Provider 数量代替安全合同。
3. 每个公开 Connector 必须通过同一契约测试。
4. 永久不提供旧代理、旧数据库或旧 CLI 兼容路径，不迁移。GA 同一主版本内不得改变格式；格式变化只能随主版本升级。
5. 安全核心和攻击测试先于企业页面。
6. 文档中的每项安全承诺必须有当前版本验证证据。
7. 默认配置必须是最安全的可用路径。

首个公开版本功能应在 P0 架构和两轮设计伙伴访谈后确定。

## 12. 企业就绪门槛

### 技术

- Customer-hosted data plane。
- HA 和滚动升级。
- 版本化策略和回滚。
- 多租户隔离。
- 内置 Credential Authority 的 HA/恢复治理，以及可选外部 Vault/KMS/HSM。
- OIDC/SAML/SCIM。
- 审批和 SIEM。
- 性能、容量和故障演练。

### 安全

- 独立渗透测试。
- 威胁模型和攻击测试。
- SBOM、签名发布、可复现构建。
- 安全响应、CVE 和披露流程。
- 第三方依赖和 Connector 供应链策略。
- 无未解决 Critical/High。

### 运营

- 备份恢复和 RPO/RTO。
- 升级和回滚。
- 状态页面和事故沟通。
- 支持时区和升级路径。
- 数据处理协议、子处理者清单和删除流程。

### 商业

- 法人和合同。
- 商标和品牌清查。
- 企业服务条款。
- SLA 和责任边界。
- 定价与计量。
- 至少两个付费 Pilot。

## 13. 品牌决定

已有 rekey.dev 位于相邻 MCP/Auth 市场。正式公开前必须决定：

- Rekey 只是内部代号并更名。
- 保留 Rekey，但使用可区分的组合品牌。
- 取得可用域名、包名和商标意见后继续。

在决定前，不应为当前名称投入大规模 SEO、视觉品牌、活动或商标费用。

## 14. 决策登记

| Decision | Status | Reason | Revisit trigger |
| --- | --- | --- | --- |
| 数据面开源 | Locked | 安全信任和采用是产品基础 | 无 |
| 内置 Credential Authority 开源并作为默认 | Locked | 零依赖采用和端到端安全合同 | 无 |
| 外部 Vault 非必选 | Locked | 不绑定商业账户或第三方部署 | 客户需求只影响集成优先级 |
| Agent API 无 Secret 读取/导出 | Locked | 避免把权能交给不可信 Agent | 无 |
| SaaS 控制面不持有秘密 | Locked | 降低客户和平台风险 | 若客户明确要求托管 Vault |
| 安全修复不付费 | Locked | 开源可信度和责任 | 无 |
| 基础 OIDC 开源 | Proposed | 避免不可验证的单用户玩具 | 设计伙伴反馈 |
| SAML/SCIM 商业支持 | Proposed | 组织规模和运维价值 | 社区贡献实现 |
| 常用 Connector 开源 | Proposed | 生态和采用 | 维护成本不可控 |
| MIT 或 Apache-2.0 core | Open | 需法律、生态和历史许可评估 | 首次外部贡献前 |
| 商业控制面独立许可 | Proposed | 清晰价值边界 | 公司和融资结构 |
| Cloud 优先 | Open | 取决于设计伙伴部署偏好 | 5–10 家访谈后 |
| 首个公开版本功能 | Deferred | 先锁定安全与架构 | P0 spec 和两轮访谈后 |
| 产品名称 | Open/urgent | 已有相邻 rekey.dev | 公开发布前 |

## 15. 风险

| 风险 | 影响 | 缓解 |
| --- | --- | --- |
| 基础 proxy 被快速商品化 | 差异化消失 | 聚焦 Action Authorization、身份、审批和证据 |
| OSS 被云厂商 fork | 收入压力 | 控制面、Connector 认证、运营、品牌和企业关系 |
| Community 太弱 | 无采用和信任 | 保持完整安全数据面和基础团队能力 |
| Community 太强导致不转化 | 收入慢 | 收费于规模、管理、合规、托管和支持 |
| 企业要求过多拖垮单人团队 | 产品失焦 | 设计伙伴筛选、范围纪律、付费定制 |
| 安全漏洞损害品牌 | 高 | 外部审计、攻击测试、披露和签名供应链 |
| 品牌冲突 | 高 | 立即清查和可能更名 |
| 单人 24x7 不可持续 | 高 | Pilot 后优先补安全/runtime、control plane、solutions 能力 |

## 16. P0/P1/P2 商业路线

| Priority | Work | Done when | Verification |
| --- | --- | --- | --- |
| P0 | 品牌和许可证法律评估 | 有书面选择和风险记录 | decision record reviewed |
| P0 | OSS 安全合同 | G2 条件、攻击测试和范围公开 | threat-model validation matrix |
| P0 | 内置 Credential Authority 合同 | 默认无需外部 Vault；存储、全新初始化、解锁、轮换和禁止 API 明确 | `cargo test -p rekey-vault --test authority_contract` |
| P0 | 10–15 个买方/用户访谈 | 问题、买方和部署偏好有证据 | interview synthesis |
| P0 | 3 个设计伙伴 | 有真实工作流、负责人和成功标准 | signed design-partner brief |
| P1 | Community alpha | 五分钟接入、强模式可验证 | release checklist + attack suite |
| P1 | 付费 Pilot | 至少 2 家付费 | contract and deployment evidence |
| P1 | 托管或 self-host control MVP | 由访谈决定路径 | pilot acceptance criteria |
| P2 | Enterprise GA | 技术、安全、运营、商业门槛通过 | enterprise readiness review |

## 17. Open Questions

1. 产品最终名称。
2. 未来企业组件是否沿用当前 Core 的 MIT，或采用独立许可证。
3. 公司是否愿意承诺开放协议和数据面长期不闭源。
4. Cloud-first 还是 self-host-first。
5. 首个付费买方是 Platform、AppSec、IAM 还是 Agent Platform 团队。
6. 企业计量单位是 workspace、gateway、protected workload 还是组合。
7. 基础 OIDC、SAML 和 SCIM 的具体开源范围。
8. Connector marketplace 是否允许第三方收费。
9. 是否提供托管 OAuth app，承担用户 Token 保管责任。
10. 何时建立正式公司、保险、DPA 和 SLA。
11. 何时投入外部 Vault 集成；该决定不阻塞 Community 内置路径。

## 18. Readiness

本文件已经锁定内置 Credential Authority 属于 MIT Community 开源安全核心，外部 Vault
不构成强制依赖；足以指导企业组件许可证咨询、设计伙伴访谈和 Community/Enterprise 边界
讨论。价格、企业组件许可证、公开品牌和首个公开版本功能仍是待验证决定，不能视为已经
确定的商业承诺。
