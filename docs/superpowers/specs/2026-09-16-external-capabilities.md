# 外部能力最小切片规格提案

日期：2026-09-16。状态：供操作方选定现场输入的设计提案，未实现、未部署、未现场验收。

用户选择先完成本地功能，外部部分先做规格。本文件把外部事项收敛为可审阅的实现合同；不会因为文档写完就关闭功能项。
这里的默认方案都是提案，不是既有产品行为或外部资源创建授权。云账户、企业身份源、硬件和接收端均未选定。
仓库行为以 [feature truth matrix](../../product-foundation/feature-truth-matrix.md)、Foundation 与对应已接受规格为准。
2026-09-10 [剩余事项处置](2026-09-10-remaining-p3-disposition.md) 提供 ID/依赖；enterprise 研究不作为实现依据。

## 共同边界与实施顺序

- 先选一个现场、一个效果、一个固定目标；下列候选不要求同时实现，不增加通用 Adapter 平台。
- Agent 仍只执行已注册的固定 HTTP Action。来源读取结果、身份令牌、签名私钥和源端响应都不返回 Agent。
- 来源 profile 通过已有可信 Admin 录入边界交给 Authority 加密保存；秘密只进受保护输入/帧 body，不进 argv、环境、配置元数据或审计。
- 沿用编译期 connector 合同。新来源只增加对应的闭合解析与执行路径，不允许 Agent 选择 URL、角色、secret ID、版本或响应表达式。
- 开始审计先于秘密解密或外部效果；本地审计提交失败沿用 fail-closed。终态明确区分拒绝、失败、成功、结果未知。
- 每次来源读取受现有 Action 绝对 deadline、大小上限和响应 sealing 约束；不加跨执行明文缓存，不在鉴权失败时换身份或旧值兜底。
- 拟议新增审计证据仅含租户/主体/Action/执行 ID、来源引用及版本、结果、外部请求关联号与时序；正文、token、私钥、动态值和完整源响应不入日志。低熵秘密的散列也不作为公开证据。
- 公网源沿用生产 DNS/IP/TLS、禁重定向和禁环境代理边界。私网目标必须先满足 VEX-01 独立合同，不能打开全局“允许私网”。
- 纯读取在来源失败时不执行目标 Action。目标请求已发送但响应丢失时，不自动重放业务效果；记录结果未知。可重试的外部投递见 AUD-07 的单独合同。
- 文中的输入/输出是语义字段，不宣称新增命令、IPC opcode 或配置字段已经存在；实施时先更新相应具体规格和基线。

建议次序为单个来源或审计导出试点先行；企业身份与远程审批在独立身份/信任决策后进行；HA 在隔离与 fencing 已获现场证明后进行。
“本地 fixture 通过”只证明协议/拒绝分支；IAM、HSM不可导出、IdP撤权、WORM以及网络隔离都需要真实现场证据。

## ENT-01～05、BAK-07～08：单客户管理与人工主备

### ENT-01 集中控制面

最小建议是单客户、两个已登记节点的签名策略分发与生效回执。先用客户控制的私有文件分发位置，不建设托管数据库或远程解锁入口。
输入为客户/节点清单、独立可信的策略签名公钥、签名 bundle、目标节点与期望版本；节点本地管理员仍逐次 step-up 激活。
输出为节点 ID、vault ID、bundle 摘要、实际策略版本、激活结果与时间；控制端不能把“已上传”当作“已生效”。
签名私钥留在独立签名者，VRK和provider秘密留在每个 Authority；分发端只能读取策略和非秘密回执，无凭证导出或解锁能力。
版本回退、错租户、错签名、过期 bundle 均拒绝；断网时保留仍有效的已激活策略，到期默认拒绝，不由控制端续期。
本地记录真实激活审计；控制端记录分发与回执，二者通过 bundle 摘要关联，缺回执显示未知。
依赖现有外部策略 signer、持久签名策略、ENT-02节点归属。fixture 覆盖错签名/乱序/部分节点失败；现场证明两个节点各自的实际版本与断网到期行为。
待选输入：客户 ID、两个节点/平台与独立状态目录、分发位置及认证主体、签名公钥指纹、管理员、策略有效期与回执保留期。

### ENT-02 租户隔离

首轮建议每租户独立 VM/Authority、OS身份、磁盘与网络出口，不在一个SQLite或进程中增加 tenant 过滤层。
输入为租户到节点、vault ID、Admin/Agent入口及审计目的地的固定映射；输出为每租户独立的会话、策略和审计查询结果。
各租户独立VRK、来源bootstrap身份和备份访问权；平台/虚拟化管理员属于明确的可信计算基，不承诺隔离宿主root。
来自租户A的凭证/Action/session/approval引用在B必须拒绝，不能根据调用方传入tenant字符串重新路由；停用租户后关闭其入口并撤销会话。
映射缺失、身份过期和隔离配置失败默认拒绝；审计带租户和节点归属，中央可见性只授予明确的审计角色。
依赖ENT-01部署映射；fixture覆盖跨租户引用，现场攻击检查磁盘、socket、进程、备份、查询和出口。两个本机目录测试不等于VM隔离证明。
待选输入：租户数量/ID、VM和宿主责任方、OS身份、网络边界、备份/审计访问矩阵、跨租户管理员权限与撤销流程。

### ENT-03 SSO、SCIM与组织管理

建议一个OIDC issuer的管理员登录，加一个SCIM 2.0身份源的用户创建/停用；首轮不支持嵌套组织、自动组提权或多issuer联邦。
身份主键使用 issuer + subject 的稳定组合；邮箱和显示名称只能展示。OIDC定义了issuer、subject及ID Token校验，SCIM定义了用户资源修改协议。参见 [OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html) 与 [SCIM RFC 7644](https://www.rfc-editor.org/rfc/rfc7644.html)。
拟议登录输入为固定issuer/client/redirect URI、一次性state/nonce与授权码（使用 [PKCE](https://www.rfc-editor.org/rfc/rfc7636.html)）；输出为短期管理身份会话，不输出vault解锁材料，也不替代当前敏感操作step-up。
SCIM输入为认证来源的稳定外部ID、active状态与请求关联证据；输出为稳定内部principal映射和应用回执。身份同步不能自行生成审批私钥或扩大签名策略权限。
SCIM传输凭证、OIDC client秘密属于身份入口组件；VRK仍属于节点Authority。把SCIM用户对应到OIDC subject必须有操作方提供的可信映射，不能猜邮箱相等。
停用先阻断新会话，再撤销该主体的现有管理/Agent会话；对已发送的上游效果只能记录状态，不能承诺撤回。
不接受过期token、错误issuer/audience/nonce；目录同步超出选定新鲜度后禁止新增高权限会话。默认提议高权限会话最长5分钟，撤权目标60秒，均须现场确认。
记录登录结果、映射版本、停用接收/应用时间和受影响会话数，不记token；SCIM重复变更幂等。不假定协议自带有序事件号；停用映射只由管理员重新核验后恢复，旧active请求不能自动复活身份。
依赖ENT-01/02及明确管理身份入口；fixture模拟issuer/key轮换、错audience、重放和乱序SCIM；现场证明真实IdP停用到节点拒绝的时延。
待选输入：IdP产品/版本、issuer/JWKS、client ID和认证方式、精确redirect URI、SCIM认证方式、external ID到subject映射、管理员清单、同步新鲜度与撤权SLO。

### ENT-04 与 BAK-07：先做人工灾备提升

最小建议为一主一冷/温备、人工提升。复制已完成的加密备份和原始receipt，复用 [BAK-06](2026-09-10-external-backup-operations.md) 的传输/摘要验证；不复制运行中的SQLite/WAL。
这只能交付有界灾备切片，不能宣称自动HA、持续复制或零丢失。当前备份仍需操作方step-up创建，定时复制旧文件不代表产生了新恢复点。
输入为主备节点、成功备份receipt/摘要、对应解锁因素和带证据的旧主fencing决定；输出为恢复节点、恢复点、隔离证据及新的主权登记。
备份位置只持密文，解锁因素由恢复操作方独立保管；恢复出的同一vault仍共享历史VRK，不能把两个副本称作密码学隔离。
提升顺序固定为：阻断旧主Admin/Agent及provider出口并确认其不可恢复服务 → 校验最新可用备份 → 空目录恢复 → 本地检查后解锁 → 新建会话 → 放行新主。
fencing必须由旧主之外的基础设施控制，并持续覆盖旧主重启/分区恢复；ping不通、写一个主节点标志或人工口头确认都不是证据。
不能证明隔离时拒绝提升；旧主有未决上游效果时先核对外部结果，不自动重放。回切同样执行fencing，不合并两个分叉数据库。
备份恢复不会恢复会话/challenge；旧主内存会话可能仍活着，所以必须隔离旧主。恢复可能回退近期撤权，放行前必须重新核对最新权限并在需要时轮换上游身份。
审计保存备份摘要、实际恢复点、操作者、fencing执行/确认时间、提升结果与未决效果清单；分叉审计独立保留，不篡改序号拼接。
依赖ENT-02、BAK-06与操作方控制的fencing设施。fixture覆盖缺receipt、旧备份、恢复失败和缺fence拒绝；现场切断网络、杀主、旧主复活，确认始终只有一个可产生外部效果的主。
待选输入：两个节点和故障域、备份创建节奏、传输位置、独立fencing执行器及权限/证据、入口切换方法、恢复因素保管人、上游幂等/查询能力。

### BAK-08 与 ENT-05：测量和现场验收

输入为已选试点范围、版本/构建摘要、配置摘要、测试身份、故障注入点和目标RPO/RTO；输出为逐项通过/失败/未测证据及残留资源清单，不产出笼统“企业版通过”。
RPO测量故障时Authority最后已提交状态与可恢复快照的差距，另列丢失/未知的审计与外部业务效果；RTO从确认故障到新主通过受控业务读并重新开放入口计时，包含人工等待和解锁。
至少演练备份落后、传输中断、隔离失败、主机宕机、网络分区、旧主复活、错误解锁因素与恢复后旧会话拒绝；每种都保存时间线和两端证据。
目标未满足就记录失败；现场输入缺失就标未测，不能用本地fixture替代。到期测试身份/策略不得临时扩大权限绕过。
ENT-05依赖已选ENT-01～04实际交付；BAK-08依赖BAK-07。首轮不预设可承诺的RPO/RTO数值，尤其不把每小时传输等同一小时RPO。
验收方分别拥有企业IdP/网络/provider日志；测试只用合成secret，输出去秘密后的证据。待选输入：现场负责人、允许故障窗口、明确目标值、各能力验收用例、证据保留与清理责任。

## EXT-01～07：一个来源或一种外部签名效果

### EXT-01 AWS：固定版本 Secrets Manager 只读源

提案仅支持一个完整Secret ARN和明确VersionId，读取SecretString作为一个完整非空UTF-8令牌，注入既有固定Action；不支持SecretBinary、版本标签漂移、列表、写入或自动轮转。
AWS的 `GetSecretValue` 接受SecretId/VersionId，需 `secretsmanager:GetSecretValue`；客户管理密钥还需对应 `kms:Decrypt`。此Decrypt只是服务读取依赖，不是给Agent开放KMS。参见 [AWS API](https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html)。
拟议输入为region、完整ARN、VersionId、管理员受保护导入的短期access key/secret/session token及到期时间；输出仅为本次PreparedCredential和非秘密版本证据。
请求由固定region服务端点的SigV4签名完成；短期凭据含session token，参见 [AWS SigV4](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_sigv.html)。不读取ambient SDK credential chain、不调用IMDS或自动AssumeRole。
源秘密归AWS，bootstrap凭据加密存Authority、执行时短暂使用；过期/403/解密失败/返回ARN或版本错配均阻断目标Action，不重试旧版本。审计记录资源引用/VersionId与请求关联号，不记SecretString。
依赖一个新闭合source connector与共同边界。fixture验证签名向量、错版本、到期、403与反射封堵；现场使用最小IAM测试身份，证明固定版本读取和跨secret拒绝，结束撤销测试身份。
待选输入：账户/region、完整ARN、VersionId、目标Action、最小IAM/KMS策略、短期凭据安全交付方式/有效期、外部日志读取人。

### EXT-02 GCP：固定 SecretVersion 只读源

提案固定 `projects/P/secrets/S/versions/N`，N为数字版本，不接受latest。官方 `versions.access` 是GET，返回name与payload，要求 `secretmanager.versions.access` 和cloud-platform OAuth scope。参见 [GCP access API](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/projects.secrets.versions/access)。
输入为完整版本名、受保护导入的短期OAuth access token及到期时间；返回payload.data解码后的完整UTF-8令牌，仅进入本次PreparedCredential。无ADC环境读取、服务账号私钥或自动refresh token路径。
源归GCP，token归Authority；核对响应name、base64与payload CRC32C，字段说明见 [SecretPayload](https://docs.cloud.google.com/secret-manager/docs/reference/rest/v1/SecretPayload)。缺校验数据、损坏、禁用/删除版本或token过期都失败，不改读latest。
审计记录版本资源和读取结果，不记录payload。依赖新source connector；fixture覆盖错name/校验和/到期与403，现场证明特定版本最小IAM访问和禁用后拒绝，不能用scope存在推导IAM已授权。
待选输入：项目ID、secret ID、数字版本、目标Action、服务主体/IAM绑定、token安全交付方式/有效期、测试禁用权限及清理责任。

### EXT-03 Azure：固定版本 Key Vault Secret 只读源

提案固定vault HTTPS origin、secret name和非空version，只读取secret value。官方GET路径为 `/secrets/{name}/{version}?api-version=2025-07-01`，需secrets/get；认证使用Key Vault OAuth授权域。参见 [Azure Get Secret](https://learn.microsoft.com/en-us/rest/api/keyvault/secrets/get-secret/get-secret?view=rest-keyvault-secrets-2025-07-01)。
输入为上述固定引用、受保护导入的短期Entra access token及到期时间；输出value只进本次PreparedCredential，返回secret ID必须匹配完整版本。首轮不自行登录、查询实例元数据或自动刷新。
源归Key Vault，token归Authority；过期、403、禁用、未到可用时间、错误ID或非文本值均拒绝，不自动换vault/版本。审计保留secret引用和版本及结果。
依赖新source connector；fixture覆盖wrong vault/version、attributes与token到期、超限/反射，现场用固定租户主体证明最小读权限及跨vault拒绝。
待选输入：Entra tenant/主体、vault origin、secret name/version、RBAC或access policy选择、目标Action、token安全交付/有效期、测试撤权和清理责任。

以上三项的KMS签名、密钥生成、unwrap、跨账户角色链及自动身份续期均延期。若以后需要签名，必须另选用途、算法、固定key version和独立签名者权限，不能把读取secret的验收当作KMS验收。

### EXT-04 1Password：固定 item 的一个字段

建议已有1Password Connect部署上固定vault UUID、item UUID、field ID和期望item版本；GET完整item后只取指定string字段。官方Connect使用Bearer token，提供固定item详情端点。参见 [Connect API](https://www.1password.dev/connect/api-reference)。
输入还含固定Connect origin和受保护导入token；输出字段值只用于固定Action。源归1Password/Connect，token归Authority；现场应使用专用只读vault，因为应用固定item不代表Connect权限已细化到item。
Connect读取端点不提供本提案所需的历史版本选择；期望版本仅作响应匹配，版本变化必须由管理员重新登记，不能假装能读旧版本。
缺field、重名ID、版本错配、401/403或API报告同步失败均阻断；无Rekey本地缓存兜底。成功读取只证明Connect提供了期望版本，不证明其已同步云端最新状态。审计item引用/实际版本与结果，不记整个item或字段值。
依赖新connector；私网Connect另依赖VEX-01式独立目标绑定。fixture验证错item/field/version与过期token；现场证明真实同步后版本变化拒绝、token撤销和专用vault权限。
待选输入：Connect版本/origin/网络归属、vault/item/field UUID、期望版本、只读token安全交付、目标Action及测试item所有者。不会为试点自动部署Connect或购买订阅。

### EXT-05 PKCS#11/HSM：独立审批签名者的硬件密钥

建议只替换独立审批signer的Ed25519私钥后端，Agent与Broker API不加任意sign。一个已固定设备/slot/key ID签署既有grant精确字节，输入仍须通过review及reviewed-sha256复核。
PKCS#11定义C_Sign及设备/会话错误；候选设备必须实际支持兼容Ed25519的机制，不能仅凭“PKCS#11兼容”认定支持。参见 [OASIS PKCS#11 3.1](https://docs.oasis-open.org/pkcs11/pkcs11-spec/v3.1/os/pkcs11-spec-v3.1-os.pdf)。
私钥归HSM且不可导出，PIN只进可信交互输入；厂商模块属于独立signer可信代码，显式固定路径/版本，不扩展Broker动态插件机制。
输出为现有grant格式的签名和公钥匹配证据；signer本地验证后才以0600新文件交付。设备移除、PIN取消/锁定、算法不支持、错误公钥或challenge到期均失败，不回退软件私钥。
超时不宣称“未签过”；不自动重试或产生新授权。记录request/approver/key引用、review摘要、设备操作结果，不记PIN、私钥或完整请求正文。
依赖现有独立signer与审批内核；软件token fixture只证明协议/错误处理，现场须证明真实设备非导出属性、厂商机制、公钥、拔出/重连和PIN策略。
待选输入：设备型号/固件、PKCS#11模块和摘要、slot/serial/key ID、算法能力、公钥及审批人ID、PIN交互方式、硬件管理员和丢失撤权流程。

### EXT-06 OS Keychain：一个macOS凭证源

建议仅macOS generic-password精确service/account查询，不扫描所有条目、不使用shell `security` 输出秘密，也不等同现有KEY-05恢复授权。
Apple提供 `SecItemCopyMatching` 读取匹配条目，参见 [Apple Security API](https://developer.apple.com/documentation/security/secitemcopymatching(_:_:))。
输入为管理员固定的Keychain条目标识、访问条件与目标Action；输出仅为本次PreparedCredential。秘密留在OS Keychain，Authority保管引用而不复制持久secret；不得复用Rekey解锁授权service。
读取由可信Authority执行边界调用原生API，不经过Agent/UI明文中转；锁定、未找到、多义查询、拒绝交互或访问控制失败均阻断Action，不弹出Agent可控制的解锁流程。
OS条目本身无统一TTL承诺；引用有效期和固定条目更换属于管理员责任。审计仅内部引用、结果和时间，不记secret或任意Keychain属性。
依赖macOS特定闭合source路径；fixture覆盖状态映射/零泄漏，现场用随机测试条目验证实际应用身份、锁定与用户拒绝，结束删除测试条目。
待选输入：macOS版本、签名/运行用户、指定keychain/service/account、访问控制与交互要求、引用有效期、固定Action、条目删除责任。

### EXT-07 外部签名服务：只选Vault Transit审批签名

建议替代“任意Provider Adapter”为一个独立signer后端：固定Vault origin、Transit mount/key/version，使用非derived Ed25519签署已审阅grant字节。不是Agent callable任意消息签名服务。
官方Transit提供 `POST /transit/sign/:name`，input为base64、key_version可固定，Ed25519有其算法语义。参见 [Vault Transit sign](https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data)。
输入为上述引用、受保护token、独立固定公钥和现有reviewed摘要；输出为核对版本并由本地公钥验证后的现有grant。使用完整规范签名字节，不把review哈希当成可互换签名输入。
私钥仅Vault持有，token仅独立signer持有，不进入Broker；审批者必须知晓远程Vault管理员属于签名信任边界。
错版本、错公钥、403、超时或grant到期均不给出成功文件，无自动重试/自动批准；远端可能已签但响应丢失时标结果未知。记录关联号、版本、摘要和结果，不发送/记录无关原始业务正文。
依赖独立signer；私网部署须另评signer出口边界，不能借VEX-01放开所有网络。fixture验证错签名/版本/超时；现场证明固定key ACL、撤token、实际签名被既有Broker接受和grant重放拒绝。
待选输入：Vault版本/origin、mount/key/version、公钥、最小ACL/token交付与期限、审批者归属、远端审计权限及测试签名用途。

## VEX-01～04：Vault扩展逐项收敛

### VEX-01 单个私网Vault目标

建议以部署专属规则绑定一个Vault源端点，而非通用CIDR白名单：输入固定HTTPS hostname/port、精确允许地址集、TLS信任根和所属租户。
每次解析的全部目标必须在允许集合，实际连接固定到核验地址且保留原hostname TLS校验；拒绝loopback、link-local/metadata、重定向、Agent supplied host与混合DNS结果。
自定义CA仅适用于此Vault连接，不能更改全系统CA或其他Action的公网限制；IP/CA轮换须管理员显式更新绑定。
输入为私网目标绑定与既有KV/dynamic profile；输出仍是原有source效果和目标证据。bootstrap secret归Authority，网络管理员负责不把同一地址重新分配给非Vault服务。
证书/地址/租户错配、DNS变化或网络分区均拒绝，无公网/其他私网兜底；审计绑定版本、连接目标和失败阶段，不记Vault请求token。
依赖部署隔离规格与既有source；fixture模拟DNS rebinding、IPv4/IPv6绕过、混合答案、错误CA/hostname，现场验证实际DNS/路由/私网证书与跨租户出口。
待选输入：Vault hostname/port、精确IPv4/IPv6地址、CA链、DNS管理方式、租户/出口拓扑、轮换窗口和管理员。fixture的loopback例外不得进入production。

### VEX-02 只选AppRole登录

首轮选择AppRole，Kubernetes/OIDC登录延期。官方login输入role_id及默认要求的secret_id，返回client_token与lease_duration等。参见 [Vault AppRole API](https://developer.hashicorp.com/vault/api-docs/auth/approle#login-with-approle)。
拟议输入固定origin/auth mount/role ID、受保护SecretID和其到期信息；每次执行登录一次，只用于该次固定KV读，完成后revoke-self。选择有界TTL的service token，不设置无限/周期token。
SecretID与登录所得token都由Authority执行边界持有；Agent看不到登录响应。AppRole ACL仅允许所选KV路径与自身清理，RoleID/SecretID不允许Agent替换。
登录会消耗SecretID使用次数，超时不自动重试；SecretID过期、token寿命不足以覆盖执行/清理或revoke失败，明确失败/清理未确认，不返回成功。崩溃残余靠Vault TTL，不宣称重启清理完成。
审计登录/清理阶段和到期证据，不记token、SecretID或accessor。依赖P-07A；私网另依赖VEX-01；fixture覆盖错误role、过期、响应缺TTL与清理失败，现场证明最小ACL、使用次数、自然到期和撤销。
待选输入：Vault版本/origin、auth mount/role ID、SecretID交付/TTL/次数、服务token TTL、KV引用与权限、测试撤销权限及自然到期验收时间。

### VEX-03 仅token续期；Namespace和更多引擎延期

候选是在现有登录token生命周期中显式续期一次，不建全局常驻续租器；只有现场证明单次TTL不足且不能调长时才选此切片，不默认与VEX-02首轮同时实施。
Vault `renew-self` 只对可续期且存在租约的token有效，返回实际租期；请求increment不是到期保证。参见 [Vault token renewal](https://developer.hashicorp.com/vault/api-docs/auth/token#renew-a-token-self)。
输入为现有token的可续期证据、固定增量和绝对最大寿命；输出为核验后的实际新deadline。token仍留Authority；不续SecretID、不更换身份、不扩大ACL。
续期失败/超时后不启动新的业务效果；已发送效果不可撤回，进入受控终止/清理与结果未知判断。超过绝对寿命、锁定或策略到期就停止，不因续期重置capability有效期。
审计续期前后期限与结果；不记录token。依赖明确token生命周期、取消/清理路径；fixture用假时钟测边界和短于请求的实际TTL，现场测Vault max TTL、撤销竞争和清理结果。
待选输入：必须续期的任务时长证据、token类型/renewable配置、increment、绝对最大寿命、清理deadline和Vault策略。Namespace、额外engine仍独立待选，不能借本项自动加入。

### VEX-04 仅“最新版本读取”；写入延期

候选新source语义显式选择latest，保留现有exact-version source不变。Vault KV v2省略version会返回最新版本。参见 [Vault KV v2 read](https://developer.hashicorp.com/vault/api-docs/secret/kv/kv-v2#read-secret-version)。
输入固定origin/mount/path/key及管理员接受版本漂移的授权；一次读取后冻结返回的metadata.version和值，整个执行不再次解析latest。
输出值只进PreparedCredential，审计记录实际版本。缺版本、删除/销毁值、字段错配或空值拒绝；读失败不退旧版本。请求授权仍绑定原业务参数，不把参数摘要误称为源secret版本绑定。
若业务要求审批人先批准某个精确secret版本，则必须继续使用exact-version；latest候选不满足该需求。
依赖P-07A和版本漂移接受决定；fixture模拟读取前/后轮转及缺metadata，现场在合成KV条目轮转，证明单次执行只用一个版本且审计可对应。
待选输入：固定版本不足的用例、KV引用/字段、轮转责任方、漂移接受范围、目标Action与审批要求。写入、CAS冲突、未知提交重试等有副作用能力另行规格，本项不实现。

## AUD-07～08：远程投递与外部不可改写存储

### AUD-07 一个SIEM接收端

建议独立导出进程读取已有本地审计快照/JSONL并投递一个客户HTTPS接收端，不让Broker调用SIEM或持有其token。
输入为固定接收端、传输身份、稳定来源实例ID、不可变批次及序号范围；输出必须是接收端确认的批次摘要/持久接收凭据，再推进本地cursor。HTTP 200但无约定确认不能视为入库。
采用至少一次投递，批次/事件去重键包括来源实例、vault、审计序号；恢复/克隆创建新来源实例ID，防止回退后的相同序号覆盖不同事件。
本地批次与cursor持久保存；确认丢失重发同批，接收端去重，禁止exactly-once宣传。网络/429/5xx按有界退避，401/403和永久格式错误进入可见失败状态。
本地保留/清理必须覆盖未确认区间；源记录已被清理而本地没有完整批次时报告不可恢复的缺口并停止推进cursor，不能静默跳到最新序号。
建议默认最多重试24小时或本地积压256MiB，先到上限即停止读取新增批次并告警，保留原审计与未确认批次，不丢弃最旧事件；数值由现场容量确认。
本切片远端故障不改变已存在的本地审计授权门禁；本地日志持续增长的容量责任必须明确，要求“远端未确认就禁止业务”的现场需另定同步语义。
exporter只持SIEM写入身份，无vault解锁权。拟议传输记录含批次摘要/范围、尝试/确认时间和错误，不复制秘密或原始请求；投递日志与被投递审计分开，防止递归。
依赖本地稳定快照与唯一接收合同；fixture测确认丢失、乱序、重复、断网、磁盘满和恢复后实例变更；现场查询SIEM真实落库/去重/缺口，不能只检查客户端退出0。
待选输入：SIEM产品/版本、精确HTTPS endpoint、TLS/认证方式、批次格式与大小、持久ACK/去重约定、最大积压/时间、告警接收人及事件查询权限。

### AUD-08 一个S3 Object Lock归档候选

建议将已封口审计批次及摘要写入客户指定S3 versioned bucket的唯一object key；先以隔离测试桶演练，再由合规责任方选择保留模式/期限。本文不提出法律符合性结论。
AWS Object Lock对对象版本实施retention或legal hold；governance允许特权绕过，compliance不允许普通权限缩短保留，legal hold需有权主体明确解除。参见 [S3 Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html)。
输入为bucket/region、对象前缀、身份、保留模式和retain-until时间、可选hold指令；输出为具体version ID、内容摘要、实际retention/hold读取回执。
归档写入身份只负责写入，保留/hold管理身份独立；审计批次可能含敏感业务元数据，需按客户存储加密和访问策略保护。源凭证不入桶。
上传或确认未知时不标完成；重复投递核对同批摘要和已记录version，不能覆盖/删除旧版本。保留期限不匹配、hold应用失败、错误bucket均失败，保留本地待归档批次。
审计归档/hold更改需保存操作者、对象version、前后状态与外部回执；到期不自动删除，解除hold与清理需操作方明确决定。
依赖AUD-07式批次/receipt与真实存储权限；fixture只能测请求/回执处理。现场以测试身份分别尝试改写、删version、缩短retention与解除hold，并读取真实拒绝/允许证据。
测试桶通过不等于生产桶通过；本地SQLite追加、SHA-256、HTTP上传成功都不能证明WORM。compliance测试可能不可提前清理，选定窗口与费用责任后才可实施。
待选输入：AWS账户/region/bucket及版本化/Object Lock状态、前缀、写入/hold管理角色、保留模式/期限、治理绕过权限、允许测试对象、证据查询人、到期清理和费用责任。

## 远程 APR-08、APR-09、APR-10

### APR-08 只运输审批材料的远程中继

建议单组织、单操作者控制的HTTPS文件中继，Broker不新增公网监听；可信本地操作方上传，独立审批者下载并本地review/sign，再把grant交回。现有本机搬运签名仍可继续用。
中继输入为来源签名challenge信封及请求ID、期限、目标审批人；原始body/headers可能敏感，首轮通过操作方另选安全通道传递，不进入通知或中继索引。
中继输出只是带摘要的上传/下载回执或grant文件，不产生授权决定。审批者独立固定origin公钥及可信Action/policy/trust文件，不能从同一中继自动信任全部材料。
origin私钥仍在Authority，审批私钥仍在独立signer；中继凭证仅限运输。中继可丢弃/替换材料但不得因此制造有效grant，数据真实性最终由现有来源/审批签名与精确绑定验证。
按现有 [origin认证规格](2026-09-10-approval-origin-authentication.md) 与 [独立signer](2026-09-10-local-approval-endpoint.md) 执行；不改quorum/expiry内核，也不为网络慢而延长签名有效期。
来源信封没有key ID，不能从信封自动选公钥；错origin、错主体/会话/策略/参数、过期或重放均由既有链路拒绝。签名超时重新prepare，不能重签旧过期请求。
中继断网只影响交付，不可自动批准；grant上传未知时仅重传同一文件，不能重新签发。Broker锁定/重启/revoke后中继旧条目仍可能存在，UI必须标明外部状态可能过期。
中继审计只记运输主体、请求ID/文件摘要、时间和结果，Broker审计仍是真实执行证据；中继“已签”不等于Broker“已执行”。
依赖现有审批内核和独立签名者；fixture做篡改/错origin/过期/断网/重复交付，现场在两台操作方设备证明合法grant接受及错body/重放拒绝，不执行真实有副作用业务。
待选输入：中继运营方/精确endpoint、传输认证/TLS、保存时限、两台设备/审批人、公钥独立固定渠道、敏感原始请求传输渠道、无副作用测试Action。

### APR-09 一个远程通知入口

最小建议先只做中继pull inbox，不同时接聊天、邮件和push。输入为经身份认证的审批人ID与游标；输出请求ID、来源标签、创建/到期时间及详情入口，不含正文、token或可直接授权的URL。
收件箱显示待审/已交付grant/过期/交付失败等运输状态；批准仍发生在独立review/sign，按钮点击或消息回复不能变成grant。
详情核对流程必须把准确Action、原始参数、策略与可信origin交给signer；本地macOS绑定信息页或只有hash的通知都不能替代完整审阅。
中继只保存必要索引/文件和访问身份；重复通知按请求ID去重，过期隐藏在默认待审列表但保留到选定期限的非秘密审计。broker失效无法实时获知时明确“快照，执行时重新验证”。
失败显示明确状态，无静默丢弃或自动换审批人。依赖远程APR-08；fixture测跨审批人枚举、过期/重复/丢回执，现场证明唯一入口与独立signer衔接及其他用户不可访问。
待选输入：只选pull inbox或另一个明确通知产品、认证/收件人ID、索引与文件保留期、访问策略、传输失败可见位置。默认方案不创建聊天/邮件集成。

### APR-10 人员目录只做稳定ID映射与撤权

建议复用ENT-03同一身份源，映射稳定外部subject、内部principal、approver ID及审批公钥；组织名称/岗位仅展示，禁止根据邮件域或显示名自动授予审批权。
输入为可信目录变更与管理员确认的签名策略映射；输出版本化映射、停用/撤权回执和受影响请求清单。目录不托管审批私钥，不自行生成或替换公钥。
停用立即阻断远程访问并请求各节点撤销相关会话；审批资格由新的有效签名策略移除。节点离线不能宣称即时撤权，必须显示未确认并受策略/会话期限上限约束。
移除审批人、换公钥或策略变更后的旧grant接受条件必须依照现有Broker绑定校验验证，不能仅在UI移除用户后继续宣称其签名已不可用。
审计稳定ID、映射/策略版本、变更来源、接收/应用时间和节点确认；不记录IdP token或私钥。依赖ENT-03、策略发布和APR-08身份绑定。
fixture覆盖同名不同subject、旧目录事件复活、停用时未决grant和公钥替换；现场从真实目录停用追踪到在线节点拒绝，并单独报告离线节点的最大暴露窗口。
待选输入：唯一目录源/issuer、subject到approver映射及公钥核验人、离职撤权时限、策略发布责任、离线节点处理与审计查询人。

## DYN-05～06：Vault动态租约的执行内续期与恢复清理

以下仍为未实施提案，依赖 [P-07B现有单次动态源](2026-09-03-vault-dynamic-lease-source-p07b.md)。租约ID、动态值、Vault token都不返回Agent；续期/清理不能扩大原Action或身份权限。

### DYN-05 单次执行、单租约、至多一次续期

最小切片只解决现有Action绝对deadline之内、初始租期短于本次业务窗口的情形；不提高Action timeout，不创建第二租约、不跨执行共享、不建daemon或脱离execution supervisor的续期任务。
拟议输入是管理员选定的可续期role、已取得的唯一lease ID、实际租期/renewable、一次请求increment及清理预留；输出是本执行内新的保守租约deadline与续期结果，Agent仍只拿原固定Action响应。
官方接口为 `POST /v1/sys/leases/renew`，JSON body为 `lease_id` 与以秒计的 `increment`；响应包含 `lease_id`、`renewable`、`lease_duration`。它不能续token租约，token续期属于VEX-03。参见 [Vault renew API](https://developer.hashicorp.com/vault/api-docs/system/leases#renew-lease)。
increment表示从当前时间起希望剩余多久，不是加到原到期时间之后；provider可以缩短或忽略建议，必须读取实际响应。参见 [Vault租约续期语义](https://developer.hashicorp.com/vault/docs/concepts/lease#lease-durations-and-renewal)。
发送前提交续期开始审计并检查原lease仍有效、Action剩余时间、锁定/drain状态与续期预算；提交失败不发送renew。一次执行最多一个renew在途，不因Agent断连遗留续期者。
renewable=false或无需续期则沿用原租期执行；确需续期但没有足够renew与revoke预算时停止业务IO进入清理，不能先执行到租约到期再补救。
成功响应必须是同一lease ID、合法TTL与可识别renewable；新deadline保守从本次请求开始的单调时钟加实际TTL计算，并始终取原Action deadline的更早值、扣除既有清理预留。
首轮不支持续期响应更换动态值或租约ID；不再次acquire，也不重新发送业务请求。实际TTL不足以继续时仍进入清理。
原业务请求如已在途，由同一个supervisor控制其IO期限；renew失败、超时、响应错配或续期结果审计失败时先取消/停止本地业务IO，再在剩余清理预算内对唯一已知lease同步revoke。
取消本地IO不能撤回上游已经产生的业务效果；已发送且无完整结果时终态为结果未知，不能因revoke成功就记成业务未发生。
renew请求已送出但响应丢失时可能已经延长租期；不自动重试，不继续按“肯定没续上”推算残余暴露。同步revoke未确认则保留清理未知，成功响应也不得交付Agent。
成功终态仍要求源租约revoke确认与终态审计提交；续期前后期限、阶段与结果可审计，原lease ID/token/value和完整provider响应不入审计。
动态租约不是独立于签发身份的永久授权：service token到期/撤销会影响其租约，父token撤销还会级联到子token及其租约。此次不续token或其父链，参见 [Vault token层级与租约](https://developer.hashicorp.com/vault/docs/concepts/tokens#token-hierarchies-and-orphan-tokens)。
role/mount的最大寿命必须经现场确认；Rekey的本地deadline不能缩短provider在崩溃后的实际暴露。没有外部最大TTL证据，就不能沿用现有P-07B的300秒残余暴露承诺来宣传续期切片。
依赖P-07B、真实可续期engine/role、执行取消与审计门禁；DYN-06可增强重启清理，但不是续期成功的替代条件。
本地fixture用假时钟验证increment不累加旧TTL、实际TTL短于建议、wrong ID、renew超时后revoke、业务IO取消、父身份失效、审计失败及绝对deadline不变。
现场只用合成动态凭证：观察源端实际续期/最大TTL、撤销父token、制造renew响应丢失，并核对业务效果与revoke结果；fixture不证明provider的自然到期或级联撤销已完成。
待选输入：Vault版本/engine/role、实际initial TTL/renewable/max TTL、bootstrap身份类型及父链归属、必须续期的Action时长、increment、清理预算、renew/revoke ACL、provider审计和独立验证权限。

### DYN-06 加密持久登记与解锁后的恢复清理

最小切片是在同一Authority数据库保存未清理租约journal，并在成功解锁后执行一次有界恢复清理；不启用自动解锁、不增加持有明文token的外部服务、不承诺发现Vault里全部租约。
拟议登记语义包含vault ID、execution ID、唯一登记ID、准确credential ID/version、固定源引用、lease ID、签发/最后确认期限、阶段及最后清理结果；这些是设计字段，现有schema尚未实现。
lease ID及敏感provider证据加密保存，AEAD绑定vault/登记/执行/credential版本身份；动态凭证值不持久化。bootstrap token继续来自对应加密credential版本，不复制到普通journal列或日志。
准确版本被旋转/撤销后仍只可用于该记录的exact revoke，不能获取新租约、执行Action或被Agent读取；待清理记录引用的历史加密版本不能提前删除，恢复密钥仍由Authority持有。
登记顺序是：本地acquire意图与开始审计提交 → 发送一次源请求 → 校验唯一lease ID → 将加密journal与lease取得审计在同一Authority事务提交 → 才允许业务IO。
有lease响应但登记事务失败时，不发送业务IO，尝试既有有界exact revoke并故障退出；审计设施故障不能靠另写一个“成功”文件绕过fail-closed。
不可消除窗口必须保留：Vault已成功acquire，但响应尚未到达或journal尚未提交时SIGKILL，本地可能永远不知道lease ID。意图记录只能显示取得结果未知，不能据此构造ID或批量revoke整个role。
该窗口仍依赖provider有限TTL与操作方源端调查；除非另行引入provider原子幂等/可关联查询合同，否则本地事务、fsync或journal都不能保证每个已发租约可恢复登记。
正常清理先持久提交清理开始证据，再以绑定的origin、精确lease ID与原credential版本请求 `POST /v1/sys/leases/revoke`、`sync:true`；该参数要求Vault等同步撤销完成再返回，参见 [Vault revoke API](https://developer.hashicorp.com/vault/api-docs/system/leases#revoke-lease)。
收到明确成功后，把非秘密receipt（登记ID、阶段、时间、可公开请求关联号）与清理完成审计、journal完成状态在同一事务提交。不存在只写完成标志却漏审计的成功状态。
远端revoke成功后本地提交前崩溃，恢复仍视作待核对；只能针对同一租约再次清理/查询，不能假定“没记录所以没撤”。普通403、404或“找不到”字符串不单独构成已撤销证明。
恢复顺序为：锁定启动只报告待处理/未知计数，不解密、不联网清理 → 成功解锁 → 校验journal与准确历史版本 → 有界恢复清理 → 展示逐条完成/未知/需人工处理。
恢复期间不恢复旧capability/challenge、不重放业务请求；与未清记录关联的来源暂不接收新执行，其余是否可服务沿用既有生命周期门禁，不发明全局可用性保证。
锁定/drain、清理超时或再次崩溃使工作停在持久阶段；下次显式解锁可重试exact cleanup。无凭据可用或版本缺失时保留未知并明确报错，不能改用当前版本或ambient身份。
Vault token已过期/被撤销时清理可能403；Vault的级联机制与本地“已过TTL”都不是实际业务账户已删除的回执。要标确认失效需源端可信证明，否则保持清理未确认并由操作方处理。
备份只包含快照时已提交journal；恢复旧备份不能发现快照后取得的租约，还可能重新出现已经完成清理的记录。先按ENT-04隔离旧主，再恢复核对，不能两个副本并行领取清理任务。
不可将备份恢复称作全部revoke保证；缺失记录、旧token、provider失联、未知acquire窗口都要分别报告。非秘密receipt导出不包含lease ID，解密journal只发生在Authority清理路径。
依赖P-07B、独立journal加密/AAD与schema规格、Authority事务、历史版本保留规则和backup/recovery合同；若同时做DYN-05，续期确认后的journal期限与审计也需同事务提交。
fixture应逐点SIGKILL：源端acquire成功前后、journal提交前后、revoke成功/receipt提交之间；覆盖错误credential版本、篡改密文、锁定启动、旧备份和token过期，断言不重放Action、不误报全部清理。
现场对合成租约核对Vault审计及实际下游账户状态，证明成功解锁后的exact清理，同时明确演示acquire登记窗口仍有残余租约；不能只用本地journal“完成数”证明外部删除。
待选输入：Vault版本/engine/role、精确历史bootstrap版本保留期、撤销/查询最小权限、token与租约最大寿命、恢复清理批次/时间预算、备份时间点、fencing责任、源端证据与人工残余处理人。

## 交付与下一步

每个已选切片在写实现前冻结操作方输入、明确其版本/字段合同和威胁模型差异，再执行本地fixture与现场验收；不提前生成空配置、空服务、私钥或付费资源。
本文件的Cargo check仅证明文档变更未破坏当前工作区构建，不能作为这些外部能力的实现证据；实际结果由本次任务日志记录。
当操作方尚未提供输入时，以上设计保持“提案/未实施”，不降级为无认证、允许私网、宽权限或自动批准方案。
