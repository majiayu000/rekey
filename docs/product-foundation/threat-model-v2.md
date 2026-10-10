# Rekey 0.5 开发整合威胁模型

当前开发线为 vault27 / policy8，新增能力以[统一整合合同](../superpowers/specs/2026-10-09-unified-experiments.md)为准。已发布 0.4 的 vault26 / policy7 不迁移、不双读。以下通用边界继续适用。

行为来源为 [Agent call SPEC](../superpowers/specs/2026-10-05-rekey-agent-call-model.md)。0.4 默认本机调用没有 capability token，连接和权限由用户签名决定。以下边界不继承旧版设备验收。

- G1同用户程序可调用本机接口；调用方名称可伪造，仅记录/收紧，绝不能放宽默认权限。
- A6网页/SDK请求：loopback IPv4绑定；Host只接受发布地址；要求公开rekey占位头，并拒绝Origin、Sec-Fetch-Site、CONNECT、Upgrade、混淆长度与真实认证头。抢占端口会使daemon启动失败；0600地址文件不代表对恶意同用户的网络隔离。
- 签名规则固定host/方法/路径/查询键，默认读允许、写审批、危险写拒绝；参数规范化一次，规则和审计共享结果。写审批绑定具体规范请求、策略摘要与调用方；时间窗不覆盖Deny，锁定/策略变更即清除。
- 源凭据用途分离：HTTP、SSH、OAuth和AWS源不能互相当作普通Bearer使用。SSH公共身份来自签名策略，私钥不为列举解密；服务器签名绑定校验后按host公钥判定，未知/未绑定需审批。
- T0结果遮蔽防止源值与支持的可逆表示反射；T1经显式签名开启，Agent收到临时凭据，目标/权限/实际期限另行审计。EKS presign暴露public access-key identifier而不返回secret key；拒绝嵌入bootstrap session token。
- OAuth使用固定供应商端点、随机state与适用的S256，refresh/client secret加密、缓存按锁定/策略变更清除；Notion非expiring access持久化是显式供应商例外。网络失败与需重新授权区分，后台审计失败关闭服务。
- scan是完整值匹配接口，限速与有界输入，不返回匹配内容；它仍可被同用户用来验证一个完整猜测值，不能宣称没有任何oracle。
- 凭据只在受控内存和出站请求内出现，管理输入走隐藏TTY/显式stdin；审计不写正文、查询值或认证值。审计提交失败关闭服务；started在解密前提交，取消不能伪造成功。
- 默认App和CLI不提供长期密钥的显示、复制或导出；人类保存/轮转仍需对应管理证明，软件验收通过签名Connection扫描确认真实存值，不能用旧版reveal合同恢复默认导出。

真实Keychain、SE私钥、Touch ID、签名MCP阳性、供应商授权和公开安装必须有当前0.5设备证据；历史0.4及更早结果不能替代。lab受管环境、G2和企业能力仅为储备；编译不代表部署验收。

## 新增实验能力边界

- mTLS 只接受签名 Connection 中显式的 T0 固定 HTTPS 认证声明。客户端私钥由 Worker 验证当前策略摘要与已提交 started 后一次性交给 TLS owner；每次后端 poll 检查策略、期限与生命周期。轮换、撤销和策略激活确认前取消并排空旧 owner；不复用连接、TLS session 或重试。客户端认证不提升 G1 隔离等级。
- CA signer 为独立类型，仅管理员逐次 A2 可导入、轮换、签发外部 CSR、撤销序列号与发布完整 CRL。Agent 无 CA 签名/读取入口。证书、CRL 与现有 HTTP action 的完整集合由 generation MAC 认证；授权变更只允许预期增量，触发器引起的额外删除拒绝提交。软件证据不代表真实 CA 运维与吊销分发已部署。
- SSH 仍由 Worker 持有密钥。每个 socket 按签名策略限制签名次数和持续时间；一次授权不绕过该预算。外部审批需一人或两名不同的允许审批者，绑定完整 challenge 与请求 review；本机 Presence 不能代替外部签名。接受审批与 started 同事务提交，待审批连接 EOF/额外输入使 challenge 失效；Worker 入队后由原 owner 等待终态，所有输出按当前策略和生命周期门控。
- Agent PKI 准入与 HA 没有实现；lab 编译、合成 TLS/SSH 与历史性能数据不代表这些能力或真实硬件验收。

## 旧版历史说明

以下是历史0.3/v2边界，Profile/run/L2等声明不适用于0.4个人产品。

### Rekey 0.3 威胁模型与保护边界（v3 设计）

路径为历史链接兼容而保留，本文描述 **0.3.0-alpha.2 未发布候选**。
行为依据是 [v3 SPEC](../superpowers/specs/2026-10-02-rekey-v3-personal-first.md)，
不是历史v2档案或未来企业方案。证据与未验项见[功能事实矩阵](feature-truth-matrix.md)。
vault25 / policy6已于2026-10-05冻结，继续覆盖全部0.3版本，包括预发布；改号不改变安全模型；此维护约束不提升安全等级或代替设备验收。

Presence 不得签发新的七天授权、修改密码或轮换恢复密钥；签发与改密码只接受密码/恢复密钥，恢复轮换保持仅密码。已解锁 step-up、unlock 与 Locked shutdown 共用失败退避，Presence 成功不重置猜测次数。App 仅在首次成功读取后的固定十秒窗口复用 LAContext，不缓存 K。

## 资产、主体与信任边界

保护对象是provider Key、VRK/DEK、解锁证明、策略签名私钥、审批与预算授权，以及可验证
的当前状态。可信端为Authority、已验证策略/Action、执行器和管理App；上游、Agent输入、
MCP客户端和网页均不可信。CLI不直接打开数据库或链接Vault crypto。

| 攻击者 | 本合同边界 |
|---|---|
| A1：被prompt注入、只能调用Agent接口 | 所有等级均禁止读取凭据、任意URL与越权执行 |
| A2：同用户任意代码，无root/物理在场 | L1目标；当前L1-dev不能承诺阻止其直接读进程/文件或窃取bearer |
| A3：还能诱导用户确认 | 规范请求、可信目标及完整差异减少误批，不能消除社会工程 |
| A4：root、内核、物理取证、恶意管理员 | 不保护 |
| A5：上游返回/变换秘密 | 只阻断已实现的有限表示，不保护任意编码、哈希或隐蔽信道 |

## 保护等级

L0是加密保存、Agent访问锁定。L1-dev保证Agent接口不返回Key，适用于当前源码和Linux
用户安装。L1还依赖签名hardened App/daemon、发送证明前的peer验证、userPresence、
同用户内存与受保护锚权限。V1/V2、DPK与CAS设备验收未完成，不能宣称L1。
L2还必须由实际启动的隔离子树及deny-other网络策略证明，不能从Profile字段推断。

UI锁定且无会话显示L0，解锁显示已确认的L1-dev下限，未知/故障不报等级；服务签名
是独立标签。签名peer正负向软件测试不代替完整A2验收。

## 九项不变量及具体边界

1. **I1：Agent无secret-read。** Agent UDS、MCP和gateway只能使用已授权Action。Admin
   reveal是另一通道，每次需要新证明；A1 desktop token不能替代。
2. **I2：先授权与durable started，后credential。** Authority持有解密材料，请求中的
   PreparedCredential只消费一次，受控内存零化；不能把页锁等同所有临时副本证明。
3. **I3：敏感管理逐次证明。** 查看明文、扩大范围、策略激活、七天授权、备份/恢复、
   wrapper/根轮换与shutdown均按其合同验证；shutdown在Locked也需证明。LOCK无需证明。
   离线restore需源密码/恢复因子；VRK轮换保留两因子要求，不让Presence替代解密材料。
4. **I4：先验证daemon身份。** 正式macOS CLI/App在发密码或K前查同Team精确rekeyd身份；
   开发/未签名路径必须提示身份未校验，等级仍只按已确认状态显示，不能声称L1。
5. **I5：秘密不进argv/env/log/audit/metadata。** 管理证明走隐藏TTY或显式stdin/frame body。
   `run`子进程环境中的短期capability是明确例外；不是provider Key，权限仍受Profile约束。
6. **I6：固定上游。** origin/method来自认证Action，参数只能构成已声明路径/查询；拒绝
   credentials-in-URL、重定向、代理环境与非公网DNS，连接钉在已检查IP。
   DoH默认关闭。管理员显式设置REKEY_DOH_URL后，系统仅返回198.18.0.0/15虚拟地址时，
   才向选定HTTPS JSON DoH服务查询A/AAAA；服务及全部答案均须公网并固定连接，TLS正常验证。
   解析服务获得目标域名，不获得provider Key。未配置或失败均不退回虚拟地址。
   固定IP仍保留原Host/SNI，但不保证所有TUN的域名分流；DoH不提供代理出口。显式私有来源合同不变。
7. **I7：未知与审计失败拒绝。** canonical/schema/policy不明不能执行；durable审计失败fault。
   有副作用后的未知结果不自动重试，不将收到部分输出或部分SSE当成成功。
8. **I8：认证代数与外锚。** 见下节。检测旧header整库回滚，不等于硬件单调计数器。
9. **I9：范围内Agent零打扰。** allow调用不会触发系统认证；只有require-approval进入
   明确审批。确认每次run由签名Profile显式选择；后台轮询/通知不会读取K。

## Presence、Approver与策略

K是七天有效的随机bearer证明，App只在用户明确操作时从userPresence保护的DPK读取。
Worker保留hash和原双时钟上限；重复resume、错误resume或重启不续期。普通密码unlock
不会从磁盘自动发布K verifier；手动/idle lock、wrapper变化或故障撤销授权。
正常停机可以保留wrapped ticket，但不保留进程内授权。泄露K仍可在有效期内重放；
hash不是不可重放证明，challenge nonce防的是grant挪用/重用。

个人模式使用固定SE P256信任，团队模式使用固定外部Ed25519信任；私钥不进daemon。
App只签daemon给出的原始RKPOLICY字节并展示完整替换差异；切工作区、关闭表单、取消或
过期会使上下文失效，迟到认证不激活；正常系统认证造成的暂时失焦保留既定例外。真实SE/Touch ID行为未以软件签名测试替代。

规则中的Approver是唯一来源：LocalPresence一次性一次使用，或Ed25519 keys+threshold。
外部library保留单/多人及时间窗；窄sign CLI不因此自动扩大。Remote保留lab枚举但拒绝执行。
本机review绑定完整canonical请求、上下文和期限；每次决定需当前K，默认拒绝，owner
wait/cancel不执行请求也不消耗最后一次capability。approve后仍需调用者显式重提原请求，
最终一次消费先于started/凭据使用；未知决定结果取消而不自动补发。

个人规则必填template-default/allow/require-approval，选择本身进入签名snapshot6。
同一principal+Action不能出现冲突选择；App放宽规则必须经完整差异、新证明及新签名。
实现/API已冻结，最新全量合流结果仍待完成；没有新增自动许可或第二规则引擎。

## 代数、恢复与储存攻击

Header的非零u64大端代数由VRK派生独立HMAC密钥认证，绑定vault ID与格式。
业务真实变更每事务+1；无变化/失败+0，查询、普通审计、Agent执行不加代数。
实际DB事务COMMIT前，先推进受保护high-water，再原子替换/fsync文件锚。锚已保留后
提交失败或超时不能回退；fault并保持原错误，重启可能出现安全侧疑似回滚。

普通unlock/resume先验证候选root、header及必需状态，成功审计后才发布。
旧snapshot或历史缺失进入无VRK的rollback-suspected，lock/重启不是自动同意。
确认必须重新认证源密码或恢复因子，比较明确展示的vault/source generation/high-water，
完整校验内容后重新定代到最大已知值+1，并保持Locked。离线restore同样先inspect再确认。
错误/取消证明不写DB或锚；context变化必须重读并由用户重新判断，不自动重试。

文件模式是L1-dev弱检测：同用户可回滚文件。L1还需真实DPK读改删/重建与跨目录CAS
验收；flock不单独提供此保证。不防root、整钥匙串回滚，也不单靠header MAC检测保留
新header而替换旧合法行。旧备份依赖其历史因子；确认恢复不宣称使泄露的旧因子失效。
Agent执行不推进代数：最后一次管理变更后的合法旧快照可以重置随后累积的用量，
因此预算不防拥有本机状态写权限的攻击者回滚，也不承诺硬费用封顶。
Incomplete marker必须保留；不能通过删marker、DB或anchor来绕过确认。没有迁移/回填。

## 共享执行、预算与返回方向

Profile的稳定principal、instance与精确能力/Action版本来源于已验证snapshot；仍执行
普通策略。共同canonicalization在审批之前校验model并补入/收紧实际output bound，
同一effective body进入hash、review与HTTP。原始JSON数字如发生parse/JCS精度丢失被拒绝。

单一认证request ledger按principal+instance+UTCday记录一次请求与一次终态usage；
capability续签和daemon重启不重置。未知usage/中断按saved max结算；非生成能力output=0。
并发已在途请求可造成有界超额，不是硬费用封顶或精确账单系统。
每次准入和结算均认证完整历史账本，成本随历史增长；alpha没有日汇总或历史压缩。
这属于一周自用需观察的性能限制，不通过改变已冻结的格式来补一套汇总状态。

Gateway只绑定127.0.0.1动态端口；run读取经验证的Admin响应，不信port缓存文件决定
capability目的地。Host/Origin/auth/path/header/body都受限，审批控制头不会进上游。
策略激活已提交但bind失败时保留激活事实，endpoint不可用，SDK launch失败，不重签。

SSE原始tools/thinking字节保持，raw bytes和decoded JSON字符串均检查；初始值、delta、
done快照与SDK有序text投影共用有界遮蔽上下文，包括Anthropic交错文本块的block index顺序。未知跨delta语义或超限拒绝。
首字节前的安全拒绝保留RESPONSE_SECURITY_VIOLATION与不可重试属性；已发SSE后失败中止正文。
2026-10-06 本机修复候选在完整检测后回收已发 raw 前缀及不再需要的工具元数据尾；
累计 wire 和 retained 限额仍生效，真实 needle 前缀和编码标记仍可能保留到限额。
已有 4MiB fixture 通过不代表任意元数据流都可接受。
完成帧必须等EOF与durable结算后释放；取消/断开仍由Supervisor终态记账。
支持的raw/base64/base64url/hex/percent/JSON表示有限，嵌入base64完整对齐保证要求
秘密至少16字节；短Key给固定警告。无法保证任意变换/压缩/加密/侧信道均被识别。

## 平台、发布与残余风险

Linux Profile netns目前不可用：共享可写工作目录/Unix socket边界及SDK桥未完成。
旧agent-run与Docker参考只证明指定拓扑，不能升格为当前Profile L2。
Codex Seatbelt受managed-preferences限制；不能自动放宽规则或重试裸进程。
macOS sandbox-exec是受限实验入口；仅按实际已测build/arch说明。

真实provider/模型、计费usage、V1/V2、DPK/CAS、SE/Touch ID、Installer/SMAppService
全生命周期、T12与公开下载全部是独立门槛。当前合成/CLI/MCP/Broker/UI证据不替代它们。
企业source/relay/OIDC/插件/指标/DR均属lab；没有SLA、通用多租户或云端权限承诺。
历史v2发布事实保留在原release notes，不改变本候选Pending状态。

2026-10-04 [统一候选设备证据](../evidence/v3-release-acceptance-2026-10-04.json)已覆盖受保护代数的 ad-hoc 读/写/删拒绝、双并发 CAS、旧库认证后疑似回滚及实际 hardened daemon 的 LLDB 拒绝。SE 建钥/重载、私钥不可导出和无交互签名拒绝已验证；交互签名/取消、已安装服务与完整产品攻击矩阵仍是独立门槛，不提升保护等级。

## 0.5 desktop privacy extension

The [personal desktop contract](../superpowers/specs/2026-10-09-personal-desktop-security.md) extends remembered grants to explicit 1/7/30-day choices while retaining protected PresenceKey access, one-way replacement and same-ticket monotonic caps. Password/recovery alone issue grants; A1 remains at most seven days. Admin opcode72 revokes only the authenticated desktop token, optionally forgets the remembered grant, and audits before success. Agent authorization is unchanged by privacy lock; full-vault lock retains its drain/revocation behavior. UI cache clearing is a presentation boundary, not same-user isolation or new hardware attestation.
