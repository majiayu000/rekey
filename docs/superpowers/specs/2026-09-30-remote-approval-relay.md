# APR-08 单组织 HTTPS 审批文件中继

配置/私有store的format1描述属于本APR-08原始切片。后续
[目录消费合同](2026-09-30-identity-directory.md)冻结format2和新增directory必填块，
不迁移非空v1状态；其实现与验收进展以canonical tracker为准。原运输/验签边界保持本合同。

状态为冻结实现合同，2026-09-30。本切片只有运输授权，signer/Broker 继续独立决定签名和业务授权。没有 inbox/list、通知、目录/SCIM、用户登录/refresh、自动签名或 Broker 公网入口。客户真实 IdP 人员 token、ACL、互联网 TLS、两设备和运维验收后置；本地合成 fixture 不替代这些现场结论。

## 五条路由、三种资源

| 方法和路径 | 身份和用途 |
| --- | --- |
| PUT /v1/requests/{UUID}/challenge | 唯一 uploader，以单个 X-Rekey-Approver-Id 指派审批者，body 只含来源认证的原样 challenge 信封 |
| GET /v1/requests/{UUID}/challenge | 原 uploader 或指派 approver 下载原样信封 |
| PUT /v1/requests/{UUID}/grant | 指派 approver 交回原样 grant |
| GET /v1/requests/{UUID}/grant | 原 uploader 或指派 approver 下载 grant |
| GET /v1/requests/{UUID}/receipt | 同上，读取当前两份不可变 upload receipt 和 expired 状态 |

UUID 不是 capability，跨用户存在/无权限请求同为404。认证失败401，IdP未知503，冲突409、文件首次过期410、超限413、容量503。无 query token/cookie/CORS/共享链接、无 list/search。Challenge≤64KiB，grant≤4KiB，receipt响应≤4KiB。未知路径404、上述路径其它方法405。

Challenge 使用既有 origin verifier 和配置独立固定的公钥，要求 tenant/request ID、one-time、quorum=1、maxUses=1、时间和收件 ApproverId 一致。Grant 仅用既有 closed SignedApprovalGrant DTO 获取路由及时间，不在 relay 验签，不持 policy/approver key。其有效截止不超过已认证 challenge 截止。伪签名能被运输但不能绕过现有 signer/Broker。

首次 PUT 将 blob/SHA/routing/receipt/运输审计在同一 SQL 事务提交后201。相同 actor/request/recipient/原样 bytes 重传200且返回同一原 receipt；不同 bytes/recipient/owner409，不能覆盖或重新指派。已登记同文件的重传可在到期后取得原 receipt，不能重新激活。GET blob 到期立即410；GET receipt 仍显示 expired。每个 GET 在交出 bytes 前提交运输审计。

Receipt 固定字段为 recordType=rekey.approval.transport.receipt.v1、instanceId、requestId、fileKind、sha256、byteLength、actor(issuer/sub)、recipientApproverId、acceptedAtMs、fileExpiresAtMs、status=stored、meaning=transport-only; Broker revalidates at execute。Receipt 只证明持久运输，不证明已批准、已执行、当前有效或密码学不可否认。GET receipt 的状态提示为外部快照，Broker lock/restart/revoke 可能使其失效。

## 固定认证与配置

`rekey-approval-relay serve --config PRIVATE.json`。闭合 camelCase formatVersion=1 profile 必填 instanceId、endpoint(HTTPS origin+/v1)、listenAddress、stateDir、tlsCertificateFile、tlsKeyFile、idpIssuer、introspectionUrl、idpCaCertificateFile、introspectionClientId、introspectionClientSecretFile、personnelClientId、audience、tenantId、originPublicKey、uploaderSubject、approvers=[{subject,approverId}]。仅一个 origin/tenant/issuer/人员 client；subject清单可显式允许同一人兼任 uploader/approver。停止→编辑受保护配置→重启更新，不实现热目录。

每次请求 fresh RFC7662 introspection，固定 HTTPS URL，以私文件中的 confidential-client secret 作 Basic 认证，POST token 和 token_type_hint=access_token；无成功缓存。返回 active 必须 boolean；active=false→401。active=true 还必须 exact iss、固定 audience（字符串或字符串数组包含）、exact personnel client_id、Bearer token_type、稳定 sub、整数 iat/exp；iat≤now<exp 且 exp-iat≤300秒，nbf如有≤now。缺/错类型 claim 不可推断，返回503；错 issuer/audience/client 或未来/过期返回401。权限只依据固定 issuer/sub 和显式 subject→ApproverId，绝不依据邮箱、display name、group、自报 tenant 或 JWT。

认证后，在 SQL commit 和响应 bytes 交出前重查已验证 token exp 与同一请求绝对截止。人员撤权只能证明下一次 introspection/ACL 拒绝；不能擦除已下载文件或撤销 Broker 有效 grant。client_credentials 身份没有列入清单则无运输权限。私 token/secret 不入 argv/env/URL/log/receipt，也不散列入 config digest。

Outbound reqwest 固定 URL、no_proxy、无 redirect/retry，仅配置的 IdP CA（关闭内置根），证书/主机名校验；总3秒、body≤64KiB，严格响应类型和重复字段。允许操作方显式固定的企业私网 IdP，无 caller URL 或私网绕过开关。服务 HTTPS TLS≥1.2、hyper HTTP/1.1，无明文/upgrade/keepalive；最多16并发连接，TLS/header各3秒，整请求从接受连接起10秒，header≤32条/16KiB。超时取消连接和认证 future，不留下后台网络继续者。

配置、TLS材料、client secret为当前用户0600、单硬链接普通文件，nofollow/nonblocking且有界读取；stateDir当前用户0700、单进程排他锁、DB0600。服务目录不放 Authority origin私钥、审批者PKCS8、Transit token、Admin socket或capability。启动只输出非秘密 instance/config digest。错误固定类别，不显示 provider响应、token、秘密文件内容或内部异常。

## 独立持久化与保留

新 stateDir/relay.sqlite 与 Vault 完全独立。SQLite user_version=1、STRICT、WAL、synchronous=FULL；requests、transport_events 和 singleton metadata。metadata 固定实例/endpoint/tenant/origin/issuer/人工访问清单归属，配置摘要中不含秘密内容；重启必须同一归属，显式清单更新只在重启由受保护配置应用，既有请求仍保留原 owner/recipient。旧格式/错实例拒绝，无迁移。互斥事务避免并发覆盖。

有效 blob总量≤64MiB、requests≤4096、events≤32768。容量满拒绝新增/下载审计，不能删除仍在保留期对象腾位。24小时保留文件/receipt/event；request行在 challenge和grant都到保留期后才清理，避免晚交回 grant 被提前删。启动先清理，每60秒有界清理，清理与其审计同事务，停止后无后台清理。到期410不等待删除。WAL/备份/宿主root不在磁盘擦除保证。

SQL/fsync失败回滚、无成功 receipt/bytes，并使服务停止新 admission/fault退出；故障后不静默换存储。commit后断连保留 immutable receipt，GET receipt或同文件重传恢复。数据库复制/回滚可能重复交付旧有效文件，真实性/expiry/replay仍由现有链验证。

## 人工操作链和验收

从既有 approval prepare/get 得到原签名信封；origin pin、可信 Action/policy/trust 独立取得。操作方上传，审批者下载；原 body/headers/content_type 走另选安全通道，不入 relay。审批者用原 rekey-approval-sign review/sign，重核 reviewed摘要；上传同一 grant，操作方下载核 SHA 后走原 execute --approval。网络慢不延长60秒签名有效期。

curl必须首参`-q`、`--proxy '' --noproxy '*' --proto '=https' --max-time 10`，无`-L`，正常CA校验；Authorization仅0600私人 curl-config。下载 umask077、独占新临时文件，核对 SHA/receipt，不覆盖已有 reviewed/grant 文件。身份 token由既有可信客户登录客户端取得，本服务不增加登录工具。

本地验收用合成 IdP＋真实 HTTPS relay 进程，将真实 origin challenge 和 signer grant 原样运输至真实 Broker，验证正常一次执行、正文/session/replay/伪签名/来源篡改拒绝。合同测试另覆盖 fresh撤权、错误claims、跨subject、same-file retry/冲突、SQL audit失败无blob/GET泄漏、restart/排他锁、容量/保留、IdP TLS/超限/慢请求、header/body界限及 canary。完整 workspace suite/发布由 root 独占；真实 SIEM、人员目录、APR09/10和真实客户 IdP现场不属于本切片。

独立 APR-09 增量见 [远程审批 pull inbox](2026-09-30-remote-approval-inbox.md)：在上述文件运输 API 之外增加一个经认证的摘要列表入口，APR-08 的五条文件路由与验权合同保持各自范围。
