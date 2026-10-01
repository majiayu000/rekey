# APR-09 单入口远程审批 pull inbox

状态：冻结实现合同，2026-09-30。依赖 [APR-08 文件中继](2026-09-30-remote-approval-relay.md)，只在同一 HTTPS 服务增加一个经认证的 `GET /v1/inbox` 入口。它是受保护 curl 终端操作入口，不是网页完整 review UI。无 email/chat/push、替换审批人、人员目录、签名按钮、服务端签名、自动批准或 Broker 公网入口。

## 固定 API 与身份

每次 inbox GET 用 APR-08 的同一固定 IdP fresh introspection 和显式 issuer/subject 清单，无缓存。服务端列出当前 uploader 自己创建，或当前 subject 与原 recipient/ApproverId 精确匹配的条目；一人显式兼任两个角色时同一 request 只出现一次。caller 不提交 subject/approver ID；任何游标都不授予权限。未列 subject 404、无效/停用 token 401、IdP未知503。除 GET 外405；cookie/upgrade、请求 body、重复/未知 query 均拒绝。既有文件路由继续按原 API 单独认证。

Query 仅允许可选 `cursor` 和 `includeExpired=true|false`，默认 false。游标明文格式 `非负十进制challenge_accepted:canonical-UUID`（长度≤64），其中 challenge_accepted 是原 challenge 运输接收时间；不加HMAC/key/config。所有 query 总长≤256字节、重复字段和非规范格式400。服务器每次重新应用当前身份ACL、到期过滤、稳定排序 `(challenge_accepted ASC, request UUID ASC)`，查询最多26条、返回最多25条并给 nextCursor。任意构造/复制其它人的cursor只能改变位置，不能读取其条目。页数不是跨请求一致的snapshot；时钟回退或并发新增更早位置可能需要从首页重拉，不承诺一次遍历看到所有新项。客户端按 requestId 合并，不把分页/重复拉取当成新审批或重新投递。

Response≤16KiB，固定 `recordType=rekey.approval.inbox.v1`、items、nextCursor、snapshotAtMs、snapshot=`transport-only; Broker revalidates at execute; lock/restart/revoke may invalidate these files`。每项只含 requestId、sourceLabel=`ed25519:固定origin公钥hex`、createdAtMs（challenge运输接收时间）、expiresAtMs（当前待交付文件截止）、transportStatus、需认证的相对 detailPath/receiptPath。来源标签是运输方配置的公开pin提示，必须和独立可信origin pin比较，不能靠中继标签自动信任密钥。详情路径无query/token，UUID不是capability；响应不含原body/headers、challenge/grant内容、人员token、capability或可直接授权URL。

## 运输状态和时效

`awaiting-review` 是仍有效且未交回grant；`grant-stored` 只表示有仍有效的grant文件，relay未验签，不表示已批准/执行；`grant-expired` 表示该已交回文件过期，不能覆盖或重新激活；`expired` 表示未交回grant的challenge过期。默认隐藏所有上述已过期文件条目，`includeExpired=true` 才列仍在24h保留期的过期快照。已有grant的expiresAtMs是原grant截止（不超过challenge截止），接收grant不改变创建时间或cursor位置，不把late grant当成新请求。

`transport-failed` 是仍有效且无grant，而此request最近一次非downloaded运输事件为已认证owner/recipient的HTTP错误；它显示最后已知运输失败快照，可能是详情获取/交回失败，不宣称某次上传未发生。之后同文件成功重传的原有事件可恢复awaiting-review；错误不会自动换审批人或生成grant。没有成功入库challenge的未知/失败上传没有inbox条目，由原明确HTTP失败和运输审计显示，不能伪造请求行。审计不足/SQL故障的inbox返回显式503，不回空列表假称没有待办。

SQLite user_version仍为1，无schema迁移、新表/索引或第二账本；复用requests的challenge_accepted/id/expiry/grant存在及transport_events。一次read+inbox audit在同SQL事务，commit完成后才返回bytes；提交前后重查原绝对deadline和人员token expiry。默认页若某项在提交期间到期则503无条目，客户端显式重拉。响应始终是外部快照；Broker当前policy/session/lock/restart/revoke状态由execute重新核验。复用APR-08私文件、TLS、no_proxy/no_redirect、3s IdP/10s整连接、容量/fault/drain及24h保留清理。

## 人工链与验收

操作方上传原origin-signed envelope；审批者用受保护curl文件查询inbox，按requestId去重，核sourceLabel与独立pin，再经认证detailPath下载。原body/headers/content_type和可信Action/policy/trust继续经另选安全通道交给原独立signer做完整review/sign；只有hash/摘要通知不能替代完整核对。审批者交回grant，操作方用同入口发现grant-stored再按原文件API下载，原execute --approval仍验证签名、完整绑定、时效和一次使用。

curl首参`-q`，`--proxy '' --noproxy '*' --proto '=https' --max-time 10`、无`-L`、正常CA校验；Authorization仅0600私人curl-config。例如 `curl -q --config PRIVATE_TRANSPORT.conf --proxy '' --noproxy '*' --proto '=https' --max-time 10 'https://FIXED_ENDPOINT/v1/inbox'`；下一页用同固定endpoint的`--get --data-urlencode 'cursor=返回游标'`，不能直接跟随调用方/响应中的任意origin。下载遵循APR-08独占临时文件/umask077/SHA检查。

定向实际TLS测试覆盖25+1分页、相同created时间UUID排序、cursor篡改不越权、跨subject/双角色去重、默认到期过滤/显式保留快照、late grant不新排位/过期grant不重投递、transport failure状态、restart/ACL移除、fresh IdP停用、inbox审计失败无data、既有CA/proxy/deadline回归。原真实HTTPS→signer→Broker E2E必须从此inbox取得requestId后下载并完成正负业务链。真实人员登录/停用传播、两设备、公网部署和原始请求安全通道现场仍后置；不因此声称APR10/ENT03完成。
