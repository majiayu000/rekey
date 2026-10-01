# AUD-08 固定 S3 Object Lock 审计归档

状态：实施合同；真实 AWS 权限、Object Lock 和防改写/删除验收后置。

独立 `scripts/rekey-audit-archive.py` 只运输 AUD-07 已封口批次，不链接 Authority、不解锁或读数据库。复用同目录 audit delivery 的私文件及批次校验函数。新工具、定向测试和本规格是最小切片；不新增云 SDK、Provider 层、后台 daemon、bucket 创建/配置、对象删除或 retention 修改。

受保护 profile 是当前用户 0600 单硬链接普通 JSON 文件，祖先路径禁 symlink，最多64KiB，closed 字段 `format_version:1, purpose:archive|legal-hold, bucket, region, expected_bucket_owner, prefix, source_instance_id, vault_id, operator_label, access_key_id, secret_access_key, session_token, expires_at_ms`。要求短期 STS 三件套，expiry 在调用前后验证；不读取 argv/env/ambient AWS profile/metadata/credential chain，不自动登录/刷新。bucket 为无点的标准单段桶名，region 是商业 AWS region 形状，endpoint 唯一生成 `https://BUCKET.s3.REGION.amazonaws.com`；不接受自选端点、China/GovCloud/access point/directory bucket。operator_label 是人工声明的运维标签，不宣称 AWS 已核验的 IAM principal。archive 和 legal-hold profile 的 purpose 分别检查，实际 IAM 最小权限与角色分离由客户配置并验收。

`archive --profile PRIVATE --batch SEALED_BATCH --state PRIVATE_DIR --mode GOVERNANCE|COMPLIANCE --retain-until UTC --legal-hold ON|OFF` 冻结一个批次/目标/期限。state 是本用户0700、单进程 flock，immutable JSON journal + canonical batch，文件0600、nofollow/create-exclusive/file+dir fsync；partial 文件存在则要求人工检查。公开目标、源/vault UUID必须和 batch 匹配，batch 的完整无过滤 export/trailer/序列/摘要按 AUD-07 校验。对象 key 固定为 `PREFIX/SOURCE_UUID/VAULT_UUID/BATCH_UUID-EXPORT_SHA256.json`，上传内容是同一批次的规范 JSON，另计算对象 SHA256/长度。state 只保存一个批次，128MiB/1000个文件上限，无后台删除。

先 fsync payload + upload intent 再首次 PUT；单次 conditional PUT 使用 `If-None-Match:*`、SHA256 checksum、retention mode/until、明确 hold 和 SSE-S3。用 SigV4 对 body/所有实际 header/固定路径签名，STS token只进HTTP header。已有对象412或发送结果未知后，下一次显式 archive 调用以 HEAD 获取当前具体version，核对 SHA256 FULL_OBJECT/长度，再读该version的 retention/hold；不同内容、空/null版本、期限/mode/hold不符均失败，不能覆盖、删旧版本或自动换key。HEAD验证具体version及内容摘要后立即fsync，再读该version的retention/hold；后续永远只读该version。若先前意图已提交但发送前终止，恢复HEAD明确404时只对同key/同bytes再次conditional PUT；403或其他未知不能推断不存在。初次响应丢失之前仍有无法证明旧version的窗口，操作方不得在该前缀创建delete marker或替换当前version，fixture不能证明此IAM约束。

成功需要 HEAD checksum/长度/具体version、GET retention 与 GET legal-hold 的实际回执全部匹配 intent，然后 fsync immutable receipt 才输出 verified。HTTP200/ETag/本地hash都不单独构成成功。expired目标不得新上传，工具不延长期限或自动清理。`verify --profile PRIVATE --state DIR` 重新读取已知version，报告当下 retention/hold，保留原回执；hold可能由有权主体改变，verify不将旧ON当成仍ON。回执只证明读取的服务结果，不是WORM或合规法律证明。

`legal-hold --profile MANAGEMENT_PRIVATE --state DIR --operation-id UUID --status ON|OFF` 仅对归档已知version操作。先读取并保存before、人工标签/时间和固定operation ID，再一次 PUT exactversion + XML/Content-MD5，随后重新读取retention/hold，保存before/after及请求ID回执。每次操作意图/回执不可覆盖；相同ID重启只重用相同状态/actor，结果未知时先读同version，允许确认已达目标或显式再次发送同意图，不自动网络重试；冲突或不同before值要求人工检查。工具从不发送 governance bypass 或 retention 修改/删除请求。

网络阶段共用一次绝对30秒预算，每个 DNS/TLS/HTTP最多8秒；初始与终态本地fsync可能额外等待，不宣称整个CLI的磁盘IO也受该期限约束。生产 HTTP 用独立子进程做全操作 deadline，超时kill/waitpid，不能遗留继续上传的线程。DNS所有结果必须public且连接pin到已筛选地址，TLS验证固定hostname与系统信任根；不用proxy/redirect/自动retry/custom CA。响应≤64KiB、严格关键header唯一、XML限制无DOCTYPE/ENTITY、expected bucket owner每次签入请求。远端错误内容不展示；会反射身份字段的version/request ID在进入公开journal前封住原凭证及常见编码形式。任意网络/读回/磁盘故障非零、保留pending/partial，不声称远端未发生。Python不能保证进程内秘密物理清零。

协议依据 [PutObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObject.html)、[HeadObject](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadObject.html)、[GetObjectRetention](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectRetention.html)、[GetObjectLegalHold](https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectLegalHold.html)、[PutObjectLegalHold](https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutObjectLegalHold.html)、[S3 SigV4](https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html)。检查具体版本与校验和、期限制及hold读回，不把governance权限绕过能力和compliance法律属性合并为同一声明。

本地验收须包含公开SigV4向量、TLS S3协议fixture、正常归档、PUT/hold响应丢失和重启、412同批确认/不同批拒绝、错owner/version/checksum/mode/date/hold、认证期限、角色隔离、无proxy/redirect/自动retry、慢DNS/headers绝对超时无晚发送、文件/父路径替换与fsync故障、凭证反射和日志canary。真实客户测试桶和生产桶各自用写入/管理身份尝试改写、删具体version、缩短retention、解除hold并查真实服务拒绝/允许记录；没有这些证据只提高到本地合同/黑盒级，不能声称现场WORM已完成。
