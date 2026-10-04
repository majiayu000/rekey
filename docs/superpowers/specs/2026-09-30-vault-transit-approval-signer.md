# EXT-07 固定 Vault Transit 审批签名

> Status: Lab (v3 scope; enterprise reserve)
> Existing contracts and evidence are retained; this capability is excluded from the default v3 build and release package.

状态：本地实现合同，真实 Vault ACL、非派生密钥配置与撤权未现场验收。

现有独立 `rekey-approval-sign` 增加显式 `--vault-transit-profile PRIVATE.json`，不改变 policy library 的纯函数或 Agent API。sign 时该参数与 `--key-file` 必须二选一；review 可选相同 profile，既有软件签名 review 保持原合同。没有自动 fallback、解锁、provider 注册表或新 crate。

Profile 为本用户 0600、单硬链接普通文件，O_NOFOLLOW/O_NONBLOCK 打开，最多 64 KiB，以 zeroizing buffer 读取；严格拒绝未知/重复字段。固定字段为 `credential_type: vault-transit-approval-v1`、`origin`、`mount`、`key`、正数 `key_version`、小写 hex32字节 `public_key`、`vault_token`、毫秒绝对 `token_expires_at_ms`。token 只在该受保护文件中，不读 ambient Vault 环境、不入 argv/review/grant/log/digest，也不散列 token。origin 为精确 HTTPS origin，无 userinfo/query/fragment/path；mount/key 为各一个 ASCII 字母数字、下划线或连字符路径段。只支持非派生 Ed25519 显式版本，由操作方核验 Vault 端设置；本地固定公钥必须匹配独立可信 policy 的 approver 公钥。

review digest 在现有 Action、origin challenge、policy、参数与请求校验后额外绑定非秘密 origin/mount/key/key_version/public_key；token 与到期时间不进入 digest，允许相同目标续 token。sign 必须用 profile 重建相同 review。改变公共目标、版本、公钥或请求均要求重新 review；不在错误分支切换本地 key。

仅 POST `/v1/MOUNT/sign/KEY` 一次，`X-Vault-Token` 标为 sensitive header。JSON 字段严格是标准 BASE64 `input`、显式 `key_version` 与 `prehashed:false`。input 为现有 `RKAPPROVAL\0\x01 || RFC8785(unsigned_grant)` 全字节，不签 review digest，不传 context，不创建/导出/轮转密钥。协议依据 [Vault Sign Data API](https://developer.hashicorp.com/vault/api-docs/secret/transit#sign-data)。

传输使用 reqwest 无环境 proxy、无 redirect、无内部重试、HTTP/1、内置 WebPKI 公共根与原 hostname 校验。解析一次 DNS，全量结果经过与 Broker 完全共享的纯 `ip_is_public` 谓词，任一私网/不受支持地址即拒绝，连接固定到已筛选地址。无生产私网/CA/解析器开关。Tokio current-thread runtime 对 DNS/connect/read 使用一个绝对 10 秒 deadline；超时取消整个请求 future，DNS 阻塞 resolver 残留不得继续到请求，runtime 不无限等待它，CLI 失败后退出进程。响应最多 64 KiB；403、redirect、丢响应、超时及 provider 错误固定脱敏 exit 1，远端已签名与否未知，不自动重试。

只接受 200 JSON 的 `data.signature` 为精确 `vault:vN:BASE64`，N 必须等于 profile 的显式版本，标准 BASE64 解码后必须64字节；先用 policy approver 公钥本地验证，再放入原 BASE64URL_NOPAD grant 并调用生产 `parse_and_verify_approval_grant`。provider 的其余公共 response envelope 字段允许存在，未使用字段不展示或记录。任何返回签名不得绕过既有 origin challenge、policy、Action、body 与 review 校验。

grant 的 issued/not_before 在远端调用前确定，expires 为 issued+60秒、challenge期限、policy期限的最小值。token 在调用前及响应到达后重查，响应验证后重查 grant/policy/challenge期限；过期即无成功文件。输出沿用 0600 create_new，新增 nofollow、所有者/权限/路径inode检查与文件/父目录 fsync；已有文件或symlink不可覆盖，磁盘失败非零，部分文件保留供 review。确认输出成功前不输出签名成功。

本地 fixture 使用合成 policy/origin/approver 和真实 TLS 接收端，CA/解析结果仅由 cfg(test) 代码注入。验证 exact request/domain bytes、既有生产 grant verifier、公共目标 review 绑定、403/错版本/错签名/大小/时限/到期/文件权限/路径/symlink/日志 canary、DNS 混合私网和 IPv6、以及软件签名回归。真实 Vault 私钥不可导出、非派生配置、token ACL/撤销、公网 TLS 和真实 Broker 消费 remote grant 的现场证明另行记录，fixture 不替代这些结论。
