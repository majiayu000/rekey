# DYN-05 执行内单次 Vault 动态租约续期

日期 2026-09-30。本文替代 P-07B 中动态源 profile v1 和“不续期”条款；其余固定 Action、响应封闭、500ms 清理预留及失败合同继续适用。DYN-06 持久租约 journal 不属于本次变化。

## 关闭的管理员合同

加密 profile marker 改为 `vault-dynamic-source-v2`，既有 origin/mount/role/key/vault_token 字段保持必填，新增必填整数 `renew_increment_seconds`，范围 5..300。未知、重复、遗漏字段和 v1 profile 在 Admin 持久写入前拒绝。没有旧格式回退、schema 迁移、新 Agent 参数或后台管理器。管理员通过现有 add/rotate 的受保护 frame body 显式选定 increment。

## 一次执行的顺序

`execution.started → acquire → vault.lease.issued → [vault.lease.renewal_started → renew → vault.lease.renewed] → fixed business action → exact synchronous revoke → vault.lease.revoked → execution terminal`。

保留 acquire 实际 renewable 与 TTL。仅当 renewable=true 且初始租约截止早于原 Action 截止时在业务 IO 前续期一次；无需续期或 renewable=false 沿用初始截止。既不重试 renew/acquire，也不重放业务。所有阶段仍由同一个 admitted execution supervisor 所有。

renew 固定为 `POST /v1/sys/leases/renew`，以既有 origin 和 bootstrap `X-Vault-Token` 请求，JSON body 精确为 `{"lease_id":"<已取得的唯一 ID>","increment":<管理员秒数>}`。无路径中的 ID、query、prefix 操作或任意 endpoint。请求和响应沿用 Zeroizing、禁止 redirect/proxy、public-IP/TLS 和 64KiB 有界响应合同。

200 响应必须包含同一个 ID、整数实际 TTL 5..300、boolean renewable，各字段仅一次；要求无 JSON 尾随数据。允许 Vault 常规 metadata；data 只能 null/空对象，auth 只能 null，均不接受新动态值。token/已取得动态值在 body/header 的原样与编码反射被封闭；租约 ID 只在必需的受保护 body 中出现，不向 Agent 输出。错误响应内容和 parser/provider 错误文本不进入审计。

## 期限和停止

续期前提交 renewal_started，随后再次检查生命周期 remote-effect admission、取消信号和未扣清理预留的有效原租约/Action 截止。无正窗口则不发送 renew、不发送业务 IO，直接 exact revoke。

renew IO 最迟在 `min(原Action截止, 初始请求开始+初始实际TTL)-500ms` 结束。成功后的租约截止为 `续期请求开始的单调时钟+返回实际TTL`，从不累加旧 TTL 或使用建议 increment 作为实际 TTL。业务 IO 最迟在 `min(原Action截止, 当前租约截止)-500ms` 结束。保留可识别的返回 renewable，但本执行不再续期。

锁定/drain 关闭 gate 后不再启动续期或业务 IO。已在途续期或业务在既有取消信号到来时停止；acquire 为捕获精确 ID 的有界响应接收继续由既有 supervisor 保护。停止业务后 supervisor 仍在原 Action 剩余清理预算内 exact revoke，无自动续期者、额外 acquire 或继续业务。

## 审计与错误

renewal_started 必须先于续期 IO 提交；提交失败不发送 renew，仍尝试 exact revoke，Authority 审计失败保持 fail-stop。renewed 记录固定 outcome/reason 和既有 execution/credential 身份，不含 ID/token/value/profile/provider response。续期响应失败、错配、超时、取消、结果审计失败统一进入 `UPSTREAM_INDETERMINATE`、`retryable=false`；不因已成功 revoke 推断未知续期没有发生。revoke 未确认或 revoke/terminal 审计失败仍不得交付业务成功。

## 验收边界

本地 Broker/Authority/UDS fixture 覆盖单次成功、无需/非 renewable、实际 TTL 小于建议、错 ID/重复字段/data/非法 TTL、原绝对截止、超时、开始/结果审计故障、锁定和取消、exact cleanup、反射与审计 canary。纯时间函数用显式 Instant 验证请求开始+实际 TTL 的保守计算。真实 Vault 现场需要独立账号/role/renew ACL 与 provider 验证权限；fixture 不能证明 provider 自然到期、最大 TTL 或级联撤销已完成。

官方合同核对于 2026-09-30，参见 [Vault renew/revoke API](https://developer.hashicorp.com/vault/api-docs/system/leases#renew-lease) 与 [租约 TTL 和续期语义](https://developer.hashicorp.com/vault/docs/concepts/lease#lease-durations-and-renewal)。increment 是续期时建议的剩余期限，provider 可缩短或忽略它；本实现只使用实际响应 TTL。
