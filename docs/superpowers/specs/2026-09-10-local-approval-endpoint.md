# APR-08 本机独立审批端

用户选择本人审批、先仅在本机运行独立端。本切片实现一次、单人审批的离线终端签发工具。APR-08 的来源认证切片见 [approval-origin-authentication](2026-09-10-approval-origin-authentication.md)：操作者可以把 Broker 签名的 challenge 信封拷到自己控制的第二台机器上签发。这不是托管远程审批服务、通知收件箱或人员目录。现有 Broker challenge/grant 验证、会话绑定、用量扣减、失效和审计继续作为执行授权的唯一入口。

`rekey-approval-sign review REQUEST.json --policy POLICY.json --trust TRUST.json --action ACTION.json --approver-id UUID --origin-key HEX` 验证签名策略，按其现有 canonicalize/evaluate API 验证请求与已认证 challenge，展示完整固定 Action、请求、审批者与摘要。`sign` 使用相同参数并增加 `--reviewed-sha256 HEX --key-file KEY.der --output NEW_GRANT.json`，重新验证输入和有效期，只对已核对摘要签发现有 SignedApprovalGrant。不存在自动同意、后台续签或 Agent 可调用的审批 socket。

REQUEST 为严格 JSON 对象，包含 `challenge`（`rekey.approval.challenge.envelope.v1`）、`content_type`（可空）、`headers`（名称和值的数组对）、`body`（原始 JSON 文本或空字符串）。ACTION 是管理员从本地可信来源核对的完整 FixedHttpAction；POLICY 和 TRUST 也由操作者独立提供，不能从 Agent 提交的目录直接选择。Action 定义未被策略签名覆盖，本工具不能证明其来自 Broker。`--origin-key` 必须是操作者从本机 `rekey approval origin` 钉扎的 64 位小写 hex；未签名的 v1 challenge、错误 origin 或被改过的 inner challenge 均拒绝。信封只认证 Broker 发出的 challenge 字节，不认证 Action/policy/trust 文件或操作者意图。本切片不宣称同用户恶意进程隔离。

审批要求限定为 one-time、quorum=1、max_uses=1。核对 Action ID/version、resource/schema、完整参数摘要、策略版本/摘要/规则和审批者集合；展示请求仅作数据，JSON 控制字符与终端方向控制字符转义。签名摘要覆盖展示内容、选定审批者和可信 Action。私钥为当前用户拥有、无组/其他权限的普通 PKCS8 Ed25519 文件，拒绝符号链接；签名密钥必须匹配策略审批者。审批输出以独占创建的 0600 文件写入，不覆盖既有文件。

验收包括合法签名被既有 verifier/Broker 接受、正文错配、审阅后修改、错误密钥、过期拒绝、错误 origin、未签名 challenge、文件权限，以及既有 Broker 的重放/会话错配拒绝。测试使用合成身份与请求；不替用户批准真实业务操作。合并前需人工审查授权与密钥处理代码。

操作者步骤见 [user-guide 本机独立审批端](../../user-guide.md#local-independent-approval-endpoint)：钉扎 `rekey approval origin`，从本机 `rekey approval prepare` 取得信封，把原始请求正文写入 `approval-request.json`，用独立选择的 policy/trust/Action 与 origin hex 先 `review` 再 `sign`，并在 60 秒内对同一请求执行。
