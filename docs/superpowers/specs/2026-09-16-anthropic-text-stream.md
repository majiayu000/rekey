# NET-07 最小 Anthropic 文本流合同

状态：用户已接受独立流式接口及失败后已检查前缀不可收回；本文先于实现冻结范围。

仅 `opaque-token` 凭证和显式 `text_stream: {model, max_tokens}` Action。可信 Admin 经 step-up 持久登记固定 `POST https://api.anthropic.com/v1/messages`、`x-api-key` 空前缀，model 为 1..128 字节 ASCII 名称，max_tokens 为 1..8192；固定版本头 2023-06-01、stream true。禁止额外请求/响应头。request/response body 上限和绝对 deadline 仍来自 Action。Agent 仅提交非空、有界 user/assistant 纯文本 messages；不接受 tools、thinking、系统提示或任意 provider 参数。旧 Execute 拒绝流式专用 Action，MCP 不暴露流式操作。

新增 Agent 操作 ExecuteTextStream，沿用 ExecuteMeta。响应为零或多 STREAM_CHUNK 后唯一 STREAM_TERMINAL，均绑定原始请求 ID、从零开始连续 sequence。terminal 有 completed/incomplete/failed；无 terminal、错 ID/序号、空 chunk、非法 UTF-8 或截断均失败。准入之前可返回原有空 ERROR；流内失败不转发上游错误内容。completed 仅在 end_turn、完整文本事件序列、HTTP EOF、全部 sealing 以及 execution.finished 审计成功后发送。max_tokens/refusal 等明确结束为 incomplete，其他协议/错误为 failed。已发送前缀不能代表成功或自动重试依据。CLI 增量写出并 flush，失败或 incomplete 非零退出。

真实 reqwest chunk 读取复用 DNS public-IP 校验、TLS/SNI、固定地址、redirect 禁止及 no_proxy。SSE 严格有界解析：仅 message_start、单个 text content block start/delta/stop、message_delta、message_stop 和 ping；未知输出类型失败。JSON escape 先解码，再拼接实际 Agent 文本检查。原始 SSE、错误、headers 均不转发。检查全部 header，并对原始 SSE 和文本投影分别进行现有有限 secret variants 检查。

增量检查保留 `3 * max_needle_len + 2` 原始字节窗口及边界上下文。现有 contains_secret 只有一层 percent decode（每输出字节最多消耗三输入字节）和长度不变 hex normalization，因此任何匹配跨度不超过 3*max_needle_len；多保留两字节消除未完整 percent escape。安全释放点对齐 UTF-8 边界，已检查的上下文保留在总量有界缓冲中以保证 decoding 的状态不因滑窗改变。这是有限编码合同，不检测任意变换/隐蔽信道。最长 needle 导致的必要延迟可使很短响应直到结束才释放。

复用同一 capability、策略参数与 approval、started audit、remote effect admission、绝对 deadline、runtime supervisor、drain/cancel 和终结审计。仅使用 opaque token，无租约/revoke 新路径。输出 mpsc 容量一，chunk 最多 16 KiB；慢消费者 deadline 后失败，断连关闭输出、runtime 继续收尾，不能 detach 持秘密的任务。SQLite 新增 Action 配置列，格式从 10 升级至 11，格式门禁在读取新列前拒绝旧 state/backup；不迁移或回填旧状态。

本地验收：真实 TLS + Agent UDS 在上游结束前收到已检查首片；秘密变体和 JSON escape/跨 delta 任意分割、后段 secret、缺事件/截断、流内 error、deadline、慢消费者、断连及审计故障。不得使用真实 provider/key 或把已缓冲结果分段冒充流式。仅上述 fixture 通过后记录证据，不声称实网验收。

## 本地验收记录（2026-09-16）

真实本地 TLS → production reqwest 分块读取 → Broker → Agent UDS 的 8 项测试通过，首片必须在 fixture 放行上游结束屏障前到达。4 项 projection/sealer 单测覆盖所有切分点、UTF-8、JSON escape、混合 LF/CRLF、全部末尾截断，以及 `%A`+`0` normalization 前瞻和双层 percent 输入的一层解码匹配。CLI 8 个协议情形、MCP manifest/projection 拒绝、v10 缺列格式门禁通过；原 buffered transport/execution/sealing 的 20 项定向回归通过。

Socket 接收内部事件及每次 frame 写出共享 admission 的绝对 deadline；到期关闭流，未发送 terminal 按失败处理。deadline 前已经进入 socket 的安全前缀无法收回。只有单个固定 text block 被投影；不支持 tools、thinking、多 provider、MCP 流式或租约型凭证。短于秘密检测保留窗口的响应可能直到结束才释放。本记录不声称真实 Anthropic 账号/网络验收、发布或整库回归。

CLI：`rekey --agent-socket /absolute/agent.sock execute-text-stream ACTION_ID@VERSION --capability - --body-file messages.json`；capability 从 stdin 读取，messages 文件形如 `{"messages":[{"role":"user","content":"hello"}]}`。Admin Action 必须显式配置 `text_stream.model` 与 `text_stream.max_tokens`；策略/批准仍绑定 Agent 原始 messages，Broker 固定加入 model/max_tokens/stream 和版本头。Action 请求字节上限同时约束 Agent 输入及规范化后的上游 JSON。成功文字到 stdout，完成提示到 stderr；failed/incomplete/EOF 非零退出。
