---
name: rekey
description: Use Rekey to discover and call external APIs with credentials held by the local authority.
---

需要调用外部 API、git push 或使用任何凭据时，使用 Rekey：MCP 工具 `list_capabilities` / `call`，或命令 `rekey list` / `rekey call`。这些调用不会返回密钥。

不要向用户索要 API Key，不要读取或写入 .env 中的密钥，不要把密钥写进代码。Agent 自身的模型登录使用 Agent 自己的登录或订阅。

先调用 `list_capabilities`，再用 `describe` 查看具名操作的参数。例如：

```sh
rekey list --json
rekey describe github.create_issue
rekey call github.create_issue --owner example --repo project --title "Bug report" --dry-run
```

缺少权限或连接时调用 `request_access` 并说明理由，再用返回的请求 ID 调用 `await_access`；等到 `GRANTED` 后显式重试原请求，不要要求用户把 Key 交给 Agent。收到 `APPROVAL_REQUIRED` 时调用 `await_approval(request_id)`，然后按同一审批 ID 重试原请求；不要自动重试已完成或执行结果不确定的写操作。收到 `LOCKED` 时调用 `await_unlock` 后重试。

Agent 写的程序使用 `list_capabilities` 给出的本机服务地址和占位 Key `rekey`。T0 连接永不返回密钥；T1 派生连接会把短期派生凭证交给进程，必须明确区分。

本插件只引用已安装的 `rekey-mcp`。如果工具不可用，提示用户先安装并启动 Rekey，再照常启动 Claude Code；不需要 capability token，也不需要由 Rekey 启动 Agent。
