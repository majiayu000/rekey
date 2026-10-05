---
description: Request a Rekey connection or permission without collecting credentials.
argument-hint: <provider-or-connection> <reason>
---

根据用户给出的参数 `$ARGUMENTS`，调用 Rekey MCP 工具 `request_access`，指定 provider 或 connection、需要的操作和理由。只请求权限，不收集密钥；用户在 Rekey App 中处理请求。显示请求 ID，随后调用 `await_access(request_id, timeout_s: 120)` 等待结果；返回 `GRANTED` 后显式重试原请求。
