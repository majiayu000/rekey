# Rekey v2 北极星与定位

## 一句话目标

Rekey 是本地 Credential Authority。它让不可信 AI Agent 只能执行管理员预先注册的动作，
而不能读取、导出或自行携带真实凭据。

## 要解决的问题

把 API token 放进 Agent 的参数、环境变量、配置文件或通用代理，会同时授予“使用凭据”和
“取得凭据”两种能力。Agent 一旦被提示注入、依赖投毒或工具误导，凭据就可能被复制到日志、
响应、子进程或任意网络目的地。

Rekey 的产品边界是把这两种能力拆开：管理员持有凭据和动作定义权，Agent 只持有短期、
限动作、限次数的 capability，并只能调用固定动作。

## 不变承诺

1. Agent API 不提供 get、read 或 export secret。
2. Agent 不能选择 upstream origin、HTTP method、path、认证头或 redirect。
3. 凭据不进入 argv、环境变量、JSON metadata、日志或审计字段。
4. 审计提交、策略求值、上游筛选或响应封印失败时，请求显式失败。
5. 默认部署只声明 G1 同用户本地边界；G2 仅指通过攻击脚本验证的 Linux
   container/namespace 参考拓扑。

## 当前目标用户与场景

- 单机开发者或自动化主机上的 AI coding agent。
- 使用固定 HTTPS API 动作，例如在指定仓库创建 GitHub issue。
- 管理员可以在本机交互完成初始化、解锁、凭据、动作、策略和 session 管理。

## 明确非目标

Rekey v2 不做 MITM、系统 CA、透明代理、任意 HTTP 转发、Dashboard、通用密码管理器、
多租户控制面、SSO/SCIM、HA、多区域或 Windows 支持，也不读取或迁移 v1 vault。

## 成功标准

功能完成不等于安全发布。公开安全声明前必须同时满足：

- [功能真值矩阵](feature-truth-matrix.md)中的对应自动化证据通过；
- 独立人工审查覆盖密码学、IPC、审计与失败语义；
- systemd required-job 和真实 GitHub E2E 等外部证据不再缺失；
- 文档声明不超过已验证的 G1/G2 边界。

规范性实现细节以
[Credential Authority v2 Foundation](../superpowers/specs/2026-08-28-credential-authority-v2-foundation.md)
为准。
