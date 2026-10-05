# Rekey

Rekey 把密钥留在本机，让 Agent 调用你签署规则允许的操作。

当前源码为 **0.4.0-alpha.1 候选**，使用 vault26 / policy7。公开版本与下载以 [GitHub Releases](https://github.com/majiayu000/rekey/releases) 为准；源码检查不代表新版本已经发布或通过真机安装验收。0.3 vault 需要在新目录重建，旧目录不会迁移或覆盖。

## 开始使用

安装后的主线是添加密钥、签署连接规则、接入正常启动的 Agent：

```bash
rekey setup
rekey add github-pat
rekey connect claude-code --print
rekey connect claude-code
claude
```

`setup` 和 `add` 打开 macOS App，密码、密钥和规则审阅在管理界面完成。`connect` 在写入前展示配置与说明书差异；已有配置会备份，重复执行保持幂等。Codex 使用 `rekey connect codex`，然后正常启动 `codex`。本机调用不需要 capability 或令牌。

每个连接绑定一个密钥、一个固定 host 和规则。默认读允许、写审批、危险写拒绝；路径、方法、模型与预算由签名规则限定。调用方名称只用于记录和收紧权限，同一系统用户的程序可以伪造名称。

## 四个调用入口

- CLI：`rekey list`、`rekey describe OPERATION`、`rekey call OPERATION --parameter value`、`rekey http CONNECTION GET /path`；`--dry-run` 返回判定，不访问上游。
- MCP：`rekey-mcp` 提供发现、描述、调用、HTTP、访问请求和等待工具。Claude Code 插件位于 [plugins/rekey](plugins/rekey)。
- 本机 HTTP：默认 `http://127.0.0.1:7787/c/CONNECTION/`，SDK Key 填 `rekey`；普通 HTTP 与 Git smart HTTP 显式带 `Authorization: Bearer rekey`。daemon 注入真实认证头，Agent 只得到调用结果。端口与地址保存在私有 `service.json`。
- SSH agent：私钥留在 Rekey，标准 OpenSSH 通过 `ssh-agent.sock` 请求签名；规则按已验证的服务器公钥授权。未知或未绑定目标需要审批。

写审批可以一次放行，也可以对精确连接、规则和调用方开放时间窗，最长 8 小时；锁定或策略变更立即失效。被明确拒绝的规则不能通过审批放行。缺连接或权限时，Agent 用 `request_access` 描述需要的操作，用户在 App 处理；错误响应包含 `next`，引导 Agent 等待或重新调用。

## 开发卫生

App 可导入 `.env`，预览只显示变量名、目标连接和位置。确认后可将支持的 LLM Base URL 改为本机服务，保留 0600 备份。

```bash
rekey scan --staged
rekey scan --stdin
rekey connect claude-code --with-hooks
```

扫描以 vault 中的真实值做完整匹配，只输出连接、路径和位置。pre-commit 命中会阻止提交。锁定时默认提示并放行；`--strict` 阻止。每文件最多 10 MiB，每批最多 100 MiB；普通扫描忽略 `.git`、`node_modules`、构建输出等目录。

## OAuth 与临时凭据

Google、GitHub、Slack、Notion 使用用户自己的 OAuth client。授权和 refresh 在 daemon 内完成，源令牌不会交给 Agent。各供应商的 PKCE、回调、refresh 与 Notion 持久 access token 例外见 [SPEC](docs/superpowers/specs/2026-10-05-rekey-agent-call-model.md)。

AWS `credential_process`、EKS kubectl exec plugin 和 GitHub App 可以显式开启 **T1**：Agent 进程会收到临时凭据。目标 role / cluster / installation、仓库、权限和 TTL 均在签名规则中固定，调用方不能覆盖。

```bash
rekey aws-credentials CONNECTION
rekey kubectl-credentials CONNECTION
rekey github-token CONNECTION
```

T0 仅返回调用结果，T1 返回临时凭据；两者有不同的公开发现、界面和审计标注。

## 安装、恢复与边界

macOS 使用签名、公证的 pkg，Linux 使用归档；实际支持的发布平台见 [安装说明](docs/installation.md)。[macOS 构建说明](apps/macos/README.md)列出 Developer ID、双 provisioning profile、登录项和打包要求。

本机默认是同一系统用户的 G1 拓扑。加密、签名规则、出站限制、响应遮蔽和审计共同限制 Rekey 接口；它们不阻止同用户的恶意程序读取其他进程内存、伪造调用方或使用另一个网络客户端。真实 Keychain、Secure Enclave、Touch ID 和安装体验必须按设备证据验收，不能由单元测试推断。

旧 `run`、Profile、本机 capability 和隔离启动器已退出默认个人产品；企业代码保留在 `lab`，旧运行时验收脚本归档，编译检查不宣称企业部署通过。备份、恢复、轮换、审计提交失败关闭等 Authority 合同继续保留。

## 开发与验证

```bash
cargo check --workspace --all-targets
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

[0.4 SPEC](docs/superpowers/specs/2026-10-05-rekey-agent-call-model.md)、[实施记录](docs/superpowers/plans/2026-10-05-agent-call-implementation.md)、[功能事实矩阵](docs/product-foundation/feature-truth-matrix.md)和[威胁模型](docs/product-foundation/threat-model-v2.md)共同记录实现与验收状态。合成上游、真实供应商、真人系统认证和公开下载证据分开记录。
