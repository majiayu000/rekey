# Rekey

Rekey 把 API Key 留在你的电脑上。Agent（Claude Code、Codex 等）需要调用模型或服务时，请 Rekey 代为调用；Rekey 按你签署的规则放行，把结果交回 Agent，Agent 拿不到真实的 Key。

执行前持久审计，返回时检查凭据反射：上游响应里出现 Key 的原值或支持的可逆编码形式会被遮蔽。检查只覆盖这些明确支持的表示，不能阻止所有数据外泄或授权范围内的误用。

> 当前源码是未发布的 0.5 开发版；最新公开版本以 [GitHub Releases](https://github.com/majiayu000/rekey/releases) 为准。版本格式、保护等级等细节见[安全模型与术语](docs/security/README.md)。

## 快速开始（macOS）

1. **安装**：从 [GitHub Releases](https://github.com/majiayu000/rekey/releases) 下载签名的 `.pkg` 安装（也可以用随版本发布的 Homebrew cask，见[安装说明](docs/installation.md)）。
2. **打开 Rekey，创建保险库**：运行 `rekey setup` 或直接打开 Rekey App，设置密码并离线保存恢复密钥。
3. **添加 Key**：真实密钥用 App 的 Secure Enclave 个人模式：

   ```bash
   rekey add glm --app
   ```

   在 App 中粘贴 Key、填写允许的模型并签署规则。只想**测试/体验**时，可以用命令行一步完成的基础模式（不安全，见下方警告）：

   ```bash
   rekey add glm --model glm-5.3-flash
   ```

   按提示输入保险库密码、粘贴 Key。Rekey 会保存 Key 并生成一条连接规则：读请求直接放行，写请求要你批准，危险写入拒绝；LLM 只允许列出的模型，并带每日预算。

   （一步完成的 `rekey add` 属于当前源码；已发布的 0.4 安装版里，这条命令会打开 App，在 App 中粘贴 Key 并签署规则。）
4. **接入 Agent**：

   ```bash
   rekey connect claude-code
   ```

   先展示要改的配置，确认后写入（已有文件会备份）。Codex 用 `rekey connect codex`。
5. **正常使用 Agent**：直接运行 `claude` 或 `codex`。Agent 读数据时直接拿到结果；**要写入时**（例如创建 issue），Rekey App 会弹出通知，你批准一次或在一段时间内放行，拒绝则不会执行。

**测试时不想每次重启都输密码**：`rekey unlock --remember 7d`（最长 30 天）。它同样属于基础模式，只用于测试；`rekey lock --forget-remembered` 可取消。

命令行出错时会用中文提示原因和下一步；Agent 和脚本通过管道调用时仍得到 JSON（也可设置 `REKEY_OUTPUT=json` 强制 JSON）。

> **警告：基础模式（不带 `--app` 的 `rekey add`、`rekey unlock --remember`）仅限测试，不安全。** 基础模式的签名私钥（`~/.rekey/policy-signer-p256.p8`）和记住解锁的密钥（`remembered-unlock.key`）是同用户可读的文件。本机以你身份运行的任何程序——包括 AI Agent，尤其是跳过权限确认运行的 Agent——都能读到它们，从而自己批准访问请求和写操作、签出放宽的规则，甚至结合 `desktop-unlock.bin` 离线解密保险库。所以基础模式只用于开发和测试，不要存放需要保护的密钥；保护真实密钥请用 App 的 Secure Enclave 个人模式（`rekey add <预设> --app`）。同一个保险库第一次选定签名方式后不能互换，测试和真实使用请用不同的保险库。

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

AWS `credential_process`、EKS kubectl exec plugin 和 GitHub App 可以单独开启**临时凭据**：Agent 进程会收到短期有效的凭据。目标 role / cluster / installation、仓库、权限和 TTL 均在签名规则中固定，调用方不能覆盖。

```bash
rekey aws-credentials CONNECTION
rekey kubectl-credentials CONNECTION
rekey github-token CONNECTION
```

其他入口只返回调用结果；临时凭据入口在界面和审计中单独标注，详见[安全模型与术语](docs/security/README.md#调用结果与临时凭据)。

## 安装、恢复与边界

macOS 使用签名、公证的 pkg，Linux 使用归档；实际支持的发布平台见 [安装说明](docs/installation.md)。[macOS 构建说明](apps/macos/README.md)列出 Developer ID、双 provisioning profile、登录项和打包要求。

Rekey 与 Agent 运行在同一系统用户下。加密、签名规则、出站限制、响应遮蔽和审计约束的是 Rekey 自己的接口；它们不阻止同一用户下的恶意程序读取其他进程内存、冒充调用方或绕过 Rekey 直接联网。root 和恶意管理员不在保护范围内。保护等级、各版本数据格式、企业实验功能和验收边界见[安全模型与术语](docs/security/README.md)。

## 开发与验证

```bash
cargo check --workspace --all-targets
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace -- --test-threads=1
```

[0.4 SPEC](docs/superpowers/specs/2026-10-05-rekey-agent-call-model.md)、[实施记录](docs/superpowers/plans/2026-10-05-agent-call-implementation.md)、[功能事实矩阵](docs/product-foundation/feature-truth-matrix.md)和[威胁模型](docs/product-foundation/threat-model-v2.md)共同记录实现与验收状态。合成上游、真实供应商、真人系统认证和公开下载证据分开记录。
