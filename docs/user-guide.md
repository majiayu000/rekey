# Rekey 0.4 用户指南

本文对应 **0.4.0-alpha.1 候选版，尚未公开发布**。当前模型使用 vault/backup 格式 **26**、签名策略格式 **7**。0.3 的保险库和备份不兼容；请保留旧目录，在新目录重建。完整验收状态见[验收报告](evidence/agent-call-acceptance-2026-10-05.md)。

本机软件检查、真实 Codex 的合成上游链及 GitHub 读写分项已有通过证据；Claude 账号、真实 OAuth/云服务、正式设备交互与公开下载安装仍待验。以下命令描述当前实现的操作，不表示候选版已经完成发布验收。

Rekey 保存凭据，Agent 正常启动，在需要凭据时调用 Rekey。CLI、MCP、本机 HTTP 和 SSH agent 的本机调用不需要授权令牌；权限来自用户签署的 Connection / SSH / 临时凭据规则。HTTP 请求仍须带公开占位值 `rekey`，它只是请求标记。AWS、EKS 和 GitHub App 的 T1 派生入口会把临时凭据交给 Agent，使用前须单独签署开启。

## 首次使用

确认使用的二进制和目录：

```bash
rekey --version
rekey --help
```

macOS 安装版的首选入口是：

```bash
rekey setup
rekey add github-pat
```

在 App 中创建新的个人保险库、保存恢复密钥，添加 API Key，选择预设并审阅 Connection：凭据、固定 host、路径、读写规则和可选调用方限制。随后签署并激活策略。保存密钥本身不会授予调用权限；已有保险库先启动服务并解锁。个人签名使用 Secure Enclave，没有软件签名回退。新版真实设备上的系统认证次数与耗时仍待验。

需要独立目录的源码用户可在自己的终端中操作：

```bash
rekey --state-dir /absolute/path/rekey-04 init --mode personal
rekey --state-dir /absolute/path/rekey-04 serve
```

`serve` 在前台运行，启动后锁定。在另一个终端解锁同一目录，并在 App 中选择该目录完成凭据与规则签署：

```bash
rekey --state-dir /absolute/path/rekey-04 unlock
rekey --state-dir /absolute/path/rekey-04 status --passive
```

密码和 API Key 使用隐藏输入或显式 stdin，不能放进命令参数、环境变量、项目说明文件或 MCP 配置。恢复密钥应离线保存；它不是 Agent 的调用令牌。

## 接入 Agent

在项目目录先预览，再确认写入：

```bash
rekey --state-dir /absolute/path/rekey-04 connect claude-code --print
rekey --state-dir /absolute/path/rekey-04 connect claude-code
```

支持 `claude-code`、`codex`、`cursor`。指定项目目录：

```bash
rekey --state-dir /absolute/path/rekey-04 connect codex --project /absolute/path/project --print
rekey --state-dir /absolute/path/rekey-04 connect codex --project /absolute/path/project
```

命令更新受管 MCP 配置及 `CLAUDE.md` / `AGENTS.md` 的 Rekey 标记段，显示变更并要求确认，已有文件会保留私有备份。MCP、受管 CLI 说明及扫描钩子均绑定本次选择的 vault 绝对目录；更换目录后重新执行 `connect`。重复执行替换同一标记段，不写凭据或调用令牌。随后按客户端正常方式启动 Agent，让它先列出 Rekey 能力。

Claude Code 插件位于 [`plugins/rekey`](../plugins/rekey)，由仓库根目录的 marketplace 清单注册。先添加本地源码或解压后的发行目录，再安装：

```bash
claude plugin marketplace add /path/to/rekey --scope user
claude plugin install rekey --scope user
```

在项目目录将两条命令的 scope 都改为 `project` 可只为该项目启用。隔离配置下两种安装已通过，`rekey@rekey` 为 enabled，MCP 配置和 skill 已进入插件缓存；真实 Claude 对话仍因账号暂停未验收。

## 发现与调用

```bash
rekey list --json
rekey connection list
rekey describe github.list_issues
```

`list` 返回可用的公共能力，包括已签署的 T1 派生能力；不会返回密钥或 T1 根凭据 ID。`connection list` 是管理员编辑视图，返回完整签名编辑基线。操作是否可用由当前策略决定，不凭命令名称假定授权。

以下例子假定 App 已激活名为 `github` 的 GitHub PAT Connection，绑定相应仓库规则。替换公开的 owner / repo 参数：

```bash
rekey call github.list_issues --owner OWNER --repo REPO --dry-run
rekey call github.list_issues --owner OWNER --repo REPO
rekey call github.create_issue --owner OWNER --repo REPO --title 'Test from Rekey' --dry-run
```

`dry-run` 返回规范化路径、读写分类、命中规则与判定，不访问上游、不解密凭据、不消耗审批。确认后去掉 `--dry-run`。命名操作的参数使用 `--name value`；查询使用 `--query name=value`，额外公开请求头使用 `--header name:value`，正文可通过 `--body-file FILE` 传入。

通用 HTTP 入口使用同一套签名规则：

```bash
rekey http github GET /repos/OWNER/REPO/issues --query per_page=10 --dry-run
rekey http github POST /repos/OWNER/REPO/issues --json '{"title":"Test from Rekey"}' --dry-run
```

路径段必须是允许的 slug，不能用百分号编码、斜杠注入或 `..` 扩大授权。查询键、请求头与值也受规则约束。普通 POST 归写；只有签名预设明确声明的具体操作可按语义读处理。GraphQL mutation、歧义文档或解析失败归写。

## 审批与访问请求

默认规则为读允许、写审批、危险写拒绝；具体 Connection 可进一步收紧。命中审批时，CLI 默认等待 App 决定，再对同一个请求重试一次。`--no-wait` 立即返回审批信息。拒绝、取消、超时或未知结果后不要自动循环重试写操作。

App 显示完整请求后可批准一次、30 分钟或自定义时间窗，最长 8 小时。窗口绑定同一 Connection、规则、调用方和策略摘要，锁定或改策略后失效；不能覆盖 deny。SSH 未绑定目标和 git 签名不提供时间窗。

调用方显示用于记录和附加限制，不是认证边界。同一系统用户下的程序可以伪造标签，因此调用方规则只能收紧默认权限。

缺少 Connection 或权限时，Agent 可发起访问请求：

```bash
rekey request github --op github.list_issues --reason 'Read issues for this task'
rekey await REQUEST_ID --timeout 120
rekey await-unlock --timeout 120
```

在 App 中添加凭据并激活对应规则后，再批准访问请求；批准请求不能绕过签名授权。请求 10 分钟过期，用户可拒绝或屏蔽调用方。CLI 错误中的 `next` 指示下一步，Agent 应照该提示处理。

## 本机 HTTP 与 SDK

服务默认监听 `127.0.0.1:7787`；实际端口见所选保险库的 `service.json`。路由是 `/c/CONNECTION/UPSTREAM_PATH`。占位头必须是 `Authorization: Bearer rekey` 或 `x-api-key: rekey`；真实 Key 会被拒绝，不会转发。浏览器 Origin、异常 Host 和不允许的请求形态会被拒绝。

```bash
curl -H 'Authorization: Bearer rekey' \
  'http://127.0.0.1:7787/c/github/repos/OWNER/REPO/issues'
```

SDK 的 key 设置为公开占位值 `rekey`，base URL 指向相应 Connection：

| 预设 | 本机 base URL（默认端口，连接名仅示例） |
|---|---|
| Anthropic | `http://127.0.0.1:7787/c/anthropic` |
| OpenAI | `http://127.0.0.1:7787/c/openai/v1` |
| GLM Anthropic | `http://127.0.0.1:7787/c/glm/api/anthropic` |
| GLM Responses | `http://127.0.0.1:7787/c/glm-responses/api/v1` |

在 App 中明确签署允许的模型、单次输出上限和日预算后再使用 LLM。CLI 与 HTTP 共用预算。预算按已结算用量准入，在途并发可能超出；它不保证对抗本机状态回滚的费用封顶。流式响应未完成或安全检查失败时应视为失败，不能把收到部分正文当成完整成功。

## 导入 `.env` 与防泄漏

```bash
rekey import /absolute/path/project/.env --dry-run
rekey import /absolute/path/project/.env
```

CLI 只让 daemon 预览变量名、预设提示和未支持的行，不读取或显示变量值。第二条命令打开 App。用户选择后导入凭据，再审阅并签署 Connection；原文件默认不变。明确确认改写后，daemon 创建 mode-0600 备份、把选中的值替换成占位值并添加所需 base URL，再原子发布新文件。不要同时用编辑器或脚本修改该文件；元数据检查与 rename 之间不构成并发写入的原子比较交换。

```bash
rekey scan --staged
rekey scan /absolute/path/project/file
rekey --state-dir /absolute/path/rekey-04 connect claude-code --with-hooks
```

扫描使用保险库中完整秘密及支持的变体，结果仅含位置，不回显匹配内容。`--with-hooks` 安装受管 pre-commit 检查。扫描失败不等于文件安全；保险库锁定、超限或限速时应先处理错误。它不是对所有可能编码和历史提交的完整泄漏证明。

## SSH 与 Git

```bash
rekey ssh-agent status
rekey ssh-agent generate work-key
rekey --state-dir /absolute/path/rekey-04 connect codex --with-ssh --ssh-host github.com --print
rekey --state-dir /absolute/path/rekey-04 connect codex --with-ssh --ssh-host github.com
```

macOS 默认生成 Secure Enclave P-256 密钥；软件 Ed25519 / P-256 只能用显式 `--mode` 选择。生成密钥本身不启用 SSH：策略还须包含签名公钥及 host 规则，公钥也须按目标服务要求登记。在 App 的个人策略编辑中加载完整 SSH 集合，或直接生成新密钥，复制公钥到目标服务；登记独立核对过的 host 公钥，选择 Allow/Approve/Deny 和 git 签名判定。可粘贴标准 OpenSSH 公钥、known_hosts 条目或 base64 wire blob。既有 host 与 rule ID 会保留，生成草稿时 HTTP、SSH 与 T1 三组完整一起审阅和签署。撤销 SSH 连接不删除保险库里的私钥。已有签名 SSH 授权的配置使用 `<state-dir>/ssh-agent.sock` 的 `IdentityAgent`，私钥不交给 Agent。已验证 session-bind 按签名 host 规则判定；未知 host 或缺少绑定需要审批，明确 deny 不能用窗口绕过。真实 OpenSSH 向 GitHub 测试仓库 push 已通过，临时 deploy key 和 ref 已清理；这不代替 App 真机上的生成、签署和 Touch ID 验收。

Git smart HTTP 使用独立 `github-git` 预设，固定 `https://github.com`、owner 和完整 `repo.git`。`info/refs` 与 `git-upload-pack` 为读，`git-receive-pack` 为写；PAT 在 daemon 内转换为固定 Basic 认证。通过本机 HTTP 使用时也要配置公开请求标记，例如只对该 URL 设置 Git 的 `http.extraHeader=Authorization: Bearer rekey`。默认请求正文上限为 1 MiB，不宣称无限仓库传输。

## OAuth 与 T1

OAuth 通过 App 保存用户自己的 client、签署有限操作和 scope ceiling，再打开浏览器：

```bash
rekey add google-drive
rekey oauth login CONNECTION
```

支持 Google Drive / Gmail / Calendar、GitHub OAuth App、Slack 和 Notion 的有限操作。Google / GitHub 使用本机随机回调；Slack / Notion 需填写登记的固定本机回调。Notion 的权限来自 Portal capabilities，不是 OAuth 请求 scope。OAuth token 保留在 Rekey；真实 provider 登录与刷新仍待验。

T1 必须逐个签署开启，**Agent 进程会拿到临时值**：

```bash
rekey aws-credentials CONNECTION
rekey kubectl-credentials CONNECTION
rekey github-token CONNECTION
```

AWS 返回 `credential_process` JSON，固定 role / region / session policy，TTL 为 900–3600 秒；EKS 返回 `ExecCredential`，固定 cluster / region，AWS 验证窗口约 15 分钟，客户端过期时间提前到约 14 分钟；GitHub App 返回安装令牌，固定 installation、repository IDs 与 permission ceiling，TTL 上限 3600 秒。调用方不能覆盖签名目标。根密钥不会返回；T1 stdout 本身包含临时秘密，不应贴进日志或提交。

## 日常维护

```bash
rekey status --passive
rekey audit list --limit 50
rekey lock
rekey shutdown
```

锁定立即终止本机授权和审批窗口。关闭 App 不等于停止 daemon。`shutdown` 和备份等写操作需要新的逐次证明。备份、恢复、磁盘故障和格式升级的具体步骤见[运维手册](operations-runbook.md)。公开安装包、真实设备验收和发布状态见[候选发布说明](releases/v0.4.0-alpha.1.md)。
