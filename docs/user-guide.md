# Rekey 0.4 用户指南

本文对应 **2026-10-08 已公开预发布的 0.4.0-alpha.1**（GitHub prerelease）。当前源码为未发布的 0.5.0-alpha.1。每个版本线都需要新建保险库，不会迁移或覆盖旧的；请保留旧目录，在新目录重建。各版本的数据格式和保护等级见[安全模型与术语](security/README.md)。完整验收状态见[验收报告](evidence/agent-call-acceptance-2026-10-05.md)。

本机软件检查、真实 Codex 的合成上游链及 GitHub 读写分项已有通过证据；Claude 账号、真实 OAuth/云服务、正式设备交互与公开下载安装仍待验。以下命令描述当前实现的操作，不表示候选版已经完成发布验收。

Rekey 保存凭据，Agent 正常启动，在需要凭据时调用 Rekey。CLI、MCP、本机 HTTP 和 SSH agent 的本机调用不需要授权令牌；权限来自用户签署的 Connection / SSH / 临时凭据规则。HTTP 请求仍须带公开占位值 `rekey`，它只是请求标记。AWS、EKS 和 GitHub App 的临时凭据入口会把短期凭据交给 Agent，使用前须单独签署开启。

## 首次使用

确认使用的二进制和目录：

```bash
rekey --version
rekey --help
```

macOS 安装版（已发布的 0.4）的入口是：

```bash
rekey setup
rekey add glm
```

`setup` 在 App 中创建新的个人保险库并保存恢复密钥。**当前 0.5 开发版**在 macOS 默认目录且已安装 App 时，`rekey add <预设>` 会打开 App：保存或选择已有凭据，审阅完整连接规则，再系统认证签署并激活。CLI 的打开回执只表示已发起跳转，是否成功以 App 的激活结果为准。App 刚启动、仍在连接服务时收到的接入页面，会在连接完成后按同样的检查打开；若它在你提交上一个接入表单的检查期间打开，上一个表单不保存密钥，请在新页面重新填写。连接名、凭据 ID、模型白名单和有效期都会带入表单；用户仍须审阅确认。

App 提前检查已安装信任根对应的签名密钥。已有 Secure Enclave 密钥继续由硬件签名；已有基础模式 `policy-signer-p256.p8` 继续由随 App 安装的签名器使用，并明确显示软件保护等级。后者是当前用户 0600 文件，同用户进程可读。找不到匹配密钥时停止，不创建替代密钥或更换信任根。

**减少密码输入**：在 App 安全设置中选择 30 天密码复核周期，并用原密码启用系统认证。有效期内，日常界面解锁和规则激活可使用系统认证；每次敏感操作仍需确认。30 天不是所有管理操作的免确认期。修改密码、恢复因素或续期系统认证仍需原因素。界面锁定保留已签署的 Agent 规则；锁定整个保险库会撤销访问。

无 App、自定义目录或显式 `--stdin-secrets` 使用 CLI 基础模式，仍以原密码操作。CLI 的 `rekey unlock --remember 7d`（最长 30d）是另一种机制：0600 的 `remembered-unlock.key` 用于后台重启解锁，同用户可读，不等于 App 的受保护系统认证，也不能代替敏感操作证明。`rekey lock --forget-remembered` 可撤销此记住状态。这把密钥**只能用于解锁**：它不能批准写操作，也不能代替任何二次验证（明文查看、关机等）。2026-10-22 之前用 `--remember` 写下的文件不会自动降级，请重新执行一次 `rekey unlock --remember` 或 `rekey lock --forget-remembered`。

**不用 App 批准（基础模式）**：写操作进入审批后，先用 `rekey approval pending` 找到请求，用 `rekey approval review ID` 查看完整请求和 `review_sha256`，确认后执行 `rekey approval approve ID --review-sha256 HASH --password`，在隐藏输入里填保险库密码（脚本用 `--password-stdin`）；拒绝用 `reject`。连续输错会触发与解锁相同的限速。

常用选项：`--name` 设置连接名，`--credential-id` 复用已保存密钥，`--model` 可重复，`--valid-days` 设置规则有效期（默认 90 天）。`--app` 明确要求走 App，不能与 `--stdin-secrets` 合用。OAuth 的 client 参数在 App 表单中填写。取消或草案失败后，可在凭据来源中选择已保存条目继续，无需再次粘贴 Key。

需要独立目录的源码用户可在自己的终端中操作：

```bash
rekey --state-dir /absolute/path/rekey-dev init --mode personal
rekey --state-dir /absolute/path/rekey-dev serve
```

`serve` 在前台运行，启动后锁定。在另一个终端解锁同一目录，并在 App 中选择该目录完成凭据与规则签署：

```bash
rekey --state-dir /absolute/path/rekey-dev unlock
rekey --state-dir /absolute/path/rekey-dev status --passive
```

密码和 API Key 使用隐藏输入或显式 stdin，不能放进命令参数、环境变量、项目说明文件或 MCP 配置。恢复密钥应离线保存；它不是 Agent 的调用令牌。

## 接入 Agent

在项目目录先预览，再确认写入：

```bash
rekey connect claude-code --print
rekey connect claude-code
```

支持 `claude-code`、`codex`、`cursor`。指定项目目录：

```bash
rekey connect codex --project /absolute/path/project --print
rekey connect codex --project /absolute/path/project
```

命令更新受管 MCP 配置及 `CLAUDE.md` / `AGENTS.md` 的 Rekey 标记段，显示变更并要求确认，已有文件会保留私有备份。重复执行替换同一标记段，不写凭据或调用令牌。随后按客户端正常方式启动 Agent，让它先列出 Rekey 能力。

0.5 源码起，使用默认保险库（`~/.rekey`）时写入的文件不含本机路径：MCP 配置只有 `"command": "rekey-mcp"`，说明书里是普通的 `rekey` 命令，这两个文件可以随项目提交；扫描钩子同样使用普通的 `rekey`。使用其他目录时加 `--state-dir`：

```bash
rekey --state-dir /absolute/path/rekey-dev connect claude-code --print
```

这时 MCP 配置、说明书和扫描钩子都写入这个绝对目录，让 Agent 连到这一个保险库；预览会提示含本机绝对路径的文件不要提交。更换目录后重新执行 `connect`。已发布的 0.4 总是写入绝对目录。

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

`list` 返回可用的公共能力，包括已签署的 T1 派生能力；不会返回密钥或 T1 根凭据 ID。LLM 连接会列出签名的模型白名单与额度，文本输出末尾提示签名规则还有几天过期（不足 7 天时警告）。每个具名操作附带自己的读写判定（JSON 中的 `decisions`，文本里如 `github.create_issue  write=Approve`）；连接一行的 `read=` / `write=` 只是对根路径 `/` 的判定。`describe` 同时返回该 Connection 的签名规则、本调用方的附加规则、限额与过期时间，以及一组示例参数（`example_args`，都是占位值，如 `OWNER`、`REPO.git`，需要换成实际值；连接签名绑定的仓库等值不会出现在示例里）和该示例的判定与命中的规则；LLM 具名操作的 `model` 参数只接受白名单中的值。`connection list` 是管理员编辑视图，返回完整签名编辑基线。操作是否可用由当前策略决定，不凭命令名称假定授权；实际参数下的判定以 `--dry-run` 为准。

同一个操作名可能属于多个连接，例如同时添加了 `qwen` 与 `qwen-intl`，两者都有 `qwen.chat`。这时 `describe` 和 `call` 需要用 `--connection` 指定连接（MCP 工具传 `connection` 参数），否则返回 `INVALID_INPUT`，提示里会列出可选的连接名：

```bash
rekey describe qwen.chat --connection qwen-intl
rekey call qwen.chat --connection qwen-intl --model MODEL --dry-run
```

以下例子假定 App 已激活名为 `github` 的 GitHub PAT Connection，绑定相应仓库规则。替换公开的 owner / repo 参数：

```bash
rekey call github.list_issues --owner OWNER --repo REPO --dry-run
rekey call github.list_issues --owner OWNER --repo REPO
rekey call github.create_issue --owner OWNER --repo REPO --title 'Test from Rekey' --dry-run
```

`dry-run` 返回规范化路径、读写分类、命中规则与判定，不访问上游、不解密凭据、不消耗审批；请求头里会列出凭据注入的位置，值只是占位，例如 `authorization: Bearer «rekey:github»`。确认后去掉 `--dry-run`。命名操作的参数使用 `--name value`；查询使用 `--query name=value`，额外公开请求头使用 `--header name:value`，正文可通过 `--body-file FILE` 传入。`--connection`、`--dry-run`、`--no-wait`、`--approval` 是保留选项，不会当作操作参数。

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
rekey request --connection github --op github.create_issue --reason 'File the bug found in this task'
rekey await REQUEST_ID --timeout 120
rekey await-unlock --timeout 120
```

provider 可以是预设名（如 `github-pat`），也可以是预设家族，即预设名第一个 `-` 之前的部分：`github` 对应 `github-pat`、`github-git`、`github-oauth`，带上 `--op github.list_issues` 后只剩声明了该操作的 `github-pat` 与 `github-oauth`；`qwen` 对应四个地域变体。已有连接时用 `--connection` 指定连接名。操作名写完整名称（如 `github.list_issues`）。未知 provider 或没有预设声明该操作时立即返回 `INVALID_INPUT`，提示里列出可用的预设或操作；其他 API 可以请求 `generic-bearer` 或 `generic-header`。

在 App 中添加凭据并激活对应规则后，再批准访问请求；按 provider 的请求由任一候选预设的已启用连接满足，批准请求不能绕过签名授权。请求 10 分钟过期，过期后 `rekey await` 返回 `EXPIRED`；用户可拒绝（返回 `REJECTED`）或屏蔽调用方，屏蔽后该调用方的请求返回 `DENIED`，可在 App 中解除。同一调用方 1 分钟内最多发起 3 个请求，超出返回 `RATE_LIMITED`，提示里给出可以再次请求的 UTC 时间；格式不对的请求不占用这 3 个名额。访问请求与屏蔽列表只保存在内存中，`rekeyd` 重启后清空。创建、处理与屏蔽变更总会写入审计，但不记录理由文本；已激活签名策略时，这些审计行另外记录调用方标注、请求的连接或 provider 与操作路径。这些行不是调用，App 活动页不统计它们。CLI 错误输出单行 JSON，其中 `next` 指示下一步，Agent 应照该提示处理；`rekey request` 和 MCP `request_access` 的返回另含 `user_hint`，供 Agent 提醒用户打开 Rekey。0.5 源码起，在终端里直接运行时错误改为中文说明和建议命令，通过管道调用（Agent、脚本）或设置 `REKEY_OUTPUT=json` 时仍是 JSON；`init`、`serve`、`restore` 由 `rekeyd` 执行，它们的失败输出由 `rekeyd` 直接给出，不走这套格式。

App 运行时（包括窗口关闭、界面锁定或在后台）每 15 秒检查访问请求和本机审批。首次连接服务或首次出现请求时，App 请求系统通知权限，选择会保存，重启后保留；可在审批收件箱关闭或重新开启。允许通知时，每个新请求发一条带提示音、固定文案的系统通知，不含提供方、理由或任何密钥，点击只会打开收件箱，不会批准。macOS 默认的横幅约 5 秒后收起，错过时可在通知中心找到；想让它一直显示，到“系统设置 › 通知 › Rekey”把样式改为“提醒”。排查时运行 `/usr/bin/log show --last 30m --info --predicate 'subsystem == "com.starlight.rekey"'`，日志只含请求编号和系统通知设置。无论是否允许通知，Dock 图标角标都会显示待处理请求数。App 未运行时没有提醒。

## 本机 HTTP 与 SDK

服务默认监听 `127.0.0.1:7787`；实际端口见所选保险库的 `service.json`。每个保险库各用一个端口：端口已被另一个保险库或程序占用时，服务不会启动，`rekeyd` 报 `SERVICE_PORT_IN_USE` 并给出被占用的端口，0.5 开发版 App 会弹出“本机服务端口已被占用”，显示端口和该保险库 `service.json` 的完整路径；在该保险库目录的 `service.json` 写入空闲端口（如 `{"port":7788}`，权限 0600）后点“重试”或重新启动，并相应修改 SDK 的 base URL。App 不会自己改端口。路由是 `/c/CONNECTION/UPSTREAM_PATH`。占位头必须是 `Authorization: Bearer rekey` 或 `x-api-key: rekey`；真实 Key 会被拒绝，不会转发。浏览器 Origin、异常 Host 和不允许的请求形态会被拒绝。

```bash
curl -H 'Authorization: Bearer rekey' \
  'http://127.0.0.1:7787/c/github/repos/OWNER/REPO/issues'
```

服务自身拒绝请求时返回 JSON 错误（含 `code` 和 `next`）。503 表示暂时不可用：`LOCKED`（解锁后重试）、`AUTHORITY_BUSY`（同一连接最多 4 个在途调用，稍后重试）、`DRAINING`（服务正在停止）、`FAULTED`（审计写入失败后停止放行，需检查磁盘并重启）。403 表示规则、预算或请求内容不被允许，重试无效；400 / 404 是请求形态或路由错误。上游自己的状态码和已遮蔽正文原样返回。Rekey 只向上游请求未压缩的响应，SDK 自带的 `Accept-Encoding` 不会转发；上游仍返回压缩正文时按 502 `RESPONSE_BLOCKED` 拒绝，不转交任何内容。

写操作需要审批时返回 403 `APPROVAL_REQUIRED`，审批 ID 在 `approval.challenge_id`。这个审批属于发起 HTTP 请求的程序，`rekey approval await` 和 MCP `await_approval` 等不到它。用户在 App 收件箱（基础模式下用 `rekey approval approve`）批准后，把完全相同的请求（方法、路径、查询、请求头、正文都不变）再发一次，并加上请求头 `x-rekey-approval-challenge: <challenge_id>`：

```bash
curl -X POST -H 'Authorization: Bearer rekey' -H 'Content-Type: application/json' \
  -H 'x-rekey-approval-challenge: CHALLENGE_ID' \
  -d '{"title":"Test from Rekey"}' \
  'http://127.0.0.1:7787/c/github/repos/OWNER/REPO/issues'
```

这个头只用来关联审批，不是令牌，也不会转发给上游。批准前带头重发会再次返回同一个 `APPROVAL_REQUIRED`，不会执行；批准只能用一次，正文变了也不能用；不带头重发不会使用这次批准。

SDK 的 key 设置为公开占位值 `rekey`，base URL 指向相应 Connection：

| 预设 | 本机 base URL（默认端口，连接名仅示例） |
|---|---|
| Anthropic | `http://127.0.0.1:7787/c/anthropic` |
| OpenAI | `http://127.0.0.1:7787/c/openai/v1` |
| GLM Anthropic | `http://127.0.0.1:7787/c/glm/api/anthropic` |
| GLM Responses | `http://127.0.0.1:7787/c/glm-responses/api/v1` |
| DeepSeek | `http://127.0.0.1:7787/c/deepseek/v1` |
| Moonshot（Kimi，中国站 / 国际站 `moonshot-intl`） | `http://127.0.0.1:7787/c/moonshot/v1` |
| Qwen（百炼兼容模式；北京 `qwen`、新加坡 `qwen-intl`、弗吉尼亚 `qwen-us`、香港 `qwen-hk`） | `http://127.0.0.1:7787/c/qwen/compatible-mode/v1` |
| OpenRouter | `http://127.0.0.1:7787/c/openrouter/api/v1` |
| Gemini（OpenAI 兼容） | `http://127.0.0.1:7787/c/gemini/v1beta/openai` |

百炼和 Moonshot 的 Key 按地域签发、不能跨地域使用，请按 Key 所属地域选预设（连接名默认与预设同名）。DeepSeek、Moonshot、Qwen、OpenRouter 和 Gemini 预设只开放 Chat Completions 与模型列表（Qwen 的模型列表走原生 `/api/v1/models`），未声明的端点（例如 OpenRouter 的 `/api/v1/responses`）一律拒绝。DeepSeek 和 Gemini 的单次输出上限只认 `max_tokens`，带 `max_completion_tokens` 的请求会被拒绝；OpenRouter、Moonshot 和 Qwen 两者都接受，缺省时注入 `max_completion_tokens`（Qwen 思考模型只有它同时限制思维链）。Stripe 预设只读：固定 `Stripe-Version`，只允许余额、客户、扣款和 PaymentIntent 的查询，写入和删除一律拒绝（Stripe 写请求要求表单编码，Connection 操作只发送 JSON）。

在 App 中明确签署允许的模型、单次输出上限和日预算后再使用 LLM。CLI 与 HTTP 共用预算。预算按已结算用量准入，在途并发可能超出；它不保证对抗本机状态回滚的费用封顶。流式响应未完成或安全检查失败时应视为失败，不能把收到部分正文当成完整成功。

## 导入 `.env` 与防泄漏

```bash
rekey import /absolute/path/project/.env --dry-run
rekey import /absolute/path/project/.env
```

CLI 只让 daemon 预览变量名、识别结果和未支持的行，不读取或显示变量值。AWS 密钥、数据库或消息队列连接串和口令（如 `*_PASSWORD`）无法经本机服务代理：预览在 `unsupported_protocol` 中写明原因（`aws`、`database`、`password`），App 显示为“未迁移：协议不支持代理”；它们不能导入或改写，原值留在文件中。第二条命令打开 App：逐项选择导入、跳过或标记为非密钥，导入凭据后审阅并签署 Connection，策略有效期默认沿用当前已签署的策略；原文件默认不变。明确确认改写后，daemon 创建 mode-0600 备份、把选中的值替换成 `rekey` 占位值并写入 base URL（默认变量名去掉 `_API_KEY`、`_AUTH_TOKEN`、`_KEY` 或 `_TOKEN` 后缀，例如 `OPENAI_API_KEY` 对应 `OPENAI_BASE_URL`），再原子发布新文件。文件里已有这个变量时（例如兼容服务商常用的 `OPENAI_BASE_URL`），即使它选了跳过或非密钥，这一行也会被换成本机服务地址，原值只留在备份中；审阅页逐行标出，回执列为“已替换为本机服务地址”。要保留原行，请在审阅页改用其他变量名；若原地址指向兼容服务商，请确认所选预设与它一致。备份含原始密钥：回执会说明 git 是否忽略它，确认替换无误后请删除，或确认它已在 `.gitignore` 中。没装开发者工具（Command Line Tools 或 Xcode）的 Mac 上不运行系统自带的 git，以免弹出安装对话框，回执显示“未能确认 git 是否忽略它”。不要同时用编辑器或脚本修改该文件；元数据检查与 rename 之间不构成并发写入的原子比较交换。

```bash
rekey scan --staged
rekey scan /absolute/path/project/file
rekey hooks install --print
rekey hooks install
```

扫描用保险库中的完整密钥及支持的编码变体（原始、base64、hex、percent、JSON 转义）做精确匹配，结果只有连接名、路径和行列，不回显匹配内容；部分片段不算命中。

- **扫描范围**：生效签名规则中已启用的 Connection、SSH 密钥和临时凭据授权所引用的凭据。禁用的 Connection、只导入还没签署规则的凭据不参与。引用的凭据已吊销或不存在时跳过，并警告"签名规则引用的 N 个凭据不可用"，其余照常扫描。
- **扫描哪些文件**：`--staged` 只读暂存区；不带参数时扫描当前仓库里 Git 跟踪的文件和未被 ignore 规则排除的新文件（`node_modules`、构建输出只有被 ignore 时才跳过）；显式给出的目录会递归扫描其中所有普通文件，包括 `.git` 和 `node_modules`，只跳过符号链接。单文件 10 MiB，单次 100 MiB。
- **额度**：同一系统用户每分钟共享 600 MiB 的扫描额度，换调用方或改程序名不会重置；超出返回 `RATE_LIMITED`，并给出重置时间。
- **pre-commit 钩子**：`rekey hooks install`（与 `connect --with-hooks` 相同）安装受管 pre-commit 检查：先预览，确认后写入，并备份原钩子。钩子运行 `rekey scan --staged`（非默认保险库目录时带 `--state-dir`）。已有钩子不会被覆盖：sh、bash、zsh 等 shell 钩子在第一行之后插入扫描，即使原钩子以 `exit` 或 `exec` 结束，扫描也先执行；Python 等其他钩子原样改名为同目录的 `pre-commit.rekey-chained`，由 Rekey 的包装脚本在扫描通过后以相同参数和输入运行。`rekey hooks uninstall` 恢复原钩子。命中总是阻止提交，终端里每条命中显示"检测到 <连接> 的密钥出现在 <路径>:<行>；请改用 rekey call 或本机服务地址"。Rekey 未运行、保险库锁定、没有生效（或已过期）的签名规则、额度用完时，钩子打印警告并放行；超过 10 MiB 的暂存文件被跳过并警告，其余照常扫描。要在这些情况下也阻止提交，把钩子里的命令改成 `scan --staged --strict`。

扫描失败或被跳过不等于文件安全；它也不是对所有可能编码和历史提交的完整泄漏证明。

### Claude Code 工具输出扫描（示例，不自动安装）

PostToolUse hook 在工具执行后运行，可以把它收到的 JSON（含工具输入和输出）原样交给 `rekey scan --stdin`。下面的脚本在命中时用 `updatedToolOutput` 把 Bash 输出换成占位文本，Claude 收到的是替换后的内容；hook 的任何输出都不含密钥值。工具已经执行，原输出仍可能留在 Claude Code 的本地记录或遥测中。保存为 `/absolute/path/rekey-scan-output.sh` 并 `chmod 700`：

```sh
#!/bin/sh
# Claude Code PostToolUse hook: scan the hook input (tool input and output).
findings=$(rekey scan --stdin)
case $? in
0) exit 0 ;;
esac
case "$findings" in
*'"connection"'*)
  cat <<'EOF'
{"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"Rekey 在这次命令输出里检测到已保存的密钥，输出已被替换。不要复述、保存或使用密钥；调用服务请改用 rekey call 或本机服务地址。","updatedToolOutput":{"stdout":"[Rekey 已隐藏这次输出：其中含有已保存的密钥]","stderr":"","interrupted":false,"isImage":false}}}
EOF
  exit 0 ;;
esac
echo "Rekey 没有扫描这次工具输出（保险库锁定、额度用完、Rekey 未运行或输出超过 10 MiB，见上面的错误）。" >&2
exit 1
```

在项目的 `.claude/settings.json` 中登记：

```json
{
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          { "type": "command", "command": "/absolute/path/rekey-scan-output.sh" }
        ]
      }
    ]
  }
}
```

- 自定义保险库目录时，把脚本里的命令改成 `rekey --state-dir /absolute/path/rekey-dev scan --stdin`。
- 保险库锁定、额度用完（`RATE_LIMITED`，错误里有重置时间）、Rekey 未运行或输入超过 10 MiB 时，`rekey scan --stdin` 以错误退出，脚本 `exit 1`：Claude Code 把它当作非阻断的 hook 错误显示给你，Claude 照常看到原输出，这次输出没有经过检查。想要"不能扫描就不给看"，把最后两行换成命中分支里的替换输出。
- `updatedToolOutput` 必须符合工具的输出结构，上面的结构只适用于 Bash。其他工具（如 Read、MCP 工具）可以只输出 `additionalContext` 提示，Claude 仍会看到原输出。
- 每次扫描都计入每分钟 600 MiB 的额度，与 pre-commit 钩子共用。

## SSH 与 Git

```bash
rekey ssh-agent status
rekey ssh-agent generate work-key
rekey --state-dir /absolute/path/rekey-dev connect codex --with-ssh --ssh-host github.com --print
rekey --state-dir /absolute/path/rekey-dev connect codex --with-ssh --ssh-host github.com
```

`--with-ssh` 只为 `--ssh-host` 列出的具体主机（可重复，不接受通配符）在 `~/.ssh/config` 开头写入指向 `<state-dir>/ssh-agent.sock` 的 `IdentityAgent`，并以 `Match all` 结束这一段，文件里原有的全局设置（如 `Include`、`IdentityFile`）照旧对所有主机生效。改动前同样预览、确认并备份；再次执行替换这一段。

macOS 默认生成 Secure Enclave P-256 密钥；软件 Ed25519 / P-256 只能用显式 `--mode` 选择。生成密钥本身不启用 SSH：策略还须包含签名公钥及 host 规则，公钥也须按目标服务要求登记。在 App 的个人策略编辑中加载完整 SSH 集合，或直接生成新密钥，复制公钥到目标服务；登记独立核对过的 host 公钥，选择 Allow/Approve/Deny 和 git 签名判定（新生成密钥的 git 签名默认允许）。可粘贴标准 OpenSSH 公钥、known_hosts 条目或 base64 wire blob。既有 host 与 rule ID 会保留，生成草稿时 HTTP、SSH 与临时凭据三组规则完整一起审阅和签署。撤销 SSH 连接不删除保险库里的私钥。已有签名 SSH 授权的配置使用 `<state-dir>/ssh-agent.sock` 的 `IdentityAgent`，私钥不交给 Agent。已验证 session-bind 按签名 host 规则判定；未知 host 或缺少绑定需要审批，明确 deny 不能用窗口绕过。真实 OpenSSH 向 GitHub 测试仓库 push 已通过，临时 deploy key 和 ref 已清理；这不代替 App 真机上的生成、签署和 Touch ID 验收。

Git smart HTTP 使用独立 `github-git` 预设，固定 `https://github.com`、owner 和完整 `repo.git`。`info/refs` 与 `git-upload-pack` 为读，`git-receive-pack` 为写（默认需要审批）；PAT 在 daemon 内转换为固定 Basic 认证。通过本机 HTTP 使用时，把该仓库的地址改写到本机服务，并只对本机服务地址配置公开请求标记（`github-git` 换成你签署的连接名，端口见 `service.json`）：

```bash
git config --global url."http://127.0.0.1:7787/c/github-git/OWNER/REPO.git".insteadOf "https://github.com/OWNER/REPO.git"
git config --global http."http://127.0.0.1:7787/c/github-git/".extraHeader "Authorization: Bearer rekey"
```

之后照常对 `https://github.com/OWNER/REPO.git`（带 `.git`）执行 `git clone`、`git fetch`、`git push`；连接只放行签名的 owner / repo，其他 GitHub 仓库不受影响。git 默认发出的 `User-Agent`、`Accept`、`Accept-Language`、`Pragma` 由本机服务剥除；`Git-Protocol`（协议 v2）是 `github-git` 签名允许的头，原样转发；git 自动压缩的请求正文（`Content-Encoding: gzip`）在判定前解码一次，上游收到未压缩正文。默认请求正文上限为 1 MiB（按解码后计），超过会被拒绝，不宣称无限仓库传输，大推送请改用 SSH。2026-11-17 之前签署的 `github-git` 连接不允许 `Git-Protocol`，git 会被拒绝：重新签署该连接，或临时用 `git -c protocol.version=0`。

## OAuth 与临时凭据

OAuth 通过 App 保存用户自己的 client、签署有限操作和 scope ceiling，再打开浏览器：

```bash
rekey add google-drive
rekey oauth login CONNECTION
```

支持 Google Drive / Gmail / Calendar、GitHub OAuth App、Slack 和 Notion 的有限操作。Google / GitHub 使用本机随机回调；Slack / Notion 需填写登记的固定本机回调。Notion 的权限来自 Portal capabilities，不是 OAuth 请求 scope。OAuth token 保留在 Rekey；真实 provider 登录与刷新仍待验。提供方撤销授权或拒绝刷新（invalid_grant）时，调用返回 `NEEDS_REAUTH`，App 活动页显示“需重新授权”，可直接打开浏览器重新授权；网络或服务端错误保留授权，不显示此提示。该提示取自当日（UTC）的审计记录。

临时凭据入口必须逐个签署开启，**Agent 进程会拿到短期有效的凭据**（安全模型里称为 T1，见[安全模型与术语](security/README.md#调用结果与临时凭据)）：

```bash
rekey aws-credentials CONNECTION
rekey kubectl-credentials CONNECTION
rekey github-token CONNECTION
```

AWS 返回 `credential_process` JSON，固定 role / region / session policy，TTL 为 900–3600 秒；EKS 返回 `ExecCredential`，固定 cluster / region，AWS 验证窗口约 15 分钟，客户端过期时间提前到约 14 分钟；GitHub App 返回安装令牌，固定 installation、repository IDs 与 permission ceiling，TTL 上限 3600 秒。调用方不能覆盖签名目标。根密钥不会返回；这些命令的 stdout 本身包含临时秘密，不应贴进日志或提交。

授权为 approve 时，三个命令与 `rekey call` 一样默认等待本机批准，最长 120 秒；批准后用同一审批 ID 重试一次，拒绝或超时则返回 `APPROVAL_REQUIRED`，不会签发。因此 `credential_process` 和 kubectl exec plugin 的固定命令行无需改动。等待提示只在终端的 stderr 显示，stdout 仍只有凭证；`--no-wait` 立即返回。

## 日常维护

```bash
rekey status --passive
rekey audit list --limit 50
rekey lock
rekey shutdown
```

锁定立即终止本机授权和审批窗口。关闭 App 不等于停止 daemon。`shutdown` 和备份等写操作需要新的逐次证明。备份、恢复、磁盘故障和格式升级的具体步骤见[运维手册](operations-runbook.md)。公开安装包、真实设备验收和发布状态见[候选发布说明](releases/v0.4.0-alpha.1.md)。

### 0.5 开发候选：状态标签与启动失败

`rekey status` 的 `protection_level` 是当前保护等级：锁定且没有会话为 `L0`，解锁为 `L1-dev`，未知或故障为 `null`。`peer_security` 只说明服务签名是否已校验（`verified_signature` / `unverified`），不是等级。

服务启动失败时，`rekeyd` 在该保险库目录留下 `startup-failure.json`：错误码、修复提示、被占用的端口和时间，不含密钥，启动成功后自动删除。App 连接失败并尝试启动服务后只读取这份记录，按原因提示：

- 端口被占用：按上文修改 `service.json` 后点“重试”。
- `UNSUPPORTED_VAULT_LAYOUT` / `UNSUPPORTED_FORMAT_VERSION`：目录来自其他版本线（例如 0.4）。保留旧目录和备份，在左侧“个人工作区”选择一个新的空目录，创建保险库后重新添加密钥。App 不读取、迁移或覆盖旧库；恢复旧备份时给出同样的提示。
- 其他错误：显示错误码，修正后重试。

目录权限过宽等在服务拿到锁之前发生的失败不会留下记录。自定义目录的服务由 App 直接启动，App 显示服务退出时的原始输出；默认目录的服务作为登录项（SMAppService）启动，App 拿不到退出输出，只显示连接错误。两种情况都可以在终端运行 `rekeyd serve`（自定义目录加 `--state-dir <目录>`）查看原因。

保存短于 16 字节的凭据时，CLI 和 App 会提示：结果遮蔽对这类密钥的嵌入编码检测有限，建议改用服务商提供的完整密钥。保存本身照常完成。

### 0.5 开发候选：管理界面锁定

App 默认在电脑空闲五分钟或锁屏、休眠、切换用户时锁定管理界面；打开窗口仍需显式认证。设置可调整空闲阈值和 1/7/30 天系统认证期限，或要求每次输入密码。保存设置会撤销旧授权。用密码解锁并启用系统认证时，界面在新授权保存后才打开；其间锁定会撤销这次登录和刚签发的授权。界面锁定后 Agent 继续工作；“锁定整个保险库”才撤销 Agent 授权。若服务端会话撤销未确认，先用界面的重试完成撤销再解锁。此功能属于 0.5 源码候选，不代表已安装 App 已更新或真机系统认证已验收。
