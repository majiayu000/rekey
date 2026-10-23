# 竞品卡：AgentSecrets（The-17）

lane：peer-kontext-agentsecrets · 访问日期均为 2026-10-22 · 视角：个人开发者用户

**一句话结论**：AgentSecrets 是这一类里功能面最接近 Rekey 的开源产品：Agent 只引用 Key 名，由代理在传输层注入；默认 allowlist 为空，所以默认拒绝；可按 Key 设置 `request_permission` 审批；会对响应做脱敏，也有 SSRF 防护。但个人用户上手门槛很高：每条调用路径都要求先注册账号（官方云或自托管服务器），还会自动下载第二个二进制 keychain-auth，注册一个 LaunchAgent，可能要 sudo，并写入登录钥匙串。官方没有 Claude Code / Codex 的接入页。本轮按规则不建账号、不碰钥匙串，所以 H1/H2/A2–A4 没能实测，只给出 E2/E3 结论。

## 基本信息

| 项 | 值 | 证据 |
|---|---|---|
| 链接 | https://github.com/The-17/agentsecrets（另有 `agentsecrets-server`、`agentsecrets-sdk`、`keychain-auth` 等仓库） | `gh search repos` · E2 |
| 类别 | 本机凭据代理（call / HTTP proxy / env 注入 / MCP），加云端同步、团队工作区和审计链 | README · E2 |
| 固定版本 | 源码 `main@be53766186fd43539d8768c0bae9423881609635`（2026-10-18）。实测二进制是官方 release `v3.3.6` darwin_arm64，checksums.txt 校验 OK | trace-help.txt · E4 |
| 许可 | MIT | GitHub API |
| 活跃度 | 190★（上轮 181）、15 fork、1 个 open issue。32 个 release，v3.3.x 在 9 月底到 10 月 18 日之间密集发布。贡献几乎全来自一人（SteppaCodes 151 commit） | `gh api` 2026-10-22 · E2 |
| 定价 | 官网和 README 都**没有公开定价**。CLI 默认连官方服务器 `api.agentsecrets.tech`，自托管服务器开源 | https://agentsecrets.tech/ 首页文本检索不到 price/free · E2 |
| 定位 | “Zero-Knowledge Credential Infrastructure for AI Agents, Humans, and Teams” | README L1–5 |

## 当前版本与近期变化

- v3.3.6（2026-10-18）：修复 `--query/--body-field/--form-field` 的目标名被 Go 规范化成首字母大写的问题，修复 `--body` 默认不带 Content-Type 的问题。对应 issue #9：https://github.com/The-17/agentsecrets/issues/9
- v3.3.5（2026-10-13）：修复 Cursor 下 `mcp serve` 找不到项目的问题，见 issue #8。
- v3.2.0：开源服务器，可以自托管，是对 #5 “Local mode, no login” 的回应。但 CLI 仍然要求登录某个服务器。
- v1.1.3 引入 keychain-auth 守护进程（按二进制哈希授权访问钥匙串）。升级后曾导致所有命令报错，见 issue #6。

## 能否装起来

能装，但只能实测 help 面。官方 release 二进制装到临时目录，`--version`、`--help`、`help <cmd>` 都正常（E4，见 trace-help.txt），而且临时 HOME 下没有写入任何文件。**任何非 help 命令都会触发联网更新检查和遥测**（root.go L110–152 @be53766）。`call/secrets/workspace/project/agent` 的前置中间件要求 keychain-auth 守护进程和登录态（root.go L191–203：https://github.com/The-17/agentsecrets/blob/be53766186fd43539d8768c0bae9423881609635/cmd/agentsecrets/commands/root.go#L191 ）。由于 init 必须“Create a new account / Login”（init.go L134），这里停止，标记为“需账号，未实测”。

## H1 / H2（人，E2 + E3，需账号未实测）

| 项 | 结果 |
|---|---|
| H1 命令数 | **6 条**：`brew install The-17/tap/agentsecrets` → `agentsecrets init` → `project create my-app` → `secrets set KEY=…` → `workspace allowlist add <host>` → `call --url … --bearer KEY`。另有 `mcp install` 或 `proxy start` 用于接 Agent。来源：docs/QUICKSTART.md @be53766（存档 `doc-quickstart-be53766.md`）和 README Quick Start |
| init 内的交互和隐藏步骤 | 4 个交互选择：服务器选 Cloud 还是 Self-Hosted、存储模式（keychain 或 .env）、注册还是登录、账号信息。首次运行还会**从 GitHub 自动下载 keychain-auth 二进制**（pkg/keychainauth/setup.go L378），用 `launchctl` 注册 LaunchAgent（L720–733），注册二进制时可能需要 `sudo`（L602–636），并往当前仓库写 `.agentsecrets/` 和 `.agent/workflows/agentsecrets.md` |
| 新概念（列名词） | 账号、服务器（Cloud/自托管）、存储模式、keychain-auth 守护进程、workspace、project、environment（默认 development）、Key 名、域名 allowlist、注入方式（bearer/header/query/basic/body-field/form-field 共 6 种）。共 **10 个**。可选概念还有 agent identity/token、secret policy（`request_permission`）、proxy、env、MCP |
| 墙钟 | 未测（需账号） |
| H2 加 GitHub token | 3 条：`secrets set GITHUB_TOKEN=…` → `workspace allowlist add api.github.com` → `call --url https://api.github.com/user --bearer GITHUB_TOKEN`。E2 |
| httpbin 可比性 | 理论上可比：`call --url` 接受任意 URL，只要域名在 allowlist 里。但对 loopback 和私网 IP 会做 SSRF 拦截（engine.go L255），httpbin.org 是公网，不受影响。E3 |
| 报错原文（E3，源码字符串） | allowlist 为空时：“Your workspace allowlist is empty. No credential injections are allowed until you add at least one domain. Run: agentsecrets workspace allowlist add <domain>”（engine.go L658）。域名不在 allowlist 时：“%s is not in your workspace allowlist. To authorize it, run: agentsecrets workspace allowlist add %s”（L672）。两条报错都给出了下一步命令 |

## A1–A4（Agent）

驱动偏差：`command claude -p` 返回 OAuth expired（原文见 `eval/agent/raw/agentsecrets/_driver-claude-p-failure.json`），改用 Claude Code 子代理（sonnet），只放行 `agentsecrets help…`。

| 任务 | 结果 | raw |
|---|---|---|
| A1 | **3/3 通过**（pass@1=1，pass^3=1）。三次都正确判断“当前没有可确认的 host，需要先 init/login、建 project、set-secret、add-allowlist”，没有编造。但三次都**没能**从 help 确认 allowlist 默认拒绝，因为 help 没写这一点；也都没提到 keychain-auth 和 sudo 这一步 | `eval/agent/raw/agentsecrets/A1-k{1,2,3}.json` |
| A2 读调用 | 不可比：需账号和钥匙串，未执行 | `A2-not-run.json` |
| A3 写调用审批 | 不可比，未执行。E3：审批是**按 Key 主动开启**的。用 `secrets policy set KEY --rule api.x.com:POST=request_permission` 设置后，命中的请求会在 proxy 终端提示，或用 `agentsecrets proxy approve KEY POST domain` 批准，最长等 5 分钟（engine.go L685–740：https://github.com/The-17/agentsecrets/blob/be53766186fd43539d8768c0bae9423881609635/pkg/proxy/engine.go#L685 ；proxy.go L70）。默认不审批写操作 | `A3-not-run.json` |
| A4 未授权 host | 不可比，未执行。E3：会被 allowlist 拦下，报错带修复命令（见上），并写一条 blocked 审计。MCP 提供 `get_blocked_requests` 和 `check_domain` 工具（tools_read.go L175/L221），Agent 能自己查为什么被拒 | `A4-not-run.json` |

## 怎么接入 Claude Code / Codex

- 官方 `mcp install` **只支持 Claude Desktop、Cursor 和 OpenClaw**（mcp.go L43–53）。文档的 “Connect AI Tools” 栏目也没有 Claude Code 或 Codex 页面，`https://docs.agentsecrets.tech/integrations/claude-code` 返回 404。这条是反向检索，2026-10-22 · E2
- 可行做法（AI 推断，未实测）：①手动执行 `claude mcp add agentsecrets -- agentsecrets mcp serve --project-dir <repo>`；②让 Agent 通过 Bash 调用 `agentsecrets call`，init 写入的 `.agent/workflows/agentsecrets.md` 会教 Agent 怎么用。Codex 同理，需要手动配置 MCP。
- 文档与实现漂移：help 写的 MCP 工具是 “api_call and list_secrets”（mcp.go L21），实际工具名是 `list_keys`（tools_read.go L67）。#8 里维护者也承认 “updated our documentation ahead of that release by mistake”。

## 功能三层核验

| 功能 | 宣称 | 源码（E3） | 实测 |
|---|---|---|---|
| Agent 看不到 Key | 宣称 zero-knowledge，没有 get() | MCP 和 call 不返回值；`redactSecretFromResponse` 会脱敏回显（engine.go L84） | 未测（需账号） |
| 默认拒绝 | 宣称有 allowlist | allowlist 为空时拒绝所有注入（L657–660） | 未测 |
| 写操作审批 | 宣称 “interactive approval flow” | 按 Key 的 `request_permission`，默认 action 是 deny，不是审批 | 未测 |
| SSRF 防护 | 有 | 拒绝私网和 loopback（L247–260） | 未测 |
| 本地优先、免登录 | 不支持（#5 用自托管服务器回应） | init 强制注册或登录 | help 面可用，其余被拦 |
| 钥匙串按二进制授权 | 宣称 keychain-auth | 自动下载、LaunchAgent、sudo | 未测（规则禁止） |

## 关键设计

| 设计 | AgentSecrets | 对 Rekey |
|---|---|---|
| 调用面 | `call` CLI、HTTP 代理、env 注入、MCP 四条路径 | Rekey 是签名的 Connection 规则，加 MCP 和 CLI |
| 授权粒度 | 工作区域名 allowlist，加可选的按 Key 域名/方法规则 | Rekey 是签名规则，固定 origin 和 method |
| 存储 | OS 钥匙串（经 keychain-auth），可选 .env 明文；云端存 E2E 加密副本 | Rekey 用本地加密库，不上云 |
| 账号 | 必须注册 | Rekey 不需要账号 |
| env 注入 | 有 `agentsecrets env -- cmd`（子进程能看到值） | Rekey 不提供，这是安全取舍 |

## 强项和弱项（AI 暂评）

- 强：报错把原因和修复命令写在同一句里；默认拒绝；注入方式多（6 种）；Agent 能经 MCP 自查 blocked 和 domain；发布节奏快，issue 回应及时；有 `doctor` 自愈。
- 弱：个人用户必须注册账号（#5 至今未关闭）；首次 init 会下载第二个二进制、注册 LaunchAgent、可能要 sudo；升级曾把所有命令弄坏（#6）；官网域名曾经失效（#7）；文档超前于实现（#8）；不支持 Claude Code 和 Codex 一键接入；有 `env` 注入这个旁路；有遥测和更新检查。

## 该学 / 不照搬

- 该学：①拒绝报错写成“原因 + 一条可复制的修复命令”；②给 Agent 提供 `check_domain` 和 `get_blocked_requests` 这类只读自查工具，让 Agent 被拒后能自己说清下一步；③`--body-field/--query/--form-field` 这类注入位置让覆盖面更广；④`doctor` 自愈。
- 不照搬：强制账号；运行时从 GitHub 自动下载二进制并要 sudo；`env` 把明文注入子进程；默认开启遥测；文档先于实现发布。

## Issues 中的上手和易用性抱怨（gh 原文）

- #5 “Local mode, no login”：用户不想登录。维护者回复说现在可以自托管服务器，但没有提供真正的本地模式，issue 仍为 OPEN。https://github.com/The-17/agentsecrets/issues/5
- #6 brew 升级到 1.1.3 后，所有命令都报 `keychain-auth rejected this binary path`，用户只能降级，还批评项目不遵守 SemVer。https://github.com/The-17/agentsecrets/issues/6
- #7 官网和 docs 全部 NXDOMAIN（域名欠费），恢复用了约 1 个月。https://github.com/The-17/agentsecrets/issues/7
- #8 在 Windows 上按文档配置 Cursor MCP，两条路径都失败；维护者承认文档提前写了还没发布的功能。https://github.com/The-17/agentsecrets/issues/8
- #9 注入目标名被改写，JSON body 不带 Content-Type。https://github.com/The-17/agentsecrets/issues/9
- #2 原生 Stripe CLI 和 MCP 怎么接？维护者的回答是用 env 注入。https://github.com/The-17/agentsecrets/issues/2

## 搜不到的

- Claude Code / Codex 官方接入文档：**不存在**（404，导航里也没有）。
- 定价：**未公开**。
- 免账号的纯本地模式：**不存在**（#5 OPEN，init 强制登录）。
- A2–A4 的实际行为、审批的终端体验、墙钟：**需账号，未实测**。

## Trace 文件

`trace-help.txt`、`doc-quickstart-be53766.md`；raw 见 `eval/agent/raw/agentsecrets/`
