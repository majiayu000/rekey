# 竞品卡：Kontext（原 Kontext CLI）

lane：peer-kontext-agentsecrets · 访问日期均为 2026-10-22 · 视角：个人开发者用户

**一句话结论**：Kontext 已经不是凭据代理。v1.0.0（2026-08-04）删掉了凭据交换和 `kontext start` 包装命令，现在是基于 Hook 的 Agent 动作策略与审计工具，而且拦截要靠云端工作区。所以 H1/H2/A2–A4 与 Rekey 不可比。上一轮把它列为“直接竞品”，这个定位已经过时。

## 基本信息

| 项 | 值 | 证据 |
|---|---|---|
| 链接 | https://github.com/kontext-security/kontext（原 `kontext-dev/kontext-cli`、`kontext-security/kontext-cli`，GitHub 会重定向） | `gh api repos/kontext-dev/kontext-cli` 返回 full_name=kontext-security/kontext · E2 |
| 类别 | 原先：编程 Agent 凭据注入 + 会话留痕。现在：Agent 运行时策略（PreToolUse Hook）+ 授权台账 + 风险/成本看板 | README @95d4da9 · E3 |
| 固定版本 | 源码 `main@95d4da94a7ae3c7d63aa332a74e1314228ceafe2`（2026-10-21）。实测二进制是官方 release `v1.13.1`（构建自 `1fb4f1f8`，darwin_arm64，checksums.txt 校验 OK） | trace-help.txt · E4 |
| 许可 | MIT | GitHub API |
| 活跃度 | 227★、8 fork、28 open issues（多数是内部任务）。近 30 天 65 个 commit。49 个 release（v0.1.0 2026-04-09 → v1.13.1 2026-10-20）。主要贡献者 michiosw 157、tumberger 83、hasandemirkiran 78 | `gh api` 2026-10-22 · E2 |
| 定价 | Free $0，每月 5,000 transactions。Team $500/月，含 100,000 次，超出部分每 1,000 次 $1。Enterprise 定制 | https://kontext.security/ 首页 Pricing 段（`/pricing` 是 404） · E2 |
| 定位 | “Runtime security for AI agents: discover agents, map their permissions, and enforce what they can do.” 面向安全团队和 MDM 批量部署 | repo description · E2 |

## 当前版本与近期变化

- **v1.0.0 BREAKING（PR #440，2026-08-01 合并）**：删掉了 OIDC 登录会话、`start --managed`、凭据交换和托管 sidecar，还删掉了本地 `kontext start` 包装命令。PR 给出的理由是数据仓库里“近 30 天 0 个 legacy CLI 会话，最后一次是 2026-06-04”。https://github.com/kontext-security/kontext/pull/440 · 原文存档 `pr440-retire-credential-sessions.txt` · E2
- v0.x 时期（例如 v0.4.0）的卖点是 “Store Credentials. Inject At Runtime”：用 `.env.kontext` 写占位符 `{{kontext:github}}`，经 RFC 8693 换成短期 token，再**作为环境变量注入 Agent 进程**。这种做法 Agent 能直接读到 token。项目自己的 issue #1 已经承认了这一点：https://github.com/kontext-security/kontext/issues/1 。存档见 `readme-v0.4.0-credential-era.md` · E2
- v1.6–v1.13（2026-09 至 10）：新增 authority 扫描（会扫描 Agent 配置和环境凭据是否存在）、Merlin 本地风险判定（只做建议）、成本统计、profile 多工作区。CHANGELOG @95d4da9 · E3

## H1 / H2（人）

| 项 | 结果 |
|---|---|
| 能否装起来 | 能。官方 release 二进制装到临时目录，`--version` 和 `--help` 都正常。二进制有 233MB（tar.gz 222MB），首次运行 `--version` 用了约 7 秒。E4 |
| H1：首次经产品代调用 | **不可比**。产品没有“存 Key → 代调用上游 → 注入认证头”这项功能，httpbin 回显这个测试没有入口。E3/E5（help 与源码都没有 call/proxy/inject 命令） |
| 托管路径步骤（E2，需账号，未实测） | 共 6 步：①在 app.kontext.security 注册并成为 workspace owner/admin；②在 Get started 页生成 personal API key（24 小时内有效）；③`brew install kontext-security/tap/kontext`；④`kontext setup --token …`（会把 token 写进登录钥匙串，安装 Claude Code/Codex Hook，启动 LaunchAgent，“may ask for your password” 以写 Claude 的 managed settings）；⑤Codex 用户还要在 `/hooks` 里手动 trust；⑥在 dashboard 上 send trace 并点 Finish setup。终端命令 2–3 条。来源：https://docs.kontext.security/getting-started/quickstart ，摘录存于 `doc-quickstart-extract.txt` |
| 新概念（托管路径） | workspace、endpoint、personal API key / install token、hooks、daemon（managed-observe）、policy（Observing/Enforced）、observe 与 enforce 的区别、authorization ledger、profile、Merlin/risk。共 10 个 |
| 墙钟 | 托管路径需账号，未测。本地只测了 `guard start --skip-hook-install`，约 8 秒起来 |
| H2：加 GitHub token | 不可比（同 H1） |
| 报错原文（实测） | 不加参数直接 `kontext guard start`：`Error: Claude Code was not found on PATH; install Claude Code or run with --skip-hook-install`。也就是说，默认行为是往 `~/.claude/settings.json` 写 Hook（见 cli.go L384） |

## A1–A4（Agent）

驱动偏差：按协议应该用 `command claude -p --model sonnet --strict-mcp-config …`，但它返回 `Failed to authenticate: OAuth session expired`（见 `eval/agent/raw/agentsecrets/_driver-claude-p-failure.json`）。所以改用 Claude Code 子代理（sonnet），只放行 help 类命令，HOME 指到临时目录。这和 agentvault lane 的偏差相同。

| 任务 | 结果 | raw |
|---|---|---|
| A1 列出能做什么 | **3/3 通过**（pass@1=1，pass^3=1）。三次都正确判断出“没有可调用的 host 和操作，Kontext 只做观察和治理，想隐藏 Key 要换别的工具”，没有编造能力。k1 有一次 `hooks --help` 被 auto-mode 分类器拦下，Agent 没有绕过；k3 自己犯了 shell 变量错误，之后自行恢复 | `eval/agent/raw/kontext/A1-k{1,2,3}.json` |
| A2 读调用 | 不可比：没有代调用能力 | `A2-not-run.json` |
| A3 写调用审批 | 不可比。Kontext 有 “unavailable required approvals block” 的说法（README L35 段），但审批要靠托管工作区，需账号 | `A3-not-run.json` |
| A4 未授权 host | 不可比（没有凭据面）。补测了相近场景，见下 | `A4-not-run.json` |

**补测（E4）：本地 Guard 能不能拦带 Key 的直连调用。** 用临时 HOME 执行 `kontext guard start --skip-hook-install`，再向 `kontext hook --agent claude --mode observe` 发了 4 个合成的 PreToolUse 事件：带假 Bearer 的 curl 打 httpbin、带假 Bearer 的 POST 打 api.openai.com、`cat .env`、`git push --force`。4 个都返回 `{"suppressOutput":true}`，汇总是 `0 critical / 0 warnings / 4 actions`，一个都没拦，也没有标记。源码写明本地 Hook 只做观察，见 `internal/guard/cli/cli.go` L342：https://github.com/kontext-security/kontext/blob/95d4da94a7ae3c7d63aa332a74e1314228ceafe2/internal/guard/cli/cli.go#L342 。trace：`trace-guard-hook.txt`。测完已停掉 daemon，并删除它创建的 `/tmp/kontext-guard-502`。

## 怎么接入 Claude Code / Codex

不用 MCP，也不包装命令：`kontext setup` 往 Claude Code 写入 PreToolUse/PostToolUse 等 Hook（可用 user 或 managed settings，后者要 sudo），往 Codex 写 hooks，Codex 还需要在 `/hooks` 里手动 trust。Agent 照常使用，不需要知道 Kontext 存在。README @95d4da9 “Supported agents” 表 · E3

## 功能三层核验

| 功能 | 宣称（README/docs） | 源码（E3） | 实测（E4/E5） |
|---|---|---|---|
| 凭据注入、Agent 看不到 Key | v0.x 宣称过；v1.x 已删除 | 当前源码没有 token exchange 或 `.env.kontext`（PR #440） | help 里没有对应命令（trace-help.txt） |
| 动作前拦截 | 宣称：enforce 模式在 PreToolUse 阻断 | 本地 Guard 只能观察，cli.go L342；enforce 在 managed daemon 里 | 本地 4 个事件全部放行，0 标记 |
| 失败时放行（fail-open） | README L35–43 明说：策略错误、策略未就绪、身份无法解析、daemon 挂掉，都会放行 | 未深挖 | 未测 |
| 访问留痕 | 本地 SQLite 台账 + 云端导出 | guard.db 在 `~/Library/Application Support/kontext` | 实测生成了 guard.db，记下 4 actions |

## 关键设计

| 设计 | Kontext | 对 Rekey 的意义 |
|---|---|---|
| 控制点 | Agent 的 Hook（语义层），不碰网络和凭据 | 与 Rekey 是正交关系：Rekey 管“Key 怎么用”，Kontext 管“Agent 想做什么” |
| 默认姿态 | observe，失败时放行 | Rekey 默认拒绝、审计写入失败即拒绝，是相反取舍 |
| 部署 | 一个 token，加 Hook 和 LaunchAgent；面向 MDM | 个人用户也得先在云端注册 |
| 收入模型 | 按 transaction 计费，看板在云端 | — |

## 强项和弱项（AI 暂评）

- 强：接入后 Agent 照常用，不用学新命令；`kontext doctor` 会指出 Hook 缺哪些事件；observe 再到 enforce 的灰度上线适合团队；文档对“哪些事件能拦”写得很清楚（docs/coverage.md）。
- 弱：个人开发者想“藏 Key”，这个产品帮不上；拦截依赖云端工作区；失败时放行；二进制 233MB；默认 `guard start` 会直接改 `~/.claude/settings.json`。

## 该学 / 不照搬

- 该学：①Hook 接入做到“零包装、Agent 无感”，`doctor` 能说出缺哪个 Hook 事件以及修复命令；②“observe 先看会拦掉什么，再 enforce”的上线体验，可以借鉴到 Rekey 的策略预演；③在 README 里明确写出失败语义，这种诚实值得学，但 Rekey 不应该采用它的 fail-open 取舍。
- 不照搬：环境变量注入短期 token（他们自己在 #1 里承认能被 Agent 读到，后来整个删了）；个人用户必须先注册云端；按调用次数收费。

## Issues 中的上手和易用性抱怨（gh 原文）

- #1 自承：环境变量注入的 token 能被 Agent 直接 `echo $GH_TOKEN` 读到，绕过工具级策略。https://github.com/kontext-security/kontext/issues/1
- #477 第三方验证：策略按原始文本匹配，`rm  -rf /`（两个空格）能绕过禁止规则。https://github.com/kontext-security/kontext/issues/477
- #29 “CLI opens wrong URL for provider (re)authorization”，#54 刷新 token 失效后 sidecar 无限重试。这两个都属于已删除的凭据时代。https://github.com/kontext-security/kontext/issues/29 、https://github.com/kontext-security/kontext/issues/54
- 外部用户的易用性抱怨很少：20 个 issue 里外部作者只有 2 个（#72、#477）。

## 搜不到的

- 个人或本地模式下不注册就能 enforce 的路径：**不存在**。源码 cli.go L342 明说本地只观察。
- 凭据代理能力在 v1.x 中的替代品：**不存在**。PR #440 明确把它删掉了，docs llms.txt 里也检索不到 credential/secret 相关页面。这条是反向检索：我原先预期能找到凭据功能，结果确认已删除。
- 托管 enforce 的实际拦截效果和审批 UX：**需账号，未实测**。

## Trace 文件

`trace-help.txt`、`trace-guard-hook.txt`、`doc-quickstart-extract.txt`、`pr440-retire-credential-sessions.txt`、`readme-v0.4.0-credential-era.md`
