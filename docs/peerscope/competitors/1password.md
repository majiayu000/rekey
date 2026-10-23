# 竞品卡：1Password（面向 AI Agent 的开发者能力）— lane peer-1password

> 视角：已付费个人开发者，只比“好不好用”（上手步骤、概念量、Agent 接入、审批、报错）。
> 核查日期：2026-10-22。所有 URL 访问日期均为 2026-10-22，除另注。未登录、未使用任何 1Password 账户；本机未装 `op`（`which op` 无结果），未运行任何 op 命令。
> 证据等级：E2 = 官方文档/博客/支持页；E3 = 官方开源仓库源码（固定 commit）；E1 = 第三方报道/社区帖；E0 = 推断。

## 0 基本信息

| 项 | 内容 |
|---|---|
| 链接 | https://www.1password.dev/get-started/secure-ai-access （AI 接入总览，无页面日期） |
| 类别 | 平台方 / 替代物：通用密码管理器 + 开发者工具（CLI、SDK、SSH agent、Environments、MCP、浏览器 Agentic Autofill） |
| 版本 / 文档日期 | 文档站多数页面无日期；1Password for Claude 支持页发布于 2026-09-28；Claude Code 插件仓库 `1Password/1password-claude-plugin` plugin.json `0.2.0`，固定 commit `4f07dc8c1c98e5503d94dfbcd100a487fe3a5ac2`（2026-10-21） |
| 定价（个人） | Individual 常规价 $3.99/月（年付），新客首年促销 $2.99/月；Families $5.99/月（促销 $4.49）。Individual 的功能列表写有“1Password Developer tools（SSH、Git 签名、CLI & SDKs）”；页面未把 Environments / AI agent 功能列入任何个人套餐，也未说要加价 [E2] https://1password.com/pricing/password-manager |
| 定位 | “access without exposure”：不把原始凭据通过 MCP 交给模型，改为代注入 + 人工批准 [E2] https://1password.com/blog/where-mcp-fits-and-where-it-doesnt （2025-07-16） |

## 1 怎么解决“Agent 要用凭据”这个问题

1Password 现在给 Agent 用凭据有 8 条官方路线（来源：secure-ai-access 总览 [E2]），外加浏览器登录 1 条。按“Agent 能否看到明文”分组：

| # | 路线 | 状态 | Agent / 子进程能否拿到明文 | 依据 |
|---|---|---|---|---|
| 1 | `op run` + secret reference（`op://vault/item/field`）或 `op run --environment <id>` | GA | **能。** 明文作为环境变量注入子进程；官方原文：“secrets made available as environment variables only for the duration of the process”，并提醒同用户进程可读彼此环境 | [E2] https://www.1password.dev/cli/secrets-environment-variables/ |
| 2 | 用 `op run --environment` 包裹 MCP 配置（mcp.json 里不写 Key） | 未标 | **MCP 服务进程拿明文**；模型本身不直接拿，但同用户的 Agent shell 可读该进程环境（推断） | [E2] secure-ai-access；[E0] |
| 3 | Environments 本地挂载 `.env`（UNIX 命名管道，不落盘） | 文档站未标 beta；旧站标 Beta | **能。** 首次读取弹授权，之后“until 1Password locks”任何进程都可读，官方写明不区分进程；Agent 执行 `cat .env` 即得明文（推断：只要已授权） | [E2] https://1password.dev/environments/local-env-file |
| 4 | Environments MCP Server（桌面 App 内置 `1password-mcp`，stdio） | 核心未标 beta | **MCP 不返回值**：“cannot return secret values … even if an agent requests them”。但只管理（列/建/追加变量/建挂载），不负责调用 | [E2] https://1password.dev/environments/mcp-server |
| 5 | Claude Code / Cursor 插件（MCP 配置 + skill + PreToolUse 校验 hook） | Beta | **导入时会进上下文**：插件 skill 第 146 行要求“用 Read 工具读取 .env 的键和值”，再把值作为 MCP 参数传入；只是禁止“在聊天里贴出”。挂载后靠 skill 文字禁止读 FIFO，非强制 | [E3] github.com/1Password/1password-claude-plugin @4f07dc8 `skills/1password-environments/SKILL.md` L99-101, L146 |
| 6 | NVIDIA OpenShell 集成（占位符 + 网关在沙箱外替换） | Beta | **不能。** “Secret values never enter the agent process or context”；只对已批准 host/port 替换，默认只读，可设过期 | [E2] https://1password.dev/environments/nvidia-openshell |
| 7 | Shell Plugins（如 `op plugin init claude` 给 Claude Code CLI 自己的 ANTHROPIC_API_KEY） | GA | **能（推断）。** 通过注入环境变量给 CLI；文档未说明子进程是否继承 | [E2] https://1password.dev/cli/shell-plugins/claude-code |
| 8 | SDK / CLI 程序化读取 Environments；SDK AI-agent 教程 | Beta（Environments 读取） | **能。** SDK 教程直接 `secrets.resolve()` 后作为 `sensitive_data` 交给 Agent，且官方自称“not recommended”、需 Service Account | [E2] https://www.1password.dev/sdks/ai-agent |
| 9 | 1Password for Claude / Agentic Autofill（浏览器登录） | 2026-07 起 Mac 上线；Browserbase 版 2025-10 早期访问 | **不能。** 扩展代填，模型看不到密码/OTP；仅 Login 项，不支持 passkey、API Key | [E2] https://support.1password.com/1password-claude/ ；https://1password.com/blog/1password-for-claude |

另：Credential Broker（OIDC 工作负载身份，2026-07-29 公开预览）面向 Business 客户 CI/机器，不是个人开发者路线 [E2] https://1password.com/blog/1password-credential-broker-public-preview 。

**结论：** 个人开发者今天真正“开箱可用”的 API Key 路线（1/3/7）都把明文交到 Agent 能触达的进程里；“Agent 看不到明文”的路线要么只管元数据（4），要么只做网页登录（9），要么依赖第三方沙箱且为 Beta（6）。

## 2 从零到“Claude Code 用我的 API Key 调一次 LLM”（已付费 Individual，按官方文档逐步数，E2）

前提：已装 1Password 桌面 App 并登录（不计步）。

**路线 A：Environments + Claude Code 插件 + 挂载 .env（官方主推给 Claude Code）**
1. 设置 > Developer > 打开“Show 1Password Developer experience”（[E1/E2] 旧 Environments 文档 https://developer.1password.com/docs/environments ）
2. Developer > View Environments > New environment，命名保存 [E2] https://1password.dev/environments
3. 新增变量（如 `ANTHROPIC_API_KEY`）或导入 .env
4. Connect 本地 .env：Choose file path → Mount .env file（3 次点击）[E2] local-env-file
5. Claude Code 内 `/plugin marketplace add 1Password/1password-claude-plugin` + `/plugin install 1password@1password`（或在 Discover 里装）[E2] claude-plugin
6. 设置 > Developer > 勾选“Integrate with MCP clients” [E2]
7. 重启 Claude Code，让它列 Environments，桌面 App 弹授权并选择权限 [E2]
8. Agent 运行读取 .env 的调用脚本；首次读 FIFO 再弹一次 Authorize [E2]

= **8 步、约 3 处设置开关、2–3 次授权弹窗**。要懂的概念 ≈ **7**：Developer experience、Environment、变量、本地挂载 .env（FIFO/命名管道、10 个上限、Git 冲突）、MCP 集成开关、插件/skill/hook、“授权持续到 1Password 锁定”。要求 Claude Code ≥ 2.1.273、`sqlite3` 在 PATH（hook 用），仅 Mac/Linux。

**路线 B：op CLI + secret reference + op run（最通用）**
1. 安装 1Password CLI
2. 桌面 App 打开 CLI 集成（Settings > Developer）
3. 把 API Key 存为条目
4. 写 `.env`：`ANTHROPIC_API_KEY=op://<vault>/<item>/<field>`（或复制 secret reference）
5. 让 Claude Code 跑 `op run --env-file=.env -- python call.py`，首次 Touch ID 授权
= **5 步、概念 ≈ 5**（CLI、App 集成、vault/item/field、secret reference 语法、op run）。代价：子进程环境里是明文 [E2]。

对比口径：两条路线都没有“这次调用是什么 host/路径”的概念；Key 一旦交给进程，后续调用 1Password 不再参与。

## 3 功能三层核验表

| 能力 | 官方宣称 | 文档可核（E2/E3） | 实测（E4/E5） |
|---|---|---|---|
| Agent 看不到明文 | 是（MCP、OpenShell、for Claude） | MCP 不回值成立；但插件导入时值经 Read 进上下文（E3）；op run / 挂载 .env 给进程明文（E2） | 未测（禁止登录） |
| 按调用审批 | “each action requires authorization” | MCP：首次每工具+每 Environment 批准，之后复用到锁定；挂载 .env：首读批准后到锁定；OpenShell：连接时一次批准；SSH：可选“per request”；for Claude：每任务一次 | 未测 |
| 按 host/路径限制 | OpenShell“approved hosts” | 只有 OpenShell（host+port+只读/可写，无路径/方法）；其他路线无 | 未测 |
| 审计 | Credential Broker 有完整归因；Business 审计日志 | 审计日志仅 1Password Business [E2] https://support.1password.com/activity-log/ ；个人版 MCP/挂载/OpenShell 页面均未提审计；OpenShell 仅 `openshell term` 观察 | 未测 |
| Touch ID 粒度 | 生物识别审批 | Shell plugin 首次使用；for Claude 每任务；SSH 按 key×应用（默认）/×终端会话/×每请求，持续到锁定或退出 [E2] https://www.1password.dev/ssh/agent/security | 未测 |
| Windows | — | MCP 与挂载 .env 不支持，hook 在 Windows 直接放行 [E2] claude-plugin | — |

## 4 关键设计表

| 设计点 | 1Password 做法 | 对 Rekey 的意义 |
|---|---|---|
| 凭据交付形态 | 环境变量 / FIFO 文件（交明文给进程）为主；OpenShell 网关替换为辅 | Rekey 的“签名规则调用、进程拿不到 Key”是其主路线所没有的 |
| 授权生命周期 | “until 1Password locks”，按工具×Environment | 粒度粗但打扰少；Rekey 需证明逐次/时间窗审批不比这更烦 |
| 出口约束 | 仅 OpenShell：host+port+读/写，默认只读，过期时间 | 与 Rekey Connection 规则同方向，但无方法/路径/模板 |
| Agent 接入 | 一键插件（MCP+skill+hook），复用现有密码库、现有 Touch ID | 上手门槛是 Rekey 最大对比劣势：用户已有 1P，零迁移 |
| 防误用 | skill 文字规则（“不要读挂载路径”“不在聊天里贴值”）+ PreToolUse hook 校验挂载 | 文字约束不是强制边界（E3） |
| 浏览器登录 | Agentic Mode：Agent 控制浏览器时扩展锁定，只露本任务批准项 | Rekey 不覆盖网页登录 |

## 5 强项 / 弱项

强项
- 现成用户基数与零迁移：Key 已在库里；Touch ID、桌面 App、SSH agent 都是既有习惯 [E2]。
- 一条命令装 Claude Code 插件，Agent 自己完成导入/挂载/校验 [E2/E3]。
- 立场清晰：公开承诺不经 MCP 暴露原始凭据（2025-07-16 博客）[E2]。
- OpenShell 集成证明其也在走“网关替换占位符 + host 限制 + 过期”方向 [E2]。

弱项
- 个人 API Key 主路线（op run / 挂载 .env / shell plugin）把明文交给 Agent 可触达的进程；挂载 .env 授权后“no distinction between processes” [E2]。
- 插件导入流程让 Agent 用 Read 读入 .env 值（进入模型上下文与对话日志）[E3]。
- 无按调用的 host/路径/方法限制（OpenShell 除外且 Beta、需第三方沙箱）；个人版无审计日志 [E2]。
- 平台限制：MCP / 挂载仅 Mac/Linux；挂载 .env 不支持并发、可致 Vite 等 watcher 重启循环 [E2]。
- 概念多：Environment / secret reference / shell plugin / OpenShell provider / Service Account 各成体系，文档也分散在两套域名（developer.1password.com → 1password.dev 301）[E2]。

## 6 用户反馈（E1）

- HN「1Password for Claude」28 分 7 评：质疑价值（“Why bother?”）、“No Claude code support, useless feature.”（hebetude）；发帖者解释 CLI 会把凭据暴露进模型上下文 https://news.ycombinator.com/item?id=48936522 （评论 48939129、48938535）
- HN「Why 1Password hasn't released an MCP server」15 分 7 评（2025-07-17）：有人认可不经 MCP 暴露密钥，也有人批评追 AI 热点 https://news.ycombinator.com/item?id=44588660
- HN「What do you find awful about 1Password today?」：开发者工具仅一条提到 SSH “a lot of paper cuts”（jorvi），其余抱怨 Electron、自动填充不稳 https://news.ycombinator.com/item?id=47942844
- 1Password 社区「Remove MCP support」（2026-05-21，10 回复）：用户要求删除 MCP、考虑换 Apple Passwords；官方称模型“never gets custody of the secret”、功能保留 https://www.1password.community/1password-at-home-31/remove-mcp-support-24624
- Reddit：本工具无法访问 reddit.com（检索被拒），未覆盖。

反向检索：已检索“1Password MCP limitations agent secrets complaint”，命中上述社区帖与第三方 fnox 文档，无官方限制清单。

## 7 该学 / 不照搬

该学
- 一键 Claude Code 插件形态：MCP + skill + PreToolUse hook 打包，`/plugin install` 即可；hook 在 Agent 跑 shell 前校验配置。
- 复用已有解锁会话：“授权到锁定为止”显著降低打扰；Rekey 时间窗审批可对标这个体验。
- OpenShell provider 的表单字段（host、port、读/写默认只读、过期）——个人用户易懂的最小规则面。
- Agentic Mode：Agent 接管时把可用凭据收窄到“本任务批准项”的心智模型。

不照搬
- 把明文以环境变量 / FIFO 交给子进程作为 Agent 主路线。
- 让 Agent 用文件读取工具读入真实值再“承诺不贴出”的导入流程。
- 靠 skill 文字（而非机制）禁止 Agent 读取挂载文件。

## 8 搜不到的（区分未公开 / 不存在）

| 项 | 状态 |
|---|---|
| Environments 是否需要个人版以外的套餐 | 未公开：定价页未列，文档只说“1Password account/subscription”；Business 需管理员开策略。推断个人版可用（旧文档写可用于“personal workflow”） |
| MCP / 挂载 .env / OpenShell 的审计记录（个人版） | 未公开；Business 审计日志页不提这些事件 |
| MCP 授权的具体时长 / 是否按会话 | 未公开（仅“until 1Password locks”） |
| 按 HTTP 方法/路径的限制 | 不存在于任何个人路线的文档中（OpenShell 只到 host+port+读写） |
| Shell plugin 注入的变量是否被子进程继承 | 未公开 |
| `1password-mcp` 服务端源码 | 不开源（随桌面 App 分发）；仅插件仓库开源（MIT） |
| 报错体验（错误信息原文） | 未实测，文档仅有排障零散描述；需登录才能验证 |
| Reddit 用户反馈 | 工具受限未取到 |

## 历史

- 2026-10-23：1Password for Agents（2026-10-22 发布）只覆盖网站登录，Agent 不碰 API Key 的场景仍未覆盖；详见 [深度调研](../rounds/20261023-1password/report.md)。
