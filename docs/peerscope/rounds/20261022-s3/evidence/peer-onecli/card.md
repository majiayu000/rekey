# OneCLI 竞品卡（peer-onecli，20261022-s3）

访问与实测日期均为 2026-10-22。源码引用固定在 `onecli/onecli@6eaf8780f6310587ae86906eb9573ab531e92c12`（tag v2.16.0）与 `onecli/onecli-cli@aa226247ce49cf6a22339cdf43ed160ac8d17b33`（tag v2.11.0）。凭据全部是假 Key；测试账号只建在 localhost 自托管实例上。

## 结论

- **本机自托管能装起来，但要经过 5 个容器加 Web 注册，而且官方 raw compose 路径默认跑不通本机 `onecli run`** [E4]。从 compose 起步到第一次注入成功，用了 11 条 shell 命令和 2 个 Web 表单，另加 4 条绕行命令，墙钟 12.4 分钟（其中约 7 分钟花在镜像拉取和一次 ghcr 超时上）。
- **Agent 很快能自己用起来**：A1、A2 都是 3/3。代价是每次运行都要先试错两次（缺 `--`、缺 `--agent`），而且 CLI 手里的是工作区管理员 API Key [E4]。
- **写操作默认不拦截，未授权的 host 或路径也默认放行**：A3 的写调用 3/3 直接完成，A4 0/3 被拒。网关只是不注入凭据，然后照常转发 [E4]。审批要另外配置 org policy rule。配置后的审批卡片体验不错，但本机 CLI 持有的同一把 Key 能自己批准自己的请求 [E4]。
- **定位继续往“团队 agent 平台”走**：10-06 以来的 9 个 feature release 都是 App 集成、托管 sandbox、Slack、Helm 这类内容，个人本机凭据代理没有新进展 [E3]。

## 基本信息

| 项 | 内容 | 来源 / 等级 |
|---|---|---|
| 链接 | https://github.com/onecli/onecli 、https://onecli.sh | GitHub API，2026-10-22 [E3] |
| 类别 | 开源 + 云，“The agent harness built for teams”，带 MITM 凭据网关 | README L8–L9 [E3] |
| 固定版本 | 服务端 v2.16.0（`6eaf878`，2026-10-22 发布），镜像 `ghcr.io/onecli/onecli-*:2.16.0`；CLI v2.11.0（`aa22624`，2026-07-30，最新） | releases API [E3] |
| 许可 | Apache-2.0；`ee/` 目录用 OneCLI Enterprise License，生产环境使用要订阅 | [README License](https://github.com/onecli/onecli/blob/6eaf8780f6310587ae86906eb9573ab531e92c12/README.md) [E3] |
| 活跃度 | 3,585★（10-06 为 3,559），256 fork，179 open issues；10-06 至 10-22 发了 9 个 release | GitHub API [E3] |
| 定价 | 云：Free $0（3 agents、500 calls/mo），Team $149/mo，Scale $499/mo，Enterprise 面议。比较表中“Self-hosted deployment”只在 Enterprise 列打勾，开源仓库本身可自托管 | https://onecli.sh/pricing，2026-10-22 [E2]；`onecli-pricing-2026-10-22.txt` |
| 融资 / 曝光 | Launch HN “OneCLI (YC S26)” 2026-08-19，88 分 | https://news.ycombinator.com/item?id=49363710 [E2] |

## 1. 10-06 以来的变化（v2.8.0 → v2.16.0）

完整内容见 `release-notes-since-1006.md`（GitHub releases API）[E3]：

- v2.8.0 (10-06)：Google Drive 文件夹权限、grouped Slack approvals、OAuth refresh 加固、egress guard
- v2.9.0 / v2.10.0：Circleback、Pylon 集成，所有连接页面加 setup-guide 链接，agent sandbox 拆成两个镜像
- v2.11.x (10-08)：Kubernetes Helm chart、agent webhooks、evals 与 run history，以及 cosign 签名修复
- v2.12.0 → v2.16.0：Activity 的 Runs/Network tab、Send now、桌面浏览器、shared connections、OAuth 权限缺失提示、GitHub skill 库、custom connections、多副本 runner、agent 自管 webhook
- 和个人本机凭据代理有关的只有两项：custom connections 和 egress guard。CLI 自 v2.11.0（07-30）之后没有新 release，服务端已经移除了 CLI 仍在调用的接口：`agents get-default` 返回 410 GONE，`rules *` 和 `policy rules *` 也全部 RETIRED [E4，`h1-cli.log`]。

## 2. 本机自托管能否装起来

能装 [E4]。我走的是官方文档里的 **Raw Docker Compose** 路径（[self-hosting.md L17–L35](https://github.com/onecli/onecli/blob/6eaf8780f6310587ae86906eb9573ab531e92c12/docs/self-hosting.md#L17)），镜像版本固定为 `ONECLI_VERSION=2.16.0`。我没有运行 `curl https://onecli.sh/install | sh`：它是官方脚本，但按协议不跑 curl|sh。CLI 也没用 `curl onecli.sh/cli/install | sh`，而是下载 GitHub release 的 tarball 并校验 sha256。

- 服务栈：postgres、migrations、api（749 MB）、web（544 MB）、gateway（49 MB），镜像合计约 2 GB。`runner` 这个 profile（托管 sandbox）没有启用。
- 第一次 `docker compose up` 报错：`failed to resolve reference "ghcr.io/onecli/onecli-gateway:2.16.0": ... context deadline exceeded`（网络问题，重试后成功）。
- 首次访问 http://localhost:10254 必须**注册账号**（邮箱和密码，本地实例），页面提示“You are the first here. Set up this OneCLI instance.”。不需要云账号。
- 云托管路径（app.onecli.sh）需要账号，未实测。

## 3. H1 / H2

### H1：从零到第一次注入成功（E4，trace 见 `h1-cli.log`）

| 指标 | 值 |
|---|---|
| shell 命令（happy path） | 11 条：git clone、写 `.env`、chmod、`docker compose up -d --wait`、安装 CLI、`config set api-host`、`auth login --api-key`、`agents create`、`secrets list`（为了拿 id）、`agents grants attach-secret`、`onecli run --agent local-claude -- curl …` |
| Web 表单 | 2 个：注册账号；Connections → Custom → Add connection（名称、Key、host、Bearer、可选 path） |
| 绕行命令 | 4 条。(1)(2) 往 `.env` 加 `ONECLI_AGENT_PROXY_ADDRESS=host.docker.internal:10255` 并重启（**产品问题**）；(3)(4) 加 `GATEWAY_ALLOW_PRIVATE_DESTINATIONS=httpbin.org,...` 并重启（**本机环境问题**：Clash fake-ip DNS 把 httpbin 解析成 198.18.x，网关按私网地址拒绝。错误信息写清了原因和开关，这一点是加分项） |
| 墙钟 | 744 s ≈ 12.4 min。镜像拉取和 ghcr 超时约 7 min，剩下是配置和排障 |
| 查外部资料 | 2 次：读 compose 注释找 `ONECLI_AGENT_PROXY_ADDRESS`，读 CLI 源码确认只改写 `host.docker.internal`。按 persona（不读源码）判断，这里大概率卡住（AI 暂评） |
| 新概念（11 个） | organization/workspace、账号、workspace API key（`oc_…`）、agent、agent access token（`aoc_…`）、connection/secret（custom）、host pattern / path pattern、注入方式（Bearer / header / URL param / URL path）、grant（attach-secret）、gateway（HTTPS_PROXY + MITM CA bundle）、`onecli run` 包装 |

报错原文（按出现顺序）：
1. `onecli agents get-default` → `"GET /v1/agents/default was removed: the default-agent concept is retired. ..."`，`code: GONE`（CLI 和服务端版本不一致）
2. `onecli run --dry-run -- env` → `"This workspace has no agents yet. Create one in the dashboard, then run this again."`
3. `onecli run --agent local-claude -- curl …` → `curl: (56) Proxy CONNECT aborted`。原因：服务端下发的 `HTTPS_PROXY=http://x:<aoc>@gateway:10255` 用的是 compose 内部主机名。CLI 只把 `host.docker.internal` / `gateway.docker.internal` 改写成本机地址（[run.go L370–L375](https://github.com/onecli/onecli-cli/blob/aa226247ce49cf6a22339cdf43ed160ac8d17b33/cmd/onecli/run.go#L370)、[L417–L430](https://github.com/onecli/onecli-cli/blob/aa226247ce49cf6a22339cdf43ed160ac8d17b33/cmd/onecli/run.go#L417)）。compose 默认值是 `gateway:10255`（[docker-compose.yml L141](https://github.com/onecli/onecli/blob/6eaf8780f6310587ae86906eb9573ab531e92c12/docker/docker-compose.yml#L141)）。`--gateway localhost:10255` 也不起作用，因为它只用作改写目标。install.sh 用的是同一份 compose，没有设置这个变量，所以很可能也有同样问题（E3 推断，未实测）。相关旧 issue：[#496](https://github.com/onecli/onecli/issues/496)，Install 页给 CLI 的端口不对。
4. `{"error":"destination_not_allowed","host":"httpbin.org","message":"OneCLI gateway refused to connect to httpbin.org: it resolves to a private, loopback, or link-local address. Operators can allow internal destinations with GATEWAY_ALLOW_PRIVATE_DESTINATIONS."}`（本机环境导致）
5. 成功：httpbin 回显里有 `"Authorization": "Bearer sk-peerscope-DUMMY-0000000000000000"`。

### H2：再加一个 GitHub token（E4，`h2-cli.log`）

3 条命令：`secrets create --file … --host-pattern api.github.com --header-name Authorization --value-format 'Bearer {value}'`、`secrets list`、`agents grants attach-secret`，再跑 1 次 `run`。新概念 0 个。上游返回 `401 "Bad credentials"`，说明假 token 已经注入并送达上游；如果没有注入，GitHub 返回的是“Requires authentication”。注意 `secrets create --value` 会让真实 Key 出现在 argv 和 shell history 里，CLI 也提供 `--file` 可以避开。

## 4. A1–A4（K=3，raw：`eval/agent/raw/onecli/*.json`，过程：`agent-runs.md`）

**驱动偏差**：`command claude -p` 因为独立 OAuth 过期而不可用，报错原文是 `Failed to authenticate: OAuth session expired and could not be refreshed`，见 `claude-p-attempt/`。改用 Claude Code 子代理（sonnet），Bash 只放行 onecli 包装器，与 agentvault lane 的做法一致。Claude Code 本身没有被 `onecli run` 包装，所以官方装进 `~/.claude` 的 skill 和 hook 没有生效。接入面是“CLI 包装 `onecli run -- curl`”。

| 任务 | pass@1 | pass^3 | 平均轮数 | 泄露（Agent 可见输出含假 Key） | 说明 |
|---|---|---|---|---|---|
| A1 列能力 | 1.00 | 1.00 | 5.7 | 0/3 | 三次都答对 `httpbin.org /anything/*` 和 `api.github.com` 全路径。`--help` 是一份 43.7 KB 的 JSON，三次都被截断 |
| A2 读调用 | 1.00 | 1.00 | 5.7 | 2/3 | 200 且已注入。httpbin 回显把 Key 原样带回，OneCLI 不封口反射回来的凭据；只有一次是 Agent 自己用 sed 遮掉了。最终回答都不含 Key |
| A3 写调用 | 完成 1.00（拦截 0/3） | 完成 1.00 | 6.0 | 3/3 | 默认 org Default Rule 是 `allow`，POST 直接 200 |
| A4 越权 host / 路径 | 0.00 | 0.00 | 8.0 | 0/3 | `httpbin.org/headers`（不在 path 范围内）和 `postman-echo.com` 都被放行，只是没注入；网关不拒绝，也不给原因或下一步。Agent 都正确描述了“放行但未注入” |

12 次运行中的共性摩擦：9 次撞上 `unknown flag -s`（`run` 后面要加 `--`），10 次撞上 `No agent specified and this workspace has no default agent`，12 次都在 `agents list` 里看到明文 `aoc_` agent token。全部自行恢复。

**补充：配置审批后的 A3（K=1，人工，`a3-approval.log`）**：`org policy rules create --action allow --require-approval --targets '[{"kind":"network","hostPattern":"httpbin.org","method":"POST"}]'` 发布后立刻生效。之后的 POST 被网关挂起：Dashboard 的 Recent Activity 显示 `202 · Pending`，铃铛角标 1，卡片列出 method、path 和 body 预览，3 分钟倒计时，有 Approve / Deny 两个按钮。点 Approve 后，原来那次 curl 直接拿到 200，前后 23 s。CLI 一侧在挂起期间没有任何提示。
**自批准 [E4]**：用 CLI 存在 `~/.onecli/credentials/api-key` 的同一把 `oc_` Key 调 `GET :10255/v1/approvals/pending` 能看到请求，再调 `POST /v1/approvals/<id>/decision {"decision":"approve"}`，返回 `{"success":true}`，挂起的请求随即完成。网关接受 `oc_` bearer 作为用户身份（[auth.rs L179](https://github.com/onecli/onecli/blob/6eaf8780f6310587ae86906eb9573ab531e92c12/apps/gateway/crates/context/src/auth.rs#L179)，[lib.rs L351](https://github.com/onecli/onecli/blob/6eaf8780f6310587ae86906eb9573ab531e92c12/apps/gateway/crates/server/src/lib.rs#L351)）。用本机 `onecli run` 时，Agent 和 CLI 是同一个用户、同一个 HOME，所以 Agent 能读到这把 Key。`--enforce`（Seatbelt）能否挡住读取未验证。

## 5. 怎么接入 Claude Code / Codex

- **方式**：CLI 包装加 HTTPS_PROXY 和 MITM CA，没有 MCP 凭据面（CLI 的 120 个命令里没有 MCP）[E3]。命令是 `onecli run -- claude` 或 `onecli run -- codex`，Install 页还建议写 `alias claude="onecli run -- claude"`（[install.ts](https://github.com/onecli/onecli/blob/6eaf8780f6310587ae86906eb9573ab531e92c12/packages/api/src/routes/install.ts)）。Claude 自己访问 Anthropic 的流量也会经过网关；没配 Anthropic Key 时提示 `No Anthropic credentials configured`。
- **`onecli run -- claude` 会改的文件**（在临时 HOME 里实测，副本见 `onecli-run-claude-writes/`）[E4]：
  - `~/.claude/skills/onecli-gateway/SKILL.md`（384 行）。内容要求优先于其他 skill 的认证流程、遇到缺凭据时自建 `"onecli-managed"` stub 文件，还包含批量审批的头部约定
  - `~/.claude/hooks/UserPromptSubmit/onecli_gateway_detect.sh`
  - `~/.claude/settings.json`：注册 UserPromptSubmit hook（[run.go L1073–L1096](https://github.com/onecli/onecli-cli/blob/aa226247ce49cf6a22339cdf43ed160ac8d17b33/cmd/onecli/run.go#L1073)）
  - `~/.onecli/ca-bundle.pem`、`~/.onecli/skills/gateway.md`、`~/.onecli/config.json`、`~/.onecli/credentials/api-key`
- **Codex**：写 `~/.codex/config.toml` 的 proxy_url（[run.go L624–L640](https://github.com/onecli/onecli-cli/blob/aa226247ce49cf6a22339cdf43ed160ac8d17b33/cmd/onecli/run.go#L624)）和 `~/.codex/auth.json` 占位（[L594–L600](https://github.com/onecli/onecli-cli/blob/aa226247ce49cf6a22339cdf43ed160ac8d17b33/cmd/onecli/run.go#L594)）[E3，未实测]。Electron 系编辑器会改写 VS Code 的 `settings.json`（L1177–L1251）。
- 这些都是对用户全局配置的静默写入。实测过程中只写进了临时 HOME，没有碰真实的 `~/.claude`、`~/.codex`。

## 6. 用户反馈（GitHub issues，gh 读取于 2026-10-22，`issues-search.txt` / `issues-selected.json`）

- [#496](https://github.com/onecli/onecli/issues/496)（open，08-17）：Get Started 页把 api-host 写成网关端口，`onecli auth login` 失败，报错也没有说明原因。和本次 H1 的第 3 个错误同属“本机地址和端口配置”一类。
- [#228](https://github.com/onecli/onecli/issues/228)（open）：默认绑定 127.0.0.1，rootless 容器访问不到。
- [#121](https://github.com/onecli/onecli/issues/121)（open）：“Consider sqlite vs postgresql for simple/light setups”。轻量部署诉求。
- [#266](https://github.com/onecli/onecli/issues/266)（open）：“Allowlist instead of blocklist”。和 A4 默认放行是同一个问题。
- [#482](https://github.com/onecli/onecli/issues/482)（open）：grant 已经正确发布，仍然 401 `credential_not_found`。
- [#297](https://github.com/onecli/onecli/issues/297)（open，5 条评论）：子 agent 继承了“All credentials”，没有继承父 agent 的选择性范围。
- [#268](https://github.com/onecli/onecli/issues/268)（open）：Linux 默认安装把 admin API 和 Postgres 暴露在 docker bridge 上。
- 反向检索（HN Launch 帖 37 条评论，`hn-launch-49363710-comments.json`）：有人质疑赛道太挤（[49364395](https://news.ycombinator.com/item?id=49364395)）、星数增长异常（[49367087](https://news.ycombinator.com/item?id=49367087)）、授权许可不清楚（[49370999](https://news.ycombinator.com/item?id=49370999)），也有人提到替代品 Infisical Agent Proxy（[49371194](https://news.ycombinator.com/item?id=49371194)）。官方回复说审批会绑定到具体请求（method、URL、body）（[49364820](https://news.ycombinator.com/item?id=49364820)）。#577（Codex CLI 报错）因 GitHub API 超时没有读到正文。

## 功能三层核验

| 功能 | 宣称（E2） | 源码（E3） | 实测（E4） |
|---|---|---|---|
| Agent 看不到 Key | README “Credentials it never sees” | 网关 MITM 注入 | 成立：Agent 拿不到存储的 Key。但上游回显时 Key 会原样回到 Agent，没有封口 |
| host/path 匹配注入 | “matched by host and path pattern” | secret.hostPattern / pathPattern | 成立；不匹配时放行，只是不注入 |
| 确定性人工审批 | README “Deterministic human-in-the-loop approvals” | policy `requireApproval`，网关挂起连接 | 成立，但要手动建 org rule；本机 CLI Key 能自批准 |
| 默认拒绝 | 无此宣称 | Default Rule `allow`（`org policy default get`） | 默认放行任意 host |
| Claude Code / Codex 接入 | Install 页一行命令 | `onecli run` 写 skill、hook、settings | Claude 写入已实测（临时 HOME）；Codex 未实测 |
| 自托管 | README Quick Start | compose / Helm | 能起，但 raw compose 加本机 CLI 默认代理地址不可达 |

## 关键设计

| 设计 | OneCLI | 对 Rekey 的含义 |
|---|---|---|
| 调用面 | 透明 HTTPS_PROXY + MITM CA，Agent 直接 curl 真实 URL | 零学习成本，但不限定动作；Rekey 用签名规则 |
| 授权粒度 | secret 按 host/path 注入；App 按 tool 分 allow/ask；org rule 按 method/host/path 加审批 | 接近 Rekey 的 Connection 规则，但默认 allow |
| 审批送达 | Web Dashboard 铃铛卡片、Slack（grouped approvals） | 卡片能显示解析后的 body，值得学 |
| 审批身份 | 用户 session 或 `oc_` API key 都能批准 | Rekey 的 A2 新鲜证明正好补这个缺口 |
| 本机形态 | 5 容器 + Postgres + Web 注册 | Rekey 单 daemon，概念多但不需要容器 |
| Agent 自我说明 | 43.7 KB JSON `--help`；`describe` 一类的面没有 | Rekey MCP `list_capabilities` / `describe` 更适合 Agent |

## 强项

- Web UI 很直观：添加 custom connection 的表单把注入格式实时预览成 `Authorization: Bearer ••••••`，path 限定是可选折叠项（AI 暂评）。
- 错误 JSON 普遍带下一步提示，例如 `destination_not_allowed` 指出了要改的环境变量，`no default agent` 指出了 `onecli config set agent`。
- 审批卡片有 body 预览、倒计时，批准后原请求直接完成，Agent 不需要重试。
- 接已有密码库（Bitwarden、1Password 按需注入，README）。集成面广，有 40+ OAuth App。

## 弱项

- 个人本机路径太重：约 2 GB 镜像、Postgres、注册账号；官方 raw compose 默认配置下本机 `onecli run` 连不上网关 [E4]。
- 默认放行，写操作不拦截，没有对反射回来的 Key 做封口 [E4]。
- CLI 和服务端版本漂移：CLI 最后一次发布是 07-30，大量子命令已 RETIRED，`agents get-default` 返回 410。
- 本机 CLI Key 权限过大：Agent 能改 grant、建 secret、自批准 [E4]；`agents list` 还会把 `aoc_` 明文打出来。
- `onecli run -- claude` 静默改写全局 `~/.claude/settings.json` 并安装 skill。

## 该学 / 不照搬

- **该学**：审批卡片（解析后的 body 预览、倒计时、批准后原请求直接继续）；错误里带具体修复变量名或命令；Web 表单里实时预览注入格式；`onecli run --dry-run` 列出将注入哪些环境变量。
- **不照搬**：默认 allow；透明 MITM 加全局 CA 环境变量；把管理员 API Key 放在 Agent 能读的 HOME；静默改写用户的全局 Agent 配置；用 43 KB JSON 当 `--help`。

## 搜不到 / 未完成

- `claude -p` 驱动不可用，改用子代理（偏差已记录）。官方 `onecli run -- claude` 完整模式（Claude 自身流量走网关，skill 和 hook 生效）没有实测，原因是要避免用户的 Claude OAuth 经过 MITM。
- `--enforce`（Seatbelt）模式下 Agent 能否读到 `~/.onecli/credentials` 未验证。
- install.sh 路径是否同样遇到 `gateway:10255` 问题：E3 推断，没有运行。
- 云托管（app.onecli.sh）需账号，未实测。
- Codex 接入未实测；issue #577 正文未读到（网络超时）。
