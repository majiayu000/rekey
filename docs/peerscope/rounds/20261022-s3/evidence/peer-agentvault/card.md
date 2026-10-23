# 竞品卡：Infisical Agent Vault（体验 + Agent 可用性，20261022-s3）

访问日期均为 2026-10-22，`gh`/curl 请求 UA 为 peerscope-adoption/0.1。下文 `SRC` = `https://github.com/Infisical/agent-vault/blob/872578e4cdf9e03d5e3bcb5512023a70bf90ed65`。

## 基本信息

| 项 | 内容 | 证据 |
|---|---|---|
| 链接 | https://github.com/Infisical/agent-vault | E2 |
| 类别 | 自托管 HTTP 凭据代理和凭据库（透明 MITM 代理，HTTPS_PROXY 方式），单个二进制，同时是 server 和 CLI | README `SRC/README.md#L34` E2 |
| 固定版本 | **v0.40.0 = `872578e4`**（tag 指向的 commit 就是 main HEAD，2026-10-01T06:04Z）。和上轮 10-05 固定的版本完全相同 | `gh api repos/Infisical/agent-vault/git/ref/tags/v0.40.0` E2 |
| 许可 | “MIT Expat”，`ee/` 目录另有许可证；固定版本里没有 `ee/`。GitHub 显示 NOASSERTION | `SRC/LICENSE#L1-L8` E3 |
| 活跃度 | 2402★ / 171 fork；`pushed_at` 2026-10-21（只有 PR/分支活动）；**10-02 之后 main 上 0 个 commit**；open PR 有 #458 Go/Node/CA bundle 升级、#446 出站 HTTP/SOCKS 代理、#455 passthrough 的 Set-Cookie、#427 日志视图内存 | `gh api .../commits?since=2026-10-02` 返回空 E2 |
| 定价 | OSS 自托管免费；文档里有 enterprise CTA，引导到 Infisical 平台（企业支持/SLA），没写价格 | `SRC/docs/snippets/enterprise-cta.mdx#L2-L4` E2 |
| 定位 | “agents never see the underlying credentials”（CLI `--help` 原话），官方推荐**另一台主机**部署 | `SRC/README.md#L63`、`SRC/docs/tutorial.mdx#L17` E2 |

### 1. 10-06 以来的 release/changelog 变化

**没有变化。** 最新 release 仍是 v0.40.0（2026-10-01），v0.40.0 之后 main 上没有新 commit。它的 changelog 只有：per-vault Skills tab（#391）、netguard 多地址回退（#374）、漏洞披露文档（#392）和依赖升级。10-06 以后只有未合并的 PR（#446/#455/#458 等）和新 issue（#448 clone vault、#449 skill 命令不存在、#445 govulncheck 报 3 个 reachable 漏洞）。（E2，`gh api releases` / `pulls?state=all`，2026-10-22）

## 怎么解决问题（用户视角）

1. 人在 server 机上启动服务（master password），注册 owner，建 vault，存 credential，定义 service（host 匹配 + auth 类型 + 用哪个 credential），建 agent 拿到 `av_agt_` token。
2. 在 Agent 机上设好 `AGENT_VAULT_ADDR/TOKEN/VAULT`，然后 `agent-vault run -- claude`。`run` 给子进程注入 `HTTPS_PROXY=http://<token>:<vault>@host:14322`，并把 `SSL_CERT_FILE/NODE_EXTRA_CA_CERTS/...` 指向自签 CA（`SRC/internal/isolation/env.go#L42-L61`，E3）。同时会**静默**往 `~/.claude/skills/agent-vault-cli/SKILL.md` 写 skill（`SRC/cmd/run.go#L213`、`#L263-L308`，不提示，E3；文档说 “prompting once”，和代码不一致）。
3. Agent 照常发 HTTP 请求，代理按 host 注入凭据；遇到 401/403 就按 skill 创建 proposal，人在浏览器或 CLI 里批准。

**本地 CA 的负担（E4）**：走 `agent-vault run` 时用户**不用**把 CA 装进系统信任库，CA 写到 `~/.agent-vault/mitm-ca.pem`，只通过子进程环境变量生效（本轮实测 curl 直接通过）。直接设 `HTTPS_PROXY` 不经 `run` 会失败：`curl: (56) CONNECT tunnel failed, response 407`（要在代理 URL 里带 token）。官方 CLI 文档还给了一个把 CA `sudo security add-trusted-cert` 进**系统钥匙串**的示例（`SRC/docs/reference/cli.mdx#L143`，E2），本轮没有执行。另外 `run` 用 `SSL_CERT_FILE` 指向单个 CA，会**替换**子进程原本的信任 bundle。社区报告过 git、插件更新、yt-dlp 等在代理下出问题（[#210](https://github.com/Infisical/agent-vault/issues/210)）。

## H1 / H2 实测（E4，trace：`h1-trace.txt`、`h2-trace.txt`、`errors-trace.txt`）

环境：macOS arm64；官方 release 资产 `agent-vault_0.40.0_darwin_arm64.tar.gz`，sha256 与 `checksums.txt` 一致（没有运行 `curl get.agent-vault.dev | sh`）；HOME 指向临时目录；`AGENT_VAULT_TELEMETRY=false`（**默认开启**匿名遥测，`SRC/docs/reference/cli.mdx#L29`）；用桩替掉 `pbcopy`（`agent create` 会把 token 自动复制到剪贴板，`SRC/cmd/agent_create.go#L104`）。为了能本机脚本化，全程走 CLI 路径；官方教程的第 1–5 步在 Web UI 里做（`SRC/docs/tutorial.mdx#L20`）。

| 指标 | H1（LLM Key → httpbin） | H2（GitHub token） |
|---|---|---|
| 命令数 | **7**：安装 1 + `server -d` + `auth register` + `vault credential set` + `vault service add` + `agent create` + `run -- curl`（另需 export `AGENT_VAULT_ADDR`） | **2** 条配置命令（`credential set` + `service add`）+ 1 条调用 |
| 结果 | 回显 `"Authorization": "Bearer sk-peerscope-DUMMY-…"` ✓ | api.github.com 返回 401 `Bad credentials`（已注入并到达上游）✓；path 作用域 `httpbin.org/anything/gh/*` 回显 `Bearer ghp_peerscopeDUMMY…` ✓ |
| 墙钟 | 7 条命令执行合计约 26 s（12:53:41→12:54:08Z，已脚本化，不含读文档；下载 13.5 MB 另计）。AI 读文档、定位 CLI 路径约 10 分钟，不代表人类 | 约 4 s |
| 新概念（13） | master password、server/两个端口（14321 API / 14322 MITM）、owner 账号、vault、credential、service（host 匹配/path glob）、auth type（bearer/basic/api-key/custom/passthrough）、token-key 引用、agent + `av_agt_` token、vault 角色（proxy/member/admin）、`AGENT_VAULT_ADDR/TOKEN/VAULT` 三个环境变量、`run` 包装 + MITM CA、proposal | 不新增 |
| 查外部资料 | 4 页（installation、tutorial、claude-code quickstart、cli reference） | 0 |
| 报错 | 无 | 无 |

报错原文抽样（`errors-trace.txt`）：

- 漏设 vault：`vault is required in agent mode: set AGENT_VAULT_VAULT or pass --vault`（清楚，但会先打印整页 usage）
- 坏 token：`agent token rejected by broker (HTTP 401) — verify AGENT_VAULT_TOKEN is current and has access to vault "default"`（清楚）
- 缺 `--name`：`Invalid services: service 0: name is required`；`--name pe` 报 `must be at least 3 characters`
- service 引用不存在的 credential 时，`service add` **照样成功**，等到调用时才报 502 `{"error":"credential_not_found",...,"message":"A required credential could not be resolved; check vault configuration"}`（没说缺的是哪个 key）

## Agent 接入（Claude Code / Codex）改了哪些配置（E2 + E3）

- Claude Code：设 3 个环境变量，然后 `agent-vault run -- claude`；`run` 写 `~/.claude/skills/agent-vault-cli/SKILL.md`（每次运行时内容不同就覆盖），写 `~/.agent-vault/mitm-ca.pem`，给子进程注入 `HTTPS_PROXY/HTTP_PROXY/NO_PROXY/NODE_USE_ENV_PROXY/SSL_CERT_FILE/NODE_EXTRA_CA_CERTS/REQUESTS_CA_BUNDLE/CURL_CA_BUNDLE/GIT_SSL_CAINFO/DENO_CERT`。**Claude Code 自己的 Anthropic 会话流量也会经过 MITM**（默认 passthrough）。
- Codex：同样用 `agent-vault run -- codex`，skill 写到 `~/.agents/skills/agent-vault-cli/SKILL.md`（`SRC/docs/quickstart/codex.mdx`、`SRC/cmd/run.go#L238`）。
- 不改 MCP 配置，没有 MCP server。skill 安装没有 opt-out（[#338](https://github.com/Infisical/agent-vault/issues/338) open）；`NO_PROXY` 被固定覆盖，没法自定义（[#315](https://github.com/Infisical/agent-vault/issues/315)）。
- Agent 能在环境变量和 `HTTPS_PROXY` URL 里看到自己的 `av_agt_` token（`SRC/internal/isolation/env.go#L46`），看不到上游 Key 的存储值。

## A1–A4（详见 `agent-runs.md`、`eval/agent/raw/agentvault/`；驱动有偏差：sonnet 子代理代替 `claude -p`）

| 任务 | pass@1 | pass^3 | 判定 |
|---|---|---|---|
| A1 | 3/3（host 全对） | 是 | **部分**：agent token 只能看到 name/host，看不到 auth 方式，Agent 只能猜 |
| A2 | 3/3 | 是 | **完成**，但 leaked_key=3/3：假 Key 原文出现在工具输出里（上游回显、不封存），最终回答靠 Agent 自觉打码 |
| A3 | 3/3 完成 | — | **无审批**：写调用和读调用同样直接放行，不能按方法限制（`SRC/docs/learn/services.mdx#L293`；FR [#323](https://github.com/Infisical/agent-vault/issues/323)、[#192](https://github.com/Infisical/agent-vault/issues/192) open） |
| A4 | 0/3 | 否 | **未完成**：默认 passthrough，未授权 host 直接放行（不带凭据）。strict-deny（非默认，没有 CLI 开关）下 403 报错清楚，并附 `proposal_hint` |

## 功能三层核验

| 功能 | 文档声称 (E2) | 源码 (E3) | 实测 (E4) |
|---|---|---|---|
| 凭据按 host 注入 | 有 | `internal/isolation/env.go` | ✓ H1/H2 |
| path 作用域 service | 有 | — | ✓ `httpbin.org/anything/gh/*` |
| Agent 看不到凭据 | “Agents never see the underlying credentials” | 无响应体剥离（FR [#258](https://github.com/Infisical/agent-vault/issues/258) open） | ✗ 回显型上游会把 Key 原文交给 Agent |
| 未知 host 返回 403 + proposal | services FAQ 说返回 403（`learn/services.mdx#L420-L424`） | 默认 passthrough（`agents/protocol.mdx#L158`、`learn/services.mdx#L6`） | 默认放行，**文档前后矛盾** |
| proposal 审批 | 浏览器链接或 CLI | `cmd/proposal.go` 用 `ensureSession` | ✓ create→approve 可用；Agent 用 CLI 查不了状态（`show` 要登录，skill 写的 `get --json` 不存在，[#449](https://github.com/Infisical/agent-vault/issues/449)） |
| 按调用/按方法审批 | 无 | 无 | ✗ |
| skill 安装前提示 | “prompting the user once” | 不提示，直接写（`cmd/run.go#L263-L308`） | 未实测（避免写真实 `~/.claude`） |
| agent token 不能读值 | proxy 角色 | `server.go` 角色校验 | ✓ `credential get` → `Member role required`；REST 直写 service → 403 `Vault admin role required` |

## 关键设计

| 设计 | Agent Vault | 对个人用户的影响 |
|---|---|---|
| 接入方式 | 进程级 HTTPS_PROXY + 自签 CA（env 注入） | 不用改代码，所有 HTTP 客户端都能用；代价是全部流量（包括 Agent 自身 LLM 流量）都过 MITM，兼容性问题（#210、#194、#366） |
| 部署假设 | 另一台主机 | 个人单机用户和官方安全前提不一致；同机时 `vault service/proposal` 这类 CLI 命令会**回落到磁盘上的人类 owner 会话**（`cmd/service.go#L28` 用 `ensureSession`，`cmd/helpers.go#L540` 只有部分命令认环境变量 token），本轮 E4：Agent 的 shim 在共享 HOME 下成功 `service add` 了一个把 LLM_API_KEY 绑到 postman-echo.com 的服务，并读回 Key 原文（`agent-scope-probe.txt`） |
| 授权粒度 | host(+port+path glob)；不按方法 | 写/删和读同权 |
| 未知 host | 默认放行（不注入） | 容易接入，但不能当出口白名单用 |
| 审批 | 配置变更级 proposal（新 host/凭据） | 没有单次调用确认 |
| 凭据录入 | `credential set KEY=VALUE`（argv） | 值会进 shell history/ps；Web UI 可以避免 |
| 遥测 | server/CLI 默认开启 | 要手动关 |

## 强项

- 上手很短：7 条命令、零报错就跑通，H2 只多 2 条命令；错误信息大多带“下一步”（E4）。
- 透明代理，不改 Agent 和工具代码，`curl`/SDK/CLI 都能用；Claude Code 和 Codex 都是一条 `run --` 接入。
- strict-deny 和缺凭据的报错是 JSON，带 discover/skill 链接和 `proposal_hint`，对 Agent 友好（E4）。
- path 作用域、多凭据同 host 分路由，好用（E4）。

## 弱项

- 回显或反射型上游会把真实 Key 交给 Agent（A2 3/3 leaked）。
- 默认放行未知 host；写操作没有审批；没有方法级限制。
- 官方安全模型要求分机部署，个人单机用会踩到 owner 会话回落。
- skill 静默写入 `~/.claude`/`~/.agents`，没有 opt-out；skill 里的轮询命令不存在。
- 文档在“未知 host 是否 403”上自相矛盾；遥测默认开启；`agent create` 自动写剪贴板。

## 该学 / 不照搬

- **该学**：`service add` 一条命令（host + auth type + key 名）就成；按 path glob 路由同 host 的多把凭据；拒绝响应里统一带 `help`、`proposal_hint` 链接；agent 自助发起 proposal 并给出审批 URL；CLI 输出直接给出 `AGENT_VAULT_*=... agent-vault run -- <command>` 这种可复制的下一步。
- **不照搬**：默认 passthrough；上游响应不封存；凭据放 argv；整个 Agent 进程（含 LLM 流量）都走 MITM；静默写用户 Agent 配置目录；同一 CLI 里 env token 和磁盘人类会话混用。

## 社区上手/易用性抱怨（gh 原文，2026-10-22 读取）

- [#210](https://github.com/Infisical/agent-vault/issues/210)（closed）“Agent Vault very aggressively proxies everything”：git clone、插件更新、yt-dlp 在代理下出问题。
- [#338](https://github.com/Infisical/agent-vault/issues/338)（open）skill 安装无法 opt-out。
- [#315](https://github.com/Infisical/agent-vault/issues/315)（open）`run` 覆盖 `NO_PROXY`，不能自定义。
- [#449](https://github.com/Infisical/agent-vault/issues/449)（open, 10-10）skill 让 Agent 运行不存在的 `proposal get --json`（本轮 E4 复现）。
- [#192](https://github.com/Infisical/agent-vault/issues/192)（open）请求按调用人工审批；维护者回复 “Need to think about how this can be done in a manageable way”。
- [#258](https://github.com/Infisical/agent-vault/issues/258)（open）请求从响应体剥离凭据；维护者表示同意。
- [#366](https://github.com/Infisical/agent-vault/issues/366)（open）axios 经 broker 访问 https 失败，“the docs say it works”。
- [#194](https://github.com/Infisical/agent-vault/issues/194)（closed）Codex CLI WebSocket 经代理失败；[#274](https://github.com/Infisical/agent-vault/issues/274)（open）Claude Code `/rc` 在代理下 403。
- [#305](https://github.com/Infisical/agent-vault/issues/305)（open）私网 IP 被拒时报错不够清楚。
- 反向检索：`gh search issues` 搜 “setup/install/onboarding/confusing”、“certificate/CA/TLS” 都是 0 条结果；全量列出 issue 后也没看到“安装失败/CA 信任困难”类抱怨。结论是**没有公开记录**，不代表不存在；样本只有约 55 个 issue。

## 搜不到 / 没做的

- 没走 Web UI（教程默认路径）：没测浏览器注册、审批页、日志页的体验，只从文档数步骤（E2：教程 6 步，其中 5 步在 Web UI）。
- 没测 `agent-vault run -- claude` 包住整个 Claude Code（安全分类器拦截）；skill 的实际安装行为只核了源码（E3）。
- 驱动偏差：`claude -p` OAuth 失效，用 sonnet 子代理代替，工具约束只写在提示里；没有 turns/token 精确计量。
- 没测 Docker 镜像、`--isolation container`、Infisical credential store（需账号）。
- 已发布的 v0.40.0 和 main 一致，所以没有“已发布 vs 源码”的差异。

## 清理

`agent-vault server stop` 已执行，24321/24322 没有监听；临时目录在 `/private/tmp/claude-502/av.axIb`，没有写真实 `~/.claude`、`~/.agent-vault`、钥匙串或系统信任库。
