# Rekey 同类产品调研：用户好不好用（2026-10-22）

> 本轮只比个人开发者“好不好用”：上手步骤、要懂的概念、Agent 接入、写操作审批、出错时的提示。性能和安全攻防不重跑，沿用 2026-10-05 的结果。
> 基线：`majiayu000/rekey@f7d857a`（0.5.0-alpha.1，未发布），对照最新公开版 0.4.0-alpha.1。远端 main 已到 `26bf862`（#89，只新增 deepseek、qwen 等预设），不影响本轮结论。核查日期 2026-10-22。
> 证据等级（图例）：[E2] 只看了官方文档；[E3] 读过固定版本源码；[E4] 实际装上跑过，留有命令记录；D1 表示单平台的零星用户声音，D2 表示多平台或多作者、已成规模。

## 1 结论

- **默认就拦得住的，在实测的三家里只有 Rekey；但它不用 App 的路径还走不通。** 实测的 OneCLI 和 Agent Vault 默认会放行写操作和未授权的 host [E4]。Rekey 这两项都拦下了 [E4]。按源码看，AgentSecrets 也会默认拒绝未授权域名、对响应脱敏，只是写审批默认不开 [E3，未实测]。Rekey 的问题在“拦下之后”：没有 App 时，审批因为一个格式 bug 无法完成 [E4]。
- **概念量和竞品同一量级，不是最差。** 按统一口径（§3 注）重数：Rekey 11、OneCLI 11、Agent Vault 12、AgentSecrets 10。Rekey 实测走的是“不用 App 的 CLI 基础模式”，不是 README 主推的 App 路径，命令数和绕行有一部分来自这条路线本身。App 路径本轮没测。
- **竞品有两类成规模的痛点，正好是 Rekey 架构上避开的**：透明代理要装 CA、客户端不兼容（19 位作者，D2），自托管装不起来（15 位，D2）。但显式调用也有代价：有 4 位用户称赞 MITM“对 Agent 透明”（D1）；“Agent 不会用、文档写错命令”有 10 位作者（D2）；Kontext 的同类凭据会话功能因为“近 30 天 0 个会话”下线了 [E3]。
- **Rekey 的易用性短板很具体**：CLI 审批 bug、describe 不显示规则、报错不说根因、审批 ID 有歧义、`--help` 有 40 个命令，文档与实际流程有 5 处不一致（§4）。
- **最像 Rekey、却没深挖的是 sallyport**（189★）：Mac App + MCP；默认每个新进程首次调用点一次批准，逐次审批要按 key 手动开启；自称约两分钟上手，并且明确说上游回显不在保护范围内 [E2]。下一轮第一个要补测它。Kontext 已经不做凭据代理，改做 Hook 式审计 [E3]。1Password 面向个人的路线仍然把明文交给进程 [E2]。

## 2 范围、版本与覆盖率

| 对象 | 固定版本 | 本轮做了什么 |
|---|---|---|
| Rekey | `f7d857a`（0.5，源码构建），对照 0.4.0-alpha.1 | 在隔离目录里实测“无 App 的 CLI 基础模式”H1/H2；MCP 工具层 A1–A4 各 1 次 |
| OneCLI | `onecli/onecli@6eaf878`（v2.16.0），CLI `onecli-cli@aa22624`（v2.11.0） | Docker 自托管实测 H1/H2；A1–A4 各 3 次 |
| Agent Vault（Infisical） | `872578e`（v0.40.0；10-02 后 main 无提交） | 本机二进制实测 H1/H2；A1–A4 各 3 次 |
| AgentSecrets | `The-17/agentsecrets@be53766`（v3.3.6） | 需要注册账号、写钥匙串，没有实测；读源码和文档；A1 跑了 3 次 |
| Kontext CLI | `kontext-security/kontext@95d4da9`（v1.13.1） | 已不是凭据代理；跑了本地 guard 和 A1 |
| 1Password | 官方文档，2026-10-22 | 不登录；读文档，官方 Claude Code 插件读到 commit `4f07dc8` |
| sallyport | README，2026-10-22 | 读了 README（[存档](evidence/discover/sallyport-README-20261022.md)） |
| 候选池 | 约 50 个 | GitHub 按星数搜索、HN、维护者自家仓库 |

覆盖率：
- 候选约 50 个，深挖 6 个，实测 3 个（Rekey、OneCLI、Agent Vault）。
- Agent 任务原始记录 43 份：其中 35 份是实际运行，6 份是未跑说明，2 份是驱动失败记录（1 份保留、1 份排除）。
- 用户声音：HN 22 帖、341 条评论；GitHub issues 223 条。

**和计划的偏差**：
1. 协议要求所有产品都用同一个 `claude -p` 驱动，但本机这条路径的 OAuth 已过期。竞品改由 sonnet 子代理驱动，每个任务 3 次；Rekey 用脚本直接调 MCP 工具，每个任务 1 次，没有 LLM 参与。所以 Agent 完成率不能直接比，§5 只比较**产品行为**：拦没拦、泄没泄、报错有没有说清。
2. Rekey 的 H1 按协议不碰你的 App，走的是 `init` + `serve` + `unlock` + `add` 的 CLI 路径，不是 README 的 `rekey setup` App 主路径。

## 3 体验对照（人）

| 指标 | Rekey 0.5（无 App 的 CLI 路径） | OneCLI | Agent Vault | AgentSecrets | 1Password（op run） |
|---|---|---|---|---|---|
| 从零到第一次代调用 | 成功路径 7 条命令，开 2 个终端；实际走了 15 条命令 + 9 次 `--help` + 6 条绕行 [E4] | 11 条命令 + 2 个 Web 表单 + 4 条绕行 [E4] | 7 条命令，0 报错 [E4] | 6 条命令 + 4 个交互选择，需注册账号 [E2] | 5 步 [E2] |
| 要懂的新概念（统一口径） | 11 | 11 | 12 | 10 | 约 5（只看文档，未按统一口径重数） |
| 运行依赖 | 单 daemon + SQLite；审批要用 macOS App | 5 个容器、约 2 GB 镜像、Postgres、Web 注册 | 单二进制 + 本地 CA | 云账号 + 钥匙串 + 开机服务，可能要 sudo | 1Password 桌面版 + 订阅 |
| 加第二个 Key | 1 条命令，2.45 秒 [E4] | 3 条命令 [E4] | 2 条命令 [E4] | 3 条命令 [E2] | — |
| 不用 GUI 能走完吗 | **不能**：generic 预设连读操作都要审批，而 CLI 审批入口报错 [E4] | 能 | 能 | 能（需云账号） | 能 |

注：
- **概念计数口径**（已写进协议）：只计主路径上必须理解的名词；隔离测试带来的不计（Rekey 的 state-dir、`service.json`）；只是显示项的不计（L1-dev 警告、T0/T1）；审批相关的名词各家都不计，因为只有部分产品默认开审批；可选项不计。按这个口径，Rekey 从 16 减到 11，Agent Vault 去掉 proposal 后从 13 减到 12，OneCLI 和 AgentSecrets 不变。
- 墙钟各家条件不同：Rekey 不含构建，OneCLI 含拉镜像约 7 分钟，Agent Vault 是脚本化执行。所以只记录，不比较：Rekey 约 7 分钟、OneCLI 12.4 分钟、Agent Vault 约 26 秒。

**判定（Rekey 对比各家）**：
- 上手步骤：比 Agent Vault 差；与 OneCLI 持平（OneCLI 依赖更重，Rekey 绕行更多）；比 AgentSecrets 好（不用注册云账号）。
- 概念量：持平。
- 运行依赖：比 OneCLI、AgentSecrets 好。
- 不用 GUI 能否完成：缺口。

## 4 Rekey 实测里的具体卡点

命令记录：[trace.jsonl](evidence/self-rekey/trace.jsonl)、[MCP 探针](evidence/self-rekey/)。

| # | 卡点 | 原文或现象 | 证据 |
|---|---|---|---|
| 1 | 没有 App 时，CLI 看不了审批详情 | 报 `INVALID_FRAME: broker returned invalid local approval review`。同一个函数里，元数据要求 `local-review.v1`，记录正文却要求 `review.v1`，而 daemon 和 App 用的都是 `local-review.v1`。CLI 的测试夹具用的也是错的 `review.v1`，所以测试一直是绿的 | [local.rs#L189](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-broker/src/executor/local.rs#L189)、[policy_approval.rs#L344](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-cli/src/commands/policy_approval.rs#L344)、[tests/local_approval.rs#L153](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-cli/tests/local_approval.rs#L153) [E3+E4] |
| 2 | README 写“默认读允许”，generic 预设实际读也要审批 | `list --json` 显示 `"read": "approve"`，dry-run 显示 `"effect": "approve"` | trace H1-14、H1-15 [E4] |
| 3 | 上游被拒的根因没告诉用户 | 本机代理把域名解析到 198.18.x，Rekey 内部判为 `private-address` 后拒绝；对外只在约 10 秒后显示 `upstream request failed` | trace [E4] |
| 4 | 审批 ID 有歧义 | `next` 让用 request_id 调 await_approval，照做会得到 `approval-request-unknown`；正确的是 `approval.challenge_id` | [MCP 探针](evidence/self-rekey/mcp-probe-A3A4.jsonl) [E4] |
| 5 | describe 不显示允许的模型和规则 | `glm.messages` 里的 `model` 只是 `string`，Agent 只能靠猜 | [tools/list 探针](evidence/self-rekey/mcp-probe-A1-tools-list.jsonl) [E4] |
| 6 | 不可逆的信任根选择事前没有确认 | 首次 `add` 只事后打印一行；`policy status` 把软件 key 显示成 `secure-enclave-p256` | [software.rs#L76](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-policy/src/bin/policy_sign/software.rs#L76) [E3+E4] |
| 7 | 规则 90 天过期不提醒 | 只有原始的 `expires_at_ms`；过期后调用被拒，报 `policy-expired` | [E3+E4] |
| 8 | 端口被占用时报错不可操作 | serve 只报 `ipc unavailable`，需要手写 `service.json`，文档没写 | trace [E4] |
| 9 | 文档过时 | user-guide 标题仍是“0.4 用户指南”，还写着“在 App 中签署”，但 0.5 的 `add` 已能在 CLI 签署 | [E4] |
| 10 | 公开版没有一步式 add | 0.4.0-alpha.1 的 `rekey add` 会打开 App；CLI 一步式只在未发布的 0.5 里有 | [E3] |

## 5 Agent 可用性（产品行为）

汇总由脚本从原始 JSON 算出，结果在 [agent-pass.txt](evidence/summary/agent-pass.txt)，已排除驱动失败的记录。

| 任务 | Rekey（MCP 工具层，1 次） | OneCLI（3 次） | Agent Vault（3 次） | AgentSecrets（A1 实测，其余读源码） |
|---|---|---|---|---|
| A1 自己列出能做什么 | 与配置一致 [E4] | 3/3 | 3/3（看不到认证方式） | 3/3（只用 help）[E4] |
| A2 读调用，Key 会不会进入 Agent 可见的输出 | 本轮没有复测回显：本机 DNS 下 httpbin 不可用，只证明 Key 已注入、响应里不含 Key。此前唯一的封口证据是 0.3.0-alpha.2 修复源码在本机 fixture 上 12/12 合成反射探针被拒（[发布说明](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/docs/releases/v0.3.0-alpha.2.md)），不是 httpbin 回显，也不是发布包 | 2/3 次泄露 [E4] | 3/3 次泄露 [E4] | 默认对每个响应脱敏 [E3] |
| A3 写操作（POST）：拦截 | 拦下，进入审批 [E4] | 默认 0/3 拦截；配置审批规则后能拦 [E4] | 0/3 拦截，没有方法级限制 [E4] | 默认放行，可按 Key 开审批 [E3] |
| A3 写操作：批准后能否完成 | 没有 App 时不能：记录类型 bug；修好后还需要 `--remember` 的 presence 文件，或新增的密码批准 [E4/E3] | 能，约 23 秒 [E4] | 不适用 | 未测 |
| A4 未授权的 host 或路径 | 拒绝，返回 `NOT_CONFIGURED` / `DENIED` / `INVALID_INPUT`，并带 `next` [E4] | 默认 0/3 拒绝，放行时不带凭据、不给原因；可以用 block 规则逐个拉黑，但没有默认拒绝模式（[#266](https://github.com/onecli/onecli/issues/266)） | 默认 0/3 拒绝（passthrough）；strict 模式下返回 403 并带 `proposal_hint`，官方文档对默认值前后矛盾 | allowlist 为空时拒绝，并给出修复命令 [E3] |

**判定（Rekey 对比实测的两家）**：
- A3 拦截、A4 拒绝：Rekey 占优。
- A1：持平。
- A2：暂优，待用当前版本复测回显。
- A3 完成度：Rekey 缺口。

这些都是 pilot 样本，只说明默认行为，不说明 Agent 完成率。按源码看，AgentSecrets 在 A2、A4 上和 Rekey 同级。

**绕过尝试（Rekey 自查）**：
- **读签名私钥**：同用户的 Agent 能读到 `~/.rekey/policy-signer-p256.p8`（0600，属主就是当前用户）。但激活策略还需要保险库密码或恢复密钥 step-up（[policy_approval.rs#L88-L122](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-cli/src/commands/policy_approval.rs#L88-L122)），光拿到私钥签不出能生效的规则 [E3]。
- **读 `--remember` 文件自己批准**：开了 `rekey unlock --remember` 以后，`remembered-unlock.key` 里存的就是 presence 密钥（[mod.rs#L462-L503](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-cli/src/commands/mod.rs#L462-L503)），而 `rekey approval approve` 正是从 stdin 读 presence 密钥来批准写请求（[policy_approval.rs#L389-L420](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-cli/src/commands/policy_approval.rs#L389-L420)）。因此同用户的 Agent 很可能读这个文件就能批准自己的写调用 [E3，源码推断，未实测]。
- **结论**：这和 OneCLI“同一把 `oc_` Key 能批准自己的请求”[E4] 属于同一类问题。两家在同用户威胁下都可能被自批准。不开 `--remember` 时，同用户进程无法自批准，但你自己也无法在 CLI 批准：CLI 批准目前只接受 presence 证明，这类证明只在 App 或 `--remember` 路径下产生。这就是 02 第 1 项要新增密码批准的原因。这仍在 README 声明的 L1-dev 边界内（同用户的恶意进程不在保护范围），但修 CLI 审批 bug 时要一并处理，见 02。

## 6 各竞品要点

- **OneCLI**：定位已转向团队 harness。10-06 以来的 9 个 feature release 都是团队方向：App 集成、托管 sandbox、Slack、Helm。审批卡片体验好：body 预览、3 分钟倒计时，批准后约 23 秒完成。
  - 用户抱怨集中在：自托管安装（[#496](https://github.com/onecli/onecli/issues/496)、[#228](https://github.com/onecli/onecli/issues/228)）、想要 sqlite 轻量部署（[#121](https://github.com/onecli/onecli/issues/121)）、规则想用 allowlist（[#266](https://github.com/onecli/onecli/issues/266)）。
  - `onecli run` 会静默写入 `~/.claude/settings.json` 的 hook 和 skill [E3/E4]；raw compose 下代理地址错误，见 [run.go#L370](https://github.com/onecli/onecli-cli/blob/aa226247ce49cf6a22339cdf43ed160ac8d17b33/cmd/onecli/run.go#L370)。
  - 价格：云版 Free / $149 / $499；开源版（Apache-2.0）可以自己部署，官方托管的企业自托管方案只在 Enterprise 档 [E2]。
  - [卡片](evidence/peer-onecli/card.md)。
- **Agent Vault**：上手最快，`agent-vault run -- claude` 就能用，不改 MCP 配置。
  - 代价：回显泄露、默认放行；同机部署时 CLI 会回落到 owner 会话，Agent 在共享 HOME 下给 Key 绑了新 host 并读回 [E4]。官方的安全前提是部署在另一台主机上。
  - skill 里写的 `proposal get --json` 命令不存在（[#449](https://github.com/Infisical/agent-vault/issues/449)）。
  - [卡片](evidence/peer-agentvault/card.md)。
- **AgentSecrets**：功能面和 Rekey 最接近：默认拒绝并带修复命令（[engine.go#L657-L673](https://github.com/The-17/agentsecrets/blob/be53766186fd43539d8768c0bae9423881609635/pkg/proxy/engine.go#L657-L673)）、响应脱敏、SSRF 拦截（[engine.go#L250-L255](https://github.com/The-17/agentsecrets/blob/be53766186fd43539d8768c0bae9423881609635/pkg/proxy/engine.go#L250-L255)）[E3]。
  - 上手很重：必须有账号，首次运行会从 GitHub 下载第二个程序，还要注册开机服务。
  - 用户要的免登录本地模式至今没做（[#5](https://github.com/The-17/agentsecrets/issues/5)，仍 open）；1.1.3 升级曾经坏过（[#6](https://github.com/The-17/agentsecrets/issues/6)，2026-05-07 已修复）。
  - [卡片](evidence/peer-agentsecrets/card.md)。
- **Kontext CLI**：v1.0.0（PR #440）删掉了凭据交换，理由是“近 30 天 0 个会话” [E3]。
  - 现在做 Hook 式的策略和审计：拦截要连云端，并且失败时放行；本地 guard 模式下 4 个模拟操作全部放行 [E4]。
  - 免费档每月 5,000 次，Team 档 $500/月 [E2]。
  - [卡片](evidence/peer-kontext/card.md)。
- **1Password**：个人能直接用的三条路线（`op run`、挂载 `.env`、Shell plugin）都把明文交给子进程或任意进程 [E2]。
  - 官方 Claude Code 插件导入时，会让 Agent 读入 `.env` 的值 [E3]。
  - 唯一和 Rekey 相近的是 NVIDIA OpenShell 路线（占位符、按 host 和读写限制），但还是 Beta。
  - 个人版没有审计日志；Individual 年付 $3.99/月 [E2]。
  - [卡片](evidence/peer-1password/card.md)。
- **sallyport**：免费 Mac App，用 brew cask 安装，`claude mcp add` 接入。默认每个新进程首次调用时批准一次（默认点击，可改 Touch ID），之后该进程不再询问；逐次审批要按 key 或 MCP server 手动开启（[05-approvals.md](https://github.com/OlegSotnikov/sallyport/blob/22a457f956fc83219968a2b37ac4a232cbdce594/docs/05-approvals.md)）。
  - 只支持 Apple Silicon、macOS 14+；最新 release v0.8.16（2026-07-17），最近推送 2026-07-19，约 3 个月没更新。
  - 自称从安装到第一次受控调用约两分钟。
  - 明确说上游响应原样返回，回显不在保护范围内。
  - 189★，Apache-2.0；仓库只放各版本源码快照，不接受 PR [E2，未实测]。

## 7 竞品地图更新（只列变化）

完整候选表见 [candidates.md](evidence/discover/candidates.md)。星数是 2026-10-22 的快照，括号内是相对 10-05 的增量。

| 变化 | 产品 | 说明 |
|---|---|---|
| 类别下调 | Kontext CLI | 直接竞品 → 相邻（审计 / Hook） |
| 上轮漏掉的，和 Rekey 最像 | sallyport（189★） | Mac App + MCP，默认按进程审批，见 §6 |
| 上轮漏掉的 | varlock（4,809★） | 面向个人的“AI 安全 `.env`”：给 Agent 看 schema、不给值；npm/brew 安装 |
| 上轮漏掉的 | keypaste 416★、hasp 353★、sigcli 291★、caracal 224★ | 直接竞品，本轮只拉了采用度，没深挖 |
| 新出现 | KeyValet（1★）、briefcred（3★）、secrets-broker（15★）、AskKey（Windows） | 个人向本机 broker + 系统认证审批，还没有采用 |
| 新出现 | Alter（YC S25，闭源） | 审批 + 审计，Agent 看不到凭据；2026-10-21 上 Launch HN，63 分；面向团队 |
| 平台内置 | AWS Agent Toolkit secret safety skill | 官方自述只是 best-effort |
| 采用度 | Agent Vault 2,402（+96）、OneCLI 3,585（+26）、AgentSecrets 190（+9）、Rekey 0 | 直接竞品整体增长放缓 |

## 8 用户声音（易用性）

详见 [voc.md](evidence/voc/voc.md)。Reddit 匿名访问被拦截（403），所以样本偏向自托管的技术用户。

| 编号 | 痛点簇 | 独立作者 | 等级 | 对 Rekey 的含义 |
|---|---|---|---|---|
| P2 | 透明代理要装 CA、客户端不兼容，忘设代理就 fail open | 19 | D2 | Rekey 架构上避开了 |
| P1 | 自托管装不起来（Docker + Postgres、首次运行 401、升级后坏） | 15 | D2 | Rekey 是单 daemon；但 0.5 还没在全新机器上按发布包验过 |
| P4 | OAuth 应用接入繁琐，不支持同一 host 多把 Key 或多账号 | 约 14 | OneCLI 有 41 条 App request issue | Rekey 也要用户自带 OAuth client，同样繁琐 |
| P3 | 编码 Agent 自己的 LLM 登录接不上 | 12 | D2 | 要写清 Rekey 不代管 Agent 自己的登录 |
| P5 | 权限粒度和默认拒绝难表达 | 12 | D2 | Rekey 规则强，但写规则门槛高，需要一键模板 |
| P6 | Agent 不会用，skill 文档写了不存在的命令 | 10 | D2 | Rekey 的 describe 和 next 缺陷属于这一类；显式调用型产品更容易踩 |
| P7 | 同类太多、选择疲劳 | 11 | D2 | 需要一句话讲清差异 |

也有反向声音：有 4 位 HN 用户称赞 MITM 方案“对 Agent 透明、对接口无感”（D1，见 [voc.md](evidence/voc/voc.md) 称赞簇 G2）。本轮没有找到“审批打断太多”的原话；有用户说，低频任务宁愿用推送审批，也不想写策略（D1）。

## 9 关键事实核验

| 事实 | 影响哪条结论 | 来源与日期 | 结果 |
|---|---|---|---|
| CLI 审批的记录类型不匹配是 bug | §4 卡点 1，02 P0 | 源码 L189、L324、L344；App `apps/macos/Model.swift` L729 用 `local-review.v1`；spec 2026-10-05 L35 把 CLI 列为审批通道 | 成立 |
| generic 预设读也要审批 | §4 卡点 2 | trace H1-14、H1-15 | 成立 |
| OneCLI 默认放行写操作 | §1、§5 | [raw/onecli](eval/agent/raw/onecli/) A3-k1..3；源码里审批是可选规则 | 成立（默认）；配置后能拦 |
| OneCLI 同一把 Key 能自批准 | §5 | [a3-selfapprove.log](evidence/peer-onecli/a3-selfapprove.log) | 成立（测了 1 次） |
| Agent Vault 回显泄露、默认放行未知 host | §5 | [raw/agentvault](eval/agent/raw/agentvault/) A2、A4；`services.mdx` L6 与 L420–L423 说法矛盾 | 成立（以实测为准） |
| AgentSecrets 默认拒绝、默认脱敏、写审批默认不开 | §1、§5 | `be53766` 的 `engine.go` L657–L673、L34，`policy.go` L37–L38 | 成立 [E3]，未实测 |
| Kontext 删除凭据代理 | §1、§7 | PR #440，2026-08-01 合并 | 成立 |
| Rekey `--remember` 文件可用于自批准 | §5 | `mod.rs` L462–L503、`desktop.rs` L154–L162、`policy_approval.rs` L389–L420 | 源码推断成立，未实测 |
| 反向检索：“不走 MITM”是不是 Rekey 独有 | §1 | AgentSecrets 源码 `be53766`（`call --url` 显式调用）、KeyValet 和 sallyport 的 README（MCP） | 不是独有：这三家的主路径也是显式调用，其余同类没核 |
| 反向检索：“竞品没有审批” | §5 | OneCLI 有审批规则，AgentSecrets 可按 Key 开审批，sallyport 默认按进程审批、逐次审批可选 | 不成立：OneCLI、AgentSecrets 只是默认不开 |
| 概念数可比 | §3 | 各卡片的概念清单，按统一口径重数 | 重数后 Rekey 11、OneCLI 11、Agent Vault 12、AgentSecrets 10 |
| 1Password `op run` 把明文注入子进程环境 | §6 | 官方文档，2026-10-22 | 成立 |

## 10 没做到

- 统一的 `claude -p` 驱动失败（OAuth 过期），Agent 完成率没有可比数据；Rekey 只跑了工具层，每个任务 1 次。
- Rekey 的 App 主路径（`rekey setup`）没测；回显封口没用当前版本复测；`--remember` 自批准没有实测；LLM 预设没测；0.4 二进制没实测。
- AgentSecrets 和 Kontext 云端需要账号，没有实测；1Password 不登录，只有文档证据；sallyport 只读了 README 和审批文档，没有实测。
- keypaste、hasp、sigcli、KeyValet 本轮只拉了采用度和 README。
