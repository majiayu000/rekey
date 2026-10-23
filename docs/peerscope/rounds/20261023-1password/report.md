# 1Password for Agents 深度调研与 Rekey 对比（2026-10-23）

> 本文要支撑一个决定：**1Password 这次发布会不会挤占 Rekey 的位置？Rekey 要不要因此调整方向？**
> 放弃条件：如果 1Password 给个人用户提供“Agent 调用 API 时不交出 Key，并且有方法/路径级规则和按调用审批”，Rekey 就失去主要差异点，需要重新定位。
> 证据等级：**官方** = 1Password 官方文档或新闻稿；**源码** = 读过固定版本的公开代码或 npm 包；**媒体** = 记者转述；用户声音中，“零星”指单平台少量，“成规模”指多作者或多平台。
> 未实测：1Password 的这几条路线都需要账户（for Agents 还要美国账户和合作方 Agent），本轮没有登录任何账户。
> Rekey 基线：`main@f7d857a` 加未提交改动，0.5.0-alpha.1 未发布。

## 1 结论

- **这次发布做的是“Agent 代你登录网站”，没有覆盖“Agent 调用 API 不碰 Key”。** 上线范围只有网站登录（用户名、密码、一次性验证码），默认路径是浏览器扩展填表，只对美国的 Individual/Family 账户开放【官方】。
- **但 1Password 已经在另一条线上做 Rekey 同方向的事。** 1Password + NVIDIA OpenShell（2026-09-28 起 beta）让编码 Agent 在沙箱里只拿到占位符，由 OpenShell 网关在沙箱外替换成真实 Key【官方】。1Password 的配置界面只让你设 host/端口、是否允许写和有效期，并在连接时授权一次；但底层 OpenShell 本身支持按调用二进制、host/端口/路径绑定，以及配置 L7 检查后按方法和路径放行，还有 OCSF 结构化审计（导出为 best-effort）、对规则变更的人工审批（Policy Advisor，默认关闭，可设自动批准）【[NVIDIA 官方文档 v0.1.5](https://docs.nvidia.com/openshell/latest/how-it-works/providers/profiles)，未实测】。它**没有对单次调用的人工批准**；密钥在有效期内交由 OpenShell 网关保管；Agent 必须跑在 OpenShell 沙箱里。所以“Agent 不碰 Key”和“规则粒度”都**不是 Rekey 的独有点**。Rekey 剩下的差异是：写操作逐次审批（可开时间窗）、不需要沙箱也不需要账户、密钥不离开本机保险库、审计提交失败就拒绝执行。
- **这次发布的“Agent 看不到密码”是有条件的。** 有密码学保证的部分：只有用户本人能创建授权（需要 vault key）；凭据在经过 attestation 的 enclave 里解密，中转服务读不到。靠合作方自觉的部分：填充到提交之间明文就在页面里；token 和 integration key 要放进 Agent 的浏览器；多个 Agent 共用一把密钥；走 SDK 路径时合作方代码会拿到明文【官方】。
- **授权粒度比宣传粗。** 按登录项批准一次，首发时有效 30 天，期间可在后台反复使用（官方说可配置时长“planned”）；撤销只能整条连接一起撤【官方】。不过 Rekey 在这一点上也不能自夸：Rekey 同样分不清同一用户下的不同 Agent（调用方识别可伪造），读操作默认免审批，规则默认 90 天有效。
- **决定：待验证。** 现在不改方向，但定位要更新：规则粒度已不是差异点。Rekey 是“写操作逐次审批 + Agent 照常启动（不需要沙箱和账户）+ 密钥不离开本机 + 审计失败即拒绝执行”的 API 调用层。重新评估的触发条件见 §7。

## 2 它到底是什么

### 2.1 产品形态

| 项 | 事实 | 证据 |
|---|---|---|
| 发布 | 2026-10-22，“1Password for Agents”，定位为个人 AI Agent 的“trust layer” | [新闻稿](https://1password.com/press/2026/october/1password-for-agents-trust-layer-personal-ai-agents)【官方】 |
| 底层 | 合作方接口叫 **Agentic Autofill**（partner preview），与 Business 版 Credential Broker 共用后端：SDK 都在 `client.credentialBroker` 下 | [partners 文档](https://www.1password.dev/agentic-autofill/partners)【官方】；npm `@1password/sdk@0.0.0-credential-broker-dev-preview.2`【源码】 |
| 合作方 | 已在推出：Meta Muse、Grok Bot。即将上线：Claude Duet、ChatGPT Work、dots、Townie。另有 9 家在接入：Browserbase、Browser Use、Perplexity、Kernel、Ramp 等 | [产品页](https://1password.com/personal-ai-agent-integrations)、[博客](https://1password.com/blog/1password-for-ai-agents)【官方】 |
| 价格与范围 | Individual 和 Family 免费附带；仅 1password.com（美国），.eu/.ca 不支持；Business 账户、共享保险库暂不支持 | 同上；[partner FAQ](https://www.1password.dev/agentic-autofill/partners/faq)【官方】 |
| 凭据类型 | 只有登录项：用户名、密码、TOTP。passkey、社交登录、银行卡都还没有 | [partners 文档](https://www.1password.dev/agentic-autofill/partners)【官方】 |
| 接入方式 | **默认且推荐**走浏览器扩展。浏览器之外的场景，要先经 1Password 安全审查，再用 SDK，这时合作方代码会拿到明文 | [FAQ](https://www.1password.dev/agentic-autofill/partners/faq)（“If your product needs credentials outside a browser, contact 1Password”）、[sdk](https://www.1password.dev/agentic-autofill/partners/sdk)【官方】 |
| 协议 | 私有接口（OAuth + PKCE + 扩展的 CDP 接口），合作方需由 1Password 开通；不是 Web Bot Auth、HTTP Message Signatures 或 MCP | [partners 文档](https://www.1password.dev/agentic-autofill/partners)【官方】 |

### 2.2 一次登录怎么走

1. **连接**：合作方注册 OAuth 客户端，注册本身需要 Business 账户。用户走一次 OAuth + PKCE，合作方拿到 token 和 `ops_` 开头的 integration key。新闻稿说的“unique digital key”很可能就是它，但官方没有明说。
2. **请求**：Agent 通过 CDP 调用浏览器里的 1Password 扩展，发起访问请求：一个任务目标，加最多 5 个登录项，每项写明网站和理由。
3. **批准**：在用户设备上的 1Password App 里批准，需要 Touch ID、Face ID 或密码解锁。桌面端目前是 Nightly 渠道。手机端分两种：在合作方自己的 iOS/Android App 里发起已经可用（1Password 8.12.42+）；直接用 1Password 手机 App 打开审批链接，以及网页弹窗，还在开发中。用户可以挑选具体批准哪个登录项。
4. **填充**：扩展先校验 1Password credential broker enclave 的 AWS Nitro attestation，再用 Noise 会话取回这一条登录，然后填表、提交，返回 `fill_submitted`。失败时清掉已填的值。Agent 只拿到一个引用指针和状态码。

来源：[approval](https://www.1password.dev/agentic-autofill/partners/approval)、[fill](https://www.1password.dev/agentic-autofill/partners/fill)、[security](https://www.1password.dev/agentic-autofill/partners/security)【官方】。背景资料：1Password 的[机密计算文档](https://support.1password.com/confidential-computing-security/)介绍了 Nitro Enclave 里的 Session Bridge。本产品是否复用这一组件，属于推断。

### 2.3 保证与边界（官方原文）

| 类型 | 内容 | 位置 |
|---|---|---|
| 机制保证 | 只有本人能创建授权，需要 vault key：“Only the person can create a grant” | [security](https://www.1password.dev/agentic-autofill/partners/security) |
| 机制保证 | 凭据在 enclave 里解密，“The 1Password services that relay the session can't read it” | 同上 |
| 机制保证 | OAuth token 不能列出条目，也不能批准请求 | 同上 |
| 靠合作方 | 从填充到提交，值就在页面里；要求合作方在此期间不让模型读页面 | [fill](https://www.1password.dev/agentic-autofill/partners/fill)、security |
| 靠合作方 | 每次调用扩展，都要把 token 和 integration key 放进 Agent 的浏览器 | security、FAQ（“Can I keep the token and integration key out of the agent's browser entirely?”答“Not at launch”） |
| 靠合作方 | 同一个人的所有 Agent 共用一个 token 和 key，隔离要合作方自己做 | security、FAQ（“Can several of my agents use one person's access?”） |
| 常驻访问 | “Approval limits which logins your integration can use, not how often”；首发时授权 30 天，可配置时长“planned” | security、[approval](https://www.1password.dev/agentic-autofill/partners/approval) |
| SDK 明文 | `client.credentialBroker.logins.read()` 返回用户名、密码和 OTP，原文为“Your code receives the values” | [sdk](https://www.1password.dev/agentic-autofill/partners/sdk) |
| 撤销 | 只能由合作方后端撤整条连接；用户不能单独撤某个登录项，也不能在 1Password 里撤 | FAQ（“Can I revoke access to a single login?”“Can a person revoke access from inside 1Password?”均答“Not at launch”） |
| 未讨论 | 登录后的操作约束、prompt injection | 产品页、FAQ |

### 2.4 1Password 的 Agent 产品线全貌

| 产品 | 时间 | 做什么 | Agent 能否碰到明文 |
|---|---|---|---|
| Agentic Autofill（Browserbase） | 2025-10 | 本次发布的前身；旧版文档记录为每次填充都要审批，授权模型不同 | 有填充窗口 |
| Environments + MCP、Claude Code / Cursor / [Codex](https://1password.com/blog/1password-trusted-access-layer-for-openai-codex) 插件 | 2026-05 起 | 管理开发用的环境变量；MCP 不返回明文 | `op run` 和挂载 `.env` 会把明文交给进程（见 [竞品卡](../../competitors/1password.md)） |
| **1Password + NVIDIA OpenShell** | **2026-09-28 起 beta** | 编码 Agent（如 Claude Code）在沙箱内只拿占位符，OpenShell 网关在沙箱外替换。1Password 界面可设 host/端口、是否允许写（默认只读）、有效期，在连接时批准一次；OpenShell 本身另有按二进制、路径、方法（L7）的网关策略和 OCSF 审计。密钥在有效期内交由 OpenShell 保管 | **拿不到**（“Secret values never enter the agent process or context”） |
| Credential Broker | 2026-06-15 起 Business 私测 | 按工作负载身份（先支持 GitHub Actions）下发凭据。SDK 今天已有 `environmentVariables.read()`，会把明文交给工作负载；`ApiKey` 只出现在注释里。官方说“later this year”扩展到 AI Agent | 交给工作负载 |
| 1Password for Claude | 2026-07 | Claude 浏览器登录，宣传为“每个会话都要新批准，没有常驻授权” | 填充时 Claude 暂停 |
| 1Password for Agents | 2026-10-22 | 本次发布 | 见 §2.3 |
| agent-identity-specs 草案 | 2026-07 开源 | 本地 Workload Identity Broker 签发 SPIFFE 身份，换取委托令牌；目标场景包括编码 Agent | 研究草案，不是产品 |

来源：[1Password OpenShell 文档](https://www.1password.dev/environments/nvidia-openshell)、[NVIDIA 官方文档 v0.1.5](https://docs.nvidia.com/openshell/latest/how-it-works/providers/profiles)、[Policy Advisor](https://docs.nvidia.com/openshell/latest/how-it-works/policies/advisor)、[OCSF 导出](https://docs.nvidia.com/openshell/latest/observability/ocsf-json-export)、[OpenShell 博客](https://1password.com/blog/1password-nvidia-openshell)、[Credential Broker 博客](https://1password.com/blog/introducing-1password-credential-broker)、[1Password for Claude 安全说明](https://support.1password.com/1password-claude-security/)、[agent-identity-specs@a050798](https://github.com/1Password/agent-identity-specs/tree/a05079801249f7cc5f9015d4adbe03db1aea5dd3)（4★，2026-07-16 建仓）【官方/源码】。

注意：1Password for Claude 宣传“没有常驻授权”，这次合作方接口是 30 天授权，两者口径不一致。合作方也可以每个会话新建请求，做到按会话审批。

## 3 和 Rekey 逐项对比

对比对象：1Password 侧取**这次发布**和 **OpenShell** 两条路线；Rekey 侧取 `main@f7d857a` 加未提交改动（0.5 未发布）。1Password 侧只有文档证据，Rekey 侧有源码，部分有实测。

| 维度 | 1Password for Agents | 1Password + OpenShell（beta） | Rekey 0.5（未发布） |
|---|---|---|---|
| 场景 | 网站登录 | 编码 Agent 的 API 调用 | API 调用（HTTP、LLM、GitHub、SSH 签名、云临时凭据） |
| Agent 能否拿到明文 | 正常路径拿不到；填充窗口和 SDK 路径靠约定 | 拿不到（网关替换） | 拿不到调用用的 Key；T1 派生凭据需要单独开启 |
| 上游回显 Key | 不涉及 | 未说明 | 源码会封口（[sealing.rs](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-broker/src/executor/sealing.rs)）；实测只有 0.3.0-alpha.2 修复源码的本机 fixture 12/12，0.5 未复测 |
| 规则粒度 | 按登录项 | host/端口/路径绑定，按调用二进制；配置 L7 后按方法和路径放行（网关策略，需另行配置 profile 或 sandbox policy）；有效期 | 签名规则：origin、方法、路径模板、参数；LLM 模型白名单和预算 |
| 审批 | 每个登录项批一次，30 天 | 连接时批一次；规则变更可经 Policy Advisor 人工批准；**没有单次调用的人工批准** | 读默认允许；写默认逐次审批，或开最长 8 小时的时间窗；规则默认 90 天有效 |
| 区分不同 Agent | 不能（共用密钥） | 按沙箱挂载 provider，并按调用二进制匹配（文档，未实测），可能比 Rekey 强 | **也不能可靠区分**：同用户下调用方识别可伪造，任何同用户进程都能调用（[spec](../../../superpowers/specs/2026-10-05-rekey-agent-call-model.md)） |
| 撤销 | 整条连接 | 到期或断开 | 锁定立即失效；改签策略可移除单个 Connection，立即生效 |
| 审计 | 个人版未公开 | OCSF 结构化事件，可导出 JSON 接入 SIEM；`openshell term` 实时观察（文档） | 本机持久审计；审计提交失败则拒绝执行 |
| 依赖 | 1Password 账户 + 合作方 + Chromium | 1Password 账户（个人还是 Business 未明确）+ 桌面 App（Mac/Linux）+ 运行中的 OpenShell 网关；Agent 必须在 OpenShell 沙箱镜像里启动 | 本机 daemon；macOS App 用于审批，CLI 密码批准是未提交改动 |
| 审批体验 | App 弹窗 + 生物识别；合作方 App 内可发起 | 连接时一次授权提示 | macOS App 横幅容易错过；CLI 批准修复尚未提交 |
| 价格 | 订阅附带（约 $3–6/月） | 同左 | 免费开源 |
| 成熟度与分发 | 已上线；20 万家以上企业客户的品牌 | beta | 0.5 未发布，0★ |

**判定**：
- **规则粒度**：Rekey 与 OpenShell 持平。Rekey 是签名策略，OpenShell 是网关策略；1Password 的配置界面本身较粗。
- **写操作逐次审批**：Rekey 有；两条 1Password 路线在已读的官方文档（partner approval/FAQ、1Password 与 NVIDIA 的 OpenShell 文档）里都没有描述单次调用的人工批准，未实测。
- **审计**：两边都有。Rekey 审计提交失败就拒绝执行（源码）；OpenShell 是 OCSF 日志（文档）。
- **“Agent 不碰 Key”**：Rekey 与 OpenShell 持平，都是设计上不交出 Key。
- **区分 Agent**：Rekey 和 1Password for Agents 都做不到；OpenShell 按沙箱和调用二进制匹配，文档上更强（未实测）。
- **审批体验、分发、成熟度**：1Password 明显领先。

## 4 用户与媒体怎么看

- **媒体只转述官方说法，没有独立测试**；没人追问“digital key”是什么标准，也没人提 prompt injection【媒体】。PCWorld 是唯一实质性的批评：登录之后 Agent 做什么不受管。TechCrunch 引用 Axios 的报道：美国银行已经开始检测账户里的 Agent 活动【媒体】。
- **针对这次发布本身的用户声音很少**：只有 HN 和 MacRumors 的少量评论，主要是质疑“Agent 控制着整个浏览器，还怎么保证看不到”（4 位作者、2 个平台；按定义算成规模，但人数少）。
- **发布前 Grok Bot 旧版 1Password connector 的反馈**（2026-09 至 10，机制不同：CLI 会话、专用 vault、只读 service account），不算对这次发布的反应：可靠性差（7 位作者，同一论坛，成规模）、提示措辞误导（3 位）。
- **开发者需求**：1Password 社区里有 9 位以上开发者要“按调用审批、远程审批 op CLI 和 SSH”（[功能请求](https://www.1password.community/developers-69/feature-request-remote-approval-for-op-cli-desktop-prompts-to-support-agentic-workflows-24119)、[kovyrin 的 Agent Secret](https://kovyrin.net/2026/06/04/agent-secret/)），成规模。这正是 Rekey 在做的。
- Reddit、X 匿名访问失败，样本有偏。详见 [reception 笔记](evidence/reception/notes.md)。

## 5 相关玩家

- **Bitwarden Agent Access SDK**（2026-03，Apache-2.0，早期 alpha）：开放协议，按凭据逐个批准；`run` 子命令把凭据作为环境变量注入子进程（明文给进程）。它**与 OneCLI 原生集成**：OneCLI 拦截 Agent 的 API 调用，从 Bitwarden 取 Key；官方称这“有助于确保”Agent 和模型看不到 Key。这就是“密码库 + 本机 API 网关”的现成组合（[官方博客](https://bitwarden.com/blog/introducing-agent-access-sdk/)）。
- 其他：Auth0 Token Vault 走 OAuth 委托（2025-11 GA）；Google Gemini Spark 用浏览器内的密码管理器登录；Dashlane 表态不允许 Agent 自主访问；Web Bot Auth 是 IETF 草案，只解决“Agent 是谁”。详见 reception 笔记。

## 6 对 Rekey 的含义

1. **不在“网站登录”上竞争。** 1Password、Google 都在做，并且有分发优势。
2. **更新差异叙事。** “Agent 不碰 Key”已经有 1Password（OpenShell）和 OneCLI + Bitwarden 在做。OpenShell 的网关策略在规则粒度上也和 Rekey 相当。Rekey 能讲的是：写操作逐次审批（可开时间窗）、Agent 照常启动（不需要沙箱、不需要账户）、密钥不离开 Rekey 自己的保险库（OpenShell 是在有效期内把密钥交给它的网关保管，网关可以跑在本机）、审计提交失败就不执行。每一条都要有当前版本的实测；回显封口还缺 0.5 的复测（见[上轮计划](../20261022-s3/02-my-plan.md)）。
3. **学它的审批体验。** 生物识别弹窗、写清“谁在要、要做什么、为什么”、在合作方 App 内发起批准，正好对应 Rekey 的短板。
4. **“密码库作为来源”的价值上升了。** Bitwarden 已和 OneCLI 打通。Rekey 的 lab 构建里已经有 1Password Connect 来源（[onepassword_source.rs](https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/crates/rekey-broker/src/executor/onepassword_source.rs)，只适用于 Business 的 Connect Server，个人版用不了）。上轮你决定暂缓接入第三方密码库，这次仍由你决定。
5. **现成的切入点。** 开发者要“按调用审批 CLI 和 SSH”（9 位以上，成规模）。1Password + OpenShell 只在连接时批准一次；Policy Advisor 批准的是规则变更，不是单次调用。所以这一点它还没做到。

## 7 决定与触发条件

**决定：待验证。** 维持方向，按 §6.2 更新定位。出现以下任一情况时重新评估：

- OpenShell 或 Environments 加上**单次调用的人工审批**（路径/方法级规则 OpenShell 已经有）；
- 1Password 的配置界面直接暴露方法/路径规则，个人用户不用写 OpenShell 策略就能用；
- 出现不依赖 OpenShell 沙箱的本机网关（例如桌面 App 直接提供本机代理或 MCP 代调用）；
- Credential Broker 对个人账户开放，并且 `environmentVariables` 或 `ApiKey` 能在不把明文交给 Agent 的前提下使用（官方说“later this year”扩展到 AI Agent）。

## 8 覆盖率与没做到

- **读了什么**：1Password 新闻稿、博客、产品页、机密计算文档、partner 文档 10 页、1Password 与 NVIDIA 的 OpenShell 文档、npm SDK 类型、2 个开源仓库；Bitwarden 官方博客；媒体 8 家以上；HN、1Password 社区，以及一个外部论坛（发布前的 Grok Bot 反馈）。
- **审查**：这份报告经过三轮独立审查，第三轮结论为可以交付，审查意见和处置在 [reviews/](reviews/)。
- **没做到**：
  - 没有实测，需要账户和合作方 Agent；
  - Reddit 和 X 匿名访问失败；The Verge、Engadget 被拒；
  - 合作方（Muse、Grok 等）的集成细节未公开；
  - 个人版审计日志未公开；
  - “unique digital key”的含义官方没有说明。

原始笔记：[devdocs](evidence/devdocs/notes.md)、[reception](evidence/reception/notes.md)。
