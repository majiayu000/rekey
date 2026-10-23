# 1Password for Agents：技术与开发者面取证笔记

- 访问日期：全部 2026-10-23（UTC 04:40–05:30），匿名访问，UA `peerscope-adoption/0.1`
- 证据等级：E2 官方文档 / 官方博客 / 官方新闻稿；E3 读源码或已发布包；E1 媒体转述
- 原始 Markdown 抓取件放在会话 scratchpad，没有复制进仓库（版权考虑）；需要时可以按下面的 URL 重新抓取

## 0. 一句话结论

"1Password for Agents"（个人版）的开发者底层就是 **Agentic Autofill 合作伙伴接口**（partner preview）。合作方要先注册一个 OAuth 客户端，用户在 1password.com 授权一次，合作方拿到 **OAuth token 和 `integration_key`（`ops_` 开头，内含 AES-256 解锁密钥）**。新闻稿里说的"unique digital key"，最可能指的就是这个 integration key（推断：官方没有把两个名称对应起来）。之后的流程是：Agent 通过 CDP 调用 Chromium 里的 1Password 扩展，创建 access request；用户在自己设备上的 1Password App 里批准；扩展先验证 AWS Nitro Enclave 的 attestation，再走 Noise 通道取出这一条登录，填进表单并提交。Agent 只收到 `fill_submitted` 或错误码。后端和 Business 版 **Credential Broker** 是同一套（同用 `credential-broker-access-requests`，SDK 里同属 `client.credentialBroker` 命名空间）。

## 1. Agent 如何接入

| 要点 | 事实 | 证据 |
|---|---|---|
| 状态 | 仅限 partner preview，"Endpoints, response shapes, and dates can change." 这些页面不在 llms.txt 索引里 | E2 https://www.1password.dev/agentic-autofill/partners.md |
| 接入面 | 主路径是**浏览器扩展**，没有单独的 HTTP API。FAQ："There's no separate HTTP endpoint for access requests." | E2 https://www.1password.dev/agentic-autofill/partners/faq.md |
| 调用方式 | 通过 CDP 附着到扩展的 service worker `chrome-extension://<id>/background/background.js`，然后调用 `globalThis.api.agenticAutofill.v1.*` 和 `api.agenticMode.v1.*` | E2 https://www.1password.dev/agentic-autofill/partners/fill.md |
| 浏览器 | 仅支持带扩展的 Chromium（云端或本地均可），扩展需 Nightly 8.12.46.6 及以上；品牌版 Chrome 会忽略 `--load-extension` | E2 fill.md、supported-builds.md |
| SDK 备选 | `@1password/sdk@0.0.0-credential-broker-dev-preview.2`（仅 JS），提供 `createOAuthClient`，**可以读出明文** username/password/totp。官方警告 "your code can receive credential values"，要求先联系 1Password 做安全审查 | E2 https://www.1password.dev/agentic-autofill/partners/sdk.md ；E3 npm 包 typings |
| MCP / A2A | Agentic Autofill 文档里**没有** MCP 或 A2A。MCP 只出现在 Environments MCP Server（Business 开发者产品） | E2 llms.txt 检索 |
| 准入门槛 | 合作方必须有 1Password **Business** 账户才能注册 OAuth 客户端，而且要由 1Password 为该账户开启 "OAuth Application"："1Password turns it on." | E2 https://www.1password.dev/agentic-autofill/partners/quickstart.md 、production.md |

## 2. "数字密钥"是什么

- **连接**：OAuth 2.0 授权码流程加 PKCE（只支持 S256），scope 为 `brokered-credentials:request-access brokered-credentials:read`；`/oauth/authorize` 在 my.1password.com，`/v1/oauth/token` 在 api.1password.com。E2 https://www.1password.dev/agentic-autofill/partners/connect.md
- **integration key**：用户首次授权时，由用户浏览器生成"integration keyset"及其解锁密钥，放在回调 URL 的 fragment 里只交付一次："It never reaches a 1Password server."（security.md）。格式为 `ops_` 加 base64url JSON `{ver:1, typ:"oauth_integration_key", key:<32B hex>, path://api.1password.com/oauth-clients/../accounts/../users/..}`。E2 https://www.1password.dev/agentic-autofill/partners/keys-and-tokens.md
- **令牌寿命**：access token 15 分钟；refresh token 每次使用后轮换；一个连接最长约 90 天。E2 connect.md、keys-and-tokens.md
- **没有更窄的会话密钥**："There's no narrower session key."，也就是说每次扩展调用都要把 access token 和 integration key 一起送进 Agent 的浏览器。E2 keys-and-tokens.md、faq.md
- **是否基于开放标准**：用的是标准 OAuth/PKCE 加私有的 `ops_` 密钥封装。**没有**使用 Web Bot Auth、HTTP Message Signatures、DPoP 或 A2A（几份 partner 文档里都检索不到）。标准化的思路只出现在另一份研究草案里（见第 6 节）。

## 3. 请求格式与审批

- **请求**：`{version:2, goal(≤140字), entries[1..5]:{type:"login", parameters.website, reason(≤100), keywords[≤5]}}`，`type` 只能是 `login`。返回 `accessRequest.id` 和 `appLink: onepassword://grant-brokered-access?...`。E2 https://www.1password.dev/agentic-autofill/partners/access-requests.md
- **审批**：appLink 必须在用户设备上打开；用户用 Face ID、Touch ID 或密码解锁 App，选择要授予哪些登录（可以改选或增加）；提示 2 分钟后关闭。合作方按固定时间表轮询 `getAccessRequestStatus`，状态有 pending / resolved / denied / failed / expired。E2 https://www.1password.dev/agentic-autofill/partners/approval.md
- **审批只能在 1Password 客户端里完成**："Approving a login is cryptographic work that needs the person's vault key"，合作方的 App 不能代为批准。E2 faq.md
- **可以批准的位置**：桌面 Mac/Win/Linux（Nightly 渠道）；合作方 iOS/Android App 内嵌（8.12.42 及以上）；1Password 手机 App 直接打开链接和网页弹窗仍在开发中。E2 approval.md、supported-builds.md
- **授权粒度**：按登录项批准一次，而不是每次填充都批准；授权**有效期 30 天**，不绑定聊天会话："A grant isn't tied to a chat session." 后台和定时任务可以在用户不在场时填充。E2 approval.md、faq.md
- **审批文本不加密**：goal、reason、website 以可读的 base64url JSON 放在链接里，"Not at launch" 端到端加密。E2 faq.md

## 4. Agent 拿到什么，在哪里填充

- 批准后得到的 `reference` 只是一个指针（`accounts/<a>/capability/login/configurations/<id>`），不含凭据。E2 approval.md、faq.md
- `fillCredential({accessToken, integrationKey, resourcePath, tabId})` 由扩展执行：取回登录、填表、提交，返回 `fill_submitted`。这个返回值**不代表登录已成功**；失败时扩展会清空已填内容。E2 fill.md
- **解密位置**：扩展先验证 AWS Nitro Enclave 的 attestation（需访问 crl.1passwordservices.com），再用 Noise 会话从 enclave 取回单条登录；"The 1Password services that relay the session can't read it." E2 https://www.1password.dev/agentic-autofill/partners/security.md ；Noise_NX_25519_ChaChaPoly_SHA256、PCR、Rekor 等细节见 E2 https://support.1password.com/confidential-computing-security/
- **Agentic Mode**：必须开启，否则返回 `agenticModeNotEnabled`。开启后扩展会隐藏内联建议和保存提示。E2 fill.md
- **支持的凭据**：只有 Login（用户名、密码、TOTP）；不支持 passkey、社交登录、银行卡、地址；只能用个人 Personal/Private 保险库，不支持共享保险库；只支持美国的 Individual/Family 账户。E2 partners.md "Supported today"
- **API Key**：Agentic Autofill 目前没有这项能力。SDK 类型注释写着 `ApiKey, ... as they land`（E3，见 npm 包 `dist/credential_broker.d.ts`，版本 0.0.0-credential-broker-dev-preview.2，npm gitHead 为 eefdc47b，**这个 commit 在公开的 onepassword-sdk-js 仓库里不存在**）。营销页提到"GitHub, with API keys saved in the vault"，但只是用例描述，**没有接口支撑**。E2 https://1password.com/personal-ai-agent-integrations

## 5. 审计与撤销

- 撤销：只能由合作方后端调用 `POST /v1alpha1/oauth-integrations/self:revoke`，撤掉的是**整个连接**。用户**不能在 1Password 内部撤销**，也不能单独撤销某一条登录（"Not at launch"）。E2 https://www.1password.dev/agentic-autofill/partners/disconnect.md 、faq.md
- 官方博客的说法是 "disconnect the integration at any time"，实际操作是在合作方产品里断开。E2 https://1password.com/blog/1password-for-ai-agents
- 审计：partner 文档里**没有**面向个人用户的审计或活动日志说明（找不到）。Business 版 Events API v3 beta 有 "Vault item agentic autofill" 和 "Credential broker grant" 事件类型。E2 https://www.1password.dev/events-api/beta/audit-events
- 早期的 Browserbase 文档写过"detailed audit logs planned"（E1 转述，原页已下线）。

## 6. 开源组件（E3）

- `1Password/agent-identity-specs` 仓库，MIT 许可，固定 commit https://github.com/1Password/agent-identity-specs/tree/a05079801249f7cc5f9015d4adbe03db1aea5dd3 ：Internet-Draft `draft-1password-agent-identity-local-delegated-00`（2026-04），是 6 篇系列中的第 1 篇。内容是参考架构：本地 Workload Identity Broker 做 OS 级对端校验（代码签名）后签发 SPIFFE JWT-SVID，再用 OAuth Token Exchange 换取 ≤15 分钟的委托 AT 和 ≤60 秒的 Txn-Token，并引用 RFC 9421 和 WIMSE。它**明确把编码 Agent 列为目标场景**，原文是 "AI coding agents (e.g., terminal-based agentic tools"。**这是研究或规范草案，不是 1Password for Agents 的实现**；配套的 OS-Level Workload Attestation 草案状态为"coming soon"，尚未发布。
  - 草案自己列出的缺口：G-6 "No Standardized Prompt Injection Detection Protocol"；G-7 消费级设备上存在残留的二进制 attestation 缺口；同用户进程可以抓取内存。
- `1Password/onepassword-ipc-client`（Apache/MIT），固定 commit https://github.com/1Password/onepassword-ipc-client/tree/48df0f2abb3070ef6ebf449b1af661f7101f6833 ：只提供与桌面 App 之间的 IPC 传输层（macOS Mach port、Linux 抽象 socket、Windows 命名管道，分块帧，返回 responder 的 audit token 用于反向 attestation）。README 写明 "use undocumented IPC endpoints"，不包含任何 Agent 端点。
- `1Password/cpace`（Rust CPace PAKE，2026-06），用途未公开，推测与设备配对有关（推断）。
- 扩展、enclave 代码和 sdk-core（wasm）**都没有开源**；credential-broker 预览版 SDK 的源码 commit 也没有公开。

## 7. 与既有产品的关系

| 产品 | 机制 | 与 for Agents 的关系 | 证据 |
|---|---|---|---|
| Agentic Autofill × Browserbase（2025-10） | 桌面 App ↔ Browserbase 之间建立 Noise 通道、前向轮换密钥、每次填充都审批，只限 director.ai | 前身。旧文档 developer.1password.com/docs/agentic-autofill 现在 307 跳转到 /security-for-ai，**已下线** | E2（跳转实测）+ E1 https://1password.com/blog/closing-the-credential-risk-gap-for-browser-use-ai-agents |
| 1Password for Claude（2026-07-16） | 需要 Claude 桌面 App、Claude in Chrome、1P 桌面 App 和 1P 扩展；仅限 Mac；Touch ID；"limited to the current task" | 同样走扩展加 Agentic Mode。是否也走 OAuth/integration key/enclave 路径**未公开**；它的"按任务结束"和 partner 文档的"30 天授权"表述不一致 | E2 https://www.1password.com/blog/1password-for-claude |
| Credential Broker（Business，2026-06-15 起 private beta，据官方博客） | 管理员配置集成和信任策略，工作负载用 OIDC 验证，`OP_INTEGRATION_KEY`，从 Environments 取 secret | **同一后端**：access request 路径都叫 `credential-broker-access-requests`；SDK 的 `client.credentialBroker` 同时有 `environmentVariables` 和 `logins` | E2 https://www.1password.dev/brokered-access ；E3 npm typings |
| Environments + MCP Server、Claude/Cursor/Codex 插件、agent hooks | MCP 管理 Environments，"without returning secrets to the agent"；hooks 负责校验 .env 挂载 | 面向开发者和编码 Agent 的另一条线，与个人版登录填充是分开的 | E2 https://www.1password.dev/security-for-ai |
| NVIDIA OpenShell（beta） | 把 Environment 的 secret 托管给 OpenShell gateway，按 TTL 有效，在指定 host:port 上把占位符替换成真值 | 编码 Agent 拿 API Key 的官方路径（Agent 只看到占位符） | E2 https://www.1password.dev/environments/nvidia-openshell |
| op run / Shell Plugins / SSH Agent | 本地桌面 App 加生物识别 | 传统开发者路径，与 for Agents 无关 | E2 llms.txt |

## 8. 合作方集成方式

- 新闻稿和博客点名的合作方有 Muse（Meta）、Claude Duet、ChatGPT Work、dots、Grok Bot、Town，以及 Browserbase、Browser Use、KERNEL、Perplexity、Ramp 等，**但没有公开任何一家的技术细节**。"Availability, platforms, and capabilities vary by partner integration."（博客）
- 从文档推断（推断，未经合作方证实）：它们走的都是同一个 1Password 侧接口（合作方注册 OAuth 客户端、用扩展填充或在 App 内审批），这是 1Password 定义的私有接口，**不是开放协议**，而且要 1Password 开通才能用。
- 第三方 Agent（Claude Code、Codex、自建 Agent）：理论上，任何持有 Business 账户、被 1Password 开通的开发者都能按 partner 文档接入，但前提是 Agent 要驱动一个 Chromium 浏览器，FAQ 说明 "Your agent uses 1Password through the browser extension."。CLI 或 API Key 场景要单独联系 1Password（FAQ）。对编码 Agent，现成可用的是 Environments、MCP、OpenShell 和 op run，**不是** for Agents。

## 9. 官方明说的限制（反向检索：limitations / does not / not supported）

1. 填表到提交之间，明文就在页面里："anything that can read the page can read them"。合作方必须自己阻止模型读 DOM 或截图（fill.md）。
2. 明确是长期访问：持有 token 和 integration key 就能在用户不在场时使用全部已授权登录，直到授权到期（security.md）。
3. 同一个用户名下的多个 Agent 共用一把密钥，1Password 无法区分它们（security.md、faq.md）。
4. 官方要求合作方的措辞："Say 'your platform and the model don't handle the values'"，不得宣称凭据永远到不了 Agent 环境（security.md）。
5. 登录之后的操作不受约束（E1：webpronews 和 AgentFilipHQ 评论）；partner 文档只要求 "Use a login only for the goal and reason the person approved"，属于合作方义务，没有技术强制。
6. 文档没有专门讨论 prompt injection。只有 Agentic Mode 防止扩展界面泄露状态，再加上"不要加载不可信扩展"的要求。
7. 不支持 Business、共享保险库、passkey、单条撤销和用户侧撤销；地区只限美国（partners.md）。
8. 批评面：kovyrin.net（2026-06）认为多个 Agent 并行时 Touch ID 提示会失去意义（E1，https://kovyrin.net/2026/06/04/agent-secret/ ）。

## 10. 搜不到 / 未公开

- 官方没有把 "unique digital key" 和 integration key 对应起来：未公开（属于推断）。
- Web Bot Auth、HTTP Message Signatures、A2A 在产品中的使用：文档中不存在（只出现在研究草案的参考列表里）。
- support.1password.com 上面向终端用户的 "1Password for Agents" 帮助文章：搜不到。
- 个人用户可见的审计日志：未公开。
- 各合作方的集成技术细节、1Password for Claude 是否已迁到 OAuth/enclave 路径：未公开。
- 扩展 `extension-api.md` 已抓取，但本轮没有逐条比对；Web Archive 当时离线，无法取回旧版 Agentic Autofill 页面。
