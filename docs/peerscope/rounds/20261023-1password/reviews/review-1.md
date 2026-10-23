# 独立审查 1：1Password for Agents 调研（2026-10-23）

审查对象：`report.md`、`evidence/devdocs/notes.md`、`evidence/reception/notes.md`。
核对方式：2026-10-23 匿名抓取（UA `peerscope-review/0.1`），未登录任何账户。来源包括 1password.dev partner 文档 `*.md`、1password.com 新闻稿/博客/产品页、support.1password.com、npm `@1password/sdk@0.0.0-credential-broker-dev-preview.2` tarball、GitHub API，以及 Rekey 仓库源码（HEAD f7d857a 加未提交改动）。
脚本：`scan_claims.py` 提示 4 条强结论（report.md:73/75/77/107）；`check_report.py` 没有命中。

## 总评

**改完再交付。** 主结论“这次发布只做网站登录，不覆盖 API 调用层”成立。但报告漏掉了 1Password 已经上线的 OpenShell 集成（2026-09-28 beta）。这条路线已经做到“占位符 + 网关在沙箱外替换 + host/port + 读写 + TTL”，覆盖了 Rekey 核心场景的一大块，会改变 §1、§6、§7 的结论和触发条件。另外，Rekey 侧有一条证据张冠李戴，有几处对自己宽松，用户声音大半其实来自发布前另一套集成，还有一个数字错了 1000 倍。

## 必须改

1. **漏了 1Password + NVIDIA OpenShell，§1、§6、§7 的结论跟着偏了。**
   - 位置：report.md:9（“Rekey 的核心场景……这次没有被覆盖”）、:59（§2.4 Environments 行只写“op run 和挂载 .env 会把明文交给进程”）、:108（§6.2 把“Agent 进程里从来没有 Key”当差异点）、:119（§7 第 3 条触发条件）。
   - 证据：官方文档 https://www.1password.dev/environments/nvidia-openshell.md 写明 “Inside the sandbox, the agent only ever works with placeholder values”，并且 “Secret values never enter the agent process or context”。可以设置 Host、Port、Allow writes（默认只读）和 Secrets expire（TTL）。要求只写了 “A 1Password account”，加 Mac/Linux 桌面 App，以及 Claude Code 这类 OpenShell 支持的编码 Agent。官方博客 https://1password.com/blog/1password-nvidia-openshell 显示 2026-09-28 进入 beta。上轮卡片 `docs/peerscope/competitors/1password.md:28,80,91` 已经记录了这一点，这次报告没有带进来。
   - 建议：把 §1 第 1 条限定为“**这次发布**没有覆盖”，再补一句“但 1Password 已有 OpenShell beta，Agent 只拿占位符，按 host/port/读写/TTL 替换，与 Rekey 同方向；没有方法/路径/模板规则和逐次审批，还依赖第三方沙箱”。§2.4 补一行 OpenShell。§6.2 的差异点改成“方法/路径级签名规则 + 逐次写审批 + 本机审计 + 不依赖沙箱”，不要再说“Agent 不碰 Key”是独有点。§7 第 3 条改成“已部分满足（OpenShell，beta）”，触发条件改为“OpenShell/Environments 加上按调用审批或路径/方法规则，或者出现不依赖 OpenShell 的本机网关”。

2. **Rekey 回显封口的证据写错了出处，§3 和 §6 互相矛盾。**
   - 位置：report.md:73（“Rekey 侧有源码和 10-05 的 fixture 实测”）、:108（“回显封口还缺当前版本的复测”）。
   - 证据：现有的唯一实测是 `docs/releases/v0.3.0-alpha.2.md:22-23`。那是 0.3.0-alpha.2 修复源码在本机跑的 fixture：12/12 个合成凭据反射探针都被拒绝，原文还写明“不代表真实 provider 或发布包验收”。上轮 `rounds/20261022-s3/02-my-plan.md:61` 也明说当前版本还没有复测。仓库里找不到所谓“10-05 fixture”。
   - 建议：改成“Rekey 侧：源码实现了编码变体封口（`crates/rekey-broker/src/executor/sealing.rs`），实测只有 0.3.0-alpha.2 本机 fixture 12/12，0.5 尚未复测”。判定从“Rekey 更强”降为“机制设计上更强制（Rekey 源码，未在 0.5 实测）；1Password 侧只有文档”。

3. **授权粒度和“不区分 Agent”两行对自己宽松。**
   - 位置：report.md:11、:74、:72、:108。
   - 证据：Rekey 的本机 CALL 不需要令牌。spec `docs/superpowers/specs/2026-10-05-rekey-agent-call-model.md:49` 写明“同用户下这种识别可以被伪造，它不是安全边界”，README.md:64 也写了“不阻止同用户的恶意程序……伪造调用方”。也就是说，Rekey 同样不能可靠区分是哪个 Agent，任何同用户进程都能调用。另外，`docs/user-guide.md:25,109` 写明默认规则是“读允许、写审批”，规则默认 90 天有效。这同样是不需要人在场的常驻读权限，可以和 1Password 的 30 天授权直接对比。
   - 建议：§3 授权粒度一栏，Rekey 侧补上“调用方识别可伪造、不是边界；读默认免审批；规则默认 90 天”。判定改成“规则维度更细（方法/路径）；两者都不能可靠区分同一用户下的多个 Agent”。§1 第 3 条批评 1Password“分不清 Agent”时，加一句“Rekey 也一样”，或者删掉这组对比。“任何本机 Agent 都能用”要注明它的另一面：任何同用户进程也都能用。

4. **“2 亿企业客户”错了 1000 倍，而且放错了行。**
   - 位置：report.md:75。
   - 证据：新闻稿 https://1password.com/press/2026/october/1password-for-agents-trust-layer-personal-ai-agents 写的是 “trusted by over 200,000 businesses”（20 万）。Credential Broker 博客写的是 “More than 180,000 businesses”。
   - 建议：改成“20 万家以上企业客户”，并挪到“成熟度与分发”那一行。审批体验那一行不该引用客户数。

5. **用户声音把发布前另一套 Grok Bot 集成算进了这次发布。**
   - 位置：report.md:87-88（“集成可靠性差 7 位”“锁定和付费 12 位以上，成规模”）。
   - 证据：forum.cursor.com 的帖子都是 1Password for Agents（10-22）发布之前开的：173142 开于 09-27，172310 开于 09-18，171948 开于 09-17，172524 开于 09-21，173354 开于 09-29。reception 笔记 :75 自己也写了，那套集成是“CLI 会话 → 专用 vault → 只读 service account”，机制和这次的 Agentic Autofill（OAuth + 扩展填充）不同。
   - 建议：把这两簇单列为“发布前 Grok Bot 旧版 1Password connector 的反馈（2026-09 至 10，机制不同）”，不要作为对这次发布的反应。针对 10-22 发布本身的用户声音只剩 HN 的少量评论和 MacRumors 评论，规模要如实写小。“成规模”的标签相应改掉。

6. **“只能通过浏览器扩展”说过头了，和同一张表里的 SDK 行矛盾。**
   - 位置：report.md:26、:9（“CLI 和 API Key 都不在范围内”）。
   - 证据：FAQ 原文是 “If your product needs credentials outside a browser, contact 1Password for guidance and a review of our shared security model before you build with the SDK.”。sdk.md 列了两种模式：“Request with the SDK, fill with the extension” 和 “Read with the SDK”。另外，npm 包 `dist/credential_broker.d.ts` 里已经有 `environmentVariables.read()`，返回 `EnvironmentCredential`（一组环境变量）。
   - 建议：改成“默认且推荐走浏览器扩展；浏览器之外可以经 1Password 安全审查后用 SDK（会拿到明文）”。

7. **§7 触发条件 2 漏了 SDK 已经能下发环境变量（API Key 的常见形态）。**
   - 位置：report.md:118。
   - 证据：同一个预览版 SDK 的 `credentialBroker` 下今天已经有 `environmentVariables` 和 `logins` 两类。注释原文是 “([`EnvironmentVariables`] and [`Logins`] today; `ApiKey`, ... as they land)”（npm gitHead eefdc47b，发布于 2026-10-06）。
   - 建议：写清“Credential Broker（Business）已经能把 Environment 变量交给工作负载，Agent 会拿到明文；`ApiKey` 还只是注释”。触发条件改成“个人账户可以用 Credential Broker 的 environmentVariables 或 ApiKey，并且不把明文交给 Agent”。

8. **Rekey 侧没有写清基线：§3 的“CLI 密码批准”依赖未提交改动。**
   - 位置：report.md:68 表头写的是“Rekey 0.5（源码）”，:75。
   - 证据：`git diff crates/rekey-domain/src/ipc.rs` 显示，`parse_local_approval_proof_body` 允许 `ProofKind::Password` 是工作区里的未提交改动，HEAD f7d857a 只接受 Presence。8 小时时间窗在 HEAD 和 v0.4.0-alpha.1 里都已存在（`local_calls.rs:821`）。
   - 建议：表头注明“main@f7d857a 加未提交改动，0.5.0-alpha.1 未发布”，并在“CLI 密码批准”后注明“未提交、未发布”。

## 建议改

1. report.md:33、:75、:109：“手机端还在开发”不准确。approval.md 写明，从合作方自己的 iOS/Android App 内审批已经可用（8.12.42+），还在开发的只是 1Password 手机 App 直接打开审批链接和网页弹窗。建议按这个拆开写。§6.3“学它的手机端批准”的依据会因此更强。
2. report.md:108“1Password 的关键防护……都靠合作方自觉”说得太宽。security.md 列出的几项是密码学或机制保证：“Only the person can create a grant”，授权创建需要 vault key；在经过 attestation 的 enclave 里解密；Agentic Mode。靠约定的只是填充窗口、多 Agent 隔离和 SDK 明文这三项。建议改成“部分关键防护靠合作方自觉”。
3. report.md:11、:45：没提官方写的 “configurable lifetimes are planned” 和 “Longer-lived access for scheduled jobs is planned”。另外合作方可以每个会话新建请求，做成按会话审批（approval.md:211）。建议补上，以免读者以为 30 天是固定设计。
4. report.md:35：Session Bridge 那段，“这次的产品具体用了哪部分，未公开”只对一半。partner security.md 已经官方写明：扩展会校验 credential broker enclave 的 Nitro attestation，用 Noise 会话从 enclave 取回单条登录，“The 1Password services that relay the session can't read it.”。建议以 partner security.md 为主要依据，“Session Bridge 是受信代理人”只作为机密计算通用文档的背景，并标注“推断适用”。
5. report.md:96：Bitwarden 那行太简略，而它和 Rekey 最相关。官方博客 https://bitwarden.com/blog/introducing-agent-access-sdk/ 写了两点：`run` 子命令会把凭据作为环境变量注入子进程（明文给进程）；另外它与 OneCLI 原生集成，“OneCLI will intercept any API calls … fetch the API key from within the Bitwarden vault”。这是“密码库 + 本机 API 网关”的现成组合。建议补进 §5，并在 §6.4 讨论“密码库作为来源”时提到。
6. report.md:110“上轮你决定暂缓接入第三方密码库”：Rekey 源码里已经有 lab-only 的 1Password Connect 来源（`crates/rekey-broker/src/executor/onepassword_source.rs`，`#[cfg(feature = "lab")]`）。建议注明“lab 下已有 1Password Connect（Business/Connect Server）来源，个人版 1Password 不适用”。这属于高发错误第 2 条“漏了自家”。
7. report.md:90：“没有找到任何评论把它和 Rekey 联系起来”几乎是同义反复，Rekey 0★、未发布，本来就不会有人提。检索范围也没包含 Reddit/X（匿名访问失败），却得出了“没有”。建议删掉 Rekey，只保留 OneCLI 一类，限定为“在可访问的媒体、HN 和 1P 社区里”，并补一条反例：Bitwarden 官方已经把密码库和 OneCLI 放在一起讲。
8. report.md:76：“可单独撤 Connection”的实现方式是重新起草、重新签署整份策略（`rekey policy draft --connections-stdin`，“[] revokes all local access”，main.rs:954），不是一键撤销。建议写成“改签策略移除单个 Connection 立即生效”。
9. report.md:79：价格写的是“约 $3–5/月”。上轮卡片记录的是 Individual $3.99、Families $5.99（促销价 $2.99/$4.49）。建议改成“约 $3–6/月”。
10. report.md:56：说 Agentic Autofill（Browserbase）“同上，有填充窗口”，但 devdocs 笔记 :68 记录的是旧版“每次填充都审批”，授权模型不同。建议注明。
11. 读者负担：
    - report.md:26、:43–:48 的“FAQ Q41/Q48”等编号是作者自己数的，页面上没有编号，读者找不到。建议改用问题原文或锚点链接。
    - report.md:108 的“见上轮 02”没有链接。建议链接到 `../20261022-s3/02-my-plan.md`。
    - report.md:27 证据列写的是“devdocs 笔记【官方】”，应该直接给官方页面链接。
    - report.md:129“这份报告没有经过第三方核对”，处置后要更新。
12. 笔记内部不一致（高发错误第 9 条）：
    - devdocs 笔记 :70 写 Credential Broker 是“public preview”，官方博客是 “private beta starting June 15, 2026”。
    - reception 笔记 :71 说 Codex MCP“未在官方页面核实”，但 1Password 博客列表里有官方文章 “1Password is now a trusted access layer for OpenAI's Codex”（2026-05-20）。
13. §5 里 Visa/Mastercard、Google、Web Bot Auth 这几行，和用户问的“1Password 这次怎么回事”关系较弱，可以压缩成一句，以减轻篇幅。

## 事实抽查表

| 事实 | 位置 | 结果 | 来源与日期 |
|---|---|---|---|
| 授权 30 天，按登录项而非按次，可后台使用 | report:11、:45 | 成立（但漏了“可配置寿命已在计划中”） | 1password.dev/agentic-autofill/partners/approval.md :208-211；faq.md，2026-10-23 |
| SDK 能读出明文 | report:10、:44 | 成立；属于需要 1Password 审查的非默认模式 | partners/sdk.md（“Read with the SDK. Your code receives the values.”），2026-10-23 |
| 多 Agent 共用 token 和 integration key，1Password 无法区分（FAQ 第 41 问） | report:11、:46 | 成立（按页面顺序确实是第 41 问） | faq.md；security.md “Several agents, one person”，2026-10-23 |
| “不支持 CLI”（FAQ 第 48 问） | report:9、:26 | 部分错误：FAQ 指向 SDK 的替代路径，不是“只能扩展” | faq.md 第 48 问，2026-10-23 |
| 撤销只能整条连接，用户在 1Password 内撤不了 | report:11、:48、:76 | 成立 | partners.md “Supported today”；faq.md 第 46、47 问，2026-10-23 |
| 仅限美国 Individual/Family；.eu/.ca 不支持 | report:24 | 成立 | partners.md；1password.com/blog/1password-for-ai-agents，2026-10-23 |
| Credential Broker “later this year”扩展到 AI Agent；private beta；GA 目标 2026 年底 | report:57、:117 | 成立 | 1password.com/blog/introducing-1password-credential-broker（2026-06-15），2026-10-23 |
| npm 类型注释里有 `ApiKey, ... as they land` | report:118 | 成立；但同一处已有 `EnvironmentVariables` | npm @1password/sdk@0.0.0-credential-broker-dev-preview.2 `dist/credential_broker.d.ts:10`，gitHead eefdc47b，发布于 2026-10-06 |
| agent-identity-specs：本地 Broker、SPIFFE、Txn-Token、编码 Agent 是目标场景；4★；2026-07-16 建仓 | report:60、:64 | 成立 | GitHub API 与草案 @a050798 :261、:314-315、:230（“coming soon”），2026-10-23 |
| 1Password for Claude “没有常驻授权” | report:58、:62 | 成立 | support.1password.com/1password-claude-security/（“There are no standing approvals”，发布于 2026-08-17） |
| 合作方：Muse、Grok Bot 逐步推出；Duet、ChatGPT Work、dots、Townie 即将支持；另有 9 家 | report:23 | 成立（9 家：Instinct、Browserbase、Browser Use、Dana、KERNEL、Perplexity、Ramp、Tomo、Wajo） | 产品页、博客、新闻稿，2026-10-23 |
| “有现成的 2 亿企业客户” | report:75 | **错误**：是 20 万 | 新闻稿 “over 200,000 businesses”，2026-10-23 |
| 手机端审批“还在开发” | report:33、:75 | 部分错误：合作方 App 内审批已经可用 | approval.md 表格；faq.md “Is mobile approval supported?”，2026-10-23 |
| Session Bridge / Nitro Enclave 与本产品的关系 | report:35 | 措辞基本克制；但“未公开”不准确，partner security.md 已经写明 enclave 解密 | partners/security.md；support.1password.com/confidential-computing-security/（发布于 2026-10-06） |
| 能力格“编码 Agent 现成路线会把明文交给进程”（§2.4 Environments 行） | report:59 | **不完整**：OpenShell 路线不交明文 | 1password.dev/environments/nvidia-openshell.md；博客 2026-09-28 |
| 能力格“个人版审计未公开” | report:77 | 成立（partner 文档中没有；Events API 只有 Business 事件） | partners/*.md 全文检索；events-api/beta/audit-events.md :63、:281 |
| Rekey：回显封口有“10-05 fixture 实测” | report:73 | **错误**：实测出自 0.3.0-alpha.2 fixture 12/12 | docs/releases/v0.3.0-alpha.2.md:22-23 |
| Rekey：写操作逐次审批，或最长 8 小时时间窗 | report:74 | 成立（默认读允许、写审批） | local_calls.rs:821、ipc.rs:1305、user-guide.md:109 |
| Rekey：审计提交失败则拒绝执行 | report:77 | 成立（源码） | rekey-vault/src/authority/audit.rs:63-87 `fault_on_audit_failure` |
| Rekey：任何本机 Agent 都能用 / 能区分 Agent | report:72、:74 | 前半成立；但调用方识别可伪造，不是边界 | spec 2026-10-05 :49；README.md:64 |
| 1P 社区“按调用、远程审批”需求 9 位以上 | report:89、:111 | 成立（帖内非员工作者 10 人，另有 kovyrin 博客） | 1password.community 帖 24119（14 条回复），2026-10-23 |
| Grok Bot“10–20% 的时候能用”是对这次发布的反应 | report:87 | **归属错误**：帖子开于 2026-09-27，针对的是旧版 service-account connector | forum.cursor.com/t/173142.json |
| TechCrunch 转述 Axios：美国银行在检测 Agent 活动 | report:84 | 成立 | techcrunch.com 2026-10-22 原文 |

## 高发错误清单逐项

1. 基线：发现问题，见必须改第 8 条。
2. 漏了自家：发现问题，见建议改第 6 条（lab 下已有 1Password Connect 来源）。
3. 只看 README 就说“没有”：发现问题。§2.4 只写了 Environments 的明文路线，漏了同一文档站里的 OpenShell，见必须改第 1 条。
4. 正文里的概括句没查过：发现问题。“关键防护都靠合作方自觉”见建议改第 2 条；“只能通过浏览器扩展”见必须改第 6 条。
5. 对自己宽松：发现问题，见必须改第 2、3 条，以及建议改第 8 条。
6. 指标归错类：发现问题。客户数放进了“审批体验”，见必须改第 4 条。
7. 用过时说法：发现问题。用户声音用的是发布前旧集成的帖子，见必须改第 5 条。
8. 计数手数：合作方 9 家、社区 9 人以上、HN 帖子都核对无误。“成规模”标签依赖的计数有误归属，见必须改第 5 条。媒体“8 家以上”与笔记中的 10 行一致，查了，没问题。
9. 改完不同步：发现问题，笔记之间、笔记与正文不一致，见建议改第 12 条。
10. 新写的内容没回源：本轮是首审，不适用。处置时新补的 OpenShell、Bitwarden 内容必须回源。
11. 只处置必须改：首审，不适用。处置时建议改也要逐条写。
12. 用截断的输出证明“没有”：查了，没问题。FAQ、partners 全文我都完整抓取并检索过。笔记里的“没有 MCP/A2A”和我检索的结果一致。
13. 把已关闭的问题当成现状：发现问题，见必须改第 5 条。另外，“长 URL 阻塞同步（官方已修）”在笔记里已标注为已修，没有问题。
14. 只找支持、不找反例：发现问题。“没有评论把它和 Rekey/OneCLI 联系起来”没有做反例搜索（Bitwarden 官方已经把密码库和 OneCLI 放在一起讲），见建议改第 7 条。Rekey 卖点的绕过实验也没写：同用户进程可以直接调用 agent.sock 并伪造调用方；T1 会交出临时凭据；基础模式的签名私钥同用户可读（激活仍需保险库密码）。§3 只在“部署与信任”一行提了 L1-dev。§6.2 列卖点时应该同时写出这些绕过面，见必须改第 3 条。
15. 产出离开工作区就读不懂：check_report 没有命中，但有读者打不开的引用，例如自编的 FAQ Q 号、没有链接的“上轮 02”，见建议改第 11 条。
16. 只看默认配置就说竞品“没有”：发现问题。SDK 的读模式和环境变量能力是需要申请才开的可选路径，报告一处说“只能扩展”、一处说“SDK 交明文”，混在一起，见必须改第 6、7 条。30 天是首发默认值，可配置寿命已在计划中，见建议改第 3 条。
17. 建议和我方自己声明的边界冲突：发现轻微问题。§6.2 要“讲成机制”，但 README:64 已声明同用户恶意程序不在保护范围内。宣传口径必须同时写出 L1-dev 边界，见必须改第 3 条。

## 对 6 个问题的简答

1. 是否回答原问题：回答了“这次发布是什么”。但漏了 OpenShell，导致“有没有类似功能”一问只答对一半。§5 的支付和身份类内容略有扩大范围。
2. 事实抽查：23 条，其中错误或归属错误 4 条，部分错误 3 条，见上表。
3. 对 Rekey 是否宽松：是，见必须改第 2、3、8 条。“Rekey 更强”只能限定为“规则维度更细、机制设计更强制（源码，未在 0.5 实测）”。
4. 高发错误：见上。
5. 遗漏：OpenShell（会改变结论）、SDK environmentVariables、Bitwarden 与 OneCLI 的集成、官方 Codex 文章、Rekey 自家的 lab 1Password 来源。
6. 读者负担：FAQ 编号、无链接的引用、§5 偏长，见建议改第 11、13 条。

## 处置（作者）

必须改：
1. 已改。作者回读了 OpenShell 官方文档（Agent 只拿占位符；可设 host/端口、是否允许写、TTL；只在连接时授权；文档未提路径/方法规则或逐次审批）。§1、§2.4、§3（新增 OpenShell 列）、§6.2、§7 已重写，“Agent 不碰 Key”不再写成 Rekey 独有。
2. 已改。回显封口的证据改为“0.3.0-alpha.2 修复源码的本机 fixture 12/12，0.5 未复测”，并链接 sealing.rs。判定降为“设计更细、更强制（依据 Rekey 源码）”。
3. 已改。§1 和 §3 补上 Rekey 的对应弱点：调用方识别可伪造、读默认免审批、规则默认 90 天；“区分 Agent”一栏判两边都做不到。
4. 已改。客户数改为“20 万家以上企业客户”，移到成熟度一行。新闻稿原文是“trusted by over 200,000 businesses”，作者先前读到过却抄错了。
5. 已改。发布前 Grok Bot 旧 connector 的反馈单列，注明机制不同；针对这次发布本身的用户声音如实写为“少量，零星”。
6. 已改。改为“默认且推荐走浏览器扩展；浏览器之外的场景经安全审查后用 SDK，会拿到明文”，并引用 FAQ 原句。
7. 已改。§2.4 写明 Credential Broker 的 SDK 已有 `environmentVariables.read()`（会交出明文），`ApiKey` 仅出现在注释；§7 触发条件相应改写。
8. 已改。页首和 §3 写明 Rekey 基线为 main@f7d857a 加未提交改动；CLI 密码批准注明“未提交”。

建议改：
1. 已改：手机端拆成“合作方 App 内可用（8.12.42+）”和“1Password 手机 App、网页弹窗开发中”。
2. 已改：§2.3 拆成“机制保证 / 靠合作方”两类。security.md 原文里没有“Agentic Mode”，因此这一项不列为机制保证。
3. 已改：补上“可配置时长 planned”，以及“合作方可以每个会话新建请求”。
4. 已改：主要依据换成 partner security.md（attestation + Noise，中转读不到）；Session Bridge 降为背景，并标“推断”。
5. 已改：作者回读了 Bitwarden 官方博客（2026-03-24，Apache-2.0，alpha；run 会注入环境变量；与 OneCLI 原生集成），写进 §5 和 §6.4。
6. 已改：§6.4 注明 lab 构建已有 1Password Connect 来源（executor.rs:46 处为 `#[cfg(feature = "lab")]`），只适用于 Business 的 Connect Server。
7. 已改：删掉“没有评论把它和 Rekey 联系起来”这句；反例（Bitwarden + OneCLI）写进 §5。
8. 已改：改写为“改签策略可移除单个 Connection，立即生效”。
9. 已改：价格改为“约 $3–6/月”。
10. 已改：§2.4 注明旧版 Agentic Autofill 是每次填充都审批，授权模型不同。
11. 已改：FAQ 编号换成问题原文；“见上轮 02”加了链接；证据列直接链官方页面；审查状态已更新。
12. 已改：devdocs 笔记改为“private beta”；reception 笔记补上官方 Codex 文章链接（作者已回源确认），报告 §2.4 也补了 Codex。
13. 已改：§5 压缩为 Bitwarden 一段，其余合并成一句。

check_report.py 复跑：0 处命中。
