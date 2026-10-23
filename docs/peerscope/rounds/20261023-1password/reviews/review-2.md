# 独立审查 2：1Password for Agents 调研（2026-10-23）

审查对象：`report.md`（按 review-1 重写后）、`evidence/devdocs/notes.md`、`evidence/reception/notes.md`、`reviews/review-1.md` 末尾“处置（作者）”。
核对方式：2026-10-23 匿名抓取（curl UA `peerscope-review/0.1`；1password.com 博客 curl 超时，改用 WebFetch 读取），未登录任何账户。一手来源：1password.dev 的 `nvidia-openshell.md` 和 partners 下 `security/faq/approval/sdk/fill.md`；1password.com 的 OpenShell 与 Codex 博客；bitwarden.com 博客；NVIDIA OpenShell 文档（latest = v0.1.5 的 `how-it-works/providers/profiles.md` 和 `llms.txt`，以及 dev 版 `manage-policies`、v0.0.116 版 `policy-advisor.md`）；Rekey 仓库（HEAD f7d857a 加 `git diff`）。
脚本：`scan_claims.py` 报 0 条强结论；`check_report.py` 没有命中。

## 总评

**改完再交付。** 上轮 8 条必须改、13 条建议改，报告正文全部落实了，新写的内容大部分也和 1Password 的页面一致。但新补的 OpenShell 段只读了 1Password 那一页，没有读它自己链出去的 NVIDIA OpenShell 文档（对应高发错误第 3、16 条）。NVIDIA 官方文档写明 OpenShell 支持 L7 方法/路径规则、按调用二进制匹配、OCSF 结构化日志，还有 Policy Advisor（规则变更走人工审批）。这样一来，§1 第 2 条、§3 的“规则粒度 Rekey 更细”、§6.2 的差异点、§7 的第 1 条触发条件都站不住，需要再改一轮。还有一点：密钥会被转交给 OpenShell 网关保管（custody），这一点没写。

## 上轮处置逐条核对

### 必须改

| # | 上轮问题 | 结果 | 依据 |
|---|---|---|---|
| 1 | 漏了 OpenShell | **形式上落实，内容不准** | §1:12、§2.4:61、§3 新列、§6.2、§7 都已补写。但 OpenShell 的能力被低估了，见本轮必须改第 1 条 |
| 2 | 回显封口证据出处 | 落实 | report:79 已改为“0.3.0-alpha.2 修复源码本机 fixture 12/12，0.5 未复测”，与 `docs/releases/v0.3.0-alpha.2.md:22-23` 一致；sealing.rs 链接在 f7d857a 可访问（HTTP 200） |
| 3 | 对自己宽松（调用方可伪造、读默认允许、90 天） | 落实 | report:14、:81、:82；spec `2026-10-05-rekey-agent-call-model.md:49` 原文“同用户下这种识别可以被伪造，它不是安全边界”；`docs/user-guide.md:25,109`（HEAD 里分别在 :25、:107）为“读允许、写审批”和“默认 90 天” |
| 4 | 客户数 | 落实 | report:88“20 万家以上企业客户”，放在“成熟度与分发”一行 |
| 5 | Grok Bot 旧 connector 的反馈算错归属 | 落实（措辞有小问题） | report:99-100 已单列旧 connector 的反馈。“零星”和页首自己的定义冲突，见建议改第 1 条 |
| 6 | “只能扩展” | 落实 | report:28 引了 FAQ 原句，与 faq.md:224 一致 |
| 7 | SDK environmentVariables | 落实 | report:62、:123 |
| 8 | 基线 | 落实 | report:7、:73、:85-86；`git diff crates/rekey-domain/src/ipc.rs` 确认 `ProofKind::Password` 是未提交改动 |

### 建议改

| # | 结果 | 依据 |
|---|---|---|
| 1 手机端拆分 | 落实 | report:35 与 faq.md:140、approval.md:42-45 一致（iOS/Android 合作方 App 内 8.12.42+ 可用；1Password 手机 App 直接打开链接和网页弹窗开发中） |
| 2 机制保证 / 靠合作方 | 落实 | report:44-52 与 security.md:19、21、23、31-34 一致；security.md 里确实没有“Agentic Mode”，作者的取舍正确 |
| 3 可配置时长 planned、按会话新建请求 | 落实 | report:14、:50、:69；approval.md:210-211 |
| 4 Session Bridge 降为背景 | 落实 | report:36-38 |
| 5 Bitwarden + OneCLI | 落实（一处措辞偏满） | report:106；见建议改第 3 条 |
| 6 lab 1Password Connect 来源 | 落实 | `executor.rs:46-47` 是 `#[cfg(feature = "lab")] pub(crate) mod onepassword_source;`，文件头为“One fixed public Connect item” |
| 7 删“没人把它和 Rekey 联系起来” | 正文落实；**笔记未同步** | reception notes:82 仍保留原句，见建议改第 2 条 |
| 8 改签策略移除单个 Connection | 落实 | report:83；main.rs:954“[] revokes all local access”（HEAD 同行） |
| 9 价格 $3–6 | 落实 | report:87 |
| 10 旧版每次填充都审批 | 落实 | report:59 |
| 11 读者负担 | 落实 | FAQ 改用问题原文；`../20261022-s3/02-my-plan.md` 有链接，且文件存在；审查状态已更新（report:128） |
| 12 笔记内部不一致 | 落实（两处已改） | devdocs:70“private beta”；reception:71 已有 Codex 官方链接。另有新的不同步，见建议改第 2 条 |
| 13 §5 压缩 | 落实 | report:105-107 |

## 必须改

1. **OpenShell 的规则能力被低估了，§1、§3、§6、§7 跟着偏了。**
   - 位置：report:12（“文档没有提到路径或方法级规则……Rekey 的差异要落在规则粒度”）、:61（§2.4 OpenShell 行）、:80/:82/:84（§3 OpenShell 列的规则粒度、区分 Agent、审计三格）、:91（判定“规则粒度……Rekey 的设计更细”）、:112（§6.2）、:115（§6.5）、:121（§7 第 1 条触发条件）。
   - 问题：1Password 那页确实只让用户设 host、端口、是否允许写和 TTL。但它同时写明，占位符只在“the active network policy”匹配时才替换，并让读者去看 OpenShell 的 policy 文档。作者没有沿着这个链接读 NVIDIA 文档，就把“1Password 页面没写”当成了“OpenShell 没有”。
   - 证据（NVIDIA 官方文档，2026-10-23 读取）：
     - `docs.nvidia.com/openshell/latest/how-it-works/providers/profiles.md`（v0.1.5）:76-83 列了静态凭据替换必须全部通过的检查：“The calling binary and destination are allowed”；“The host, port, and canonical request path match the credential binding”；“The HTTP method, path, or protocol operation is allowed when L7 inspection is configured”；以及“The credential has not expired”。
     - 同页的 GitHub profile 示例里有 `rules: - allow: { method: GET, path: "**" }`，以及按 path 拆分的 `/graphql` 端点。
     - `manage-policies`：`read-only` 预设只允许 GET、HEAD、OPTIONS，`enforce` 拦截其余请求；被拒绝的请求会记录 method、path 和原因。
     - `llms.txt`（latest）列出了 Policy Advisor（Agent 被拦后提出窄规则，由开发者在沙箱外批准，可选的 auto 模式在 prover 无增量时自动批准），以及 OCSF 结构化事件和 JSON 导出（面向 SIEM）。
     - 1Password 文档 `nvidia-openshell.md` 写明“1Password transfers custody of the Environment's secrets to OpenShell for a defined time-to-live”；OpenShell 博客（2026-09-28）也写了“OpenShell has custody of the credentials for the configured TTL”。
   - 改法：
     - §1 第 2 条改成：“1Password 的配置界面只设 host/端口/读写/TTL，并在连接时授权一次；但底层 OpenShell 自身支持按方法/路径的 L7 规则、按调用二进制匹配、OCSF 审计日志，以及对规则变更的人工审批（Policy Advisor）【NVIDIA 官方文档，未实测】。它没有按每次调用审批。密钥在 TTL 内交由 OpenShell 网关保管。”
     - Rekey 的差异改为：写操作逐次审批（带时间窗）；不需要沙箱、不需要账户；密钥不离开本机保险库（不交给第三方网关保管）；签名策略加审计失败即拒绝。**不要再把“规则粒度更细”当差异点**，最多写成“粒度相当，Rekey 是签名策略，OpenShell 是网关策略”。
     - §3 OpenShell 列：规则粒度写“host/端口/路径/方法（L7，需配置 profile 或 sandbox policy），按二进制”；审计写“OCSF 结构化日志，可导出”；区分 Agent 写“按沙箱挂载 provider、按调用二进制匹配（文档，未实测）”。这一点很可能比 Rekey 可伪造的调用方识别更强，判定“区分 Agent：两边都做不到”需要改。
     - 判定“规则粒度、写审批、本机审计：Rekey 更细、更强制”拆开：规则粒度改为持平；写操作逐次审批 Rekey 有、OpenShell 没有；审计两边都有，Rekey 是失败即拒绝执行（源码），OpenShell 是 OCSF 日志（文档）。
     - §7 第 1 条触发条件中“路径/方法级规则”已经满足，删掉。只保留“OpenShell 或 Environments 加上按调用审批”，以及“1Password 配置界面直接暴露方法/路径规则”。
     - §6.5“OpenShell 只在连接时批准一次，还没做到这一点”保留，但要加上 Policy Advisor 审批的是规则变更、不是每次调用。

## 建议改

1. **用户声音的等级定义和用法冲突。** report:5 定义“成规模”为“多作者或多平台”。按这个定义，report:99 的簇（4 位作者、HN 和 MacRumors 两个平台）应该算成规模，正文却写“零星”。report:100 的 7 位作者是多作者，也没有标等级。reception 笔记 :39 把这一簇标为 D2。建议把定义改成“成规模 = 多作者**且**多平台”，或者对这一簇按定义如实标注，正文、笔记、定义三处保持一致。

2. **笔记没同步（高发错误第 9 条）。** report:136 把两份笔记作为“原始笔记”链接出去，但 reception 笔记与正文结论不一致：
   - :82 仍写“没有搜到媒体或评论把两者联系起来”，而这句已从正文删掉，Bitwarden 官方博客就是反例。
   - :54 的 Bitwarden 一行没有提 OneCLI 集成。
   - :84 第 (3) 点用簇 C/D/E（发布前的旧 connector）论证“大厂集成”的缺口。
   - :99 结论的唯一触发点是 Credential Broker，没有 OpenShell。

   建议逐条改，或者在笔记顶部加一句“结论以 report.md 为准，§5 和结论已被取代”。

3. **Bitwarden + OneCLI 的措辞比原文满。** report:106 写“Agent 和模型都看不到”，官方原文是对冲的“helps ensure API keys are never exposed to the AI agent or the LLM”。建议改成“官方称有助于确保 Agent 和模型看不到 Key”。

4. **OpenShell 的“依赖”格可补一项。** report:85 写的是 1Password 账户、桌面 App（Mac/Linux）和 OpenShell 沙箱。OpenShell 文档要求“running gateway”，且 Agent 必须在 OpenShell 沙箱镜像里运行（`--from <image>`）。这是 Rekey“照常启动 Agent”的反差点，可以写进 §6.2。另外，1Password 文档只写了“A 1Password account”，没有限定个人还是 Business；博客的 CTA 指向 Business 试用。建议在 §3 注明“账户类型未明确”。

## 事实抽查表

| 事实 | 位置 | 结果 | 来源与日期 |
|---|---|---|---|
| OpenShell：Agent 只拿占位符，网关在沙箱外替换 | report:12、:61 | 成立 | 1password.dev/environments/nvidia-openshell.md（“Inside the sandbox, the agent only ever works with placeholder values”），2026-10-23 |
| OpenShell：可设 host/端口/是否允许写（默认只读）/TTL | report:12、:61、:80 | 成立（指 1Password 配置界面） | 同上，“Allow writes… If you leave it unselected, the provider allows read-only access” |
| OpenShell：连接时授权一次 | report:12、:81 | 成立 | 同上（authorization prompt 列出 provider、variables、destinations、expiry）；博客“approves the connection after reviewing” |
| OpenShell beta，2026-09-28 | report:12、:61 | 成立 | 1password.com/blog/1password-nvidia-openshell（September 28, 2026，“now in beta”） |
| “文档未提路径/方法规则” | report:12 | **对 1Password 页面成立，对 OpenShell 不成立** | NVIDIA profiles.md（v0.1.5）:76-83、示例 `allow: {method: GET, path: "**"}`，2026-10-23 |
| OpenShell“审计未说明” | report:84 | **不成立** | NVIDIA llms.txt：Sandbox Logging、OCSF JSON Export；manage-policies：拒绝请求记录 method/path/reason |
| OpenShell“区分 Agent 未说明” | report:82 | 不完整：按调用二进制匹配、按沙箱挂载 provider | NVIDIA profiles.md:80“The calling binary and destination are allowed” |
| 密钥在 TTL 内由 OpenShell 保管 | 报告未写 | 遗漏 | nvidia-openshell.md“transfers custody”；博客“has custody of the credentials” |
| security.md：只有本人能创建授权（vault key） | report:13、:44 | 成立 | partners/security.md:19 |
| security.md：enclave 解密，中转读不到 | report:13、:45 | 成立 | security.md:23 |
| security.md：token 不能列条目、不能批准 | report:46 | 成立 | security.md:21 |
| 靠合作方：填充窗口、token 进浏览器、多 Agent 共用、常驻访问 | report:47-50 | 成立 | security.md:31-34 |
| 30 天、可配置时长 planned、可按会话新建请求 | report:14、:50、:69 | 成立 | approval.md:210-211 |
| 手机审批：合作方 iOS/Android App 内可用，1P 手机 App 和网页开发中 | report:35 | 成立 | faq.md:140；approval.md:42-45 |
| SDK `logins.read()`“Your code receives the values” | report:51 | 成立 | sdk.md:20、:135 |
| Codex 官方文章：MCP 不返回明文 | report:60 | 成立（2026-05-20，“the MCP server does not return secret values”；应用经本地挂载 `.env` 取值） | 1password.com/blog/1password-trusted-access-layer-for-openai-codex |
| Bitwarden Agent Access SDK：2026-03、Apache-2.0、早期 alpha、run 注入环境变量、与 OneCLI 原生集成 | report:106 | 成立；“看不到”原文为“helps ensure” | bitwarden.com/blog/introducing-agent-access-sdk/（2026-03-24） |
| Rekey 封口：sealing.rs；0.3.0-alpha.2 fixture 12/12；0.5 未复测 | report:79 | 成立 | executor.rs:58 `mod sealing`（非 lab）；docs/releases/v0.3.0-alpha.2.md:22-23；rounds/20261022-s3/02-my-plan.md:61 |
| Rekey 调用方识别可伪造 | report:14、:82 | 成立 | spec 2026-10-05:49 |
| Rekey 读默认允许、写审批、默认 90 天、时间窗最长 8 小时 | report:14、:81 | 成立（HEAD 里同样存在） | user-guide.md:25、:109、:111；`git show f7d857a:docs/user-guide.md` :25、:107 |
| Rekey lab 1Password Connect 来源 | report:114 | 成立 | executor.rs:46-47 `#[cfg(feature = "lab")]`；onepassword_source.rs:1 |
| CLI 密码批准为未提交改动 | report:85-86 | 成立 | `git diff crates/rekey-domain/src/ipc.rs`：`Presence` 改为 `Presence \| Password` |
| 改签策略移除单个 Connection | report:83 | 成立 | crates/rekey-cli/src/main.rs:954 |
| Rekey LLM 模型白名单与预算 | report:80 | 成立 | connection.rs:279“LLM connections require signed model and budget limits”；user-guide.md:145 |
| Rekey 0★、公开 | report:88 | 成立 | GitHub API：private=false，stars=0，2026-10-23 |

## 高发错误清单逐项

1. 基线：查了，没问题。页首和 §3 写明了 f7d857a 加未提交改动，CLI 密码批准也注明了未提交。
2. 漏了自家：查了，没问题。lab 1Password Connect 来源已补。
3. 只看 README 就说“没有”：**发现问题**。OpenShell 只读了 1Password 那一页，没读 NVIDIA 的 profile/policy 文档，见必须改第 1 条。
4. 正文里的概括句没查过：发现问题。“规则粒度、写审批、本机审计 Rekey 更细”这句里，规则粒度和审计两项站不住，见必须改第 1 条。
5. 对自己宽松：上轮的问题已修。本轮“区分 Agent 两边都做不到”对 OpenShell 判得过低，等于相对抬高了 Rekey，见必须改第 1 条。
6. 指标归错类：查了，没问题。
7. 用过时说法：查了，没问题。Grok Bot 旧反馈已单列。
8. 计数手数：查了，没问题。§8“partner 文档 10 页”、合作方 9 家、社区 9 人以上，与笔记一致。
9. 改完不同步：**发现问题**，reception 笔记没有跟着正文改，见建议改第 2 条。
10. 新写的内容没回源：**部分发现问题**。Bitwarden、Codex、security.md 的新内容都回源了，而且准确。OpenShell 只回到 1Password 一层，没有回到 NVIDIA 一手文档。
11. 只处置必须改：查了，没问题。13 条建议改逐条写了处置。
12. 用截断的输出证明“没有”：发现问题。“文档没有提到路径或方法级规则”只基于单页，不足以支撑“OpenShell 没有”。
13. 把已关闭的问题当成现状：查了，没问题。
14. 只找支持、不找反例：发现问题。Rekey 的差异点“规则粒度”没有拿 OpenShell 自己的文档做反证。
15. 产出离开工作区就读不懂：查了，没问题。相对链接都能解析到仓库内文件，等级图例在页首。注意这几个目录目前未纳入 git 跟踪。
16. 只看默认配置就说竞品“没有”：**发现问题**。1Password 的“New profile”界面只有 host/port/读写，但选“Existing profile”或改 sandbox policy 就能用方法/路径规则。
17. 建议和我方自己声明的边界冲突：查了，没问题。§6.2 没有声称防同用户恶意进程。

## 对 6 个问题的简答

1. 是否回答原问题：回答了。§1 第 1、2 条分别回答“这次发布是什么”和“有没有类似的功能”。
2. 事实抽查：25 条。2 条不成立（OpenShell 审计、路径/方法规则），1 条不完整（区分 Agent），1 条遗漏（密钥托管），其余成立。
3. 措辞与证据：§3 判定“规则粒度 Rekey 更细”需要撤回。其余判定都标了“源码 / 只有文档”，匹配。
4. 遗漏：OpenShell 的 L7 规则、OCSF 日志、Policy Advisor、密钥托管给网关。
5. 前提：基线正确。
6. 读者负担：篇幅合适。笔记与正文冲突会误导转发笔记的读者。

## 处置（作者）

必须改：
1. 已改。作者回读了 NVIDIA OpenShell 文档：profiles.md（v0.1.5）列出了五项替换检查，包括调用二进制、host/端口/路径绑定，以及配置 L7 后按方法和路径放行；GitHub 示例里有 `allow: { method: GET, path: "**" }`；没有单次请求的人工批准。llms.txt 提到 Policy Advisor 和 OCSF JSON 导出。
   - §1 第 2 条、§2.4、§3 OpenShell 列（规则粒度、审批、区分 Agent、审计、依赖）、§3 判定、§6.2、§6.5、§7 都已改写。
   - “规则粒度更细”不再作为 Rekey 的差异点。
   - 补上“密钥在有效期内交由 OpenShell 保管”。
   - §7 第 1 条改为“单次调用人工审批”，并新增“配置界面直接暴露方法/路径规则”一条。
   - read-only 预设具体包含哪些方法（GET/HEAD/OPTIONS），作者没有在 llms.txt 摘要里核实到，正文没有引用这一点。

建议改：
1. 已改：保留“多作者或多平台”的定义，按定义如实标注——4 位作者、2 个平台记为“成规模但人数少”，旧 connector 簇（7 位作者）记为“成规模”。
2. 已改：reception 笔记顶部注明“§5 与结论已被 report.md 取代，以 report.md 为准”。
3. 已改：Bitwarden + OneCLI 改为官方的对冲措辞“有助于确保”。
4. 已改：依赖格补上“运行中的网关、Agent 在沙箱镜像里启动、账户类型未明确”；§6.2 加上“Agent 照常启动”这一反差。

check_report.py 复跑：0 处命中。
