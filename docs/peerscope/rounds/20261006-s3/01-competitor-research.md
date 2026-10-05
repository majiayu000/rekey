# Rekey 同类精品调研 — 20261006-s3

> 阶段 3（复评）+ 补市场层。基线 `majiayu000/rekey@043a020`（v0.3.0-alpha.1）。核查日期 2026-10-06。
> 产品层（功能、性能、安全）沿用 2026-10-05 deep 对比：`.git/codex/evidence/competitive-comparison-20261005/comparison.md`。初始复评没有重跑；后续只复验Rekey的4MiB SSE，见02。

## 证据边界

| 内容 | 来源 | 等级 | 本轮验证 |
|---|---|---|---|
| 发布版与竞品性能/反射/审计 | 10-05固定SHA及原始协议/数据 | E5 | 沿用，未重测竞品 |
| 本机SSE候选 | 13个源码/binary哈希、12格/768次原协议回归 | E5 | 已复验，非发布包或真实provider |
| 候选池与关注度 | 10-06 GitHub元数据、官方README | E2/E3 | 静态快照，star不等于用户数 |
| HN痛点 | 6帖、114条相关评论 | D1 | 仅一个平台，不证明用户更偏好 |
| Relay、Bitwarden集成与Keychains | 官方文档/公告 | E2 | 已读取，未运行 |

## 1 结论

- **产品层没有变化**：10-05 之后，Rekey 的发布版和三个直接竞品的固定版本都没有改动功能代码（见 §3），上轮的判定原样沿用。
- **市场层是这次的主要发现**：
  - 采用度：Rekey 是 `缺口` [E3]。0 star，已有公开 alpha release，但未检索到 HN 发布帖；同类的 OneCLI 有 3,559 star，Agent Vault 有 2,306 star。
  - 定位：用户在 HN 上对“凭据代理”最集中的质疑是“代理挡住了 key 泄露，却挡不住 agent 拿着代理去乱用”[D1]。Rekey 的固定动作、参数授权、审批和反射封口正好回答这个问题。这是 Rekey 最值得讲的差异点，但还没有讲出去。
  - 品类拥挤度：本轮候选池有22个产品/替代物，其中7个直接竞品（见 §4）。“agent 看不到 key”已是多家公开宣称的定位；未逐家实测。

## 2 范围、版本与覆盖率

| 对象 | 版本 | 本轮做了什么 |
|---|---|---|
| Rekey | `043a020` / v0.3.0-alpha.1；`origin/main` 自此无新提交 | 核对未合并分支；拉采用度 |
| Agent Vault | `872578e`（10-05 固定），默认分支 0 个新提交；最新 release v0.40.0（2026-10-01） | 变化检查、采用度 |
| KeyFence | `672cdef`，0 个新提交；v0.4.0（2026-09-20） | 同上 |
| OpenBao | `2fff36b`，1 个新提交（发布博客，非功能）；v2.7.1（2026-10-01） | 同上 |
| 1Password | 闭源，开发者面 | 官方页面检索 |
| 新增候选 | 见 §4 | 采用度 + 公开描述 |

覆盖率：
- 候选 22 个：直接竞品 7、相邻基础设施 5、agent 工具授权平台 4、密码管理器 3、替代物 3。
- 深挖沿用上轮的 5 个。新候选看了GitHub元数据、README与发布帖；后续补Relay、Bitwarden、Keychains官方文档，没有读新候选源码。
- 用户声音：HN 上 12 个相关发布帖，抽取其中 6 个帖子下的 189 条评论（剔除无关帖后），筛出 114 条相关评论做编码。
- 初始复评eval：0，发布版比较沿用10-05；后续Rekey SSE回归12格/768次，非新增竞品性能排名。

## 3 和上轮相比（复评）

| 项 | 上轮（10-05） | 本轮 | 变化 | 证据 |
|---|---|---|---|---|
| Rekey 发布版功能 | 85 项主题：54 已实现 / 9 部分 / 22 缺失 | 同 | 无。mTLS 动作、SSH 签名、SSE 让步、账本优化都在未合并分支上（`codex/competitive-*`），不计入 | `git merge-base` 核对 [E3] |
| Rekey 4MiB JSON p95 | 基线 207.9ms；优化分支 20.6ms | 发布版仍是 207.9ms | 无 | 10-05 raw [E5] |
| Rekey 4MiB SSE | 0/192 成功 | 同 | 无 | 10-05 raw [E5] |
| Agent Vault / KeyFence / OpenBao 功能 | 见 10-05 矩阵 | 同 | 无（0 / 0 / 1 个非功能提交） | `evidence/peer-changes-since-20261005.json` [E3] |
| 竞品池 | 4 家 | 22 个候选 | 新增 OneCLI、Kontext CLI、AgentSecrets、Aegis、agentgateway 等 | §4 |

## 4 竞品地图与采用度

采用度取自 `adoption_stats.py`（2026-10-06），见 `evidence/adoption.jsonl`。star 只代表关注度，不等于用户数。

| 类别 | 产品 | 形态 | 采用度 | 和 Rekey 的关系 |
|---|---|---|---|---|
| 直接 | OneCLI | 开源 + 云；现首屏定位为“团队 agent harness，一个网关守住 key” | 3,559★；90 天 57 提交；HN 两次上首页（161、110 分） | 本候选池中star较高的直接竞品；README首屏定位为团队agent平台 |
| 直接 | Agent Vault（Infisical） | 开源 HTTPS_PROXY 代理 + 凭据库，研究预览 | 2,306★；HN 156 分；Infisical 品牌 | 上轮深挖；透明代理，不限动作 |
| 直接 | Kontext CLI | 开源 Go，面向编程 agent 的凭据代理 | 223★；HN 70 分 | 卖点是“访问留痕”，和 Rekey 的审计重叠 |
| 直接 | AgentSecrets | 开源，“零知识”凭据设施 | 181★ | 同类 |
| 直接 | passless | 开源，WebAuthn 凭据代理，人和 agent 都用 | 104★；90 天 184 提交 | 相邻：硬件密钥方向 |
| 直接 | Aegis（getaegis） | 开源，本地透明代理 | 14★；最后推送 2026-08-06，90 天 2 提交 | 近两个月不活跃；不能推断项目已停更 |
| 直接 | KeyFence | 开源 | 4★ | 上轮深挖 |
| 相邻 | agentgateway | 开源 agent/MCP 网关，含出站凭据注入 | 5,178★；90 天 764 提交 | 企业网关方向，可能顺手覆盖“注入凭据” |
| 相邻 | OpenBao / HashiCorp Vault | 通用 secret 管理；Vault 有 MCP server | 8,315★ / 36,342★ | 上轮深挖 OpenBao；不是代执行 |
| 相邻 | WorkOS Relay | SaaS，代用户调第三方 API，凭据在 WorkOS 侧替换 | 未取到采用度 | 官方 Relay 文档确认托管代调用，early access；WorkOS API key 仍需保护 [E2] |
| 相邻 | Keychains.dev | SaaS 凭据代理 | Product Hunt发布日期未补一手核验 [E1] | [官方quickstart](https://keychains.dev/docs)与[威胁模型](https://keychains.dev/docs/threat-model)自述云端注入、scope批准与scope内误用边界 [E2]，未实测 |
| 工具授权平台 | Nango | 开源 OAuth/API 连接层，900+ API | 12,528★ | 多租户 SaaS 场景，不是本机个人 |
| 工具授权平台 | Arcade / Composio / Auth0 Token Vault | 托管的 agent 工具授权 | Arcade MCP 1,045★；composio.dev Tranco 36,840 | 面向产品开发者，不是个人 |
| 密码管理器 | 1Password | Environments + MCP server + Agentic Autofill | 1password.com Tranco 1,999 | 平台方：已在做“agent 不看到密码”[E2] |
| 密码管理器 | Bitwarden、Keeper | 通过 OneCLI 集成 / Secrets Manager MCP | — | Bitwarden–OneCLI 有官方文档；未实测 [E2] |
| 替代物 | `.env` + 事后扫描（如 Sieve） | 现状 | HN 18 分 | 真正的头号对手是“继续用 .env” |
| 替代物 | 自己搭 mitmproxy / OS keyring 替换 | DIY | HN 评论里至少 5 人说自己搭过 | 说明需求真实，也说明门槛低 |
| 替代物 | 沙箱（Zerobox、yolo-cage、容器） | 隔离而非代理 | Zerobox HN 141 分 | 很多人用“隔离”代替“代理” |
| 替代物 | fly.io tokenizer | 旧的认证代理 | HN 评论引用 | “这事早就有”论据来源 |

## 5 用户声音：痛点簇

来源只有 HN（Reddit 匿名接口 403，其他平台需要登录态，没有采），所以每簇最高 D1。作者已哈希，原文在 `evidence/voc/hn_broad.json`。

| # | 痛点簇 | 独立作者 | 代表原话（节选） | 对 Rekey 的含义 |
|---|---|---|---|---|
| C1 | 代理只防 key 泄露，不防 agent 拿代理去乱用或经响应带出数据 | ≥8 | “if they can still make arbitrary API calls…”；“prompt injected into using the services it has (fake) keys” | Rekey 的固定动作、参数 schema、审批、反射封口直接回应这一簇 [D1] |
| C2 | 真正新的是“敏感动作需要人确认” | 2 | “What seems genuinely new … is the approval layer” | Rekey 已有审批收件箱（#51）[E3] |
| C3 | 透明代理要装 CA、改 HTTP_PROXY，Node 等不遵守代理，忘开就失效 | 4 | “Fails open in the most insecure method ever” | Rekey 不做 MITM，通过 MCP/CLI 调固定动作，没有这类问题；代价是每个动作要注册 |
| C4 | “直接用 Vault / AWS Secrets Manager 不就行” | 4 | “Don't see any reason to use this over vault.” | 要在一句话里讲清“Vault 管存放，Rekey 管执行” |
| C5 | 信任只是转移到另一个黑盒；同机的 agent 可能逆向拿到 vault | 4 | “this feels like vpn all over again”；“reverse engineer many things” | Rekey 当前确认下限是 L1-dev（历史 G1/G2 不是当前分级），这一簇会直接问到 Rekey |
| C6 | 身份、OAuth 刷新、WebSocket 鉴权等边角 | 4 | “token refresh endpoint then the response…” | Rekey 无 WS；OAuth 在 lab |
| C7 | 很多人自己搭了一套 | ≥5 | airut、agent-creds、mitmproxy 自建 | 需求真实，但用户愿意 DIY |

## 6 产品层判定（沿用 10-05，未重跑）

| 维度 | 对 Agent Vault / KeyFence | 证据 |
|---|---|---|
| 凭据反射 | 优势：10-05 反射 probe 中两家都把注入值泄漏到响应，Rekey 封口 | [E5] |
| 审计失败处理 | 优势：Rekey 解密前先提交审计，失败即停；两家 probe 显示继续执行 | [E5] |
| 动作与参数限制 | 源码差异：Rekey 固定 origin/method/path + schema；Agent Vault 到host/path，KeyFence还有限定method/size/content-type；未跑业务场景，优势判定不可验证 | [E3] |
| 小响应延迟 | 缺口：1KiB JSON p95 3.29ms 对 1.69 / 2.69ms | [E5] |
| 4MiB 流式响应 | 缺口：0/192 成功，两家全部成功 | [E5] |
| SSH / mTLS / PKI / 团队 / HA | 缺口：发布版没有，分支在做 | [E3] |
| WebSocket / HTTP2 | 缺口 | [E3] |

候选补充（不改发布版基线）：`2e1a152` 已有 `optimized-v6` 完整432格复测，4MiB text/tool SSE 在 c1、c4 各192/192成功；不是“候选尚未验证”。其整合与本轮复验见 [02](02-my-plan.md)。

市场层判定见 §1：采用度为缺口 [E3]；定位差异点有用户需求支撑 [D1]。

## 7 可借鉴 / 不宜照搬

- **可借鉴**
  - OneCLI 和 Agent Vault 接已有密码库（Bitwarden、Infisical），降低迁移成本。
  - Kontext 把“谁在什么时候用了哪个 key”作为卖点，正好是 Rekey 已有的审计能力。
- **不宜照搬**
  - 透明 MITM 代理：C3 显示它带来 CA 和代理配置的麻烦，也和 Rekey“固定动作”的安全模型相冲突。
  - OneCLI 转向团队平台：和 Rekey“个人先行”的方向不一致（见 v3 方向决定）。

## 8 关键事实核验

| 事实 | 影响哪条结论 | 来源与日期 | 结果 |
|---|---|---|---|
| Rekey 发布版 = `043a020`，`origin/main` 之后无新提交，`competitive-*` 分支未合并 | §3 产品层无变化 | `git log`、`git merge-base`，2026-10-06 | 成立 |
| 三家竞品自 10-05 固定版本后没有功能提交 | §3 沿用判定 | GitHub compare API，2026-10-06 | 成立（OpenBao 1 个发布博客提交） |
| Rekey 0 star，OneCLI 3,559、Agent Vault 2,306 | §1 采用度缺口 | GitHub API，2026-10-06 | 成立 [E3] |
| OneCLI 首屏定位已变为“团队 agent harness” | §4、§7 | README @ HEAD，2026-10-06 | 成立 |
| HN 上没有 Rekey 的发布帖 | 认知层缺口 | HN Algolia `query=rekey`，2026-10-06 | 成立（20 条命中均与本项目无关）[E3] |
| Aegis 近两个月不活跃 | 活跃度观察 | GitHub `pushed_at` 2026-08-06，90 天 2 提交 | 成立（只能说“近两个月不活跃”） |
| 1Password 已做 agent 不看密码的能力 | 平台方风险 | 1password.dev / 官方社区公告 | 成立 [E2]，未实际使用 |
| WorkOS Relay 2026-08-06 发布 | 相邻托管方向 | [WorkOS 官方原文](https://workos.com/blog/credentials-out-of-agent-context)及[Relay 文档](https://workos.com/docs/pipes/relay)，2026-10-06 读取 | 官方自述 2026-08-06 推出，当前 early access；未实测 [E2] |
| Bitwarden 与 OneCLI 集成 | 平台方风险 | [Bitwarden 官方公告](https://bitwarden.com/blog/introducing-agent-access-sdk/)，2026-03-24；2026-10-06 读取 | 存在集成的官方声明成立；Agent Access SDK 本身的 env 注入不能混同 OneCLI 代调用 [E2]，未实测 |
| Keychains.dev有官方凭据代调用与scope限制文档 | 候选定位、C1边界 | [quickstart](https://keychains.dev/docs)与[threat model](https://keychains.dev/docs/threat-model)，2026-10-06读取 | 官方声明成立[E2]，未实测；Product Hunt具体日期仍E1 |
