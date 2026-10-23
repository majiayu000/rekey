# Rekey 竞品池刷新（discover lane，20261022-s3）

访问日期：全部 2026-10-22（UTC 约 12:50–13:05）。对外请求 UA `peerscope-adoption/0.1`，不带用户身份。

## 取证与口径

- 采用度快照：`adoption_run_20261022.jsonl`（本轮全量 555 行）与 `gh_*.jsonl` / `domain_*.jsonl`（按 kind:name 分文件，已把 20261006-s3 的上轮快照拷进来作基线，脚本自动算 `_delta` / `_per_day`）。基线时间 2026-10-05T18:59Z，间隔约 16.75 天；“两周增速”= `stars_per_day × 14`。
- `commits` 是默认分支近 90 天提交数；“最近 release”是最新 release tag，括号内是该 release 的资产下载数（二进制安装的近似，不是用户数）。
- GitHub 搜索原始结果没有单独存档（命令行直出），复现方法：`gh api search/repositories -f q="<kw> pushed:>2026-07-01" -f sort=stars`，关键词见文末。
- HN：`hn_search_20261022.tsv`（Algolia，`tags=story`，`created_at_i > 2026-08-01`，另有按名字回查的 `name:` 行）。
- 维护者自家仓库：`majiayu000_repos_20261022.tsv`（`gh repo list majiayu000 --limit 300`，共 300 行）。
- `hn:rekey` 显示 4 条 >100 分的 story，这是同名撞车（“rekey”是通用词），不算 Rekey 自己的曝光。
- `domain:keychains.dev`、`domain:alterauth.com` 没有返回任何行，即 Tranco 前 100 万里没有它们。

## 主表

“新”的标准：2026-10-06 之后创建仓库、首次发布，或首次登上 HN（≥50 分）。“上轮”指在 20261006-s3 的 22 个候选里。

| 类别 | 产品 | 链接 | 形态 | 采用度（2026-10-22） | 上手方式 | 面向谁 | 是否新 |
|---|---|---|---|---|---|---|---|
| OSS-直接竞品 | Infisical Agent Vault | https://github.com/Infisical/agent-vault | HTTP 凭据代理 + vault（Go） | ★2402（+96，约 +80/两周），近 90 天 38 提交，v0.40.0（1753 次下载，+1506） | 二进制 / Docker / Infisical 云 | 团队为主，个人也能自托管 | 上轮 |
| OSS-直接竞品 | OneCLI | https://github.com/onecli/onecli | 沙箱化 Agent harness + 凭据网关 | ★3585（+26），75 提交，v2.16.0；Launch HN 2026-08-19 88 分 | Docker / 云 | 团队（README 写 "for teams"） | 上轮 |
| OSS-直接竞品 | AgentSecrets | https://github.com/The-17/agentsecrets | 零知识 secrets CLI + 代理 | ★190（+9），39 提交，v3.3.6 | go install / 二进制 | 个人开发者 | 上轮 |
| OSS-直接竞品 | Kontext CLI | https://github.com/kontext-dev/kontext-cli | CLI 凭据代理 | ★227（+4），166 提交，v1.13.1 | 二进制 | 个人 + 团队 | 上轮 |
| OSS-直接竞品 | passless | https://github.com/pando85/passless | WebAuthn 凭据 broker | ★112（+8），159 提交，v0.20.2（192 次下载） | 二进制 | 个人 | 上轮 |
| OSS-直接竞品 | Aegis | https://github.com/getaegis/aegis | 本机透明代理 | ★14（+0），2 提交，最后 push 2026-08-06，趋于停更 | npm | 个人 | 上轮 |
| OSS-直接竞品 | KeyFence | https://github.com/atgreen/keyfence | 凭据代理 | ★4（+0），46 提交，v0.4.0 | 二进制 | 个人 | 上轮 |
| OSS-直接竞品 | KeyValet | https://github.com/KeyValet/KeyValet | 本机凭据 broker：MCP + 本机网关，Touch ID / polkit / Hello 逐凭据或逐次审批，Agent 只拿到响应 | ★1，82 提交，v0.3.0（9 次下载）；HN 搜不到 | `curl keyvalet.dev/install.sh \| sh` | 个人开发者（macOS/Linux/Win） | **新**（2026-10-07 建仓） |
| OSS-直接竞品 | briefcred | https://github.com/vkend/briefcred | Touch ID 门控的本机 broker：短期凭据、key-swap、MCP 工具 | ★3，242 提交，v0.1.3；HN 搜不到 | `brew install vkend/briefcred/briefcred` | 个人开发者（macOS） | **新**（2026-10-08） |
| OSS-直接竞品 | key-vault-for-llm (kv) | https://github.com/DFanso/key-vault-for-llm | 本机 secrets broker：MCP stdio、TUI、菜单栏，Touch ID / Hello | ★4，139 提交，v1.1.0 | curl 安装脚本 | 个人 | **新**（2026-10-08） |
| OSS-直接竞品 | AskKey | https://github.com/A1mAssist/AskKey | Windows 本机加密 vault + 审批 broker + MCP | ★1，94 提交，v1.0.3 | 下载 .exe 安装包（UAC） | 个人（Windows） | **新**（2026-10-17） |
| OSS-直接竞品 | mintrun | https://github.com/ninja-c9/mintrun | JIT 凭据 minter + 盲 CLI runner + MCP | ★2，184 提交，v0.16.0 | 二进制 | 个人 | **新**（2026-10-15） |
| OSS-直接竞品 | keyleash | https://github.com/h-a-forster/keyleash | 本机加密 vault + 代理，给 Agent 替身 key | ★1，19 提交 | `go install` | 个人 | **新**（2026-10-12） |
| OSS-直接竞品 | secrets-broker (Alino) | https://github.com/Alino/secrets-broker | 逐条命令 Touch ID / Secure Enclave 审批，MCP | ★15，无 release | 源码安装（docs/setup.md） | 个人 | **新**（2026-10-10） |
| OSS-直接竞品 | agent-access-broker | https://github.com/kcosr/agent-access-broker | 集中策略 broker：CLI/HTTP/MCP，审计，导入 MCP/OpenAPI | ★3，533 提交，v0.2.0 | 自托管服务 | 团队 / 管理员 | **新**（2026-10-11） |
| OSS-直接竞品（本轮补漏） | hasp | https://github.com/gethasp/hasp | 本机 secrets broker | ★353，7 提交，v1.0.44（60 次下载）；HN 2026-06-26 2 分 | 二进制 / 官网 gethasp.com | 个人 | 否（2026-04 建仓，上轮漏掉） |
| OSS-直接竞品（本轮补漏） | sigcli | https://github.com/sigcli/sigcli | 认证 CLI + 代理："Give agents access, not your credentials" | ★291，11 提交，@sigcli-cli-v1.7.0 | npm | 个人 | 否（2026-04，上轮漏掉） |
| OSS-直接竞品（本轮补漏） | sallyport | https://github.com/OlegSotnikov/sallyport | Mac vault，经 MCP 替 Agent 执行认证动作 | ★189，0 提交，最后 push 2026-07-19，v0.8.16 | macOS App | 个人（Mac） | 否（2026-07，上轮漏掉） |
| OSS-直接竞品（本轮补漏） | OpenKeylet | https://github.com/omaekumiko2-create/OpenKeylet | 本机密码 / 凭据管理器，供 Agent 经 MCP 使用 | ★129，38 提交，v0.15.0（104 次下载） | 二进制 | 个人 | 否（2026-08，上轮漏掉） |
| OSS-直接竞品（本轮补漏） | claw-wrap | https://github.com/dedene/claw-wrap | 替沙箱内 Agent 带密钥执行 CLI 工具 | ★140，1 提交，v0.6.0 | 二进制 | 个人 | 否（2026-02） |
| OSS-直接竞品（本轮补漏） | earl | https://github.com/mathematic-inc/earl | HCL 操作模板 + OS keychain 的 CLI 代理 | ★113，46 提交，v0.6.4 | cargo / 二进制 | 个人 | 否（2026-02） |
| OSS-直接竞品（本轮补漏） | authsome | https://github.com/agentrhq/authsome | OAuth2 / API Key 凭据网关 | ★97，0 提交，最后 push 2026-07-24 | pip / 二进制 | 个人 | 否，趋于停更 |
| OSS-直接竞品（长尾） | wardn / aquaman / postern / phantom-secrets / cloak / tap-oss | 例：https://github.com/rohansx/wardn | 凭据隔离代理 | ★11–37；aquaman 47 提交，wardn 2 提交 | 多为二进制或 npm | 个人 | 否 |
| OSS-相邻（secrets 平台） | Infisical | https://github.com/Infisical/infisical | secrets 平台（Agent Vault 的母体） | ★29915，4178 提交，v0.167.0；Tranco 89661 | 云注册 / Docker | 团队 / 企业 | 否 |
| OSS-相邻（secrets 平台） | Phase | https://github.com/phasehq/console | "Secrets management for teams and AI agents" | ★930，210 提交，v2.78.1 | 云 / Docker | 团队 | 否（上轮漏掉） |
| OSS-相邻（.env 层） | varlock | https://github.com/dmno-dev/varlock | "AI-safe .env"：给 Agent 看 schema，不给 secret | ★4809，188 提交，varlock@1.23.0（858 次下载） | npm / brew | 个人开发者 | 否（上轮归入“.env+扫描器”，未单列） |
| OSS-相邻（个人密码库） | keypaste | https://github.com/notinferred/keypaste | 兼容 KeePass 的密码库，面向用 AI Agent 的人 | ★413，749 提交 | 桌面 App | 个人 | 否（2026-09-05） |
| OSS-相邻（网关） | agentgateway | https://github.com/agentgateway/agentgateway | Agent / MCP 网关 | ★5487（+309，约 +258/两周），881 提交，v1.6.0（21108 次下载） | Docker / K8s | 平台团队 | 上轮 |
| OSS-相邻（集成平台） | Nango | https://github.com/NangoHQ/nango | OAuth / 集成平台 | ★12936（+408，约 +341/两周），926 提交 | 云 / 自托管 | 产品团队 | 上轮 |
| OSS-相邻（集成平台） | Arcade | https://github.com/ArcadeAI/arcade-mcp | 工具调用授权 | ★1056（+11），32 提交；Tranco 402681 | pip / 云 | 团队 | 上轮 |
| OSS-相邻（集成平台） | Composio | https://github.com/ComposioHQ/composio | 工具集成 + 认证 | ★30681，1390 提交；Tranco 38086 | pip / npm / 云注册 | 团队 / 产品 | 上轮 |
| OSS-相邻（企业 vault） | OpenBao | https://github.com/openbao/openbao | Vault 分叉 | ★8643（+328，约 +274/两周），395 提交，v2.7.1 | 二进制 / Docker | 企业 | 上轮 |
| OSS-相邻（企业 vault） | HashiCorp Vault | https://github.com/hashicorp/vault | 企业 secrets | ★36416（+74），920 提交，v2.2.0 | 二进制 / 云 | 企业 | 上轮 |
| OSS-相邻（老牌 broker） | CyberArk Secretless Broker | https://github.com/cyberark/secretless-broker | 应用不持密钥的 sidecar broker | ★394，9 提交，v2.0.0 | Docker / K8s | 企业 | 否（失败或停滞参照） |
| OSS-相邻（授权 / 治理） | caracal | https://github.com/Garudex-Labs/caracal | "Authority, not credentials"：策略审批的动作 | ★224，217 提交，v1.0.0 | pip / 二进制 | 团队 | 否（上轮漏掉） |
| OSS-相邻（授权 / 治理） | NyxID | https://github.com/ChronoAIProject/NyxID | 让 Agent 安全调用任意 API 的代理网关 | ★40，942 提交，v0.71.0 | 自托管 | 团队 | 否 |
| OSS-相邻（钱包 / 支付） | Stripe Link CLI | https://github.com/stripe/link-cli | Agent 代付，支付凭据不暴露，用户逐笔批准 | ★867，184 提交 | npm | 个人 | 否（2026-04，上轮漏掉） |
| OSS-相邻（钱包 / 支付） | Steward | https://github.com/Steward-Fi/steward | Agent 钱包 + 凭据代理 | ★98，931 提交 | 自托管 | 开发者 | 否 |
| 沙箱 | Strands Box (AWS) | https://github.com/strands-agents/box | Agent 沙箱，限制执行 / 读写 / 网络 | ★453，26 提交，v0.1.0（518 次下载）；HN 2026-10-08 5 分 | pip / 二进制 | 开发者 | 边界（建仓 2026-10-02，公开宣传 2026-10-08） |
| 沙箱 | moat | https://github.com/majorcontext/moat | 容器运行 Agent + 凭据注入 | ★49，31 提交，v0.8.2 | 二进制 | 个人 | 否 |
| 沙箱 / 工作站 | eldar-os | https://github.com/benjaminwood/eldar-os | NixOS 工作站 + 内置凭据代理 | ★7 | Nix flake | 个人（NixOS） | **新**（2026-10-16） |
| 本机防护 / 盘点 | agent-guard | https://github.com/nirholas/agent-guard | 常驻 Agent 的本机 guard + 出口代理 + key vault | ★5，2 提交 | `npm i -g @nirholas/agent-guard` | 个人 | **新**（2026-10-10） |
| 本机防护 / 盘点 | heldkeys | https://github.com/hugomn/heldkeys | 列出 Agent 在本机能拿到的凭据（只读扫描） | ★6，16 提交，v0.2.3（37 次下载） | `brew install hugomn/tap/heldkeys` | 个人 | **新**（2026-10-15）；是互补工具，不是替代 |
| 闭源-SaaS | Alter (YC S25) | https://alterauth.com/ | Agent 的特权访问管理：vault、逐请求策略、人工审批、审计；Agent 不见凭据；140 个 provider | Launch HN 2026-10-21 63 分 / 28 评论（https://news.ycombinator.com/item?id=50176908）；不在 Tranco 前 100 万 | 云 + SDK，“Start in 10 minutes” 或预约 demo；未列价格 | 团队 / 企业（安全评审、SIEM） | **新**（首次上 HN 首页） |
| 闭源-SaaS（相邻） | Agent Vault (agentvault.io) | https://agentvault.io/ | 给 Agent 的虚拟卡和登录 | HN 2026-10-15 10 分（https://news.ycombinator.com/item?id=50106206） | 云注册（app.agentvault.io） | 个人 / 小团队 | **新**；与 Infisical Agent Vault 同名，容易混淆 |
| 平台内置（潜在终结者） | AWS Agent Toolkit 的 secret safety skill | https://github.com/aws/agent-toolkit-for-aws ；https://aws.amazon.com/about-aws/whats-new/2026/06/safe-secrets-handling-in-agent-toolkit-for-aws/ | Claude Code/Codex/Cursor 插件：动态引用 + `asm-exec`，PreToolUse hook 拦截 get-secret-value；AWS 自己说 best-effort、不是安全边界 | ★2931，192 提交（整个 toolkit） | 插件安装 + AWS 账号 | AWS 用户 | 否（2026-06-17 GA，上轮漏掉） |
| 闭源-SaaS | WorkOS Relay | https://workos.com/blog/credentials-out-of-agent-context | 托管凭据注入 | 本轮未重新采集 | 云 | 产品团队 | 上轮 |
| 闭源-SaaS | Keychains.dev | https://keychains.dev | 托管凭据代理 | 不在 Tranco 前 100 万 | 云注册 | 开发者 | 上轮 |
| 闭源-SaaS | Auth0 Token Vault | https://auth0.com | 托管 token vault | 本轮未采集 | 云 | 企业 | 上轮 |
| 闭源-密码管理 | 1Password / Bitwarden / Keeper | https://1password.com | 密码管理 + Agent 集成 | 1password.com Tranco 2019；Bitwarden / Keeper 本轮未采集 | App + 云 | 个人 + 企业 | 上轮 |
| 替代方案 | .env + 扫描器 / DIY mitmproxy+keyring | — | 自建 | 无 | — | 个人 | 上轮 |
| 自家相邻 | keyspoor（majiayu000） | https://github.com/majiayu000/keyspoor | 离线 secret 扫描：只读 MCP、Git hooks、CI | ★0，30 提交，v0.1.4（490 次下载） | 二进制 | 个人 | **新**（2026-10-03 建仓）；与 Rekey 互补 |
| 自家相邻 | cove（majiayu000） | https://github.com/majiayu000/cove | 个人 AI 网关（Go）：模型路由、API key、用量 | ★0，22 提交 | 开发预览 | 个人 | 2026-09-30 建仓；与 Rekey 的 LLM 连接重叠 |
| 自家相邻 | ccp（majiayu000） | https://github.com/majiayu000/ccp | Claude Code 多 provider profile，token 存 macOS Keychain | ★0 | — | 个人 | 否 |
| 本体 | Rekey | https://github.com/majiayu000/rekey | — | ★0（+0），56 提交 | — | 个人 | — |

## 星数变化（基线 2026-10-05 → 2026-10-22，只有上轮已在快照里的 13 个仓库有增量）

| 产品 | 2026-10-05 | 2026-10-22 | 增量 | 每天 | 约两周 | 相对增幅 |
|---|---|---|---|---|---|---|
| Nango | 12528 | 12936 | +408 | 24.36 | +341 | 3.3% |
| OpenBao | 8315 | 8643 | +328 | 19.59 | +274 | 3.9% |
| agentgateway | 5178 | 5487 | +309 | 18.45 | +258 | 6.0% |
| Infisical Agent Vault | 2306 | 2402 | +96 | 5.73 | +80 | 4.2% |
| HashiCorp Vault | 36342 | 36416 | +74 | 4.42 | +62 | 0.2% |
| OneCLI | 3559 | 3585 | +26 | 1.55 | +22 | 0.7% |
| Arcade | 1045 | 1056 | +11 | 0.66 | +9 | 1.1% |
| AgentSecrets | 181 | 190 | +9 | 0.54 | +8 | 5.0% |
| passless | 104 | 112 | +8 | 0.48 | +7 | 7.7% |
| Kontext CLI | 223 | 227 | +4 | 0.24 | +3 | 1.8% |
| Aegis / KeyFence / Rekey | 14 / 4 / 0 | 14 / 4 / 0 | 0 | 0 | 0 | 0 |

## 搜不到或没完成

- 新候选（KeyValet、briefcred、kv、AskKey、mintrun、keyleash）在 HN 上都按名字搜不到，Product Hunt 未查。
- Bitwarden、Keeper、Auth0、WorkOS 本轮没有拉采用度。
- `keychains.dev`、`alterauth.com` 不在 Tranco 前 100 万，没有其他流量数字。
- alternativeto、theresanaiforthat 没查（SOP 写明会被 Cloudflare 拦）。
- 头部竞品的 README（agent-vault、onecli、agentsecrets、kontext-cli、sigcli、hasp）都没有 Alternatives 或 Comparison 小节可以反查；mintrun 的 README 有一张对比表，比的是 .env 和 `op run`。
- `treg`（superdesigndev，★5959，"OpenRouter for agent tools"）在搜索里排得很靠前，但没核实它是否管理凭据，没有列入主表。

GitHub 搜索用的关键词：agent credential proxy, secrets for ai agents, mcp secrets, api key proxy llm agent, credential broker agent, keyless agent, agent vault, credential injection agent, ai agent api key, agent secrets, mcp credential, secret proxy agent, agent credentials, credential proxy, secret broker, never sees api key, agents never see, api keys ai agents proxy；另外用 `created:>2026-10-05` 跑了 6 组。
