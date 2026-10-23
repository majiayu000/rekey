# 独立审查 review-2 — 20261022-s3（易用性复评）

审查日期 2026-10-22。只读核对：本地源码 `f7d857a`（`git rev-parse HEAD` 确认，工作区只有 `docs/peerscope` 改动）；AgentSecrets `be53766`（审查员 scratchpad 浅克隆）；GitHub API（匿名，UA `peerscope-review/0.1`）；本轮 `evidence/`、`eval/agent/raw/`、`evidence/summary/agg.py`。`scan_claims.py` 提示 3 处（01:112、02:72、PROTOCOL:52），逐条看过，均有来源或属于协议说明；`check_report.py` 0 处命中。

## 总评：改完再交付

上次 8 条必须改、9 条建议改基本都落实了，新写的 AgentSecrets 列、概念重数、43/35/7/1 计数都回得到一手来源。但新写进去的内容里有两处和一手来源对不上，而且都在头条或核验表里：一是“Rekey 不开 `--remember` 时需要密码 step-up”与源码和 02 自己的说法矛盾；二是 sallyport 被写成“按调用审批”，它的默认其实是“每个进程首次调用点一次”，逐次审批要按 key 手动开。两处都是改几句话的事，改完不需要再审。

## 上次处置核对

### 必须改

| # | 结论 | 依据 |
|---|---|---|
| 1 概念计数口径 | 落实 | PROTOCOL.md:46–48 写了口径；01:48 写了减法过程。回源复算：Rekey 卡片 16 项（`evidence/self-rekey/card.md:52`）去掉 state-dir、service.json、L1-dev、T0/T1、审批 5 项 = 11 ✓；Agent Vault 13 项（`peer-agentvault/card.md:38`）去掉 proposal = 12 ✓；OneCLI 11（`peer-onecli/card.md:54`）、AgentSecrets 10（`peer-agentsecrets/card.md:36`）不变 ✓。00:6、01:10/:42、03:12 同步。遗留：02:7 的放弃门槛“12 个以上”与现状 11 几乎不起作用，见建议改 5 |
| 2 H1 路径说明 | 落实 | 01:10、:35、:39 表头、00:6、00:16 都写明测的是“不用 App 的 CLI 路径”；“门槛最高”已删 |
| 3 AgentSecrets 列 | 落实，且回源成立 | `be53766` 的 `pkg/proxy/engine.go` L657–L661（allowlist 为空即拒，带修复命令）、L670–L673（不在 allowlist 即拒）、L34 起脱敏常量、L42 注释“Redaction runs on every proxied response”、L773 `redactResponse` 在尾部流水线无条件调用；`pkg/capabilities/policy.go` L37–L38 policy 为 nil 返回 Allow。小瑕疵见建议改 3 |
| 4 A2/A3 证据不对称 | 落实 | 01:81 改为未复测、:83 拆行、:86–:90 判定拆分；01 正文已无 E5。但 12/12 的出处描述不准，见建议改 1 |
| 5 `--remember` 自批准 | 部分落实 | 推断本身回源成立（见事实抽查表）。02:13–27、03:7 处理得对。但 01:97 新写的“Rekey 只有在不开 `--remember` 时，才需要额外的密码 step-up”与源码不符，见必须改 1 |
| 6 sallyport | 部分落实 | 存档 `evidence/discover/sallyport-README-20261022.md` 与 GitHub API 现取 README 逐字节相同（`diff` 无差异），189★、Apache-2.0 成立。但“按调用审批”超出了 README 和官方 docs，见必须改 2；另有遗漏，见建议改 6 |
| 7 记录数 | 落实 | `find eval/agent/raw -name '*.json'` = 43；`agg.py` 跳过 `excluded:true`（只有 `rekey/A1-k1.json`）；逐文件核对：实际运行 35（agentsecrets 3、agentvault 12、kontext 3、onecli 13、rekey 4），未跑 6，`agentsecrets/_driver-claude-p-failure.json` 1，排除 1，合计 43 ✓。措辞小问题见建议改 7 |
| 8 check_report | 落实 | 复跑 0 处命中 |

### 建议改

| # | 结论 | 依据 |
|---|---|---|
| 1 “真实需求”措辞 | 落实 | 01:11、00:8、01:157；G2 簇在 `evidence/voc/voc.md:44`，4 人、D1 ✓ |
| 2 AgentSecrets #6 | 落实 | 01:112；GitHub API：closed 2026-05-07T00:57:55Z，completed ✓；#5 仍 open ✓ |
| 3 OneCLI 自托管定价 | 落实 | 01:104 |
| 4 OneCLI A4 block 规则 | 落实 | 01:84；#266 仍 open（GitHub API） |
| 5 P0 #1 修复方案 | 落实 | 02:16–27 写了测试夹具、契约测试、presence 来源和 A/B 方案 |
| 6 基线说明 | 落实，回源成立 | 01:4；GitHub compare `f7d857a...main` ahead_by=1，唯一提交 `26bf862`（#89）。它改了 `local.rs`、`Model.swift`，但只是预设列表和 stripe 只读预设，不碰 `local-review.v1`，不影响结论 |
| 7 读者负担 | 大体落实 | §8 有 P 编号；01:59 给了 trace 和探针链接；01:67 不再写“本会话实测”；01:49 墙钟“只记录，不比较”。01:64、:65、:70 仍只写 “trace”，靠 01:59 的节首链接兜底，可接受 |
| 8 G02 依据 | 落实 | 03:8 |
| 9 首屏封口文案 | 落实 | 02:59–61 |

## 必须改

1. **01:97 的 step-up 说法与源码和 02 矛盾**
   - 位置：01-competitor-research.md:97（“Rekey 只有在不开 `--remember` 时，才需要额外的密码 step-up”）。
   - 问题：CLI 批准路径只接受 presence 证明，没有密码 step-up 选项。`approval_decide` 固定调用 `read_step_up(ProofKind::Presence, true)`（`crates/rekey-cli/src/commands/policy_approval.rs:389-420`）。daemon 侧 `verify_presence` 只认内存里的 `PresenceGrant`（`crates/rekey-vault/src/authority/desktop.rs:154-162`），而这种 grant 只在 desktop remember / resume 路径里创建（同文件 :211、:331、:426）。所以不开 `--remember`、也没有 App 时，基础模式根本批不了，不是“多一步密码”。密码 / 恢复密钥 step-up 是激活策略用的（01:95 引的 L88–L122），和批准写调用是两条路径。02:17 写的“现成来源只有 `--remember` 文件”是对的，01:97 和它冲突。
   - 改法：改成“Rekey 不开 `--remember` 时同用户进程无法自批准，但你自己也无法在 CLI 批准（目前只有 presence 一种证明）；这就是 02 第 1 项要新增密码 step-up 批准的原因”。

2. **sallyport 被写成“按调用审批”，默认其实是按进程审批**
   - 位置：00-README.md:8（“Mac App + MCP + Touch ID”）；01:13（“Touch ID 按调用审批”）；01:123（“带 key 标记的调用逐次审批”）；01:135（“按调用审批”）；01:172（“sallyport 默认对带标记的 key 逐次审批”）；02:72。
   - 证据（GitHub API 读取，2026-10-22）：
     - README 存档 L42–L45：新进程需要 session 审批；被标记的 key 或 MCP server 才逐次审批。
     - `docs/05-approvals.md`：“Session approval is the default because it asks once per process run. Per-call approval is opt-in for selected keys or MCP servers.”
     - `docs/14-trust-model.md`：sessionAuth 默认值是 `click`（不是 Touch ID）；trust-model 的已知风险里写着，被批准过的进程可以使用任何未设逐次审批的凭据。
   - 影响：sallyport 的默认是“每个新进程点一次”，之后这个进程的写调用不再询问。和 Rekey“写操作默认要批准”比，默认粒度更粗；但它默认也会拦新进程，不是“默认放行”。01:172 的“默认对带标记的 key”读起来像默认就有逐次审批，容易误导。
   - 改法：统一写成“默认每个新进程首次调用点一次批准（可改 Touch ID 或关闭）；逐次审批要按 key 手动开启 [E2]”。00:8 去掉“Touch ID”或改成“点击 / Touch ID”。01:172 改成“sallyport 默认按进程审批，逐次审批可选”。

## 建议改

1. **12/12 封口的出处写得不准**
   - 位置：01:81（“沿用 10-05 实测 12/12（当时测的是 0.3 发布版）”）、02:61、03:19。
   - 证据：仓库里唯一的 12/12 出处是 `docs/releases/v0.3.0-alpha.2.md:23`：“相同生产组件源码的本机 fixture 复测……12/12 合成凭据反射探针拒绝”，同文还写明“不代表真实 provider 或发布包验收”。提交日期是 2026-10-06（`0828fca4`，#69）。上一轮 `rounds/20261006-s3/` 里搜不到 12/12。
   - 改法：改成“0.3.0-alpha.2 修复源码在本机 fixture 上 12/12 合成反射探针被封口（不是 httpbin 回显，也不是发布包）”。

2. **01:83 把 A3 完成不了全归给 bug**
   - 问题：修好 record_type 以后，基础模式批准仍需要 presence 证明，见必须改 1。
   - 改法：“没有 App 时不能（record_type bug；修好后还需 `--remember` 的 presence 文件，或新增密码批准）”。

3. **01:78 表头写“源码，未实测”，A1 格却是实测**
   - 证据：`eval/agent/raw/agentsecrets/A1-k{1,2,3}.json` 是实际运行，success=true。
   - 改法：A1 格标 [E4]，或者把表头改成“AgentSecrets（A1 实测，其余源码）”。另外 01:110 的 “SSRF 拦截……见 engine.go#L685”链接指向的是审批 / 策略段；SSRF 拦截在 `engine.go` L250–L255，链接要么改，要么分开引用。

4. **原问题的直接回答不够直白**
   - 问题：用户的上一句是“从一个用户的角度出发，现在是不是一个非常好用的库”。00 的结论只能推出答案，没有直说。
   - 改法：00 结论第一条前加一句：“现在还算不上好用：默认安全做得比实测竞品好，但不用 App 时连审批都走不完，步骤和报错也比竞品更难懂；装了 App 的主路径本轮没测。”

5. **02:7 的放弃门槛几乎不起作用**
   - 问题：现状已经是 11，“补完 P0 后仍要理解 12 个以上”只有在 P0 反而加了概念时才会触发；同一文件的 02:46 和 03:12 目标是 ≤ 10。
   - 改法：放弃条件改成“补完 P0 和 P1 后概念仍 > 10”，和验收目标对齐；或者写明为什么故意放宽。

6. **sallyport 的几处遗漏会影响“下一轮第一个补测它”**
   - 证据（GitHub API，2026-10-22）：
     - 最新 release 是 v0.8.16（2026-07-17），`pushed_at` 是 2026-07-19，已经三个月没有更新；
     - README 写明只支持 Apple Silicon、macOS 14 及以上；
     - trust-model 写明有 host / path 绑定，所以 A4 很可能会拒绝。
   - 改法：01 §6 补上“最近更新 2026-07，仅 Apple Silicon”；02:72 补测前先确认项目还活着。

7. **“7 份是未跑说明”的口径**
   - 位置：01:30、00:12。
   - 问题：7 份里有 6 份是 `*-not-run.json`，第 7 份是 `agentsecrets/_driver-claude-p-failure.json`，属于驱动失败，但没有排除；`agent-pass.txt` 还把 `_driver` 当成一个任务行输出。
   - 改法：写成“6 份未跑说明、1 份驱动失败记录（保留）、1 份驱动失败（已排除）”，并让 `agg.py` 跳过以 `_` 开头的文件。

8. **1Password 的“约 5 个概念”没有按统一口径重数**
   - 位置：01:42。
   - 改法：在格里注明“E2，未按统一口径重数”，或者直接删掉。

9. **小的读者负担**
   - 01:163“（独立审查复核）”、01:168“（独立审查读码）”是过程说明，改成直接引用源码位置就够了。
   - `evidence/self-rekey/card.md:99` 仍然用 E5，没有图例；不在交付正文里，可以顺手改成 E4。

## 事实抽查表

| 事实 | 位置 | 结果 | 来源与日期 |
|---|---|---|---|
| `remembered-unlock.key` 里存的就是 presence 密钥，同用户可读 | 01:96、02:17、03:7 | 成立 | `f7d857a`：`crates/rekey-cli/src/commands/mod.rs:462-503` 把 daemon 返回的 key 以 0600 写入 `remembered-unlock.key`（:434 定义文件名），stderr 自述 “a 0600 file readable by this user”；`desktop.rs:211` 生成随机 key 建 `PresenceGrant`，并返回 HEXLOWER 编码；`desktop.rs:89-101` 的 `decode_presence_key` 正好接受 64 位小写 hex。2026-10-22 |
| `approval approve` 用 stdin 上的 presence 证明批准 | 01:96 | 成立 | `policy_approval.rs:389-420`（`read_step_up(ProofKind::Presence, true)`）；`desktop.rs:154-162`。2026-10-22 |
| 不开 `--remember` 时 Rekey 需要“密码 step-up” | 01:97 | 错误 | 批准路径只认 presence；grant 只在 `desktop.rs` :211/:331/:426 的 remember/resume 路径创建。见必须改 1 |
| sallyport“按调用审批” | 00:8、01:13、:135、:172 | 部分错误 | `OlegSotnikov/sallyport` 的 `docs/05-approvals.md`（session 默认，逐次审批 opt-in）、`docs/14-trust-model.md`（sessionAuth 默认 `click`），GitHub API 2026-10-22 |
| sallyport 189★、Apache-2.0、README 存档与线上一致 | 01:126 | 成立 | GitHub API 2026-10-22：stargazers 189，license Apache-2.0；README `diff` 无差异 |
| sallyport 仍在活跃 | 02:72（隐含） | 未写，查到已停更约 3 个月 | releases：v0.8.16 2026-07-17；pushed_at 2026-07-19 |
| AgentSecrets 默认拒绝 + 带修复命令 + 每个响应脱敏 + 写审批默认不开 | 01:84、:81、:82、:168 | 成立 | `be53766`：`engine.go` L657–L673、L34–L42、L773；`policy.go` L37–L38。2026-10-22 |
| AgentSecrets SSRF 拦截的出处是 engine.go L685 | 01:110 | 链接错位 | SSRF 在 `engine.go` L250–L255；L685 是 policy/审批段 |
| 概念重数 11 / 11 / 12 / 10 | 01:42、:48 | 成立（按新口径） | 各 card 概念清单逐项减算，见上次处置核对第 1 条 |
| Agent 原始记录 43 / 35 / 7 / 1 | 00:12、01:30 | 成立；“7 份未跑说明”里含 1 份驱动失败 | 逐文件读取 43 个 JSON；`agent-pass.txt` 由 `agg.py` 生成。2026-10-22 |
| `rekey --help` 有 40 个命令 | 01:12 | 成立 | `trace.jsonl` H1-02 的 Commands 段 41 项，含 `help`，去掉后 40 |
| OneCLI 10-06 以来 9 个 feature release | 01:101 | 成立（数量） | `evidence/peer-onecli/releases.tsv`：v2.8.0–v2.16.0 共 9 个 minor（另有 2.11.1/2.11.2 补丁）；“都是团队方向”未逐条核 |
| 回显封口 12/12“10-05 实测、0.3 发布版” | 01:81 | 部分错误 | `docs/releases/v0.3.0-alpha.2.md:23`：修复源码本机 fixture、合成反射探针、明确不代表发布包；提交 2026-10-06 |
| 星数：OneCLI 3,585、Agent Vault 2,402、AgentSecrets 190、varlock 4,809、hasp 353、Rekey 0 | 01:137、:141 | 成立 | GitHub API 2026-10-22（keypaste 现为 417，差 1，可忽略） |
| 远端 main 只多 #89 且不影响结论 | 01:4 | 成立 | GitHub compare `f7d857a...main`，ahead_by=1，2026-10-22 |

## 高发错误清单逐项

1. 基线：查了，没问题（HEAD = `f7d857a`；远端 +1 不影响结论）。
2. 漏了自家：查了，没问题（候选表含 keyspoor、cove）。
3. 只看 README 就说“没有”：发现问题。sallyport 只读 README，就写成了“按调用审批”；官方 docs 说逐次审批是可选项。见必须改 2。
4. 概括句没查过：查了。“新出现的都在 15★ 以下”已删，01:141 的“增长放缓”有星数增量支撑。
5. 对自己宽松：发现问题。01:97 把 Rekey 不开 `--remember` 的情况说成“多一步密码”，实际是 CLI 根本批不了。见必须改 1。
6. 指标归错类：查了，没问题。
7. 用过时说法：查了，#6 已改；#5 仍 open ✓。
8. 计数手数：查了。43/35 对得上，“7 份未跑说明”口径小瑕疵，见建议改 7。
9. 改完不同步：发现问题。01:97 与 02:17 对 presence / step-up 的说法冲突（必须改 1）；02:7 与 02:46 门槛不一致（建议改 5）。
10. 新写的内容没回源：AgentSecrets 列、概念数、计数都回源成立；sallyport 描述和 12/12 出处没完全回源。见必须改 2、建议改 1。
11. 只处置必须改：查了，没问题。9 条建议改都有处置，且大体落实。
12. 用截断输出证明“没有”：查了，没有发现。
13. 把已关闭的问题当现状：查了，没问题。
14. 只找支持、不找反例 / 绕过实验：反向检索行在（01:171–172）；`--remember` 绕过已写进核验表（01:170），但只是源码推断、未实测，02:25 已列为修完后的实测项，可以接受。
15. 离开工作区读不懂：`check_report.py` 0 命中；只剩过程性注释和 card 里的 E5，见建议改 9。
16. 只看默认配置：OneCLI block 规则、Agent Vault strict、AgentSecrets 按 Key 审批都已注明；sallyport 反过来，把可选项写成了默认，见必须改 2。
17. 建议和我方边界冲突：查了。02 第 1 项方案 A 新增“密码 step-up 批准”，与 spec 10-05 把 CLI 列为审批通道一致；方案 B 只是文档化，没有越界。

## 前提与新遗漏

- 前提卡来自用户确认，没有把假设写成已确认；没有重跑性能和安全。
- 结论基本回答了“和同类比，好不好用”，但没有对“是不是非常好用”给出一句直白回答，见建议改 4。
- 新遗漏：sallyport 停更约 3 个月、只支持 Apple Silicon、默认按进程审批（见必须改 2、建议改 6）。没有发现其他会改变结论的对手。

## 处置（作者）

必须改：
1. 已改：01 §5 的绕过结论改为“不开 `--remember` 时，同用户进程无法自批准，但你自己也无法在 CLI 批准”，并说明这正是 02 第 1 项要新增密码批准的原因。
2. 已改：作者回读了 sallyport 的 `docs/05-approvals.md`（默认按会话审批，逐次审批需手动开启）。00、01 §1/§6/§7/§9 和 02 都改成“默认按进程审批”。

建议改：
1. 已改：作者回读了 `docs/releases/v0.3.0-alpha.2.md` L23，12/12 改写为“修复源码的本机 fixture”，01、02、03 都已更新。
2. 已改：01 A3 完成度一格补上了 presence 前提。
3. 已改：表头改为“A1 实测，其余读源码”；SSRF 拦截的链接改到 L250–L255。
4. 已改：00 开头加了直接回答。
5. 已改：放弃门槛改为“P0+P1 后仍 > 10”。
6. 已改：sallyport 补了“只支持 Apple Silicon”“最近推送 2026-07-19”；02 写明先确认项目还在维护。
7. 已改：计数口径改为 6 份未跑说明 + 2 份驱动失败记录；`agg.py` 跳过以 `_` 开头的文件。
8. 已改：1Password 那格注明“未按统一口径重数”。
9. 已改：删掉了“独立审查复核/读码”这类过程说明；卡片里的 E5 改为 E4。

审查员说明这两处只需改几句话，改完不必再审；作者按规则复跑 check_report，结果 0 处命中。
