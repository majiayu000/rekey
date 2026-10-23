# 独立审查 review-1 — 20261022-s3（易用性复评）

审查日期 2026-10-22。只读核对：本地源码 `f7d857a`、竞品固定 commit（Agent Vault `872578e`、OneCLI `6eaf878`、AgentSecrets `be53766`，均在审查员 scratchpad 里浅克隆）、GitHub API（匿名字段，未带用户身份）、本轮 `evidence/` 和 `eval/agent/raw/`。

## 总评：改完再交付

方向和大部分一手事实站得住：CLI 审批 bug 是真的，generic 预设读也要审批是真的，竞品默认放行也是真的。但有三处会改变结论措辞或优先级：

- 头条里的“概念量最差”“上手门槛最高”，计数口径不统一，而且 Rekey 走的不是 README 主路径；
- §5 表格漏了源码上默认行为与 Rekey 最接近的 AgentSecrets，也漏了和 Rekey 形态最像的 sallyport；
- 绕过实验没有覆盖 `unlock --remember` 生成的同用户可读 presence 文件，而 P0 #1 恰好会把这条路打开。

`check_report.py` 有 3 处命中，按规则也算未通过。

## 必须改

1. **概念数 16 vs 11/13/10 口径不一致，“概念量比所有被测产品都差”不成立**
   - 位置：00-README.md:5；01-competitor-research.md:9、:35、:44；02-my-plan.md:4、:21；03-catchup-ledger.md:12。
   - 问题：没有写计数规则，各家清单的口径也不一样。
     - Rekey 的 16 个里，有 4 个是隔离测试自己造出来的，或者只是显示项：`state-dir`（为了隔离才指定）、`service.json` 端口（本机已有 daemon 占了端口才碰到）、L1-dev 警告、T0/T1 等级。另外它把审批（challenge/request 两个 ID、presence、review 摘要）算进来了。
     - AgentSecrets 的 10 个明确把 agent identity、secret policy（审批）、proxy、MCP 列为“可选”，不计入（`evidence/peer-agentsecrets/card.md:36`）。
     - OneCLI 的 11 个不含审批（`evidence/peer-onecli/card.md:54`）。
     - 去掉 Rekey 那 4 个后约为 12，落在 10–13 区间内。
     - 另外，00:5 写“竞品是 11–13 个”，和 01 表里 AgentSecrets 10、1Password 约 5 也对不上。
   - 改法：
     - 在 PROTOCOL 里写一条计数规则：只计 README 主路径上必须理解的名词；隔离测试带来的不计；审批类要么各家都计，要么都不计。
     - 按这条规则重数四家。
     - 结论降为“概念量与竞品同一量级（约 10–13），Rekey 多出的是审批相关的 3–4 个”。
     - 02 的“降到 8”和“10 个以上就放弃”这两个门槛，要按新口径重设。

2. **Rekey 的 H1 不是用户实际会走的路径，“上手门槛最高”缺少同条件比较**
   - 位置：01:9、:34、:43；00-README.md:5。
   - 问题：README 主线是 `rekey setup` → App（`evidence/self-rekey/card.md:69`）。本轮按协议不碰 App，走的是 `init` + `serve` + 第二终端 + 手写 `service.json` 的非文档路径。7 条成功命令、15 条主命令、9 次 `--help` 里，有一部分是这条路线和隔离环境带来的。竞品走的则是各自文档里的主路径。
   - 改法：
     - 在 §2 的“和计划的偏差”和 00 的“没做到”里写明：Rekey 的 H1 测的是“无 App 的 CLI 基础模式”，不是 README 主路径；App 路径的上手步骤本轮没测。
     - 头条改成“无 App 的 CLI 路径门槛最高”。

3. **§5 Agent 可用性表漏了 AgentSecrets，“安全默认最好”说得太满**
   - 位置：00-README.md:5（“安全默认最好”）；01:9（“在被测产品里最完整”）、:66–:73。
   - 证据：AgentSecrets `be53766` 的源码显示：
     - allowlist 为空时一律拒绝，并给出修复命令（`pkg/proxy/engine.go` L657–L661）；
     - 域名不在 allowlist 时拒绝（L670–L673）；
     - 每个响应都做脱敏（L34 起，`redactionPlaceholder`）；
     - 只有写审批默认不开：`EvaluateSecret` 在 policy 为 nil 时返回 Allow（`pkg/capabilities/policy.go` L37–L38）。

     也就是说，按源码推断，AgentSecrets 在 A2、A4 上很可能和 Rekey 一样会拦，只在 A3 上不同。
   - 改法：
     - §5 加一列 AgentSecrets，标 [E3] 未实测：A2 默认脱敏，A4 默认拒绝并附修复命令，A3 默认放行、可按 Key 开审批。
     - 00 的头条限定为“在实测的三家里”，并补一句“源码上 AgentSecrets 在 A2/A4 与 Rekey 同级，差在写审批默认不开、且必须注册云账号”。

4. **A2 和 A3 判“Rekey 占优”的证据不对称**
   - 位置：01:69、:70、:73。
   - A2 的问题：竞品泄露是用 httpbin 回显测出来的。Rekey 这一轮没有跑回显，只用 GitHub 401 证明 Key 已注入（这个测不出回显泄露），封口依据沿用 10-05 的 12/12。那次测的版本也不是 `f7d857a`。另外，图例里没有 E5。
   - A3 的问题：协议的成功条件包括“批准后能否完成”（PROTOCOL.md:31）。Rekey 拦下了，但本轮没能完成（`raw/rekey/A3-probe.json`，success=false）；OneCLI 配置审批后能完成。
   - 改法：
     - A2 改成“本轮未复测回显；沿用 10-05 的结果（版本 X），本轮只证明已注入、响应里不含 Key”，不判占优，或判“暂优，待复测”。
     - A3 拆成两行：拦截判 Rekey 占优；无 App 时的完成度判 Rekey 缺口。
     - 判定句改成“A3 拦截、A4 拒绝 Rekey 占优；A2 待复测；A1 持平；A3 完成度是缺口”。
     - 删掉 [E4/E5] 里的 E5，或者在图例里补上定义。

5. **绕过实验不充分：漏了 `unlock --remember` 留下的 presence 文件；和 OneCLI 的对比双重标准**
   - 位置：01:75；02:10–12（P0 #1）。
   - 证据（源码推断，未实测）：
     - `rekey unlock --remember` 会把 desktop key 写到 `state_dir/remembered-unlock.key`，权限 0600，同用户可读。CLI 帮助文本自己写着 “Basic mode: the key is a 0600 file, not Secure Enclave”（`crates/rekey-cli/src/main.rs` 约 L404–L405、`commands/mod.rs:462-503`）。
     - 这把 key 就是 `PresenceGrant` 的凭证（`crates/rekey-vault/src/authority/desktop.rs:205-211`、`:154-162`）。
     - `rekey approval approve` 接受的正是 stdin 上的 Presence proof（`policy_approval.rs:389-420`）。

     所以，CLI review bug 修好以后，开了 `--remember` 的同用户 Agent 可以自己读文件、自己批准写调用，和报告批评 OneCLI 的“同一把 Key 自己批准自己”是同一类问题。

     报告用“同用户恶意进程不在 L1-dev 范围”给 Rekey 开脱，却把 OneCLI 的同用户自批准算作缺陷。OneCLI 的 `oc_` key 同样放在 `~/.onecli`，同样是同用户可读（`evidence/peer-onecli/a3-selfapprove.log`）。
   - 改法：
     - 核验表加一行“`--remember` 文件 → `approval approve` 自批准”，标为未实测或源码推断。
     - 对比句改成“两家在同用户威胁下都可能自批准；Rekey 不开 `--remember` 时需要密码 step-up”。
     - P0 #1 的验收补一条：新的 CLI 批准路径不接受任何同用户可读文件作为证明，并且要做一次绕过实测（换入口直连 admin.sock、换配置来源）。

6. **漏了与 Rekey 形态最像的对手 sallyport，“新出现的个人向同类都在 15★ 以下”会误导读者**
   - 位置：00-README.md:8、:18；01:12、:93–:94。
   - 证据：sallyport（189★，Apache-2.0，`OlegSotnikov/sallyport`）的 README（2026-10-22 经 GitHub API 读取）写的是：
     - 免费 Mac App，brew cask 安装；
     - MCP 接入，`claude mcp add sallyport -- …/sp mcp`；
     - 支持按调用审批，审批用点击或 Touch ID；
     - 自称“从安装到第一次受控调用约两分钟”；
     - 明确说响应原样返回，回显不在保护范围内。

     这正是用户问的“个人用户好不好用”最直接的对照，而且它可能比 Rekey 上手更快、在回显封口上更弱，两个方向都会影响结论。hasp（353★，local-first broker）、keypaste（416★，2026-09 才建仓）也不在 15★ 以下。
   - 改法：
     - 00 和 01 §1 改成“上轮漏掉的个人向同类里，sallyport（189★，Mac + MCP + Touch ID）和 Rekey 最像，本轮没有深挖”。
     - 把“补测 sallyport”放到 02 下一轮复评的第一位。
     - 至少补一条 [E2] 卡片行：安装方式、审批方式、自述的上手时长、是否封口。

7. **Agent 任务原始记录数写错**
   - 位置：00-README.md:12；01:26。
   - 证据：`find eval/agent/raw -name '*.json' | wc -l` 结果是 43（另有 1 个 `A1-prompt.txt`）。按家数：OneCLI 13、Agent Vault 12、Rekey 5、AgentSecrets 7、Kontext 6，合计 43，不是 54。`summary/agent-pass.txt` 还把已标 `excluded:true` 的 `rekey/A1-k1.json`（驱动 OAuth 失败）算进了 A1 的分母，变成 1/2。
   - 改法：改成“43 份（其中 n 份为未跑说明或驱动失败）”，并让 `agg.py` 跳过 `excluded` 的记录。

8. **`check_report.py` 有命中（高发错误第 15 条：有命中就是没过）**
   - 位置：00-README.md:6、:18；01:126。
   - 问题：“没有 / 独有”这类说法没写查了哪里。
   - 改法：
     - 00:6 补上“反向检索见 01 §9”；
     - 00:18 改写成具体名单，见第 6 条；
     - 01:126 写明检索范围：AgentSecrets 源码 `be53766`、KeyValet README，其余同类未核。

## 建议改

1. **01:10、00:6，“差异点有真实需求”的措辞超出了证据**
   - 问题：19 位和 15 位作者抱怨的是竞品的 MITM 和自托管，这是“痛点”，不能直接当成“对显式调用型产品的需求”。反向证据也有：VoC 的 G2 里用户称赞的正是 MITM 的“对 Agent 透明”；P6 说显式调用型产品更容易让 Agent 用错；Kontext PR #440 退役凭据会话的理由是“近 30 天 0 个会话”。
   - 改法：改成“竞品有两类成规模的痛点（MITM 兼容 19 人、自托管 15 人），Rekey 架构上避开了；但显式调用本身也有代价（G2、P6），而且 Kontext 的同类功能因为没人用而下线”。

2. **01:81，AgentSecrets #6 是已关闭的旧问题**
   - 证据：#6 在 2026-05-07 关闭，状态 completed（GitHub API）。
   - 改法：改成“1.1.3 升级曾经坏掉（#6，已于 05-07 修复）”。

3. **01:79，“自托管只在 Enterprise 档”有歧义**
   - 证据：定价页的比较表里，“Self-hosted deployment”确实只在 Enterprise 列打勾。但仓库是 Apache-2.0，可以自托管，本轮就是这么测的（`evidence/peer-onecli/onecli-pricing-2026-10-22.txt`）。
   - 改法：写成“云版定价 Free / $149 / $499；开源版可自托管，托管的企业自托管方案只在 Enterprise 档”。

4. **01:71，OneCLI A4 也要写清可选配置（高发错误第 16 条）**
   - 证据：OneCLI 有 block 规则和 `manual_approval` 规则（`apps/gateway/crates/policy-engine/src/enforce.rs`、`crates/approval/src/lib.rs` @`6eaf878`），但没有 allowlist 模式（#266 仍 open）。
   - 改法：A4 格改成“默认 0/3 拒绝；可以用 block 规则逐个拉黑，但没有默认拒绝模式（#266）”。

5. **02:10–12，P0 #1 的修复方案先核对现有设计**
   - 证据：CLI 已经有 `approval approve/reject`（`policy_approval.rs:389`），需要 presence proof（desktop key）。产品 spec 2026-10-05 L35 也把“CLI 隐藏输入”列为审批通道之一，所以这确实是 bug，不是 CLI 本来就不该处理这类审批。另外，CLI 自己的测试夹具用的就是错误的 `review.v1`（`crates/rekey-cli/tests/local_approval.rs:153`），所以测试一直是绿的。App 侧要求 `local-review.v1`（`apps/macos/Model.swift:729`），和 daemon 一致。
   - 改法：
     - 写明修复要同时改 CLI 的测试夹具。
     - 写明“修完以后，基础模式的批准还需要 presence proof，现成的来源只有 `--remember` 文件”，再和必须改第 5 条一起决定：新增“密码 step-up 批准”，还是复用 presence。
     - 加一条契约测试：用 daemon 的真实输出喂给 CLI 解析器。

6. **基线说明**
   - 证据：远端 main 已经到 `26bf862`（#89，2026-10-22 09:21Z，新增 deepseek、qwen 等预设，`f7d857a` 之后 +1）。逐个看过它改的文件，没有影响本轮任何发现。
   - 改法：在 01:4 加一句“远端 main 已到 26bf862（#89，只增加预设），不影响本轮结论”。

7. **读者负担**
   - 01:11、02:18 引用了“P6”，但 01 §8 的表格没有 P 编号，读者对不上。要么给表格加编号，要么改用簇名。
   - 01:52、:53、:58 只写了“trace H1-14”“trace”，没有链接，请链到 `evidence/self-rekey/trace.jsonl`。
   - 01:55 的“本会话实测”是自查口吻，请改成指向 `mcp-probe-A1-tools-list.jsonl`。
   - 01 §3 的墙钟一行，各家条件不一样（有的不含构建，有的含拉镜像），又没有用于任何判定，可以删掉，或注明不可比。

8. **03:8，G02 的竞品依据和这一行的能力对不上**
   - 问题：G02 是“describe 显示规则”，依据却写的是“AgentSecrets 的报错附修复命令”。
   - 改法：换成真正对应的依据（例如 OneCLI 或 Agent Vault 的 list/describe 输出），或者标“无竞品依据，来自自测”。

9. **02:34，首屏文案“Key 不会出现在 Agent 的输出里”说得太满**
   - 问题：本轮没有复测回显封口；README:64 也写明同用户的程序可以绕开 Rekey。
   - 改法：改成“上游回显的 Key 会被封口（10-05 实测）”。

## 事实抽查表

| 事实 | 位置 | 结果 | 来源与日期 |
|---|---|---|---|
| CLI `approval review` 因记录类型不匹配必然报 INVALID_FRAME，是 bug 而不是设计如此 | 01:51、02:11 | 成立 | `f7d857a` 的 `crates/rekey-broker/src/executor/local.rs:189` 写入 `local-review.v1`；`crates/rekey-cli/src/commands/policy_approval.rs:324` 接受 `local-review.v1` 的 metadata，但 :344 要求 body 是 `review.v1`，同一个函数里自相矛盾；App 端 `apps/macos/Model.swift:729` 要 `local-review.v1`；spec 10-05 L35 把 CLI 列为审批通道；trace H1-19 有报错原文。2026-10-22 |
| 修好 bug 后，基础模式的 CLI 批准仍需 presence proof | 02:11（未提及） | 成立（报告遗漏） | `policy_approval.rs:389-420`；`desktop.rs:154-162`。2026-10-22 |
| generic 预设读也要审批，和 README“默认读允许”冲突 | 01:52 | 成立 | trace H1-14（`"read":"approve"`）、H1-15；`f7d857a` 的 README.md:23。2026-10-22 |
| Agent Vault 默认放行未知 host，官方文档前后矛盾 | 01:71、:124 | 成立 | `872578e` 的 `docs/learn/services.mdx` L6、`docs/agents/protocol.mdx` L158（默认 passthrough），与 `services.mdx` L420–L423（FAQ 说返回 403）矛盾。2026-10-22 |
| Agent Vault 没有方法级限制（能力表里“没有”的格子） | 01:71、card | 成立 | `872578e` 的 `services.mdx` L293 写明不按 method 匹配；#323 仍 open（GitHub API，2026-10-22） |
| OneCLI 默认不拦写操作，审批是可选的（能力表里“0/3 拦截”的格子） | 01:70 | 成立（默认）；可选严格模式已在正文注明 | `6eaf878` 的 `apps/gateway/crates/approval/src/lib.rs:3`（`manual_approval` 规则）、`policy-engine/src/enforce.rs:272`；raw `onecli/A3-k1..3` |
| OneCLI A4 没有默认拒绝 | 01:71 | 成立；但有 block 规则，没写进正文 | 同上，`enforce.rs`；#266“Allowlist instead of blocklist”仍 open（GitHub API，2026-10-22） |
| AgentSecrets 默认拒绝未授权域名，并对响应脱敏 | 01:81 | 成立，但 §5 没有用上 | `be53766` 的 `pkg/proxy/engine.go` L657–L673、L34；`pkg/capabilities/policy.go` L37–L38（policy 为 nil 时写操作放行）。2026-10-22 |
| AgentSecrets #6“brew 升级后坏掉” | 01:81 | 错误（写成了现状，实际已修复） | GitHub API：closed，2026-05-07T00:57:55Z，completed |
| AgentSecrets #5 免登录本地模式没做 | 01:81 | 成立 | GitHub API：open，2026-10-22 |
| Kontext 因“近 30 天 0 个会话”删除凭据会话 | 01:82 | 成立 | PR #440 正文“0 legacy CLI sessions in the last 30 days”，merged 2026-08-01（GitHub API） |
| Agent 原始记录 54 份 | 00:12、01:26 | 错误（43 份） | `find eval/agent/raw -name '*.json'` = 43。2026-10-22 |
| 星数：Agent Vault 2402、OneCLI 3585、AgentSecrets 190、varlock 4809、Rekey 0 | 01:92、:97 | 成立 | GitHub API，2026-10-22 |
| “新出现的个人向同类都在 15★ 以下” | 00:8、01:12 | 字面成立，但会误导 | sallyport 189★、hasp 353★、keypaste 416★（GitHub API，2026-10-22），属于“上轮漏掉”的一类，都是个人向；sallyport 的 README 自述 Mac + MCP + Touch ID，约 2 分钟上手 |
| OneCLI 自托管只在 Enterprise 档 | 01:79 | 部分错误（有歧义） | `evidence/peer-onecli/onecli-pricing-2026-10-22.txt`：开源版 Apache-2.0 可以自托管 |
| 概念数 16 / 11 / 13 / 10 可以直接比较 | 01:35 | 无法成立（口径不一致） | `evidence/self-rekey/card.md:52`、`peer-onecli/card.md:54`、`peer-agentvault/card.md:38`、`peer-agentsecrets/card.md:36` |
| 只拿到 Rekey 私钥签不出生效规则；Rekey 不像 OneCLI 那样会被同用户自批准 | 01:75 | 前半句成立（源码）；后半句无法核实，且源码显示开 `--remember` 时存在同类路径 | `policy_approval.rs:88-122`；`main.rs` 约 L404 的 remember 帮助文本；`desktop.rs:205-211`。未实测 |
| 基线 f7d857a | 01:4 | 成立（用户确认）；远端 main 已到 26bf862，不影响结论 | 本地 `git rev-parse HEAD`；GitHub compare（f7d857a...26bf862，ahead 1），2026-10-22 |

## 高发错误清单逐项

1. 基线：查了，没问题。本地 HEAD 就是 `f7d857a`，工作区只有 `docs/peerscope` 的改动；远端多出的 1 个提交不影响结论（见建议改第 6 条）。
2. 漏了自家：查了，没问题。候选表里列了 keyspoor、cove（candidates.md:72–73）。
3. 只看 README 就说“没有”：查了，没问题。Agent Vault 和 OneCLI 的“没有”都回到了 docs 或源码。
4. 正文里的概括句没查过：发现问题，见必须改第 6 条（“都在 15★ 以下”）和建议改第 1 条（“真实需求”）。
5. 对自己宽松：发现问题，见必须改第 4、5 条（A2、A3 证据不对称；同用户自批准的双重标准）。概念数和 H1 路径反而是对自己偏严，见必须改第 1、2 条。
6. 指标归错类：查了，没有明显问题。墙钟一行条件不可比，见建议改第 7 条。
7. 用过时说法：发现问题，见建议改第 2 条。
8. 计数手数：发现问题，见必须改第 7 条。
9. 改完不同步：发现问题，见必须改第 1 条（00 写 11–13，01 表里是 10–13）。
10. 新写的内容没回源：不适用（第一次审查）。
11. 只处置必须改：不适用（第一次审查）。
12. 用截断的输出证明“没有”：查了。VoC 的 223 条 issue = 145 + 52 + 6 + 20，加和对得上；没有发现用 `head` 截断后下结论的地方。
13. 把已关闭的问题当成现状：发现问题，见建议改第 2 条。
14. 只找支持、不找反例，以及绕过实验：反向检索那一行在（01 §9）。但绕过实验只试了“读签名私钥”，没有试 `--remember` 文件、直连 admin.sock，见必须改第 5 条。
15. 离开工作区读不懂：发现问题，见必须改第 8 条（check_report 命中）、必须改第 4 条（E5 没有图例）、建议改第 7 条（P6、trace 没有链接）。
16. 只看默认配置：Agent Vault 的 strict 模式、OneCLI 的审批规则都已经注明；OneCLI 的 block 规则漏了，见建议改第 4 条。
17. 建议和我方边界冲突：查了。CLI 审批在 spec 10-05 L35 里是设计内的通道，P0 #1 不冲突；但修复方案要说清 presence proof，见建议改第 5 条。

## 前提与范围

- 前提卡写明是用户确认的：基线 `f7d857a` 加 0.4.0-alpha.1、只看好不好用、档位 deep。报告没有把假设写成用户已确认。
- 结论回答了“和类似产品比，Rekey 好不好用”，也没有重跑性能和安全，没有越界。
- 但 §5 的“安全阀最完整”、02 第 5 项的“市场叙事”有一点往安全和市场方向扩，篇幅不大，可以保留。

## 处置

（作者填写）

（以下由作者填写）

必须改：
1. 已改：协议补了概念计数口径；四家重数为 Rekey 11、OneCLI 11、Agent Vault 12、AgentSecrets 10；00、01、02、03 同步更新，02 的门槛改为 12 / 10。
2. 已改：01 §2 偏差第 2 条、§3 表头和 00 都写明测的是“不用 App 的 CLI 路径”，App 主路径没测；“门槛最高”的说法已删除。
3. 已改：§5 加了 AgentSecrets 列（源码，未实测）；00 和 01 的头条限定为“实测的三家”，并补写了 AgentSecrets 与 Rekey 同级的部分。
4. 已改：A2 改为“暂优，待复测”，并写明 10-05 测的是 0.3 版本；A3 拆成“拦截”和“完成度”两行；去掉了 E5。
5. 已改：作者回源码核对了 `mod.rs` L462–L503、`desktop.rs` L154–L162、`policy_approval.rs` L389–L420，确认 `remembered-unlock.key` 存的就是 presence 密钥。绕过结论改成“两家在同用户威胁下都可能自批准”。02 第 1 项加了方案 A/B 和绕过实测，03 G01 同步更新。
6. 已改：作者通过 GitHub API 读取并存档了 sallyport 的 README（189★、Apache-2.0、brew cask、约两分钟上手、回显不封口），已写进 00、01 §1/§6/§7 和 02“下一轮复评”第 1 条。
7. 已改：`agg.py` 跳过 excluded 的记录；总数 43，其中实际运行 35、未跑说明 7、排除 1。
8. 已改：`check_report.py` 复跑结果为 0 处命中。

建议改：
1. 已改：01 §1 和 §8 补了反向声音（G2，4 人，D1）和 Kontext 下线这件事。
2. 已改：#6 改为“2026-05-07 已修复”。
3. 已改：定价写清了“开源版可自托管”。
4. 已改：OneCLI 的 A4 补了 block 规则和 #266。
5. 已改：02 第 1 项写明要同时修测试夹具、加契约测试，并说明 presence 证明的来源问题。
6. 已改：01 页首注明了远端 main 已到 `26bf862`。
7. 已改：§8 加了 P 编号；trace 和探针都改成链接；墙钟一行改为只记录、不比较。
8. 已改：G02 的依据改为“来自自测”。
9. 已改：首屏文案改为“上游回显的 Key 会被封口”，并注明要等当前版本复测通过后再写。
