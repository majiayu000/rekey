# Agent 调用模型验收记录 · 2026-10-05

**对象：0.4.0-alpha.1 候选版，未发布。** 行为基线为[冻结 SPEC §12](../superpowers/specs/2026-10-05-rekey-agent-call-model.md#12-验收矩阵)，vault/backup26、policy7。本记录汇总并行开发中真正完成的软件检查与待验项；代码锚点只说明覆盖位置，不能单独证明测试通过。旧 0.3 报告不复用为本次验收。

## 证据口径与已完成检查

本次开发使用隔离 worktree；前一轮远端核查源 head 为 `f1a5ab95d1654912da8d80d13eabacb777f91c38`，对应 draft [PR #68](https://github.com/majiayu000/rekey/pull/68)。实现与审查修复均已提交；以下历史日志按各自执行版本保留，不把早期基底 hash 当作当时未提交源码的快照。

后续收尾已修复默认 App 仍调用旧明文 reveal 和 `connect` 忽略所选 vault 的缺口。最终合成源码完整 workspace **exit0，101组，918 passed /0 failed /10 ignored /0 filtered**，日志 `/tmp/rekey-human-workspace-test.log`。该轮在独占 `rekey-agent-call-macos-ci` 工作树执行，含 human/App 提交 `226f881` 与 root 的两个 connect 源码/测试依赖；整合后逐文件比对334个 workspace/App/human夹具文件，差异为0，不用该树基底 hash 代替当时未提交源码快照。

最新专项：19项connect通过（`/tmp/rekey-call-connect-state-green.log`），真实quickstart12通过（`/tmp/rekey-call-connect-quickstart-real.log`），default/lab all-targets check及CLI两模式strict Clippy通过。目录回归在旧实现因MCP缺少args失败（`/tmp/rekey-call-connect-state-red.log`），新实现以真实PTY写三格式，并执行hook argv recorder，覆盖空格/单引号/命令替换字面路径、扫描拒绝传递、幂等与更换vault。软件human gate与真实Swift/CLI/Broker链通过（`/tmp/rekey-human-live.log`、`/tmp/rekey-human-ui-contract.log`），完整App WAE typecheck及ConnectionContract通过；没有读取真实provider密钥或使用硬件签名者。

用户明确排除 Claude 客户端的本轮验收：C14 与 C15/C16 中的 Claude 场景不再执行命令、登录、模型或插件测试，也不记作通过。此前 `account_on_hold` / `api_error` 仅为当次返回错误，不证明用户当前邮箱或账号状态。Codex、Rekey App、provider 与设备项按各自证据判断。

| 检查 | 实际结果与范围 | 可复跑锚点 |
|---|---|---|
| Domain / Policy | 190 项通过；路径段回归在旧实现先失败、修复后通过，focused check / strict Clippy 通过。 | [Connection 判定](../../crates/rekey-policy/tests/connections.rs)、[OAuth/T1 签名上限](../../crates/rekey-policy/tests/grants.rs)、[Domain 审计合同](../../crates/rekey-domain/src/audit.rs) |
| MCP | 13 项 unit + 11 项 stdio 已实跑通过；新增 await_access 回归提交 `0ec55cb`，覆盖协议、公开发现、调用、等待、密封与 500 次调用。 | [stdio 集成](../../crates/rekey-broker/tests/mcp_stdio.rs)、[MCP 单元合同](../../crates/rekey-broker/src/bin/rekey-mcp.rs) |
| CLI | 最终 agent_call 6 项通过；token-free 命名调用、HTTP 正文、默认审批等待、错误 `next`、T1 发现和旧个人命令拒绝。 | [agent_call](../../crates/rekey-cli/tests/agent_call.rs) |
| Swift | 两条脚本入口链通过：真实 CLI / daemon 的 Connection 草案签署激活与 subprocess boundary；使用软件测试签名者。App Connection 合同和完整源码 typecheck 通过；SSH 更新后再次通过，新增完整三集合 draft、旧 host/rule ID 保留、公钥展示和生成 proof 只走 stdin 的检查。 | [脚本](../../scripts/test-macos-ui.swift)、[App 合同](../../apps/macos/Tests/ConnectionContract.swift) |
| Python quickstart | 启用真实 CLI / daemon 的 12 项通过，另有 fake CLI 边界；没有登录真实 provider。 | [quickstart 测试](../../scripts/test-agent-quickstart.py) |
| 个人 IPC | 最终 8 项通过，覆盖完整签名、dry-run、反射密封、精确审批、审计失败、共用预算、新 HTTP 拒绝及 C2 的500次调用。 | [personal_policy](../../crates/rekey-broker/tests/personal_policy.rs) |
| SSH | 4 个真实 UDS 合同通过，含标准 wire / session-bind、unknown-host 审批、签名 host 窗口和 OpenSSH git namespace 签名；并读取实际审计页。另有真实 OpenSSH / GitHub push，通过生产 KDF 与 Authority 内部生成 key，不导出私钥。 | [ssh_agent](../../crates/rekey-broker/tests/ssh_agent.rs)、[live_ssh](../../crates/rekey-broker/tests/live_ssh.rs) |
| OAuth / T1 | delegated_credentials 最终9项通过，使用合成 IdP / STS / GitHub；另有 OAuth gate/锁定/排队/错误终态及成功刷新后 preflight 拒绝的 RED→GREEN，最终日志 `/tmp/rekey-call-delegated-reviewed.log`。 | [delegated_credentials](../../crates/rekey-broker/tests/delegated_credentials.rs)、[OAuth](../../crates/rekey-broker/src/oauth.rs) |
| `.env` / scan | 最终 broker hygiene14 + vault hygiene8 通过，含真实 vault、原子改写/0600 备份、符号链接拒绝、预览脱敏、大小限制与审计 fail-closed。 | [hygiene](../../crates/rekey-vault/tests/hygiene.rs) |
| 原生 Codex | 真实 Codex 六个 MCP 工具的 U2–U5 合成上游链通过，1 passed、2 filtered、67.74秒；软件 P256 与合成 Presence 模拟用户批准，trace 无 canary。 | `e54a2dd` 的 `crates/rekey-broker/tests/native_agents.rs`；`/tmp/rekey-clients-native-codex.log` |
| Codex / 真实 GitHub 分项 | GitHub preflight200，原生 Codex 实际 read200；Rekey Presence 审批 POST201 创建 issue67，再审批 PATCH200 关闭，typed audit 校验和秘密未泄漏检查通过。历史双客户端测试 exit101，因当次 Claude 无实际读；该客户端现已排除本轮验收。 | [native_agents](../../crates/rekey-broker/tests/native_agents.rs)，`/tmp/rekey-clients-live-github-ua-fixed.log`，74.07秒 |

性能恢复前的整合检查 `cargo test --workspace --no-fail-fast -- --test-threads=1` **exit0**。该轮源代码包括两项OAuth回归、插件marketplace与修复脚本，先于性能夹具恢复；按 `/tmp/rekey-call-workspace-submission.log` 的101个 `test result` 行相加，合计 **917 passed /0 failed /9 ignored /0 filtered**。Linux平台导入修正后的整合目录又以4线程通过同样917/0/9（`/tmp/rekey-call-workspace-current-ci-fixes.log`）；此轮仍先于性能夹具恢复为默认ignored。通过数包含 broker lib188、MCP unit13/stdio11、CLI agent_call6、个人 Connection8、delegated9、SSH UDS4 与完整 vault 回归，不重复加到917。

9个 ignored 为：broker owner 子进程辅助夹具1、generation rollback 子进程辅助夹具1、手动 live SSH1、旧 SDK Claude/Codex 场景2、原生 Agent 手动场景3、正式签名 peer identity1。它们未在这轮自动测试直接通过；live SSH另有独立实跑记录，子进程 helper 由各自父测试调用，旧 SDK 与设备项不能借 ignored 宣称完成。默认 cfg 排除的 lab targets 显示0项测试也不代表其 runtime 通过。前一轮旧 `broker_ipc` 夹具的 `INVALID_FRAME` 失败保留在 `/tmp/rekey-clients-workspace-m6-fixed.log`，最终修复后的全仓绿不改写旧日志。

原生 Codex 独立命令为 `cargo test -p rekey-broker --test native_agents codex_native_approval_and_access_flow -- --ignored --nocapture`，日志中为 exit0、1 passed /0 failed /0 ignored /2 filtered。该新增手动测试提交晚于早期915项全仓日志，不混入早期统计；User-Agent 修复及新增3个手动测试后的全仓再次 exit0（`/tmp/rekey-call-workspace-post-live.log`，915 passed /0 failed /9 ignored，101组）。OAuth gate 首轮整合后的全仓亦 exit0（`/tmp/rekey-call-workspace-final-gate.log`，915/0/9），其后新增锁定与 preflight 回归；最终9/9 M6及 default/lab strict Clippy 通过，最终全仓统计见下表。真实 GitHub 命令为 `cargo test -p rekey-broker --test native_agents live_github_native_reads_and_presence_approved_issue_cleanup -- --ignored --nocapture`；最初缺 User-Agent 的403已修复。最终日志证实 Codex 读和审批写入/清理分项，但因当次 Claude 返回 `account_on_hold`、无实际读，末尾 both-native 断言失败，整体0 passed /1 failed /2 filtered、exit101。不能把分项结果写成原双客户端C15通过；该历史错误不推断当前账号状态，本轮不再执行Claude验收。[测试 issue67](https://github.com/majiayu000/rekey/issues/67) 已关闭，执行 lane 又用独立 `gh api` 读确认 closed。源码 `e54a2dd` 已整合为 `fd8686e`；后续随机 marker 修复不重用为一次新的外部验收。

| 已完成本机 gate（对应各日志版本） | 命令/范围 | 已核查日志 |
|---|---|---|
| Default all-targets | `cargo check --workspace --all-targets` | `/tmp/rekey-call-reviewed-check.log`，Finished |
| Default strict Clippy | `cargo clippy --workspace --all-targets -- -D warnings` | `/tmp/rekey-call-reviewed-clippy.log`，Finished |
| Lab all-targets | `cargo check --workspace --all-targets --features lab` | `/tmp/rekey-call-lab-check-last.log`，Finished |
| Lab strict Clippy | `cargo clippy --workspace --all-targets --features lab -- -D warnings` | `/tmp/rekey-call-reviewed-lab-clippy.log`，Finished；只证明企业储备编译 |
| 完整 workspace | `cargo test --workspace --no-fail-fast -- --test-threads=1` | `/tmp/rekey-call-workspace-submission.log`，exit0，917/0/9 |
| Rules fuzz smoke | [`connection_rules`](../../fuzz/fuzz_targets/connection_rules.rs)，41,065次 | `/tmp/rekey-call-fuzz-rules-final.log`，exit0，OOM/timeout/crash=0/0/0 |
| SSH ASan fuzz smoke | [`ssh_agent`](../../fuzz/fuzz_targets/ssh_agent.rs)，38,124次 | `/tmp/rekey-hygiene-m7-fuzz-ssh-agent.log`，exit0，OOM/timeout/crash=0/0/0 |

恢复性能夹具之后，默认suite会多发现1个ignored benchmark。perf worktree的完整workspace为 **916 passed /1 failed /10 ignored**（`/tmp/rekey-perf-workspace-test.log`）；唯一失败是未修改的 `successful_admin_lists_reset_idle_activity` 的30ms相对计时断言。其serial exact独立复跑两次均exit0（`/tmp/rekey-perf-idle-rerun1.log`、`/tmp/rekey-perf-idle-rerun2.log`）。CPU争用是可能解释，尚未独立证明原因；保留失败，不改Vault代码/阈值，不将该lane全仓说成通过。

性能门槛已恢复为默认可选中的签名Connection/CALL，独立60秒soak **1 passed /0 failed**，总运行100.92秒含setup，日志 `/tmp/rekey-perf-current-run.log`，JSON `/tmp/rekey-perf-current-report.json`。1927调用/0错误，1941 started/terminal/finished精确配对；512 queue尝试中128接受/384busy、500 durable audit、119/7 IPC handlers及各1reserve、12×4MiB密封、3次lock/unlock、2次周期备份、备份干扰和shutdown drain1均通过，RSS窗口差-4602KiB在64MiB增长上限内。原capability每Session四permit随模型作废，其余门槛保持。该本机报告在提交前执行，JSON commit标记为基底d6937e2；对应fixture文件完整提交为7c2d783，不把基底hash当作未提交源码快照。default/lab all-targets check与scoped strict Clippy通过，独立审阅无finding。CI先删旧JSON再要求本次非空报告，防止零测试/旧报告假绿。

Rules/SSH fuzz 都是短 smoke，不是长期 fuzz 或漏洞不存在证明。dotenv / secret_scan 此前各有1000次局部执行报告，但本次未找到原始日志，不补编日志，不作为最终发布 gate 通过证据。旧 hygiene 规则 fuzz 日志曾产生 crash，不能拿其当最终绿；上表引用的是修复后的独立最终 rules 日志。CI 配置存在不等于远端 GitHub workflow 已成功运行。

## 当前提交的远端检查

只读核对 GitHub 完成 job 的日志，未重跑外部测试。[security-gate run 37322706572](https://github.com/majiayu000/rekey/actions/runs/37322706572) 的源 head 为 `f1a5ab9`：

| 检查 | 实际结果 | 日志 / 边界 |
|---|---|---|
| Linux P0 | job success；workspace101组 **918 passed /0 failed /7 ignored** | [job111805544212](https://github.com/majiayu000/rekey/actions/runs/37322706572/job/111805544212)，只汇总 `Connection, CLI, MCP and workspace tests` step；另有真实ENOSPC6/6和SDK8/8，不重复加进918。下载日志 `/tmp/rekey-evidence-ci-linux-f1a5ab9.log`。 |
| macOS P0 | workspace101组 **917 passed /0 failed /10 ignored**；整个 job failure | [job111805544562](https://github.com/majiayu000/rekey/actions/runs/37322706572/job/111805544562)，Swift两链通过；旧 `test-human-vault` 调用已移除的 `desktop-reveal`，Native contracts step exit1。下载日志 `/tmp/rekey-evidence-ci-macos-f1a5ab9.log`。该脚本由独立lane修复，修复后的head须另验。 |
| Fuzz | 当前head9个jobs全success | [run37322706693](https://github.com/majiayu000/rekey/actions/runs/37322706693)：policy、ssh_agent、dotenv、ipc、action、secret_scan、connection_rules、restore、response_sealing。此处记录远端job结果，不混用早期本机迭代数。 |
| Performance | 当前head真实1 test通过，110.62秒；**1001 CALL /0错误、1015组 started/terminal/finished** | [run37322706594](https://github.com/majiayu000/rekey/actions/runs/37322706594)，日志 `/tmp/rekey-call-performance-final-ci.log`，本次报告[artifact11350957428](https://github.com/majiayu000/rekey/actions/runs/37322706594/artifacts/11350957428)。 |

性能JSON的 `commit=a7e98c9de615f676409071c9283561bcac2b2579` 是 GitHub 的 PR merge ref；checkout日志明确为将源 head `f1a5ab9` 合入 `043a020`，不能将merge ref伪称为源分支hash。60秒soak的110.62秒总运行时间包含setup与其他性能检查；报告中的512 queue尝试（128接受/384busy）、500 durable audit、IPC容量、12×4MiB密封、3次lock/unlock、2次周期备份、backup干扰和shutdown drain均有本次结果。Linux P0绿、macOS workspace绿不把macOS整job红改写为全CI通过。

上述检查的主要复跑命令是 `cargo test -p rekey-domain -p rekey-policy`、`cargo test -p rekey-broker --test personal_policy --test ssh_agent --test delegated_credentials -- --test-threads=1`、`cargo test -p rekey-broker --bin rekey-mcp --test mcp_stdio -- --test-threads=1`、`cargo test -p rekey-cli --test agent_call` 与 `REKEY_QUICKSTART_REAL=1 PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-agent-quickstart.py`。Swift 脚本的合法入口是 `CLI_BINARY` 或 `--subprocess-boundary-only`；它们不调用真实 Touch ID。复跑结果须另记，不凭列出命令宣称通过。

## C1–C16

“部分”表示已有通过的软件证据，但仍缺该验收条目的完整场景；“待验”表示所要求的真实外部或设备场景没有执行。

| 项 | 状态 | 已有证据 | 尚缺证据 |
|---|---|---|---|
| C1 所有调用方不返回长期明文 | 部分 | CLI / MCP / HTTP 的合成 canary 及变体密封；SSH 私钥不返回；[hygiene](../../crates/rekey-vault/tests/hygiene.rs)、[MCP](../../crates/rekey-broker/tests/mcp_stdio.rs)、[SSH UDS](../../crates/rekey-broker/tests/ssh_agent.rs)。T1 临时值单独标注。 | 全接口最终组合回归与真实客户端观察；不能把 T1 输出描述为完全不接触凭据。 |
| C2 500 次 allow 不打扰 | 软件通过 | MCP 的 `direct_mcp_performs_500_calls_without_proof_token_or_agent_launcher`；个人 IPC `five_hundred_allowed_reads_require_no_presence_or_capability`。 | 最终全仓中两组已通过；无 presence/token/launcher，且 approval.requested计数为0。真实 UI 的零交互观察仍需确认。 |
| C3 规则语法与优先级 | 软件通过 | [connections](../../crates/rekey-policy/tests/connections.rs)：路径注入、未声明查询、deny / specificity / approve ties、GraphQL 与签名语义读；命名参数 `a/b` 新回归在旧实现失败、修复后通过。 | 最终集成全量回归已通过；真实上游可用性独立验收。 |
| C4 调用方只能收紧 | 部分 | `forged_or_missing_caller_never_expands_defaults`、[caller 标注](../../crates/rekey-broker/src/ipc/caller.rs)，同 UID 标签不作为安全边界。 | 真实进程 exec / 父进程伪装矩阵及正式 TeamID 设备检查。 |
| C5 HTTP A6 | 部分 | [gateway](../../crates/rekey-broker/src/runtime/gateway.rs)、个人 IPC 反射/真实 key 拒绝；新增强制公开占位头、Host / Origin 和浏览器头拒绝。 | 最终个人IPC8已验证真实key、缺占位标记、evil Host、Origin、cross-site Sec-Fetch-Site拒绝且不出站；完整浏览器/DNS rebinding现场仍待验。 |
| C6 访问请求 | 部分 | [local_calls](../../crates/rekey-broker/src/runtime/local_calls.rs)、[agent IPC](../../crates/rekey-broker/src/ipc/agent.rs)、[App 合同](../../apps/macos/Tests/ConnectionContract.swift)；请求、等待、签名激活后 resolve、屏蔽、10 分钟过期和限速。 | 原生 App 请求→处理→await 全链、通知权限与实际等待过期。 |
| C7 时间窗 | 部分 | `one_time_approval_binds_body_and_window_never_overrides_deny_or_lock`；SSH signed-host 专项 UDS 回归；App 完整 review/hash/window 软件合同。 | 实际 30 分钟跨 UI/HTTP 调用与策略变更后的现场验证。 |
| C8 `.env` 导入 | 部分 | [hygiene](../../crates/rekey-vault/tests/hygiene.rs) 的 preview / import / rewrite、0600 备份和 unsupported 保留；Swift stdin 合同。 | App 实际选择→签署→改写→SDK 成功调用。并发编辑残余窗口有明确限制。 |
| C9 防泄漏 | 部分 | 完整秘密及 raw/base64/JSON escape、位置输出和部分匹配拒绝；真实 vault 扫描、hook 受管写入、固定本机用户限速桶。 | 最终hygiene已绿；暂存区pre-commit完整阻断/限速的现场矩阵仍需记录。 |
| C10 SSH agent | 软件与真实 push 通过 | 4 个 UDS / OpenSSH 合同、unknown-host / missing-bind 审批与明确 deny；[live_ssh](../../crates/rekey-broker/tests/live_ssh.rs) 实际向 GitHub push 并核对审计，日志 `/tmp/rekey-call-live-ssh.log`。App 已补完整 SSH 编辑/签署软件链。 | App 正式签名设备上的密钥生成、host 登记和签署交互仍待验；不以 software signer 代替 Secure Enclave。 |
| C11 OAuth | 部分 | 合成 PKCE / callback、refresh rotation / cache、反射密封、`NEEDS_REAUTH`、过时 callback 拒绝与审计修复检查。 | Google / GitHub / Slack / Notion 的真实用户 client 登录与刷新；各 provider 不可互相替代验收。 |
| C12 T1 | 软件通过 | 合成 STS 校验签名 role / region / session policy / TTL、presence、cancel、实际 expiry 审计；EKS 与 GitHub App 固定目标 / 权限；普通 HTTP 不接收 OAuth/AWS 根 payload。 | 真实云服务可用性与下游工具配置；不把临时值 stdout 宣称为长期密钥泄漏。 |
| C13 connect | 软件通过 | [connect](../../crates/rekey-cli/src/commands/connect.rs) 与其测试覆盖预览、确认、备份、幂等标记段、拒绝异常文件；Python real quickstart 通过。 | 用户环境实际配置 diff 与客户端加载仍需验收。 |
| C14 Claude 插件 | 本轮排除；保留历史安装证据 | [marketplace](../../.claude-plugin/marketplace.json) 与[插件源码](../../plugins/rekey)；本机真实 Claude CLI 在隔离配置下 user/project 添加市场和安装均exit0，`rekey@rekey` enabled，缓存含清单/MCP/skill，项目设置有效。`/tmp/rekey-clients-plugin-install.log`。 | 用户要求本轮不再执行Claude命令、登录、模型或插件测试；未验场景不记通过，历史安装未修改常规全局配置。 |
| C15 真实 Agent | Codex分项通过；Claude本轮排除 | 真实 Codex 已完成 U2–U5合成上游链与真实 GitHub read200；审批 POST201 创建 issue67、审批 PATCH200 关闭，typed audit 有效且无根密钥泄漏。使用软件P256/合成Presence模拟用户批准，日志和命令见上。 | 历史Claude无MCP最小检查返回 `account_on_hold` / `api_error`，只说明当次错误，不判断当前邮箱账号状态。双客户端历史测试未通过；用户排除本轮Claude验收，未执行项不改为通过。 |
| C16 两分钟体验 | App设备项待验；Claude本轮排除 | App 保存→完整 Connection 审阅→签署激活的软件合同，正式 App 严格签名校验通过。 | 此前设备核查为 `CGSSessionScreenIsLocked=true`，当时新候选及已安装旧版的离线 init 均exit5；相同签名/profile的独立synthetic DPK查找返回-25300、插入返回-25308（不允许交互）。当前正式候选仅构建/签名验证、未安装；App真机计时仍待验，密码≤1次、Touch ID≤2次、总时长≤2分钟。Claude相关场景本轮排除，不继续执行。 |

## 独立安全审查收尾

独立只读审查覆盖规则、HTTP / caller、SSH、OAuth/T1、dotenv / scan。下列确定缺口的修复和客户端回归已整合至当前源 head；历史lane提交hash保留，不称为公开审计认证：

| finding | 触发与修复 | 证据 |
|---|---|---|
| P1 connect连接错误vault | MCP配置、受管CLI说明与pre-commit未使用所选state目录，可能误连旧default vault；现全部绑定同一绝对目录并安全引用shell路径。 | 旧实现RED、新实现connect19/0；真实hook argv、三格式、幂等及更换目录通过，独立只读复审闭环。 |
| 默认App使用已归档reveal | UI显示/复制入口与新I1冲突，默认CLI没有该命令；移除无效UI及读取缓存链，human gate改为opaque保存/轮转及签名扫描。 | 3项存值、v2轮转、逐次A2、remember/restart/revoke、真实audit-failed mutation无stdout且版本不变；Python与Swift真实链通过。 |
| P1 命名路径参数可扩大语义读 | 签名外部 preset 的 string schema 不含 regex，`a/b` 原样插入 `{id}`，POST 可跨越原单段授权；所有替换段复用既有 `slug(value,100)`。 | `0278225`；`signed_external_preset_path_arguments_cannot_expand_semantic_read_segments` 真实签名 RED→GREEN；190 项 domain/policy 通过。 |
| P1 派生取消后仍可能发布结果 | 派生完成与锁定/取消之间的竞态；root 以执行存活检查阻止终态发布。 | 修复已整合于 `d6937e2`；历史回归 `f571974` 的 `locking_during_sts_issuance_cancels_without_publishing_temporary_credentials` 通过。 |
| P1 OAuth 刷新副作用 | 发出前复用生命周期gate，取消/后续拒绝保留已发生的刷新，缓存命中保持blocked语义；只记录一个终态。 | 锁定/排队与刷新后preflight均RED→GREEN，最终9/9 M6，独立复审确认闭环。 |
| P2 EKS expiry 精度 | 临时响应的客户端 expiration 与签名 URL 的秒级实际寿命边界不一致；按签名时间对齐并提前客户端刷新。 | root 集成修复；`f571974` 扩展的 `eks_credential_binds_signed_cluster_and_returns_no_long_term_secret` 验证签名时间+900秒，7/7组通过。 |

OAuth 活动审计现使用绑定签名 Connection / credential / policy 的 factory；callback 与 refresh 失败不再因缺少授权证据导致审计完整性拒绝，6/6 修复检查绿。失败审计仍 fail-closed，没有删掉审计断言来放行。

审查另外促成强制公开 HTTP 占位标记、固定 UID scan 桶、公开出站 User-Agent 和 `.env` 并发编辑限制说明。收尾源码的 Developer ID App 为 `target/agent-call-pr68-final-signed/Rekey.app`，构建日志 `/tmp/rekey-call-pr68-final-signed.log`，build exit0、`codesign --verify --deep --strict` exit0。它尚未发布或安装；历史 `agent-call-reviewed-signed` 结果不替代本次构建。DPK只读查询与独立synthetic写入、旧版/新版 init 对照排除了目前可证实的profile漏配；设备锁定下插入-25308的证据为 `/tmp/rekey-call-dpk-mutation-probe.log`，未读取真实Keychain值或降低DPK边界。

独立最终审阅发现OAuth刷新未复用副作用gate：等待刷新锁的请求可能在LOCK后继续发起轮换，取消时错记blocked。修复先进入SPEC，再复用现有gate/guard/AtomicU8；缓存命中保持无副作用，失败与取消产生唯一indeterminate。`locking_during_oauth_refresh_records_one_remote_terminal_and_cancels_queued_reads`在旧实现RED，在最终实现GREEN，并检查invalid_grant失败终态与无二次IdP/API请求；最终又补成功刷新后目标 preflight 拒绝分支：有先前刷新记 indeterminate，缓存命中仍 blocked，回归验证唯一终态与不再次刷新；`/tmp/rekey-call-oauth-preflight-red.log` 为旧实现 RED，`/tmp/rekey-call-delegated-reviewed.log` 为9/9 GREEN，default/lab strict Clippy通过。独立复审确认该P1闭环，无相关实质残留。

运维修复脚本也已改用签名 Connection，移除旧 action/admin-session 参数；真实 PTY 隐藏输入、拒绝/EOF、零执行轮换和新版本 TLS 读取通过，执行lane与root均通过，最终日志 `/tmp/rekey-call-repair-reviewed.log`。

新版archive smoke已替换旧Profile/capability/P9，使用archive提供的5个默认binary、vault26/policy7、固定公开测试origin、合成密钥和外部软件签名，实跑CLI/MCP读取、写审批、scan、connect预览、lock/shutdown通过，最终包含新marketplace/plugin与修复脚本（`/tmp/rekey-call-smoke-reviewed.log`）。实际workflow的打包步骤本机执行，Markdown原始source链接转为精确tag GitHub链接；inventory通过。macOS profile/pkg/distribution共32项再次通过（`/tmp/rekey-call-{profile,pkg,distribution}-reviewed.log`）。它们不是已公开下载或已安装的notarized包证明。


[default security gate](../../.github/workflows/security-gate.yml)保留 check / strict Clippy / workspace、真实 quickstart、Vault / P0 故障与备份耐久、ENOSPC、机械和依赖边界、Swift 软件合同；本机检查与当前远端结果见上表；Linux真实ENOSPC已通过，前一轮macOS整个P0因旧human脚本失败；其修复本机已验，最终head的CI及正式安装/下载仍需独立证据。[lab gate](../../.github/workflows/lab-weekly.yml)仅声明企业储备编译与归档语法，旧 runtime fixtures 未验收。

C10 真实 push 使用 `majiayu000/rekey` 临时 deploy key 和 ref，结束后已核对 key 列表为空、准确 ref 查询404；没有把生产私钥导出。临时 ref 为 `rekey-c10-acceptance-1791201885233`，证据在上述专用日志。

新增IPC共12个（agent9–16、admin62–65，复用agent6/7），以 [ipc常量](../../crates/rekey-domain/src/ipc.rs)核对。OAuth/T1 与 App 源码已落地；M1–M7没有分别公开预发布，也没有按里程碑完成生产/测试LOC拆分，≤3000生产净增目标尚未证明。

M7 尚未闭合：Claude相关C14/C15/C16已按用户要求排除本轮执行，未验项不记通过；真实OAuth/云服务、App设备C16、最终head CI及公开预发布下载/安装仍待补。最终本机软件gate绿不等于候选版冻结或已经发布。未创建公开 tag 或发布，不将候选文档当成可下载 release 的证据。新日志应更新本报告中的对应行并附实际命令、时间、版本和结果，不能凭实现代码把待验改为通过。

远端PR为[#68](https://github.com/majiayu000/rekey/pull/68)，前一轮CI源head `f1a5ab9`，仍为draft。首个head的Linux strict Clippy导入错误已修复，早期performance success实际0 tests的结果不作为验收；当前真实performance通过，具体CI分项和macOS剩余失败见上表。本次只读main规则仍要求 `P0 (ubuntu-latest)`、`P0 (macos-latest)` 和旧 `Linux container G2 reference boundary`；SPEC已把G2移入lab，合并前须maintainer对齐必检规则，不能以lab编译冒充旧G2运行验收。
