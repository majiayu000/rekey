# 2026-11-17：设计与实现对照及补齐

**结论：采用（以本 PR 两平台 CI 通过为条件）。** 0.5.0-alpha.1 源码线的软件部分已按当前生效设计补齐，可以进入所有者的真机与发布验收。81 条核验缺口中 75 条已修复，5 条部分完成（原因见“仍未完成”），1 条为所有者验收（C14 Claude 插件，所有者已排除）；集成时另发现并修复 2 个已有缺陷。尚有 1 项新的所有者决定（§7.3 第 5 点），它影响的是 App 的系统认证次数，正属于真机验收要观察的内容，不阻塞进入验收。

## 决定与范围

本轮要支撑的决定：0.5.0-alpha.1 源码线的软件部分是否已经覆盖全部当前生效的设计，可以进入所有者的真机与发布验收。
判定方法：只计入经过独立反向核验的缺口；每个行为修复都要有修复前失败、修复后通过的回归测试，规格含糊处由所有者决定后先改 SPEC 再改代码。
放弃条件：需要真实设备（Touch ID、Secure Enclave、Keychain）、已安装签名 App、真实供应商或云账号、公开发布 / tag / tap、七天日用的项目不在本轮处理，保持 Pending；需要改变 vault27 / policy8 / 审计格式、迁移或改变规则语义的修复停下来交给所有者。

源码基线 `0499a8d1`（main，已含 #94 本机 HTTP 拒绝语义修复与 #95 依赖安全升级）；集成分支 `design/completion-20261117`，代码头 `5c249ed8`，其后只有文档提交。

## 对照方法

- 审计 workflow `wf_ab631d0c-ff3`：5 个只读审计 agent 分别对照 0.5 统一实验与 Docker HA、0.5 个人桌面安全与 App 交接、Agent 调用模型 §4–§6、§7–§10、v3 基线与机械契约；每个切片配 1 个反向核验 agent，逐条尝试推翻缺口。
- 共检查 325 项要求；审计提出 64 条缺口，核验 0 条被推翻（多条修正了状态或类别），另补充 17 条，合计 81 条。
- 分类：软件 67 条，所有者决定 13 条，所有者验收 1 条。

## 所有者决定（2026-11-17）

| 编号 | 问题 | 决定 |
|---|---|---|
| S4-01 | scan 按帧计 60 次/分钟，超过 60 个暂存文件的提交被拦 | 改为每系统用户每分钟共享 600 MiB 字节额度；超额返回 RATE_LIMITED |
| S4-V01 | 钩子在 daemon 未运行、无策略、文件超 10 MiB 时阻止提交 | 与 LOCKED 一致：默认告警放行，`--strict` 才阻止 |
| S4-09 | T1 默认需审批，但 credential_process 无法传审批 ID | CLI 默认等待本机审批（≤120 秒），批准后用同一 ID 重试一次 |
| S3-04 | connect 把含用户名的绝对 `--state-dir` 写进项目文件 | 默认目录只写 command；非默认保险库保留并提示不要提交 |
| S1-01 | Worker 崩溃残留的证书 Reserved 行永久阻止 CRL | 解锁时终结为既有 Failed 状态并写审计，不改 schema |
| S5-05 | 非流式上游响应可协商压缩，绕过遮蔽 | 所有上游请求强制 `accept-encoding: identity`，非 identity 响应一律拒绝 |
| S2-09 | 预检时无弹窗读取 SE 公钥引用 | SPEC 写明非秘密的公钥查询不算读取 Keychain 秘密 |
| S3-13 | 0.4 里程碑未分批预发布、未报告行数 | 记为豁免 |
| S4-19 | 每次调用的字节数审计 | 0.5 审计格式冻结，不做 |
| S4-V04 | 扫描范围 | 只覆盖已启用 Connection / SSH / T1 引用的凭据，写进用户指南 |
| S5-04 | lab 测试每周运行 | 修订为每周只编译与 clippy |
| S5-06 | JSON 模式未校验服务警告在命令结束时才出现 | 修订 I4：交互模式发送证明前提示，JSON / 管道模式结束时报告 |
| S5-09 | 故障态停机不校验证明 | 写为 fail-stop 例外 |

## 实现

实现 workflow `wf_5182dd1e-f00`：12 个工作包各在独立 worktree 实现，每包实现后由独立 agent 审查，有阻塞意见再修；最后由集成 agent 合入 `design/completion-20261117` 并按 CI 方式全量验证。

| 工作包（分支 `design/*-20261117`） | 缺口 | 结果 | 审查 |
|---|---|---|---|
| App 链（`app`） | S3-03、S5-V01、S5-01、S5-07、S5-08、S2-04、S2-02、S2-03、S2-V02、S4-18、S4-14、S4-04、S4-05、S4-12、S4-17、S4-V02 | 16 修复 | 要求修改，已修 |
| 访问请求与审批（`access-approvals`） | S3-05、S4-02、S4-03、S4-10、S4-V05、S3-V03、S3-09、S3-V02、S3-11 | 8 修复，S4-V05 部分 | 要求修改，已修 |
| 调用方识别（`caller-identification`） | S3-01、S3-02、S3-V04、S3-07 | 4 修复 | 通过 |
| 上游编码与 Git（`upstream-encoding-git`） | S5-05、S4-08、S3-08、S5-10 | 4 修复 | 通过 |
| scan 额度与钩子（`scan-budget-hook`） | S4-01、S4-V01、S4-V03、S4-11、S4-15、S4-16、S4-V04、S4-20 | 6 修复；S4-15 与 connect 包合起来完成；S4-20 余下的证据文档在集成时补齐 | 通过 |
| connect 写入（`connect-writers`） | S4-06、S4-07、S3-10、S3-04、S4-15 | 5 修复（含 S4-15 的 `rekey hooks`） | 通过 |
| T1、SSH 与容量（`t1-ssh-capacity`） | S4-09、S4-13、S1-02、S1-03、S1-04 | 5 修复 | 通过 |
| 默认构建覆盖与门控（`default-coverage-gating`） | S3-12、S3-V01、S5-02、S5-V02、S2-V01、S2-01、S2-08、S2-05 | 7 修复，S2-V01 部分 | 通过 |
| PKI 崩溃预留（`pki-crash-reservations`） | S1-01、S1-V03 | 2 修复（S1-V03 的事实矩阵用例数在集成时更新） | 通过 |
| 脚本、HA 与 P0（`scripts-ha-p0`） | S1-05、S1-06、S1-V02、S1-V01、S5-03 | 3 修复，S1-V01、S5-03 部分 | 通过 |
| 测试稳健性与 fuzz（`test-robustness-fuzz`） | S5-11、S5-12、S3-06 | 3 修复 | 通过 |
| 文档与 SPEC 同步（`docs-spec-sync`） | S2-09、S3-13、S4-19、S5-04、S5-06、S5-09、S1-07、S2-06、S2-07、S3-14、S5-13、S5-V03、S3-15 | 11 修复（S5-13 的 CLAUDE.md 一行与事实矩阵措辞在集成时补上），S3-14 部分，S3-15 所有者验收 | 通过 |

集成的冲突与修复：15 处文本冲突全部手工合并并逐行核对（各包新增的每一行都在集成头上，合并或移动的行逐处检查）；`7dcbff9e` 把 `flate2` 写入 fuzz 工作区的锁文件（否则 fuzz CI 的 `--locked` 对齐失败）；`9336fe1e` 让插件 skill 的新示例符合指引合同（合并后该合同测试先失败、修复后通过）。

集成时发现并修复的已有缺陷（不在 81 条内）：

- `1f69bf7e`：基础模式用保险库密码批准或拒绝写操作后，Authority 写入 reason 为 `local-password` 的决定行，但 rekey-domain 的审计页校验只接受 `local-presence`，daemon 的 `AUDIT_QUERY` 因此返回 `STORAGE_INTEGRITY_FAILED`，`rekey audit list`、`audit export` 和活动页随之失效。校验现在按与 presence 决定相同的证据接受它。broker 回归在修复前失败，错误正是 `STORAGE_INTEGRITY_FAILED`。
- `5c249ed8`：暂存扫描用 `--diff-filter=ACMR` 列文件，漏掉类型变化（例如把符号链接换成含密钥的普通文件，提交不经扫描）；暂存的子模块指针又让 `git cat-file blob` 失败，提交被 USAGE 拦下。现改读 `--raw` 输出，扫描类型变化，跳过 gitlink。真实 daemon 上的两个新测试在修复前分别以“类型变化未扫描”和 USAGE 失败。
- `df4b698b`：§5、§6.3 与用户指南把“本机服务登记的审批不能由 CLI/MCP 等待”写成绝对规则；调用方识别合入后，标注相同的调用方可以等待或取消，文档已改为按标注判断。

## 验证

代码头 `5c249ed8`，本机 macOS arm64，`cargo +1.95.0`（固定工具链），负载约 5–9：

| 检查 | 结果 |
|---|---|
| `cargo fmt --all --check`、`git diff --check 0499a8d1...HEAD` | 通过 |
| `cargo check --workspace --all-targets`，默认与 `--features lab` | 通过，0 警告 |
| `cargo clippy --workspace --all-targets -- -D warnings`，默认与 `--features lab` | 通过 |
| `cargo test --workspace --offline -- --test-threads=1`（CI 原命令） | 退出码 0；123 组结果，1,216 通过 / 0 失败 / 13 忽略，用时 998 秒 |
| 三条机械契约（两条 `rg` 与 `cargo tree -p rekey-cli -e normal`） | 无匹配 |
| `cargo audit --deny warnings`，根锁与 `fuzz/Cargo.lock` | 0 条公告 |
| `cargo metadata --locked --manifest-path fuzz/Cargo.toml` | 通过 |
| `scripts/test-human-vault.py`、`scripts/test-cli-add.py`（debug CLI） | PASS |
| `scripts/test-docker-ha.py`（控制器单测） | 18 项通过 |

集成 agent 在合并后的 `9336fe1e` 上用同一 CI 命令跑过两次，都是 1,212 通过 / 0 失败 / 13 忽略；本轮 4 个新测试使总数变为 1,216。

集成 agent 在 `9336fe1e` 上另外完成、本轮代码改动不涉及的检查：`scripts/build-macos-ui.sh` 构建的 release App 包上，ConnectionContract、UI 合同（6 PASS + 3 CHECK，含真实 Swift/CLI/Broker 签署链）与 `--startup-only` 启动合同通过；`test-agent-quickstart.py`（含真实 CLI + daemon）12 项、`p5-connector-sdk.sh`、lab `child_wait` 2 项通过；新接入 security-gate 的 `p0-acceptance.sh` 与 `p0-crash-recovery.sh` 通过；9 个 fuzz 目标在 stable 下编译通过。未改动的 `p0-runtime-faults.sh` 与 `p0-durability.sh` 在本机失败，原因是已安装的 rekeyd 占用默认端口 7787（`SERVICE_PORT_IN_USE`），改用私有端口的副本通过；基线在本机同样失败。

Docker HA 真实演练（代码头 `5c249ed8`）：由 `git archive 5c249ed8` 和 `scripts/Dockerfile.dr` 构建镜像，release `rekey`、`rekeyd` 与策略夹具都从该源码编译（image ID `sha256:07480effd05a0dc41f8790e56af2c9c0035c0a87f5ec2b43414d15db9e9990c9`，linux/arm64）。`python3 scripts/test-docker-ha.py --image <tag>` 退出码 0：18 个控制器单测通过，5 项现场检查全部 PASS（加密副本推进；最后一次复制之后的写入与吊销在受隔离的切换后保留；第二次切换与新备节点；独占控制器与只读状态、终止保留节点；自有资源清理）。之后没有残留 `rekey.ha.cluster` 标签的容器、卷或网络，镜像已删除。这只证明单台可信主机上的软件行为。

## 仍未完成

所有者决定与授权：

1. **§7.3 第 5 点“全程只做一次 step-up（A2）”与固定 10 秒认证复用冲突（新）。** App 的 `.env` 导入依次写入密钥、签署策略、改写文件，共用一个系统认证 context，该 context 在首次认证后固定复用 10 秒、不滑动（v3 以来的安全决定）。用户审阅签署草案超过 10 秒时会再认证一次。建议把 §7.3 第 5 点改为“同一流程共用一个系统认证 context（固定 10 秒、不滑动），审阅超过 10 秒时再认证一次”，不放宽复用窗口；真机验收时记录实际弹窗次数。
2. **插件版本号**：`plugins/rekey/.claude-plugin/plugin.json` 仍是 `0.4.0-alpha.1`，改版本号需要所有者授权。
3. **新依赖 `flate2`**（纯 Rust 后端）：用于解码 `github-git` 的 gzip 请求体。替代方案是拒绝 gzip，但 Git 在引用较多或协商较长时会压缩请求体，拒绝后 clone / fetch 会失败。
4. **lab 储备的测试失效**（不属于默认产品；所有者已决定 lab CI 只编译）：lab 会话审批路径自 #68 起不可用（lab `local_approval` 0/8）；lab EXECUTE 路径的公开与内部错误码命名不一致，约 89 个 lab 测试失败；`executor::llm` 的 lab 夹具缺 policy8 的 `derived_credentials`（22 个失败）；根测试夹具仍用 policy format 6；rekey-cli 的 lab hygiene OAuth 用例失败。需要决定恢复还是退役这些用例。

部分完成项：

- S4-V05：没有签名策略时，`access_request` 审计行不带调用方与目标（加字段属于审计格式变更，0.5 冻结）。
- S5-03：上游已收到请求后再 SIGKILL 的场景无法用发布二进制确定性复现（公网 IP 筛查按设计拒绝本地夹具，也不允许注入 CA），已写入 SPEC §12；默认关闭的公网成功路径没有运行。
- S1-V01：`scripts/test-pki-process.py` 真实进程 PKI 验收没有在本机重跑。它需要解包的 v0.4.0-alpha.1 签名二进制，这些二进制会在数据保护钥匙串中为一次性旧保险库写入代数锚（按设计不删除），会改动所有者的真实钥匙串，留给所有者在可接受的环境中运行。
- S2-V01：lab `local_approval` 套件的新断言因上面第 4 点无法在运行时验证。
- S3-14：插件版本号，见上面第 2 点。

已知限制（已写入 SPEC 或用户指南）：C1 canary sweep 不含 T1 派生凭证、OAuth、LLM 流式、lab 接口与需审批的 SSH 签名；serve 锁之前的启动失败不留记录；App 的“需重新授权”只读当天（UTC）的审计；`.env` 导入路径没有短密钥警告；mTLS 的私网地址筛查没有测试；scan 额度只在 daemon 内存中，重启后重新计；60 号操作码常量仍名为 `PROFILE_LIST`（线格式是 Connection 列表）。

所有者验收（保持 Pending）：真实 Touch ID / Secure Enclave 次数、已安装签名 App 与 SMAppService 生命周期、真实供应商与云服务、签名公证包与公开下载、Claude C14–C16（所有者已排除）、七天日用。
