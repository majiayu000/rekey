# KEY-03：认证历史性能的后续方案（待审）

**状态：Proposed，尚未接受、尚未实现。** 本文关联 [PR #68](https://github.com/majiayu000/rekey/pull/68) 中已有的 KEY-03 测量与后续工作，不另开重复 issue。它不替代已接受的 [0.4 SPEC §5.6](2026-10-05-rekey-agent-call-model.md#56-预算与限速)，不修改生产代码、vault26 / policy7、0.3 冻结线、发布门禁或当前信任模型。合并本文只接纳研究与验收计划；不等于批准新的持久格式、缓存信任或热路径实现。

代码基线：`627b299bcd29b9779bc27689d53141ffd4a8a179`；其中生产实现继承 `7085c96d796b695bf61a17380d4ec27a736baa15`。后续实现必须重新固定当时的基线、候选和测试树，不复用旧头的通过结论。

## 1. 已知问题和已经完成的工作

[当前实测](../../evidence/2026-10-07-authority-history.md) 使用真实 Authority worker、命令队列、认证 SQLite、生产 KDF 与合成记录。共享云主机 debug、每项 5 样本的 admission 中位数为：

| 历史条数 | Authority admission | Authority settlement | 排在 admission 后的 `status()` |
| ---: | ---: | ---: | ---: |
| 1,000 | 32.87 ms | 25.36 ms | 32.87 ms |
| 10,000 | 325.62 ms | 308.80 ms | 326.77 ms |
| 100,000 | 3,583.14 ms | 3,186.73 ms | 3,583.43 ms |

`status()` 使用 `refresh_activity = false`，不是 `admin_status()`，也不是 Broker 管理 IPC。现有 JSON 中的 `admin_status*` 字段是历史名称，不能据此声称测过实际管理通道。idle status 在 100k 规模为 0.33 ms，说明该组排队时延主要跟随前面的整份历史工作；这些数值不能当作 release SLA 或改进收益。

SHA-256 换为已有 AWS-LC、SQL prepare 复用、有序插入/二分定位已经由 [格式保持优化](2026-10-05-ledger-format-preserving-optimization.md) 完成。本轮不能把这些再次列成新优化，也不能用旧 0.3 release 数字与 0.4 debug 数字相减报告提速。

当前定位：

| 代码 | 当前责任 |
| --- | --- |
| [`store/usage.rs:43–99`](https://github.com/majiayu000/rekey/blob/627b299bcd29b9779bc27689d53141ffd4a8a179/crates/rekey-vault/src/store/usage.rs#L43-L99) | 加载完整有序集合，验证摘要与 seal，然后解析每一条原始 context。 |
| [`crypto/usage.rs:24–134`](https://github.com/majiayu000/rekey/blob/627b299bcd29b9779bc27689d53141ffd4a8a179/crates/rekey-vault/src/crypto/usage.rs#L24-L134) | 原始 JSON、字段顺序、长度前缀、optional presence、严格递增 ID、总数、revision 和 vault 绑定。 |
| [`store/usage.rs:251–390`](https://github.com/majiayu000/rekey/blob/627b299bcd29b9779bc27689d53141ffd4a8a179/crates/rekey-vault/src/store/usage.rs#L251-L390) | 用量读取、admission、settlement、pending 恢复都走完整认证；变更重算完整摘要。 |
| [`history_benchmark.rs`](https://github.com/majiayu000/rekey/blob/627b299bcd29b9779bc27689d53141ffd4a8a179/crates/rekey-vault/src/store/usage/history_benchmark.rs) | 已有两个 opt-in 入口，分别测 store 与 Authority，带持久化断言。 |

## 2. 必须保留的边界

以下是后续实现的最低验收合同；其中新增的失效注入检查是**拟补验收**，不暗示现有 suite 已覆盖所有情形。

- **H1，先完整认证。** 每次可信用量读取或变更都必须检查完整有序历史，即使坏记录属于其他 principal、Connection 或 UTC 日；完整 raw-row 摘要、总数与 seal 验证成功后才能使用解析结果。SQL 索引、mtime、`PRAGMA data_version`、进程内 revision 或已缓存 totals 均不能替代此证明。
- **H2，格式与原文。** 保留现有 canonical 字节协议、AAD/AEAD、随机 nonce、revision 上限和 vault 绑定。不能先把 JSON 规范化再认证，不能静默改字段、第二账本或 schema digest。相同业务输入必须与冻结的摘要 oracle 逐字节一致。
- **H3，授权集合。** 预期新集合只能由已认证旧集合加本次允许的 row 变更推导。不能读取任意 SQL 写后状态再为其生成新 seal，把触发器或意外额外行“合法化”。拟补的触发器/额外变更验收必须在实现前加入，并明确与现有测试的覆盖差别。
- **H4，账务语义。** 保留 principal × instance × admission UTC day 的预算桶；请求一次记账；测得 token、未知 token 的保守结算、非生成零 token、重复 settlement 幂等、冲突 settlement 拒绝、checked arithmetic 及当前软上限语义不变。audit prune 不重置用量。
- **H5，事务和外部效果。** `execution.started` 与获准的 usage 变更、前置 approval audit 在同一成功事务后才允许远程效果。deadline、audit/commit/磁盘失败时保留原来的回滚与 fail-closed；丢弃 receiver 不取消已拥有的 settlement，也不能提前释放执行/审批所有权。
- **H6，生命周期。** unlock、backup/restore、rotation、重启后 pending 恢复及原有 generation/anchor 检查必须复跑。不能将 usage revision 的认证等同于逐次外部 freshness 锚定；当前 [usage 事务](https://github.com/majiayu000/rekey/blob/627b299bcd29b9779bc27689d53141ffd4a8a179/crates/rekey-vault/src/store/usage.rs#L282-L345) 与 [行政 generation 事务](https://github.com/majiayu000/rekey/blob/627b299bcd29b9779bc27689d53141ffd4a8a179/crates/rekey-vault/src/store/generation.rs#L1-L123) 是不同路径。新的 replay/anchor 方案须单独列出证明与失效模式，不能声称已具备更强 rollback 或 L1 保证。
- **H7，真实工作量。** 不削减生产 KDF、已有容量限制、审计条数、已接受 deadline/错误语义或完整验证次数来制造性能收益。现有 0.4 软件和手动设备验收保持各自范围。

### 为什么不直接换成 Merkle 路径或缓存

只校验被访问叶子的 Merkle 路径，可证明读到的记录属于认证 root，但不会立即发现另一条未访问历史记录在磁盘上损坏。一个只查当前日期的认证聚合也有相同区别。root commitment 覆盖整个逻辑集合，与每次读取都实际检查全部存储字节，是两种检测时机。

因此，“任何无关历史行被改，下次用量操作也要失败”的 H1 语义与从可变、不受信存储中跳过任意历史部分的通用次线性读取不相容。不能把后一方案命名为等价的增量认证。可信不可变快照、受保护存储或不同的损坏检测时机，均需要先有新的信任模型和发布 SPEC；本提案没有批准这些改变。

## 3. 建议实施顺序

### A. 先归因，保留现有 oracle（可独立交付的下一项）

在现有 test-only benchmark 增加阶段计数与原始时长：SQL 解码/分配、canonical digest、AEAD 验证、全量 context 解析、预算汇总、新摘要、audit/commit。记录总行数、原始 context 总字节数、最大记录宽度、扫描行数与分配量；不输出 context、凭据或请求正文。

计时 instrumentation 必须只存在于测试配置，既不绕过正常 worker/SQL 路径，也不新增生产依赖。各阶段可能嵌套，报告要说明 inclusive/exclusive，不能盲目相加成“总耗时”。先用同一 harness 在基线与候选 source tree 上各运行一次正确性验收，再比较。

本阶段只产生可复核的归因和基线。若它证明主要时间仍是必须保留的线性工作，结论应保留这一事实，不以一个未认证缓存作为自动下一步。

### B. 仅在有收益证据时，评审格式保持的流式全量验证

这是**候选设计，尚未实现**。目标是降低每次操作持有整个 `Vec<UsageRecord>` 的内存与分配成本；总扫描复杂度仍为 O(N)，不承诺降低排队时延。额外 SQL 扫描可能变慢，需用 §5 的取舍门槛决定是否保留。

建议边界：

1. 保留同一 SQLite transaction 与同一 Authority owner。第一遍按 request ID 扫描完整 raw rows，使用原 canonical 编码计算摘要/总数，验证原 seal；只保留当前行和固定摘要状态。不能把事务拆成多个 snapshot。
2. 认证成功后，在相同 snapshot 第二遍解析**全部** context，并检查现有 principal/day 关系；流式累计目标桶 totals、保留唯一目标记录及 duplicate/missing 判定。任何一条无关记录的 malformed context 仍要失败，不能使用目标 SQL WHERE 提前过滤。
3. 对插入/结算，用已认证旧 snapshot 加恰好一次授权变更，按相同排序生成预期新摘要和计数。插入要覆盖开头、中间、末尾位置；结算要保留相同 context 与幂等判断。不能让向量消失同时删除 ordered-ID 验证。
4. 写入 row、预期 state、audit 后，在提交前重新验证实际存储状态与**独立推导的预期值**相符，防止 SQL 触发器产生额外效果；还要检查 audit/header 等越界变更，而非仅看 usage 行数。具体检查机制及其成本须在实现 SPEC 中先确定。所有一致性验证发生在可能的 anchor reservation/commit 前；此项不得趁性能重构被省略。
5. 中途 deadline 只能按原错误语义安全回滚，不能提前提交半个扫描。保持先 started commit 后远程效果；不新增允许其他 Authority mutation 在半个事务中插入的调度路径。
6. 对最大行宽 W，目标工作内存是 O(W + 固定状态)，不声称无条件固定内存上限。SQLite page cache、allocator retention、备份与 KDF RSS 分开测；不通过偷偷缩短合法 context 来达到上限。

此方案首先适用于单次查询/变更。恢复多个 pending、backup 和 rotation 的多记录输出需求必须分别设计，不能把已有 Vec helper 全部替换后宣称所有生命周期都已流式化。若其额外扫描显著拖慢 admission，保留原实现，报告内存/时延取舍；不要把降低 RSS 自动宣传成提速。

### C. 真正减少历史扫描，必须另立已接受的契约

如果未来产品明确接受不同的存储信任或损坏检测时机，另开独立 release SPEC，至少确定：

- root/叶子/节点的 domain separation、canonical 编码、集合完整性、重复/缺失/乱序证明；认证聚合必须绑定 principal、instance、UTC day、requests、tokens 和计数，不能成为第二个未认证事实来源。
- admission、settlement、recovery、audit 和 header 的原子更新边界；预期根必须从已认证旧状态加授权 delta 推导，不能 seal 未经验证的 SQL 结果。
- root 的 freshness 与完整 DB/局部节点重放、crash、anchor reserve 后 commit 失败的处理；不同保护等级能证明什么。nonce 与版本规则需要独立审查。
- 初始化、unlock、备份恢复、rotation、pending 未决集合与日切路径；旧 vault 保留、新格式新建，不加入迁移、双读或 backfill。
- 逐行损坏检查何时发生、未访问页的损坏何时被发现、完整性扫描预算耗尽时如何 fail-closed，以及这些与 H1 的明确差异。

上述决定未接受前，不实现树、分段 seal、持久化 totals、revision cache 或旁路 worker；也不把本文当作此类改动的授权。

## 4. 现有可执行验收入口

以下命令在完整 checkout 中使用仓库固定的 Rust 1.95.0；这里只列**已经存在**的入口，不伪造尚不存在的 benchmark flag、测试名或通过结果。运行环境须允许正常 Unix sockets，具备 Cargo.lock 对应依赖；禁止把 EPERM 或缺依赖记作测试通过。

```bash
cargo +1.95.0 fmt --all --check
cargo +1.95.0 check --locked --workspace --all-targets
cargo +1.95.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.95.0 test --locked -p rekey-vault --lib crypto::usage::tests -- --test-threads=1
cargo +1.95.0 test --locked -p rekey-vault --lib store::usage::tests -- --test-threads=1
cargo +1.95.0 test --locked -p rekey-vault --test usage -- --test-threads=1
cargo +1.95.0 test --locked -p rekey-vault --test generation_rollback --test header_generation --test backup_restore --test vrk_rotation -- --test-threads=1
cargo +1.95.0 test --locked --workspace -- --test-threads=1
cargo +1.95.0 tree --locked -p rekey-cli -e normal
git diff --check
```

按 AGENTS.md 同时执行两项 forbidden-API 搜索，并确认 CLI normal dependencies 不含被禁 crate。重构触及 lab 编译路径时也必须补对应全 targets check/Clippy；正常 PR 的 P0、performance、fuzz 和相关失效注入门禁仍须通过，本文不替代它们。

已有 opt-in 历史基准：

```bash
cargo +1.95.0 test --locked -p rekey-vault --lib history_benchmark -- --ignored --nocapture --test-threads=1
cargo +1.95.0 test --release --locked -p rekey-vault --lib history_benchmark -- --ignored --nocapture --test-threads=1
```

每个命令必须实际运行两个命名测试：
`store::usage::history_benchmark::authenticated_usage_history_benchmark`、
`store::usage::history_benchmark::authority_usage_history_benchmark`。
要求恰好 2 passed / 0 failed、各规模完整结果。0 tests、ignored 未执行、编译失败、超时退出或部分输出均不构成验收。测试 assertions 不能移到计时后才忽略失败：必须保留每次 started/settled 成功、最终 history + 5 条、5 requests / 35 tokens、全部 pending 保守恢复、duplicate settlement 幂等、backup 非空、关闭再认证读取等断言。

当前每项只有 5 样本，仅报告 min/median/max；不能为这组数据包装可靠的 p95/p99。默认 CI 没执行 ignored benchmark 时，CI success 不等于完成 KEY-03 规模验收。

## 5. 拟补的回归与性能失败条件

这些是下一份实施 PR 要增加/扩展的验收，**本 docs PR 未新增或执行这些测试**。

| ID | 场景与必须观察的结果 | 已有入口 / 拟补缺口 |
| --- | --- | --- |
| K03-01 | 空集合、首/中/末插入、optionals、Unicode 和不同 raw JSON 编码：摘要逐字节等于冻结 oracle。 | 现有 `crypto::usage::tests`；拟补 streaming adapter 与 oracle 随机差分。 |
| K03-02 | 其他 principal/instance/旧日的行被修改、删除、增加或调序；下一次当前桶读取/admission/settlement 失败，不产生 started/terminal 新成功。 | 现有 `valid_numeric_rewrite_row_deletion_missing_root_and_cross_vault_root_fail_closed`；拟补无关桶与所有入口交叉矩阵。 |
| K03-03 | raw context 必须先被认证，全部合法性校验仍覆盖无关行；事务各遍之间的存储变更不得混用 snapshot。 | 现有 `profile_context_is_authenticated_and_terminal_cannot_rewrite_it`；拟补多遍/并发 snapshot。 |
| K03-04 | SQL 触发器额外改 ledger/state/audit/header，不能被新 seal 吸收；在产生可成功外部效果前失败。 | 拟补专门失效注入，不能假称已有全面覆盖。 |
| K03-05 | duplicate request、same/conflicting settlement、跨日、跨 principal/instance、non-generation、overflow 均与基线一致。 | 现有 admission/buckets/later-day tests；拟补两种实现的操作序列差分与溢出边界。 |
| K03-06 | 被 SQL 阻塞至 monotonic 或 wall deadline，started/usage/audit 回滚；terminal commit 故障保留保守 usage 并 fail-closed。 | 现有 `begin_checks_both_deadlines_after_blocked_sql_and_rolls_back_every_write`、`terminal_audit_failure_rolls_back_settlement_and_faults_without_lost_usage`；在多遍各阶段补注入点。 |
| K03-07 | 丢 receiver、hard kill、unlock/re-auth、backup/restore、VRK rotation、audit prune 仍满足原完整性和幂等合同。 | 现有 usage lifecycle tests 与 §4 lifecycle suites；拟补每规模/最大行宽代表组合。 |
| K03-08 | 真实 Authority 1k/10k/100k，包含空目标桶与所有记录落入同一当前桶，两种极端都通过。 | 现有 4 instance × 30 日、少量 pending；拟补当前日热桶与多个 principal。 |
| K03-09 | 0/现有稀疏/高比例 pending、窄/宽 context，分别测 recovery 和 steady state；不可由 fixture 分布隐藏成本。 | 拟补参数化；先文档化实际允许范围，不靠丢合法输入压低内存。 |
| K03-10 | store / Authority / Broker 管理 IPC 分层报告；status、lock/revoke 与 backup 干扰要真走对应操作并等待业务断言。 | 前两层已有；真实管理 IPC、长历史下 lock/revoke、重叠 backup 为拟补，不能由 `status()` 代替。 |
| K03-11 | 单独进程测每个规模，fixture seed 在测量进程外完成；分别报告进程 RSS/HWM 与操作窗口峰值相对窗口开始 RSS 的增量，记录采样方法/间隔及 KDF/SQLite/allocator 干扰；同一受控宿主对基线/候选交错测至少 3 批，每批每热操作至少 50 样本。 | 拟补采样/独立进程 harness；备份、cold unlock 单列，现有 5 样本历史数据不回写伪造。 |
| K03-12 | 原始结果包含 checkout SHA、实际测试树、harness hash、Rust/profile、OS/CPU、features、实际条数/宽度/pending 比例、原始时长和失败计数。 | 现有 receipt 可扩展；必须同时保留 baseline/candidate 结果与完整退出状态。 |

**正确性硬失败：** 任意 oracle 不一致、少/多记一笔、漏扫坏行、未认证数据影响预算、错误地成功/可重试、部分状态提交、降低安全检查或 crash/reopen 失效，立即拒绝候选；无论快多少都不进入性能比较。

**拟议性能决策门槛（尚非产品 SLA）：** 在同机、同 Rust/profile、同 harness 与规模下，3 批独立结果方向一致才讨论收益。若 B 以“降低内存”交付，100k 稳态操作窗口的增量峰值 RSS（按 K03-11 的相同采样方法）至少下降 25%，且 1k/10k/100k 的 admission、settlement、队列 status 中位时延均不得增加超过 10%；冷启动与备份变化另报。阈值需在实施前评审固定，不能看到候选结果后调整。如果数据落在噪声区，结论为未证明收益，保留旧实现。若声称时延优化，则需事先另定主指标/容忍度，不能拿内存指标代替。

无论达到哪个常数门槛，B 仍逐次 O(N)，KEY-03 的历史增长问题只能标注“缓解部分成本”或“仍开放”，不能标记成已解决。

## 6. 交付、审查与门禁

下一项最小 PR：仅 A 的测试内归因/采样改进与证据。它以真实现有入口生成 baseline receipt，保持 production blobs 不变；实现 B 前需审查其 SPEC 修订、触发器一致性机制、内存/时延取舍与回归。C 仍是独立产品/安全设计决策，不在当前批准范围。

在 `627b299b` 上重新读取到的 [P0](https://github.com/majiayu000/rekey/actions/runs/37606339179)、[performance](https://github.com/majiayu000/rekey/actions/runs/37606339271)、[fuzz](https://github.com/majiayu000/rekey/actions/runs/37606339249) 共 12 个 job 均成功。这是原基线的远程证据；本提案不把它算作新实现或新 benchmark 的结果。

[PR #68](https://github.com/majiayu000/rekey/pull/68) 已于 `2026-10-07T15:51:10Z` 以 squash commit [`9a99ed57`](https://github.com/majiayu000/rekey/commit/9a99ed5705c48724edd7b23993798e91df977172) 合入 `main`，当前版本为 `0.4.0-alpha.1`。该提交的 tree `be168e8b39df575edf128fba182ca2d92f3d5d1c` 与本文测量基线 `627b299b` 相同；历史测量仍归属于原测量提交，不作为新 head 的运行结果。

此次读取的 [Protect main](https://github.com/majiayu000/rekey/rules/22063399)（active ruleset `22063399`）要求 `P0 (ubuntu-latest)` 与 `P0 (macos-latest)`；旧 `Linux container G2 reference boundary` 已在 0.4 合并窗口退休，其他现有保护继续生效。本文不修改 ruleset、不恢复退休夹具，也不代表 release/device acceptance。上述合并和规则调整是同步基线时观察到的既有远端状态，不是本 docs PR 的改动。

本 docs PR 的验收是源码/契约引用核对、现有入口与测试名核对、文档差异审查及准确披露运行限制。§4 是下一次实现的真实执行清单；不是一份声称已在本轮跑完的成绩单。
