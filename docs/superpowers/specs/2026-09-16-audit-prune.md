# AUD-06 本机显式执行审计清理

状态：已实现并通过本切片定向验收；主线程工作区全量验收待整合。用户已授权优先本地功能。本规格替代 P-02 中“不提供删除”的限制，仅限下述安全集合；不是自动保留策略、全部审计事件清理或合规存储。

## 命令与授权

`rekey audit prune --before-ms CUTOFF` 经现有 Admin socket 操作，复用 password/recovery 的隐藏 TTY 或显式 stdin step-up。Agent 不提供此操作。要求已解锁，逐次验证 proof，截止时间沿用 Admin mutation deadline 并传入 Authority；CLI 不直接读取 SQLite。

cutoff 是非负且不晚于当前时间的 Unix 毫秒，严格选择 `< cutoff`。本轮不选择默认保留天数、不加定时器、预览平台或新配置面。该命令是显式数据删除，不在真实用户保险库执行验收。

## 保留与删除单位

- 按内部 `request_id` 整组选择。必须存在 `execution.started` 和唯一 terminal，组内所有记录时间均早于 cutoff。
- 保留未完成执行、跨 cutoff 的整组记录，以及具有任意 approval 关联的 request 组。申请和执行通过 `approval_request_id` 关联，旧 grant 以后仍可能再次提交，因此不能简单按 request_id 删除审批历史。
- 所有非 execution 管理记录、审批记录、备份记录及清理标记保留。不能把本切片宣称为所有日志类别回收。
- 删除组内的相关 connector 事件，不能留下孤立的执行中间事件。遇到不满足预期配对的记录，保留该组；不能修复或掩盖既有完整性错误。

## 事务与分页

AuthorityWorker 在单个 SQLite 事务中选择、删除并追加 `audit.pruned` 成功事件。提交紧邻之前再次检查 mutation deadline。SQL、审计或截止时间失败必须整体回滚；审计失败沿用 Authority fault 语义。

成功回执只包含 cutoff、删除行数、执行组数及清理标记 sequence。没有可删行时返回零和无标记，不制造分页失效。重复命令在同一 cutoff 下允许返回零。响应丢失时结果不确定，不能宣称未删除。

保留永久的 `audit.pruned` 标记。带旧 snapshot 的查询如果 `snapshot_max_sequence` 小于最新清理标记 sequence，明确返回 `AUDIT_SNAPSHOT_EXPIRED`，不悄悄跳过已删记录或自动换快照。新查询使用当前最大 sequence。SQLite 的既有 AUTOINCREMENT 保持游标单调；不新增 schema/format version。

JSONL 多页导出若中途快照失效，必须失败，不输出完整结束记录或成功 receipt，按现有失败合同保留可识别的未完成文件。

## 验收

使用临时保险库和合成事件，验证旧完整组删除，cutoff 等值、跨界、未完成、审批关联及管理事件完整保留。验证清理后的新执行、terminal、重启 reconcile 与重复清理，不制造孤儿配对或重复恢复记录。

故障测试覆盖删除后 SQL/审计失败及提交前超时，确认删除和标记同时回滚。旧分页与进行中的多页导出必须显式失效；无删除不使旧快照失效。IPC/CLI 测试覆盖锁定、错误 proof、Agent 拒绝与恶意回执。

该操作不执行 VACUUM，不承诺数据库文件缩小、安全擦除、WORM 或旧备份同步删除。主分支仅在实现和上述验证到达后更新成熟度。

## 线协议与精确选择

Admin 消息 `AUDIT_PRUNE = 39`。metadata 为 `{before_ms: i64}`，proof 仅在
既有 proof-only body 中。回执为 `{before_ms, deleted_rows, deleted_groups,
prune_sequence}`；最后一项只有非空清理才是正 sequence，否则为 null。
CLI 拒绝未知字段、额外 body、cutoff 不匹配、越界序号或不一致计数。
非空清理标记必须大于删除行数，符合既有 AUTOINCREMENT 序号约束。

可删组必须恰有一条 started 和一条 terminal，terminal sequence 晚于 started；
terminal 限 finished/blocked/indeterminate。无 started 的 blocked 永远保留。
组内其他事件只允许 `connector.github.authorized`、`connector.github.token_revoked`、
`vault.lease.issued`、`vault.lease.revoked`。任意审批事件或任意事件的非空
approval_request_id/approval_id/approver_id 均保留整组。管理/未知事件同组同样保留。
逐行复用审计的存储完整性解析，解析损坏必须报错；不通过删除把损坏隐藏。

快照过期判断使用全表最新清理标记，先于任何查询过滤。snapshot 等于标记时仍可用。
Admin 连接关闭可能丢失已入 Worker 的操作结果，不会将后台仍可能提交的操作返回为
明确的 Busy；不为断连建立新的取消协议。

## 本切片验证证据

- Vault 集成测试 6 项通过，覆盖三个 terminal、各类保留组、全局/过滤/重启快照失效、两次重启 reconcile、重复 no-op、后段 SQL/审计/提交失败回滚及一万执行组的截止时间内清理。使用原 schema；重复 started/terminal 由现有唯一索引拒绝，另验证可构造的 terminal 先于 started 异常保留。
- Store 定向测试 1 项通过。测试专用 AFTER INSERT 触发器确认已删除目标行并写入 marker，再消耗时间使提交前 deadline 过期；验证删除和 marker 同时回滚，无生产探针。
- 真实 Broker IPC 测试 1 项通过，覆盖成功清理、locked/Agent/错误或缺失 proof 拒绝、旧快照失效与 marker 等值快照可用。
- CLI 进程协议测试 2 项通过。使用合成 Broker 验证正常/no-op 回执、恶意回执、proof body 与输出秘密 canary，以及多页导出收到过期错误后没有 complete trailer 或成功 receipt。协调者另用真实 CLI/Broker 和真实 schema 的一次性合成库验证了 locked 拒绝、step-up、2 行执行组删除、旧 snapshot 过期、no-op 及输出 canary（本机 artifact `audit-smoke.log`）；导出中途失效仍由 CLI 协议测试和真实后端快照测试分别证明。
- 不在真实用户保险库运行清理；不扩展为自动保留或所有审计类别回收。
