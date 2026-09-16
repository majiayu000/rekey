# AUD-06 本机显式执行审计清理

状态：待实现。用户已授权优先本地功能。本规格替代 P-02 中“不提供删除”的限制，仅限下述安全集合；不是自动保留策略、全部审计事件清理或合规存储。

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
