# AUD-06 解锁状态下的自动审计保留
结论：采用 admin step-up 设置/撤销的持久年龄策略，后台仅在 unlocked 时自动清理；旧逐次 apply 提案已被用户选择取代。用户已明确允许该自动维护授权。本文件在源码修改之前冻结，未宣称已实现或验收。
当前证据：Worker 单线程 owns Store/VRK；audit_prune 已有完整组、完整性解析、deadline、删除+marker 单事务；Broker 已有 idle_task 与 lifecycle coordinator（authority.rs:172-190；store/audit_prune.rs:21-113；runtime.rs:782-811）。
1. 接口只有 `audit retention set --days D|--disable`、`audit retention status`；无 apply、默认 D、interval flag、Agent 操作、保存 proof 或自动 unlock。
2. Root 保留 schema/FORMAT 20→21；Admin `AUDIT_RETENTION_SET=50`、`AUDIT_RETENTION_STATUS=51`，managed 分类上界同步；状态读仍遵循 owner/OIDC 管理授权，取消 step-up 仅限状态读。
3. SET metadata 为 `{"days":D|null}`、body 仅现有 password/recovery proof；CLI 必选且互斥，null 表示撤销。STATUS metadata `{}`、原始 body 空；返回 DTO `{days:Option<u64>,updated_at_ms:i64}`，empty body；unknown fields/非法回执拒绝。
4. Worker 验证正整数 D 的 checked `D*86400000` 能表示 i64；SET 的 Authority now/cutoff 必须非负可表示，否则 Domain(InvalidAuditQuery)；不可 clamp。时钟本身无效返回现有 ClockUnavailable。
5. SET require_unlocked→verify_proof→立即 drop/zeroize proof→验证原 seal→生成新 seal→原 mutation deadline 下提交 row+不可删除 `audit.retention_changed` 管理事件；失败回滚，set 不 prune。该成功调用沿现有管理 mutation 刷新 activity。新增SET必须传递Admin dispatch已生成的原request_deadline，覆盖managed admission、等待owner、proof/KDF及Store precommit；handler不得重新起25s预算，已耗尽或近到期时沿原typed AuthorityBusy合同且零变更。
6. 单独 STRICT `audit_retention` 表：singleton=1、nullable positive days、非负 updated_at_ms、nonce12/ciphertext16；不扩展 authorization policy/trust row。初始 disabled row 仅在新 init 同一初始化事务内创建。
7. 在既有 crypto/policy_state.rs 复用 LifecycleSeal：独立 canonical `RKAR`/v1、vault_id、enabled byte、days(禁用为0)、updated_at_ms；AAD purpose `AuditRetention=12`、object_id=0/object_version=1、SHA256 canonical，仍84字节。新专用函数不复用 PolicyState purpose/记录内容。
8. Store open 检查表/布局/字段/恰好 singleton；v20/旧布局拒绝，不迁移。v21 缺 row、坏字段或坏 seal是 StorageIntegrityFailed；绝不 missing→disabled。locked 时仅结构验证，不声称认证成功。
9. 每个恢复 unlocked 的路径（password/recovery unlock及desktop resume）与 restore 在任何业务使用/完成前验证 retention seal；desktop resume复用同一个retention_record及既有fault错误合同，坏nonce/ciphertext/缺行返回StorageIntegrityFailed并Faulted，不能先发desktop.resumed再延迟发现；VRK rotate 先用旧 VRK 验证，再以新 VRK reseal，在既有 replace_root_ciphertexts 同事务更新；days/updated_at 不变。restore 保持 backed-up row，不造默认值。
10. 唯一可信后台命令 `AuditRetentionMaintenance {not_after:Instant, reply:Reply<Option<AuditPruneReceipt>>}`：无 proof、无外部 cutoff/days。dequeue 首先过期限拒绝；Locked/disabled 返回 None、无删除/marker/activity刷新；Faulted 返回 Faulted。
11. unlocked/enabled 的命令从当前 sealed row 取 D，采一次 Authority now，checked 计算 fresh cutoff，调用同一个 Store::audit_prune；marker reason为 retention-policy。禁止在 Unlock/CheckIdle/执行/其他 mutation 内附带 prune。
12. 使用现有 idle_task，但以独立分支发该命令：先完成原 try_idle_lock，再在 due 时 try_coordinate，重查 Running 与 reject_if_busy；拿不到 owner则 defer。owner 保持至 maintenance 回执完成，不增加任务、scheduler/配置/平台。
13. 固定内部 cadence=60s；第一次 due 在现有 idle_task 第一 tick；每次完成/明确 skip/defer 后以 now+60s 安排，不补发漏 tick、不 burst。配置后首次运行≤下一 due（正常调度约60s），锁定期不解锁、不触发删除。
14. 单次 maintenance 的原 absolute deadline=开始+1s（内部常量，不是用户选项），覆盖 enqueue/reply/Store per-row 与 precommit；用现有 bounded try_send，至多一在途维护。完整组原子删，不增加分页游标/半组删除。
15. Deadline 是既有合作式检查；SQLite 单次调用/OS IO可能越预算，返回后 precommit 检查回滚，不声称强制中断内核/SQL的硬时限。大库反复超预算可保留更久，不能宣称严格最大保留期。
16. Worker 顺序与 coordinator 线性化 set/disable/lock/shutdown：已准入维护可在其后的 lock turn前完成；lock先被执行则 skip。收到 shutdown 停发新 tick；不取消一个尚有效的已入队写命令后静默释放其结果责任。
17. try_send Full 或真实 Worker AuthorityBusy 回执是已知未提交/回滚，可日志 defer到下一 cadence；reply timeout/closed/畸形回执是结果未知，必须在仍持coordinator owner时通过既有lifecycle同步进入非Running的Draining及sticky stop-pending gate，随后记录安全code/request_fault并沿既有cleanup停止。仅异步发送StopCommand不足；不得释放owner后让排队SET/业务/remote-effect准入继续。不能当Busy或自动retry；commit可能已成功，marker是事务事实。
18. StorageIntegrityFailed/AuditCommitFailed 沿现有 Worker fault helper；其他真实clock/storage/entropy错误保留类型，Broker在owner内依第17项同步关闭全部准入并发送既有fault/cleanup，不扩大Worker Faulted错误分类。status/后台均不刷新 idle activity；现有 idle lock可正常清 VRK。
19. 时间回拨检测使用 Worker 单个 volatile `retention_last_clock_ms` 高水位，比较 now 与该值及 sealed updated_at_ms；倒退/epoch underflow返回 ClockUnavailable、零删除，不重用旧 cutoff或静默 stale prune。
20. 高水位仅活在当前 Worker 生命周期（lock不清）；重启/整库回滚无持久时间锚，不声称检测全部宿主时钟回滚、认证 row replay 或真实世界日志年龄。每次成功取样仍重算 fresh cutoff；固定60s是轮询频率，不是保留保证。
21. Store 原 eligible-group 规则不变：严格 `<cutoff`，单 start+terminal 且 start<terminal；审批、未知、管理、未完成、重复/跨 cutoff 组保留；整表结构损坏拒绝。lease journal/审批状态/备份不删。
22. 删除+`audit.pruned` marker仍同一 transaction/precommit deadline；无删除不插 marker、不使旧 snapshot/export失效；有删除沿原 prune_sequence使旧 snapshot失效。后台/SET均无业务执行或远程效果。
23. 验收必须覆盖 sealed row restart/disable/missing/tamper、locked/Agent/wrong proof、atomic set audit/commit故障、restore/VRK reseal；后台真实 idle任务→队列→Worker→SQLite、clock回拨/overflow、queue busy/late dequeue、shutdown/lock/disable竞争、回执未知无重试、no-op/完整组/旧snapshot行为。
24. 保留既有 prune/审计故障测试并追加聚焦合成测试；监听/KDF/全 runtime 是否获准或可运行由 root gate决定。本 planning未运行 Cargo/test/KDF/daemon/网络、未修改源码/规范。
精确生产 footprint（全部既有文件，新 production module=0，依赖/lock/config不变）：
- domain: `crates/rekey-domain/src/{audit.rs,ipc.rs}`。
- vault: `crates/rekey-vault/src/{model.rs,command.rs,handle.rs,authority.rs,bootstrap.rs}`。
- vault authority: `crates/rekey-vault/src/authority/{audit.rs,dispatch.rs,vrk_rotation.rs}`。
- vault store: `crates/rekey-vault/src/store/{audit_prune.rs,schema.rs,sqlite.rs,integrity.rs,vrk_rotation.rs}`。
- vault crypto: `crates/rekey-vault/src/crypto/{aad.rs,policy_state.rs}`。
- broker: `crates/rekey-broker/src/{runtime.rs,ipc/admin.rs,ipc/admin/audit_query.rs}`。
- CLI: `crates/rekey-cli/src/{main.rs,commands/audit.rs,commands/mod.rs}`。
共23个生产路径。单一 retention writer 独占上述23个生产路径（包括schema/FORMAT21及Admin50/51接线）；root独占共享spec/baselines/lock及DR格式常量/夹具，整合所有原像后统一验证。测试复用 vault/tests/audit_prune.rs、broker相关runtime/IPC tests、cli malicious_broker；本报告未修改它们。
未涵盖物理安全擦除/VACUUM、删除旧备份、全日志/审批清空、归档/WORM门槛、永久抗回滚或后台自动解锁；这些不计AUD06当前最小功能。

## 授权和最小边界

用户回答“允许新增上述自动维护授权”。所有 Admin 设置/撤销仍逐次验证 step-up；仅当前经过认证的持久策略允许可信 Worker 在已解锁时执行原完整组 prune。此为原逐次人工 prune 合同的明确授权扩展。SET 必须显式包含 days 字段（正整数或 null），缺字段不能被当作撤销；Agent socket 不接受这两个 Admin opcode。

无新依赖或迁移；格式21拒绝所有旧格式目录/备份，不覆盖原状态。身份授权、业务执行、secret sealing、现有错误类型和已准入远程效果的清理责任保持原合同。已解锁而旧 row/seal 损坏时失败关闭，不能视为没有启用策略。

2026-10-01 独立首轮审阅确认两项P1，先明确第9/17/18条，再进行有界修复：未知结果同步全准入关闭，desktop resume使用前验证密封。desktop.rs此前仅允许测试literal初始化，现授权最小生产验证调用及合成resume故障测试；其它29文件责任不扩展、不调用真实Keychain。原候选/日志保留，P1未复审关闭前不宣称自动保留完成。
