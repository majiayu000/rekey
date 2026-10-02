# DYN-06 加密租约登记与显式解锁恢复

格式统一为15，旧状态/备份拒绝，不迁移。第一阶段交付 Authority 的加密登记、完整集合认证、历史版本 cleanup-only 和真实轮换/restore 接线；Broker 执行/恢复接线是下一阶段，不能以单独 Authority API 宣称进程恢复已经完成。

Authority 随机生成 LeaseRegistrationId，绑定现有 execution request/session/action/version、准确 credential/version、规范 HTTPS origin/mount/role 引用。source_ref_hash 只散列非秘密来源（域 `RKVSRC\0\x01`、各字段 u16 BE 长度）；token、lease ID和动态值不散列公开。每登记独立随机 DEK，VRK 包装，更新只换 payload nonce；DEK/VRK 轮换均换新登记 DEK。payload 为闭合长度编码 source+可选 unique lease ID，不含动态值、token、body/provider响应；complete 重新加密无ID的payload，不声称 WAL/备份擦除。

两个 STRICT 表保存行和单例 authenticated-set manifest。行包含准确执行/版本/来源摘要、revision、acquire_intent/issued/renewing/cleanup_started/complete、时间、实际确认TTL结果、renewable、none/unconfirmed/confirmed cleanup结果、完成时间和 last_audit_event_id；最后审计 FK 与准确历史 credential/version FK 均 RESTRICT。密文suite/AAD、nonce/DEK包裹均严格长度/判别验证。无 secret索引。manifest 对 registration_id 排序，认证完整行metadata+全部密文/nonce，空集合也有 VRK seal；manifest 还认证 nullable last_audit_event_id 并以 FK 保留对应审计。每次验证必须与当前审计表按 sequence DESC 排序的最新 vault.lease.* 唯一event_id 完全一致。仅初始从未有租约审计允许 None；合法complete保留登记与最新anchor。两journal表旧有效空/complete快照复放但保留新租约审计会拒绝，不能开放来源；删行、插伪行、换行、改来源/版本/阶段/TTL/审计引用不能把来源误开放。完整数据库连审计一起旧有效快照回滚仍无法由本地 AEAD 判断新旧。

固定84字节 AAD 和现有suite保持：purpose9 LeaseJournalWrapDek 绑定vault/registration、执行/准确版本/来源身份；purpose10 LeaseJournalPayload 的 revision 与 constraints_hash 绑定所有身份和阶段/TTL/结果/last-audit；purpose11 LeaseJournalState 绑定vault、manifest revision/count/digest/带presence的last_audit_event_id。nullable使用显式presence byte。每个登记 mutation、对应审计和manifest更新在一个commit_audited事务，queued命令及commit前检查同一单调deadline。SQL/audit/crypto失败 rollback，审计或integrity失败沿用worker fail-closed；reply丢失不能认为未提交。不增加运行缓存、文件账本或 Agent API。

具体内部 API 为 begin、issued、definite-abort、renew-begin、renew-result、cleanup-prepare、cleanup-finish、counts/recovery-batch。同origin/mount/role的任何非complete记录拒绝新acquire，即使credential重建/轮换也不能绕过。确定HTTP未开始或既有indeterminate=false拒绝时，definite-abort原子complete、无ID、cleanup none，Broker保留原 UPSTREAM_FAILED/retryable 合同。未知且无ID保留隔离，不猜ID、不revoke-prefix、不以TTL/404推断删除。renew成功记录请求起点+实际TTL而非increment；失败保留可清理状态，不声称续租成功。

cleanup-prepare只从已验证未完成登记读取准确历史版本profile，允许retired/revoked，不能改用current；缺版本或坏密文fault并保留未知。返回不可Clone/Serialize的consume-once PreparedLeaseCleanup，只供固定 exact revoke，不允许业务/acquire。cleanup_started+审计+manifest持久提交之后才返回。finish仅可信严格204+空body+sealing确认时complete并清除活跃ID，其余保留unconfirmed。locked counts 标verified=false，仅结构计数，不解密或外部IO；unlocked每次使用持久集合验证，不另建cache。unlock和restore证明全部row/set/历史引用，坏journal不能开放worker。

DEK轮换在原credential全量ciphertexts事务内同时更新所有journal与manifest；VRK轮换同原header/wrappers/credentials/policy事务完成journal重包裹、重加密和new-root manifest。任一坏journal或晚deadline使整笔回滚。SQLite在线Backup自然包含两表；restore先证明journal再安装为locked，不联网。现有历史版本保留与audit-prune白名单不放宽；manifest和FK不会证明完整旧备份没有丢近期登记。

后续 Broker 正常顺序是 execution.started → prepare/profile → begin持久ACK → admission再次检查 → 一次acquire → issued登记持久ACK → business；renew-begin/结果和cleanup-prepare/finish接同一journal审计，不由terminal tracker重复写。begin后HTTP未开始则definite-abort。issued/cleanup-start持久失败时不交付业务成功；若本次执行已持exact profile/ID，保留DYN05唯一有界紧急 exact revoke 例外，不借fault后解密或伪造receipt。错误响应最多4个候选即时cleanup保留原合同，未知intent不宣称所有候选可恢复。provider返回与issued commit之间SIGKILL可留下无ID intent，这是明确不可恢复窗口。

恢复只在调用前 Locked→Unlocked，reload policy与journal证明后、enter_running/session admission之前；password/recovery/desktop汇合，Running重复unlock不清live租约。最多8 known-ID、总8秒，每条1秒（既有500msrevoke+500msjournal），全部clamp绝对deadline；剩余/deferred/unconfirmed来源继续隔离，无background重试/自动unlock。no-ID只统计unknown，无providerIO。恢复仅exact revoke，不renew/reacquire/business、不补旧execution.finished、不复活session/challenge。后续状态/解锁DTO必须实际输出verified与pending/unknown及至多8条非秘密摘要，不能只写文档。

本地定向验证覆盖集合删行/换行/跨vault/版本/来源篡改、审计及SQLrollback/deadline、retired/revoked cleanup-only、pending/unknown/complete真实backuprestore、两种rotation与坏journal整笔rollback。后续独立provider进程+SIGKILL夹具验证各持久窗口。真实Vault角色删除、历史token有效性/撤权、旧主fencing、下游自然到期和恢复SLO后置现场验证。

所有 unlock 和 desktop resume 入口在返回成功前验证同一 journal 集合及全部历史凭证引用。

Stage B 的真实DTO为 status.lease_journal（verified/pending/unknown/complete）与 unlock/desktop metadata.lease_recovery（performed、journal、deferred、最多8条registration/准确credential/version/complete或unconfirmed或deferred/updated时间）。无ID intent只给unknown总数、不猜其ID。Running重复unlock返回performed=false、当前验证计数和空条目，不清live lease。恢复保持Locked的普通admission关闭；coordinator内先reload policy，再最多8条exact cleanup，全部clamp同一8秒绝对deadline与每条1秒上限，其中provider窗口最多500ms，剩余给journal。未知/deferred保留来源隔离；关键storage/audit/integrity错误不吞、不进入Running。旧Broker所有独立vault.lease.* append被journal mutation替换；malformed最多4候选仅作当前已持秘密的有界紧急exact revoke，不假造issued或成功receipt，intent继续unknown。

Desktop CLI 必须按操作解析这两个不同的闭合回复：remember 仅有 expires_at_ms；resume 同时要求 expires_at_ms 与 typed lease_recovery（包括闭合嵌套字段）。不能把恢复摘要当作未知字段拒绝，也不能通过忽略任意字段或把摘要变为可选来兼容。原生桥接 stdout 仍为 expiry、换行、秘密正文；任何缺失、未知或错误类型 metadata 必须在输出秘密之前以 INVALID_FRAME 失败。

恢复首批和最终批次必须来自已解锁且已验证的同一次 Authority 快照。内部 LeaseRecoveryBatch 以 unavailable: Option<AuthorityError> 区分 Locked/Faulted，状态读只投影未验证计数，恢复消费对应 typed error；不得以超时后的未验证计数进入 Running。该内部原因不增加 IPC 字段、Command 或第二次 status 探测。恢复的 exact revoke 由外层 timeout_at(provider_deadline) 约束，截止时仅记 unconfirmed，不用相对计时延长provider/全批预算。
