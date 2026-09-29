# AUD-07 独立审计投递

状态：本地实现合同。真实 SIEM 的持久存储、去重与容量验收仍需现场输入。

`scripts/rekey-audit-delivery.py` 是无解锁能力的独立 Python 工具。操作方先从可信渠道取得既有 `BackupReceipt`，以 `init --vault-receipt FILE --endpoint HTTPS_URL` 登记 `--source-instance-id` 与 `--vault-id`。Receipt 的 vault_id 必须一致，工具不验证备份内容，也不从审计文件猜测身份。Receipt 不是签名证据，操作方负责来源真实性。每次命令显式重复两个身份；本机 0700 outbox 永久固定身份、receipt SHA-256 和精确 HTTPS 目标。restore/clone 必须登记新的 source_instance_id 和新的 outbox；工具无法自动识别由操作方冒用旧身份的克隆。

`enqueue --export FILE` 读取既有 CLI `audit export --output FILE` 完整 JSONL，不调用 unlock、不读取数据库。输入及队列文件必须为本用户 0600 普通文件；拒绝符号链接、路径替换及并发操作。Header 必须是 v2 schema、所有过滤字段为 null，最终 complete trailer 的 row_count 必须匹配。事件为严格倒序且无重复，新区间从永久 cursor+1 连续到 snapshot_max_sequence。新区间缺口、部分文件、错 trailer、过滤导出和回退明确失败。已有 ACK 的旧记录可出现在完整快照中，旧区间允许正常 prune 留下的缺口；接收端仍须按 source_instance_id/vault_id/sequence 去重。首次 cursor 为 0，已经 prune 的初次导出不能偷偷建立最新 cursor。

仅允许一个未确认批次。原始完整 JSONL、SHA-256、随机 batch_id、来源身份、新区间 first_sequence/last_sequence、snapshot_max_sequence、row_count、created_at_ms 永久保存为不可变 `batch-FIRST.json`。已有 pending 时停止入队；不再生成 batch、不跳序。已确认文件永久保留，工具不自动清理。单个快照上限 16 MiB、outbox 总量上限 256 MiB、未确认批次年龄上限 24 小时；入队时为该批次的精确 ACK journal 和最长整数确认时间预留空间。先到上限停止，不删除最旧事件。源端 prune 保留责任属于操作方，工具不会阻止 prune，也不改变本地业务审计门禁。

`send --token-stdin` 从受保护 stdin 读取 token；省略该选项时使用隐藏 TTY。TTY 关闭 echo 失败产生的 GetPassWarning 必须成为错误，不能回退到可回显输入。token 不得通过 argv、环境、文件或日志提供。POST 的 JSON 是原样批次（含 export_jsonl），认证使用 Bearer。固定 HTTPS，系统 CA 验证，禁止 redirect 和环境代理；所有解析 IP 必须为公网。生产无私网/CA 放行选项，TLS fixture 仅通过测试代码注入解析器和 CA。单线程 CLI 为每次请求 fork 专用子进程，请求含 DNS 在内绝对 10 秒、响应上限 64 KiB；截止时杀停并回收子进程，截止后不能继续连接或发 POST。每次 send 最多 3 次尝试、总绝对期限 35 秒，退避为 1、2 秒。网络/429/5xx 有界重试，401/403、其他 HTTP 错误、无 ACK、错误格式或绑定均永久失败，以不可变 `failure-FIRST.json` 保存固定类别；后续 send 停止并要求操作方 review，不自动清除失败。错误只输出固定类别，不输出原始异常/响应/token。

接收端只在持久写入后返回 JSON ACK，其字段必须精确为 `record_type: rekey.audit.delivery.ack.v1`、`durable: true` 及 batch 的 batch_id/source_instance_id/vault_id/first_sequence/last_sequence/snapshot_max_sequence/row_count/sha256_hex。所有字段和值必须匹配；HTTP 200 不足以确认。`ack-FIRST.json` 原子创建并 fsync 文件和目录，包含 ACK 及确认时间；永久 ACK journal 是唯一 cursor，无第二份 cursor 状态。丢 ACK 或进程重启重发同一不可变 batch。接收端必须对同一 batch 返回同一 durable ACK，不能声称 exactly-once。

文件提交使用同目录独占临时文件、fsync、原子硬链接安装、目录 fsync。磁盘/权限/同步失败必须返回非零；保留 partial 文件供 review，检测到 partial 即停止后续命令。持久 ACK 已落盘而最后目录同步失败时本次仍失败；重启可读取已存在 ACK，cursor 仅来源于 journal。root 目录 fd 固定，并在读写与网络前后验证路径仍对应同一目录；同用户恶意写者属于 G1 信任边界，SHA-256 不提供签名认证或 root 隔离。

本地测试覆盖成功、精确 ACK、丢 ACK 重发、重启、连续范围、partial/filter/trailer、权限/symlink/路径替换、磁盘失败、响应/时间界限、认证拒绝及日志 canary，并以合成库真实 CLI 导出接真实 TLS receiver。真实 SIEM 落库查询/去重、认证撤销、生产公网/TLS及24小时容量仍是现场缺口。
