# 账本热路径的格式保持优化

## 范围与依据

基线为 `043a020`。现有 release 测量在 100,000 条历史记录下，
admission + settle 的 p95 为 1,059.56 ms。每次调用加载完整有序 `Vec`，
认证完整历史，随后完整解析 context；写入还再次计算完整摘要。
admission 在追加后重新排序，SQL 每次重新 prepare。

只修改 `crates/rekey-vault/src/{store,crypto}/usage.rs`。最小实现：

- 账本摘要改用 vault 已有直接依赖 `aws-lc-rs` 的 SHA-256 实现；
  原有字段顺序、长度前缀、optional presence、原始 JSON、ordered ID 检查不变。
- 使用连接内置的 prepared statement cache 复用账本 SQL。
- 已认证的有序记录用二分定位；admission 有序插入，settle 二分查找。

仍加载完整 `Vec`，仍完整认证后逐条解析完整 `UsageContext`。
时间与空间仍为 O(N)，不声称解决历史增长问题。此次不加入 revision cache、
cached totals、第二账本、新表、独立 seal 或跳过历史的路径。

## 不变的契约

vault25、backup25、policy6 的 durable 格式保持不变。摘要必须逐字节匹配原
sha2 实现；AAD 与 AEAD seal 算法、随机 nonce 规则保持原实现。
事务、audit fail-closed、错误类型、context 验证、预算日切、重复请求、
重复 settlement、rollback 和崩溃恢复行为保持现有代码契约。

## 验证与证据

crypto 单元测试用固定摘要向量及随机有序记录对照原 sha2 实现，覆盖
全部 optional 字段、原始 JSON、乱序/重复/删除/修改、seal state 篡改。
复跑现有 usage 测试和 audit commit/fault 测试，包含跨日、重复、
context、预算、rollback、备份和进程强杀恢复。

本 lane 运行 workspace check 和 focused tests；完整 suite 与正式压力矩阵由
root 串行运行。原性能 harness 复制到独占证据目录，通过临时源码快照加载，
不修改原 perf 工作树。测量入口与精确命令、日志、轻量测量原始数据保存在
`.git/codex/evidence/competitive-optimization-20261005/tranche-001/ledger/`。
轻量测量只证明入口可执行；正式收益以后续同机串行测量为准。

## 本地验收 checkpoint

2026-10-05 最终reviewed源码fmt/all-targets check/clippy、串行workspace 1046 passed/6 ignored与机械合同通过。正式optimized-v3三轮432cells/27648attempts完成，完整成功body hash 0 mismatch；ledger每规模20samples及reopen durability断言通过。实际收益与仍未解决的工具流、O(N)、RSS/慢SQL截止边界见 competitive-comparison-2026-10-05.md 和本机 tranche-001 final-validation-summary.json。仅本地实现/合成验收，不宣称CI、真实provider、全能力或性能领先。
