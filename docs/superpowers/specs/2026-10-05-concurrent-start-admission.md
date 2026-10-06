# 有效并发请求的 started 提交排队

状态：本地实施合同，正式复测待完成。基线 043a020，0.3 持久格式不变。

## 证据与最小行为改动

既有有效矩阵中 c4 小 JSON 有 100/192 个 HTTP503，拒绝约0.28–1.64ms；
源码 `commit_started_with_usage` 在 Running 时协调锁一有争用就返回
AuthorityBusy，即使只是另一有效请求正提交 durable started。原始记录没有
错误正文，因此不能证明每个503都来自这一分支。旧单元测试明确规定立即
拒绝；本次有意修改这一运行行为，需回归与同负载复测证明效果。

最小版本只在 Running 且 try_coordinate 争用时等待现有协调锁。
拿锁后仍重新检查 lifecycle 与当前 policy，然后提交 started/usage。
生产调用已有 admission_deadline 的外层 timeout_at。当前只有 Profile 把
policy 到期加入该截止时间；为保证新增等待不跨越有效授权，所有生产请求
统一复用同一个 policy 单调/墙钟截止约束，并在请求交给 authority 前重查 policy 到期。authority 保留现有 SQL 事务前截止校验；不新增 COMMIT 前墙钟检查，因此不承诺任意慢 SQL 或调度下持久提交绝不越过墙钟。
等待不会延长 action、approval 或 policy 时限。Locked/draining/shutdown、实际 authority queue满、
审计故障和会话并发上限的错误合同保留。不增加配置、独立队列或持久状态。

## 验收

- 锁由正常工作占用：确定性 poll 为 Pending；释放后提交成功。
- 期限耗尽：使用生产外层 timeout_at 和 request_deadline，取消等待后没有
  started 或 credential effect；释放会话 permit。
- 排队后进入 draining：拿锁后拒绝，没有 started。
- 排队期间 policy 变更：拿锁后拒绝，只有原 policy-changed blocked 审计。
- 复用既有 ledger timeout/rollback、drain、policy、终端审计故障测试。
- 三轮同机优化构建 c1/c4/c16/c64 复测保存状态、错误正文和完整响应摘要；
  不把超出会话上限的拒绝算吞吐，不提前宣布所有503消失或竞品领先。

变更文件只限 executor.rs、executor/tests.rs 与本 SPEC。这是待独立审查和
本地验证的实现，不宣称已合并、发布或完成全范围目标。

## 本地验收 checkpoint

2026-10-05 最终reviewed源码fmt/all-targets check/clippy、串行workspace 1046 passed/6 ignored与机械合同通过。正式optimized-v3三轮432cells/27648attempts完成，完整成功body hash 0 mismatch；ledger每规模20samples及reopen durability断言通过。实际收益与仍未解决的工具流、O(N)、RSS/慢SQL截止边界见 competitive-comparison-2026-10-05.md 和本机 tranche-001 final-validation-summary.json。仅本地实现/合成验收，不宣称CI、真实provider、全能力或性能领先。
