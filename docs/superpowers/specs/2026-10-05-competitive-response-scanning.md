# 竞品实测后的响应扫描优化

状态：实施范围冻结，2026-10-05。基线 `043a0206473b2d37eec6222c4fefbc7b41fc5090`，产品 `0.3.0-alpha.1`。

用户要求全面对比与功能、性能改进，范围包括 SSH、mTLS、PKI、团队和 HA。完整能力范围另由本次源码矩阵逐项登记；本改动只处理已经实测确认的响应扫描瓶颈，不把它当成全面功能或性能领先。

## 问题与最小改动

同机优化构建、相同 TLS fixture 的三轮矩阵显示大响应延迟明显落后。`rekey-broker/src/executor/sealing.rs` 使用 `windows(needle.len())` 对每种凭据编码逐字节比较；4 MiB 响应的扫描成本突出。替换这一处字面量搜索为已在 lockfile 中的 `memchr::memmem::find`，直接声明 memchr 依赖。

接口保持 `find_subslice(&[u8], &[u8]) -> bool`。空 needle 仍返回 false；字节匹配语义不变。raw/base64/hex/percent/JSON escape、编码对齐、header 和跨 chunk 的所有既有投影与限额保持原合同；不缓存凭据、不改审计持久化、不降低检查覆盖。vault25、backup25、policy6 保持冻结。

文件：broker Cargo.toml、Cargo.lock、executor/sealing.rs。测试只增加能验证字面量算法等价和大响应中反射位置的必要覆盖，复用既有编码/分块/审计失败测试。无新抽象、配置面或持久结构。

## 第二轮：消除重复字面量扫描

全套编码中，ASCII 凭据的 raw/percent-safe、base64 standard/url/no-padding 及不同对齐常产生相同字节串。相同 needle 扫描多次不会增加反射覆盖。生成后按字节排序并仅删除完全相同的 needle；固定 header 的 OWS 扩展后同样去重。各编码投影的并集、最长 needle 和跨 chunk hold 不变，丢弃的副本仍由 Zeroizing 清零。不按内容相似、包含关系或长短删减；不缓存 secret-derived state。复用所有编码、header、分块检测测试，并重跑同一优化构建矩阵评估收益，未测前不承诺性能数字。

## 验证

保留现有基线二进制及 hash。先跑现有 sealing、stream/header reflection 测试和 workspace check；再使用相同 fixture、请求驱动和安全保障复测。数字必须说明样本、并发、优化构建的 test-only domain ID helper 与真实网络筛选被 fixture 路由 pin 替代的边界。吞吐不把拒绝计成功；4 MiB 流式失败独立登记，不能以字面量搜索优化冒充修复。

完成 workspace test、fmt 和仓库机械边界检查后，才能将实现作为可交付改动。真实 provider、SSH/PKI/团队/HA、硬件审批等未验收项保持未完成状态。

## 本地验收 checkpoint

2026-10-05 最终reviewed源码fmt/all-targets check/clippy、串行workspace 1046 passed/6 ignored与机械合同通过。正式optimized-v3三轮432cells/27648attempts完成，完整成功body hash 0 mismatch；ledger每规模20samples及reopen durability断言通过。实际收益与仍未解决的工具流、O(N)、RSS/慢SQL截止边界见 competitive-comparison-2026-10-05.md 和本机 tranche-001 final-validation-summary.json。仅本地实现/合成验收，不宣称CI、真实provider、全能力或性能领先。
