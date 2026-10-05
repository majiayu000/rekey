# 请求内 SSE 安全前缀回收

状态：已实现，定向验收通过。范围仅 `executor/text_stream.rs` 与 `executor/llm_stream.rs`。

## 问题与边界

Sealer 保留全部原始 SSE，而 Observer 同时保留 SDK 组装文本；有效 wire
未超过 Action response bound 时，两份历史仍会耗尽同一个 retained bound。
本改动只回收已发送且没有解析/检测引用的前缀，不改变 0.3 的 durable 格式、
配置、协议、审计或错误合同，也不代表完整能力或竞品性能已经领先。

## 最小实现

- Sealer 记录绝对 `base`、`emitted` 与累计 `total`。`total` 永远累计输入字节；
  回收不降低 wire 计数，`limit + 1` 仍返回 `response-too-large`。
- Sealer 保持原 `Vec::with_capacity(limit)`，不会在部分凭据反射尚未检出时
  扩容并留下无法清零的旧 heap allocation。回收减少 retained 长度与扫描，
  不承诺释放预分配容量或降低物理 RSS；独立审查发现的 Vec::new 回归已修正。
- 回收位置不得超过已发送位置、调用者仍引用的最早位置与
  `total.saturating_sub(hold)`。移动保留 suffix 后清零废弃区域，raw scanner
  仍保留原来的 `6 * max_needle_length + 5` 字节 escape/normalization 上下文。
- LLM 的 frame cursor、decoded tail frame 起点、terminal 起点保持绝对坐标。
  只释放完整且位于 raw/decoded watermark 之前的 frame，再回收安全前缀。
- 网络 chunk 按现有 `TEXT_STREAM_CHUNK_MAX_BYTES` 分片进入 parser，避免一次
  大网络读人为保留整份 wire。每次接收整块先核对累计 wire bound；每个解析
  frame 仍在释放前核对 raw suffix + Observer retained + frame cursor 队列
  的原逻辑 memory bound，未放宽上限。
- fixed text projection 的 raw scanner 在检查后回收无消费者前缀；text Sealer
  只回收已经投递的 UTF-8 完整前缀，pending frame 的原上限不变。
- raw、编码、Unicode/percent、跨帧与 SDK 有序组装反射检查全部保留；SDK
  组装 buffers 不截断。巨型单帧或组装状态仍可因原 retained bound 被拒绝。
- Complete 持有 terminal 后缀；仅已有 settlement/audit 成功调用 release
  后释放终止帧。断开接收者仍运行到原 runtime-owned 结算。

## 验收

定向 unit tests 覆盖：每字节网络 chunk、回收后的跨 escape/percent/reflection、
UTF-8、三协议 bytes 保真、slow receiver/断开接收者、结算前 withheld terminal、
累计 wire bound 与 `+1`、巨型单帧 retained bound，以及精确 4 MiB Chat text
和仅 arguments 的可释放多帧 SSE。首帧完整 tool ID/name 只出现一次的真实
工具流保持 pinned；同为 4 MiB 时仍可能因 retained bound 失败，单独测试
这个失败边界，不将 arguments-only 成功算成正式工具 fixture 改善。
旧测试若依赖 raw 全历史耗尽 memory，则改为验证新的安全回收成功，并另外
用实际未回收的 raw/decoded 状态证明同一 retained bound 仍拒绝超量。

本 lane 运行定向 tests 与 `cargo check --workspace`；全 workspace tests 和
正式性能矩阵由集成 lane 完成。不得用调大 bound 或修改 fixture 获得成功数字。

Anthropic/Responses 的完整有序 SDK 组装缓冲与每 event 重扫保持不变，仍可能
有平方级扫描成本；本优化不能外推这两种协议的大流性能。

已完成 text stream 7 项和 LLM stream 26 项定向 unit tests；旧 retained-field
state 测试仍在原上限失败，无需删掉或放宽。`cargo check --workspace` 通过。
正式性能数据由集成 lane 单独记录，本 SPEC 不声明竞品领先。

## 本地验收 checkpoint

2026-10-05 最终reviewed源码fmt/all-targets check/clippy、串行workspace 1046 passed/6 ignored与机械合同通过。正式optimized-v3三轮432cells/27648attempts完成，完整成功body hash 0 mismatch；ledger每规模20samples及reopen durability断言通过。实际收益与仍未解决的工具流、O(N)、RSS/慢SQL截止边界见 competitive-comparison-2026-10-05.md 和本机 tranche-001 final-validation-summary.json。仅本地实现/合成验收，不宣称CI、真实provider、全能力或性能领先。
