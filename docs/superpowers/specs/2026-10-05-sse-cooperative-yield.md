# SSE 切片结束时合作式让出

状态：本地验收通过，未推送或发布；基线 `c62bd0c058500f2b55c0ee1cc07a4637658a2c1c`。本规格只定义显式调度点的移动；性能结论限于下述实际负载。

## 最小候选

`crates/rekey-broker/src/executor/llm_stream.rs::run` 已用既有 `TEXT_STREAM_CHUNK_MAX_BYTES`（16 KiB）拆分上游 chunk。当前每观察一个完整 SSE 帧，在完成该帧的保留量检查、watermark、释放和 compact 后调用 `yield_now().await`。

只把这一个显式让出移到内层帧循环之后、每个 raw part 的末尾。没有完整帧的 part 也让出；EOF 的既有空 part 同样让出。错误仍在原位置直接返回，不为错误路径补让出。没有新增帧计数、阈值、配置、缓存或抽象，不改变切片常量。

假设：多个短帧落在同一 part 时，减少逐帧显式重新调度可能降低开销；大帧尚未闭合的 part 现在也有显式调度点。效果尚需测量，小网络 chunk 或跨多 part 的大帧可能增加让出次数。

## 保持的逐帧合同

原始字节 push/sealing、boundary、`observe_frame`（JSON 解码与秘密检查）、cursor/frame ledger、retained 上限、watermark、`release_through` 和 compact 的调用顺序及错误传播不变。每个完整帧仍立即执行这些步骤；不在 part 末尾批量检查或批量释放。

原始累计响应上限、保留量上限、Zeroizing 与清理、usage、终态识别和 EOF 验证不变。终帧仍由 `Complete::release` 在唯一结算及审计完成后释放；不修改调用者的结算、审计或错误映射。

## 合作式边界与等待

本候选仅保证正常完成每个现有 raw part 后执行一次显式让出。16 KiB 是本次新增原始输入的大小边界，不是两次让出之间的总扫描字节、CPU 工作量或耗时上限：一个 part 可补完此前多个 part 累计的大帧；一次 `observe_frame` 可处理整个大帧，语义检查和 compact 也可能涉及此前保留的状态。帧处理内部不新增抢占点。

每帧 `release_through(...).await` 保留在原位置。sender 有余量时，该等待可立即完成；发送返回 Pending 时仍可让调度器处理接收端。不能把一次 await 视为必然让出，也不保证显式让出后哪个任务先运行。接收端断开仍沿用原释放及结算合同。

`next_chunk().await` 的位置、transport 错误映射及上游行为不变。上游 future 返回 Pending 时仍提供等待机会；立即就绪时依靠 part 末尾的显式让出。空的非 EOF 上游 chunk 沿用既有行为，不新增输入验证。

调用者仍用同一 absolute effect deadline 包裹流式执行，并用既有生命周期取消分支管理执行及唯一终态。让出粒度改变可能改变外层 timeout/cancel 得到 poll 的时机；同步处理不能被 timer 强行抢占。本候选不承诺帧间取消、16 KiB 内取消或固定毫秒响应，不改变既有 `upstream-timeout`、取消及审计原因。

## 验证与接受条件

实现 lane 只做该文件的 `rustfmt --check`、`git diff --check` 和只读源码检查。编译、完整 workspace 测试和性能由 root 独占运行；未运行的检查不能作为验收或性能获胜证据。

复用既有有意义的流式测试：跨分片秘密、三个 provider 原始字节与终帧、retained 上限、usage、慢接收端 backpressure、断开、审计及取消/超时合同。没有新增仅断言让出位置的测试。若运行证据表明需要保证特定调度或取消响应界限，须先明确真实合同并增加针对该行为的回归；不能从本次移动推导出硬时限。

独立审查指出，现有取消测试依赖 EOF 闸门，未强制覆盖持续 Ready 的不完整
帧输入。新增行为回归在首个未完整 chunk 返回前同步触发生命周期取消，要求
执行不再继续读取上游，并通过实际 supervisor / UDS 验证空输出、失败终态、
保守计费和唯一 indeterminate 审计。该场景不依赖另一个任务的调度顺序；
root 用旧让出位置的受控变异证明测试能发现继续读取，不能推导一般公平性
或固定毫秒取消上限。候选测试通过；旧位置使上游读取从要求的 1 次变为
18 次，原断言失败，退出 101。首次包装脚本错误预期 19 次而报告失败，
原日志保留，`mutation-reconciliation.json` 单独记录实际失败与恢复后的通过。

## 已完成验收（2026-10-06）

同一 SHA 的 4 MiB 工具流、固定 4 KiB 分块、4 个 Tokio worker、7 对交替 A/B、每对每版本 20 次 sample：生产 run + release 的 wall p50/p95 从 35.087/36.508 ms 变为 32.230/34.745 ms；进程 CPU p50/p95 从 43.530/46.701 ms 变为 35.367/37.723 ms。7 对 CPU p95 均降低，候选/基线比率 0.758–0.874。每次完整正文、usage 7、完成终态及终端保留均验证通过。该计时不含 TLS、网关、vault、audit、fixture 准备或 RSS；不能作为完整产品延迟。

独立 scanner 微测在候选 binary 反而变慢（wall p95 6.164 → 7.450 ms），扫描生产源码没有变化；二进制和运行条件差异未能排除，不能将 full run 的全部差异精确归因于 yield。完整 HTTP 正式复测 `optimized-v6` 共 432 cells / 27,648 attempts，成功完整正文 SHA256 无不一致，所有 driver/server exit0，fixture 正常退出且测试 VM 恢复。c1 大 text/tool SSE p95 58.607/59.663 ms，仍慢于同轮竞品；c16/c64 仍受 session cap4 拒绝。

最终源码 fmt、workspace all-targets/all-features check、clippy -D warnings、完整串行 workspace test（1069 passed / 0 failed / 6 ignored）、diff、禁止 secret API 与 CLI 正常依赖合同通过。独立静态复审及新增取消回归关闭后无开放 P0/P1/P2；这不是人工独立安全审查，也不宣称固定取消时限。0.3 vault25/backup25/policy6 不变。

证据根：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-optimization-20261005/tranche-012-sse-yield`。配对 raw、`paired-micro-summary.json`、`review/report-v2.md`、变异日志、`attempt-002-full-validation/root-result-audit.json`、源码 overlay、release manifest 与 `coordinator/measured/optimized-v6/{aggregate.json,matrix.md}` 保留原数据；首次 overlay 包装脚本失败也保留，没有性能样本进入本批统计。
