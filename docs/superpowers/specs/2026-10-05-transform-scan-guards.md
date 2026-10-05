# 响应 transform marker guards 等价性

范围：基线 `3963dd305c7911a45ec31ac789218434ce95538a` 已有 marker guards。
本次只证明、回归验证这两个 guard，并评估现有 `slice::contains` marker
扫描是否值得替换为已经直接依赖的 `memchr::memchr`。跳过 allocation 是
基线行为，不计为本次新增收益。只涉及 `executor/sealing.rs` 与本规格；
无新增依赖、needle 副本、缓存、抽象层、配置或持久结构。

## 保持的检测合同

令 `Sub(x, N)` 表示 `x` 包含集合 `N` 的任一非空 byte needle。
`J` 是现有的一次 JSON escape 解码，`P` 是现有的一次 percent 解码，
`F` 是现有的完整 `%HH` hex 大小写归一化。非法或不完整 escape 保持
literal。完整检测仍为：

`C(x, N) = Sub(x, N) ∨ Sub(J(x), N) ∨ Sub(P(x), N) ∨ Sub(F(x), F(N))`。

先检查初始 literal 的完整 needle 并集；raw、auth value、base64 std/url
有/无 padding、hex lower/upper、至少 16 字节时的三 alignment 内部 sextets、
percent safe lower/upper 与 percent-all 均保持。调用方增加的 fixed-header
OWS 投影同样保留。空 needle 不匹配，空集合始终 false，重复 needle 不
改变布尔结果。`contains_secret -> bool` 与调用方安全错误合同不变。

四个项独立作用于原始 `x`，不增加递归解码、`J(P(x))`、`P(J(x))` 等组合。
marker 仍存在但 escape 非法、未完成或只在边缘时，沿用现有投影而不依据
token 完整性跳过检查。

## 两个 identity guard 的充分性

没有反斜杠时，`J` 的 Unicode 与 simple escape 分支均不能执行，逐 byte
复制得到 `J(x) = x`。初始 literal 未匹配后，JSON 项不能新增匹配，可
跳过 JSON allocation 与扫描。

没有 `%` 时，`P(x) = x` 且 `F(x) = x`。percent decode 项因此不能新增
匹配。对于 fold 项还必须考虑 needle 的变化：`F` 只小写完整 `%HH` 的
后两个 hex byte，从不删除或生成 `%`，也不改变其它 byte。故若 `F(n)`
含 `%`，它不可能成为不含 `%` 的 `x` 的子串；若 `F(n)` 不含 `%`，`n`
本身就没有 `%`，归一化分支完全不执行，必有 `F(n) = n`。后者已经由
初始 literal 检查覆盖，空项仍不匹配。因此无 `%` 的 `x` 可跳过 percent
decode 与 haystack/needle normalization allocation、扫描。

这是 haystack guard，不是 needle guard。不得在有 `%` 的 `x` 上省略 fold
项：`x = %AB`、`n = %ab` 的 literal 与 decode 项均 false，fold 项 true。
每个 escape 的 hex case 可独立混合，必须保留现有 normalization。

## 复杂度与收益边界

只允许替换两个 marker membership scans，继续借用原始 haystack。两个
marker scans 的最坏时间都是 `O(|x|)`、额外空间 `O(1)`；完整检测的最坏
渐近 CPU 与空间复杂度不变，marker-present 路径保留原 allocation 与
扫描数量。没有新增敏感 pattern 复制，现有 `Zeroizing` 投影寿命不变。

先在相同 release 二进制与环境中交替测 baseline/candidate。微测只说明
marker scan 及完整 `contains_secret` 的本地成本，不替代 root 的全套
回归、正式 HTTP/SSE benchmark 或真实 provider 验收。若现有 contains
生成等效向量化且替换没有实际收益，生产 marker scans 保持原状。

## 定向验证

与不使用 marker guards 的四项 reference 对照，覆盖任意短 binary
haystack、单/多 needles、空与重复 needles，并明确覆盖无 marker、单
marker 与双 marker 分支。完整/非法/未完成 JSON 和 percent token 放在
开始、中间、末尾；包含 simple escapes、Unicode/surrogate、mixed-case
percent fold 与一次投影的边界。

对生成器输出的每个 needle，分别构造 literal、JSON escape、percent
decode 与 fold 反射，确认完整并集未被裁掉；使用合成测试数据。完成
workspace check、定向 sealing tests 与格式检查，保留 actual exit codes。
workspace full suite 与正式性能矩阵由 root 单独执行和报告。

## 本地 marker 微测结论

2026-10-05，macOS 26.5.1 / aarch64、rustc 1.95.0；同一个 release
二进制同时编译基线与仅两处 marker scans 替换的候选，使用相同的 17 个
合成 needles。每轮 30 个 size/path cells，每个 cell 7 组 A/B、B/A
交替配对，共运行两轮。两轮无 marker 的 64 KiB 路径 candidate/baseline
配对时间中位比为 0.912 / 0.904，4 MiB 为 0.890 / 0.902，均每轮
7/7 组更快。因此保留这两处替换。小窗和有 marker 的路径不承诺收益；
第二轮 32 byte cell 的调度噪声明显，不能用其数字宣称稳定加速或回退。

本地证据在 `.git/codex/evidence/competitive-optimization-20261005/` 下的
`tranche-003/transform_guards/`：两个 CSV、summary JSON、environment
JSON 与独立 microbench 源码。测量的是完整 `contains_secret` 的合成
成本，没有运行服务、HTTP/SSE 流或真实 provider；正式矩阵仍由 root
验收。新增测试是既有 identity guards 的回归覆盖，不代表新增投影。
