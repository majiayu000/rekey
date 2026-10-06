# 字面搜索首字节预筛选候选

范围仅为 `crates/rekey-broker/src/executor/sealing.rs` 和本规格。在现有
`find_subslice` 空 needle、needle 长于 haystack 的 guard 后，若
`memchr::memchr(needle[0], haystack)` 找不到首字节，直接返回 false；否则
仍调用原有 `memchr::memmem::find`。无新依赖、缓存、needle 副本、生产
抽象、配置、接口或持久结构。

完整 needle 匹配必然包含其首字节，所以缺席 guard 不能丢掉匹配。
空 needle 仍不匹配，长度 guard 仍先执行。JSON escape、percent decode、
percent hex fold 四个独立投影及其 marker guards、生成 needle 并集、
`Zeroizing` 所有权、调用方安全错误合同均保持原样；不增加组合解码。

Q7 的同机 release 隔离微测在原源码上观测到 4 MiB 合成 tool 流的实际
production run wall p50 102341.416 µs，预构造窗口的实际
`contains_secret` p50 63508.583 µs，窗口包含 149207 次合格字面搜索。
证据为 `.git/codex/evidence/competitive-optimization-20261005/` 下
`tranche-007-sse-cpu/micro-summary.json`。两者的内存布局与计时边界不同，
不能用差值作因果归因，也不能据此宣称本候选加速。

首字节缺席时可能省去 memmem matcher 构造；首字节存在时增加一次
membership scan。最坏渐近时间仍为线性搜索，额外空间 O(1)。收益尚未
证明，必须同时报告首字节频繁出现和小输入的负向结果，不能挑选快的
cell 或替代正式 HTTP/SSE、实际 provider 验收。

## 验证与测量

复用现有独立四投影短 binary 等价测试、单投影与编码反射覆盖。补充
0..255 的全部首字节、空/过长 needle、开始/中间/末尾匹配、常见首字节
但后续不匹配和重叠前缀的合同覆盖。

配对微测仅位于 Q9 evidence 的 `experiment.patch` / `micro-only.patch`，
正式源码保留生产 guard 与必要回归，不携带 ignored benchmark。实验的
同一二进制中，原算法
reference 与实际 `contains_secret` 候选使用完全相同的 marker guards、
四投影和 wiped 缓冲。合成 secret 固定为
`SYNTHETIC-REKEY-BENCH-SECRET`，auth 为 `Bearer ` 加该值，实际生成
19 个去重 needles。输入在计时外构造，准确长度为 32 B、1 KiB、64 KiB、
4 MiB，各含首字节缺席、全部首字节频繁出现、percent/backslash 密集、
末尾真实匹配。marker-heavy 非反射与投影 correctness 在计时外检查。
每个 cell 输出全部 7 对数据，A/B 与 B/A 交替；计时中 black_box 实际
扫描与结果，期望值和 baseline/candidate 等价断言均在计时外。

主线程独占编译、定向回归、格式检查及 release 微测；实现 lane 只交付
补丁、源码 hash 与静态检查。微测通过并有足够收益证据后，主线程再
复跑 Q7 production micro 与正式 HTTP 矩阵；否则撤掉生产候选。不提交
或推送，不将计划中的验证记为已通过。
