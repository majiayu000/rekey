# Chat tool metadata 的有界 decoded Tail 回收

日期：2026-10-05。范围仅为 `llm_stream.rs` 中 Chat
`tool_calls[index].id` 与 `tool_calls[index].function.name` 的安全检测尾部。
这是当前 streaming 契约的局部修订，不改变提供给 SDK 的 SSE bytes、字段、顺序或拼接视图。

## 检测与回收契约

每个非空 decoded fragment 仍先追加到旧 Tail，再调用现有
`contains_secret(old_tail + fragment, needles)`。检测失败仍返回
`ResponseSecurityViolation`，不得先释放该 fragment 或其跨片前缀所在帧。
所有现有 raw、base64、hex、percent、auth value / OWS / alignment needles
以及检测器的 JSON escape、percent decode、percent hex normalization 投影均保留。

令 N 为非空 needles，L 为其最大长度，H 为原 raw Sealer 的
`6 * L + 5`，B 为完整检测通过后最后 `min(H, len)` 字节。仅上述两个
Chat metadata 字段使用以下规则：

1. N 为空时 keep = 0。
2. B 含 `%` 或反斜杠时 keep = B.len()，沿用原固定 H 尾部。
3. 否则 keep 为 B 的后缀中，同时是某个 needle 的非空 proper prefix
   的最大长度；没有候选时 keep = 0。

裁剪仍先移动被保留的 suffix，再 zeroize 被移除字节，最后 truncate。
frame reference 删除边界为 `total - keep`，删除 decoded end 不大于该边界的记录。
keep = 0 同时清空 Tail bytes 和该 Tail 的全部 frame references。
其他 Chat 字段、legacy function_call、Anthropic 与 Responses 仍使用原固定 H。

Tail 的任何 append 在超出现有 capacity 前必须显式增长：分配新的
`Zeroizing<Vec<u8>>`，复制现存 Tail，清零旧 buffer，再交换并追加 fragment。
新 capacity 至少覆盖所需长度，采用现有 capacity 的两倍（最小 8 bytes）
保持 Vec 式摊销增长；不得 exact-size 每次增长、缓存或为每个 Tail 预分配最大 H。
该局部增长规则也用于原固定 H Tail，不改变其检测、裁剪或引用语义。
metadata 回收可能令逻辑 len 为 0 而 capacity 较小，随后保留真正 prefix
再接较长 fragment；这条路径不得让 Vec 自动 realloc 释放尚未清零的旧 prefix。

## 安全依据

字面匹配第一次跨 append 边界出现时，旧侧必为某 needle 的 proper-prefix
suffix；最长候选包含所有较短候选，多片拼接仍由下一次完整检测捕获。
marker 分支保留原 H。marker-free B 中三个投影恒等；若 H 长窗口的开头
受窗口前 JSON token 影响，该影响最多 11 源字节，窗口最后
`H - 11 = 6 * (L - 1)` 字节仍恒等，足以覆盖任何潜在匹配的旧侧。
percent token 只需更短上下文。无 marker 的 normalized-needle prefix 与原
needle prefix 相同，因此无需复制或缓存另一组 pattern。

不得改成未经 marker guard 的 literal-only suffix：合成 secret `qrst`
按 `q%7` / `2st`，或 `q\u007` / `2st` 两片传入时，完整 percent / JSON
投影才会发现反射。secret `%ab%cd` 的 `%Ab%` / `Cd` 也需要原 normalization。
surrogate pair、非法和未完成 escape 仍由现有检测器解释，不新增 parser。

最长 suffix 使用借用 needle 的有界 KMP。对每个 n 只需考虑前
`min(n.len() - 1, B.len())` 字节，并扫描 B 同样长度的 suffix。
该前缀的 failure table 使用可清零的 `Zeroizing<Vec<usize>>` scratch，
不同 needles 复用同次调用的 scratch，不复制 secret pattern、不新增 cache 或依赖。
每次回收时间为 `O(B.len() + needles.len() + sum(min(n.len()-1, B.len())))`
（空 needle 的候选上限按 0 计），
额外空间为 `O(max(min(n.len()-1, B.len())) * sizeof(usize))`；
避免按候选长度重复比较带来的最坏平方时间。

## 输出、结算和限制

watermark 仍取 raw safety boundary、最早仍被 decoded Tail 引用的帧起点、
terminal 起点的最小值，且只释放完整 SSE 帧。`Complete.release` 仍只能在
usage / audit settlement 后调用。raw hold、terminal、usage、audit、wire limit、
retained limit 及错误合同不变。

此规则保守而非所有 encoding 的最小安全 suffix：无害 `%` / 反斜杠以及
长期 dormant 的真实 needle prefix 仍会 pin。Chat 没有独立 metadata close，
因此该种流仍可能在原 retained bound 返回 `response-too-large`，不得丢弃 prefix
或放宽上限换取通过。普通 marker-free、无 needle prefix 的完整工具 id/name
可以回收 frame references，使原精确 4 MiB full-tool fixture 在原上限下完成。

只宣称逻辑 retained bytes / references 回收。Tail 增长现已要求先清零再释放
旧 allocation，包含回收后较小 capacity 引入的路径；Vec capacity、
parser/network/sender 分配与 RSS 不是此优化的释放或上限承诺。

## 验收

- 有界 KMP 与直接 suffix oracle 在小 alphabet、空/重复/重叠 needles 上一致，
  并覆盖长周期性 pattern；多片划分与原固定 H 检测判定一致。
- Chat id/name 的 `q%7`、`q\u007`、mixed-case percent、simple JSON escapes、
  surrogate 与 malformed escape，所有生成 needle 投影及 interleaved 工具保持拒绝或保留原 bytes。
- 精确 4 MiB 原 full-tool fixture 与非空合成凭据/auth-value needles 均保持 bytes
  和 terminal withholding；+1 wire、巨型 frame 和真实 prefix/marker pin 仍在原界限拒绝。
- 检测前缀帧不得越过 watermark；失配后可整帧释放；未显式 settlement/release
  时 terminal 仍不释放。既有三协议、usage、慢接收方与断连测试保持通过。
- 验证反复回收后小 capacity → 7-byte 真前缀 → 100-byte fragment 的增长轨迹；
  旧 allocation 在交换/释放前已清零，完整反射仍拒绝且前缀帧仍 pin。
  增长保留摊销 capacity；移除清零的受控负例必须被测试捕获。
  清零 witness 仅在该测试的 7-byte-prefix 增长调用周围启用，使用 thread-local
  开关与局部 Drop guard 在返回或 panic 时恢复；默认关闭，不额外扫描/复制旧数据。
  普通 release 不编译该 hook；cfg(test) 默认只在增长时读取开关。
- 本 lane 执行 workspace check、定向 llm_stream tests 和 fmt；完整 suite 由根 lane 执行。
