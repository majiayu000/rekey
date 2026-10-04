# v3 安全核心独立代码审查（2026-10-05）

基线：PR #62 `5de61bf417e6ea60906b47f92201b4f2c19d80ed`。
范围：presence、daemon 签名校验、SDK gateway、响应遮蔽、本机审批、DoH。
由独立只读 security-reviewer 完成初审及修复复核；root 实现修复并运行测试。
不覆盖全部代码、lab 或外部人工安全审计，也不代替签名设备验收。

## 已关闭的问题

| 问题 | 原行为 | 修复与回归 |
|---|---|---|
| P1：Anthropic 交错文本块绕过遮蔽 | 按事件到达顺序的 all-text 不等于 SDK 最终内容顺序；秘密可分散于两个 block，最终拼装恢复 | 按 index 保存 Zeroizing 文本投影，初始值和 delta 都检查；计入已有 retained bound，stop 后仍保留。原始 SSE、工具及 thinking 保留 |
| P1 同一问题的补充绕过：错序 start index | SDK 将 start append 到数组，之后按 index 接受 delta；声明 index 与实际创建顺序不一致会使排序投影失真 | 在既有状态插入前要求连续 start index，复用 active + stopped 集合，无额外状态；完整攻击序列回归拒绝 |
| P2：首 chunk 前丢失安全错误属性 | run_stream 原 BrokerError 被转成 Terminal(Failed)，网关返回 UPSTREAM_FAILED / retryable=true | 使用既有、有界错误事件带回原 BrokerError；首 chunk 前保留 envelope，之后继续中止正文，不伪造 JSON/完成帧。响应头秘密反射明确返回不可重试的安全错误 |

涉及生产文件：
[llm_stream.rs](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/executor/llm_stream.rs)、
[execution_supervisor.rs](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/execution_supervisor.rs)。
回归另覆盖[真实 HTTP 网关](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/tests/gateway.rs)。

合成秘密仅为 `synthetic-secret-1234`，未使用真实 provider：

```text
message_start
start block 0: text=""
start block 1: text="secret-1234"
delta block 0: text="synthetic-"
stop block 0 / block 1
message_delta: end_turn, output_tokens=7
message_stop
```

旧 arrival 投影为 `secret-1234synthetic-`；SDK 最终按内容顺序得到完整合成秘密。
错序 start 的补充序列为 start1="`synthetic-`"、start0="`noise`"、
delta0="`secret-1234`"；现于首个错序 start 拒绝。
SDK 拼装行为由[官方 Anthropic Python SDK 源码](https://github.com/anthropics/anthropic-sdk-python/blob/main/src/anthropic/lib/streaming/_messages.py)核实，
审查取得的源码 SHA-256 为
`b628629188df66541a35d052a0ebdbfb4d5d18efd17d25f3655e9cd28c1204af`。
独立 reviewer 在内存执行官方相关函数验证拼装；root 的 Rust 合成流与真实 loopback
HTTP / Authority 回归分别证明 Rekey 旧代码的两项失败和修复后的行为。

## 检查证据

- 修复前两个新回归均实际失败：SSE 错误放行；网关返回 UPSTREAM_FAILED。
- 修复后 SSE 全组 **24 passed / 0 failed**。
- 修复后 gateway 全组 **18 passed / 0 failed**，正文及未允许头的反射都返回
  RESPONSE_SECURITY_VIOLATION / retryable=false；每次执行只结算一次。
- 原错误响应检查现明确区分三种安全拒绝、超大响应、传输中断；
  超大响应保留 RESPONSE_TOO_LARGE / HTTP403，不再丢成泛化的 HTTP502。
- 完整 workspace **1030 passed / 0 failed / 6 ignored**（856.218秒）；default/lab all-targets 与 strict Clippy、fmt、机械边界通过。分发 9 项和归档文档清单通过；归档预检使用未执行的 binary fixture，仅证明文档/文件清单，不代替实际包 smoke。
- 第一轮修复的 gateway 失败、修复前 RED 与被中断的旧全仓均保留，
  不当作通过；没有扩大期限或删掉拒绝断言。

原始日志目录：
`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/v3-release-acceptance-20261003/`。
文件前缀为 `v3-core-review-red-`、`v3-core-review-green-`、
`v3-core-closeout-`。

## 已核查边界

Presence 的已解锁 / 活跃 verifier / 双时钟 / 退避与吊销守卫；发送前 audit-token
代码身份、Apple 链及同 Team / daemon ID；网关 Host / Origin / 认证 / 路径 / 大小
默认拒绝；审批主体、session、Action/version、参数和策略绑定、一次消费；
DoH 显式启用、resolver 与全部答案公网筛查、pin、正常 TLS、无代理/重定向及共同期限。

复核后，在上述代码与修复范围内未发现剩余阻塞。
此结论不等于不存在其他漏洞，不使用“整个产品安全”或新保护等级宣称。

## 合并前自动审查补充

最终提交 `e921357` 的九项 CI 通过后，GitHub 自动审查新增四条意见。
Profile 的 session.created 提交后，存活检查失败或响应准备失败原先只由 guard
撤销内存会话，未记录 session.revoked；此正确性问题已修复。使用真实 SQLite
写锁阻塞创建审计，锁内将策略过期锁存，提交后验证原 POLICY_INVALID 返回、
会话已撤销且 created/revoked 成对；另验证撤销审计失败返回 AUDIT_COMMIT_FAILED。
新回归在旧实现实际失败（仅 created），修复后 Profile 组四项通过。
独立 reviewer 已只读复核补丁及调用路径，无剩余阻塞；该轮未重复运行测试。
日志为 `v3-profile-revoke-red.log` 与 `v3-profile-revoke-green.log`；追加的完整
workspace **1031 passed / 0 failed / 6 ignored**，默认与 lab 严格 Clippy、fmt 和
分发九项通过；日志为 `v3-final-profile-*`。最终 head 的 CI 另行核实。

其余三条属于已明确的 alpha 边界：

- Agent 执行不推进 generation（SPEC §5.4）。同代数合法旧快照可重置随后用量，
  本轮明确补入 SPEC、README 和威胁模型；不承诺防本机状态回滚的费用封顶。
- 准入使用已结算输出，未结算输出不预留（SPEC §8.5）。并发在途请求可以超额，
  发布保留软预算合同，不临时改为硬预留机制。
- 每次认证完整历史账本（SPEC §8.1）。成本随历史增长，不添加第二份汇总状态，
  不更改冻结格式；一周自用记录真实性能后再作后续主版本决策。

这是对意见和既有设计的有证据取舍，不把这些限制列为已修复能力。

随后 `3035064` 九项 CI 全绿，新一轮自动审查确认两项补充正确性问题：

- Profile 映射键遗漏 principal，误拒绝不同主体使用同名实例的独立 Action/credential。
  Policy 与 Broker 仅在现有索引键补 principal；同主体冲突仍拒绝。
  两层新增回归均先实际失败，再通过；Policy Profile 组9项、Broker Profile组5项通过。
- macOS helper 只处理 SIGTERM，终端 SIGINT 会直接杀死 helper，跳过 Agent 回收和
  scratch 清理。现用既有原子标记和清理路径处理两种信号；成功恢复原 handler 才
  返回既有内部确认143。安装第二个 handler 失败时，Drop 恢复已安装前缀。
  prepare 子进程矩阵旧实现实际失败；修复后两种信号均不启动已取消的 Agent。
  真实 helper/Agent/scratch 矩阵通过，验证直接 Agent 已回收、临时目录已删除。

补充涉及的[策略校验](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-policy/src/lib.rs)、
[Profile](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/runtime/profile.rs)、
[helper](https://github.com/majiayu000/rekey/blob/v3.0.0-alpha.1/crates/rekey-broker/src/sandbox/macos.rs)
均不增加配置或修改持久格式。日志前缀 `v3-review2-red-` / `v3-review2-green-`；
独立 reviewer 已复核三处 principal 索引与双 handler 的安装/回滚/恢复顺序，
无剩余阻塞；该轮只读复核、未重复运行测试。
补充修复后的完整 workspace **1033 passed / 0 failed / 6 ignored**，default/lab
严格 Clippy、fmt 和分发九项通过；日志前缀 `v3-review2-final-` / `v3-review2-clippy-`。
最终 CI 另行核对，未扩展为外部人工审计结论。

## 未验证与发布边界

新版认证 context 实际弹窗次数、明文失焦清除、审批可见取消、SMAppService 生命周期
及 T12 仍未验证；2026-10-05 用户明确暂缓，未改填通过。
外部人工审计仍未完成；真实 Anthropic / OpenAI / GitHub 不沿用 GLM 实测结论。
L1 / L2 保持现有未宣称状态。[发布与一周自用](../v3-release-and-dogfood.md)继续记录这些项目。
