# 普通 HTTP 的一次 live handoff

状态：实施规格；无私钥种类、SSH/mTLS 执行器或格式变更，沿用 vault25/backup25/policy6。

当前普通 HTTP 在 prepare 后仅检查全局 atomic，尚未交接的已准入请求可在会话撤销后开始传输。本次只把同一个已预留 ExecutionPermit 接入 transport 构造及第一次 poll。已交接请求仍遵守原有 in-flight 和自然 drain 宽限，不将私钥执行器的强撤销语义写进 0.3 普通 HTTP。

最小修改：session.rs 增加内部同步 live-handoff 闭包及现有 wait_revoked 的 permit 投影；executor.rs 仅在第一次 handoff 获取既有 lifecycle coordinator，再持 registry.inner 验证 permit，构造并 poll 一次。Pending 后立即释放两锁，后续由原有 HTTP future 拥有工作。无新服务、trait、registry、配置或 IPC。

锁顺序 coordinator → registry.inner。闭包无 await、Worker 调用或递归 registry。检查 closed、entry 存在、非 revoked、双时钟过期、effect deadline、action 授权及在途预留。不能重新检查 uses_left/exhausted；最后一次预留仍合法。沿用已有 capability error。

等待首次 coordinator 时监听 permit.wait_revoked；尚未交接的任务可在 drain 持锁等待在途时退出。第一次 poll 后不再监听独立会话撤销；原有全局取消和自然 drain 行为保持。SESSION_REVOKE 拒绝后续新执行，不新增“旧已交接 HTTP 立即停止”的承诺。

整段 HTTP 等待保留独立、优先检查的 absolute action timer；transport 相对 timeout 在排队后重新起计不能放宽原截止时间。registry gate 的 CAPABILITY_EXPIRED 不替代外层 action 到期的既有 upstream-timeout 错误。

effect marker 在首次受保护构造前保守设置。未构造的拒绝记 blocked；交接后无可信完整结果记 UNKNOWN。完整结果沿用原 sealing、terminal receipt 和输出合同。

边界：本次只加强普通 HTTP 最后 send/open_stream 的首次本地交接，不证明已经入队的 reqwest/hyper 后台静止，也不证明 source acquisition/GitHub token 等全部交接。SSH/mTLS 仍需 typed prepare、版本与 rotate/revoke 绑定、每 poll 准入、owned socket close/join、终端 receipt 后的强 ack；这些属于独立私钥执行器，尚未实现。

验证：last use 不重耗；revoked/closed/双时钟/截止/action/无预留拒绝且闭包不运行；直接 revoke 与同步闭包串行；首次等待 coordinator 的真实 AdmittedExecution 撤销后退出并释放 permit，owner 无须先释放；第一次 handoff 后保留既有 in-flight completion；排队及静默 backend 仍守原 absolute deadline；完整旧自然 drain/lock/unlock 回归保持。

初版“每 poll +外层 wait_revoked”实现被完整回归否定：自然 drain 会过早取消普通 HTTP。已经收窄，不将该初版通过的强取消测试当成最终合同证据。

本地 handoff 的 backend factory/poll 若 panic，必须先在 registry 只读锁内捕获 unwind，释放该锁后原样恢复 unwind。否则 std::sync::Mutex 会中毒，后续 permit 清理触发 registry 的既有 abort，绕过 supervisor 的故障隔离与 terminal 配对。捕获仅为解锁，不返回成功、不吞 panic、不修改全局 poisoned-lock 合同；原 lifecycle_drain 的真实 panic-transport 测试必须不变通过。

绝对 action timer 的 typed upstream-timeout 必须保留原审计 reason：handoff 前记 blocked/upstream-timeout，handoff 后 buffered send 记 indeterminate/unknown/upstream-timeout，open_stream 保留原 indeterminate/unknown/text-stream-failed。不能因计时由 adapter 执行而改成通用取消原因。真实 TLS post_effect_audit 既有 fixture 和 queued-relative-timer 负例必须验证该合同，terminal queue/receipt 责任不变。

adapter 的内部 timeout_reason 由两个已有调用点提供静态字符串，不形成配置/公开协议。所有非超时关闭准入/取消分支保留原原因；同一绝对排队计时负例分别验证 buffered 与 streamed 的既有原因，返回 typed upstream-timeout 不变。
