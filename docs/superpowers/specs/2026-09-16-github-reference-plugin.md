# GitHub Issue 参考子进程接入

当前合同包含 CreateIssue 与 CreateIssueComment。macOS 使用本仓库打包的 `rekey-github-create-issue` sidecar，或 Admin 绑定的具体 artifact。Broker 从已验证 Action 选择操作，子进程只收到封闭 operation/body envelope；输出与同一纯合同的完整规范 envelope 逐字节比较。未知字段、操作或内容修改均不能进入远程准入。JWT、installation、私钥、token、capability、header、URL 均不进入子进程。两操作 wire 合同见 [Action 登记规格](2026-09-16-action-plugin-registration.md)。

打包 sidecar 位于宿主可执行文件同目录（Cargo deps/examples 宿主寻找上级目录）。显式登记则从不可变 Action 读取路径及可信摘要，失败不回退。打开 artifact 后验证实际读取字节，再复制为私有 0700 临时目录内的只读可执行快照，并核对复制字节 SHA-256。未显式登记的默认打包路径依赖可信安装目录；该执行快照摘要不等于发布来源证明。没有市场、环境路径覆盖或自动下载。

macOS 独立 deny-default Seatbelt profile 只允许系统 dylib 读取与精确 sidecar 文件、匿名标准 pipe；没有代码目录、HOME、临时目录的读写授权，也没有任何网络/UDS权限。禁止 fork；exec 仅限该固定快照（不能衍生其他程序）。stdin/stdout 有界为 256 KiB（覆盖现有最大 title/body 的 JSON escape 展开）；stderr 丢弃、环境全清、cwd=/。spawn 前仅调用 async-signal-safe libc 设置 CPU soft/hard 1/2 秒、关闭 core dump，并将实际 FD 快照中的所有 3+ FD 标记 CLOEXEC，包含先打开再降低 soft/hard limit 后存活的高 FD；快照至 fork 之间，可信 Broker 不并发制造非 CLOEXEC FD 或改变 limit，Rust/Tokio 后续 pipe/socket 本身以 CLOEXEC 创建。不声明任意恶意父进程的并发 FD 保证。绝不在 pre_exec 分配或加锁。

runner 使用既有 effect_deadline，包含输入写入、输出读取、退出等待；本地 artifact 快照读写为同步文件 IO，不宣称其硬限时，但在快照/FD 准备后、spawn 前再次检查 deadline，过期不得启动。错误时 kill/wait 单个进程（fork 已禁止），tokio future 丢弃时 kill-on-drop。每 10ms 使用 proc_pid_rusage 检查 64 MiB RSS，查询失败直接拒绝并杀死。此为采样内存看门狗，允许采样间超冲，**不是硬内存上限**；完整 P-10 的严格资源合同仍未完成。父 Broker 正常取消杀死子进程；父被 SIGKILL 时不保证子进程立即退出，但仍受 Seatbelt 与 CPU 限额约束。不得宣传 macOS PDEATHSIG 或硬内存资源隔离。

非 macOS 保持原有内置解析，不声明插件支持。测试使用真实 sidecar、真实 Broker 与确定性 transport；不访问 GitHub。公开请求匹配、revoke 在 success 前、审计闭合及恶意输出/超量/超时/文件/网络/fork/环境/FD/父退出均须验证。此实现需人工安全审查。

## 首个单操作切片的历史验证记录

2026-09-16，macOS 26.5.1 / 25F80 / arm64；实验 Seatbelt，不声明 Apple 支持的稳定沙箱 API。`github_issue_plugin.sb` SHA-256 为 `2e67ee1eb738b7b5d5b3ecc2044b459c8b66dff2b39ff9a5fa81f2097f3e4014`。

先 `cargo build -p rekey-broker --bin rekey-github-create-issue`；完整 Broker 构建使用 `cargo build -p rekey-broker --bins`。归档与 macOS app 构建清单均带 sidecar。缺失或非法 sidecar 在 macOS 直接拒绝，无内置解析回退。

- `cargo check --workspace` 通过。
- `cargo test -p rekey-connector github_issue`：1 通过。
- `cargo test -p rekey-broker --lib github_issue_plugin -- --test-threads=1 --nocapture`：8 通过（含隔离测试宿主 helper）。真实 native probe 覆盖已知 FD、FD 500 后降低 soft/hard limit 至 128、环境、fork、外部 exec、文件读写、UDS、loopback TCP、CPU、RSS watchdog、输入/输出超量、绝对 deadline、崩溃和伪造输出。文件/网络/fork/exec 均有未隔离成功控制组。
- 父 SIGKILL 测试先由 probe 的 stdout READY 握手证明 main 已启动，再杀死父宿主；未隔离 probe 能读取 `/etc/passwd` 后继续存活，受限 probe 的文件/loopback TCP 尝试仍失败。此测试不宣称父死自动 kill；早期仅通过 ps 映像与短 sleep 的测试有启动竞态，已替换为真实握手。
- `cargo test -p rekey-broker --test github_issue_plugin -- --nocapture`：1 通过。真实 Authority/Agent IPC、native sidecar、确定性 transport 收到精确规范请求。revoke response 的 gate 未放行时 Agent 无成功结果；放行后返回 201，审计 started → connector authorized → token revoked → finished 顺序闭合。非法公开字段无上游请求。
- `cargo test -p rekey-broker --lib github_profile`：原 4 项回归通过；格式、diff whitespace、macOS 构建脚本语法检查通过。整库回归由集成线程执行。

当时限制：未做外部 GitHub 写入；第三方 artifact/可信摘要登记随后按下节实现；RSS 为采样阈值，完整 P-10 严格内存合同未闭合；父被 SIGKILL 后不保证立即停止空闲子进程；不覆盖恶意父线程并发制造非 CLOEXEC FD；本地同步 artifact IO 没有硬超时；人工安全审查仍是合并门槛。


## 后续 Action 显式登记

上述固定打包路径继续作为无显式声明时的内置实现。新增的 [SDK-04 两操作登记](2026-09-16-action-plugin-registration.md) 允许 Admin 将具体路径、可信 SHA-256 和协议绑定到不可变 Action 版本；显式绑定失败不回退。该增量不改变本文的 Seatbelt/CPU/RSS/父死边界。

## 当前 macOS 硬内存候选的实际探针

2026-09-16 在同一 macOS 26.5.1 / 25F80 / arm64（XNU 12377.121.6）使用普通用户原生小探针；每次单个子进程、最多触碰 96 MiB、父进程 5 秒超时 kill/reap。这里只记录候选验证，不修改生产资源合同。

| 路径 | 64 MiB jetsam 声明 | 实际结果 |
| --- | --- | --- |
| 直接 posix_spawn 控制组 | 无 | 触碰 96 MiB，正常退出 |
| 直接 posix_spawn 实验组 | SPI 返回 0 | 初始剩余限额约 63 MiB，约 64 MiB RSS 时 SIGKILL；不是父 watchdog 杀死 |
| sandbox-exec → probe 控制组 | 无 | 触碰 96 MiB，正常退出 |
| sandbox-exec → probe 实验组 | SPI 返回 0 | 子程序剩余限额为 0，实际 footprint 101761432 字节，触碰 96 MiB 后正常退出 |

因此，不能直接给当前 sandbox-exec 启动增加 jetsam 属性就宣称硬内存限制：实验中的后续 exec 丢失了限制。Apple 的 [spawn SPI 声明](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/libsyscall/wrappers/spawn/spawn_private.h#L51-L53) 和 [内核接线](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_exec.c#L5294-L5329) 证明接口存在，不替代完整启动链的运行证据。

同版本 `RLIMIT_AS` 有实际虚拟地址空间限制，不能笼统说 macOS 未实现：本探针以当前 VM 大小加 16 MiB 设置后，直接运行和自 exec 的 96 MiB mmap 都返回 ENOMEM；但 64 MiB AS 设置返回 EINVAL，原生程序初始虚拟映射约 415 GiB。该值不是 RSS，不能把较小 AS 预算直接用于现有插件。参见 [AS 设置入口](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_resource.c#L1647-L1654)、[映射限额](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/vm/vm_map.c#L3903-L3930)、[exec 应用位置](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_exec.c#L2133-L2135)。尚未实测低于 exec 初始映射时的静默丢失分支。

保留当前 CPU 限额、RSS 采样看门狗与 Seatbelt，不新增可信 launcher 或合作式父死监控来冒充内核保障。父 SIGKILL 后立即终止仍未闭合。完整本地源码、逐样本结果及编译记录在主仓库 `.git/codex/threads/remaining-sdk-20260916/resource-probes/`；只代表该 OS build，不代表其他版本支持。

## 2026-09-17 两操作扩展合同

当前实现以 [Action 插件登记合同](2026-09-16-action-plugin-registration.md) 为准：同一参考 artifact 处理 create_issue 与 create_issue_comment，唯一协议为 github-issues-v1，输入输出均为封闭 operation/body envelope；旧裸 body 协议移除。Broker 从可信 Action 选择操作并比对完整规范 envelope，在现有 token exchange 之前拒绝不匹配。两操作增量已通过真实 Broker9项及 macOS/Linux 的 P6 release CLI/本地TLS验收；Linux P6 使用原有进程内实现，显式 artifact 登记在Linux上拒绝。完整资源限制仍按下面的实测边界记录。

## 2026-09-17 最终 exec 与重新 exec 的资源探针

同一 macOS 26.5.1 / 25F80 / arm64 上，每次仅一个 workload、最多触碰 96 MiB、父进程 5 秒兜底，得到如下新结果。未修改生产 runner 或系统设置。

| 启动链 | 本机观测 |
| --- | --- |
| direct jetsam64 → 可信进程 sandbox_init → 原地处理 | 393ms 内核 SIGKILL，非 watchdog |
| sandbox_init → SETEXEC+jetsam64 → artifact | 390ms 内核 SIGKILL，非 watchdog |
| 上一链 → artifact 再次 exec 自身 | limit_bytes_remaining 从 66,109,128 降为 0；触碰 96 MiB 后正常退出 |
| direct jetsam64 → sandbox_init 且完全禁止 exec | self-exec 返回 EPERM；386ms 内核 SIGKILL，非 watchdog |

因此仅在最后一次 exec 施加 jetsam 仍不足以限制任意登记 artifact：当前 profile 必须允许启动该文件，也允许它再次执行自身并丢掉限额。固定可信 sidecar 可以在读任务前自设 deny-default 沙箱并完全禁止 exec，但这改变信任/启动合同，不能用来证明任意动态 artifact 已受同等保护。初始化不能放在多线程 Broker 的 post-fork Rust 闭包中。

jetsam 针对 phys_footprint ledger；本轮最大 RSS 达 70,025,216 bytes，不能将 64 MiB footprint 配置写成严格 64 MiB RSS 上限。父 PID 的 kqueue NOTE_EXIT 只是退出通知；同进程 watcher 受 SIGSTOP 或饿死影响，独立监护进程也不是父死同步内核级联。当前保留已有采样、CPU 与存活父进程 deadline 合同，不新增监护层来冒充完整 P-10。

依据：[XNU SETEXEC](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_exec.c#L4363-L4370)、[exec 的 jetsam 参数处理](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/bsd/kern/kern_exec.c#L4943-L4976)、[footprint ledger](https://github.com/apple-oss-distributions/xnu/blob/xnu-12377.121.6/osfmk/kern/task.c#L7199-L7205)、[kevent/NOTE_EXIT](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/kevent.2.html)、[Apple 自定义 Seatbelt 支持边界](https://developer.apple.com/forums/thread/661939)。探针 C 源码、编译和逐样本日志保存于主仓库 `.git/codex/threads/remaining-effects-20260917/resource-research/`；这些实验只证明当前 OS build 的观测。
