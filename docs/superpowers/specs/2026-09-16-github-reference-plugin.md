# GitHub CreateIssue 参考子进程接入

已接受的最小切片：macOS 将公开 title/body 解析及规范序列化移入本仓库固定打包的 `rekey-github-create-issue` sidecar。Broker 仍验证 GitHub profile 与 Action，插件仅收到原始公开 JSON body，Broker 将输出与自己依同一纯合同计算的规范内容逐字节比较。未知字段、内容修改、额外效果均不能进入远程准入。JWT、installation、私钥、token、capability、header、URL 均不进入子进程。

固定 sidecar 位于宿主可执行文件同目录（Cargo 的 deps/examples 测试宿主寻找其上级目录）。无环境路径覆盖，无注册/市场/自动下载。Broker 打开该文件后复制为私有 0700 临时目录内的只读可执行快照，并核对复制字节 SHA-256；随后仅执行该快照。此摘要核对证明本次快照一致，不等于可信发布摘要登记；安装目录完整性仍由可信宿主管理。SDK-04 不在本切片内。

macOS 独立 deny-default Seatbelt profile 只允许系统 dylib 读取与精确 sidecar 文件、匿名标准 pipe；没有代码目录、HOME、临时目录的读写授权，也没有任何网络/UDS权限。禁止 fork；exec 仅限该固定快照（不能衍生其他程序）。stdin/stdout 有界为 256 KiB（覆盖现有最大 title/body 的 JSON escape 展开）；stderr 丢弃、环境全清、cwd=/。spawn 前仅调用 async-signal-safe libc 设置 CPU soft/hard 1/2 秒、关闭 core dump，并将实际 FD 快照中的所有 3+ FD 标记 CLOEXEC，包含先打开再降低 soft/hard limit 后存活的高 FD；快照至 fork 之间，可信 Broker 不并发制造非 CLOEXEC FD 或改变 limit，Rust/Tokio 后续 pipe/socket 本身以 CLOEXEC 创建。不声明任意恶意父进程的并发 FD 保证。绝不在 pre_exec 分配或加锁。

runner 使用既有 effect_deadline，包含输入写入、输出读取、退出等待；本地 artifact 快照读写为同步文件 IO，不宣称其硬限时，但在快照/FD 准备后、spawn 前再次检查 deadline，过期不得启动。错误时 kill/wait 单个进程（fork 已禁止），tokio future 丢弃时 kill-on-drop。每 10ms 使用 proc_pid_rusage 检查 64 MiB RSS，查询失败直接拒绝并杀死。此为采样内存看门狗，允许采样间超冲，**不是硬内存上限**；完整 P-10 的严格资源合同仍未完成。父 Broker 正常取消杀死子进程；父被 SIGKILL 时不保证子进程立即退出，但仍受 Seatbelt 与 CPU 限额约束。不得宣传 macOS PDEATHSIG 或硬内存资源隔离。

非 macOS 保持原有内置解析，不声明插件支持。测试使用真实 sidecar、真实 Broker 与确定性 transport；不访问 GitHub。公开请求匹配、revoke 在 success 前、审计闭合及恶意输出/超量/超时/文件/网络/fork/环境/FD/父退出均须验证。此实现需人工安全审查。

## 本机验证记录

2026-09-16，macOS 26.5.1 / 25F80 / arm64；实验 Seatbelt，不声明 Apple 支持的稳定沙箱 API。`github_issue_plugin.sb` SHA-256 为 `2e67ee1eb738b7b5d5b3ecc2044b459c8b66dff2b39ff9a5fa81f2097f3e4014`。

先 `cargo build -p rekey-broker --bin rekey-github-create-issue`；完整 Broker 构建使用 `cargo build -p rekey-broker --bins`。归档与 macOS app 构建清单均带 sidecar。缺失或非法 sidecar 在 macOS 直接拒绝，无内置解析回退。

- `cargo check --workspace` 通过。
- `cargo test -p rekey-connector github_issue`：1 通过。
- `cargo test -p rekey-broker --lib github_issue_plugin -- --test-threads=1 --nocapture`：8 通过（含隔离测试宿主 helper）。真实 native probe 覆盖已知 FD、FD 500 后降低 soft/hard limit 至 128、环境、fork、外部 exec、文件读写、UDS、loopback TCP、CPU、RSS watchdog、输入/输出超量、绝对 deadline、崩溃和伪造输出。文件/网络/fork/exec 均有未隔离成功控制组。
- 父 SIGKILL 测试先由 probe 的 stdout READY 握手证明 main 已启动，再杀死父宿主；未隔离 probe 能读取 `/etc/passwd` 后继续存活，受限 probe 的文件/loopback TCP 尝试仍失败。此测试不宣称父死自动 kill；早期仅通过 ps 映像与短 sleep 的测试有启动竞态，已替换为真实握手。
- `cargo test -p rekey-broker --test github_issue_plugin -- --nocapture`：1 通过。真实 Authority/Agent IPC、native sidecar、确定性 transport 收到精确规范请求。revoke response 的 gate 未放行时 Agent 无成功结果；放行后返回 201，审计 started → connector authorized → token revoked → finished 顺序闭合。非法公开字段无上游请求。
- `cargo test -p rekey-broker --lib github_profile`：原 4 项回归通过；格式、diff whitespace、macOS 构建脚本语法检查通过。整库回归由集成线程执行。

限制仍保留：未做外部 GitHub 写入；第三方 artifact 管理/可信摘要登记/SDK-04 未实现；RSS 为采样阈值，完整 P-10 严格内存合同未闭合；父被 SIGKILL 后不保证立即停止空闲子进程；不覆盖恶意父线程并发制造非 CLOEXEC FD；本地同步 artifact IO 没有硬超时；人工安全审查仍是合并门槛。
