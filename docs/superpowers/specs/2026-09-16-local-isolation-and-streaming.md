# 本机隔离、插件与流式响应的实施边界

2026-09-16，状态：OS-05 已选择并本机实验实现；插件与流式章节仍为未实现提案。本文不把设计或内部测试计划当作能力完成。用户已选择本地功能优先，外部能力先规格；下列涉及安全合同变化的选择分别记录。

## OS-05 / OS-06：macOS Agent 隔离

本轮只读检查环境为 macOS 26.5.1 / 25F80，存在 `/usr/bin/sandbox-exec`，但本机 man page 标注 DEPRECATED，SDK sandbox.h API 标注 No longer supported。Apple DTS 明确 SBPL 不是向第三方开放支持合同的接口，不能将其包装为官方受支持的产品保证。[Apple DTS](https://developer.apple.com/forums/thread/661939)

用户已于 2026-09-16 选择先实现 macOS Seatbelt。闭合 profile 名称为 `macos-seatbelt-v1`，属于实验支持；只按实际通过攻击测试的 OS build/架构报告能力，不声称 Apple 为 SBPL 提供稳定合同。macOS 的 `agent-run` 在计划验证后自动选择固定 `/usr/bin/sandbox-exec`，缺失、规则安装失败、spawn 失败均直接失败，没有裸宿主执行 fallback。Linux 的 `linux-netns-v1` 保持原合同。

### 已选择的最小实施合同

- 复用现有 state/Agent socket canonical/disjoint/owner/peer UID 校验。当前启动目录作为只读代码目录，必须与 state 和 Agent socket 所在目录不重叠；不允许把 `/`、用户 HOME 或临时父目录作为宽泛代码目录。目录重叠按文件系统目录身份（设备号/inode）核对祖先，覆盖大小写与 APFS firmlink 别名；代码目录也不得覆盖或位于 `/System/Volumes`，避免系统卷入口递归暴露 Data volume。命令二进制可位于代码目录外，但仅授予其精确路径读取。
- 固定 deny-default SBPL，通过 `-D` 参数传入路径，不拼接路径为 SBPL。仅开放固定系统运行时只读路径、只读代码目录、命令文件、0700 随机临时目录，以及精确 canonical Agent UDS 的 outbound。固定运行时根不得覆盖 state 或 Agent endpoint。
- 子进程 cwd/HOME/TMPDIR 为独立临时目录；PATH=/usr/bin:/bin、LANG=C，可选 REKEY_CAPABILITY；清除其他父环境。临时目录是唯一普通可写目录。Agent socket 目录不可写。
- 不开放 IP、DNS、其他 UDS、Mach 服务、Apple Events、跨沙箱 signal/process-info/task ports、调试或保护范围内的凭证文件；fork/exec 的子孙继承策略。没有自定义 SBPL、额外权限开关或 VM 依赖。
- 原生 `posix_spawn` 使用 CLOEXEC_DEFAULT；只显式继承 stdout/stderr，stdin 为 `/dev/null`。stdout/stderr 必须为普通文件、pipe、TTY 或精确 `/dev/null` 设备，socket 拒绝。所有准备/spawn API 错误直接返回。capability 不进入 spawn argv。
- 实际进程树是 CLI → rekeyd → sandbox-exec → Agent，CLI 与 rekeyd 各自 wait/reap 直属子进程并转交退出码。信号退出映射为 5。macOS 没有本实现可依赖的 PDEATHSIG：不承诺父进程被 SIGKILL 后杀光后代；必须证明父进程退出后后代仍受策略限制。临时目录正常结束时清理；异常杀死 launcher 可能留下该目录。此项不等价于 Linux `--die-with-parent`，也不是插件的资源限额/强制终止合同。

### 验收

正向必须启动真实二进制、连接 Agent UDS、完成已授权 fixed Action。负向覆盖 state/Admin/其他 UDS、路径别名、目录外写入、IP TCP/UDP/DNS、Mach/跨进程访问、继承 FD、环境、fork/exec 和父进程退出。对可测试攻击先跑未隔离控制组；SIP/TCC 已拒绝的项目不能计为 Seatbelt 独立防护证据。记录 OS build、架构、profile hash 与结果。

SBPL 的路径控制不保护允许读取的代码目录中被可信宿主事先放入的凭证副本或硬链接；启动目录应只含待运行代码。宿主同 UID 外部攻击者、root、内核漏洞与恶意管理员不在本合同内。默认 G1 与 Linux G2 既有声明不变。OS-06 仍待其他平台实现和逐平台验收，Windows 未实现。

### 本机验收记录（2026-09-16）

- 环境：macOS 26.5.1，build 25F80，arm64；本地 debug rekeyd 为 linker ad-hoc 签名，非公证发布产物。
- 固定 `macos.sb` SHA-256：`7861822ebb3af53011285566825fd922f882822f7826a52577a39c22c9ba2176`。
- `cargo test -p rekey-broker --test sandbox_macos -- --test-threads=1 --nocapture`：7 项通过；包含 APFS/case 别名、保护目录内 Admin socket 伪装为 Agent endpoint 的拒绝。
- 真实 Broker 的 capability / policy / fixed Action 链路通过；上游是确定性测试 transport，未声称接入外部 provider。
- 工作区回归 `cargo test --workspace --offline`：497 通过、0 失败、1 个既有忽略项；最终 state/endpoint 别名拒绝补丁另经上述 7 项 macOS 测试复验。`cargo check --workspace --all-targets`、Clippy（warnings denied）、格式及机械合同检查通过。
- CLI 烟测：stdin capability 与环境清理、退出码转交、CLI 父进程退出后后代继续受限，3 项通过。
- `task_for_pid` 未隔离控制组同样失败，因此不计入 Seatbelt 独立防护证据；未独立证明 ptrace 防护。网络成功控制组覆盖本机 IPv4/IPv6 TCP/UDP 与 UDP send，未声称完成公网 TCP 成功控制组。
- 本记录只证明这一系统 build；其他 macOS build、Linux 本轮运行与 Windows 均无新验证。合并前仍需人工安全审查。

## SDK-04 / P-10：先冻结插件执行合同

现有 connector 是编译期静态合同，Broker 负责秘密、网络效果、deadline、审计和清理。动态加载不能把不受信任的本地库装入持有秘密的 Broker 进程。

最小提案为单个固定、版本化的独立子进程 connector：输入只含其授权 Action 的公开描述、请求参数和合同版本，输出结构化的效果请求或公开结果。VRK、来源身份、私钥和 PreparedCredential 不传给子进程；所有凭证相关网络、签名、租约和撤销仍经 Broker 的既有授权边界执行。插件不能请求任意 URL、路径、认证头、文件或扩大 Action 参数。

注册由 Admin step-up 固定 artifact 内容摘要、合同版本和允许的效果；执行前必须核对实际打开 artifact 的身份与内容。签名验证只能证明来源，不证明插件安全。首版不建远程市场、自动下载更新、别名或兼容协议。

子进程需独立限额与隔离，包含进程数、CPU、内存、输入/输出字节和绝对 deadline；超限/断连/协议错配关闭效果准入并终止整个进程组。子进程退出不能取消 Broker 已准入效果的审计与 revoke 责任。收尾失败、写效果结果未知沿用 fail-closed/indeterminate，不能重试写入。

验收必须包含伪造效果、越权参数、超量输出、死循环、内存耗尽、fork、网络/文件/调试绕过、子进程崩溃和父进程关闭。正向测试只用一个真实具体 connector；纯 echo 或未接入执行链的模块不能证明动态 connector 可用。

实施前仍须选定首个第三方 connector 的实际效果、可执行格式和目标平台。进程协议与效果范围冻结后，先交付 P-10 的隔离执行，再接 SDK-04 注册加载。若选择 WASM，则单独明确运行时、host calls、内存/fuel和供应链，不能同时实现两套沙箱。

## NET-07：流式响应必须有新的失败合同

当前响应合同要求完整缓冲、检查秘密反射后再向 Agent 写出；失败只返回一个空 ERROR frame。边发送边检查无法保留“后续失败时没有任何已发送正文”的保证。因此不能仅把 transport 改成分块转发。

最小候选限定一个固定 provider/Action，并新增明确的流式协议：数据片段必须以唯一请求绑定，只有成功 terminal 表示完整成功；上游截断、超时、sealing、审计或撤销失败返回失败 terminal。Agent 已收到的非秘密前缀无法收回，不得视为完整成功或自动重试依据。现有非流式路径保持原合同。

秘密反射检查应在任何对应字节发送前完成，至少保留最长受保护变体长度减一的尾部，跨 HTTP/TLS/协议分块检查；所有适用 source/token/leased value 的变体必须在响应准入前固定。此描述仅为候选算法，不能替代对编码、边界、取消和 partial-output 的测试与独立审查。

需要有界背压、客户端断连后的 runtime-owned drain、统一绝对 deadline，以及最终审计/租约撤销的责任。MCP/CLI 必须区分片段与成功完成，不把部分文本包装为普通成功响应。

实施前需确定一个具体流式 Action、provider 帧格式，以及接受“失败可能已经发送非秘密前缀”的产品合同。验收使用跨分块 secret 变体、任意截断点、缓慢消费者、断连、deadline、审计故障和 revoke 失败；不能以模拟流速或分段输出已完整缓冲的结果冒充实时上游流式能力。
