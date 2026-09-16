# 本机隔离、插件与流式响应的实施边界

2026-09-16，状态：OS-05 已选择并本机实验实现；GitHub 参考插件与独立 Anthropic 文本流已实现并通过专项验收，通用动态加载仍为提案。本文不把设计或内部测试计划当作能力完成。用户已选择本地功能优先，外部能力先规格；下列涉及安全合同变化的选择分别记录。

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

首个本仓库 GitHub 参考插件已确定为 macOS 原生可执行文件；未来第三方 connector 仍须明确实际效果、可执行格式和平台。进程协议与效果范围冻结后，先交付 P-10 的隔离执行，再接 SDK-04 注册加载。若选择 WASM，则单独明确运行时、host calls、内存/fuel和供应链，不能同时实现两套沙箱。

### 首个可审阅候选：GitHub CreateIssue 参考插件

当前仓库没有第三方插件 artifact，2026-09-16 继续实施时已给用户两个明确选项：先提取本仓库真实 GitHub CreateIssue 请求适配，或等待用户提供的第三方 Connector。用户随后选择先实现本仓库参考插件。以下为已接受并实现的首个效果范围，具体验收见 `2026-09-16-github-reference-plugin.md`；不把参考插件称作第三方适配。

候选只处理现有 `github_profile.rs` 中 title/body 的公开解析、拒绝未知字段、大小限制和规范序列化。固定 repository/Action 由可信 Admin 注册，插件不接触 `GitHubAppProfile`、installation 身份、JWT、私钥或 token。输出至多一项固定 Action 的结构化请求；Broker 核对原始已授权参数与效果绑定，继续负责签名、兑换、HTTP、sealing、revoke 和最终审计。插件不能换 repo、方法、路径、认证头或扩大用户批准的内容。

本地正向验收必须经过真实可执行子进程、Broker 的授权/执行路径和确定性 transport，并断言规范请求实际到达 transport、revoke 先于成功、审计闭合。伪造效果、artifact 摘要不符、异常退出、输出超限和 deadline 均须阻止业务效果或按已准入阶段完成审计/撤销。没有指定测试仓库和写入授权时，不向 GitHub 创建 issue。

现有 `agent-run` 不能直接用作此 runner：它允许 fork、stdin 为 `/dev/null`、stdout/stderr 直接交给调用者，且只 wait 直属子进程；未实现插件所需的有界 pipe、资源预算和 deadline 终止。P-10 必须有单独可证明的执行合同；进程组或 `setrlimit` 不能单独充当完整资源隔离证据。SDK-04 的持久 artifact 登记与 Action 绑定随后接入，不新增市场、自动下载或多个协议。

## NET-07：流式响应必须有新的失败合同

当前响应合同要求完整缓冲、检查秘密反射后再向 Agent 写出；失败只返回一个空 ERROR frame。边发送边检查无法保留“后续失败时没有任何已发送正文”的保证。因此不能仅把 transport 改成分块转发。

最小候选限定一个固定 provider/Action，并新增明确的流式协议：数据片段必须以唯一请求绑定，只有成功 terminal 表示完整成功；上游截断、超时、sealing、审计或撤销失败返回失败 terminal。Agent 已收到的非秘密前缀无法收回，不得视为完整成功或自动重试依据。现有非流式路径保持原合同。

秘密反射检查必须先于对应字节发送，所有适用 source/token/leased value 的变体在响应准入前固定。不能简单保留原始流的“最长 needle−1”尾部：现有 contains_secret 还会 percent-decode 后匹配，编码输入跨度可达 needle 的三倍，并有未完整 `%HH` 状态。SSE JSON escape 与多个 delta 拼接又改变 Agent 实际看到的字节；必须先定义最终文本投影，并在跨事件连续文本上检查。任何有界增量算法都须证明覆盖现有有限编码合同，不能声称检测任意编码或隐蔽信道。

需要有界背压、客户端断连后的 runtime-owned drain、统一绝对 deadline，以及最终审计/租约撤销的责任。MCP/CLI 必须区分片段与成功完成，不把部分文本包装为普通成功响应。

本轮已确定 Anthropic 纯文本 Action 与独立失败合同，详见 `2026-09-16-anthropic-text-stream.md`。验收使用跨分块 secret 变体、任意截断点、缓慢消费者、断连、deadline、审计故障和 revoke 失败；不能以模拟流速或分段输出已完整缓冲的结果冒充实时上游流式能力。


### 公开 API 的流式做法与具体候选

2026-09-16 核对官方 API 合同，而非推断 ChatGPT 网页或 Claude Code 的内部实现：

| API | 可见增量 | 完成与失败 |
| --- | --- | --- |
| OpenAI Responses | `response.output_text.delta` | `response.completed`、`response.incomplete`、`response.failed` 和流内 `error` 分开；局部文本 done 不是整体成功 |
| Anthropic Messages | `content_block_delta/text_delta` | `message_stop` 结束消息，但须结合 `message_delta.stop_reason` 判断正常结束、长度截断等；HTTP 200 后仍可能出现流内 error |

来源：[OpenAI streaming events](https://developers.openai.com/api/reference/resources/responses/streaming-events)、[Anthropic streaming](https://platform.claude.com/docs/en/build-with-claude/streaming)、[Anthropic stop reasons](https://platform.claude.com/docs/en/build-with-claude/handling-stop-reasons)。两者允许消费方先显示增量，后续失败不会收回已显示前缀。这不能替代 Rekey 的凭证反射检查。

建议的首个 Action 是 Anthropic Messages 纯文本生成：Admin 固定模型与输出上限，固定 `POST https://api.anthropic.com/v1/messages`、版本头及 `stream:true`；Agent 仅提交有界文本 messages，不开放 tools、thinking、文件或任意参数。认证头由 Broker 注入。该固定 Action 已在独立接口实现；实网验收需要具体 Admin 配置和测试账号，不在当前本地验证范围。接口来源：[Messages create](https://platform.claude.com/docs/en/api/messages/create)。

最小候选新增独立操作，不改旧 Execute：`CHUNK* → TERMINAL` 绑定请求 ID、序号单调。只发送解析并检查后的文本，不原样转发 SSE、provider 错误或 header。terminal 分 completed/incomplete/failed，EOF 或缺 terminal 始终不算成功。首版仅完整文本序列及 end_turn 可进入成功判定；截断保持 incomplete，拒答保持明确语义，未知输出类型明确失败。

Broker completed 必须晚于 provider 完成、全部检查、finished audit 和适用的 revoke；provider 自己的结束事件不能提前代表本地成功。CLI 失败/不完整须非零退出，MCP 不得把前缀包装为普通成功结果；不自动重试已发生效果的调用。若未来支持工具参数增量，完整 JSON/schema/授权校验之外，还须等 Broker completed 后才执行工具，这属于 Rekey 拟议限制。

用户已于本轮明确选择新增独立流式接口，接受后续失败时此前已检查前缀不可收回；原非流式操作仍完整检查后再返回。保持旧合同只能实现“真实 SSE 接收但完整缓冲后一次返回”，不改善首字延迟，不能将它或分段播放已缓冲正文记为 NET-07 完成。

## 2026-09-17 Linux Agent 验收增量

本轮复用现有 linux-netns-v1，不增加 Linux 插件后端。确定性验收使用实际 rekeyd 启动器、真实本地 Broker/Agent UDS 与合成 transport，覆盖授权请求成功、state/Admin 隐藏、TCP/UDP 拒绝、环境与继承 FD。负向用例必须有未隔离成功控制，先证明 sandbox 可真正启动；bwrap/userns 环境失败应令验收失败，不能充当攻击阻断。

本机可用 Docker Desktop 的 LinuxKit/aarch64；只使用独立测试容器及合成数据，不修改已有服务。若容器需放宽其自身 seccomp/capabilities 才能启动嵌套 namespace，应记入验证拓扑，并与 native Ubuntu CI 区分。该 Agent profile 允许只读宿主树及 fork/exec，不能复用来宣称不可信插件已隔离；macOS 的更窄代码目录授权不自动套用到 Linux。

### Linux 继承文件描述符修复合同

本轮真实攻击验收发现：父进程将已打开的 state 文件以非 CLOEXEC 的 FD 211 传入启动器时，现有 bwrap 子进程仍可使用该 FD，绕过路径覆盖。首轮 5 项中 4 项通过，该项在文件分支失败（probe 返回 0 而非 19，尚未到 socket 分支）；不能把只读挂载和隐藏路径当成已打开 FD 的撤权。

最小修复是在 Linux launcher 的 post-fork/pre-exec 阶段对全部 FD 3..UINT_MAX 调用 close_range(CLOSE_RANGE_CLOEXEC)，只标记、不提前关闭 Rust 的 exec 错误管道；成功 exec 时统一关闭。标准输入仍为空，标准输出/错误仍为调用者选择的流。闭包不得分配或加锁；系统调用失败直接拒绝启动，无逐 FD 兼容回退。该功能要求提供 CLOSE_RANGE_CLOEXEC 的 Linux 内核（5.11+）；旧内核或 seccomp 拒绝时明确失败。原攻击断言保持不变，并增加高 FD 在降低 rlimit 后仍清除的验证。

最终整合源码在 LinuxKit 6.12.76/aarch64、Debian bookworm 容器中验证：`cargo check --workspace --all-targets`、Clippy warnings denied 通过；5 项 sandbox_linux 测试在 root 和 UID/GID65534 身份分别通过，原 FD211 文件断言未削弱，另覆盖 socket 与 FD500/NOFILE128。容器需 `seccomp=unconfined`、`systempaths=unconfined`，无额外 capability、privileged 或宿主挂载。没有验证原生 Ubuntu、host proc/PID 逃逸、Docker socket 隐藏或父死；不扩大既有 G2 声明。官方 close_range/CLOEXEC 语义见 [Linux man-pages](https://man7.org/linux/man-pages/man2/close_range.2.html)。
