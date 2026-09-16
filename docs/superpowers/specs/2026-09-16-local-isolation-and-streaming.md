# 本机隔离、插件与流式响应的实施边界

2026-09-16，状态：技术规格提案，未实现。本文不把设计或内部测试计划当作能力完成。用户已选择本地功能优先，外部能力先规格；下列涉及安全合同变化的选择分别记录。

## OS-05 / OS-06：macOS Agent 隔离

本轮只读检查环境为 macOS 26.5.1 / 25F80，存在 `/usr/bin/sandbox-exec`，但本机 man page 标注 DEPRECATED，SDK sandbox.h API 标注 No longer supported。Apple DTS 明确 SBPL 不是向第三方开放支持合同的接口，不能将其包装为官方受支持的产品保证。[Apple DTS](https://developer.apple.com/forums/thread/661939)

候选最小实验实现必须显式命名 experimental，限定已验收 OS build，默认仍返回 UNSUPPORTED_PLATFORM；任何规则安装或 spawn 失败均不得降级为直接运行宿主命令。不接受任意 SBPL 或任意例外配置。

固定 deny-default 规则只开放运行时必需读取、独立临时工作目录和一个 canonical、disjoint Agent UDS。禁止 state/Admin、其他 UDS、公网和 loopback TCP/UDP/DNS、进程调试、task port、跨进程内存及能代发网络请求的系统服务；清理父环境与非必要继承 FD，子孙进程继承限制。

以上是尚待证明的验收要求，不是现有 SBPL 已能满足的事实。不能为了启动某个解释器而无界开放文件、网络或 Mach 权限。

受支持产品路线有两个不同范围：

- 签名的 App Sandbox helper 配固定打包工具，评估专用 App Group 容器中的 Agent UDS；state/Admin 始终在外。必须实测无 network entitlement 时的数据面组合及子进程继承，不能从 entitlement 名称推导结果。[Apple 子进程说明](https://developer.apple.com/documentation/security/discovering-and-diagnosing-app-sandbox-violations)、[Apple App Group UDS 讨论](https://developer.apple.com/forums/thread/818192)
- 无网卡 Linux VM，使用受限的数据面桥接，复用现有 Linux launcher 的边界；需要 guest 镜像、生命周期和桥接规格，改变执行环境，不是替换原生 spawn 分支。[Apple Virtualization](https://developer.apple.com/documentation/virtualization)

验收仅攻击临时 fixtures。指定 Agent UDS 和固定 Action 应成功；state/Admin、路径别名、其他 UDS、IP/DNS、ptrace/task-port、继承 FD、子孙 exec、父进程退出分别有拒绝测试。未隔离控制组必须能执行同样操作，以免把 SIP/TCC 或目标本身不可调试误计为隔离效果。记录 OS build、架构、profile hash、签名和每项结果。

尚待产品选择：保留不支持、当前版本显式实验，或 VM 路线。OS-06 只汇总已实际验收的平台和拓扑，不泛化未来系统、任意 Agent、宿主 root 或同用户外部攻击者的防护。

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
