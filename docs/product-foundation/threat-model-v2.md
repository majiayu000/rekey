# Rekey v2 威胁模型

## 结论

Rekey v2 的核心防线不是“让 Agent 更可靠”，而是让 Agent 所能调用的接口本身不具备读密、
改目的地或绕过审计的能力。默认产品边界是 G1；Linux G2 只是一个有明确部署条件的参考边界。

## 受保护资产

- credential plaintext、VRK、DEK、password 和 recovery key；
- 管理员注册的 Action、激活的 policy snapshot 和 capability 状态；
- 审计事件的完整性、顺序和“执行前已留证”属性；
- vault ciphertext、wrapper、backup artifact 和 restore 状态。

## 对手能力

G1 假设 Agent 可完全控制 Agent IPC 输入、request body、允许的附加 header 和调用时序；可重放、
并发、断连、发送畸形 frame，诱导 upstream 反射 secret，并尝试 SSRF、redirect、DNS rebinding、
响应超限和 capability 跨动作使用。

G1 不防同一 OS 用户直接读取 broker 内存、state directory 或 socket，不防同用户 `ptrace`，
也不防 root、内核、恶意 Docker daemon、宿主机取证或已攻陷的管理员进程。

Linux G2 参考拓扑额外把 broker 和 Agent 放在不同 UID、PID namespace、filesystem view 与网络
边界中；它只对 `scripts/p1-linux-g2.sh` 明确攻击的部署形态成立。

## 信任边界与假设

| 边界 | 信任假设 | 失败方向 |
| --- | --- | --- |
| 管理员到 `admin.sock` | 管理员控制本地交互与 step-up 输入 | peer/proof 不符即拒绝 |
| Agent 到 `agent.sock` | Agent 完全不可信 | 未列入 Agent 协议的消息即拒绝 |
| Broker 到 vault | AuthorityWorker 是唯一状态与明文所有者 | store/audit 失败使 worker faulted |
| Broker 到 upstream | DNS、网络和 upstream 响应不可信 | 非公网、redirect、超限、读错或反射即拒绝 |
| Backup/restore | artifact 和路径可被篡改 | hash、schema、密文或持久化证据不符即拒绝启动/安装 |

## 主要攻击与控制

| 攻击 | 当前控制 | 剩余风险 |
| --- | --- | --- |
| Agent 直接取密 | Agent wire protocol 无读密操作；CLI 不链接 vault/crypto | 同用户可绕过 IPC 读取进程或文件，属于 G1 外 |
| 任意目的地带密请求 | Action 固定 origin/method/path/auth；capability 绑定 action version | 管理员注册恶意 Action 不在防护范围 |
| SSRF / DNS rebinding | 公网地址筛选、整组 DNS fail-closed、endpoint pinning | IP 分配规则变化需显式更新规范和测试 |
| redirect / proxy 劫持 | redirects disabled；任何 3xx 拒绝；忽略 proxy env | 宿主网络或根证书库被 root 攻陷不在边界内 |
| 响应反射凭据 | raw/base64/base64url/percent-encoded 扫描和有界缓冲 | 未纳入合同的变换编码不作通用 DLP 声明 |
| capability 重放 | hash 存储、TTL、action/version、max uses、并发限制 | capability 在有效期内泄露仍可按授权额度使用 |
| 审计后门或丢证 | `execution.started` 在解密前提交；审计失败 fault closed | 独立人工 failure-semantics 审查仍待完成 |
| crash / partial restore | WAL/FULL、marker、fsync、create-new/no-follow、receipt hash | 文件系统/硬件违反持久化语义不在软件保证内 |

## 发布前未闭合风险

- 密码学、IPC、审计与 failure semantics 尚缺独立人工安全审查记录。
- systemd required-job 尚缺真实平台证据。
- GitHub App 只有本地 TLS black-box harness，尚缺用户提供 fixture 的 GitHub live E2E。
- 默认 G1 拓扑不能防同用户内存、文件和 `ptrace` 攻击，因此不得宣传为通用 G2。

功能与证据状态以[功能真值矩阵](feature-truth-matrix.md)为准。
