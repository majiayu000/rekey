# 全范围竞品验收与后续实现范围

2026-10-05，状态：源码对比已开展；新增能力尚未实现。用户明确要求覆盖已列竞品的全部开发者/Agent 能力，包括 SSH、mTLS、PKI、团队与 HA。不能将“仅 HTTP 核心领先”作为完成条件。

基线：Rekey `043a020` / `0.3.0-alpha.1`，Agent Vault `872578e`，KeyFence `672cdef`，OpenBao `2fff36b`；1Password 公开 SDK `5866f43`，桌面与服务端闭源。逐项源码、运行状态和限制登记在本轮完整矩阵。没有实测的能力保持 source-only 或 vendor-documented-only；设计、枚举、已有测试源文件不算验收。

## 最小版与必要增加项

最小版复用现有 Authority 单 owner、capability、signed policy 参数授权、step-up、审批、执行前审计和外部 source/lease。现在先修复已测得的字面量响应扫描瓶颈，避免任何持久格式改动。

全面范围的必要增加项超过五个文件，包含 typed SSH/mTLS/private-key/PKI 操作、CA 生命周期持久状态、团队 admission/revocation，以及具体部署基础设施的复制、解封和 fencing。它们不是当前最小性能修复的一部分，也不能复用 Sign 枚举、审批 PKCS#11 工具或 DR 脚本冒充已交付。采用当前 workspace 和具体 closed operation；不增加通用插件总线、多租户数据库或自建 Raft。实现前按下面每项冻结具体接口与运行验收。

0.3 的 vault25/backup25/policy6 保持冻结。需要新 durable layout、private-key kind/AAD 或 signed policy 语义的能力进入独立后续 0.x 发布线，从 fresh state 初始化；不迁移、覆盖当前 App/vault，不加入双格式 reader。这里没有改变产品版本、创建发布或安装服务。

用户已选首套 HA 验收环境：现有 `tencent` + 新的独立 Linux 测试主机；不复用小型 `proxy`。只读 SSH 核实 tencent 为 Linux x86_64、2线程、约3.83GiB内存。用户随后授权自主查找并创建节点；已通过本机 Lima 创建 `rekey-ha-test-20261005`，Ubuntu24.04.4 LTS/aarch64、2核、4GiB配置、16GiB磁盘，guest shell/SSH资源检查通过。新节点为本机 VM，与腾讯云节点分属不同物理宿主；不是新增云 VPS，没有创建收费资源或修改腾讯云服务。guest 无 host mounts、SSH agent forwarding 或自动 TCP/UDP端口转发；Lima生成的SSH配置在 `~/.lima/rekey-ha-test-20261005/ssh.config`。两节点的互通部署、基础设施 fencing/unseal 与同步状态所有权仍需在具体实施 SPEC 里确定，普通 SSH kill 或网络失联不能冒充独立权威 fencing。

## 必须完成的能力与验收

| 范围 | 可复用部分 / 当前缺口 | 完成条件 |
|---|---|---|
| HTTP 性能 | 原封保持 scan projections、audit、signature、SSRF、usage；literal windows、历史 ledger、SSE retention 是实测瓶颈 | 完整有效响应的 p50/p95/p99、首字节、短批吞吐、稳态吞吐和 RSS 分别达标；成功率不低；同时复跑攻击与故障测试。不得删除安全保障取得数字 |
| SSH exec / Git / agent | 现有 closed action、参数 schema、capability、审批和审计；无 SSH 密钥和执行协议 | 固定 host/user/host-key/操作；远端固定 helper 通过 stdin 取公开参数，避免拼 shell。真实 OpenSSH 往返、错误 pin、取消、撤销、超时、审计失败。OpenSSH ssh-agent 和 Git 签名须单独实现 session/destination 绑定，不能把任意 signing oracle 或固定 exec 算兼容 |
| mTLS | 固定 HTTPS transport / strict server TLS；无 client identity | typed cert/key credential、有效期和 origin 绑定；标准要求 client cert 的服务器往返，错 CA/hostname/key/expiry、rotate/revoke/lock 均验证；key 不给 Agent 或子进程 |
| PKI / SSH CA / transit | Authority 及 connector effect 可复用；审批 signer 不是业务 key engine | roots/intermediates/CSR PoP/SAN/EKU/TTL、唯一 serial、leaf、CRL/撤销/轮换；SSH 证书和受限业务加解密/签名操作独立授权。durable reservation 在签署前、terminal commit 在结果返回前；禁止 private-key reveal |
| Team / RBAC / provisioning | lab OIDC/workload、relay directory、signed controlplane；不是完整团队闭环 | 独立组织 state/UID/备份、用户/组/角色和 approver 职责、禁自批；SCIM 入离职、组变更、真实 IdP 登录、禁用后新旧 session 在明确且实测的时限内撤销；团队管理 UI/CLI 的完整流程 |
| HA / restore / replication | 加密 snapshot、standby/DR、Docker 外部 fence 参考；无自动 HA | 一个选定基础设施的 single-writer active/passive、可信 fencing、唯一卷/状态所有权、node-bound unattended unseal、自动切流；真实两节点 partition/pause/resume/restart/controller 故障。测 RPO/RTO 与审计/撤销不丢；异步 snapshot 不宣称 RPO=0 |
| Identity / delegation | 当前 capability/mint/revoke、lab OIDC/JWKS/dynamic lease；无 child attenuation、全套账号后端 | child 权限只能收窄、祖先请求/用量预算及撤销原子传播；服务账号/工作负载验证、动态 lease renew/revoke/recovery、外部源失败和轮换闭环。不能仅返回任意 secret 给 Agent 以换取接口数量 |
| Protocol / SDK / client integration | built-in HTTP gateway、stdio MCP、模板；无通用 WebSocket、HTTP2、Linux Profile 和原生 SDK 包 | 分别运行 SDK/CLI/MCP/agent/git/WS fixture；保留固定动作和参数授权，WS 消息权限/credential reflection 单独定义；Linux Profile 真实内核边界验收；不能将透明任意代理直接塞回已删除的 v1 架构 |
| Ops / budgets / audit | default durable audit、lab sinks/metrics、保守 usage settlement；预算无 in-flight output reservation，ledger O(N) | 预付/结算合同明确、并发严格预算、计价与未知 usage；durable SIEM delivery / 查询 /保留 / 跨节点审计完整性；长历史性能与 crash/tamper 验证；消除 O(N) 用唯一认证结构替换，禁双账本/未经验证 cache |
| UX / platforms | macOS App、签名公证 pkg、Linux CLI；源码/合成验收与真人体验不同 | 完整 fresh install、首次设置密码/弹窗次数、一个真实工作周的 provider/client 使用记录；三至五位用户试用与独立核心安全审查。用户已暂缓的 Touch ID/清零/登录项真机项继续标未验，不反复请求 |

上述表是实现与验收清单，不是已具备功能表。完整矩阵中的 PostgreSQL backend、提案流程、目录/环境/插件、其他 secret engines、SDK/platform 差距仍逐项保留；同一结果可以通过现有系统组合完成，但须有运行证据，不按 capability 数量宣布胜出。

## 比较标准

功能逐项记“完整/部分/缺失/不可验证”，并列出默认/lab/付费/闭源范围。凡只有供应商文档、不具备账号/服务或硬件证据的项目不能判 Rekey 胜出。1Password 的 SSH agent、secret-reading SDK、环境 MCP、Credential Broker 是不同产品面，不能合并成一个无限制读取或永不读取结论。

性能以同机同负载为第一层，以完整公开 CLI/client 与真实 provider/SSH/PKI/团队/HA 部署为第二层。每个能力都有自己的延迟、资源和故障指标；未知和相同保证下未测试不算赢。当前短批 HTTP/CONNECT 测量不是最大稳态容量，当前测试 adapter 不是全产品安装验收。

后续按实测瓶颈→SSH/mTLS→PKI/key lifecycle→团队闭环→具体 HA 基础设施推进，每项修改先完成具体 SPEC、实施及复测。全部清单完成且运行证据覆盖后，才可能宣称满足“功能与性能全面更好”。
