# Rekey 全范围源码与实测对比

日期：2026-10-05。结论：当前不能宣称功能或性能全面领先。Rekey 的固定动作、参数授权、执行前持久审计和凭据反射封口有明确实现与组件证据；竞品在 SSH/mTLS、CA/PKI、团队/目录、协议兼容和 HA 上有 Rekey 尚未实现的能力。初次比较由三个实际并行 agent 分工，后续优化另有分工与独立复审，原始源码、测试与测量产物保留。没有使用新闻作功能或性能依据。

## 固定版本与证据

| 产品 | 固定源码 / 产品面 | 本轮运行证据 |
|---|---|---|
| Rekey | `043a0206473b2d37eec6222c4fefbc7b41fc5090`，公开 `v0.3.0-alpha.1` | 生产组件 TLS gateway/IPC/审计/ledger/unlock；当前原生 App、SE 和真人使用未补验 |
| Agent Vault OSS | [Infisical/agent-vault](https://github.com/Infisical/agent-vault/tree/872578e4cdf9e03d5e3bcb5512023a70bf90ed65) | 优化 CLI build、原有定向测试与新增 scope/reflection/EOF/audit probe，生产组件 TLS pipeline |
| KeyFence | [atgreen/keyfence](https://github.com/atgreen/keyfence/tree/672cdefc0fe90c94f83aca765e19d7d9af044922) | 优化 CLI build、29 项顶层定向测试、新增 SSRF/reflection/audit/budget probe，生产组件 TLS pipeline |
| OpenBao | [openbao/openbao](https://github.com/openbao/openbao/tree/2fff36bce80801e8f8d2ad5485948af16ee5db4d) | ACL/参数 2 项、SSH issuer 与 PKI CSR/撤销/TTL 4 项组件测试通过；无集群/完整 CLI 部署或性能排名 |
| 1Password developer surfaces | [Go SDK](https://github.com/1Password/onepassword-sdk-go/tree/5866f43111ffeee5952e43a13da1aafef98200c8) + 官方技术文档 | 公开 binding/plugin 与文档盘点；桌面/server/core closed，未使用真实账号、运行 SSH/Broker/团队流程或测性能 |

`source-only` 表示实际实现已读，未运行该完整场景；`runtime-component-tested` 也只升级对应组件。供应商文档和 SDK 接口不证明闭源 backend 行为或性能。表中测试通过数不是产品功能得分。

## 主要能力差异

| 能力 | Rekey 当前 default / lab | 竞品源码中的实质能力 |
|---|---|---|
| Agent 不取得 Key | default 固定 HTTP 代执行、consume-once；admin reveal 独立 step-up | AV/KeyFence 代理可不交付 Key，但本轮真实反射 probe 均泄漏合成注入值；OpenBao/1Password secret-reading API 是另外的安全边界 |
| 动作/业务参数 | signed policy + schema/JCS、固定 origin/method/path；schema 可由 admin 配为开放 | AV 当前 host/port/path；KeyFence method/path/size/content-type 无业务 JSON schema；OpenBao ACL 参数限制约束自己的 API，不等同第三方动作 |
| 持久审计失败 | default execution.started 在解密前提交，失败 worker fault | AV BatchSink best effort、KeyFence Encode error 忽略，probe 验证执行继续；OpenBao request audit gating 有真实实现，不能笼统说 Rekey 唯一 fail-closed |
| 凭据类型 | default opaque header/GitHub App；外部来源/动态 lease 在 lab | KeyFence first-class Basic/mTLS/SSH；AV OAuth/Infisical 动态 secret；OpenBao secret engines 与 CA；Rekey Basic 仅预编码 generic header |
| SSH / Git / agent | 未实现 SSH action、agent、SSH CA 或 Git key signing | KeyFence SSH exec bastion；OpenBao SSH OTP/CA/multi-issuer；1Password SSH agent/Git signing 文档与公开集成面 |
| mTLS / PKI | 无业务 client identity 或 CA lifecycle；approval signer 不计作业务 key engine | KeyFence 上游 mTLS；OpenBao cert login、roots/intermediates/CSR/CRL/OCSP/ACME；类型和验收不能互相冒充 |
| Team / IAM | default OS peer/principals；lab OIDC/workload/relay/quorum/controlplane | AV 多用户/vault RBAC、proposals；OpenBao entities/groups/namespaces/control groups/MFA；1Password teams/SCIM/events 按闭源文档层登记 |
| HA | snapshot/standby/DR 与 bounded Docker external fence 参考；无自动 HA | AV PostgreSQL storage 是 source-only，不自动证明 HA；OpenBao 同集群 Raft/leader/read standby 有实现；当前无其跨集群 DR replication 证据 |
| Delegation / budgets | 无 child attenuation；token/day 看已结算总量，无 in-flight output reservation；ledger O(N) | KeyFence child/ancestor request budgets、Lua 用量后撤销；OpenBao child/role/token/lease 合同；都须分清请求次数与 LLM 输出/计价 |
| 协议 / SDK /平台 | built-in LLM HTTP gateway、stdio MCP、模板；无 WS/HTTP2/native SDK 包；Linux Profile unsupported | AV/KeyFence HTTP/CONNECT/WS、AV TypeScript SDK/Docker；OpenBao bao CLI/API/Web UI；1Password developer plugins/SDK/Connect/env MCP 各是不同产品面 |
| 运维 /反馈 | durable本机audit，lab sink/metrics/archives；原生 UI/真实 provider 工作周及客户 HA 未验 | 完整目录、集成、控制台、计价、外部源同步/轮换与 deployment 各有差距或证据不足；不能拿 lab 类型/脚本直接计产品完成 |

完整逐项矩阵、每项固定源码行和运行限制见产物目录 `full-capability-matrix.md` / `.json`：AgentVault57、KeyFence44、OpenBao59、1Password81，共241个对方能力主题。当前 Rekey inventory 有 85 项：54 implemented、9 partial、22 absent；默认/lab/源码/实测分别标注。这是主题盘点，不是等价功能数量或胜率。

## 基线性能

同一 M3 Max/128GiB/macOS26.5.1、同一合成 TLS upstream、TLS/SNI 验证开启、优化构建。3 modes × 4 wire sizes × c1/c4/c16/c64 × 3产品 × 3轮，共432 cells、27,648 attempts。每cell fresh server/state、4次小请求 warmup，每次客户端重新建 HTTP/CONNECT 连接。下表为 c1，三轮合并192次；延迟在 body 完整读完、Python本地验证前停止。只计算完整有效无反射响应的成功吞吐。

| 场景 | Rekey 成功 p95 / 完成 | Agent Vault 成功 p95 / 完成 | KeyFence 成功 p95 / 完成 |
|---|---|---|---|
| 1KiB JSON | 3.289ms / 192/192 | 1.694ms / 192/192 | 2.685ms / 192/192 |
| 4MiB JSON | 207.907ms / 192/192 | 7.810ms / 192/192 | 8.456ms / 192/192 |
| 1KiB text SSE | 4.751ms / 192/192 | 2.118ms / 192/192 | 2.931ms / 192/192 |
| 4MiB text SSE | 无成功 / 0/192 | 11.319ms / 192/192 | 12.995ms / 192/192 |
| 1KiB tool SSE | 4.406ms / 192/192 | 1.633ms / 192/192 | 2.671ms / 192/192 |
| 4MiB tool SSE | 无成功 / 0/192 | 13.072ms / 192/192 | 14.477ms / 192/192 |

Rekey 4MiB SSE 触发 aggregate retained-memory 限额，text 中断/工具502；属于可接受响应规模的差距，不把失败延迟当速度。所有完成的正常响应 SHA256 与精确 fixture body 核对，0 mismatch；各轮波动、c4/16/64、p50/p99/首字节/RSS、每次 status/error 与 raw 样本全部保留。Rekey 单session cap4，c16/64的拒绝独立展示。

本测试不是专机或最大稳态吞吐：host还有用户进程；closed-loop吞吐包含Python validation/GIL；RSS50ms采样会漏瞬时峰值；AV burst200覆盖短批64+warmup，不证明其20RPS default长期限速；不同产品的审计和反射保障不同。测试 adapter pin已知上游地址，不据此宣称公网筛选测试通过。OpenBao和1Password没有等价HTTP代执行场景的性能实测，不能编造对它们的排名。

Rekey domain 仅为测试 ID helper 启用 release debug-assertions，其余 opt-level3/release；是生产组件 adapter 而非已发布 CLI 字节一致。原 `baseline` 因 fixture/计时问题整批排除；只使用修正后的 `baseline-v2`，失败和修正记录保留。

## 历史账本与解锁

生产 ledger store、20 samples，每次 admission+settle 合计 p95：初始0条0.534ms、1k条10.541ms、10k条107.257ms、100k条1059.562ms。历史 fixture 的构造不计时；不包含 Authority queue/IPC/network，也不将额外 verified_read benchmark 计生产成本。完整 authenticated集合在 admission和settle中重读/校验/重封，实测与O(N)源码一致。索引或双 totals cache 不能代替完整性证明。

生产64MiB/3pass KDF锁定后解锁20 samples，p50 100.817ms、p95 113.060ms，warm status p95 0.241ms；单独记录init/first unlock，不是冷OS cache。不可用降低KDF参数或把固定安全成本移出统计来宣布更快。

## 已实施与仍未完成

本轮只对确切扫描瓶颈做最小改动：naive byte windows改已锁定memchr literal search，接口和empty needle=false不变，保留所有编码投影、Zeroizing、header/chunk/限额、signature与audit。新增必要等价和4MiB反射位置回归。独立只读review未发现安全/错误合同降级。复测及最终workspace检查结果在本报告下方更新。

优化后的有效批次为 `optimized-v2`，再次432 cells、27,648 attempts、完整成功body SHA256 0 mismatch；三轮均保持原安全保障。`optimized-v1` 因本线程创建VM时短暂镜像转换产生I/O干扰整批排除，日志保留；VM完成初始化并停机后才运行有效复测，两套有效数据共55,296 attempts。

| 同轮 c1、每产品192次 | Rekey 优化后 p95 / 完成 | Agent Vault p95 / 完成 | KeyFence p95 / 完成 |
|---|---|---|---|
| 1KiB JSON | 3.509ms / 192/192 | 1.797ms / 192/192 | 2.930ms / 192/192 |
| 4MiB JSON | 20.601ms / 192/192 | 8.161ms / 192/192 | 9.289ms / 192/192 |
| 1KiB text SSE | 4.764ms / 192/192 | 1.590ms / 192/192 | 3.085ms / 192/192 |
| 4MiB text SSE | 无成功 / 0/192 | 16.157ms / 192/192 | 13.559ms / 192/192 |
| 1KiB tool SSE | 5.155ms / 192/192 | 1.922ms / 192/192 | 2.661ms / 192/192 |
| 4MiB tool SSE | 无成功 / 0/192 | 22.453ms / 192/192 | 15.845ms / 192/192 |

4MiB JSON p95从207.907降到20.601ms，约10.09倍；短批成功吞吐从4.83增到47.14req/s。这是扫描瓶颈改进，不是全产品胜出：同轮该场景仍慢于两个直接竞品，小响应未显示提升；4MiB SSE、单session cap4、长历史ledger与功能差距均未修复。不能将不同host load下的毫秒波动当独立因果，完整各轮记录和限制仍适用。

workspace check、fmt与定向扫描/stream/reflection/gateway测试通过。默认并行workspace test两次遇到等待超时（admin VRK rotation等待、CLI child/session fixtures）；失败原始日志保留。VRK单项复跑通过，完整 `cargo test --workspace -- --test-threads=1` exit0，日志汇总1035 passed/6 ignored。不把串行通过改写成默认并行通过，也未扩大修改这些测试。

SSH、mTLS、PKI、完整团队和自动 HA 尚未交付。0.3 vault25/backup25/policy6 冻结不变；必要新持久结构在后续独立0.x线具体SPEC后实现。完整未完成清单与验收在 `docs/superpowers/specs/2026-10-05-full-competitor-acceptance.md`，不是已实现宣称。真人硬件项按用户决定暂缓，真实一周使用/3–5用户/客户部署/人工独立安全审查未被合成测试替代。

用户已选 `tencent + 新Linux测试节点` 并授权自行创建。已创建本机 Lima/VZ 节点 `rekey-ha-test-20261005`（Ubuntu24.04.4 LTS/aarch64、2核/4GiB/16GiB），guest资源及SSH检查exit0；两个节点分属本机Mac与腾讯云物理宿主。此项准备不是自动HA/复制/fencing/unseal验收，也没有变更腾讯云服务。VM配置、实际验证、start/stop/delete命令在 `coordinator/ha/node-manifest.json`。

## 可复现产物

本机证据根：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-comparison-20261005`。

- `full-capability-matrix.md/json` 与每产品 report/capabilities：逐项固定源码、default/lab/闭源、命令和证据边界。
- `coordinator/benchmark-protocol.md`、`environment.json`、`tls_fixture.py`、`measure.py`、`run_matrix.py`、`aggregate.py`：完整协议与fixture/驱动/汇总。
- `coordinator/measured/baseline-v2/matrix.md/aggregate.json` 与r1/r2/r3 raw cells：有效基线。
- `coordinator/measured/optimized-v2/matrix.md/aggregate.json`：有效复测；`baseline-excluded.json` / `optimized-v1-excluded.json` 说明排除批次。
- `rekey_perf/release/{ledger-raw,unlock-raw}.json`：20-sample独立测量。
- `rekey_perf/baseline-binaries/sha256.json`、`optimized/response-scanning.patch`、`optimized/executables.json`：不可覆盖基线与优化实现。
- `coordinator/integrated-*.log`、各lanelogs、threads运行记录：真实失败、复跑和检查。未读真实Key，未修改原dirty checkout/已装App/当前vault/系统CA或发布新版本。

## 第二批性能修复与完整复测

在同一043a020基线上新增 exact needle去重、保留预分配的安全SSE前缀回收、字节相同的aws-lc canonical ledger hash/ordered insertion，以及Running协调锁争用按既有截止排队。独立复审发现并关闭了缓冲扩容清零回归；完整指纹与报告保留。没有新增格式、策略字段、双账本或跨请求cache。

有效批次 `optimized-v3`：432 cells、27,648 attempts，三个平衡轮次；全部driver/server正常退出，完整成功body SHA256 0 mismatch。相同fixture/连接/安全边界；新增非200合成error body与工具参数非空/MIME验证，计时终点保持。测试节点在测量期间停机，结束后恢复；其他用户进程未停，因此不是专机稳态容量证明。

| c1，每产品192次 | Rekey p95 ms / 完成 | Agent Vault p95 ms / 完成 | KeyFence p95 ms / 完成 |
|---|---|---|---|
| 1KiB JSON | 2.519 / 192/192 | 1.728 / 192/192 | 2.591 / 192/192 |
| 4MiB JSON | 14.730 / 192/192 | 7.896 / 192/192 | 9.218 / 192/192 |
| 1KiB text SSE | 3.870 / 192/192 | 1.841 / 192/192 | 3.016 / 192/192 |
| 4MiB text SSE | 132.940 / 192/192 | 12.129 / 192/192 | 13.538 / 192/192 |
| 1KiB tool SSE | 5.891 / 192/192 | 2.287 / 192/192 | 2.899 / 192/192 |
| 4MiB tool SSE | 无成功 / 0/192 | 12.519 / 192/192 | 14.776 / 192/192 |

c4 1KiB JSON从此前92/192成功、100次503，变为192/192成功且无503，成功p95为3.548ms。只证明此负载的Running争用修复；c16/c64仍有session cap4拒绝，不能外推所有503消失。4MiB text SSE从0/192变为192/192，但c1 p95仍132.940ms，慢于同轮两个直接竞品；4MiB完整工具流仍0/192（502）。大JSON c1 p95为14.731ms，较前批20.601ms降低，仍慢于同轮竞品；不能归纳为全产品领先。

| 初始历史 | admission+settle p95 ms，20次 |
|---:|---:|
| 0 | 0.604 |
| 1000 | 5.725 |
| 10000 | 52.933 |
| 100000 | 510.139 |

100k历史p95从1059.562ms降到510.139ms，约2.08倍；仍为O(N)，0历史0.604ms没有显示收益。每个历史规模reopen均WAL/synchronous FULL、pending0、40条audit；不含Authority queue、IPC、网络或构造fixture成本。跨批数字含host load差异，不按单一毫秒变化承诺因果或峰值。

最终源码：cargo fmt、workspace all-targets check、clippy -D warnings、完整串行workspace test（1046 passed / 6 ignored）、diff/CLI依赖/禁止secret API机械合同全部通过。未运行或宣称默认并行全仓通过，未推送、合并、安装或发布这批变更。

1Password用户确认没有隔离测试租户，闭源SSH/团队/Connect运行与性能继续未验。后续SSH/mTLS认证提交须与rotate/revoke共享执行边界；source/API规划不等于实现。所有241主题范围与真人设备/使用验收保持原清单。

本批产物根：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-optimization-20261005/tranche-001`。`final-validation-summary.json`、`coordinator/measured/optimized-v3/{matrix.md,aggregate.json}`与raw cells、`release/ledger-raw.json`、`review/performance-tranche-review.md`、`benchmark-production-overlay.json`和`release/verified-binaries/manifest.json`给出实际结果、当前源码与二进制指纹。

## 第三批：工具流规模修复与当前性能

本批将 Chat tool-id/name 的保留尾部缩短为编码边界或真实 needle 前缀需要的范围；原完整四投影检测、aggregate/raw/terminal 限额保留，proper-prefix 或编码 marker 仍可 pin 到原限额。增长缓冲复制后先清零旧有效字节，再交换并由 Zeroizing 清零旧 capacity 后释放；没有 allocator 或 RSS 清零验收声明。转换检测的两个 marker 扫描使用 memchr，未新增缓存或跳过投影的规则。

普通 HTTP 仅在 construction 与 first poll 前验证协调状态及 live permit；handoff 后仍按原自然 drain/撤销宽限执行。这不是 SSH/mTLS 所需的每次认证提交与 backend 关闭确认。独立静态复审无未关闭 P0/P1，不等同人工独立安全审查。

有效批次 `optimized-v4`：相同平衡三轮协议，432 cells、27,648 attempts；全部 driver/server exit0，完整成功 body SHA256 0 mismatch，fixture 正常退出，测试 VM 恢复。c1 表如下：

| c1，每产品192次 | Rekey p95 ms / 完成 | Agent Vault p95 ms / 完成 | KeyFence p95 ms / 完成 |
|---|---|---|---|
| 1KiB JSON | 11.127 / 192/192 | 1.438 / 192/192 | 2.590 / 192/192 |
| 4MiB JSON | 19.186 / 192/192 | 15.696 / 192/192 | 13.876 / 192/192 |
| 1KiB text SSE | 6.734 / 192/192 | 1.930 / 192/192 | 3.142 / 192/192 |
| 4MiB text SSE | 326.427 / 192/192 | 12.779 / 192/192 | 16.327 / 192/192 |
| 1KiB tool SSE | 3.587 / 192/192 | 1.462 / 192/192 | 2.462 / 192/192 |
| 4MiB tool SSE | 127.403 / 192/192 | 11.924 / 192/192 | 13.475 / 192/192 |

正常 4MiB 工具 fixture 从上一批 0/192（502）变为 192/192；c1 p50 120.513ms、p95 127.403ms、p99 146.314ms，仍明显慢于同轮竞品。它证明该 fixture 的规模问题修复，不证明所有 SDK 或所有 metadata 输入均支持。4MiB text 同样完成192/192，但 pooled p95 326.427ms；不能将完成率提升描述为延迟领先。

轮次差异必须保留：Rekey 1KiB JSON 三轮 p95 为22.664/1.857/2.709ms，4MiB text 为124.170/445.587/132.848ms；4MiB tool 为125.297/128.097/123.103ms。混合修改与非专机条件不足以把跨批延迟变化归因于单个代码改动，也不能挑选最快轮替代 pooled 结果。

c4 的4MiB JSON全部192/192完成：Rekey p95 27.401ms、144.15req/s，AV27.574ms、149.12req/s，KeyFence52.312ms、120.01req/s；只说明这一短批负载的相对结果。c4 text/tool 的 Rekey p95 为214.003/189.723ms，仍慢于两者。c16/c64 仍受 session cap4 拒绝，1KiB JSON分别38/192与42/192完成，4MiB工具分别12/192与12/192；没有提高并发能力的宣称。

最终代码 cargo fmt、workspace all-targets/all-features check、clippy -D warnings、完整串行 workspace test（1066 passed / 6 ignored）、diff/CLI依赖/禁止secret API合同全部通过。三次中间失败（自然drain、panic锁释放、timeout审计reason）在修改代码后关闭，原回归测试未放宽，失败产物保留；本表只使用最终代码。0.3 vault25/backup25/policy6 不变。没有推送、合并、安装或发布本批；SSH/mTLS/PKI/团队/自动HA与闭源1Password仍未交付或未验。

本批产物根：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-optimization-20261005/tranche-003`。`final-validation-summary.json`、`integration-manifest.json`、`release/verified-binaries/manifest.json`、`coordinator/measured/optimized-v4/{aggregate.json,matrix.md}`、raw cells 与 `handoff_review` 给出最终源码、实测及复审证据。

## TCP 发送假设的配对验证

针对约120ms的大流延迟，另做窄范围A/B：A为上文Q3不可覆盖binary，B仅对gateway accepted TCP连接设置TCP_NODELAY。每场景7对、交替顺序、fresh state、64次请求与4次warmup；3 modes × 2sizes × 7pairs × 2versions共84 cells、5376 attempts，c1。此项用于验证因果候选，不是新的竞品全矩阵或最大吞吐测试。

| 场景，448次/版本全部完成 | A p50 / p95 ms | B p50 / p95 ms |
|---|---|---|
| 1KiB JSON | 1.485 / 1.903 | 1.478 / 1.817 |
| 4MiB JSON | 11.382 / 13.562 | 11.332 / 12.995 |
| 1KiB text SSE | 2.693 / 3.136 | 2.682 / 3.207 |
| 4MiB text SSE | 121.622 / 125.274 | 122.227 / 125.760 |
| 1KiB tool SSE | 2.719 / 3.276 | 2.715 / 3.201 |
| 4MiB tool SSE | 121.911 / 125.297 | 122.365 / 130.349 |

所有driver/server exit0、完整正文SHA mismatch0，fixture exit0、VM恢复exit0。大text/tool未见可复现收益，故撤销候选，生产gateway保持Q3版本；实验binary、patch、SPEC和每一对raw均保留。不能由此断言所有网络场景无收益；本fixture仍未有全功能或性能领先证据。锁定reqwest upstream默认已启用TCP_NODELAY，Go与Python客户端默认也已启用，未增加重复配置。

源码工作量分析发现本4MiB工具fixture有3421帧、19条needle；固定4096B读取模型有约14.9万次literal搜索及3418次JSON树解析/清理。网络write不等于实际read分块，搜索输入长度不等于CPU真实读取量，静态计数不能证明125ms的来源。后续微测会分开扫描、解析和调度成本。

配对证据：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-optimization-20261005/tranche-005-sse-latency`，`paired-aggregate.json` / `paired-status.json` / `paired-protocol.md` / raw cells 与 `transport` / `scans`；候选已经撤回，未提交无收益的生产代码。

## 流式扫描的隔离微测

在仅cfg(test)的临时测量覆盖中，用同一SHA的4MiB工具fixture、19条真实合成needle、4096B固定分块、4个Tokio worker，2次warmup与20次串行sample。实际生产 `run` + `Complete::release` 的 wall p50/p95 为102.341/103.299ms，进程user+system CPU p50/p95 为111.096/113.058ms。每次验证完整字节、usage7及终端保留；准备、drain/断言、TLS/网关/vault/audit与report IO不计时。

预构造相同扫描视图后，实际 `contains_secret` 循环 wall p50/p95 为63.509/65.796ms，进程CPU为63.074/64.820ms。这个fixture扫描确实占用显著CPU；预构造缓存/分配布局与完整run不同，所以相减不能把剩余成本精确归因于JSON解析或yield。它不是完整HTTP延迟或竞品排名。

计数与静态模型一致：raw1024窗口、decoded key/string54,688窗口、semantic Tail3417窗口；字面eligible搜索149,207次，另含JSON投影搜索。网络分块仍只证明synthetic4096模型。微测代码没有加入生产提交，正式benchmark源码已恢复；不可覆盖release测量binary、raw、源码patch/hash及计时边界位于 `tranche-007-sse-cpu`。首字节缺席候选的交替配对、常首字节负载和正式复测见下一节。

## 第四批：首字节预筛选的正式复测

只在既有empty/length guard后增加三行首字节缺席判断，再保留原memmem literal search；完整JSON/percent decode/percent fold投影不变，无新缓存、分配、secret副本、配置或错误路径。两项必要回归覆盖全部首字节、binary/重叠/末尾匹配与常首字节不匹配，既有参考等价与反射测试保留。独立静态复审无开放P0/P1；实验micro代码只在证据覆盖，不进入最终源码。

同binary交替原实现/候选的16个raw/encoded/常首字节场景，各7对，全raw保留。32B与1KiB常首字节、1KiB/64KiB marker-heavy的median比率约1.005–1.011，没有宣称所有输入获益；缺席首字节与late-match的4MiB比率为0.556和0.823。20次同工具fixture隔离微测的full run+release wall p50/p95为36.302/37.249ms、进程CPU44.612/45.788ms；实际扫描wall5.625/5.894ms、CPU5.557/5.764ms。原微测相应wall p50为102.341ms和63.509ms。分块、准备和完整HTTP计时边界仍按上一节，不将CPU微测当产品延迟。

有效正式批次`optimized-v5`：同固定源码竞品、三轮平衡协议，432 cells、27,648 attempts；全部driver/server exit0，成功完整body SHA256 mismatch0，fixture exit0与测试VM恢复exit0。

| c1，每产品192次 | Rekey p95 ms / 完成 | Agent Vault p95 ms / 完成 | KeyFence p95 ms / 完成 |
|---|---|---|---|
| 1KiB JSON | 3.623 / 192/192 | 1.941 / 192/192 | 4.055 / 192/192 |
| 4MiB JSON | 13.533 / 192/192 | 8.547 / 192/192 | 8.746 / 192/192 |
| 1KiB text SSE | 4.013 / 192/192 | 1.739 / 192/192 | 2.675 / 192/192 |
| 4MiB text SSE | 62.479 / 192/192 | 11.979 / 192/192 | 15.803 / 192/192 |
| 1KiB tool SSE | 4.973 / 192/192 | 2.280 / 192/192 | 2.981 / 192/192 |
| 4MiB tool SSE | 67.154 / 192/192 | 12.975 / 192/192 | 14.633 / 192/192 |

Rekey大text/tool的c1 p50为57.377/60.730ms、p95为62.479/67.154ms，仍慢于同轮竞品。前批大text p95有明显轮次干扰；跨批下降包含host load差异，微测只支持扫描贡献，不能把全部差异归因于三行代码。当前text三轮p95为60.759/61.117/64.086ms，tool为62.162/68.750/71.470ms。所有轮次及p50/p99/RSS/首字节继续保留。

c4大JSON/text/tool全部192/192完成，Rekey p95分别27.012/102.899/115.993ms，成功吞吐145.75/32.32/28.03req/s。c16/c64仍受原session cap4拒绝：1KiB JSON分别38/192与44/192，4MiB工具各12/192；低成功率的延迟不用于宣布并发领先。小响应、全部协议、稳态吞吐及整体功能均未证明全面领先。

最终源码fmt、workspace all-targets/all-features check、clippy -D warnings、完整串行workspace test（1068 passed / 6 ignored）、diff与禁止secret API/CLI依赖合同通过。0.3冻结格式不变；没有推送、合并、安装或发布本批。SSH/mTLS的独立0.4存储候选与协议执行、PKI、团队、HA仍分别待验。

本批产物根：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-optimization-20261005/tranche-009-literal-prefilter`。`final-validation-summary.json`、`paired-summary.json`与所有micro raw、`production-stream-micro-summary.json`、`review/literal-prefilter-review.md`、`benchmark-production-overlay.json`、`release/verified-binaries/manifest.json`及`coordinator/measured/optimized-v5/{matrix.md,aggregate.json}`提供源码、binary、完整测试与每轮数据。

## 第五批：流式调度的配对验证与正式复测

仅把逐完整帧的显式 yield 移到每个现有 raw part 末尾，逐帧检查、释放、限额、清理及错误映射不变；16 KiB 是新增输入界限，不能解释成总 CPU 工作量或取消时限。新行为回归在首个持续 Ready 的不完整帧同步取消，通过实际 supervisor/UDS 检查不再读取、空输出、保守计费和唯一 indeterminate 审计。旧位置变异读取18次而断言要求1次，失败exit101；候选及恢复后测试通过。独立静态复审无开放P0/P1/P2，不替代人工安全审查。

同一4MiB工具fixture、固定4KiB分块、4个Tokio worker，7对交替A/B×20次sample/版本，full run+release wall p50/p95从35.087/36.508ms变为32.230/34.745ms，进程CPU从43.530/46.701ms变为35.367/37.723ms。7对CPU p95均降低（比率0.758–0.874），正文、usage7、完成终态及终端保留均符合。计时不含TLS/网关/vault/audit/RSS。独立scanner微测反而变慢，二进制和运行条件差异未能排除，不能精确分摊yield贡献，也不声称所有输入获益。

正式`optimized-v6`仍按固定竞品源码、同主机生产组件适配器、三轮平衡协议：432 cells、27,648 attempts，成功完整正文SHA256 mismatch0，全部driver/server exit0，fixture exit0、测试VM恢复exit0。

| c1，每产品192次全部完成 | Rekey p95 ms | Agent Vault p95 ms | KeyFence p95 ms |
|---|---:|---:|---:|
| 1KiB JSON | 2.799 | 1.963 | 2.855 |
| 4MiB JSON | 13.025 | 7.624 | 8.037 |
| 1KiB text SSE | 4.427 | 1.609 | 2.643 |
| 4MiB text SSE | 58.607 | 12.510 | 18.886 |
| 1KiB tool SSE | 3.940 | 1.943 | 2.863 |
| 4MiB tool SSE | 59.663 | 12.851 | 13.702 |

c4大JSON/text/tool全部192/192完成，Rekey p95为25.902/98.280/115.194ms，成功吞吐152.10/33.82/29.94req/s。c16/c64原session cap4仍拒绝：1KiB JSON43/192、47/192，4MiB工具各12/192。实际产品常量限制，并非benchmark遗漏配置；不能用少量成功请求延迟或快速拒绝宣布并发领先。全部p50/p99、首字节、每轮与RSS保留；短闭环fresh连接负载不是稳态最大吞吐。跨批时段与host load不同，只由配对微测支持本候选贡献。

最终fmt、workspace all-targets/all-features check、clippy -D warnings、完整串行workspace test（1069 passed / 0 failed / 6 ignored）、diff、禁止secret API与CLI正常依赖合同通过。0.3冻结格式不变，本地接受调度改动；未推送、合并、安装或发布。SSH/mTLS协议及前端、PKI、团队、HA和无租户的闭源1Password仍未完成或未验，整体功能和性能尚未领先。

证据根：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/competitive-optimization-20261005/tranche-012-sse-yield`，包括配对raw/summary、变异及复审、`attempt-002-full-validation/root-result-audit.json`、overlay与verified-binaries manifest、`coordinator/measured/optimized-v6/{aggregate.json,matrix.md}`和全部raw cells。早期包装脚本错误保留，未混入最终统计。
