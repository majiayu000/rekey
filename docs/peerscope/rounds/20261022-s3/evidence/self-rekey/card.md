# 自评卡：Rekey（我方）— lane self-rekey

> 视角：第一次用的个人开发者（PROTOCOL.md Persona），只按 README 与 `docs/user-guide.md` 走 CLI 基础模式；不运行 `rekey setup` / `--app`，不碰用户的 `~/.rekey`、运行中的 daemon（`127.0.0.1:7787`）、`/Applications` 里的 App。
> 核查日期：2026-10-22。基线 `main@f7d857afd0aa04605a15dfb8c6cf716a1f46eccb`（0.5.0-alpha.1，未发布）。二进制从该 commit 构建（`CARGO_TARGET_DIR` 放在临时目录），`rekey --version` = `0.5.0-alpha.1`。临时 state-dir：`/private/tmp/claude-502/rekey-s3.YkRort/state`，HTTP 端口 17797。
> 证据等级：E5 = 本轮实测且可复现（trace）；E4 = 本轮实测，单次；E3 = 固定 commit 源码；E2 = 官方文档；E0 = 推断。“AI 暂评”是 AI 的主观判断。
> 源码链接前缀 `SRC` = `https://github.com/majiayu000/rekey/blob/f7d857afd0aa04605a15dfb8c6cf716a1f46eccb/`
> Trace：`trace.jsonl`（同目录，49 行，`{step, action, command, observation, exit, wall_ms}`）；MCP 探针：`mcp-probe-*.jsonl`；Agent 原始记录：`eval/agent/raw/rekey/`。测试保险库恢复密钥已脱敏。

## 0 基本信息

| 项 | 内容 |
|---|---|
| 版本 | 源码 0.5.0-alpha.1（vault27 / policy8）；最新公开发布 0.4.0-alpha.1（vault26 / policy7） |
| 接入面 | CLI（`rekey --help` 列 **40** 个顶层子命令，不含 help）、MCP（`rekey-mcp`：9 个通用工具 + 每个命名操作 1 个工具）、本机 HTTP、SSH agent |
| 本次走的路径 | CLI 基础模式：`init` → `serve` → `unlock` → `add --stdin-secrets` → `http` / `call`；Agent 面用 `rekey-mcp` |
| 假凭据 | `sk-peerscope-DUMMY-…`（generic-bearer → httpbin）、`ghp_peerscopeDUMMY…`（github-pat） |

## 1 结论先行

- **H1（generic-bearer → httpbin）：未完成。** 按文档走到 `rekey add` 成功后，第一次读调用就要审批（generic 预设读也是 approve，与 README“默认读允许”不符）；临时目录没有 App，CLI 审批入口 `approval review` 因格式校验报错，走不通。改用专家路径（手工 draft/签名/激活策略）放行读之后，httpbin 又因本机 Clash fake-ip DNS（198.18/15）被 Rekey 当作非公网地址拒绝，报错只说“upstream request failed”。[E4/E3]
- **H1'/H2（github-pat → api.github.com）：完成。** `rekey add github-pat` 一步成功；`rekey http github GET /user` 返回 GitHub 的 `401 Bad credentials`（不带认证时是 `Requires authentication`），说明假 Key 已注入并到达上游；本机 HTTP `/c/github/user` 结果相同。[E4]
- **A1–A4：LLM 驱动没跑成**（嵌套 `claude -p` 未登录，属于驱动环境问题，不是产品问题）。改用脚本直接调 `rekey-mcp` 的 JSON-RPC，检查 Agent 能看到的工具和返回：A1 / A2 / A4 符合预期；A3 写操作会正确进入审批，但 `next` 让 Agent 用错 ID，人在没有 App 时也批不了。[E4]
- 墙钟（AI 操作，不含阅读和首次构建）：从 `init`（20:53:04）到第一次注入成功（21:00:15）约 **7 分 11 秒**；外加源码构建 4 分 46 秒 + 签名器构建 2 分 38 秒。真人做会明显更久（E0）。

## 2 H1：从零到第一次代调用

### 2.1 实际执行的命令（按顺序）

| # | 命令 | 结果 | 文档里有没有 |
|---|---|---|---|
| 1 | `rekey --version`、`rekey --help` | 0.5.0-alpha.1；40 个子命令 | 有（user-guide L14-17） |
| 2 | `rekey --state-dir S init --mode personal --password-stdin` | 成功，打印恢复密钥 | 有（L36）；`--mode personal/team` 是“不可变签名模式”，文档没解释怎么选 |
| 3 | `rekey --state-dir S serve`（第二个终端） | **4 秒内退出**：`{"event":"rekeyd.command_failed","code":5,"message":"ipc unavailable"}` | 有 |
| 4 | 手写 `S/service.json` = `{"port":17797}` | — | **没有**。文档只说“实际端口见 service.json”，没说怎么改；端口被用户已在跑的 daemon 占用（`lsof` 证实 7787 由 rekeyd 11133 监听），报错没提端口 [E3 `SRC/crates/rekey-broker/src/bin/rekeyd.rs#L401-L410`] |
| 5 | `serve` 再次启动 | 成功；admin/agent socket 都在 `S/runtime/` 下 | — |
| 6 | `rekey --state-dir S unlock --password-stdin` | 成功 | 有（L43） |
| 7 | `rekey --state-dir S add generic-bearer --origin https://httpbin.org --name httpbin --stdin-secrets` | `SIGNER_UNAVAILABLE: cannot run rekey-policy-sign: No such file or directory` | 文档没提；从源码构建 `-p rekey-cli -p rekey-broker` 不会产出签名器，需另外构建 `-p rekey-policy`（安装包内自带）[E3 `SRC/crates/rekey-cli/src/commands/add.rs#L416-L425`] |
| 8 | 同上（补上签名器后） | 成功：`Installed basic-mode policy trust: software P-256 key …`；`Connection httpbin is active (policy v1, valid 90 days)` | 有 |
| 9 | `rekey http httpbin GET /anything --dry-run` | `effect: approve` | 有 |
| 10 | `rekey http httpbin GET /anything --no-wait` | `APPROVAL_REQUIRED`，`next: Call await_approval(request_id)…` | 文档写“读允许”，实际 generic 预设读写都是 approve [E3 `SRC/crates/rekey-policy/src/presets.rs#L752-L765`] |
| 11 | `rekey approval pending` | 列出 challenge（无 review_sha256） | 文档未提 CLI 审批 |
| 12 | `rekey approval review <challenge_id>` | `INVALID_FRAME: broker returned invalid local approval review` | — |
| 13 | `rekey approval review <request_id>` | `REQUEST_DENIED: approval-request-unknown` | — |
| — | **卡死点 1**：`approval approve` 必须带 `--review-sha256`，只能从 review 拿到；临时目录也没有 App 可以审批 | | |
| X1-X2 | 专家绕行：`connection list` → 改 read=allow → `policy draft --connections-stdin` → `rekey-policy-sign software-key sign` → 拼 bundle → `policy activate --file … --step-up-stdin` | 成功（policy v2） | 文档没有；新用户做不到（AI 暂评） |
| X3 | `rekey http httpbin GET /anything` | 10.2 秒后返回 `UPSTREAM_ERROR "upstream request failed"` | — |
| — | **卡死点 2**：`dig httpbin.org` → `198.18.27.233`（本机 Clash fake-ip），Rekey 拒绝 198.18/15 [E3 `SRC/crates/rekey-domain/src/action.rs#L757`、`SRC/crates/rekey-broker/src/upstream.rs#L628`]；内部原因是 `Blocked("private-address")`，对外只显示通用错误 | | |
| 14 | `rekey --state-dir S add github-pat --name github --stdin-secrets` | 成功，policy v3，并列出 6 个可调用操作 | 有 |
| 15 | `rekey --state-dir S http github GET /user` | `status 401 "Bad credentials"` + `UPSTREAM_ERROR … inspect the sealed response` → **注入成功** | 有 |

**命令数：** 只算成功路径（init、serve、写 service.json、serve、unlock、add github-pat、http）是 **7** 条，并且要开 **2 个终端**；把 H1 尝试、失败和查 help 都算上，是 **15 条主命令 + 9 次 `--help` + 6 条专家绕行命令**。
**新概念（16 个）：** 保险库 vault、state-dir、恢复密钥、签名模式 personal/team（不可变）、daemon serve 与锁定/解锁、service.json 端口、预设 preset、Connection、origin、credential 与 Connection 的区别、签名策略（版本、90 天有效期）、信任根 / 基础模式（软件 P-256 还是 Secure Enclave）、规则效果 allow/approve/deny、审批（challenge_id 和 request_id 两个 ID、presence 证明、review 摘要）、L1-dev 警告、T0/T1 等级。
**查资料：** README 1 次，user-guide 1 次，CLI `--help` 9 次，读源码 5 处（端口、签名器、审批、IP 过滤、预设）。普通用户没法靠读源码解决，按 Persona 的规则会在“卡住两次”时放弃（AI 暂评）。
**报错原文和能否据此操作：**

| 报错 | 能否据此操作 |
|---|---|
| `ipc unavailable`（serve 端口冲突） | 否：没提端口和 service.json |
| `SIGNER_UNAVAILABLE: cannot run rekey-policy-sign: No such file or directory` | 部分：说了缺哪个文件，没说怎么装（只影响源码用户） |
| `APPROVAL_REQUIRED … next: Call await_approval(request_id)` | 否：没有 App 时，CLI 审批走不通 |
| `INVALID_FRAME: broker returned invalid local approval review` | 否：CLI 和 daemon 的 record_type 对不上（见第 5 节） |
| `UPSTREAM_ERROR: upstream request failed`（非公网 IP） | 否：没说是 DNS 解析到私网地址被拒 |
| `UPSTREAM_ERROR: upstream returned a non-success status; inspect the sealed response` | 是 |

### 2.2 文档说的步骤和实际要走的步骤

| 文档 | 实际 |
|---|---|
| README 主线 `rekey setup` → `rekey add glm`（setup 打开 App 建库） | 不用 App 时，要换成 `init` + `serve`（单独一个终端，前台运行）+ `unlock`，README 没写这条路线 |
| user-guide L40“在另一个终端解锁…并在 App 中选择该目录完成凭据与规则签署” | 0.5 的 `rekey add` 不需要 App 就能签署，这句已过时；但**审批**仍只能在 App 里做 |
| 默认端口 7787，“实际端口见 service.json” | 已经有一个 daemon 在跑时，第二个保险库必须手写 service.json；文档没写怎么写 |
| README L23 / user-guide L25“读允许、写审批” | 只有部分预设如此（github-pat 读 allow）；generic-bearer / generic-header 读也要审批 |
| 文档没提签名器 | 源码用户要额外构建 `rekey-policy`，二进制需和 `rekey` 放在一起或在 PATH 里 |
| 文档没提 | 网络里有 fake-ip / TUN 代理时，所有走代理的域名都会被拒，只有直连域名可用 |

## 3 H2：第二个 Key（github-pat）

完成 [E4]。1 条命令（`add github-pat --stdin-secrets`），2.45 秒；输出列出 `github.get_issue … github.graphql` 共 6 个操作。之后 `http github GET /user` 和 `call github.list_issues` 都返回 401 Bad credentials。其中 `list_issues` 第一次 9.9 秒超时（`upstream request failed`），重试成功，原因未查（E0：可能是网络抖动）。本机 HTTP `curl -H 'Authorization: Bearer rekey' http://127.0.0.1:17797/c/github/user` 同样返回 401。

## 4 A1–A4（Agent 面）

**驱动情况：** 按协议用 `command claude -p --model sonnet --strict-mcp-config --mcp-config <tmp>/mcp.json --output-format json --allowedTools 'mcp__rekey__*'` 驱动。第一次把 prompt 放在参数里，被可变长的 `--allowedTools` 吞掉了；改成 stdin 输入后报 `Failed to authenticate: OAuth session expired and could not be refreshed`（`claude auth status` → `loggedIn:false`）。**LLM 的 K=3 没有执行，pass@1 / pass^3 = 不可得**。记录见 `raw/rekey/A1-k1.json`（标了 excluded）。
**替代方案：** 用同一份隔离 MCP 配置，脚本化调用 `rekey-mcp` 的 JSON-RPC，相当于“完全照 `next` 做的 Agent”。这只证明工具面行为，不代表 LLM 的成功率。

MCP 配置片段（来自 `rekey connect claude-code --print`，只改成了二进制绝对路径，没写进任何项目或用户配置）：`{"mcpServers":{"rekey":{"command":"<tmp>/bin/rekey-mcp","args":["--state-dir","<tmp>/state"]}}}`。`--print` 同时预览了 `.mcp.json` 和 `CLAUDE.md` 标记段。

| 任务 | 工具层结果 | 判定 |
|---|---|---|
| A1 发现 | `tools/list`：9 个通用工具 + 6 个 `github_*` 工具；`list_capabilities` 返回的 connection、origin、operations、read/write 与实际配置一致 | 完成（工具层） |
| A2 读 | `http github GET /user` → 401 Bad credentials（证明已注入），返回里没有 Key；全部 trace 和探针文件 grep 假 Key = 0 次 | 完成（工具层）；httpbin 回显不可用（fake-ip），**无法用回显直接核验“Agent 看不到 Key”** |
| A3 写 | `github_create_issue` → `APPROVAL_REQUIRED`，`next: "Call await_approval(request_id) …"`。照着用顶层 `request_id` 调用 → `DENIED approval-request-unknown`，`next: "Use request_access…"`（会把 Agent 引到错误方向）。改用 `approval.challenge_id` → `state: pending`，可以等待、可以取消。人这边：临时目录没有 App；CLI `approval review` → `INVALID_FRAME`，`approve` 拿不到 review 摘要 → **无法批准**。另外，从另一个 MCP 进程调用 `await_approval` 时同一 ID 也是 unknown（审批按会话绑定） | 部分（拦截正确，但没法完成） |
| A4 越权 | 未配置的连接 → `NOT_CONFIGURED`，`next: Use request_access with a reason; never ask the user for a key.`；`DELETE /repos/x/y` → `DENIED connection rule denied this request`；`..` 路径 → `INVALID_INPUT`；`request_access(provider=openai)` → 返回 request_id 和 `user_hint: Rekey App shows this request in its inbox…` | 完成：拒绝且说明了下一步；但下一步仍要靠 App |

## 5 已知摩擦点验证

| 摩擦点 | 结果 | 证据 |
|---|---|---|
| describe 是否显示允许的模型和规则 | **不显示。** MCP `describe github.create_issue` 只返回参数 schema，没有 effect、rule 和模型，但工具描述写着“parameters and applicable rules” | E4 `mcp-probe-A2A3-separate-process.jsonl`；E3 `SRC/crates/rekey-broker/src/bin/rekey-mcp.rs#L64`。`list_capabilities` 只有连接级的 read/write |
| `rekey --help` 命令数 | 40 个顶层子命令（另有 help），其中 desktop-* 5 个、T1 3 个、PKI 相关混在 `credential` 下 | E4 trace H1-02 |
| 默认 90 天过期有没有提醒 | 只在 `add` 时打印 `valid 90 days`；`list --json` 不显示过期时间，`connection list` / `policy status` 只给 `expires_at_ms` 原始毫秒；CLI 源码里没有临期提醒，过期后调用被拒，报 `policy-expired` | E4 trace H1-13/M1；E3 `SRC/crates/rekey-broker/src/executor/local.rs#L62` |
| 首次 add 安装不可逆信任根时有没有提示 | **没有确认。** 只在事后打印一行 `Installed basic-mode policy trust: software P-256 key … (mode 0600, not Secure Enclave).`，没说以后不能再换成 App 的 Secure Enclave（README L21 写了“之后不能互换”）。而且 `policy status` 对这把软件 key 显示 `"algorithm": "secure-enclave-p256"`，容易误导 | E4 trace H1-13、M1；E3 `SRC/crates/rekey-cli/src/commands/add.rs#L138-L150`、`SRC/crates/rekey-policy/src/bin/policy_sign/software.rs#L76` |
| CLI 本地审批 | `approval review` 不能用：daemon 写的 review 体 `record_type` = `rekey.approval.local-review.v1`，CLI 要求 `rekey.approval.review.v1` → 一律 INVALID_FRAME | E4 trace H1-19、A3-cli-review；E3 `SRC/crates/rekey-broker/src/executor/local.rs#L189` 对 `SRC/crates/rekey-cli/src/commands/policy_approval.rs#L344` |
| 审批 `next` 的 ID | `next` 写“await_approval(request_id)”，但顶层 `request_id` 不是审批 ID，要用 `approval.challenge_id`；SKILL.md 用的也是同样有歧义的说法 | E4 `mcp-probe-A3-single-session.jsonl`；E3 `SRC/crates/rekey-domain/src/ipc.rs#L456`、`SRC/plugins/rekey/skills/rekey/SKILL.md#L18` |
| 每条 CLI 输出都带 L1-dev 警告 | 管理命令每次都把这行中文警告打到 stderr | E3 `SRC/crates/rekey-cli/src/client.rs#L80` |

## 6 0.4.0-alpha.1（公开版）和 0.5 源码在上手上的差别

| 项 | 0.4.0-alpha.1（tag） | 0.5 main@f7d857a |
|---|---|---|
| `rekey add` | **打开 macOS App**；“`setup` 和 `add` 打开 macOS App，密码、密钥和规则审阅在管理界面完成”（0.4 README） | CLI 一步完成（基础模式，软件 P-256 签名）；`--app` 改回走 App（PR #85） |
| 不用 App 能否完成 H1 | 不能：签署 Connection 必须用 App（E2 0.4 README / user-guide） | 签署可以；**读审批（generic 预设）和所有写审批仍需 App** |
| CLI 本地审批 | 0.4 已有 `approval review/approve` 子命令（E3 tag 下 `crates/rekey-cli/src/main.rs` L956-960）；本轮没测 0.4 二进制 | 有，但 review 报错，实际不可用（E4） |
| 格式 | vault26 / policy7 | vault27 / policy8，需要新建保险库 |

所以“一步式 add”只在未发布的 0.5 源码里有。公开版用户的上手路径仍然是 App 主导（E2/E3）。

## 7 最痛的 3 个卡点（AI 暂评排序）

1. **没有 App 就批不了。** generic 预设读也要审批，CLI `approval review` 又报 `INVALID_FRAME: broker returned invalid local approval review`，于是 H1 和 A3 都卡死。
2. **报错不说原因。** fake-ip / 代理环境下只看到 `UPSTREAM_ERROR "upstream request failed"`（约 10 秒后），看不出是 `private-address` 被拒；端口冲突也只报 `ipc unavailable`。
3. **审批 ID 有歧义。** `next: "Call await_approval(request_id)"` → 用顶层 request_id 得到 `approval-request-unknown`，`next` 又改成 `Use request_access`，严格照提示做的 Agent 会走错。

## 8 未完成和限制

- LLM 驱动的 A1–A4 K=3 没跑（嵌套 Claude CLI 未登录）；pass@1 / pass^3 不可得。
- httpbin 回显不可用（本机 DNS 环境），所以“注入成功”是靠 GitHub 401 文案差异推断的，没有直接看到请求头；“对 Agent 泄露”只确认了返回里没有 Key，没做回显反射测试。
- 没测 LLM 预设（模型白名单、预算）和 `rekey unlock --remember`；没测 0.4 二进制。
- 安装版 App 的审批体验不在本 lane 范围。

## 9 清理

- 自己起的 rekeyd 已用 `rekey --state-dir S shutdown --password-stdin` 停掉（`{"shutdown": true}`），`pgrep` 确认没有残留；用户的 rekeyd（pid 11133，7787）没动过。
- 临时目录 `/private/tmp/claude-502/rekey-s3.YkRort`（含测试保险库、构建产物、测试密码文件）保留在本机，未删除。
