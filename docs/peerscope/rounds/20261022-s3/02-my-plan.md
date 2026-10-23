# Rekey 要做的：把“拦得住”做成“用得顺”（2026-10-22）

本文件服务一个决定：**0.5 发布前，先补哪几处易用性缺口？**

判断标准：一个全新的 macOS 个人开发者，按 README 首屏操作，能否在 15 分钟内让 Claude Code 完成一次读调用、一次被批准的写调用，并且全程不碰源码和 `service.json`。

放弃条件：补完 P0 和 P1 后，如果新用户按统一口径（[协议](eval/PROTOCOL.md)）仍要理解 10 个以上的概念，或者 CLI 基础模式还是走不完审批，就把基础模式降为高级选项，README 只保留 App 路径。

竞品和证据见 [01](01-competitor-research.md)，完整台账见 [03](03-catchup-ledger.md)。

## 前 5 项

### 1. 修 CLI 审批，同时定好基础模式下“谁能批准”（P0，bug + 安全）

现在的问题有两层：
- `approval review` 解析 daemon 返回的记录时，类型校验写错了，没有 App 时必然报 `INVALID_FRAME`。CLI 的测试夹具用的也是错的类型，所以测试一直没发现。
- 修好以后，CLI 批准需要的 presence 证明，现成来源只有 `rekey unlock --remember` 写下的 0600 文件。同用户的 Agent 很可能读这个文件就能批准自己的写调用（源码推断，未实测）。

要做的：
- 修校验，同时修 CLI 的测试夹具，再加一条契约测试：直接用 daemon 的真实输出喂给 CLI 解析器。
- 先决定基础模式的批准方式，二选一：
  - **A**：新增“密码 step-up 批准”，presence 文件不能用于批准；
  - **B**：沿用 presence，但在文档里明确写出“开了 `--remember` 后，同用户进程可以自批准”。
  - 我倾向 A。
- 修完做一次绕过实测：读 `remembered-unlock.key`、直连 `admin.sock`、换 state-dir 和环境变量。

验收：在隔离 state-dir、不运行 App 的条件下，A3 写调用能被你批准并完成；同一用户下的另一个进程不能只凭本地文件完成批准。

### 2. 让 Agent 一次就调对（P0）

- `describe` 返回允许的模型、预算、路径模板和过期时间。
- 上游被拒时，把根因翻译成用户看得懂的话，例如“解析到非公网地址 198.18.x，可能是本机代理的 fake-ip”。
- `next` 里的审批 ID 改用 `challenge_id`，或者让 `await_approval` 两种 ID 都接受。
- 给 MCP 和 skill 文档加契约测试，保证写到的命令和工具真实存在。竞品在这里栽过：Agent Vault 的 skill 写了不存在的命令（#449）；用户声音里“Agent 不会用”有 10 人。

验收：修好 `claude -p` 驱动后，A1–A4 各跑 4 次，全部成功，并且不出现 `approval-request-unknown`。

### 3. 精简首次使用（P1）

- 首次 `add` 前用一句话确认信任根：“选软件签名后，以后不能换成 Secure Enclave”。
- `policy status` 改正算法显示：现在把软件 key 显示成了 `secure-enclave-p256`。
- `--help` 默认隐藏 `desktop-*` 和 T1、PKI 类命令。
- L1-dev 警告每个会话只提示一次。
- 端口冲突时直接提示改用哪个端口。

验收：用 App 路径和 CLI 路径各重做一次 H1，按统一口径计数，概念不超过 10 个，并且不需要绕行命令。

### 4. 文档和默认行为对齐（P1）

- README 写“默认读允许”，但 generic 预设读也要审批：二选一，要么把 generic 的读改成允许，要么在文档里写明。
- user-guide 的标题和“在 App 中签署”已经过时，要更新。
- 写清 0.4 和 0.5 的 `add` 区别。
- 规则 90 天过期：临期 7 天时，CLI、MCP 的 `next` 和 App 角标都要提醒。

### 5. 把差异讲清楚（P1，市场）

README 首屏用一句话说清：

> 不装 CA、不走代理、单个本机进程；写操作默认要你批准；上游回显的 Key 会被封口。

封口这一句要等 P0 之后用当前版本复测回显，测完再写；此前只有 0.3.0-alpha.2 修复源码的本机 fixture 证据。

旁边配一张实测对照表（01 §5）。不要写成“独有”：AgentSecrets、sallyport 也走显式调用。

## 不做或暂缓（建议，由你决定）

- **透明 HTTPS_PROXY 模式**：Agent Vault 靠它做到“零改动接入”，脚本化跑通只要 26 秒；也有 4 位用户称赞这种方式透明。但它会带来 CA 问题，而 CA 问题正是被抱怨最多的一类（19 人）。建议不做，继续用本机 HTTP base URL 和 MCP。
- **团队、云同步**：OneCLI、AgentSecrets 在往这个方向走，与 Rekey 个人优先的定位冲突，建议暂缓。

## 下一轮复评

1. 补测 sallyport：先确认项目还在维护（最近推送 2026-07-19）；它同样是 Mac + MCP，默认按进程审批。按同一协议跑 H1 和 A1–A4。它可能上手更快，但回显不封口。
2. 修好 `claude -p` 登录后，用统一驱动重跑 A1–A4，每个任务 4 次，各家都一样。
3. 测 Rekey 的 App 主路径 H1，并用当前版本复测回显封口。
4. 补测 varlock、KeyValet。
