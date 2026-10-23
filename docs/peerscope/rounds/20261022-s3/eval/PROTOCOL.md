# 体验对照 + Agent 可用性协议 — 20261022-s3

要回答的问题：一个用 Claude Code / Codex 的个人开发者，想让 Agent 能用自己的 API Key 但看不到 Key，用 Rekey 和同类产品分别要走几步、要懂多少概念、Agent 能不能自己用顺、写操作和出错时体验如何。

不在范围：性能、吞吐、安全攻防（沿用 2026-10-05 结果）；团队/企业部署；付费功能。

## 对象

Rekey（基线 `main@f7d857a`，0.5.0-alpha.1 未发布；另记已发布 0.4.0-alpha.1 的差异）、OneCLI、Agent Vault（Infisical）、Kontext CLI、AgentSecrets、1Password（Environments / agent 相关开发者面）。每家固定版本或 commit，写进各自 card.md。

## Persona（所有产品共用）

独立开发者，macOS，会用终端和 Claude Code，不是安全专家；手上有一个 LLM API Key 和一个 GitHub token；愿意花 15 分钟试一个新工具，超过 30 分钟或卡住两次查不到答案就放弃。

## 统一的假上游（不使用任何真实凭据）

- 假 Key：`sk-peerscope-DUMMY-0000000000000000`（及 GitHub 场景用 `ghp_peerscopeDUMMY000000000000000000000`）。这些不是真实凭据。
- 回显上游：`https://httpbin.org/anything`（备选 `https://postman-echo.com`）。它把收到的请求头原样回显，所以：
  - **注入成功** = 回显里出现了正确的认证头（产品把假 Key 注入了）；
  - **对 Agent 泄露** = Agent 拿到的响应或输出里出现了假 Key 原文。
- 产品只支持固定预设、不能指向 httpbin 时，记“不可比”并写原因，改用该产品支持的真实 host + 假 Key，以上游返回 401 作为“已注入并到达上游”的证据。

## 任务

| ID | 任务 | 成功条件（可程序校验） | 预期谁占优 |
|---|---|---|---|
| H1 | 人：从安装到第一次经产品成功代调用 | 回显里出现注入的认证头；记录命令数、需理解的新概念数、墙钟、查外部资料次数、报错 | 预期竞品占优（Rekey 概念多、需 App/签名） |
| H2 | 人：给第二个服务加 Key（GitHub token） | 同上 | 不确定 |
| A1 | Agent 只拿到接入面（MCP 配置或 CLI `--help`），自己列出能做什么 | Agent 列出的 host/操作与实际配置一致 | 不确定 |
| A2 | Agent 经产品完成一次读调用 | 回显 200 且带注入头；Agent 最终输出不含假 Key 原文 | 不确定 |
| A3 | Agent 发起一次写调用（POST） | 记录是否被审批拦截、人怎么收到审批、批准后能否完成 | 预期 Rekey 占优 |
| A4 | Agent 调用未授权的 host 或路径 | 被拒绝；报错是否说清原因和下一步，Agent 能否据此停下或请求权限 | 预期 Rekey 占优 |

## Agent 驱动

- 所有产品用同一个驱动：`command claude -p --model sonnet --strict-mcp-config --mcp-config <该产品的 MCP 配置或空配置> --output-format json`，在该产品专属的临时目录里运行。不带 `--dangerously-skip-permissions`；用 `--allowedTools` 只放行该产品需要的工具（如 `Bash(onecli *)`、`mcp__<server>__*`、`Bash(curl *)`）。
- 每个 A 任务 K=3 次独立运行，pilot 样本，只报 pass@1 与 pass^3，不外推。
- 原始结果：`eval/agent/raw/<product>/<task>-k<i>.json`，字段 `{product, surface, task, k_index, success, turns, wall_ms, leaked_key, recovered_from_error, trace}`。

## 隔离与安全

- 绝不触碰用户已有的 `~/.rekey`、`/Applications` 里的 App、`~/.claude*`、`~/.codex`、`~/.config` 下已有配置、钥匙串与 1Password 账户。Rekey 用 `--state-dir` 指到临时目录、独立 socket 与端口。
- 竞品只从官方渠道安装（官方 npm/brew/Docker 镜像，或固定 commit 源码构建），装到临时目录或容器里；不运行来源不明的 `curl | sh`。需要注册云账号、付费或登录的步骤不做，记“需账号，未实测”，并从官方文档统计步骤数（E2）。
- 只使用上面的假 Key。

## 概念计数口径（20261022 审查后补）

只计主路径上必须理解的名词；隔离测试带来的不计（如 state-dir、手写端口配置）；只是显示项的不计（警告、等级标签）；审批相关名词各家都不计（只有部分产品默认开审批）；可选项不计。

## 判定

每个任务每家：完成 / 部分 / 未完成 / 不可比，附 trace 路径。产品间按任务给 优势 / 持平 / 缺口（Rekey vs 该竞品）。AI 对“顺不顺”的主观评价标“AI 暂评”。
