# SDK-04 封闭多凭证原生插件

用户已授权继续本地功能。本切片把现有 GitHub 两操作插件登记推广为 Action 绑定的封闭原生插件：同一隔离 runner 与同一 artifact 形状，按协议选择凭证种类和公开请求合同。不是市场、动态库、任意 HTTP 效果或通用 Adapter 平台。

完整物理资源上限与启动全阶段父死仍按 [参考插件规格](2026-09-16-github-reference-plugin.md) 的既有边界记录，本切片不关闭 P-10。

## 登记

JSON 字段由 `github_issue_plugin` 更名为 `native_plugin`：`{path, sha256, protocol}`。path/sha256 合同不变。`protocol` 只能是：

- `github-issues-v1`：GitHub App Installation，固定 CreateIssue / CreateIssueComment，禁止 `text_stream`
- `anthropic-messages-v1`：Opaque Token，必须是已有 Anthropic 纯文本流 Action（`POST https://api.anthropic.com/v1/messages`、`x-api-key` 空前缀、显式 `text_stream`）

未知协议、字段名 `github_issue_plugin`、同时绑定错误凭证种类或错误 Action 形状一律拒绝。显式绑定失败不回退到打包 sidecar 或进程内解析。未绑定 `native_plugin` 时：macOS GitHub 仍用打包 `rekey-github-create-issue`；Linux GitHub 与 Anthropic 流式保持现有进程内合同。

SQLite 列由 `github_issue_plugin_json` 更名为 `native_plugin_json`。源码格式 13→14，拒绝旧库与备份，不迁移。

## 进程合同

Broker 仍从已验证 Action 决定 operation，构造封闭 envelope，插件只看到公开 body。GitHub envelope 不变。Anthropic envelope 为：

```json
{"operation":"create_message","body":{"messages":[{"role":"user","content":"..."}]}}
```

Agent 仍提交 `{"messages":[...]}`；Broker 包装 envelope。messages 规则与现有流式合同相同：1..128 条、仅 user/assistant、content 非空、deny unknown/duplicate fields。model、max_tokens、stream、版本头、API key 不进入子进程。stdout 必须与 Broker 规范 envelope 逐字节相同；Broker 只把已核对的 messages 交给现有流式配置。插件不能改模型、上限、headers 或 origin。

同一参考 sidecar 可实现上述全部 operation。Action 只接受其登记协议对应的 envelope；跨协议输出视为 mismatch，在 token/上游 IO 前 blocked。

macOS/Linux 隔离、限额、FD、deadline、快照与摘要核验复用现有 runner，不新增第二套沙箱。凭证、signing、exchange、sealing、revoke、审计仍在 Broker。

## 验收

- connector：Anthropic messages 规范化、空/过多/未知字段/未知角色拒绝；GitHub 既有合同保持。
- domain/Authority：协议与凭证/Action 错配拒绝；旧字段名拒绝；v13 状态与备份拒绝。
- 同一原生 artifact：GitHub 两操作既有真实 Broker 路径保持；另用 `anthropic-messages-v1` 绑定同一 artifact，经真实 Admin/Agent/确定性 TLS 流式夹具执行，首片仍须在上游结束前到达；恶意改 operation/messages 或加入 route 时零上游请求。
- 未登记的 Anthropic 流式回归保持进程内路径。
- release CLI/本地 TLS：GitHub P6 改用 `native_plugin` 字段；另覆盖 Anthropic 显式绑定成功与篡改 artifact 零上游。

不创建真实 Anthropic/GitHub 账号，不合并、不发布。

## 本机验收记录（2026-09-17）

源码 `codex/remaining-integration-20260916` worktree。`cargo test --workspace --offline -- --test-threads=1`：558 通过、0 失败、1 项既有 performance baseline 忽略（含子进程报告）。`cargo clippy --workspace --all-targets -- -D warnings` 与 `cargo fmt --all` 通过。真实 Broker：`tests/github_issue_plugin.rs` 9 项仍绿；`tests/native_plugin.rs` 用同一 `CARGO_BIN_EXE_rekey-github-create-issue` 绑定 `anthropic-messages-v1`，首片先于上游结束，恶意 stdout 为零上游。未运行 P6 进程脚本，未创建真实账号。不关闭 P-10，不是市场。证据：主仓库 `.git/codex/threads/remaining-native-plugin-20260917/`。
