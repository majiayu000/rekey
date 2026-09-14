# Rekey onboarding 验收记录 · 2026-09-10

四步 CLI 流程已完成核对、修复和验收。后续对齐发现另一会话已完成 GitHub App 单仓库读、轮换及写入验收，见 `docs/evidence/github-app-rotation-write-2026-09-10.json`。GHA-11 仍缺两仓库真实 webhook 增删验收。主仓库未提交、未推送。当前任务进度以 `outputs/rekey-inventory-20260910/Rekey功能清单与Agent任务优先级.xlsx` 为准。

| 顺序 | 结果 | 证据 |
| --- | --- | --- |
| 1. prepare | 真实隐藏 TTY 录入、独立 step-up、已有 Action/schema、0700/0600 交接和拒绝覆盖现有策略均通过 | `quickstart-final.log` |
| 2. 审阅、外部签名、安装和激活 | 真实 broker 默认拒绝、独立 test signer、trust install/activate 及激活后 schema 拒绝均通过 | `quickstart-final.log` |
| 3. execute | 修复非 UTF-8/CRLF 响应被解码或改写的问题；保持 bytes、capability 仅 stdin、HTTP 错误非零、不自动重试 | `review.md`、`binary-red.log`、`quickstart-final.log` |
| 4. 操作员修复 | 真实公网 401 → 隐藏终端 rotate → 操作员明确重试 200；输出不含测试秘密 | `public-evidence/agent-public-repair-receipt.json` |

## 公网 Vault Layer B

专用 GitHub-hosted Linux runner 上创建真实 HashiCorp Vault 1.20.3、PostgreSQL 16 和 Cloudflare Quick Tunnel，使用未放宽网络筛选或 TLS 验证的 rekey/rekeyd 2.0.0-alpha.2。接收端以随机 KV token 比较和真实 PostgreSQL 登录校验凭证。

- KV：固定 secret/agents/test 第 1 版、key=token，返回 HTTP 200。见 `public-evidence/vault-kv-receipt.json`。
- Dynamic：database/agent-test、key=password，真实数据库登录返回 HTTP 200；审计要求 started → issued → revoked → finished，全程唯一且成功；随后确认数据库角色已删除。见 `public-evidence/vault-dynamic-receipt.json` 和 `public-pass-summary.log`。
- 完整工作流（包括凭证修复和清理）成功，不能仅凭中途产生的单个 receipt 宣称通过。
- 只覆盖这个专用公网源与固定 Action，不代表任意 Vault 引擎、生产部署或真实 GitHub App 已验收，也不宣称独立 Codex CLI 模型会话的自主调用已完成。

运行：https://github.com/majiayu000/rekey-acceptance-20260910-ephemeral/actions/runs/34447873706

临时验收仓库提交：`ed308529e655932c36716d66fc49b5cba1ef35e4`。完整状态见 `public-run.json`；测试夹具与工作流保存在 `fixture/`。生产源码来自 `cffaa23df89ffd1dd2ff80ac9e8599c184349489` 加当前 onboarding 脚本；runner 侧仅增加安全错误码诊断。当前源码文件散列见 `local-evidence.json`。

## 网络与清理

新 Quick Tunnel 域名的 A/AAAA 发布不同步。最终等待公共 DNS 的真实 A 记录后，仅在临时 runner 内映射该域名，结束时删除该条；公共 DNS 响应见 `public-evidence/dns-evidence.json`。本机 `/etc/hosts` 和代理未修改。

本机五次准备尝试的容器、网络、隧道及 13 个匿名卷已清理，见 `local-cleanup.json`。成功 runner 也已停止隧道并清理容器、匿名卷、网络和临时秘密，清理检查成功。

## 下一项：GitHub App

专用私有仓库 `majiayu000/rekey-acceptance-20260910-ephemeral` 暂时保留，供剩余 GitHub App 验收。重新核实时旧注册标签页已关闭，新的 `https://github.com/settings/apps/new` 可访问；不再把历史 Confirm access 页面视作当前阻塞。另一会话使用的 App 已按回执删除，剩余两仓库验收需要新的专用 App。

本地注册回调页为 `http://127.0.0.1:5582/`。准备脚本位于 `/tmp/rekey-onboarding-20260910/github-setup.py`，验收脚本为同目录 `github-acceptance.py`。结束后删除 App/installation、该私有仓库及私密材料。相同 key 的 profile rotation 不代表新 provider key rotation；真实 webhook delivery 尚未验证。

## threads_run_log

使用 `/Users/lifcc/.agents/skills/threads/SKILL.md`。1 个原生只读 thread `/root/onboarding_review`，完成三次有界审查；主线程独占编辑、资源创建和验证。无合并操作。实际原生 thread 证据保存在 `threads-run-log.json`。已尝试技能要求的 `append_run_log.py`，但安装版本的 schema 只接受旧的 `multi_agent_v1.spawn_agent`，拒绝当前实际使用的 `collaboration.spawn_agent`；因此保留真实 JSON 记录，未伪造工具名或修改技能。

参考：[Cloudflare Quick Tunnel](https://developers.cloudflare.com/tunnel/setup/)、[Vault PostgreSQL API](https://developer.hashicorp.com/vault/api-docs/secret/databases/postgresql)、[Vault lease revoke](https://developer.hashicorp.com/vault/api-docs/system/leases)、[GitHub App manifest](https://docs.github.com/en/apps/sharing-github-apps/registering-a-github-app-from-a-manifest)。
