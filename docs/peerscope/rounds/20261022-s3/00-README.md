# Rekey 同类产品复评：用户好不好用（2026-10-22）

## 结论

**直接回答：现在还算不上好用。** 默认安全做得比实测的竞品好；但不用 App 时连审批都走不完，步骤和报错也比竞品更难懂。装了 App 的主路径，本轮没测。

- **默认就能拦住的，在实测的三家里只有 Rekey；但它不用 App 的路径还走不通。** OneCLI、Agent Vault 默认会放行写操作和未授权的 host，回显时还会把 Key 交到 Agent 手里，这些都实际跑过。Rekey 能拦下，但没有 App 时，因为一个格式 bug 批不了。从源码看，AgentSecrets 的默认拒绝和脱敏与 Rekey 同级，只是要注册云账号，而且写审批默认不开。
- **上手门槛：概念量持平，步骤偏多。** 按统一口径数概念：Rekey 11 个，竞品 10–12 个。实测的是 Rekey 不用 App 的 CLI 路径，README 主推的 App 路径没测。
- **最该先补的是“Agent 和人能顺利用起来”**：修 CLI 审批 bug（同时堵住 `--remember` 文件可能被用来自己批准的口子）、describe 显示规则、报错说清根因、统一审批 ID。前 5 项见 [02](02-my-plan.md)，全量见 [03](03-catchup-ledger.md)。
- **差异点与对手。** 竞品被抱怨最多的是要装 CA（19 人）和装不起来（15 人），Rekey 在架构上避开了这两类；但显式调用也有代价，“不走 MITM”也不是 Rekey 独有（反向检索查了 AgentSecrets 源码、KeyValet 和 sallyport 的 README）。最像 Rekey、上轮漏掉的是 sallyport（189★，Mac App + MCP，默认按进程审批，自称两分钟上手，但约 3 个月没更新），下一轮先确认它还活着再补测。详见 [01](01-competitor-research.md)，其中反向检索见 §9。

## 覆盖率与没做到

候选约 50 个，深挖 6 个，实测 3 个（Rekey、OneCLI、Agent Vault）。Agent 任务原始记录 43 份，其中 35 份是实际运行。用户声音：HN 341 条评论，GitHub issues 223 条。

没做到：
- 统一的 `claude -p` 驱动因为登录过期没跑成，所以只比较产品行为，不比较 Agent 完成率。
- Rekey 的 App 主路径、回显封口的当前版本复测、`--remember` 自批准实测，都没做。
- AgentSecrets、Kontext 云端和 1Password 都要账号，没有实测；sallyport 只读了 README 和审批文档，没有实测。
- Reddit 访问被拦截。

这份报告经过独立审查，审查意见和处理结果在 [reviews/](reviews/)。

## 文件

- 竞品调研：[01-competitor-research.md](01-competitor-research.md)
- 我方计划：[02-my-plan.md](02-my-plan.md)
- 追赶台账：[03-catchup-ledger.md](03-catchup-ledger.md)
- 体验对照协议：[eval/PROTOCOL.md](eval/PROTOCOL.md)
- 各竞品卡片和命令记录：[evidence/](evidence/)
