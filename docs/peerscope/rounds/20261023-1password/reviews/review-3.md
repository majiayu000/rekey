# 第 3 次审查（终审）

审查对象：`report.md`（按 review-2 处置后），以及 `evidence/reception/notes.md` 页首。只核对 review-2“处置（作者）”中的 1 条必须改和 4 条建议改，并把新写入的 OpenShell 内容回到一手来源核实。
核对方式：2026-10-23 匿名 curl（UA `peerscope-review/0.1`），未登录任何账户。读取了以下页面（均 HTTP 200）：
- NVIDIA OpenShell latest（v0.1.5）：`how-it-works/providers/profiles.md`、`llms.txt`、`how-it-works/policies/advisor.md`、`observability/logging.md`、`observability/ocsf-json-export.md`、`observability/accessing-logs.md`、`extensibility/gateway-interceptors.md`
- 1Password：`1password.dev/environments/nvidia-openshell.md`

脚本：`check_report.py report.md` 输出“没有发现问题”，exit 0。

## 总评

**可以交付。** review-2 的 1 条必须改和 4 条建议改都已落实。新写的 OpenShell 内容与 NVIDIA 和 1Password 的一手文档一致，判定措辞也都和证据强度匹配。§1、§3、§6、§7 口径一致，没有残留“规则粒度更细”这类旧说法。下面 4 条是措辞精度方面的建议，不影响结论。

## 上轮处置逐条核对

### 必须改 1：OpenShell 能力被低估

**已落实。**

| 位置 | 现在的写法 | 核对 |
|---|---|---|
| §1 第 2 条（:12） | 1Password 界面只设 host/端口/写/有效期，连接时授权一次；OpenShell 本身支持按二进制、host/端口/路径绑定、L7 方法/路径放行、OCSF 审计、Policy Advisor；没有单次调用人工批准；有效期内交由网关保管；Agent 必须在沙箱里 | 成立。profiles.md:76-84 列出四类检查（调用二进制与目的地；host、端口和规范路径绑定；配置 L7 时的方法/路径；未过期）；:510 写明 `binaries`。advisor.md 写明 proposal 是“network rule scoped to the host, port, and binary … method and path”。nvidia-openshell.md:31 原文是“transfers custody … for a defined time-to-live (TTL)”，:107 有 `--from <docker-image…>` |
| §2.4（:61） | 同上，另写“（默认只读）” | 成立。nvidia-openshell.md:74：“If you leave it unselected, the provider allows read-only access” |
| §3 规则粒度（:80） | host/端口/路径、按二进制、L7 方法/路径（需另配 profile 或 sandbox policy） | 成立。nvidia-openshell.md:69-71 区分 Existing profile 和 New profile |
| §3 审批（:81） | 连接时一次；规则变更经 Policy Advisor；没有单次调用人工批准 | 成立。advisor.md：“A proposal never changes the policy on its own. By default, every proposal waits for your review”，批准对象是 network rule。已读页面里没有逐请求挂起等人批准的机制 |
| §3 区分 Agent（:82） | 按沙箱挂载 provider、按调用二进制匹配（文档，未实测），可能比 Rekey 强 | 成立，措辞留有余地 |
| §3 审计（:84） | OCSF 结构化事件，可导出 JSON 接入 SIEM；`openshell term` 实时观察 | 成立。logging.md:38（OCSF v1.8.0）、ocsf-json-export.md:21、nvidia-openshell.md:136（`openshell term`）。不过有一个限定没写，见建议 2 |
| §3 依赖（:85） | 账户类型未明确、Mac/Linux、运行中的网关、沙箱镜像 | 成立。nvidia-openshell.md:24-26 |
| §3 判定（:91-95） | 规则粒度持平；写操作逐次审批只有 Rekey 有（“已读文档未描述，未实测”）；审计两边都有；区分 Agent 是 OpenShell 文档上更强（未实测） | 措辞与证据匹配。“已读的官方文档里没有描述”把范围限定在已读文档，没有说成“OpenShell 没有” |
| §6.2（:114） | 不再把规则粒度当差异点 | 成立，但“第三方网关”不准确，见建议 1 |
| §6.5（:117） | Policy Advisor 批准的是规则变更，不是单次调用 | 成立 |
| §7（:123-124） | 第 1 条只剩“单次调用人工审批”，新增“配置界面直接暴露方法/路径规则” | 成立，与页首放弃条件（:4）一致 |

作者在处置里说，read-only 预设包含哪些方法没有核实到，所以正文不引用。正文确实没有引用，这样处理是对的。

### 建议改

| # | 结果 | 依据 |
|---|---|---|
| 1 用户声音等级 | 落实 | report:5 的定义是“多作者或多平台”。:101 写“4 位作者、2 个平台；按定义算成规模，但人数少”，:102 写“7 位作者，同一论坛，成规模”，与 reception 笔记 :6 和 :43 的 D2 一致 |
| 2 笔记不同步 | 落实 | reception 笔记页首已注明“§5 竞争格局与结论部分已被 report.md 取代”，相对链接 `../../report.md` 能正确解析到本轮的 report.md |
| 3 Bitwarden 对冲措辞 | 落实 | report:108 写的是“官方称这‘有助于确保’” |
| 4 依赖与反差 | 落实 | report:85 写了运行中的网关、沙箱镜像、账户类型未明确；§1 和 §6.2 加了“Agent 照常启动” |

## 残留检查

- 用 `rg "规则粒度|更细"` 搜 report 和 evidence，只命中 :12、:15、:80、:91、:114，全都是新口径（持平或不是差异点）。devdocs 笔记 :72 对 OpenShell 的描述（托管给 gateway、按 TTL）与正文不冲突。
- §1 第 2、4、5 条与 §3 判定、§6.2、§7 一致。差异点四项（写操作逐次审批、无需沙箱和账户、密钥留在本机、审计失败即拒绝）在 §1:12、§1:15、§6.2 三处措辞一致。

## 建议改（不阻塞交付）

1. **“第三方网关”不准确。** 位置：§6.2（:114）“密钥不离开本机保险库（不交给第三方网关保管）”，§1:12 和 :15 的“密钥不离开本机”也有同样问题。
   - 问题：OpenShell 的 llms.txt 写明可以“Install OpenShell on a local workstation or Kubernetes”，网关可以是用户自己在本机跑的开源组件，不一定是“第三方”，也不一定离开本机。真正的差别是保管方式：1Password 会把密钥转交给网关，在 TTL 内由网关保管；Rekey 的密钥始终放在本机加密保险库里，每次调用时才解密一次。
   - 改法：改成“密钥始终留在本机加密保险库、按次解密，不需要在有效期内转交给另一个网关保管（OpenShell 网关可部署在本机或远程）”。

2. **OCSF 导出是 best-effort。** ocsf-json-export.md:21 原文是“Collection is best-effort, not a guarantee of complete audit history”。这恰好能衬托 Rekey 的“审计提交失败就拒绝执行”。
   - 改法：在 §3 审计格或判定（:93）补一句“（官方注明 best-effort，不保证完整）”。

3. **Policy Advisor 的两个限定没写。** advisor.md 写明它“off by default”，并且可以开启自动批准（风险检查没发现问题就自动通过）。§1:12 的“对规则变更的人工审批”不算错，但读者容易以为默认就有。
   - 改法：在 §1 或 §3 审批格补“默认关闭，可设为自动批准”。

4. **来源链接和审查计数。**
   - §1:12 和 §2.4 来源行（:67）只链接了 profiles 页，但 Policy Advisor 和 OCSF 的说法分别出自 advisor.md 和 observability 页。建议补上这两个链接。
   - §8:131 写“经过两轮独立审查”，加上本轮应改为三轮。

## 事实抽查表（本轮新增部分）

| 事实 | 位置 | 结果 | 来源（2026-10-23） |
|---|---|---|---|
| 静态凭据替换要求调用二进制、host/端口/路径、L7 方法/路径、未过期全部满足 | :12、:80 | 成立 | profiles.md:76-84 |
| profile 的 `binaries` 限定可访问端点的可执行文件 | :82 | 成立 | profiles.md:510 |
| Policy Advisor 审批的是网络规则（host/port/binary/method/path），不是单次请求 | :81、:117 | 成立 | advisor.md |
| Policy Advisor 默认关闭，可选自动批准 | 未写 | 遗漏（建议 3） | advisor.md |
| OCSF v1.8.0 结构化事件，JSON 导出面向 SIEM | :84 | 成立；best-effort 未写（建议 2） | logging.md:38；ocsf-json-export.md:19-21 |
| `openshell term` 实时观察 | :84 | 成立 | nvidia-openshell.md:136 |
| 1Password 在 TTL 内把密钥转交给 OpenShell 保管 | :12、:61 | 成立 | nvidia-openshell.md:31、:93 |
| 默认只读，勾选 Allow writes 才允许写 | :61 | 成立 | nvidia-openshell.md:74 |
| 依赖：1Password 账户、Mac/Linux App、运行中的网关、沙箱镜像 | :85 | 成立 | nvidia-openshell.md:24-26、:107 |
| “Secret values never enter the agent process or context” | :61 | 成立 | nvidia-openshell.md:33 |
| 网关可在本机运行 | :114 的“第三方”与此不符 | 见建议 1 | llms.txt（Installation：local workstation or Kubernetes） |
| 回显封口：OpenShell 未说明 | :79 | 成立（已读页面只看到请求路径 redaction，没有讲响应回显） | profiles.md:104 |

## 处置（作者）

4 条非阻塞建议已全部采纳：“第三方网关”改为“交给它的网关保管，网关可在本机运行”；注明 OCSF 导出为 best-effort、Policy Advisor 默认关闭且可设自动批准；补上 advisor 和 OCSF 页面链接；§8 改为三轮审查。
