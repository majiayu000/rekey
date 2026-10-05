# 0.4 Alpha 范围

**0.4.0-alpha.1 为未发布候选版。** 本页描述默认本机产品的实现范围；软件检查不等于真实 Agent、设备或 provider 验收。最终证据集中在[验收报告](evidence/agent-call-acceptance-2026-10-05.md)，操作见[用户指南](user-guide.md)。

## 默认模型

Rekey 保存密钥，提供 CLI、MCP、本机 HTTP 和 SSH agent。Agent 自行启动，调用 Rekey 获取结果。本机调用没有授权 token；用户签署的策略决定权限，HTTP 使用公开 `rekey` 占位头标记请求。

- HTTP Connection 绑定一个凭据、固定 host、预设及读写/路径规则。deny 优先，调用方覆盖只能收紧。签名预设可为具体 POST 操作声明语义读，GraphQL mutation 不归读。
- 发现、描述、调用、dry-run、访问请求及等待保留可执行的错误下一步；App 审阅请求并批准一次或最长 8 小时的同规则窗口。
- `connect` 为 Claude Code、Codex、Cursor 写入 MCP 配置和标记说明，可选安装扫描 hook 与显式 SSH host 配置。
- `.env` 预览只显示变量名；导入及可选改写由用户在 App 中确认。扫描只报告完整秘密及支持变体的位置，不回显匹配内容。
- SSH 身份和 host 规则签名，私钥不返回调用方；未知或未绑定目标需要审批。App 支持生成密钥、公钥展示、完整 host 与 git 签名规则编辑，并与 HTTP/T1 一起签署；既有 host 规则不会因编辑 HTTP 而丢失。git smart HTTP 另用固定 GitHub 预设，默认正文上限 1 MiB。
- OAuth 使用用户提供的 client 和签名权限上限，提供 Google、GitHub、Slack、Notion 的有限预设操作，token 保留在 Rekey。
- AWS AssumeRole、EKS 和 GitHub App 属于 **T1**。根凭据保留在 Rekey，但 Agent 得到临时凭据；须分别签署目标、权限和 TTL 后开启。

## 持久格式与安全范围

当前为 vault/backup **26**、policy **7**。签名策略绑定 HTTP、SSH 和 T1 完整授权记录，名称共用唯一空间。0.3 的 vault25 / policy6 不兼容；无迁移、旧格式 reader 或原地升级。旧目录与旧备份应保留，0.4 在新目录重建。

默认保护范围是同一系统用户的本机环境。调用方名称只用于记录和收紧，不能认证程序，也不能阻止同 UID 的恶意程序调用已允许规则。规则不是 Agent 启动沙箱。个人签名使用 Secure Enclave，不提供软件回退；源码 ad-hoc 构建不能代替正式签名设备的钥匙串和系统认证验收。

审计提交失败时停止授权；执行审计先于解密。上游请求固定目的地、禁重定向，响应进行秘密反射检查。LLM 预算按已结算用量执行，在途并发及同代数状态回滚的费用限制仍有边界。扫描存在单本机用户速率和大小上限，不覆盖所有编码，也不证明过去未泄漏。

`.env` 改写有私有备份、拒绝符号链接、发布前元数据检查和原子 rename。它没有对抗最后检查后并发改写的原子比较交换；改写期间需暂停编辑该文件。

## 验收尚未闭合

最终本机完整 workspace 已通过：915 passed、0 failed、6 ignored；default/lab all-targets check 与 strict Clippy、规则和 SSH 短 fuzz 也有通过日志。新增 HTTP 防护和500次 allow 已在软件回归覆盖。真实 Codex 已完成合成上游的发现、读、审批写入和访问请求链；这些结果及设备/外部场景的界限见 canonical 报告，不据此宣称候选已冻结或发布。

以下仍需实际验收：

- 完整原生 Agent 场景。Codex 合成上游链与真实 GitHub 读、审批创建/关闭 issue 已实测；Claude 最小健康检查受账号 `account_on_hold` 阻塞，双客户端整体验收仍失败。
- SSH App 生成、host 登记和策略签署的真实设备操作。OpenSSH 对 GitHub 测试仓库 push 已有通过证据。
- 正式签名 macOS 设备上的 Secure Enclave、Touch ID 次数和两分钟上手计时。
- OAuth provider 的实际登录、刷新和用户 client 配置。
- 公开预发布包的签名、公证、下载与安装。没有因源码构建成功而发布。

## Lab 与历史材料

旧 Agent Profile、`rekey run`、本机 capability、Seatbelt / netns 启动器和机构控制面不属于默认个人操作。保留代码只作为 `--features lab` 的企业储备；[lab CI](../.github/workflows/lab-weekly.yml)检查编译与归档脚本语法，明确不声称旧运行时夹具通过。

旧 0.3 的发布记录、验收 JSON 与安全审查属于历史证据，不为 0.4 新格式、新 App 或新调用接口背书。0.4 行为来源为[冻结 SPEC](superpowers/specs/2026-10-05-rekey-agent-call-model.md)。
