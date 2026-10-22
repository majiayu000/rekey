# 安全模型与术语

README、[用户指南](../user-guide.md)和[安装说明](../installation.md)只写日常用法。本页集中说明版本格式、保护等级和内部术语；更完整的实现与验收状态以[功能事实矩阵](../product-foundation/feature-truth-matrix.md)和[威胁模型](../product-foundation/threat-model-v2.md)为准。

## 版本与数据格式

| 版本线 | 状态 | 保险库 / 备份格式 | 签名策略格式 |
|---|---|---|---|
| 0.3 | 已发布 | vault25 | policy6 |
| 0.4.0-alpha.1 | 最新公开预发布（2026-10-08） | vault26 | policy7 |
| 0.5.0-alpha.1 | 当前源码，**未发布** | vault27 | policy8 |

每条版本线冻结自己的格式，不做迁移、旧格式双读或回填。新版本线需要新建保险库：保留旧二进制、旧状态目录和备份，在新目录重新添加密钥、签署连接。公开版本与下载以 [GitHub Releases](https://github.com/majiayu000/rekey/releases) 为准；源码检查不代表新版本已经发布或通过真机安装验收。

## 保护等级

Rekey 默认与 Agent 运行在同一系统用户下，当前确认的保护下限是 **L1-dev**。加密、签名规则、出站限制、响应遮蔽和审计共同约束 Rekey 自己的接口；它们不阻止同用户的恶意程序读取其他进程内存、伪造调用方名称或换一个网络客户端直接访问上游。root 和恶意管理员不在保护范围内。

命令行在服务签名未校验时会提示 `L1-dev · 服务签名未校验`：这表示密码或恢复密钥会发给一个未验证签名的本地服务，只应在可信的开发环境使用。仅凭对端校验不能把等级提升为 L1；更高等级需要独立的隔离、受保护锚点和设备证据。

历史文档中的 **G1 / G2** 只描述部署拓扑（例如 Linux 上让 Agent 以独立 UID 访问单独的 socket），不是当前保护等级。

## 基础模式与 Secure Enclave

每个保险库第一次安装的“信任根”决定之后用哪把密钥签署连接规则，装上后不能更换：

- **基础模式**（`rekey add <预设>`，**仅限测试，不安全**）：签名私钥是状态目录中 0600 的软件 P-256 文件 `policy-signer-p256.p8`，同用户进程可读，**不是 Secure Enclave**。
- **App 模式**（`rekey add <预设> --app`）：在 macOS App 中用 Secure Enclave 密钥签名。已用这种方式建立信任的保险库，命令行软件签名会以 `TRUST_MISMATCH` 拒绝。

`rekey unlock --remember 7d` 同样是软件实现：解封密钥写成状态目录中 0600 的 `remembered-unlock.key`，同用户进程可读；`rekey lock --forget-remembered` 删除它。

基础模式的签名私钥（`~/.rekey/policy-signer-p256.p8`）和记住解锁的密钥（`remembered-unlock.key`）是同用户可读的文件。本机以你身份运行的任何程序——包括 AI Agent，尤其是跳过权限确认运行的 Agent——都能读到它们，从而自己批准访问请求和写操作、签出放宽的规则，甚至结合 `desktop-unlock.bin` 离线解密保险库。所以基础模式只用于开发和测试，不要存放需要保护的密钥；保护真实密钥请用 App 的 Secure Enclave 个人模式（`rekey add <预设> --app`）。

## 调用结果与临时凭据

- **T0（只返回结果）**：Agent 只拿到调用结果，看不到任何凭据。CLI、MCP、本机 HTTP 和 SSH agent 都属于这一类。
- **T1（临时凭据）**：AWS `credential_process`、EKS kubectl 插件和 GitHub App 安装令牌会把**短期临时凭据**交给 Agent 进程。目标 role / cluster / installation、权限和有效期固定在签名规则里，调用方不能覆盖；每个 T1 入口须单独签署开启。

两类在能力发现、界面和审计中分别标注。

## 调用方名称不是身份认证

审计和审批里显示的调用方名称只用于记录和收紧权限。同一系统用户下的程序可以伪造名称，因此调用方规则只能在默认权限上再收紧，不能放宽。

## lab 实验功能

旧的 `rekey run`、Profile、本机 capability 令牌、Seatbelt/netns 隔离启动器和企业集成已退出默认个人产品，代码只在 lab 构建（`--features lab`）中保留。lab 的编译与 lint 检查不代表这些历史运行时能用于当前策略格式，也不宣称企业部署已通过。默认产品中本机调用不需要任何令牌。

## 验收边界

软件测试不等于发布验收。已安装 App、真实 Touch ID / Secure Enclave 设备事件、真实供应商与 OAuth、公开下载安装和多主机部署，都需要单独的设备或环境证据，不能由单元测试推断。
