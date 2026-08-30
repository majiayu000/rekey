# Community 与企业能力边界

## 当前 Community 范围

MIT 许可的 Rekey Community 当前交付本地、单 authority 的 Credential Authority 核心：

- 固定 HTTPS Action 和短期 capability；
- envelope-encrypted SQLite vault、step-up、backup/restore；
- 双 Unix socket、typed default-deny policy、审计 fail-closed；
- response secret sealing、上游公网筛选和有界资源；
- launchd/systemd unit 生成与 Linux G2 参考攻击 harness；
- 封闭的 GitHub App Installation 本地 black-box profile。

以上条目仍受[功能真值矩阵](feature-truth-matrix.md)中的证据状态约束，不能把“代码存在”写成
“安全发布完成”。

## 当前没有企业版实现

仓库没有付费 edition、license gate、远程 SaaS 控制面或隐藏 provider。多租户、SSO/SCIM、
组织策略分发、集中审计、HA/DR 控制面、HSM/FIPS validation 和商业支持 SLA 都未实现，
也不应出现在当前产品可用性声明中。

如果未来选择商业化，划分原则是：本地安全边界、数据可恢复性和验证工具不能被削弱或锁在
付费层；企业层只能增加组织级控制与运营能力。该原则不是实现授权，本轮不新增 schema、配置、
edition abstraction 或兼容层。

## 与外部产品的关系

Rekey 当前不取代通用密码管理器或 Secret Manager，也不声称优于 1Password、OpenBao、Vault、
Infisical 或云 Secret Manager。它解决的是更窄的 Agent action boundary。若未来要接入外部
credential source，必须先用真实用户场景完成 GitHub live E2E，再单独评估 source ownership、
failure semantics、license、lock-in 与泄露面；P2.1 不先建 registry 或 SDK。

## 发布声明规则

- 可以说：本地开发候选、固定动作、默认 G1、Linux 有界 G2 reference。
- 不可以说：生产就绪、Security Baseline Complete、通用 G2、enterprise-ready、HA 或 FIPS。
- 外部平台证据和独立人工安全审查缺失时，必须明确写为 pending。
