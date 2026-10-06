# Rekey

Rekey 是本机 API 凭据执行器：Agent 只执行你授权的操作，拿不到上游 Key。

授权固定上游、操作和参数范围；执行前持久审计，返回时检查凭据反射。
检查覆盖明确支持的表示，不能阻止所有数据外泄或授权范围内的误用。

当前版本为 **0.3.0-alpha.2（alpha）**，[发布状态与下载](https://github.com/majiayu000/rekey/releases/tag/v0.3.0-alpha.2)以 GitHub 为准。macOS 安装入口为签名、公证的 pkg；
发布工作流也会从该 pkg 生成本地 Homebrew cask，尚无公开 tap。
[安装说明](docs/installation.md)列出前置条件；设备权限和完整发布验收仍待完成。

完成 macOS 安装后，个人入口是三条命令。先在 App 确认真实模型、权限与预算：

```bash
rekey setup
rekey add anthropic
rekey run claude-code --client claude-code -- claude --model MODEL_ID
```

这里 `claude-code` 是已签名 Profile 的名称，`MODEL_ID` 换成你已确认的模型。
Setup 和 Add 打开本机 App；密码、Key、策略审阅与系统认证只在管理流程中发生。
授权范围内的 Agent 请求不逐次弹窗；`require-approval` 请求需要明确审批后由调用者重提。

Anthropic、OpenAI、GitHub PAT、GLM 和固定 Bearer 模板已经内置。`rekey add anthropic`
只负责打开管理页；在 App 选择模板、输入 Key、审阅模型/操作/预算并签署 Profile 后再启动 Agent。
其它模板从 App 安装；不要把三条命令理解为省略授权审阅。首次使用步骤见[上手说明](docs/user-guide.md#personal-setup-and-profiles)。

| 等级 | 当前可说明的边界 |
|---|---|
| L0 | 加密保存，Agent 访问已锁定 |
| L1-dev | Agent 接口不返回 Key；源码和 Linux 用户安装的已确认下限 |
| L1 | 还需签名设备上的 Keychain、内存与外部锚权限验收，当前不宣称 |
| L2 | 还需实际启动的隔离与拒绝其它网络访问，不能由 Profile 声明推断 |

## 授权与执行

内置 Anthropic、GLM（Messages / Responses 协议）、OpenAI、GitHub PAT 和固定 Bearer 模板支持按实例、能力及精确 Action
版本授权。安装操作不会自动授予权限。个人模式使用本机 Secure Enclave 策略签名；
团队模式使用外部 Ed25519 签名，两者在建库时确定。个人策略显式选择模板默认、允许或
本机审批；完整差异由 daemon 生成，App 审阅后签署，不能静默覆盖现有授权。

签名 Profile 固定主体、会话期限、次数、模型与请求/每日预算。
CLI、MCP 与 loopback SDK 网关共用授权、持久用量、审计和响应检查。
原始 SSE 支持工具和 thinking 数据；检测到秘密反射、协议歧义或超限会阻断。
流式请求遇到上游限流或过载时，经过遮蔽和审计后返回原 HTTP 状态、错误正文及 Action 允许的重试头。
TUN 的 fake-IP 默认拒绝；可为 daemon 显式配置可信 DoH，配置与隐私边界见[网络说明](docs/operations-runbook.md#dns-network-and-clashtun-fake-ip)。
缺失 usage 或中断按本次已校验的最大输出数保守结算，不是硬费用封顶。

`rekey connect cursor --print` 预览项目 MCP 配置；正式写入需显式操作。
Claude Code/Codex 的 SDK 接入使用 `rekey run` 的明确 client 适配。
已安装客户端与合成上游的本地互通不代表真实 provider 验收。
Linux Profile `netns` 目前明确不可用；Codex 的 Seatbelt 启动仍受已记录的 managed
preferences 限制，不能把宽松接入当作 L2。

## 同机信任边界

- 只通过 Agent 接口调用的进程不能读取上游 Key；请求受已签名的操作、参数、模型和预算约束。
- 当前确认下限为 **L1-dev**。同一用户下能执行任意代码的进程仍可能直接攻击文件、内存或窃取能力令牌，不能承诺抵抗这种攻击。root 和恶意管理员也不在保护范围内。
- L1 需要完整签名设备验收；L2 还需要真正运行的进程与网络隔离。Linux Profile netns 目前不可用，旧容器参考不能代替当前 L2 验收。
- 密码库解决凭据保存；Rekey 同时约束凭据可以执行的操作。允许的操作仍可能被误用，反射检查也不覆盖任意编码和隐蔽信道。

现行分级是 L0/L1-dev/L1/L2；历史 G1/G2 拓扑不是当前产品等级。完整依据见[威胁模型](docs/product-foundation/threat-model-v2.md)。

## 管理、恢复与边界

App 提供凭据管理、模板安装、策略/审批、Activity 和备份恢复。
查看明文和停止 daemon 每次需要新证明；七天系统认证授权不会因重启或恢复而续期。
回滚检测使用认证代数与外部 high-water；疑似回滚不会自动解锁，恢复须审阅并明确确认。
Agent 执行不推进代数，日预算不防本机合法旧状态回滚，也不是硬费用封顶。

永久不提供迁移、旧格式双读或回填。vault25 / policy6 已冻结，覆盖所有 0.3 版本，包括预发布。
0.3 是原 v3 设计的产品发布编号；改号不解冻格式，未来不兼容变化须另行规划发布线。
旧环境保留匹配的二进制、状态与备份，新格式使用新空目录重建。

- [使用指南](docs/user-guide.md) · [安装与卸载](docs/installation.md) · [macOS App](apps/macos/README.md)
- [运维与明确恢复](docs/operations-runbook.md) · [功能事实](docs/product-foundation/feature-truth-matrix.md)
- [威胁模型](docs/product-foundation/threat-model-v2.md) · [候选范围](docs/alpha-scope.md) · [安全报告](SECURITY.md)
- [发布进度与一周自用记录](docs/v3-release-and-dogfood.md)

## 开发

Rust/MSRV 为 `1.95.0`，默认 feature 为空：

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all
```

企业储备需显式 `--features lab`：工作负载身份、审批 relay、OIDC、外部 secret source、
原生插件、指标、审计投递/归档与 standby/DR。旧指南中的这些示例不是默认产品能力。
`rekey-approval-relay` 保留为 workspace 成员，其二进制与测试均要求 `lab`；默认构建不会编译 relay。
`lab-weekly` 的结果不替代当前候选的完整合流或发布检查。
本仓库没有 v1 MITM、系统 CA、任意目的地代理或旧 vault 兼容层。
