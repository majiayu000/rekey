# Rekey

Rekey 把 API Key 留在本机，让 Agent 只调用你授权的操作。

当前是 **3.0.0-alpha.1 未发布候选**。macOS 安装入口为签名、公证的 pkg；
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

| 等级 | 当前可说明的边界 |
|---|---|
| L0 | 加密保存，Agent 访问已锁定 |
| L1-dev | Agent 接口不返回 Key；源码和 Linux 用户安装的已确认下限 |
| L1 | 还需签名设备上的 Keychain、内存与外部锚权限验收，当前不宣称 |
| L2 | 还需实际启动的隔离与拒绝其它网络访问，不能由 Profile 声明推断 |

## 授权与执行

内置 Anthropic、OpenAI、GitHub PAT 和固定 Bearer 模板支持按实例、能力及精确 Action
版本授权。安装操作不会自动授予权限。个人模式使用本机 Secure Enclave 策略签名；
团队模式使用外部 Ed25519 签名，两者在建库时确定。个人策略显式选择模板默认、允许或
本机审批；完整差异由 daemon 生成，App 审阅后签署，不能静默覆盖现有授权。

签名 Profile 固定主体、会话期限、次数、模型与请求/每日预算。
CLI、MCP 与 loopback SDK 网关共用授权、持久用量、审计和响应检查。
原始 SSE 支持工具和 thinking 数据；检测到秘密反射、协议歧义或超限会阻断。
缺失 usage 或中断按本次已校验的最大输出数保守结算，不是硬费用封顶。

`rekey connect cursor --print` 预览项目 MCP 配置；正式写入需显式操作。
Claude Code/Codex 的 SDK 接入使用 `rekey run` 的明确 client 适配。
已安装客户端与合成上游的本地互通不代表真实 provider 验收。
Linux Profile `netns` 目前明确不可用；Codex 的 Seatbelt 启动仍受已记录的 managed
preferences 限制，不能把宽松接入当作 L2。

## 管理、恢复与边界

App 提供凭据管理、模板安装、策略/审批、Activity 和备份恢复。
查看明文和停止 daemon 每次需要新证明；七天系统认证授权不会因重启或恢复而续期。
回滚检测使用认证代数与外部 high-water；疑似回滚不会自动解锁，恢复须审阅并明确确认。

永久不提供迁移、旧格式双读或回填。当前 vault25 / policy6 仍是预 GA 格式，尚未最终冻结。
GA 后同一主版本的次/补丁版本不得改变持久格式；破坏性格式变化必须进入下一主版本。
旧环境保留匹配的二进制、状态与备份，新格式使用新空目录重建。

- [使用指南](docs/user-guide.md) · [安装与卸载](docs/installation.md) · [macOS App](apps/macos/README.md)
- [运维与明确恢复](docs/operations-runbook.md) · [功能事实](docs/product-foundation/feature-truth-matrix.md)
- [威胁模型](docs/product-foundation/threat-model-v2.md) · [候选范围](docs/alpha-scope.md) · [安全报告](SECURITY.md)

## 开发

Rust/MSRV 为 `1.95.0`，默认 feature 为空：

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all
```

企业储备需显式 `--features lab`：工作负载身份、审批 relay、OIDC、外部 secret source、
原生插件、指标、审计投递/归档与 standby/DR。旧指南中的这些示例不是默认产品能力。
`lab-weekly` 的结果不替代当前候选的完整合流或发布检查。
本仓库没有 v1 MITM、系统 CA、任意目的地代理或旧 vault 兼容层。
