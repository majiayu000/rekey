# Rekey

Rekey 把 API Key 留在本机，Agent 通过你授权的固定 Action 调用服务。

安装：当前可用的是 [Alpha 下载包](docs/installation.md) 或源码构建。
v3 的 macOS `.pkg` 和 Homebrew 安装尚未发布。

```bash
rekey init --mode team    # 外部签名器模式；恢复密钥只显示一次，请妥善保存
rekey serve   # 启动本机服务，保持此终端运行
rekey status  # 在另一个终端检查状态
```

| 保护等级 | 含义与当前状态 |
|---|---|
| L0 | 加密保存凭据，不交给 Agent 使用 |
| L1-dev | 源码构建、Linux 用户安装：Agent API 不提供凭据读取 |
| L1 | v3 签名安装目标：还须完成用户在场保护与服务端身份验证验收 |
| L2 | L1 加受限网络和文件访问；当前只有独立的隔离参考验收 |

继续阅读：[使用指南](docs/user-guide.md)、[macOS UI](apps/macos/README.md)、
[实际功能状态](docs/product-foundation/feature-truth-matrix.md)、
[威胁模型](docs/product-foundation/threat-model-v2.md)。

## 配置一次，再交给 Agent

当前默认构建保留本机加密 vault、密码与恢复生命周期、固定 HTTP Action、
capability session、策略引擎、Ed25519 审批、审计、备份恢复、GitHub App connector、
本机 MCP stdio 和 `agent-run` 隔离入口。v3 模板安装、个人 P-256 策略草案与 App 签名激活已接通；
本地审批和更简单的 Agent 接入仍在实现中，签名设备上的 Secure Enclave 验收尚未完成。

完成初始化后，按 [首次 Agent shell 接入](docs/user-guide.md#first-agent-shell-integration-source-checkout)
添加凭据、注册固定 Action、激活签名策略，再创建短期 capability。
默认拒绝策略会在授权缺失时拒绝执行。

凭据和管理证明通过隐藏终端输入或显式 stdin 传递。
Agent 只能选择已注册的 Action，不能改变上游 origin、路径、认证头或重定向策略。
响应经过大小限制与秘密反射检查后才返回。Agent API 没有读取或导出凭据的操作。

## macOS 管理界面

```bash
scripts/build-macos-ui.sh
open target/macos-ui/Rekey.app
```

源码 UI 管理凭据、Action、capability、策略、审批、审计和备份。
源码构建不能自动视为 L1；以界面的安全状态和对应验收记录为准。

## 运维与边界

- [安装、服务与卸载](docs/installation.md)
- [备份恢复、审计与故障处理](docs/operations-runbook.md)
- [发布范围](docs/alpha-scope.md)与[版本记录](CHANGELOG.md)
- [安全报告](SECURITY.md)

默认构建采用本机用户拓扑。同用户的任意代码、进程内存和文件访问仍属于
L1-dev 的边界。Linux container/namespace 验收和 macOS Seatbelt 验收只证明其指定拓扑。

固定上游拒绝私有和非公开地址、代理环境变量与重定向。
如果 TUN 返回 `198.18.0.0/15` 假 DNS 地址，需让 Action 的准确主机名返回真实 DNS，
不要通过放宽地址限制来解决。可用 `dig +short api.github.com` 检查 GitHub 解析。

状态目录和备份格式不提供迁移或旧格式回退；使用与备份对应的已验证二进制。

## 开发与企业储备

```bash
cargo check --workspace
cargo test --workspace
cargo fmt --all
```

Rust/MSRV 固定为 `1.95.0`。默认 Cargo feature 为空。
企业执行实现、命令和二进制由 `lab` 显式启用：

```bash
cargo check --workspace --features lab
cargo test --workspace --features lab
```

`lab` 保留工作负载身份、远程审批 relay、OIDC 管理、外部凭据 source、原生插件、
指标以及企业运维实验。相关测试由 `lab-weekly` 每周和手动运行，默认发布包不包含
relay、插件二进制、controlplane、审计投递/归档与 standby 脚本。
共享纯数据类型和存储完整性代码保留；这不表示默认构建开放对应企业执行能力。
相关历史 spec 的 `Status: Lab (v3 scope; enterprise reserve)` 状态头优先于旧发布描述。

本仓库不提供 v1 MITM、系统 CA、单端口代理或旧 vault 兼容层。
