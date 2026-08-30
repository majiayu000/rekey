# Rekey v2 功能真值矩阵

## 状态定义

- **Implemented**：产品路径和自动化验证入口都在仓库中；每个发布候选仍需 fresh run。
- **Evidence pending**：实现或局部 harness 存在，但声明所需的外部平台/人工证据缺失。
- **Reference only**：只对文档限定的部署拓扑成立，不升级默认产品声明。
- **Not implemented**：非目标或尚未获得实现授权。

## 当前真值

| 能力或声明 | 状态 | 仓库证据 / 缺口 |
| --- | --- | --- |
| v2 固定动作 Credential Authority 闭环 | Implemented | `scripts/p0-acceptance.sh`、workspace tests |
| 双 UDS、step-up、capability、audit fail-closed | Implemented | `scripts/p0-runtime-faults.sh`、`scripts/p0-crash-recovery.sh` |
| v4 backup/restore 与 crash/durability 边界 | Implemented | `scripts/p0-durability.sh`、`crates/rekey-vault/tests/backup_restore.rs` |
| typed default-deny policy | Implemented | `scripts/p1-policy-acceptance.sh`、`rekey-policy` tests |
| chunk-boundary response sealing | Implemented | `scripts/p1-streaming-sealing.sh` |
| launchd service-manager 流程 | Implemented | `scripts/p1-service-manager.sh`；真实签名/安装仍需发布环境复跑 |
| systemd required-job | Evidence pending | 尚无真实 systemd required-job 通过记录 |
| Linux container/namespace G2 | Reference only | `scripts/p1-linux-g2.sh`；不代表默认拓扑或通用 G2 |
| GitHub App Installation 本地 TLS black-box | Implemented | `scripts/p2-github-app.sh` |
| GitHub App live E2E | Evidence pending | 需要用户提供专用 GitHub App fixture，不能由本地 mock 替代 |
| G1 security release | Evidence pending | 密码学、IPC、审计、failure semantics 独立人工审查尚未完成 |
| 通用 G2 / enterprise-ready / production-ready | Not implemented | 禁止当前声明 |
| 多租户、SSO/SCIM、HA、多区域、Windows | Not implemented | 当前 non-goals |

## 发布候选必须 fresh 执行

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo audit

scripts/p0-acceptance.sh
scripts/p0-runtime-faults.sh
scripts/p0-crash-recovery.sh
scripts/p0-durability.sh
scripts/p1-policy-acceptance.sh
scripts/p1-streaming-sealing.sh
scripts/p2-github-app.sh
```

`scripts/p1-service-manager.sh` 会操作真实 service manager，必须在明确批准的目标主机运行。
`scripts/p1-linux-g2.sh` 需要 Linux Docker daemon，只验证 reference topology。live GitHub E2E
必须使用专用、最小权限 fixture，并由操作者通过隐藏 TTY 输入，不得把 token 写进仓库、argv 或环境。

## 机械安全合同

```bash
rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests src
rg -n 'get_secret\b|read_secret|export_secret' \
  crates/rekey-domain crates/rekey-broker crates/rekey-cli
cargo tree -p rekey-cli -e normal
```

前两条必须无匹配；CLI 依赖树不得包含 `rusqlite`、`aes-gcm`、`argon2`、`reqwest`、
`rekey-vault` 或 `rekey-broker`。
