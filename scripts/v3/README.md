# macOS v3 安全原型

这些程序只验证 SPEC 的 V1–V3 前置条件，不代表 v3 产品验收完成。全部使用临时目录、合成凭据和独立钥匙串条目，不读取用户 vault。

先构建 `rekey` 和 `rekeyd`，再在已登录的 macOS 用户会话中运行：

```sh
cargo build -p rekey-cli --bin rekey -p rekey-broker --bin rekeyd
python3 scripts/v3/run.py \
  --bin-dir target/debug \
  --identity 'Developer ID Application: YOUR NAME (TEAM_ID)' \
  --team-id TEAM_ID \
  --provisioning-profile /absolute/path/to/profile.provisionprofile \
  --interactive-keychain \
  --output /absolute/path/to/new-evidence-directory
```

`--identity` 和 `--team-id` 是公开签名身份，不是密钥。签名只作用于临时副本。V1 的 profile 必须授权 bundle `TEAM_ID.com.rekey.v3.keychain` 和访问组 `TEAM_ID.com.rekey`。仅有 Developer ID 证书不足以证明这些 entitlement 可用。

默认不允许钥匙串交互。只有显式传入 `--interactive-keychain` 才运行需要用户在场的正向读取；未完成正向对照时 V1 为 `inconclusive`。系统可能要求 Touch ID 或登录密码。程序不输出合成密钥，清理按本次 UUID 精确定位；清理错误保留在报告中。

| 原型 | 验证 | 结果边界 |
|---|---|---|
| `keychain_probe.swift` | 受 `.userPresence` 保护的 owner 读取、同 uid ad-hoc 进程非交互读取 | owner 被系统终止、profile 不匹配或正向对照未完成都不是机制通过 |
| `memory_probe.c` | `task_for_pid` 自身正向对照、ad-hoc 与 hardened `rekeyd` 对照 | 只申请 task port，不读取或转储内存；两个 daemon 都被拒绝时无法归因到 hardened runtime |
| `peer_probe.swift` | `LOCAL_PEERTOKEN` → Security.framework 校验 Team/ID；错误 ID 和 ad-hoc 零字节 | 只证明观测时身份及发送前拒绝；不证明 socket FD 独占或消除所有进程时序竞态 |

结果写入 `report.json`，每项分别为 `passed`、`failed` 或 `inconclusive`。退出码为：全部通过 `0`，至少一项明确失败 `1`，其余未确定 `2`。签名摘要针对最终签名产物。输出目录必须不存在，避免覆盖先前证据。

报告控制流回归检查：

```sh
python3 -m unittest discover -s scripts/v3 -p test_run.py
```

2026-10-03 本机首轮：V1 owner 在返回 API 状态前被终止；V2 两个对照均拒绝 task port；V3 正向与两项负向对照符合预期。原始证据位于主工作区 `outputs/rekey-v3-20261003/signed-run-1/report.json`。这些结果不能提升当前产品的同用户进程安全承诺。
