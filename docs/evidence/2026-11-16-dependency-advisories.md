# 2026-11-16：依赖公告修复

## 决定与范围

要支撑的决定：将依赖修复作为独立变更审查，解除 PR #94 的依赖审计阻断，
同时消除本次核查发现的两条 unsoundness 告警。
验收目标：根目录与 fuzz 的锁文件均通过 `cargo audit --deny warnings`，
共享依赖解析无漂移，进程退出监测与等待取消的现有行为保持成立。
放弃条件：需要改变 vault27 / policy8、存储布局、签名或授权语义时停止扩大范围。

基线为 `50f900ad`，第一批依赖修复为 `fbfd0c08`。本分支不包含 #94 的 HTTP 修复。
决定：采用最小依赖升级和明确的 FD 注册安全契约；不增加兼容层或审计豁免。
最终组合状态的完整 CI 仍是后续合并门槛。

## 公告与修复

| 公告 | 原锁定版本 | 修复后版本 |
|---|---|---|
| [RUSTSEC-2026-0459](https://rustsec.org/advisories/RUSTSEC-2026-0459.html) | libsqlite3-sys 0.32.0 | 0.39.1，经由 rusqlite 0.41.1 |
| [RUSTSEC-2026-0538](https://rustsec.org/advisories/RUSTSEC-2026-0538.html) | quinn-udp 0.5.14 | 0.5.16 |
| [RUSTSEC-2026-0386](https://rustsec.org/advisories/RUSTSEC-2026-0386.html) | Tokio 1.50.0 | 1.51.6 |
| [RUSTSEC-2026-0486](https://rustsec.org/advisories/RUSTSEC-2026-0486.html) | rustix 1.1.4 | 1.1.6 |

SQLite 随依赖从 3.49.1 升至 3.54.1。`fallible_uint` 保留原来的
`u64` / `usize` 到 `i64` 的可失败转换，超范围依然返回错误；没有存储代码变更。
Tokio 的宏依赖同步至 2.7.2。Broker 显式声明使用新注册 API 所需的最低 Tokio 版本。

Tokio 修复将 FD 生命周期前提改为调用方必须明确保证的 unsafe 契约。
已逐项核对两处调用，采用 [1.51.6 的注册 API](https://github.com/tokio-rs/tokio/blob/tokio-1.51.6/tokio/src/io/async_fd.rs)：

- `ipc/owner.rs`：平台函数返回独占的 `OwnedFd`，交给 `AsyncFd` 持有。
  查询只临时借用 raw FD，不关闭或替换；注销后才由所有者关闭。
  macOS kqueue 仍只注册可读事件。
- `github_issue_plugin/linux_tree.rs`：克隆非阻塞 ack socket 得到一个独立、
  有效且自有的 FD，交给局部 `AsyncFd`。等待正常返回或被取消时，均先注销再关闭。
  注册错误转换回原始 `io::Error`，不隐藏系统错误原因。

此变更明确并保持所有权约束；不声称曾在 Rekey 中复现任意 FD 注册或 use-after-free。

## 本轮验证

- 根目录、fuzz 锁文件的 `cargo audit --deny warnings --json`：
  `vulnerabilities.list` 均为空，`warnings` 均为空。
  本轮 RustSec 数据库为 `02e2517f457a359fc6d3440ea4560c8ea188fee8`，含 1,509 条公告。
- 按 fuzz CI 相同的共享包版本规则比较两个 `cargo metadata --locked` 输出：无漂移。
- 固定 Rust 1.95.0 的 `cargo check --workspace --all-targets --locked`：通过。
- 进程所有者回归：正常退出、SIGKILL 后子进程仍持有 socket、死进程拒绝注册、
  取消后继续等待、独立监测器，以及 macOS 进程代际验证均成立；8 项通过，
  1 项仅供子进程调用的夹具忽略。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`，以及添加
  `--features lab` 的同一检查：均通过。
- Linux aarch64 / Rust 1.95.0 容器中，
  `cargo check --locked -p rekey-broker --all-targets --features lab` 通过，
  覆盖 Linux guardian 注册路径。源码只读挂载；不代表 Linux lab 运行时验收。
- 首次 `cargo test --locked --workspace -- --test-threads=1` 未全过：
  `pki_client_csr::issued_records_survive_restart_vrk_rotation_and_backup_restore`
  在恢复后的 CRL 生成处（测试第 622 行）返回 `AuthorityBusy`；此前重启、轮换和
  恢复后的证书/CRL 记录一致性断言均通过。该 helper 为调用设置 10 秒截止时间。
  本轮保留了具体错误；没有捕获该次调用的耗时，不能据机器负载直接宣布根因。
  不修改生产超时、不放宽测试断言。
- 首次全量停下时为 985 通过 / 1 失败 / 14 忽略。该用例单独连续重跑三次均通过。
  随后以 `--workspace` 保持相同的 workspace feature 解析，重跑整个失败目标，
  并补跑中断后的 10 个 Vault 目标：PKI 目标为 22 通过 / 0 失败 / 1 忽略，
  整次补验为 112 / 0 / 1；workspace doctest 也通过。
  按每个测试目标的最终结果去重，默认 workspace 汇总为 **1,076 / 0 / 14**。
  这是首次运行加定向补验的覆盖汇总，不是一次全量绿色运行；首次失败不改记为通过。
- 所有本机测试使用固定 Rust 1.95.0、串行测试线程，并在子进程环境中设置
  `GIT_CONFIG_GLOBAL=/dev/null`、`GIT_CONFIG_NOSYSTEM=1`，避免本机全局 Git hook
  配置干扰独立分支上的 connect 夹具；没有修改全局 Git 配置或带入 #94 的代码。

本轮原始审计、metadata 与测试日志保存在本机
`~/Documents/rekey-reviews/2026-11-16-dependency-advisories/fix/`，不包含真实保险库操作。

## 交接记录与未验边界

第一批修复的完整测试、真实二进制脚本、release 运行时故障和耐久性验收由前一轮报告；
不要将它们自动算作本轮新增 Tokio/rustix 组合的验证。

前一轮 broker 夹具初始化失败一次，未保留具体原始错误。后续单项与目标重跑均成功，
只能记录为“未复现，原因未定”；高负载是推测，不是已证实的根因。
前一轮两个验收脚本使用临时包装器为测试保险库分配空闲端口，
结果只覆盖该配置，不表示在默认 7787 被占用时直接运行脚本会成功。

尚未验证：与 #94 组合后的全量测试、真实已有保险库、签名安装产物、真实供应商调用。
完整 lab 运行时不在此次验证范围；Linux lab 注册路径仅完成编译检查。

已验：两锁文件的漏洞及告警列表为空，正常退出、取消后继续等待和独立监测器行为成立，
Linux lab 路径编译成立，PKI 整目标及其余目标补验通过。
没验：与 #94 组合后的完整 CI、真实保险库与签名安装产物。
相邻情况：首次全量 PKI 的 `AuthorityBusy` 已保留原始错误，根因未最终确认；
Linux lab 运行时没有执行，不能由编译通过推导为验收完成。
