# SDK-04 单协议 Action 插件登记

用户已授权继续本地功能。最小实现只扩展既有 Action 定义及其不可变版本，不增加注册服务、安装器、市场、动态库加载、自动下载或第二套效果协议。

## 登记与版本

新增可选 `github_issue_plugin: {path, sha256, protocol}`：path 是有界绝对路径，不能含 NUL 或 `..` 路径分量；sha256 为 64 位小写十六进制；protocol 仅 `github-create-issue-v1`。只允许 GitHub App 类型凭证的固定 `POST https://api.github.com/repos/{owner}/{repo}/issues`、authorization/Bearer 认证槽。不能绑定 list/comment、其他源或文本流。结构在 Action 可信边界验证，凭证类型由 Authority 验证。

沿用 `action create/update --file` 的 unlocked、step-up、deadline、原子持久化及 action.created/updated 审计，不新增 IPC 操作。审计继续记录 Action ID/version，不写任意路径或插件输出。登记成功只表示 Admin 批准的声明已持久化，不探测文件、不执行插件，也不证明它存在或可启动。可信摘要由管理员独立获得，CLI 不自动信任磁盘当前内容。

当前无显式登记的内置 CreateIssue 保留固定打包参考 sidecar。显式登记有唯一优先路径，缺文件、摘要失配、平台不支持或执行失败时直接拒绝，绝不回退打包 sidecar。此区分是内置实现与显式插件的产品选择，不增加旧格式兼容。

Action 更新生成新版本并绑定新路径/摘要；旧 session 继续精确绑定旧 Action 版本。若原路径内容已替换，旧版本摘要失配必须失败。disable 沿用整个 Action 的会话撤销。凭证轮换不改变绑定。备份包含定义但不包含外部 artifact，恢复后必须重新提供同路径、同摘要文件。

SQLite actions 增加 nullable `github_issue_plugin_json`，源码格式 11→12；旧库和备份明确拒绝，不迁移。加载非法定义视为存储完整性错误。现有本机状态信任模型不因此变为同 UID 恶意宿主防护，不新增独立 Action sealing 框架。

## 执行边界

macOS 运行时从已 pin 的 Action 读取声明，绝不从 Agent 请求、环境或 PATH 选择代码。只支持当前原生单协议。非 macOS 上显式绑定必须失败，不能静默忽略；没有显式绑定的原内置非 macOS 路径保持原合同。

沿用 no-follow/nonblocking 打开的普通、可执行、最多 32 MiB 文件与私有只读执行快照。读取已打开文件的有界内容后，先核对 Admin 期望摘要；失配不得 spawn 或兑换凭证。随后检查执行快照与同一份读取字节一致。摘要固定具体代码内容，无需持久 inode，也不把一次注册时 stat 当成执行期保证。最终路径符号链接拒绝；父路径别名不能绕过字节摘要。源文件的 owner/ACL 并不替代摘要验证。该合同仍假设可信 Broker 宿主及私有快照目录，不能防止恶意同 UID 父进程修改运行时。

子进程只收到公开 title/body，stdout 必须逐字节匹配 Broker 的 canonical JSON。既有 Seatbelt、清空环境、FD、CPU、RSS 采样、有界 IO、deadline、kill/reap 保持。所有 profile/权限、JWT、token、HTTP、sealing、撤销和审计留在 Broker。插件失败在远程准入之前闭合 blocked audit；成功仍须晚于 revoke 和 finished audit。

## 验收

- 通过真实 Admin IPC 及 CLI create/update/list/disable，验证 step-up、错误证明、审计回滚、重启持久化及 v11 格式拒绝。
- 至少两个字节不同且遵守协议的真实原生 artifact 分别登记、运行，并通过真实 Broker/确定性 transport/revoke 成功链，证明执行选择不是固定打包文件。
- 错摘要、同路径替换、缺文件、符号链接、坏输出/崩溃/超量/deadline 均明确失败；失败不得产生远程业务请求。已有 runner 攻击证据可复用，新增测试重点放在登记选择与版本绑定。
- v1 session 不能被更新偷偷改到 v2 artifact；新会话不可登记 retired 版本；disable 阻断；备份恢复后绑定内容保持。
- 该交付仅关闭 SDK-04 的单协议 Action 登记/加载切片。通用多效果插件、硬物理内存上限及其他系统验收仍未完成。

## 必需的文件整理

实现收尾时自动门禁拒绝修改超过 800 行的 `authority.rs`。仅将既有 `handle(AuthorityCommand)` 分发方法原样搬入同级已有模式的 `authority/dispatch.rs`，保持执行顺序、超时、触碰 idle 状态与回复行为；不新增调度层或公共 API。随后对 Action 登记的 cfg 条件做等价 Clippy 整理。

## 最终本地验收（2026-09-17）

macOS 26.5.1 / 25F80 / arm64：真实 Broker 登记执行 7 项通过，包含两个不同原生 artifact 与交叉输入负控；域模型 2 项、存储 23 项、备份 14 项、runner 攻击 8 项通过。`scripts/p6-github-app-extension.sh` 的 release CLI/真实 Broker/本地 TLS 全链通过，覆盖 create/list、update 新版本绑定回读、disable 后 exit 4 与零新增远程效果。

最终 `cargo test --workspace --offline -- --test-threads=1` 汇总 541 项通过、0 失败、1 项既有忽略项（含子进程报告）。all-targets check、Clippy warnings denied、fmt、机械 API/CLI 依赖边界通过。按实际 release workflow 的复制段生成本地 staging，归档文件和文档链接检查通过；未发布归档或验证签名。独立审查及纯 dispatch 移动复核通过。非 macOS 的条件测试本机未执行，未连接真实 GitHub。

日志保存在主仓库 `.git/codex/threads/remaining-sdk-20260916/`。本切片没有实现通用多效果插件、硬物理内存限制或父死立即终止，也不代表人工安全审查已完成。
