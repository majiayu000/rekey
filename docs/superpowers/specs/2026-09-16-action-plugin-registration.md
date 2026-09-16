# SDK-04 GitHub 两操作 Action 插件登记

用户已授权继续本地功能。最小实现扩展既有 Action 定义及其不可变版本，使同一 artifact 支持 GitHub CreateIssue / CreateIssueComment。没有新增插件注册服务、任意 HTTP 效果、安装器、市场或动态库加载。

## 登记与版本

`github_issue_plugin: {path, sha256, protocol}` 保留既有三字段。path 是最多 4096 字节的绝对路径，不能含 NUL 或 `..` 分量；sha256 为 64 位小写十六进制。唯一协议升级为 `github-issues-v1`，替换旧的 `github-create-issue-v1`，没有兼容分支。

只允许 GitHub App 凭证、固定 `POST https://api.github.com/repos/{owner}/{repo}/issues` 或 `/repos/{owner}/{repo}/issues/{number}/comments`、authorization/Bearer 认证槽。number 必须是无前导零且大于零的规范 u64；不允许 list、其他 origin、额外路径分量或 text_stream。结构在 Action 可信边界验证，凭证类型由 Authority 验证。

沿用 `action create/update/list/disable` 与 unlocked、step-up、deadline、原子持久化和 action.created/updated 审计。登记只持久化 Admin 批准的声明，不探测文件或运行代码；摘要由管理员独立取得。审计不写任意 artifact 路径或输出。

macOS 上两种操作均通过参考 sidecar；未显式登记时使用包内 `rekey-github-create-issue`（现已处理两种 issue 操作）。显式登记有唯一优先路径，任何失败都不回退。非 macOS 显式登记及执行仍拒绝；未显式登记的内置实现保持原本进程内合同。

Action 更新产生新版本，旧 session 精确绑定旧路径/摘要；替换路径内容会令旧摘要失败，disable 撤销整个 Action 的会话。备份包含声明、不含 executable。SQLite 列不变；源码格式 12→13，明确拒绝旧库和备份，不迁移。

## 两操作进程合同

Broker 从已验证的 GitHubAction 决定 operation，构造封闭 JSON envelope：`{"operation":"create_issue","body":{"title":"...","body":"..."}}` 或 `{"operation":"create_issue_comment","body":{"body":"..."}}`。Agent 不能提交 operation、URL、headers、effects 列表或路由参数来扩大权限。

CreateIssue 沿用非空 title（最多 256 字节）及可选 body（最多 32 KiB）；comment 要求非空 body（最多 32 KiB）。拒绝未知/重复字段、未知 operation 及操作与 body 类型不匹配。stdin/stdout 的完整 envelope 各最多 256 KiB。插件返回规范 envelope，Broker 逐字节比对包含 operation 在内的完整结果，只将已核对的规范 body 交给现有固定网络效果路径。插件不能改变操作或已授权内容。

保留 no-follow/nonblocking 普通可执行 artifact（最多 32 MiB）、实际读取字节的 Admin SHA-256 核验和私有只读执行快照。登记失败不回退。沿用 Seatbelt、清空环境、FD 清理、CPU、RSS 采样、有界 IO、绝对 deadline、kill/reap。所有凭证、JWT/token、profile 权限、远程 IO、sealing、revoke 和审计留在 Broker；任何插件错误必须在 token exchange/远程效果之前终结为 blocked。

该合同假设可信 Broker 宿主，不防恶意同 UID 父进程。RSS 采样不是硬物理内存限制，父死立即终止仍未实现。两种固定操作不等于通用多凭证效果插件平台。

## 验收

- connector 测试两操作规范化、空/超长 body、未知/重复字段、未知操作及类型不匹配。
- domain 拒绝无效 comment number、list/错误 origin/auth/stream 以及旧协议；存储与备份拒绝 v12。
- 同一原生 artifact 经真实 Admin IPC、Broker 和确定性 transport 分别执行两种 Action，断言精确 URL/body，revoke 和 finished audit 早于成功。
- 两操作均验证恶意 artifact 改 operation/body 或加入 route 被拒绝；token exchange 和业务请求为零。保留已通过的摘要、缺失、symlink、崩溃、限额、版本绑定、disable、审计回滚、重启和备份测试。
- release CLI/本地 TLS P6 覆盖两操作的显式绑定与成功执行；Linux 对显式登记拒绝，并保持内置两操作可用。

以下是单操作切片的历史验收；两操作实现及本轮结果在剩余清单中独立记录。

## 必需的文件整理

实现收尾时自动门禁拒绝修改超过 800 行的 `authority.rs`。仅将既有 `handle(AuthorityCommand)` 分发方法原样搬入同级已有模式的 `authority/dispatch.rs`，保持执行顺序、超时、触碰 idle 状态与回复行为；不新增调度层或公共 API。随后对 Action 登记的 cfg 条件做等价 Clippy 整理。

## 单操作切片的历史验收（2026-09-17）

macOS 26.5.1 / 25F80 / arm64：真实 Broker 登记执行 7 项通过，包含两个不同原生 artifact 与交叉输入负控；域模型 2 项、存储 23 项、备份 14 项、runner 攻击 8 项通过。`scripts/p6-github-app-extension.sh` 的 release CLI/真实 Broker/本地 TLS 全链通过，覆盖 create/list、update 新版本绑定回读、disable 后 exit 4 与零新增远程效果。

最终 `cargo test --workspace --offline -- --test-threads=1` 汇总 541 项通过、0 失败、1 项既有忽略项（含子进程报告）。all-targets check、Clippy warnings denied、fmt、机械 API/CLI 依赖边界通过。按实际 release workflow 的复制段生成本地 staging，归档文件和文档链接检查通过；未发布归档或验证签名。独立审查及纯 dispatch 移动复核通过。非 macOS 的条件测试本机未执行，未连接真实 GitHub。

日志保存在主仓库 `.git/codex/threads/remaining-sdk-20260916/`。本切片没有实现通用多效果插件、硬物理内存限制或父死立即终止，也不代表人工安全审查已完成。

## 两操作切片最终验收

macOS真实 Broker9项、纯connector3项、域模型29项、存储24项、备份15项和GitHub runner/profile26项专项通过。最终整库548项通过、0失败、1项既有忽略（含子进程报告）；all-targets check/Clippy/fmt通过。macOS P6证明同一登记artifact的两操作经真实CLI/Broker/TLS成功；Linux P6证明原有内置两操作继续成功，Linux专项证明显式登记两种Action均拒绝。状态/备份格式13，v12拒绝测试通过。仍未调用真实GitHub、未实现Linux插件或完整硬资源保障。
