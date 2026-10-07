# 0.4 运维手册

适用于 **0.4.0-alpha.1 未发布候选版，vault/backup26、policy7**。请先核对实际二进制、服务用户和 state directory；默认目录是 `~/.rekey`。0.3 格式不能由 0.4 恢复或迁移，须另建新目录。验收与发布边界见[报告](evidence/agent-call-acceptance-2026-10-05.md)。

完整软件回归通过不代替当前安装包、真实设备或目标文件系统的恢复演练。正式签名包与便携源码二进制也应分别记录验收，不能把一种构建的成功回执复用为另一种构建的证明。

## 运行状态与目录

```bash
rekey --version
rekey --state-dir /absolute/path/rekey-04 status --passive
rekey --state-dir /absolute/path/rekey-04 policy status
```

启动服务默认锁定。`serve` 前台运行；安装版 macOS 可使用 App 的服务控制，自定义目录先由 CLI 启动再让 App 连接。关闭 App 不停止服务。`lock` 立即撤销本机执行权限及窗口；`shutdown` 需要新的逐次证明。不要同时启动两个 daemon 管理同一目录。

state/runtime 目录应只属于服务用户，mode0700；数据库及 Unix sockets 为 mode0600。检查权限与所有权，不能通过放宽 Admin socket 或递归 chown 来解决未知原因。

```bash
ls -ld /absolute/path/rekey-04 /absolute/path/rekey-04/runtime
ls -l /absolute/path/rekey-04/runtime
```

`IPC_UNAVAILABLE` 可能是未启动、路径或用户不一致、遗留 socket、符号链接或父目录权限异常。先定位实际原因。macOS 安装版可只读诊断 `launchctl print gui/$(id -u)/com.rekey.rekeyd`；不要另生成重复 LaunchAgent。Linux 已安装 user unit 时使用 `systemctl --user status rekey.service` 与 `journalctl --user -u rekey.service`。

## 备份

Broker 必须已解锁，备份目标必须不存在。命令在终端中隐藏读取新的证明：

```bash
rekey --state-dir /absolute/path/rekey-04 unlock
rekey --state-dir /absolute/path/rekey-04 backup --output /absolute/path/backups/rekey-04-new.rkb
```

把成功回执（含 SHA-256、vault ID 和 generation）与备份分别保存，再校验文件：

```bash
shasum -a 256 /absolute/path/backups/rekey-04-new.rkb
```

必须与成功回执的完整 digest 一致。文件存在但没有成功回执不代表备份成功；不要把 staging / pending 文件改名为完成备份。备份包含加密凭据和签名授权，密码或恢复密钥仍须离线保存。改密码或轮换当前根密钥不会重新加密已经存在的历史备份；保留对应恢复材料。

外部调度器只可传输已完成备份及回执，不能持有解锁证明。默认产品不自动选择远端、传输计划或保留策略。操作员必须明确管理目的地权限并核对远端 digest。

## 恢复演练

使用隔离的新目录，不能用生产目录验证恢复。先停止相关服务，选择 mode0700 的空目标；不要删除旧保险库、WAL 或外部 generation 记录来制造“空目录”。

```bash
mkdir -m 700 /absolute/path/rekey-04-restore
rekey --state-dir /absolute/path/rekey-04-restore restore \
  --input /absolute/path/backups/rekey-04-new.rkb \
  --sha256 RECEIPT_SHA256 --inspect
```

隐藏输入备份源的密码；使用恢复密钥时加 `--recovery`。审阅返回的 vault ID、source generation、high-water 和 history-missing。复制该次预览的**完整公共 JSON context**，明确接受后提交同一备份、同一 SHA 与新的证明：

```bash
rekey --state-dir /absolute/path/rekey-04-restore restore \
  --input /absolute/path/backups/rekey-04-new.rkb \
  --sha256 RECEIPT_SHA256 --expected-context 'EXACT_PUBLIC_CONTEXT_JSON'
```

占位 `EXACT_PUBLIC_CONTEXT_JSON` 必须替换成预览的真实完整 JSON，不能手写或省字段。context 改变时重新 inspect 并审阅，不能自动重试。恢复不是密码重置；错误证明、digest 不符、坏备份或非空目标必须失败。

成功后保存新回执，在恢复目录启动服务、解锁，核对凭据和完整签名编辑基线：

```bash
rekey --state-dir /absolute/path/rekey-04-restore serve
```

另一个终端：

```bash
rekey --state-dir /absolute/path/rekey-04-restore unlock
rekey --state-dir /absolute/path/rekey-04-restore credential list
rekey --state-dir /absolute/path/rekey-04-restore connection list
rekey --state-dir /absolute/path/rekey-04-restore list --json
rekey --state-dir /absolute/path/rekey-04-restore shutdown
```

必要时对一个专用测试 Connection 先 dry-run，再进行无副作用读调用，确认凭据仍有效。签名策略过期时必须用合法签名流程激活新版本。记录二进制版本、备份 digest、预览 context 与新 generation，关闭演练服务；不要据此覆盖生产目录。

## 中断、回滚与存储故障

`.restore-incomplete`、`.init-incomplete` 是持久安全标记。保留它们、数据库、wrappers 和 generation 历史。没有成功回执不意味着没有预留新 generation；不能手工删除标记、回退计数或编辑 SQLite。中断恢复应重新认证原备份、inspect 并显式接受当前 context；由受支持恢复路径处理其已验证的残留。中断 init 不能当成可随意重跑的清理入口。

`ROLLBACK_SUSPECTED` 没有可用根密钥。先查看 `status` 的 `rollback` 对象，只能用密码或恢复密钥和完整公共 context 确认：

```bash
rekey --state-dir /absolute/path/rekey-04 rollback-confirm \
  --expected-context 'EXACT_PUBLIC_ROLLBACK_JSON'
```

系统认证不能确认回滚；确认成功仍锁定，随后再显式解锁。context 改变时拒绝并重新审阅。

| 故障 | 操作 |
|---|---|
| `STORAGE_INTEGRITY_FAILED`、不支持格式、损坏的 crypto metadata | 停止服务，保留原目录、版本和诊断；从已验证备份恢复到另一个空目录。 |
| `AUDIT_COMMIT_FAILED`、`FAULTED` | 执行与写操作已失败关闭。修复磁盘/文件系统后重新启动，核对审计及状态再恢复使用。 |
| `POLICY_INVALID` / version conflict | 保留拒绝的工件和当前签名摘要，重新审阅并签署合法下一版本；不要直接编辑数据库或上传未签名快照。 |
| 执行后审计失败或结果未知 | 上游副作用可能已经发生。用 request ID 和上游结果核对，不能自动重复写操作或派生签发。 |
| `ENOSPC` / I/O 错误 | 停止新请求，检查 `df -h`、`df -i`，在 state directory 之外释放空间，保留 WAL 和 incomplete markers。 |

## 审计与授权变更

```bash
rekey --state-dir /absolute/path/rekey-04 audit list --limit 50
rekey --state-dir /absolute/path/rekey-04 audit export --output /absolute/path/rekey-audit-new.jsonl
```

审计导出是 mode0600 的新文件，必须收到成功回执才算完成。部分文件作为失败证据保留，重试使用新路径，不续写。导出是经脱敏的操作 metadata，不是加密凭据备份；仍需控制访问。稳定遍历需保留返回的 snapshot-max-sequence 和 before-sequence。

HTTP、SSH 与 T1 的授权只能通过完整签名策略变更。个人 App 编辑同时保存三组完整集合，SSH host 的既有 rule ID 和公钥不会因编辑 HTTP 而清空。保留编辑基线 digest，在 App 审阅完整 before/after；并发修改基线时重新获取，不自动重签。锁定、策略更改和服务停止撤销窗口与缓存；审批绑定请求方法、规范化路径、查询、请求头、正文、调用方及策略，不把批准当成可复用的通用通行证。

访问请求的“批准”仅确认当前已激活的授权满足请求；先添加凭据并签署规则。调用方标签可伪造，只能作为记录和收紧条件；屏蔽标签不能宣称阻止同 UID 恶意进程。

OAuth 重新授权使用 App / 浏览器流程，不把 refresh token 发给 Agent。T1 审计保留签名目标、权限与实际签发过期时间，不记录临时值；进程 stdout / 下游工具日志仍需由用户控制。

## `.env` 与扫描事故

导入前先预览变量名和未支持项。改写前暂停并发编辑，确认选中变量、Connection 和 base URL；daemon 返回的备份路径是恢复依据，备份含原始秘密，mode0600 仍不能当成可公开文件。未知结果先检查文件和备份，禁止自动重做 import / rewrite。

改写拒绝已发现的符号链接并在最终发布前检查 metadata，然后原子 rename；最后检查与 rename 之间仍有并发改写窗口。它不能保证保留同时发生的用户编辑。

`scan` 超限、锁定或限速返回错误时，不代表文件安全。发现泄漏后先在 provider 撤销/轮换真实凭据，再清理项目、Git 历史和外部日志；从当前暂存区删除不撤销已经泄漏的 key。Rekey 扫描响应只给位置，不需要复制匹配值来排查。

## 升级与丢失恢复材料

0.4 不读取 0.3 的 vault25 / policy6。旧二进制、旧 state 和旧备份一起保留，另建 0.4 目录并通过受支持添加流程重建密钥与 Connection。不能把旧备份当成 0.4 导入路径，不删除旧 generation 历史来降级。

密码丢失而恢复密钥可用时，可用恢复密钥解锁并修改密码；恢复密钥丢失而密码可用时可轮换恢复密钥。两者均丢失时凭据和备份不可解密。个人策略签名私钥丢失也不能替换不可变 trust root，应新建 vault 并重建授权。历史备份保留旧因素边界。

旧机构控制面、容器/namespace 故障切换与 Profile 工具仅作为 lab 企业储备保留，默认运维不运行它们；lab 编译与归档脚本语法通过不代表旧 runtime 验收完成。
