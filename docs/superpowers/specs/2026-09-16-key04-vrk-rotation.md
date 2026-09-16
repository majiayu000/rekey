# KEY-04：Locked状态下原子轮换VRK

日期：2026-09-16。状态：本地实施规格，尚未实现或验收。
范围是当前保险库的VRK与其全部加密依赖，不包含热切换、schema升级、迁移、配置项、上游凭证轮转或历史备份撤销。
本规格基于 `remaining-integration` 当前 [DEK轮换切片](2026-09-16-key04-dek-rotation.md) 和下面核实的实现；不能把已有DEK验证结果当作VRK证据。

## 现有实现依据

- `authority/credential.rs::rotate_dek_inner` 已逐版本认证、解密、生成新DEK并重加密，包含retired/revoked版本；其store批量替换含精确行数与precommit deadline检查。
- `authority.rs::verify_proof` 要求Unlocked，不能直接用于本流程；`bootstrap::{kek_for_wrapper,unwrap_vrk}` 已提供按wrapper解开VRK的原语。
- `crypto/credential_state.rs` 与 `crypto/policy_state.rs` 用VRK认证credential、policy state/trust/bundle；`bootstrap.rs` 用VRK认证header integrity mark。
- `store/policy.rs::activate_policy_bundle` 会删除 `workload_token_uses`；VRK轮换不能通过install/activate业务路径重建policy。
- `store/wrapper.rs::replace_wrapper` 会禁用旧wrapper并清零salt、nonce、wrapped VRK；当前两个单wrapper事务不能串联充当一次VRK原子替换。
- `crypto/approval_origin.rs` 从VRK和vault ID派生origin密钥。`authority/desktop.rs` 的 `desktop-unlock.bin` 含旧VRK的恢复包装，必须单独撤销。

## Admin入口与静止条件

在现有key命令组新增 `rekey key rotate-vrk --stdin-secrets`；stdin严格两行，依次为当前password、当前recovery key。无flag时分别从隐藏TTY读取，两者都必须提供。
本操作不更改password/recovery的值；它们只证明当前双因素并重新包装新VRK。不得接受argv/env/JSON metadata中的因素、desktop会话、单因素或“丢失恢复因素”兜底。
IPC新增一个Admin专用消息；编号在实施时选未占用值，不在规格中猜编号。metadata为空对象，body沿用现有双secret帧编码，首段必须标记password proof，第二段是recovery输入；响应body为空。
CLI仍是纯IPC客户端，负责严格输入/响应形状和隐藏输入；不链接crypto/SQLite。Agent调用这个消息必须拒绝，错误/日志不得回显任一输入。
Broker先获取现有lifecycle coordinator，然后检查phase恰为Locked、在途执行为零、terminal队列没有待提交项、没有stop pending；持有coordinator直到Authority确定结果。
Running时明确提示先显式lock，不由rotate-vrk自动drain、解锁或热切换；Draining/ShuttingDown、非零在途或pending terminal都拒绝，不偷跑清空工作。
正常lock已撤销capability sessions和approval challenges；检查失败不会开始解密。初始Locked启动也可执行，仍要满足零在途与terminal清空。
Worker独立检查自身仍是Locked；Faulted不得操作。整个命令不把局部VRK写入 `VaultState::Unlocked`，不调用unlock或任何会进入Running的辅助路径。

## 验证双因素与准备新密文

1. 沿用既有unlock退避计数/时钟门禁，读取各自唯一active password/recovery wrapper；分别derive KEK并unwrap到局部受保护RootKey。
2. 以常量时间比较两个候选旧VRK；任一因素错误、recovery格式错误或候选不一致统一拒绝，不暴露哪个因素通过。错误因素更新现有失败计数与拒绝审计，不生成新wrapper。
3. 用共同旧VRK验证header integrity、credential state seals、版本不变量和所有旧版本的认证密文；用 `verified_policy_material` 验证policy state/trust/bundle及它们的交叉摘要绑定。
4. 不要求策略在当前时间仍可执行才能重封装；已过期但完整性正确的bundle保持原到期时间，轮换不能使其重新有效。
5. 生成局部随机新VRK。按现有DEK切片逐版本处理旧DEK和payload：认证旧值、生成全新DEK/nonce、重加密同一payload、用新VRK包装新DEK。
6. 每次只持有一个版本的明文与旧/新DEK，及时零化；可累积替换密文，但不建立整库明文集合、不写临时明文文件、不输出凭证值。
7. 使用新VRK及新nonce重建全部credential state seals，以及存在的policy trust/bundle seals和必有的policy state seal；只换seal列，保留其认证的业务字段。
8. 用新VRK重建header integrity。生成两个新wrapper ID/salt/nonce，以同一输入password/recovery按现行KDF规则包装新VRK；不得复制旧wrapped VRK或生成新的恢复因素。
9. 在提交前计算新approval-origin公钥、所有计数、审计draft与可序列化回执内容；所有RNG、KDF、crypto、时钟与可能失败的准备工作在SQL提交前完成。

旧/新VRK、双因素、KEK、DEK、明文及派生origin seed均由Worker局部受保护所有权持有并在成功/失败路径销毁。
如需复用header integrity函数，仅提升现有helper的crate内部可见性，不复制AAD/KDF合同或添加通用密钥框架。

## 精确替换集合与不变量

| 对象 | 一次事务内允许改变 | 必须保持 |
| --- | --- | --- |
| 全部credential_versions | dek_nonce、wrapped_dek、payload_nonce、encrypted_payload | ID、version、kind关联、active/retired状态、AAD版本、suite、创建/retired时间及payload明文字节 |
| 全部credentials | state_nonce、state_ciphertext | label、kind、current_version、active/revoked状态和全部业务时间 |
| policy_state | seal_nonce、seal_ciphertext | flags、signer、highest_version、policy/bundle digest、updated_at |
| 已有policy_trust / policy_bundle | 各自seal_nonce、seal_ciphertext | 公钥、bundle原始JSON、版本、签名/摘要、安装/激活/到期时间；不存在的行不创建 |
| vault_header | integrity_nonce、integrity_ciphertext | vault ID、format/suite、created_at、schema_digest |
| key_wrappers | 两个旧active行禁用/清材料，插入两个新active行 | 旧记录身份与历史创建时间；每种恰好一个active |
| 审计 | 追加一条拟议 `vault.vrk_rotated` 成功事件 | 既有审计记录和序号语义 |

`workload_token_uses` 全部记录、replay digest、策略摘要、Action与版本以及其他业务行不得变化。
既有凭证插入/轮换helper会改变版本或状态，policy install/activate会改变生命周期甚至清replay；本流程都不调用。
旧wrapper按现行规则设置disabled时间并清零salt/nonce/wrapped VRK，不删除历史行；不清理原本已disabled的其他历史行。
空保险库也必须双因素验证，更新header、policy state seal与两个wrapper，提交一次成功审计，计数为零。

## desktop授权撤销的非原子边界

全部密文准备和双因素验证通过后、开始SQL写事务前，删除 `desktop-unlock.bin` 并fsync状态目录；文件已不存在也完成目录同步。
同步确认后清除Worker的desktop_session与desktop_resume_expiry，再进入SQL事务；保持Locked，后续不能自动记住本次双因素。
删除/fsync失败即明确报错，SQL不开始；为避免继续使用可能部分撤销的授权，清空内存desktop授权并沿用故障处理，不恢复旧文件。
文件系统与SQLite之间没有原子事务。若删除已持久成功但后续SQL失败、过期或进程崩溃，旧数据库/旧VRK可能仍在，但remembered授权已经撤销；这属于明确允许的单向副作用。
绝不通过把旧文件写回来补偿失败；用户必须重新显式输入因素。OS Keychain残留客户端ticket不授予恢复能力，服务端文件缺失时沿用现有拒绝，不在本操作额外操纵用户钥匙串。

## 单事务、deadline和确定结果

使用一个专用store事务更新上述全部密文/seal/header/wrapper并插入成功审计，不能串联当前DEK事务或两个replace_wrapper事务。
每个version/credential UPDATE必须恰好一行；header和policy_state各一行，存在的trust/bundle各一行；两个旧active wrapper更新各一行，两个新wrapper插入各一行。缺行/多行/计数不符视为完整性失败并回滚。
沿用25秒Admin mutation deadline；在取得coordinator、Worker排队/双KDF后、逐项准备过程中和SQL全部更新及成功审计插入后检查，最后一次紧邻commit之前。
precommit已过期返回现有 `AUTHORITY_BUSY` 并回滚全部SQL替换与成功审计；之前desktop撤销不回滚。不能通过抬高timeout或分批commit让大库绕过本合同。
一旦进入commit，Broker/Worker等待其确定返回，不套可取消timeout把已经提交的操作报告为Busy。客户端断连也不取消已接受的mutation。核实Admin connection外层shutdown选择分支：关闭连接只能产生未确认结果，不能发送确定失败而Worker仍在提交；不得用丢弃handler future冒充事务已撤销。
commit成功后只做无失败的内存header替换、成功计数复位与局部key销毁；仍保持Locked。不在此阶段生成随机数、重读数据库、派生公钥、写文件或追加第二条成功审计。
回执对象提前准备；响应编码/IPC发送失败属于“回执未送达”，不得推翻成功commit或再尝试回滚。SQLite commit报错时按既有审计/存储故障合同进入Faulted并停止服务，不能用内存继续猜测数据库generation。

## 错误、回执与崩溃语义

错误因素统一 `INVALID_UNLOCK_CREDENTIAL`，限速沿用 `UNLOCK_RATE_LIMITED`；非静止状态明确拒绝（Running提示先lock），Draining/停止和deadline沿用现有错误语义。
旧header/seal/payload损坏或行数不符触发完整性故障；不支持的crypto格式、熵源/时钟/存储错误明确失败。审计插入/commit失败沿用fail-closed，不静默跳过某条记录。
拟议成功回执包含vault ID、rotated_versions、resealed_credentials、`approval_origin: { algorithm: "ed25519", public_key: HEX }`和locked=true；仅非秘密metadata，无新的密码/recovery/VRK材料。
成功意味着当前库全部密文依赖已切到新VRK；原password和recovery值仍能分别解锁。回执中的origin公钥必须由操作者通过可信渠道重新钉扎，不自动更新外部审批者的信任配置。
旧session/challenge已因先前lock失效；旧origin信封在新公钥下不可通过。独立审批签名私钥/策略公钥不变，操作方需要重新prepare；不能把“签名者公钥没变”当作旧challenge仍可用。
SQL提交前崩溃：数据库保持完整旧generation；桌面恢复授权可能已撤销。SQL提交后崩溃：重启加载完整新generation、保持Locked；不存在混合generation的成功路径。
commit边界或响应丢失时调用方结果未知，不自动重试；先查持久轮换审计，再以现有可信解锁与 `approval origin` 核对当前公钥。再次显式调用会再轮换一次，不提供伪幂等保证。
完整旧备份仍可用其历史因素离线恢复，恢复后origin公钥也回到该备份generation。本操作不撤销旧备份、清理WAL/旧磁盘页、抹除已泄露旧密钥或撤销provider真实凭证。
同样的password/recovery值重新包装新VRK不修复因素本身泄露；如果需要换因素，另走已存在的密码/恢复密钥轮换。本文不添加兼容、迁移或额外恢复模式。

## 有限实施验收

1. 多credential kind、active/retired/revoked版本及空库：所有payload明文与业务元数据不变，全部目标密文/seals变化；新旧VRK分离的测试在测试进程内部完成，不导出真实密钥。
2. 两种因素分别错误、错recovery格式、两wrapper解出不同key、wrapper缺失、限速，以及Running/Draining/在途/pending-terminal条件拒绝；所有路径Worker未短暂Unlocked。
3. 未装policy、仅trust、已有bundle、过期bundle均正确重封装；存量workload replay与digest逐字节不变，已用workload token不能因轮换重用。
4. 后段坏payload、坏state/policy/header seal、晚期SQL失败、审计失败、precommit过期：完整SQL回滚，无成功事件；commit开始后时限经过仍等待确定结果。
5. desktop文件删除失败、目录fsync失败、文件缺失，以及删除成功后SQL失败：无旧ticket恢复；清空内存授权，错误与允许副作用可见。
6. 合成库在desktop删除后、precommit、commit后回执前SIGKILL；重启仅见完整旧或新generation，保持Locked，回执丢失不触发自动重试。
7. 成功后password/recovery独立解锁、锁定重启、前后备份分别恢复；检查新origin公钥、旧session/challenge拒绝及重新钉扎后的独立签名链路。
8. Admin/Agent消息边界、CLI两行stdin/隐藏TTY、秘密canary不进argv/env/metadata/日志/审计；响应错误不展示任何secret。

以上只用临时保险库、合成因素和受控故障；不访问真实 `~/.rekey`，不替换用户运行服务。实施后需授权/秘密处理的人工审查及父任务统一全量验证。
本次只交付规格并运行cargo check；这不构成VRK轮换已实现的证明。
