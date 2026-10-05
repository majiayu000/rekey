# v3 发布与一周自用

当前代码基线：PR [#62](https://github.com/majiayu000/rekey/pull/62) 的 `5de61bf`。
2026-10-05 用户授权合并和发布 alpha，并明确先跳过新版 App 真机三项。
停止新增功能；只处理已证实的安全、正确性和发布阻塞。

## 格式与边界

vault / backup **25**、policy snapshot **6** 已冻结，覆盖所有 v3 预发布和正式版本，
包括 lab。保持持久布局及规范化签名语义；不兼容变化进入 v4，不添加迁移或双读。
依据：[SPEC §9.3](superpowers/specs/2026-10-02-rekey-v3-personal-first.md#93-发布与格式不向后兼容)。

这次是 alpha。新版认证复用后的实际弹窗次数、明文失焦清除、审批可见取消和
SMAppService 生命周期均**用户暂缓、未验证**；T12 仍暂缓。
独立 agent 审查与外部人工审计分别记录，L1/L2 不因发布提升。

## 交付进度

PR #62 已合并到 main（`fa7905a`），最终源码九项 CI 全绿。alpha.1 发布流程在 macOS Swift 编译时失败；保留原 tag，修复构建后曾以 alpha.2 重新尝试，持久格式不变。

alpha.2 已通过签名、公证和安装后的 P0；共享验收将归档 Python 工具误套到 App，发布因此阻止。修正检查入口后顺延 alpha.3，两次旧 tag 均保留。

下表是 alpha.3 tag 推送前的检查快照；公开发布及下载验收的当前结果以
[GitHub release](https://github.com/majiayu000/rekey/releases/tag/v3.0.0-alpha.3)
和对应 release workflow 为准。

| 项目 | 状态 / 证据 |
|---|---|
| 停止扩展、冻结 vault25 / policy6 | 已写入 SPEC、AGENTS 与公开基线 |
| relay 移出默认编译 | 已存在：无 lib；bin / test 的 required-features 均为 lab；无需新增代码 |
| 安全核心审查 | 独立只读 reviewer 完成初审和修复复核，两项问题已关闭；范围为 presence / 签名 / gateway / 遮蔽 / 审批 / DoH；结果见[审查记录](evidence/v3-security-core-review-2026-10-05.md) |
| PR 当前 CI | PR #62 最终 head 339047a 九项全绿；本机完整 workspace 1033 passed / 0 failed / 6 ignored，default/lab all-targets 与严格 Clippy 通过。PR #63 的 alpha.2 修复九项全绿并合并（f9f674a）；alpha.3 验收入口修复须通过新 PR CI |
| 新版 App 真机三项、T12 | 用户暂缓；不能填“通过” |
| 公开发布 | 未完成；必须用 main 上的最终提交触发既有 release workflow |
| GitHub 签名配置 | 已使用现有签名材料补齐 Installer certificate / password / identity、App / daemon profile 五项；未覆盖已有六项，未输出任何凭据值 |
| 自用一周 | 尚未开始；下面的每日记录由真实工作填写 |
| 3–5 人试用 | 一周反馈后再邀请；未联系任何人 |

已有本地包 SHA-256：
`29c82c7ed634e2c04b0a3f42a23ffbffa2160d77905f3f2cd40631877dc944e6`。
这是当前账户已安装的候选，不是公共 release 下载证明。
旧候选 GLM / Claude Code / Codex / MCP 与 SE 签署实测见
[统一证据](evidence/v3-release-acceptance-2026-10-04.json)；
不能扩展为真实 Anthropic / OpenAI / GitHub 已验收。

## 发版顺序

1. 当前 head 必需 CI 通过，关闭安全审查中确认的阻塞问题。
2. 合并当前修复 PR（#62 已合并；仓库 ruleset 仅允许 squash），取实际 main 提交；不强推 main。
3. 核对 Cargo 版本与 `v3.0.0-alpha.3` 一致，确认 tag 不存在，再把 tag 指向该 main 提交。
4. 用既有 release workflow 构建、签名、公证、验证 provenance / SBOM、
   fresh-install 并发布；公共 URL smoke 失败时沿用现有撤回机制。
5. 记录 tag、main 提交、workflow URL、公开下载 URL、checksum 及最终 smoke 状态。
   本地 pkg、公证或 tag 创建均不单独算“发版完成”。

## 一周自用

用正常开发任务启动 Claude Code；逐渐覆盖真实 Anthropic 与 GitHub，
不要为凑天数重复发送合成请求。真实服务凭据通过 App 管理，记录中不粘贴 Key、
capability、证明、原始请求/响应或项目机密。尚未登记的 provider 保持未验。

第一次只记录实际设置过程：耗时、步骤、密码输入次数、系统认证次数；
后续每天记启动与卡住之处。当前命令仍要求显式指定 Profile、client 和模型：

```sh
rekey --version
rekey status --passive --state-dir /absolute/path/to/v3-state
rekey profile list --state-dir /absolute/path/to/v3-state
rekey run PROFILE --state-dir /absolute/path/to/v3-state --client claude-code -- claude --model MODEL_ID
```

PROFILE、MODEL_ID 必须来自本人已审阅的签名授权，不能猜测或扩权。
本机默认 `~/.rekey` 有须保留的旧库/daemon，先用已经确认的独立 v3 目录；
该自用方式不证明默认登录项生命周期。若网络返回 fake-IP，只使用明确配置过的
`REKEY_DOH_URL`；不要放宽公网检查。

| 天 | 日期 / 版本 | 实际任务与 provider | 密码次数 | 系统认证次数 | 卡住次数 / 额外操作 | 完成情况 |
|---|---|---|---|---|---|---|
| 1 | 待开始 | | | | | |
| 2 | | | | | | |
| 3 | | | | | | |
| 4 | | | | | | |
| 5 | | | | | | |
| 6 | | | | | | |
| 7 | | | | | | |

每天补一段，复制下面的模板即可：

> 日期 / tag / commit / 安装来源：
>
> 真实任务（只写概述）/ 客户端 / provider / 已批准模型：
>
> 启动到首个成功结果：___ 秒；正常工作：___ 分钟。
>
> 密码输入：___ 次；Touch ID 或系统认证：___ 次（逐次说明用途）。
>
> 卡住的位置 / 可见错误码 / 额外操作：
>
> 今天是否用了真实 Anthropic / GitHub：是 / 否；若否，原因：
>
> 审批允许 / 拒绝 / 取消后结果，是否需重提：
>
> 明文显示后失焦观察（未做填未测，不以掩码初始状态代替）：
>
> 退出后 `status --passive` 的会话数 / 用量结算观察：
>
> 本日最想删掉的一步：

首次设置另记：总耗时 ___ 分钟、操作 ___ 步、密码 ___ 次、系统认证 ___ 次；
记录到首个真实成功结果结束，不能只计三条终端命令。

## 第七天收敛与试用

根据实际记录选最影响使用的一项，不提前写推断逻辑或新配置。
候选顺序：首次设置压到一次密码输入；根据已签名 Profile 与启动命令推断 client / 模型，
有歧义时明确失败；relay 已在 lab，仅确认默认产物没有它。
这些仍是待反馈决策，不是本轮功能实现任务。

复查全部未测项，记录完成或继续暂缓的理由。然后找 3–5 位日常用 Agent、
愿意提供简短反馈的开发者；优先不同客户端或安装习惯。
名单与联系方式保存在本人私有位置，不写入公共仓库。邀请草稿：

> 我在做 Rekey，让 Claude Code / Codex 使用授权的 API 操作，Agent 接触不到上游 Key。
>
> 目前是 alpha，格式已冻结，仍有明确标出的设备验收限制。想请你按自己的正常任务
>
> 试用一周，记录设置耗时、每次认证和卡住的位置。先用低权限的测试凭据，
>
> 不需要把任何 Key 发给我。你愿意的话，我会发安装链接与这份记录模板。

只有公开包下载检查通过、本人一周反馈完成后才发送邀请。
未发送消息，也没有把试用或 T12 记为完成。
