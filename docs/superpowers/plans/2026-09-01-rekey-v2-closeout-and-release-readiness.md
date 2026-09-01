# Rekey v2 收尾与发布就绪验收清单

> 状态：执行中
>
> 建立日期：2026-09-01
>
> 适用分支：`codex/full-system-fix-20260407`
>
> 对应 PR：[majiayu000/rekey#10](https://github.com/majiayu000/rekey/pull/10)
>
> 行为规范：[Credential Authority v2 Foundation](../specs/2026-08-28-credential-authority-v2-foundation.md)

## 1. 目的

本文档是 Rekey v2 Foundation 从当前开发分支走到“可合并、可公开 Alpha、可继续产品化、可评估企业化”的唯一收尾执行清单。它记录尚未完成的工作、每项工作的验收标准、所需证据和阻塞关系。

本文档不替代 Feature Truth Matrix。功能状态仍以 `docs/product-foundation/feature-truth-matrix.md` 为唯一事实源；本文档只回答以下问题：

1. PR #10 合并前还必须完成什么。
2. 公开 Alpha 发布前还必须完成什么。
3. 哪些安全与可靠性能力需要继续补强。
4. 哪些属于后续产品或企业路线，不得误报为已经完成。
5. 哪些是 v2 明确删除的旧能力，不得重新混入范围。

## 2. 范围纪律

### 2.1 当前范围

- v2 Foundation 是本地 Credential Authority，不是透明代理。
- Agent 只能调用管理员预先注册的固定 HTTPS Action。
- Agent API 永远没有读取、导出或返回真实 Secret 的接口。
- 默认同用户本地拓扑只承诺 G1。
- Linux container/namespace 仅有一个有界 G2 reference，不代表通用 G2 产品。
- 当前公开实现以 macOS 和 Linux 为范围，Windows 不受支持。
- v1 数据、CLI、代理拓扑和系统 CA 不迁移、不兼容。

### 2.2 不得借收尾扩大范围

以下能力只有在单独批准新阶段后才可实施：

- 通用 Connector SDK。
- SaaS 或企业控制面。
- 多租户、SSO、SCIM、HA、SIEM。
- 外部 Vault/KMS/HSM 集成。
- macOS G2、通用 Linux G2 或 Windows。
- 任意 URL 凭据代理、透明 MITM、系统 CA、TCP passthrough。
- Agent 可见的流式响应、SSE、自动重试或 redirect。

### 2.3 文档边界

M-03 已批准公开跟踪 `feature-truth-matrix.md` 和 `threat-model-v2.md` 两份技术基线。`north-star-and-positioning.md`、`enterprise-architecture-v2.md` 和 `oss-enterprise-boundary.md` 继续作为本地、未跟踪研究资料；不得被公开仓库规则或行为文档依赖。

## 3. 状态与证据规则

### 3.1 清单状态

每项任务只能使用以下状态：

| 状态 | 含义 |
| --- | --- |
| `[ ]` | 未开始、未验证或证据已失效 |
| `[~]` | 正在执行；不得视为通过 |
| `[x]` | 验收命令和人工检查均通过，证据已记录 |
| `[!]` | 已阻塞；必须记录阻塞原因、负责人和解除条件 |
| `[-]` | 经书面决策取消；必须记录原因，不能静默删除 |

### 3.2 验收证据最低要求

一项工作只有同时满足以下条件，才可以标为 `[x]`：

- 验收发生在最终修改之后。
- 命令、环境、提交 SHA、日期和结果可追溯。
- 自动化检查必须给出进程退出码或 GitHub Actions 结论。
- 人工安全检查必须给出 Reviewer、范围、findings 和处置结果。
- 不得用“之前通过”“应该没问题”“本地看起来正常”代替当前证据。
- 文档声明必须与 Feature Truth Matrix 的能力等级一致。
- 任何安全验收不得泄漏密码、recovery key、私钥、JWT、token 或凭据正文。

推荐将完成证据填写为：

```text
完成日期：YYYY-MM-DD
提交：<full SHA>
执行环境：<OS/arch/toolchain>
命令或 Review：<exact command / review URL>
结果：PASS / APPROVED
证据：<CI URL / PR review / report path>
遗留限制：<none or explicit limit>
```

### 3.3 阶段定义

| 阶段 | 含义 | 完成条件 |
| --- | --- | --- |
| M | PR 合并门 | M-01 至 M-10 全部完成，PR 非 Draft，required checks 全绿并获批准 |
| A | 公开 Alpha 门 | M 阶段完成，A-01 至 A-11 全部完成，真实发行物安装验收通过 |
| H | 安全补强 | H 项按公开承诺所需范围完成或被明确接受为残余风险 |
| P | 后续产品能力 | 必须有独立 spec、实现、测试和 Feature Truth Matrix 状态提升 |
| E | 企业就绪 | 技术、安全、运营和商业四类门槛全部满足 |

## 4. 2026-09-01 现状快照

本节是建立清单时的静态快照，不自动代表未来状态。

| 项目 | 当前事实 | 判定 |
| --- | --- | --- |
| HEAD | `8202b51f9a10696972af70f4b09dd6a9b221d2cc` | 与远端功能分支一致 |
| 分支差异 | 相对 `origin/main`：0 behind / 52 ahead | 尚未合并 |
| 建表时工作区 | `docs/product-foundation/` 与本 closeout 文档未跟踪 | M-03 决定只公开两份技术基线和本清单 |
| PR #10 | Open、Draft、MERGEABLE | 尚不可进入正式 Review 结束态 |
| PR 规模 | 157 files，+27,856 / -3,950 | 大型安全重写 |
| Review | 无 Reviewer、无正式 Review、无 Approved | 阻塞合并 |
| 最新 CI | [run 33502567132](https://github.com/majiayu000/rekey/actions/runs/33502567132) | Ubuntu、macOS、Linux G2 reference 全绿 |
| 版本 | `2.0.0-dev` | 未进入正式发行版本 |
| Release | 无 tag、无 GitHub Release | 未发布 |
| 历史 | 52 commits；19 个含 sign-off；3 个 merge commit | 需 DCO/历史整理 |
| 主分支保护 | 无 branch protection、无 ruleset | 需治理 |
| 安全设置 | secret scanning 和 push protection 已启用 | 正向证据 |
| 依赖安全 | Dependabot security updates 未启用 | 需决策 |
| 仓库描述 | 仍描述为 v1 single-binary MITM proxy | 与 v2 冲突 |
| 产品基线 | 本地存在，Git 中不存在；tracked docs 有引用 | 远端存在断链风险 |

最新 CI 全绿是正向证据，不代表 M 阶段已经完成。规范一致性、人工 Review、文档边界、提交历史和 PR 治理仍是独立门槛。

## 5. M 阶段：PR #10 合并门

### M-01 决定并统一密码修改与恢复合同

**状态：** `[x]`　**优先级：** 阻塞合并　**依赖：** 无

**决定：** Foundation 不承诺修改密码、恢复后设置新密码或 wrapper 替换。recovery key 只用于解锁运行中的 Broker 或验证离线 backup restore；完整密码生命周期保留在 P-01。

**问题：** Foundation spec 宣称密钥层级支持 password change/recovery，并规定 `recover` 成功后创建新 password wrapper、禁用旧 wrapper；当前产品只有使用 recovery key 解锁，没有修改密码、恢复后换密或 wrapper 替换命令。

**必须完成：**

- [x] 明确 Foundation 不承诺“恢复后设置新密码”和“修改密码”。
- [x] 删除超出 Foundation 的承诺，不新增密码生命周期实现。
- [x] 同步 Foundation spec、threat model、README、Feature Truth Matrix 和 CLI help。
- [x] 在公开限制中明确 recovery key 当前只用于解锁/恢复备份，不等于密码重置流程。
- [x] 在最终提交 SHA 上记录验证证据。

**验收标准：**

1. `rg -n 'password change|change password|recover|password wrapper|recovery wrapper' README.md docs crates tests` 的每处行为性声明都能映射到现有命令和测试，或被明确标为未来能力。
2. CLI help、IPC message、AuthorityCommand 和 spec 不再互相矛盾。
3. 若采用“暂不实现”，不存在任何用户会合理理解为现已支持换密/重置密码的表述。
4. 若采用“实现”，至少覆盖成功、错误旧密码、错误 recovery key、审计失败、数据库提交失败、进程中断和旧 wrapper 失效。
5. 完成后的行为已更新到 Feature Truth Matrix，但状态不超过实际证据等级。

**证据：** spec diff、CLI help、对应测试命令和结果；若删除承诺，附决策说明。

- 完成日期：2026-09-01
- 提交：`65c2ae608de10eeccc806926f8534c79ffa4c3ac`
- 执行环境：macOS arm64；rustc 1.95.0；cargo 1.95.0
- 命令或 Review：`cargo check --workspace`；`cargo test -p rekey-cli --test cli_blackbox`；`cargo test --workspace`；行为声明搜索
- 结果：PASS
- 证据：Foundation spec、Threat Model、Feature Truth Matrix、README 和 CLI help 已统一为 recovery unlock/restore-only
- 遗留限制：密码修改、重置和 wrapper 替换保留在 P-01

### M-02 统一秘密 stdin 参数名称

**状态：** `[x]`　**优先级：** 阻塞合并　**依赖：** M-01

**决定：** 正式参数为实现和测试已使用的 `--stdin-secrets`；不增加 `--secret-stdin` alias。

**问题：** spec 和 `rekeyd` 注释使用 `--secret-stdin`，实际 credential add/rotate 使用 `--stdin-secrets`。

**必须完成：**

- [x] 选定唯一正式参数名 `--stdin-secrets`。
- [x] 同步 CLI、测试、spec、README 和注释。
- [x] 不增加兼容 alias；v2 是 breaking rewrite。
- [x] 在最终提交 SHA 上验证秘密仍不允许通过 argv value 或环境变量传递。

**验收标准：**

1. `rg -n -- '--secret-stdin|--stdin-secrets' README.md docs crates tests` 只出现正式名称和必要的否定性测试。
2. `rekey credential add --help` 与 `rekey credential rotate --help` 展示相同合同。
3. `cargo test -p rekey-cli --test cli_blackbox` 通过。
4. canary 检查证明密码和 Secret 不出现在 argv、环境、日志和审计 metadata。

**证据：** 搜索结果、CLI help 摘要、测试输出。

- 完成日期：2026-09-01
- 提交：`65c2ae608de10eeccc806926f8534c79ffa4c3ac`
- 执行环境：macOS arm64；rustc 1.95.0；cargo 1.95.0
- 命令或 Review：add/rotate `--help`；`cargo test -p rekey-cli --test cli_blackbox`；`cargo test --workspace`；机械 API 搜索
- 结果：PASS
- 证据：add/rotate 均显示 `--stdin-secrets` 和相同两行输入合同；`secret_canary` PASS；无 `--secret-stdin`
- 遗留限制：none

### M-03 决定 product-foundation 文档边界并消除远端断链

**状态：** `[x]`　**优先级：** 阻塞合并　**依赖：** 无

**决定：** 采用受限的方案 A：公开跟踪 Feature Truth Matrix 与 Threat Model；三份产品、企业和商业研究继续保留在本地。公开文件不得链接或依赖这三份本地资料。本 closeout 清单一并进入 Git，供 PR Review 使用。

**问题：** README、AGENTS、CLAUDE 和 Foundation spec 把 `docs/product-foundation/*.md` 当作正式依据，但这些文件按当前边界保留在本地且未进入 Git。

**允许方案：**

- 方案 A：批准并提交经过公开审查的基线文档。
- 方案 B：继续保持本地研究边界，把所有公开所需的行为和限制移入 tracked spec/README，并删除或替换所有远端断链。

**执行项：**

- [x] 将公开行为事实收敛到 Feature Truth Matrix、Threat Model、Foundation spec 与 README。
- [x] 删除公开文档和仓库规则对三份本地研究资料的链接与依赖。
- [x] 保留三份本地研究文件，不纳入本轮提交。
- [x] 在最终提交中纳入两份技术基线和本清单，并记录链接检查证据。

**验收标准：**

1. 远端默认分支上的每个相对 Markdown 链接都能解析到已跟踪文件。
2. AGENTS/CLAUDE 中不存在依赖未跟踪文件才能执行的仓库规则。
3. Feature Truth Matrix 的“唯一状态源”要么被正式跟踪，要么其必要状态进入另一个明确的 tracked canonical file。
4. 本地研究文档若继续不跟踪，`git status` 中的状态和保留方法已明确，不会在历史整理中丢失。
5. 没有未经批准把商业研究、品牌策略或企业路线公开到仓库。

**建议验收命令：**

```bash
git ls-files docs/product-foundation
rg -n 'docs/product-foundation|product-foundation/' README.md AGENTS.md CLAUDE.md docs
```

**证据：** 边界决策、最终 `git ls-files`、链接检查结果。

- 完成日期：2026-09-01
- 提交：`65c2ae608de10eeccc806926f8534c79ffa4c3ac`
- 执行环境：macOS arm64
- 命令或 Review：7-file relative Markdown link check；`git ls-files docs/product-foundation`；公开文件敏感模式扫描
- 结果：PASS
- 证据：Git 只跟踪 Feature Truth Matrix 与 Threat Model；全部相对链接存在；本清单已跟踪
- 遗留限制：三份产品、企业和商业研究继续在本机保持未跟踪

### M-04 完成独立密码学与持久化 Review

**状态：** `[x]`　**优先级：** 阻塞合并　**依赖：** M-01

**Review 范围：**

- Argon2id 参数和 password/recovery proof 边界。
- HKDF、VRK、DEK、wrapper 和 zeroization。
- AEAD nonce、84-byte binary AAD、format discriminator。
- credential lifecycle metadata seal。
- SQLite STRICT schema、WAL、`synchronous=FULL` 和事务原子性。
- init incomplete marker、backup receipt、restore marker。
- 完整数据库快照回放的 G1 残余风险。

**验收标准：**

1. Reviewer 不是本轮主要实现者。
2. Review 记录列出检查文件、威胁假设和攻击面。
3. Critical/High findings 为 0；Medium findings 已修复或有明确风险接受和期限。
4. 每项修复后重新运行相关 vault tests、durability harness 和 workspace gate。
5. Review 不把完整数据库回放防护误报为已实现。

**证据：** PR Review 或独立报告路径、findings ledger、修复 SHA、测试链接。

- 完成日期：2026-09-01
- 修复提交：`3b2b3e60cd8b787678871de03a75671b8b534460`
- Reviewer：Codex 当前 closeout-review 会话；独立于既有核心实现，但不是第三方人工审计
- Review：[v2 closeout security review](../../security/2026-09-01-v2-closeout-independent-review.md)
- 结果：PASS；Critical 0、High 0、Medium 1 fixed / 0 open、Low 0 open
- 验证：`cargo test -p rekey-vault`、`scripts/p0-acceptance.sh`、`scripts/p0-durability.sh`、`cargo test --workspace`、`cargo audit`
- 遗留限制：完整有效数据库快照回放在 G1 中仍不可检测，未误报为已实现

### M-05 完成独立 IPC、身份与生命周期 Review

**状态：** `[x]`　**优先级：** 阻塞合并　**依赖：** 无

**Review 范围：**

- admin.sock / agent.sock 分离和权限。
- frame length、message type、request/response binding。
- peer UID/GID 和 replaceable ancestor 防护。
- capability token 生命周期、使用次数、过期和重启撤销。
- lock、idle lock、shutdown、drain、execution supervisor。
- Agent disconnect、panic、partial frame、EMFILE 和 cancellation。
- 默认 G1 与有界 Linux G2 的声明边界。

**验收标准：**

1. Agent surface 无 admin mutation、Secret read/export 或任意 message downgrade。
2. forged broker response、错误 channel/request ID、超限 frame 均明确拒绝。
3. stop 后不再接纳新的 remote effect；已接纳 effect 的 terminal audit 语义明确。
4. Critical/High findings 为 0；其余 findings 有处置。
5. Reviewer 明确确认 G2 证据不能外推到默认部署、macOS、宿主 root 或内核攻击者。

**证据：** Review 记录、相关测试和 CI run。

- 完成日期：2026-09-01
- 修复提交：`3b2b3e60cd8b787678871de03a75671b8b534460`
- Review：[v2 closeout security review](../../security/2026-09-01-v2-closeout-independent-review.md)
- 结果：PASS；Critical 0、High 0、Medium 1 fixed / 0 open、Low 2 fixed / 0 open
- 验证：`cargo test -p rekey-broker`、`cargo test -p rekey-cli --test malicious_broker`、`cargo test --workspace`；Linux G2 仍以 CI reference job 为限
- 遗留限制：本报告不是 M-10 所需的独立 GitHub `Approved`；G2 证据不外推到默认部署、macOS、host root 或内核攻击者

### M-06 完成独立执行、SSRF、Secret Sealing 与 GitHub App Review

**状态：** `[x]`　**优先级：** 阻塞合并　**依赖：** 无

**Review 范围：**

- fixed origin/method/path normalization。
- DNS 解析、public IP 筛选、IPv4/IPv6/NAT64/6to4。
- TLS SNI、redirect disabled、proxy env ignored。
- Header allowlist、body/response bounds、truncation。
- raw/base64/base64url/percent sealing 和 chunk boundary。
- GitHub JWT、installation token scope、revoke-before-success。
- `execution.started`、connector audit、terminal audit 的顺序和错误语义。

**验收标准：**

1. Clash/TUN Fake-IP 被拒绝被记录为预期安全行为，并提供可执行排查文档，不通过放宽私网限制解决。
2. 所有 redirect、private/reserved IP、超限或截断响应均 fail closed。
3. Secret Sealing 命中后 Agent 只得到一个空错误响应，不得到 partial/trailing bytes。
4. GitHub token 无论成功、失败、disconnect 或 SIGTERM 都按合同 revoke 或返回明确 indeterminate。
5. Critical/High findings 为 0；其余 findings 有处置。

**证据：** Review 记录、攻击测试、live provider 证据范围说明。

- 完成日期：2026-09-01
- 修复提交：`3b2b3e60cd8b787678871de03a75671b8b534460`
- Review：[v2 closeout security review](../../security/2026-09-01-v2-closeout-independent-review.md)
- 结果：PASS；Critical 0、High 0、Medium 0 open、Low 1 fixed / 0 open
- 验证：`scripts/p0-acceptance.sh`、`scripts/p1-streaming-sealing.sh`、`scripts/p2-github-app.sh`、`upstream_screened`、`reflected_secret`
- 遗留限制：live provider 证据仍只限 Feature Truth Matrix 记录的一次 disposable GitHub App/repository；不是通用 Connector 或发布证据

### M-07 修正 PR 描述和证据陈述

**状态：** `[x]`　**优先级：** 阻塞 Ready for review　**依赖：** M-04 至 M-06

**必须完成：**

- [x] 删除“live GitHub App pending”。
- [x] 删除“required systemd CI pending”。
- [x] 不再维护易过期的单一测试总数。
- [x] 将“local independent security ledger”改为真实、可证明的 Review 状态。
- [x] 链接最新 required CI。
- [x] 写明默认 G1、有界 Linux G2 和单一 GitHub provider 证据范围。
- [x] 列出未实现能力和已知限制。

**验收标准：**

1. PR body 的每个完成声明都有当前 SHA 的证据。
2. 不再把本地测试、Field Validation、Released 混为一谈。
3. Reviewer 只看 PR body 就能知道变更范围、验证、风险和明确非目标。
4. PR body 不引用本地未跟踪、远端无法访问的证据。

**证据：** 最终 PR body URL 和快照。

- 完成日期：2026-09-01
- PR：[PR #10](https://github.com/majiayu000/rekey/pull/10)
- PR body head：`75c5edc9f59d7752cc71d3b8d8204890c235d8fe`
- 最新 CI：[security-gate run 33513840039](https://github.com/majiayu000/rekey/actions/runs/33513840039)
- 结果：PASS（PR 陈述验收）；CI 结论由 M-10 在最终 SHA 单独判定
- 遗留限制：PR 仍为 Draft，待最终 CI 后切换 Ready for review

### M-08 整理 DCO 与提交历史

**状态：** `[~]`　**优先级：** 阻塞合并　**依赖：** M-01 至 M-07

**决定：** 使用 GitHub signed squash merge。功能分支不做 rebase、历史改写或 force-push；M-10 合并时创建唯一进入 `main` 的 squash commit，并在 commit body 写入有效 `Signed-off-by:`。这样保留 PR 中的完整开发历史和作者记录，同时避免把 3 个开发期 merge commit 或未签名中间提交带入 `main`。

**当前问题：** 52 个分支提交中仅 19 个检测到 `Signed-off-by:`，并存在 3 个 merge commit。历史改写属于高风险动作，必须另行确认后执行。

**必须完成：**

- [x] 确定 signed squash 策略。
- [x] 记录合并前 tree SHA，PR 保留完整开发历史和作者记录。
- [ ] M-10 执行 squash 后确认 `main` 只新增一个无 merge parent 的提交。
- [x] 不改写工作树；三份本地未跟踪 product-foundation 文档保持原状。
- [-] 不执行历史改写或 force-push；signed squash 不需要该步骤。

**验收标准：**

1. 最终合并策略符合仓库 DCO 和历史约定。
2. 进入 `main` 的每个最终提交或唯一 squash commit 含有效 sign-off。
3. `git diff <pre-rewrite-tree>..<post-rewrite-tree>` 不出现未解释的内容变化。
4. `git rev-list --merges origin/main..HEAD` 为空，除非某个 merge 有书面保留理由。
5. 改写后完整 CI 重新通过，旧 CI 不作为完成证据。

**证据：** 改写前后 tree SHA、DCO 检查、最终 log、最新 CI。

- 策略确认日期：2026-09-01
- 合并前 tree：`4878f8bfb8b1a8dbb79b26a3e07f54319f02513b`
- GitHub 设置：仓库允许 squash merge
- 书面保留理由：3 个 merge commit 仅保留在合并后可删除的功能分支，用于 PR 开发溯源；signed squash 不会把它们带入 `main`
- 待完成：M-10 的实际 squash SHA、DCO trailer、tree 等价性和 main CI

### M-09 处理旧 PR #9 和 v1 遗留队列

**状态：** `[x]`　**优先级：** 合并前建议　**依赖：** M-08

**验收标准：**

1. PR #9 的每个有效变更已与 v2 当前代码比对。
2. 若无剩余价值，PR #9 被标记为 superseded 并关闭。
3. 若仍有有效修复，只重新实现适用于 v2 的最小部分，不整体合并 v1 拓扑。
4. 没有开放 issue/PR 继续把 MITM、CA、dashboard 或 passthrough 当作当前产品事实。

**证据：** PR #9 最终状态、比对说明或对应 v2 修复 SHA。

- 完成日期：2026-09-01（先于 M-08 完成，不涉及历史改写）
- PR 状态：[PR #9](https://github.com/majiayu000/rekey/pull/9) 已标记 superseded 并关闭
- 比对：PR #9 的 CI、`rekey-ca`、`rekey-proxy` 和 v1 CLI 修复均已由 v2 workspace/安全门替代，不整体合并 v1 拓扑
- 队列复查：开放 PR 仅 #10；开放 issue 为 0；没有其他开放项继续把 MITM、CA、dashboard 或 passthrough 当作当前产品事实
- 遗留限制：M-08 若改变最终 tree，须重新确认本项内容比对仍成立

### M-10 最终合并验收

**状态：** `[ ]`　**优先级：** 最终门　**依赖：** M-01 至 M-09

**本地验收命令：**

```bash
cargo fmt --all --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
rg -n 'REKEY_PASSWORD|get_secret_value|/proxy/|passthrough' crates tests src
rg -n 'get_secret\b|read_secret|export_secret' crates/rekey-domain crates/rekey-broker crates/rekey-cli
cargo tree -p rekey-cli -e normal
git diff --check
```

机械搜索的通过条件是无禁用项匹配；dependency tree 的通过条件是 CLI 不包含 rusqlite、aes-gcm、argon2、reqwest、rekey-vault 或 rekey-broker。

**最终验收标准：**

1. 所有本地命令在最终 SHA 上通过。
2. required GitHub Actions 在最终 SHA 上通过。
3. PR 已取消 Draft。
4. 至少一个独立 Reviewer Approved。
5. 所有 Review conversation resolved。
6. PR 状态为 mergeable，无过期 required check。
7. 产品基线和 README 不存在已知断链或过度声明。
8. 合并后 `main` 再次运行 CI 并通过。

**证据：** 最终 SHA、PR approval、CI run、merge commit/squash SHA、main CI。

## 6. A 阶段：公开 Alpha 发布门

### A-01 冻结 Alpha 范围与版本

**状态：** `[ ]`　**依赖：** M 阶段完成

**必须决定：**

- 版本号：推荐 `2.0.0-alpha.1`，不得继续发布为 `2.0.0-dev`。
- 支持 OS/arch。
- 预编译二进制、crates.io、Homebrew 等分发渠道。
- 默认安全等级和 Linux G2 reference 的展示方式。
- 不兼容升级、回滚和支持期限。

**验收标准：**

1. Cargo version、CLI `--version`、tag 和 Release 名称一致。
2. 支持矩阵明确写出 tested、experimental、unsupported。
3. Windows、macOS G2 和通用 Linux G2 不被暗示支持。
4. 每个承诺平台都有最终发行物测试计划。

### A-02 补齐 release workflow

**状态：** `[ ]`　**依赖：** A-01

**验收标准：**

1. tag 触发 workflow，普通 branch push 不发布。
2. 发布前执行完整 security gate。
3. 为每个目标生成 release-mode `rekey` 和 `rekeyd`。
4. 生成 SHA-256 checksums、SBOM 和 provenance/attestation。
5. 发行物签名可由公开步骤验证。
6. 任一平台失败时 Release 不标记为正式可用。
7. workflow actions 固定到 commit SHA。
8. secrets 权限最小化，日志不输出 token 或签名材料。

### A-03 从发行物完成 fresh-install 验收

**状态：** `[ ]`　**依赖：** A-02

**验收场景：**

- 干净 macOS 用户环境。
- 干净 Ubuntu 非 root 服务账户。
- 每个承诺架构至少一次。

**验收标准：**

1. 只使用下载的发行物，不使用仓库 `target/`。
2. checksum 和签名验证通过。
3. 完成 init、serve、unlock、credential add、action create、session create、execute、lock、backup、restore、shutdown。
4. 默认权限满足 state/admin/agent socket 合同。
5. 卸载后无运行进程或遗留 service；保留/删除数据由用户明确选择。

### A-04 产品化安装与卸载

**状态：** `[ ]`　**依赖：** A-01

**验收标准：**

1. README 提供每个支持平台的复制即用安装步骤。
2. 用户能确认安装的二进制版本和路径。
3. 升级只替换明确文件，不破坏 vault。
4. 卸载分别说明“保留数据”和“删除数据”。
5. 安装脚本若存在，禁止静默 sudo、远程执行未校验脚本或覆盖非 Rekey 文件。

### A-05 产品化 service manager 流程

**状态：** `[ ]`　**依赖：** A-03

当前 `scripts/rekey-service-unit.py` 只负责生成定义，不构成完整安装体验。

**验收标准：**

1. launchd 和 systemd 都有安装、启动、状态、日志、停止、重载、升级和卸载说明。
2. service 文件路径、用户、组、state dir、runtime dir 和 socket 权限明确。
3. Linux G2 所需 UID/GID/runtime-dir 参数可以被正确配置和验证。
4. locked boot、unlock、SIGTERM drain、Admin shutdown、crash restart 均在发行物上通过。
5. `rekey serve` 与 `rekeyd serve` 的职责不产生误导。

### A-06 完成用户文档

**状态：** `[ ]`　**依赖：** M-03、A-03

**README/指南至少覆盖：**

- 安装、初始化和一次性 recovery key 保存。
- 安全输入密码和 Secret。
- credential、action、policy、session、execute 全流程。
- lock、idle lock、status、shutdown。
- backup、receipt、SHA-256 和 restore。
- GitHub App closed profile。
- policy JSON 和 action JSON 完整示例。
- 错误码和常见失败。
- Clash Fake-IP 被 SSRF 防护拒绝的原因和排查。
- G1/G2 边界、host root/ptrace/direct egress 残余风险。
- response sealing 的具体覆盖和不覆盖范围。

**验收标准：**

1. 新用户在不阅读源码的情况下能完成一次真实固定 Action。
2. 所有命令均从 release artifact 验证，参数与实际 help 一致。
3. 示例不包含真实密钥、无效路径或本地-only 链接。
4. 文档不把 Field Validated 写成 Released。

### A-07 完成运维 runbook

**状态：** `[ ]`　**依赖：** A-03

**必须覆盖：**

- 正常备份与定期恢复演练。
- receipt/SHA-256 丢失、错误 proof、损坏备份。
- restore incomplete marker。
- 数据库损坏、worker fault、audit failure。
- state/runtime/socket 权限错误。
- 服务无法启动、端口/DNS/Clash Fake-IP 排查。
- 升级、回滚、v1 拒绝和非 v5 拒绝。
- recovery key 丢失后的真实结果。

**验收标准：** 每个 runbook 至少由一次干净环境演练验证；危险步骤明确标注数据影响和可恢复性。

### A-08 补齐开源治理文档

**状态：** `[ ]`　**依赖：** M 阶段完成

**需要：**

- `CHANGELOG.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SUPPORT.md`
- 版本支持和安全披露政策

**验收标准：**

1. SECURITY 提供私密漏洞报告渠道、支持版本和响应预期。
2. CONTRIBUTING 写明 fmt/check/clippy/test、机械合同、DCO 和 PR 要求。
3. CHANGELOG 与 Alpha tag 对应。
4. 文档不承诺当前无法提供的 24x7、SLA 或企业支持。

### A-09 补齐 crate 与 toolchain 元数据

**状态：** `[ ]`　**依赖：** A-01

**验收标准：**

1. 每个 crate 明确继承或设置 version、edition、license、repository。
2. 每个拟发布 crate 有 description、readme、keywords/categories。
3. 不发布的 crate 明确 `publish = false`。
4. Rust toolchain/MSRV 有书面政策并进入 CI。
5. 若发布 crates.io，`cargo package --list` 和 `cargo package` 通过且不包含秘密、fixtures 私钥或无关大型文件。

### A-10 更新 GitHub 仓库治理与产品身份

**状态：** `[ ]`　**依赖：** M-10

**必须完成：**

- 更新仍为 v1 MITM proxy 的 description/topics。
- 配置 main branch protection 或 ruleset。
- 要求 PR、required checks、Review 和 conversation resolution。
- 禁止 force-push 和直接 push。
- 启用 Dependabot vulnerability alerts/security updates，或记录不启用理由。
- 保留 secret scanning 和 push protection。
- 公开发布前决定 Rekey 名称、域名、包名和相邻 `rekey.dev` 风险。

**验收标准：** GitHub API 返回的设置与上述政策一致；仓库首页不再出现 v1 产品定位。

### A-11 Alpha 发布与发布后验证

**状态：** `[ ]`　**依赖：** A-01 至 A-10

**验收标准：**

1. tag 从已通过 main CI 的提交创建。
2. GitHub Release 包含版本、范围、已知限制、升级说明和 checksums。
3. 所有发行物签名/SBOM/provenance 可下载并验证。
4. 发布后从公开 URL 重做至少一次 macOS 和 Linux smoke test。
5. Feature Truth Matrix 只把真正公开发行的对应行提升为 `Released`。
6. 发现发布阻塞缺陷时撤回或标记有问题的发行物，不静默替换同名 artifact。

## 7. H 阶段：安全与可靠性补强

### H-01 持续 fuzzing

**状态：** `[ ]`

**目标 targets：** IPC frame decoder、action normalization、policy parser、response sealing、backup/restore envelope。

**验收标准：**

1. 每个 target 有 seed corpus 和崩溃最小化流程。
2. CI 运行短时 smoke；定时任务运行长时 fuzz。
3. 不存在 panic、无限循环、越界资源使用或策略解析分歧。
4. 发现的 crash 均转成稳定回归测试。

### H-02 ENOSPC 与文件系统故障注入

**状态：** `[ ]`

**覆盖：** audit commit、credential mutation、WAL/checkpoint、backup、restore、rename/fsync、权限变化。

**验收标准：**

1. 所有用户可见失败返回明确错误，不返回成功。
2. 不产生可 serve 的半初始化或半恢复 vault。
3. audit 失败按合同使 worker fault/fail closed。
4. retry 前置状态和残留文件有确定行为。

### H-03 密码限速重启边界

**状态：** `[ ]`

**验收标准：**

1. threat model 和用户文档明确限速在进程重启后重置。
2. Alpha 发布决策明确接受该 G1 限制或实现持久化方案。
3. 不为单机 Foundation 引入分布式限速基础设施。

### H-04 完整数据库回放风险

**状态：** `[ ]`

**验收标准：**

1. 文档明确当前完整有效快照回放不可检测。
2. 任何 G1 声明不包含 monotonic rollback protection。
3. 若未来实现外部 anchor，必须有独立 spec、故障模型和恢复合同。

### H-05 response sealing 能力边界

**状态：** `[ ]`

**验收标准：**

1. 列明已检测 raw、base64、base64url、percent 和 chunk-boundary。
2. 列明不保证任意压缩、加密、哈希派生或业务自定义编码。
3. 文案不声称阻止“一切形式”的 Secret 泄漏。
4. 新增 canonicalization 规则必须配攻击测试。

### H-06 平台与发行物测试矩阵

**状态：** `[ ]`

**候选范围：** Ubuntu systemd、额外 Linux distro、Linux arm64、macOS arm64/x86_64、release artifact install、不同 umask。

**验收标准：** 每个公开支持组合都有独立结果；未测试组合标为 experimental/unsupported，不从相邻环境外推。

### H-07 性能、容量与 soak 基线

**状态：** `[ ]`

**必须测量：** Authority queue 128、IPC 连接 128、每 session 并发 4、响应 sealing、audit 吞吐、长期内存、频繁 lock/unlock、backup 干扰、shutdown/drain。

**验收标准：**

1. 固定硬件/OS/Rust 版本和数据规模。
2. 记录 p50/p95/p99、峰值 RSS、错误率和饱和行为。
3. 超限时明确拒绝，不静默排队、截断或降级。
4. 至少一个长时间 soak 无持续内存增长或审计丢失。

### H-08 Rust 与供应链附加门槛

**状态：** `[ ]`

**候选项：** coverage、Miri、sanitizers、Loom、cargo-deny、license allowlist、unused dependency、reproducible build。

**验收标准：** 逐项决定 required、scheduled 或 deferred；不得为了清单完整一次性引入无维护能力的工具堆栈。

## 8. P 阶段：后续产品能力

以下每项在进入实现前都必须有独立 spec。完成定义统一为：行为已指定、实现已完成、contract tests 通过、真实 CLI black-box 通过、失败路径通过、Feature Truth Matrix 状态准确。

### P-01 密码生命周期

- 修改密码。
- recovery 后设置新密码。
- 原子替换并禁用旧 password wrapper。
- recovery key 轮换与丢失策略。
- 对应审计、故障注入和备份恢复合同。

### P-02 审计查询与导出

- `rekey audit list`。
- 按 request/session/action/credential/outcome/time 查询。
- 有界分页和 JSON 输出。
- 安全导出、retention 和字段脱敏。
- 后续 SIEM 输出边界。

### P-03 审批与持久化策略

- 一次性、时间窗口和双人审批。
- signed policy bundle、版本、回滚和过期。
- 持久化 policy snapshot。
- evaluator error/default deny 和审批不可用合同。
- 审批全过程审计。

### P-04 通用 workload identity

- OIDC、SPIFFE/SPIRE、Kubernetes service account、CI/cloud identity。
- 身份证明的 audience、issuer、expiry、replay 和撤销合同。
- principal 到 policy/capability 的绑定。

### P-05 Connector SDK

- typed action/effect schema。
- credential effect：inject、sign、exchange、lease、revoke。
- connector 生命周期、能力声明、测试工具和版本合同。
- MCP/OAuth adapter。
- registry、来源验证和隔离边界。

### P-06 GitHub App 扩展

- 写操作和更丰富 permissions。
- 多 repository selection 和 installation 变化。
- typed credential rotation、webhook 和失败重试。
- 多个真实 provider fixture。

当前 closed profile 只验证一个 App、一个安装、一个仓库和 metadata read，不得在 P-06 前称为通用 GitHub connector。

### P-07 外部 CredentialSource

- HashiCorp Vault。
- AWS/GCP/Azure secrets/KMS。
- 1Password、HSM、OS keychain wrapper。
- provider 不可用、版本、撤销和租约语义。

### P-08 可观测性

- Prometheus/OpenTelemetry metrics。
- 请求、拒绝、延迟、fault、活跃 capability、队列饱和、backup 指标。
- 不含敏感信息的 tracing 和 label cardinality 合同。

### P-09 Agent egress sandbox/launcher

- 受控启动 Agent。
- 禁止绕过 Rekey 直接访问网络。
- namespace/firewall/egress policy。
- 生命周期回收和攻击测试。

### P-10 Connector 隔离

- 独立进程或 WASM sandbox。
- CPU、内存、网络和时间上限。
- connector 签名、来源、权限清单和终止语义。

## 9. E 阶段：企业就绪门

### E-01 身份与组织管理

**能力：** OIDC/SAML、SCIM、human/agent/workload identity、RBAC/ABAC、组织/项目/环境层级、break-glass。

**验收标准：**

1. 跨租户、跨组织、缓存和 token 隔离攻击全部拒绝。
2. provisioning/deprovisioning 有最大生效时间。
3. break-glass 全程审计、限时、可撤销。

### E-02 控制面与 customer-hosted data plane

**能力：** 注册、签名策略同步、fleet、离线容忍、配置漂移和节点撤销。

**验收标准：** 控制面不持有客户 Secret；断网、过期策略、签名失败和回滚全部有 fail-closed 合同。

### E-03 HA、滚动升级与多区域 DR

**验收标准：**

1. 明确一致性、leader、split-brain 和 fencing。
2. 声明并实测 RPO/RTO。
3. 滚动升级期间授权、审计和撤销语义不破坏。
4. 至少一次完整灾难恢复演练。

### E-04 合规与安全运营

**能力：** SIEM、retention、legal hold、合规导出、独立渗透测试、第三方密码学审计、CVE、SBOM、签名和可复现构建。

**验收标准：** 无未解决 Critical/High；披露、修复、发布和客户通知流程完成桌面演练。

### E-05 企业运营

**能力：** 状态页、事故沟通、支持时区、升级路径、DPA、子处理者清单和删除流程。

**验收标准：** on-call 和事故职责有人承担；备份/恢复/升级/回滚由非作者照 runbook 成功演练。

### E-06 商业验证

**门槛：**

- 10 至 15 个目标买方访谈。
- 3 个 design partners。
- 2 个付费 Pilot。
- 至少一个生产或准生产环境。
- 一个受保护 Action 在 5 分钟内完成接入。
- 法人、合同、商标、服务条款、SLA、定价和计量完成。

**验收标准：** 以上证据来自真实客户和签署记录，不以内部 demo、测试仓库或口头兴趣替代。

## 10. 冻结的明确非目标

以下项目视为正确删除或明确不支持，不得作为“缺失功能”重新加入：

- [x] 不迁移或兼容 v1 vault。
- [x] 不恢复 MITM、系统 CA、dashboard、single-port proxy、TCP passthrough。
- [x] 不提供 Agent Secret get/read/export。
- [x] 不提供任意 URL credential proxy。
- [x] 不跟随 redirect，不使用 proxy environment。
- [x] 不向 Agent 暴露 SSE/streaming/retry。
- [x] P0 不支持 Windows。
- [x] 默认 G1 不宣称 hostile-agent G2。
- [x] Foundation 不强制依赖外部 Vault/KMS/HSM。
- [x] Capability session 和当前 policy snapshot 重启失效是现有设计，不是数据迁移缺陷。

任何重新打开上述项目的提案必须：

1. 建立新的 spec。
2. 说明安全模型为何改变。
3. 说明对 no-secret-read 和 fixed-action 合同的影响。
4. 通过独立安全 Review。
5. 不以“兼容旧用户”为默认理由。

## 11. 推荐执行顺序

1. 安排 M-04、M-05、M-06 三类独立 Review；可以合并为一份报告的三个章节，但 Reviewer 不能是本轮主要实现者。
2. 修复 Review findings，并在最终修改后重新验证。
3. 完成 M-07，更新 PR 证据和限制。
4. 经确认后执行 M-08 历史整理。
5. 完成 M-09，关闭 v1 遗留队列。
6. 执行 M-10，合并并验证 main。
7. 进入 A-01，单独冻结 Alpha 范围；不要自动把全部 P/H/E 项拉入首发。
8. A 阶段完成后再发布 Alpha。

## 12. 当前总判定

| 结论 | 状态 | 说明 |
| --- | --- | --- |
| v2 Foundation 核心实现 | 基本完成 | P0 主要链路达到 black-box/adversarial evidence；最终 SHA CI 正在运行 |
| PR #10 可立即合并 | 否 | M-01～M-07、M-09 已完成；M-08 等待实际 squash，M-10 仍需最终 CI 与独立 Approval |
| 所有规范与代码一致 | 已复核 | M-04～M-06 Review 完成；Critical/High 0，2 个 Medium 和 3 个 Low 已修复 |
| 所有文档完成 | 否 | product-foundation 边界、用户文档、运维和治理文档未闭合 |
| 可公开 Alpha | 否 | 无正式版本、发行物、安装流程、release workflow 和 release smoke |
| 可宣称通用 G2 | 否 | 只有有界 Linux reference；默认仍是 G1 |
| 可宣称通用 Connector | 否 | 只有 fixed HTTPS Action 和 closed GitHub App profile |
| 企业就绪 | 否 | 控制面、身份、HA/DR、合规、运营和商业门槛均未完成 |

最短合并路径只包含 M 阶段。A、H、P、E 是后续阶段，不应为了“全部做完”塞回 PR #10。
