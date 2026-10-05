# Rekey macOS UI

原生 SwiftUI 本机管理客户端。当前版本为 **3.0.0-alpha.4（alpha）**，vault25 / policy6 已冻结并覆盖全部 v3 版本。需要 macOS 14+ 和 Xcode Command Line Tools；无需 Node、浏览器服务或新数据库。新版 App 交互与登录项真机验收由用户暂缓，仍未验证，不以软件检查宣称 L1/L2。

## 构建与打开

```bash
scripts/build-macos-ui.sh
open target/macos-ui/Rekey.app
```

脚本将当前源码的 `rekey`、`rekeyd`、`rekey-mcp`、`rekey-policy-sign`、`rekey-approval-sign` 打包到 App 内，默认做 ad-hoc 签名。正式构建显式设置 `REKEY_SIGNING_IDENTITY`（或 `APPLE_SIGNING_IDENTITY`）、`REKEY_REQUIRE_DEVELOPER_ID=1` 、`REKEY_PROVISIONING_PROFILE=/path/to/Rekey.provisionprofile` 和 `REKEY_DAEMON_PROVISIONING_PROFILE=/path/to/RekeyDaemon.provisionprofile`。`REKEY_UI_OUTPUT` 可指定构建输出位置，`CARGO_TARGET_DIR` 沿用 Cargo 的构建缓存配置。不执行公证或公开发布。

正式构建需要两个独立 provisioning profile：App 标识符 `com.starlight.rekey`，内嵌 `Contents/Helpers/RekeyDaemon.app` 标识符 `com.rekey.rekeyd`，二者属于同一签名 Team 并授权 `<TeamID>.com.rekey` 访问组。构建脚本分别嵌入 profile 和对应 entitlement；独立 CLI 不加入访问组。release 的 macos-ui job 需要 base64 编码的 `APPLE_PROVISIONING_PROFILE` 与 `APPLE_DAEMON_PROVISIONING_PROFILE` secrets。缺失或不匹配会停止正式 App 构建；源码 ad-hoc 构建仍可管理密码，但不能使用受保护的系统认证授权。profile 的最终授权由 macOS 验证，构建检查不代表 V1 通过。依据 [Apple TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)。

版本来自 Cargo metadata 中 `rekey-cli` 继承的 workspace version。完整 SemVer 保存在 Info.plist 的 `RekeyVersion`；`CFBundleShortVersionString` 和 `CFBundleVersion` 使用数字主、次、补丁版本，例如 `3.0.0-alpha.4` 对应 `3.0.0`。不实现 alpha/rc 排序映射。

## 组装 macOS pkg

先提供已签名的 App，再运行：

```bash
scripts/build-macos-pkg.sh --app target/macos-ui/Rekey.app \
  --installer-identity 'Developer ID Installer: Example (TEAMID1234)'
```

默认输出 `target/macos-pkg/Rekey-<完整SemVer>.pkg`，可用 `--output-dir` 指定输出目录；已有同名产物会报错。脚本校验 App 与五个内嵌程序的 Developer ID Application 签名、hardened runtime、与 Installer 身份一致的 Team ID 和固定标识符（daemon 为 `com.rekey.rekeyd`）。Installer 必须使用单独的 Developer ID Installer 身份，Application 身份不能代替；失败不会自动降级。

包固定安装到 `/Applications/Rekey.app`，并包含 `/usr/local/bin/rekey`、`rekeyd`、`rekey-mcp` 三个指向 App 内程序的符号链接。组件不重定位；显式安装同数字版本的另一个 prerelease 会替换 App，不因 `CFBundleVersion` 相同而跳过，也不提供降级保护。preinstall 只检查链接冲突与被重定向的安装目录；第三方文件或不同目标的链接会使安装失败，不执行 App、launchctl 或任何服务注册。

仅检查本地合成 payload 结构时可显式使用：

```bash
scripts/build-macos-pkg.sh --app /path/to/synthetic/Rekey.app --unsigned
```

该选项跳过代码签名校验和 Installer 签名，产物名含 `-unsigned.pkg`；**未签名、未公证，不得安装或分发**。它不能与签名身份同时使用，也不能作为正式构建的回退路径。打包脚本本身不提交公证。现有 release workflow 已接入最终 pkg 公证、staple 与签名检查，使用新增的 `APPLE_INSTALLER_CERTIFICATE`、`APPLE_INSTALLER_CERTIFICATE_PASSWORD`、`APPLE_INSTALLER_SIGNING_IDENTITY` secrets；只支持 Developer ID Installer，不能拿 Application 证书替代。本地尚未运行该 CI 链，也未完成真实新用户安装验收。

App 在签名前会装入静态 `Contents/Library/LaunchAgents/com.rekey.rekeyd.plist`，以 `BundleProgram` 指向内嵌 `rekeyd serve`，使用默认用户 `~/.rekey`，不指定 UserName、动态 state-dir 或 KeepAlive。安装到固定位置后，App 提供显式启用登录启动与启动服务的 SMAppService 入口。已注册的服务使用不带 `-k` 的 `launchctl kickstart` 启动，不先注销或杀掉已有实例。刷新和读取记住的凭据不注册服务；系统要求批准时，用户自行打开登录项设置。仅打包 plist 不会启动或注册服务。源码构建的开发 App 仍使用 Process 启动。**真实签名设备的注册、批准、重登录、升级与卸载验收尚未完成**；编译和结构测试不替代这些结果。

应用图标源文件为 `Resources/AppIcon.png`（1024 × 1024）。构建脚本使用 macOS 自带的 `sips` 和 `iconutil` 生成标准尺寸的 `AppIcon.icns`，通过 `CFBundleIconFile` 配置 Finder 与 Dock 图标。当前采用用户选定的“双环 · 现代平面”：炭黑背景、米白与橙色双环。图标由内置 imagegen 基于双环参考图生成，提示词为“以参考图为基础，为 Rekey app 创作一个「现代平面设计」风格图标。保留双环相扣的识别结构，材质、配色与表现方式自由发挥。成熟、有个性，避免常见 AI 霓虹渐变。单张正方形图标，无文字。”

首次打开时默认使用 `~/.rekey`。首次启动选择个人或团队模式并设置密码，模式与信任根创建后不可更改；确认界面说明创建保险库后会启用登录启动并启动服务（固定位置的安装版）。恢复密钥只在完成窗口显示一次。已有保险库请启动服务，再解锁。也可以通过“个人工作区”或设置切换目录；安装版后台服务仅管理默认目录，自定义目录或机构配置需先由 CLI 启动服务，App 再连接。格式不兼容或目录非空时沿用 CLI 的明确拒绝，不迁移、不覆盖。

## 当前入口

- 凭证：真实列表、搜索、类型过滤、关联操作；添加/轮换/撤销。固定令牌由安全输入框录入，其他类型选择已有的私有 JSON profile。
- 固定操作：表单创建，定义文件导入/更新/禁用。表单采用 30 秒、64 KiB 请求、256 KiB 响应的当前默认；更细的限制通过定义文件配置。
- Provider 模板：Anthropic、GLM（固定智谱 Anthropic Messages 端点）、OpenAI、GitHub PAT 和自定义 Bearer。界面从 daemon 读取认证后的能力声明，支持勾选能力和多组固定绑定；一次管理证明后原子安装。安装不自动激活策略或发放 Agent 会话。团队签名包可通过 `rekey template catalog/install --file … --package …` 使用。
- 模板调用：`rekey execute` 与 `rekey approval prepare` 接受重复的 `--param NAME=VALUE`、`--query NAME=VALUE`。请求只使用安装时声明的参数类型和查询键，规范路径、查询与正文绑定审批；固定操作拒绝非空参数。本地 presence 审批通过专门面板审阅完整 daemon 请求。
- 个人策略：安装按 vault ID 绑定的本机 P-256 信任公钥，编辑完整 Profile 集合（主体、实例能力、会话、隔离、egress、模型与预算），每个能力明确选择 `template-default`、`allow` 或 `require-approval`。查看完整替换差异与目标定义后，由 App 调用 Secure Enclave 签署 daemon 返回的原始字节，经匿名 stdin 提交签名包与逐次管理证明。空集合撤销全部授权；模板默认的高风险审批不会隐式变成 allow。切换工作区、关闭表单或草案失效后，迟到签名不会激活；不自动重签或重试。使用系统认证时，本次读取授权和策略签署复用同一认证 context（固定十秒窗口）；结束、取消或失败时作废。snapshot6 与规则 UI 的软件联合 gate 已完成；此前安装候选的完整 App 审阅、真实 SE/Touch ID 签署激活已实测，本次共用 context 修复后的实际弹窗次数尚未测试。
- Agent 接入：选择 Profile 后显式 `connect` / `run`；MCP 只发现已授权工具，SDK 使用已验证的本机 gateway endpoint。实例、预算和审批在共用执行器校验。没有后台签策略或 Agent 触发的系统认证；Linux Profile netns 与 Codex Seatbelt managed-preferences 限制见平台说明。
- Activity：按结构化审计展示 Agent/实例/操作结果和用量；不展示 provider 凭证、原始请求或敏感响应。
- 团队策略：安装外部 Ed25519 信任根、导入签名策略并查看状态。按操作创建短期 capability、按会话 ID 撤销；没有全量活动会话列表。
- 外部 Ed25519 审批：真实 pending 收件箱、只读详情与来源签名信封导出。详情展示主体、会话、操作版本、资源、参数/策略摘要、审批人、次数和时限，以及当前本机来源公钥；相同版本的操作定义单独标明为本机元数据。信封不含原始正文或请求头，UI 未验证签名；完整请求核对与签名继续使用独立工具和独立固定的来源公钥。
- 审计：结果筛选、稳定快照分页和 JSONL 导出，锁定时仍可读取。
- 备份恢复：新文件加密备份与 generation 回执；离线恢复先认证预览 source generation / high-water / history-missing，再显式确认相同 context。上下文变化必须重新审阅，不自动重试。运行中的 rollback-suspected 只能用密码或恢复密钥确认，成功后仍锁定。
- 设置：密码修改、恢复密钥轮换、数据目录、服务启动/停止。

个人策略私钥保留在 Secure Enclave；App 只持有密钥引用并请求系统认证签名，无软件密钥回退。团队策略和外部审批使用独立签名工具：

```bash
cargo build --release -p rekey-policy --bin rekey-policy-sign --bin rekey-approval-sign
target/release/rekey-policy-sign --help
target/release/rekey-approval-sign --help
```

签名文件与 Agent 接入见 [用户指南](../../docs/user-guide.md)。`connect` 只在用户明确操作后修改所支持客户端的受管配置；不提供任意执行控制台。审批通知仅在用户开启后、App 运行期间提示，不触发认证。保护等级只按已确认事实保守显示；服务签名标签独立于等级，未知状态不宣称 L1-dev/L1/L2。

关闭 UI 不会终止 Broker；默认由 Broker 在空闲 7 天后锁定。可主动点击“锁定”或设置里的“停止服务”；停止服务保留登录启动设置，且需要逐次证明。“停止并停用登录启动”在同一次证明的 SHUTDOWN 成功后才调用注销接口；服务不可达时不会未经验证强行注销，可由用户在系统登录项中管理。不缓存密码或系统认证 K；密码/恢复密钥解锁时，可明确勾选默认关闭的“启用系统认证（7天）”。新 K 保存在要求 userPresence 的数据保护钥匙串中，保险库保存绑定 vault ID 与固定到期时间的加密根密钥材料。刷新和启动不会读取 K；重启后必须点击系统认证解锁。每次支持的 A2 操作显式读取 K，操作结束不保留；恢复与验证不会延长原期限。手动锁定、空闲锁定或更改密码/恢复密钥会撤销授权；正常停止服务保留授权。管理会话允许连续添加 API Key；每次查看或复制仍需密码、恢复密钥或系统认证的新证明，既有管理 token 不能授权明文。复制后 30 秒只清理本应用仍占有的剪贴板内容，无法清理第三方历史记录；短期 capability 和恢复结果只在当前结果窗口中存在，用户可显式保存为新建的 0600 文件。

## 验证

```bash
cargo check --workspace
xcrun swiftc -warnings-as-errors -swift-version 5 -O \
  -framework SwiftUI -framework AppKit -framework ServiceManagement \
  apps/macos/BackgroundService.swift apps/macos/PolicySigning.swift apps/macos/PresenceKey.swift apps/macos/Model.swift scripts/test-macos-ui.swift -o /tmp/rekey-ui-contract
/tmp/rekey-ui-contract target/macos-ui/Rekey.app/Contents/Resources/bin/rekey
```

测试使用随机临时保险库和合成凭证，不访问真实 provider。原生界面另行检查空状态、搜索、详情、表单与页面导航。没有把所有 GUI submit 路径宣称为自动化覆盖。

人类密钥管理验收：`python3 scripts/test-human-vault.py target/macos-ui/Rekey.app/Contents/Resources/bin/rekey`。Agent 通道不提供读取，管理会话在锁定后失效。

系统认证合成检查：`/tmp/rekey-ui-contract --presence-boundary-only`，只注入临时 CLI 和可控读取结果，不访问钥匙串。真实签名设备的访问组、未签名进程读取拒绝与 userPresence 验收使用 `scripts/v3/keychain_probe.swift` 和 `scripts/v3/run.py`；旧的无交互自动恢复测试已被新合同替换。

机构登录仅在 `--features lab` 的服务上可用：设置中选择受保护的 OIDC 节点配置后启动服务；先本机解锁，再开始机构登录、在浏览器完成认证，并接收结果到新的私有会话文件。也可显式选择已有会话文件，取消未完成登录或退出本机机构会话。应用只传文件路径，不读取管理 token；密码逐次确认仍保留。合成调用检查不替代真实 IdP／Broker／GUI 点击验收。

本机审批使用 `approval review/approve/reject`：面板验证完整原始 UTF-8 正文的 RKREVIEW 哈希，默认焦点与 Return 都是拒绝。明确决定时才逐次读取 presence key，后台通知和收件箱轮询不触发认证，取消认证不发送决定。通知使用固定文案并在本次 App 会话中去重。`/tmp/rekey-ui-contract --local-approval-boundary-only` 运行合成边界检查；它不访问真实 Keychain、Secure Enclave 或通知权限，不能替代签名设备验收。
