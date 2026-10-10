# Rekey macOS UI

原生 SwiftUI 本机管理客户端。当前开发整合候选为 **0.5.0-alpha.1**，使用 vault27 / policy8。已发布 0.4 使用 vault26 / policy7；新格式需在新目录重建，不提供迁移。需要 macOS 14+ 和 Xcode Command Line Tools；无需 Node、浏览器服务或新数据库。新版 App 交互与登录项真机验收仍未验证，不以软件检查宣称 L1/L2。

## 构建与打开

```bash
scripts/build-macos-ui.sh
open target/macos-ui/Rekey.app
```

脚本将当前源码的 `rekey`、`rekeyd`、`rekey-mcp`、`rekey-policy-sign`、`rekey-approval-sign` 打包到 App 内，默认做 ad-hoc 签名。正式构建显式设置 `REKEY_SIGNING_IDENTITY`（或 `APPLE_SIGNING_IDENTITY`）、`REKEY_REQUIRE_DEVELOPER_ID=1` 、`REKEY_PROVISIONING_PROFILE=/path/to/Rekey.provisionprofile` 和 `REKEY_DAEMON_PROVISIONING_PROFILE=/path/to/RekeyDaemon.provisionprofile`。`REKEY_UI_OUTPUT` 可指定构建输出位置，`CARGO_TARGET_DIR` 沿用 Cargo 的构建缓存配置。不执行公证或公开发布。

正式构建需要两个独立 provisioning profile：App 标识符 `com.starlight.rekey`，内嵌 `Contents/Helpers/RekeyDaemon.app` 标识符 `com.rekey.rekeyd`，二者属于同一签名 Team 并授权 `<TeamID>.com.rekey` 访问组。构建脚本分别嵌入 profile 和对应 entitlement；独立 CLI 不加入访问组。release 的 macos-ui job 需要 base64 编码的 `APPLE_PROVISIONING_PROFILE` 与 `APPLE_DAEMON_PROVISIONING_PROFILE` secrets。缺失或不匹配会停止正式 App 构建；源码 ad-hoc 构建仍可管理密码，但不能使用受保护的系统认证授权。profile 的最终授权由 macOS 验证，构建检查不代表 V1 通过。依据 [Apple TN3125](https://developer.apple.com/documentation/technotes/tn3125-inside-code-signing-provisioning-profiles)。

版本来自 Cargo metadata 中 `rekey-cli` 继承的 workspace version。完整 SemVer 保存在 Info.plist 的 `RekeyVersion`；`CFBundleShortVersionString` 和 `CFBundleVersion` 使用数字主、次、补丁版本，例如 `0.4.0-alpha.1` 对应 `0.4.0`。不实现 alpha/rc 排序映射。

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

App 在签名前会装入静态 `Contents/Library/LaunchAgents/com.rekey.rekeyd.plist`，以 `BundleProgram` 指向内嵌 `rekeyd serve`，使用默认用户 `~/.rekey`，不指定 UserName、动态 state-dir 或 KeepAlive。安装到固定位置后，App 打开后自动连接已有保险库，未运行时通过 SMAppService 注册或启动服务。已注册的服务使用不带 `-k` 的 `launchctl kickstart` 启动，不先注销或杀掉已有实例。普通刷新和读取记住的凭据不注册服务；系统要求批准时，用户自行打开登录项设置。仅打包 plist 不会启动或注册服务。源码构建的开发 App 和自定义目录使用 Process 自动启动随包服务。**真实签名设备的注册、批准、重登录、升级与卸载验收尚未完成**；编译和结构测试不替代这些结果。

应用图标源文件为 `Resources/AppIcon.png`（1024 × 1024）。构建脚本使用 macOS 自带的 `sips` 和 `iconutil` 生成标准尺寸的 `AppIcon.icns`，通过 `CFBundleIconFile` 配置 Finder 与 Dock 图标。当前采用用户选定的“双环 · 现代平面”：炭黑背景、米白与橙色双环。图标由内置 imagegen 基于双环参考图生成，提示词为“以参考图为基础，为 Rekey app 创作一个「现代平面设计」风格图标。保留双环相扣的识别结构，材质、配色与表现方式自由发挥。成熟、有个性，避免常见 AI 霓虹渐变。单张正方形图标，无文字。”

首次打开时默认使用 `~/.rekey`。首次启动选择个人或团队模式并设置密码，模式与信任根创建后不可更改；确认界面说明保存恢复密钥后会自动连接并启动服务（固定位置且默认目录的安装版同时启用登录启动）。恢复密钥只在完成窗口显示一次。已有保险库自动连接，服务未运行则自动启动，随后按需解锁。也可以通过“个人工作区”或设置切换目录；安装版后台服务仅管理默认目录，自定义目录或机构配置由 App 自动启动随包服务，不注册默认目录的登录项。格式不兼容或目录非空时沿用 CLI 的明确拒绝，不迁移、不覆盖。

## 当前入口

- 凭证与连接：保存 API Key 后选择 Anthropic、OpenAI、GLM、GLM Responses、GitHub PAT、Git smart HTTP、自定义 Bearer 或自定义 Header 预设；预设和操作 schema 从 daemon 读取。Git smart HTTP 固定 `https://github.com`、owner 和完整 `repo.git`，upload 为读、receive 为写，默认请求正文上限 1 MiB。随后审阅连接的 host、路径规则、调用方限制与 LLM 模型、预算，再签署策略。密钥只通过隐藏输入和子进程 stdin 传递。
- OAuth：Google Drive / Gmail / Calendar、GitHub OAuth App、Slack 和 Notion 使用用户自己的 client。client secret 只经 stdin 加密保存；先签署 scope ceiling 与有限操作规则，再打开浏览器。Google 和 GitHub 使用本机随机回调；Slack 的 public PKCE client 须启用 token rotation，Slack / Notion 使用已登记的固定本机回调。Notion 展示的是 Portal capabilities，并非请求 scope；GitHub `repo` 上游也具有写权限，本机规则继续限制写操作。配置指引直接链接官方文档。此轮软件检查未实际登录任何 provider。
- T1 临时凭据：保存 AWS 长期密钥或 GitHub App PKCS#1 RSA 根私钥后没有派生权限。逐个签署 AWS AssumeRole（900–3600 秒、固定 role / region / session policy）、EKS（900 秒上限、固定 cluster / region）或 GitHub App（3600 秒、明确 repository IDs / permissions）授权。审阅界面显示实际签名目标，说明 Agent 进程会拿到临时值；根凭据不会返回给 Agent。EKS 不接受 App 填入 session token，权限受 IAM / EKS RBAC 约束。
- `.env` 导入：`rekey import PATH` 打开 `rekey://import?path=…`；App 只显示变量名、预设提示和未支持的行。明确选择后保存凭据，审阅完整 Connection 草案并签署；可选替换选中的原变量为 Rekey 占位值并添加本机 base URL，daemon 原子写入并返回备份路径。默认不修改原文件。失败或未知结果不自动重试。
- 个人策略：读取当前完整 signed Connection 集合及策略摘要；编辑 read/write/具体方法、路径和允许值，调用方覆盖只能收紧。草案展示完整 before/after 与连接定义，App 确认展示定义与原始签名字节一致，再用 Secure Enclave 签名并提交逐次证明。现有 SSH 规则在连接编辑时保留；空连接集合撤销全部 HTTP 连接。窗口或工作区变化取消迟到结果，不自动重签或重试。
- Agent 接入：通过 `rekey connect claude-code`、`rekey connect codex`、`rekey connect generic` 写入客户端配置和说明；本机调用不需要 token。Agent 正常启动，需要密钥时调用 Rekey。固定操作和 capability 页面仅在 lab 显示。
- 本机审批：审阅 daemon 的完整请求后显式批准一次、30 分钟或最多 8 小时。时间窗绑定同一连接、规则、调用方和策略，锁定或更改策略后失效，不能覆盖 deny。默认焦点与 Return 是拒绝。
- 访问请求：收件箱展示 Agent 请求的 provider、connection、operation 与理由。先添加密钥并激活对应签名规则，再完成请求；可拒绝并拉黑或解除拉黑。调用方标注仅用于记录，不代表认证。后台轮询及通知不触发系统认证。
- Activity：按调用方、连接和 read/write / 临时凭据展示结构化审计计数与用量，不展示 provider 凭证、原始请求或敏感响应；点击分组可查看最近 50 条调用的路径、结果、规则和审批详情。T1 显示签名目标 / 权限与签发事件的实际过期时间。
- 团队策略：安装外部 Ed25519 信任根、导入签名策略并查看状态。导入后查看连接集合；短期 capability 管理仅在 lab 显示。
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

签名文件与 Agent 接入见 [用户指南](../../docs/user-guide.md)。`connect` 只在用户明确操作后修改所支持客户端的受管配置和说明文件；不提供任意执行控制台。审批通知仅在用户开启后、App 运行期间提示，不触发认证。保护等级只按已确认事实保守显示；服务签名标签独立于等级，未知状态不宣称 L1-dev/L1/L2。

关闭 UI 不会终止 Broker；默认由 Broker 在空闲 7 天后锁定。可主动点击“锁定”或设置里的“停止服务”；停止服务保留登录启动设置，且需要逐次证明。“停止并停用登录启动”在同一次证明的 SHUTDOWN 成功后才调用注销接口；服务不可达时不会未经验证强行注销，可由用户在系统登录项中管理。不缓存密码或系统认证 K；密码/恢复密钥解锁时，可明确勾选默认关闭的“启用系统认证（7天）”。新 K 保存在要求 userPresence 的数据保护钥匙串中，保险库保存绑定 vault ID 与固定到期时间的加密根密钥材料。刷新和启动不会读取 K；重启后必须点击系统认证解锁。每次支持的 A2 操作显式读取 K，操作结束不保留；恢复与验证不会延长原期限。手动锁定、空闲锁定或更改密码/恢复密钥会撤销授权；正常停止服务保留授权。管理会话允许连续添加 API Key；轮换或撤销凭证仍需密码、恢复密钥或系统认证的新证明。默认 App 不显示或复制已有密钥，只通过签名连接调用；CLI 的明文查看仅在 lab 中保留。恢复结果只在当前结果窗口中存在，用户可显式保存为新建的 0600 文件。

## 验证

```bash
cargo check --workspace
xcrun swiftc -warnings-as-errors -swift-version 5 -O \
  -framework SwiftUI -framework AppKit -framework ServiceManagement \
  apps/macos/BackgroundService.swift apps/macos/PolicySigning.swift apps/macos/PresenceKey.swift apps/macos/Model.swift scripts/test-macos-ui.swift -o /tmp/rekey-ui-contract
/tmp/rekey-ui-contract target/macos-ui/Rekey.app/Contents/Resources/bin/rekey
```

自动连接回归检查复用同一个测试程序和随包 CLI，不访问用户保险库：

```bash
mkdir -p /tmp/RekeyStartupContract.app/Contents/MacOS
cp /tmp/rekey-ui-contract /tmp/RekeyStartupContract.app/Contents/MacOS/RekeyStartupContract
ln -s "$PWD/target/macos-ui/Rekey.app/Contents/Resources" /tmp/RekeyStartupContract.app/Contents/Resources
/tmp/RekeyStartupContract.app/Contents/MacOS/RekeyStartupContract --startup-only
```

覆盖空目录不自动初始化、保存恢复密钥后连接、已有保险库自动启动并保持锁定、复用已运行服务、显式停止后普通刷新不重启，以及启动失败诊断。CI 同样执行此检查。

连接 UI 软件契约检查：

```bash
xcrun swiftc -warnings-as-errors -swift-version 5 \
  -framework SwiftUI -framework AppKit -framework ServiceManagement \
  apps/macos/BackgroundService.swift apps/macos/PolicySigning.swift apps/macos/PresenceKey.swift \
  apps/macos/Model.swift apps/macos/Tests/ConnectionContract.swift -o /tmp/rekey-connection-app-contract
/tmp/rekey-connection-app-contract
```

已完成完整 Swift 源码的 warnings-as-errors typecheck，以及连接序列化、编辑基线、展示定义与实际签名字节一致性、URL 路由、导入 stdin 合同、有界认证 context 复用、到期和取消失效、HTTP/SSH 审批合同、最近 50 条去重分组、OAuth scope 声明、T1 实际目标 / 过期时间和完整草案 stdin 的合成检查。未完成 0.4 真实设备上的 Touch ID 弹窗次数、Secure Enclave 签署激活、OAuth 登录和 C16；软件检查不能代替这些验收。

测试使用随机临时保险库和合成凭证，不访问真实 provider。原生界面另行检查空状态、搜索、详情、表单与页面导航。没有把所有 GUI submit 路径宣称为自动化覆盖。

人类密钥管理验收：`python3 scripts/test-human-vault.py target/macos-ui/Rekey.app/Contents/Resources/bin/rekey`。Agent 通道不提供读取，管理会话在锁定后失效。

系统认证合成检查：`/tmp/rekey-ui-contract --presence-boundary-only`，只注入临时 CLI 和可控读取结果，不访问钥匙串。真实签名设备的访问组、未签名进程读取拒绝与 userPresence 验收使用 `scripts/v3/keychain_probe.swift` 和 `scripts/v3/run.py`；旧的无交互自动恢复测试已被新合同替换。

机构登录仅在 `--features lab` 的服务上可用：设置中选择受保护的 OIDC 节点配置后启动服务；先本机解锁，再开始机构登录、在浏览器完成认证，并接收结果到新的私有会话文件。也可显式选择已有会话文件，取消未完成登录或退出本机机构会话。应用只传文件路径，不读取管理 token；密码逐次确认仍保留。合成调用检查不替代真实 IdP／Broker／GUI 点击验收。

本机审批使用 `approval review/approve/reject`：面板验证完整原始 UTF-8 正文的 RKREVIEW 哈希，默认焦点与 Return 都是拒绝。明确决定时才逐次读取 presence key，后台通知和收件箱轮询不触发认证，取消认证不发送决定。通知使用固定文案并在本次 App 会话中去重。`/tmp/rekey-ui-contract --local-approval-boundary-only` 运行合成边界检查；它不访问真实 Keychain、Secure Enclave 或通知权限，不能替代签名设备验收。

## 0.5 开发版界面隐私锁

打开和重开窗口时，界面保持锁定；服务已解锁也需要显式输入密码或选择系统认证。设置可选电脑空闲 1/5/15/30/60 分钟或禁用，默认五分钟；锁屏、休眠和切换用户默认锁定界面。隐私锁立即清除展示内容并撤销 A1 管理会话，已有 Agent 工作继续。“锁定整个保险库”另行撤销 Agent 授权。服务端撤销未确认时，界面保持锁定并提供重试。

系统认证授权可选择每次输入密码或记住 1/7/30 天，默认七天；仅密码或恢复密钥可以签发，恢复不续期，单次管理会话仍最多七天。保存设置先撤销当前会话和记住授权，再要求输入密码；只保存非秘密偏好。当前 PresenceKey 访问控制保持不变，不能以 ad-hoc 构建证明真实 Keychain/Touch ID 通过。

团队策略草稿可编辑原始 UTF-8 文本或显式生成 policy8 空草稿，最多 64 KiB，导出到新的私有文件。编辑不会签署或激活；独立 signer 的完整审阅和摘要确认仍必需。个人连接使用现有完整 Connection 表单。
