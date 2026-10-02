# Rekey macOS UI

原生 SwiftUI 本机管理客户端，按已接受的中文浅色凭证管理设计实现。需要 macOS 14+ 和 Xcode Command Line Tools；无需 Node、浏览器服务或新数据库。

## 构建与打开

```bash
scripts/build-macos-ui.sh
open target/macos-ui/Rekey.app
```

脚本将当前源码的 `rekey` / `rekeyd` / `rekey-github-create-issue` 打包到 app 内，并在本机做 ad-hoc 签名。`REKEY_UI_OUTPUT` 可指定构建输出位置，`CARGO_TARGET_DIR` 沿用 Cargo 的构建缓存配置。不包含公证或公开发布。

应用图标源文件为 `Resources/AppIcon.png`（1024 × 1024）。构建脚本使用 macOS 自带的 `sips` 和 `iconutil` 生成标准尺寸的 `AppIcon.icns`，通过 `CFBundleIconFile` 配置 Finder 与 Dock 图标。当前采用用户选定的“双环 · 现代平面”：炭黑背景、米白与橙色双环。图标由内置 imagegen 基于双环参考图生成，提示词为“以参考图为基础，为 Rekey app 创作一个「现代平面设计」风格图标。保留双环相扣的识别结构，材质、配色与表现方式自由发挥。成熟、有个性，避免常见 AI 霓虹渐变。单张正方形图标，无文字。”

首次打开时默认使用 `~/.rekey`。首次启动自动显示密码设置流程；输入并确认密码后自动创建保险库并启动服务，恢复密钥只在完成窗口显示一次。已有保险库请启动服务，再解锁。也可以通过“个人工作区”或设置切换目录。格式不兼容或目录非空时沿用 CLI 的明确拒绝，不迁移、不覆盖。

## 当前入口

- 凭证：真实列表、搜索、类型过滤、关联操作；十种已实现类型均可添加/轮换/撤销，含 AWS、GCP、Azure、1Password Connect、macOS Keychain。固定令牌由安全输入框录入，其他类型选择已有的私有 JSON profile。
- 固定操作：表单创建，定义文件导入/更新/禁用。表单采用 30 秒、64 KiB 请求、256 KiB 响应的当前默认；更细的限制通过定义文件配置。
- 授权与策略：多规则草稿表单、完整文本编辑与导入、私有文件导出；支持允许/拒绝/审批、精确参数摘要、审批人数及一次性/限时多次授权。草稿须独立签名后逐次 step-up 安装信任根和激活；界面显示生效版本。按操作创建短期 capability、按会话 ID 撤销；没有全量活动会话列表。
- 审批：真实 pending 收件箱、只读详情与来源签名信封导出。详情展示主体、会话、操作版本、资源、参数/策略摘要、审批人、次数和时限，以及当前本机来源公钥；相同版本的操作定义单独标明为本机元数据。信封不含原始正文或请求头，UI 未验证签名；完整请求核对与签名继续使用独立工具和独立固定的来源公钥。
- 审计：结果筛选、稳定快照分页和 JSONL 导出。原生管理界面锁定时隐藏内容，CLI 的锁定状态审计权限保持不变。
- 提醒：窗口活跃且已解锁时，随现有 15 秒刷新显示待审批数量，点击进入收件箱；不是后台系统推送，不自动审批。
- 备份恢复：新文件加密备份与回执、SHA-256 验证的空目录离线恢复。
- 设置：自动锁定与身份验证、密码修改、恢复密钥轮换、数据目录、服务启动/停止。

策略和审批私钥不交给 UI。外部签名工具的源码构建命令：

```bash
cargo build --release -p rekey-policy --bin rekey-policy-sign --bin rekey-approval-sign
target/release/rekey-policy-sign --help
target/release/rekey-approval-sign --help
```

签名文件的准备和 Agent shell/MCP 接入继续见根目录 `docs/user-guide.md`。这一版没有自动配置 Agent、GUI 签名、任意执行控制台或常驻通知。

关闭 UI 不会终止 Broker。管理界面默认在电脑空闲 5 分钟后锁定，并跟随锁屏、休眠、显示器休眠和用户切换锁定；设置可选 1/5/15/30/60 分钟或不因空闲锁定。后台 Agent 请求和界面轮询不计入电脑输入活动。自动锁定清除界面中的值、表单、结果及本应用仍占有的剪贴板内容，并撤销服务端管理会话；已授权的 Agent 可以继续工作。要同时撤销 Agent 授权，使用“锁定全部，包括 Agent”。Broker 自身的空闲锁定仍独立生效。

每次打开应用先锁住管理界面，启动、激活和后台刷新不读取钥匙串，也不自动恢复。手动输入保险库密码后，可保存本机恢复授权，期限独立选择每次解锁都输入（不保存）、1/7/30 天，默认 7 天；不保存主密码。之后显式选择“使用 Mac 身份验证解锁”，由系统验证设备所有者身份（按设备支持使用 Touch ID 或 Mac 密码），成功后才读取本机授权。取消或失败保持锁定，恢复不延长原到期时间。修改安全设置先撤销旧会话及恢复授权，再要求输入保险库密码。锁定全部、Broker 空闲锁定、密码/恢复密钥变更及故障仍撤销恢复授权；正常停止服务保留尚未到期的授权。

管理会话允许连续添加 API Key 和显式查看/复制当前有效凭证。复制后 30 秒只清理本应用仍占有的剪贴板内容，无法清理第三方历史记录；短期 capability 和恢复结果只在当前结果窗口中存在，用户可显式保存为新建的 0600 文件。锁定期间到达的解锁、查看或复制响应不能重新显示内容；若服务端会话撤销结果未知，界面保持锁定，完成撤销前不接受再次解锁。

## 验证

```bash
cargo check --workspace
xcrun swiftc -warnings-as-errors -swift-version 5 -O \
  -framework SwiftUI -framework AppKit \
  apps/macos/Model.swift scripts/test-macos-ui.swift -o /tmp/rekey-ui-contract
/tmp/rekey-ui-contract target/macos-ui/Rekey.app/Contents/Resources/bin/rekey
```

测试使用随机临时保险库和合成凭证，不访问真实 provider。原生界面另行检查空状态、搜索、详情、表单与页面导航。没有把所有 GUI submit 路径宣称为自动化覆盖。

人类密钥管理验收：`python3 scripts/test-human-vault.py target/macos-ui/Rekey.app/Contents/Resources/bin/rekey`。Agent 通道不提供读取，管理会话在锁定后失效。

钥匙串跨进程验证：`xcrun swiftc -swift-version 5 -framework SwiftUI -framework AppKit -framework Security apps/macos/Model.swift scripts/test-macos-keychain.swift -o /tmp/rekey-keychain-contract && /tmp/rekey-keychain-contract`，仅使用随机测试条目，完成后删除。

恢复授权的 Keychain service 按应用 bundle identifier 隔离；无 bundle 的测试使用独立测试命名空间。测试版必须设置独立 identifier，不能复用正式应用 `com.starlight.rekey`。新条目显示“本机解锁授权”。本轮在应用恢复流程中加入 LocalAuthentication；记住的密钥仍由原有登录钥匙串条目保存，不宣称密钥绑定 Secure Enclave 或不可导出。命名空间测试只运行 Foundation 查询，不访问用户钥匙串。

机构登录源码入口：设置中选择受保护的 OIDC 节点配置后启动服务；先本机解锁，再开始机构登录、在浏览器完成认证，并接收结果到新的私有会话文件。也可显式选择已有会话文件，取消未完成登录或退出本机机构会话。应用只传文件路径，不读取管理 token；密码逐次确认仍保留。16 项新调用断言、80 项原有原生流程断言及完整 macOS14 App 编译通过，真实 IdP／Broker／GUI 点击仍未验收。

自动锁定合同：`xcrun swiftc -warnings-as-errors -swift-version 5 -O -framework SwiftUI -framework AppKit apps/macos/Model.swift scripts/test-desktop-lock.swift -o /tmp/rekey-desktop-lock-contract && /tmp/rekey-desktop-lock-contract`。测试使用合成会话、独立通知中心、命名测试剪贴板与注入的设备验证，不访问用户钥匙串、不弹系统验证、不实际锁屏/休眠。真实 CLI/Authority 的期限、防篡改、撤销、Agent 连续执行和审计失败另有合同覆盖；实际设备验证与原生点击验收仍需单独进行。参见 [自动锁定规范](../../docs/superpowers/specs/2026-10-02-native-auto-lock.md)。
