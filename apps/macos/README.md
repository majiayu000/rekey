# Rekey macOS UI

原生 SwiftUI 本机管理客户端，按已接受的中文浅色凭证管理设计实现。需要 macOS 14+ 和 Xcode Command Line Tools；无需 Node、浏览器服务或新数据库。

## 构建与打开

```bash
scripts/build-macos-ui.sh
open target/macos-ui/Rekey.app
```

脚本将当前源码的 `rekey` / `rekeyd` 打包到 app 内，并在本机做 ad-hoc 签名。`REKEY_UI_OUTPUT` 可指定构建输出位置，`CARGO_TARGET_DIR` 沿用 Cargo 的构建缓存配置。不包含公证或公开发布。

应用图标源文件为 `Resources/AppIcon.png`（1024 × 1024）。构建脚本使用 macOS 自带的 `sips` 和 `iconutil` 生成标准尺寸的 `AppIcon.icns`，通过 `CFBundleIconFile` 配置 Finder 与 Dock 图标。当前采用用户选定的“双环 · 现代平面”：炭黑背景、米白与橙色双环。图标由内置 imagegen 基于双环参考图生成，提示词为“以参考图为基础，为 Rekey app 创作一个「现代平面设计」风格图标。保留双环相扣的识别结构，材质、配色与表现方式自由发挥。成熟、有个性，避免常见 AI 霓虹渐变。单张正方形图标，无文字。”

首次打开时默认使用 `~/.rekey`。首次启动自动显示密码设置流程；输入并确认密码后自动创建保险库并启动服务，恢复密钥只在完成窗口显示一次。已有保险库请启动服务，再解锁。也可以通过“个人工作区”或设置切换目录。格式不兼容或目录非空时沿用 CLI 的明确拒绝，不迁移、不覆盖。

## 当前入口

- 凭证：真实列表、搜索、类型过滤、关联操作；添加/轮换/撤销。固定令牌由安全输入框录入，其他类型选择已有的私有 JSON profile。
- 固定操作：表单创建，定义文件导入/更新/禁用。表单采用 30 秒、64 KiB 请求、256 KiB 响应的当前默认；更细的限制通过定义文件配置。
- 授权与策略：按操作创建短期 capability、按会话 ID 撤销；安装信任根、导入签名策略并查看状态。没有全量活动会话列表。
- 审批：真实 pending 收件箱和来源签名信封导出；继续在独立工具里审阅/签名。
- 审计：结果筛选、稳定快照分页和 JSONL 导出，锁定时仍可读取。
- 备份恢复：新文件加密备份与回执、SHA-256 验证的空目录离线恢复。
- 设置：密码修改、恢复密钥轮换、数据目录、服务启动/停止。

策略和审批私钥不交给 UI。外部签名工具的源码构建命令：

```bash
cargo build --release -p rekey-policy --bin rekey-policy-sign --bin rekey-approval-sign
target/release/rekey-policy-sign --help
target/release/rekey-approval-sign --help
```

签名文件的准备和 Agent shell/MCP 接入继续见根目录 `docs/user-guide.md`。这一版没有自动配置 Agent、GUI 签名、任意执行控制台或常驻通知。

关闭 UI 不会终止 Broker；默认由 Broker 在空闲 7 天后锁定。可主动点击“锁定”或设置里的“停止服务”。不缓存密码；手动解锁后，随机恢复密钥保存在 macOS 钥匙串，保险库只保存绑定 vault ID 与到期时间的加密根密钥材料。7 天内重启应用或服务可自动恢复解锁，自动恢复不延长原到期时间。手动锁定、空闲锁定或更改密码/恢复密钥会撤销授权；正常停止服务保留授权。管理会话允许连续添加 API Key 和显式查看/复制当前有效凭证。复制后 30 秒只清理本应用仍占有的剪贴板内容，无法清理第三方历史记录；短期 capability 和恢复结果只在当前结果窗口中存在，用户可显式保存为新建的 0600 文件。

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
