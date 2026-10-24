# 分发设置（维护者一次性操作）

发布 tag 仍需所有者单独授权。本页只说明 Homebrew tap 与 App 内更新依赖的外部设置；不创建 tag、Release、tap 仓库或 secret。

## Homebrew tap

`release.yml` 的 `homebrew-tap` job 在 `public-url-smoke` 通过后运行：从已公开的 Release 下载 macOS pkg，要求其 SHA-256 与 `public-url-smoke` 实际安装测试过的字节一致（macOS smoke 上传的 `smoke-tested-macos-pkg` artifact），同时符合 Release 的 `.sha256` 并通过 `gh attestation verify`，然后用 `scripts/generate-homebrew-cask.py` 重新生成 cask，并与 Release 中的 `rekey.rb` 逐字节比较，然后向 `<owner>/homebrew-rekey` 的默认分支开一个更新 `Casks/rekey.rb` 的 PR。未配置 `TAP_TOKEN` 时该 job 只输出提示并成功结束；tap 失败不会撤回已公开的 Release。

一次性设置：

1. 创建公开仓库 `majiayu000/homebrew-rekey`，勾选初始化 README（job 需要一个已有的默认分支作为 PR 基础）。
2. 创建 fine-grained personal access token：仅授权 `majiayu000/homebrew-rekey`，权限 **Contents: Read and write**、**Pull requests: Read and write**，设置到期时间。
3. 在 `majiayu000/rekey` → Settings → Secrets and variables → Actions 新建 repository secret `TAP_TOKEN`，值为上一步的 token。
4. 发布后审阅并合并 tap 仓库里的 `rekey <版本>` PR。合并后用户可执行 `brew install --cask majiayu000/rekey/rekey`。

cask 声明 `livecheck`（GitHub Releases，包含预发布、跳过草稿和改号前的 v2/v3 标签）、卸载时退出 `com.starlight.rekey`、尝试用 `launchctl` 停止 `com.rekey.rekeyd` 并按 receipt 删除 pkg 文件。`launchctl` 不能注销 SMAppService 登录项，卸载前仍须在 App 中关闭登录启动并以新的证明停止服务；不删除保险库数据或钥匙串条目。真实安装、升级与卸载验收仍需在签名设备上单独完成。

## App 内检查更新

设置页的“检查更新”读取 `https://api.github.com/repos/majiayu000/rekey/releases`（含预发布，跳过草稿和改号前的 v2/v3 标签），只提示带 `rekey-<tag>-macos.pkg` 资产、且发布页地址为本仓库 `releases/tag/<tag>` 的更高版本，然后用“打开发布页”跳转到该页。App 不下载、不校验、不安装；用户在发布页下载 pkg，由 Installer / Gatekeeper 验证签名与公证。

未认证的 GitHub API 每个 IP 每小时 60 次，App 只在用户点击时请求。提示文字提醒用户安装前先“停止并停用登录启动”并退出 App；跨版本线升级（如 0.4 → 0.5）需要新的保险库。
