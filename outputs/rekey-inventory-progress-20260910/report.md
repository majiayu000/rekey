# Excel P0/P1 执行进度

2026-09-10。最初对齐时7项验收完成；后续GHA-11也已完成，见 `outputs/rekey-gha11-20260910/report.md`，原表P0/P1的8项现均已验收。当前未提交的脚本和文档不属于已公开 alpha.2 的产物。

- ENV-01：本轮 api.github.com 解析为公网 IPv4 172.182.252.137。本轮未修改本机 hosts 或代理，当前 hosts 无临时 Cloudflare 条目。
- REL-01：公开 v2.0.0-alpha.2 对应 c25d32db3db4e1a2efbb656b1c729a993ee0bd9e。run 34329532708 双平台 build、fresh-install、public-url-smoke 均成功，Release 非 draft，11份附件已上传。原始查询见 release-run.json、release-assets.json。
- ENV-02、VFY-03：重新核对 run 34447873706 为 success。已归档公网 KV、动态 PostgreSQL 登录及 revoke 后角色删除证据。新增 interop spec §7，并同步功能基线的限定动态租约成熟度。
- UX-01、MCP-04：当前 Python 真实 TTY 4项通过。已有 Codex shell-host 公网读200及 GitHub App 写201证据，未泛化到独立模型会话或 MCP Server。
- REL-02：审查现有脚本/CI diff，完成本轮 cargo check、cargo fmt --all --check、cargo test --workspace（393通过、1忽略）、禁止 API 与 CLI 依赖检查。没有主仓库 commit/push，其他既有修改保留。

## GHA-11 原验收计划（现已执行完成）

已有单仓库回执证明读200、typed profile version2、写201和三条 token_revoked 在 finished 之前的成功审计链。不能把它算成仓库增删验收。原 App 已删除，注册入口当前可访问。

1. 新专用 App 安装到仓库 A；记录两把公钥的指纹、版本和同一个 capability。换到 key B 后由操作者撤销 provider key A，再验证新 key 的调用。Rekey 本身不负责删除 GitHub 旧 key。
2. 给 installation 加入测试仓库 B，保存 GitHub 实际生成的原始 delivery 和签名。篡改 body 应拒绝且版本不变；原始 delivery apply 后版本递增、列表精确 A+B；旧 expected-version 重放拒绝。
3. 移除 B，应用真实 removed delivery，列表恢复 A。已注册的 B Action 应被拒绝且没有 authorized/token exchange 链，证明旧仓库配置失效。
4. 回执保留非敏感 request ID、Action、binding commitment 和有序审计。随后删除本轮 App、installation、临时仓库与明文材料。

只读 thread `/root/onboarding_review` 已审查上述缺口。既有本地 P6 fixture 覆盖签名、版本和范围收窄，但不能替代 GitHub 实际 delivery。P2/P3 仍按实际需求先做最小规格，不整批实现。
