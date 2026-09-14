# GHA-11 真实验收结果

2026-09-10：已完成两仓库真实 GitHub 签名事件与 Admin apply 验收。Excel P0/P1 的8项均已验收完成，主仓库尚未提交或推送。

- App 4894893、installation 160538357，仅本轮测试仓库 A/B。
- GitHub added delivery 3841904713563914240：验签后版本1→2，同capability列表精确为A+B，B写入201。
- GitHub removed delivery：版本2→3，列表恢复A。旧B Action返回 REQUEST_DENIED，关联审计只有 started→blocked，原因为 github-profile-mismatch，没有GitHub授权或网络执行链。
- 篡改字节和旧expected-version重放均拒绝，版本不变。4次成功请求按request ID校验 started→authorized→token_revoked→finished，全success且binding commitment一致。
- GitHub delivery REST API返回的payload只有在恢复字节与GitHub记录的HMAC完全匹配时才用于验收。配置的HTTP目标返回403；这是官方delivery API取回后Admin应用的验证，不是公网接收端部署成功。
- connector_contract 1项、本轮cargo check和diff检查通过。没有修改Rust实现或削弱网络筛选。

完整脱敏回执位于 `docs/evidence/github-app-repository-webhook-2026-09-10.json`。本目录 `acceptance-fixture.py` 保存本轮分阶段验收逻辑；它依赖已销毁的临时配置，不能当作一键公共安装器。

App及两个临时仓库的API查询均为404，installation已删除，本地broker已停，测试authority、signer、capability和明文秘密已清理。本机hosts和代理未修改。早期fixture错误地附加额外Header，Rekey正确拒绝；移除fixture Header后完成正式通过路径，没有自动重试写请求。

参考：[GitHub App webhook delivery API](https://docs.github.com/en/rest/apps/webhooks)。下一候选是Excel中的BAK-06外部备份调度，应先确定最小运维规格，不往Broker添加调度平台。
