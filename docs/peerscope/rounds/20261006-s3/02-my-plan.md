# Rekey 后续处理 — 20261006-s3

发布基线保持 `043a020` / v0.3.0-alpha.1；本轮修复候选单独记录，不改写历史比较。
工作区：`/Users/lifcc/Desktop/code/AI/tools/rekey-peerscope-fixes`，分支 `codex/resolve-peerscope-blockers-20261006`。

## 已落实的选择与修正

1. **本轮不接入第三方密码库**，用户已明确选择。使用现有本机 vault；不永久排除未来接入，也不新增抽象或配置。
2. **定位**：Rekey 是本机 API 凭据执行器：Agent 只执行你授权的操作，拿不到上游 Key。README 已采用；授权范围内仍可误用，反射检查不防任意变换与隐蔽信道。
3. **上手**：Anthropic、OpenAI、GitHub PAT、GLM 与固定 Bearer 模板已经内置。README/指南已说明安装、签署 Profile 与启动的顺序。`rekey add` 目前只接受 `anthropic`；其它模板从 App 安装，不编造不存在的快捷命令。
4. **同机边界**：README 已说明 L1-dev 只确认 Agent API 边界，不能承诺抵抗同用户任意代码；L1/L2 各需设备/隔离验收。旧 G1/G2 参考不等于当前 Profile L2。
5. **mTLS/SSH**：不并入本次0.3修复，也不算下次发布版复评能力。独立候选可以按固定SHA另列；真正合并、发布和协议验收后才能升级对应结论。其0.4存储变化不能越过vault25/policy6冻结。

## SSE修复与验收

从 `main@043a020` 整合现有 `competitive-next@2e1a152` 的性能/正确性修复，未增加SSH/mTLS/PKI/团队/HA功能。
主要修复是回收已发送并检查的raw前缀、收缩完整反射检测后不必保留的工具metadata尾，并按有界输入part让出调度。
保留完整字面量/编码投影、累计wire/retained限额、审计先行、EOF终帧结算、取消/撤销错误合同和零化；格式不变。

候选此前已经完成 `optimized-v6`：432格、27,648次，成功正文SHA-256 mismatch为0；4MiB text/tool SSE在c1、c4各192/192成功。
本轮核对13个关键源码文件与既有测量overlay全部一致，两个不可覆盖release测试binary哈希均一致。
本轮原协议三轮回归12格/768次：text/tool各在c1、c4下完成192/192，完整正文SHA-256 mismatch为0；12个反射探针全部502且未反射。driver、server及fixture全部exit0。运行时其它用户进程/测试仍在活动，故只判断成功率、正文和反射拒绝，不提供新延迟排名。源文件和binary一致不代表已发布包相同，也不替代真实provider验收。

本轮整合验收：`cargo test --workspace --locked -- --test-threads=1` exit0，1,069 passed / 0 failed / 6 ignored；fmt、默认/all-targets/all-features check、默认严格Clippy、禁止secret API及CLI依赖合同通过。没有把lab完整运行测试、设备或真实provider填成通过。

本机证据：`/Users/lifcc/Desktop/code/AI/tools/rekey/.git/codex/evidence/peerscope-resolution-20261006/`。
原完整复测：`.git/codex/evidence/competitive-optimization-20261005/tranche-012-sse-yield/`。

## 发布时机与推广

v0.3.0-alpha.1 已于2026-10-05公开发布，见[release](https://github.com/majiayu000/rekey/releases/tag/v0.3.0-alpha.1)；“没有任何发布”应改为“尚未检索到HN推广帖”。
建议将本次修复作为下一个0.3 alpha候选：最终提交必需CI通过，再用既有签名、公证、安装和公开下载smoke工作流发布；不能复用已存在的alpha.1 tag。
发布前保留L1-dev下限和设备未验项，不把SSE组件成功、模板存在或代码检查当作安装后真人验收。
本轮未创建tag、安装、推送、发布或发送HN帖；这些外部动作须由用户明确授权。
推广时使用上述一句话定位与实际公开下载链接，回答同用户攻击边界，公开失败/未验项；72小时后记录关注、issue和反对意见。

## 暂缓与证据不足

- `.env`自动导入未实现；本轮先保留人工App录入，避免在自用期扩功能。首次真实provider成功前的耗时、密码/系统认证次数仍须真人记录，不能声称10分钟目标已经达标。
- “认知层先断”是根据公开关注度/未检索到HN帖作出的假设，没有转化和留存数据，不能据此排除产品/上手问题。
- HN痛点只到D1；本轮没有伪造Reddit、X、小红书或V2EX登录态采样。追加平台证据待实际可用渠道。
- [WorkOS Relay官方文档](https://workos.com/docs/pipes/relay)明确early access及WorkOS API key仍需保护；[官方博客](https://workos.com/blog/credentials-out-of-agent-context)自述8月6日推出，升级为E2，未实测。
- [Bitwarden官方公告](https://bitwarden.com/blog/introducing-agent-access-sdk/)明确OneCLI集成，升级为E2，未实测；其SDK的子进程env注入与OneCLI网关代调用是不同边界。
- [Keychains.dev官方quickstart](https://keychains.dev/docs)及[威胁模型](https://keychains.dev/docs/threat-model)确认其自述服务器注入、scope授权，也承认scope内误用边界；功能描述升级E2，未实测。Product Hunt具体发布日期仍E1。新候选源码和运行覆盖未补齐，不能升级为产品优势。
