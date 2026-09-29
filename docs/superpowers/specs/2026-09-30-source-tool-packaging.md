# 源码工具发布包补齐

日期 2026-09-30。按用户全量功能实现与测试要求，补齐既有工具进入未来归档的配置。当前公网下载和版本号不变，不创建标签或进行发布。

最小范围是现有六个二进制 rekey、rekeyd、rekey-github-create-issue、rekey-mcp、rekey-policy-sign、rekey-approval-sign，与 service-unit、agent-quickstart、operator-credential-repair、backup-sync 及本轮 audit-delivery Python入口。没有新的插件发现或安装系统。

发布workflow构建并在macOS逐一签名全部二进制；归档清单要求文件可执行、辅助入口存在、文档引用可用。归档验收启动真实MCP进程完成初始化和工具枚举，并验证signer与Python入口来自解包目录。已接受的macOS Seatbelt入口应在候选归档中验收成功启动；旧版alpha.2的unsupported行为不再是开发归档的断言。

已有签名器、MCP、onboarding、repair和backup的语义合同仍需运行。新工具的源码测试通过不等于签名/公证、公开下载或安装烟测完成。版本、发布成员成熟度以及真实Apple签名材料在后续发布闭环中核对，不在本项声称完成。
