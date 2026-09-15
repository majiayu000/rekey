import SwiftUI
import AppKit

let ink = Color(red: 0.10, green: 0.17, blue: 0.15)
let green = Color(red: 0.10, green: 0.36, blue: 0.24)
let canvas = Color(red: 0.975, green: 0.98, blue: 0.966)
let sage = Color(red: 0.92, green: 0.95, blue: 0.92)

@main
struct RekeyApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        WindowGroup("rekey") {
            RootView().environmentObject(model)
                .frame(minWidth: 1040, minHeight: 700)
                .preferredColorScheme(.light)
        }
        .defaultSize(width: 1380, height: 870)
        .windowStyle(.hiddenTitleBar)
        .commands { CommandGroup(replacing: .newItem) {} }
    }
}

struct RootView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.scenePhase) var phase
    @State private var search = ""
    @State private var type = "全部类型"
    @State private var showActionForm = false
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer(); Text("rekey").font(.system(size: 12, weight: .semibold)); Spacer()
            }.frame(height: 30).background(canvas)
            Divider()
            HStack(spacing: 0) {
                sidebar
                Divider()
                VStack(alignment: .leading, spacing: 0) {
                    header
                    if let error = model.error {
                        HStack(alignment: .top) {
                            Image(systemName: "exclamationmark.circle")
                            Text(error).font(.system(size: 12)).textSelection(.enabled)
                            Spacer()
                            Button { model.error = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain)
                        }.foregroundStyle(Color.red).padding(14).background(Color.red.opacity(0.05)).padding(.horizontal, 28).padding(.bottom, 16)
                    }
                    if model.page == .settings || model.page == .backup {
                        pageContent
                    } else if model.status == nil {
                        welcome
                    } else if !model.unlocked && model.page != .audit && model.page != .policy {
                        locked
                    } else {
                        pageContent
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                if model.page == .credentials, model.unlocked, let credential = model.selected, filtered.contains(where: { $0.id == credential.id }) {
                    Divider()
                    credentialDetail(credential).frame(width: 306)
                }
            }
        }
        .background(canvas).foregroundStyle(ink).tint(green)
        .task { await model.refresh(); if model.status == nil && model.needsSetup { model.beginSetup() } }
        .onReceive(Timer.publish(every: 15, on: .main, in: .common).autoconnect()) { _ in
            if phase == .active && !model.busy && model.operation == nil && model.result == nil && !model.showAddCredential && !model.showSession && !showActionForm {
                Task { await model.refresh() }
            }
        }
        .onChange(of: search) { _, _ in model.selectedCredential = filtered.first?.id }
        .onChange(of: type) { _, _ in model.selectedCredential = filtered.first?.id }
        .onChange(of: model.page) { _, _ in Task { await model.refresh() } }
        .onChange(of: phase) { _, value in if value == .active { Task { await model.refresh() } } else { model.visibleSecret = nil } }
        .sheet(item: $model.operation) { OperationForm(operation: $0).environmentObject(model) }
        .sheet(isPresented: $model.showAddCredential) { AddCredentialForm().environmentObject(model) }
        .sheet(isPresented: $showActionForm) { ActionForm().environmentObject(model) }
        .sheet(isPresented: $model.showSession) { SessionForm().environmentObject(model) }
        .sheet(item: $model.result, onDismiss: { model.result = nil }) { ResultView(result: $0).environmentObject(model) }
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) { Image(systemName: "key.horizontal").font(.system(size: 30, weight: .medium)); Text("rekey").font(.system(size: 31, weight: .bold, design: .rounded)) }.foregroundStyle(green)
            Text("本机凭证管理").font(.system(size: 12)).foregroundStyle(.secondary).padding(.leading, 43).padding(.top, 3)
            Button { if let url = chooseFile(directory: true) { model.changeDirectory(url.path) } } label: {
                HStack { Image(systemName: "person.crop.square"); Text("个人工作区"); Spacer(); Image(systemName: "chevron.down").font(.system(size: 10)) }.padding(12)
            }.buttonStyle(.plain).background(.white.opacity(0.65), in: RoundedRectangle(cornerRadius: 7)).overlay(RoundedRectangle(cornerRadius: 7).stroke(.gray.opacity(0.2))).padding(.vertical, 28).help(model.stateDirectory).disabled(model.busy)
            ForEach(Page.allCases.filter { $0 != .settings }) { page in nav(page) }
            Spacer()
            nav(.settings)
            Divider().padding(.vertical, 15)
            HStack(spacing: 6) {
                Circle().fill(model.status == nil ? Color.gray : green).frame(width: 7, height: 7)
                Text(model.status?.label ?? "未连接").font(.system(size: 11))
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button(model.unlocked ? "锁定" : "解锁") {
                    if model.unlocked { Task { await model.lock() } }
                    else { unlock() }
                }.font(.system(size: 11, weight: .medium)).disabled(model.busy || (!model.unlocked && model.status?.state != "locked"))
            }
        }.padding(.horizontal, 20).padding(.top, 24).padding(.bottom, 20).frame(width: 210).background(sage.opacity(0.45))
    }
    private func nav(_ page: Page) -> some View {
        Button { model.page = page } label: {
            HStack(spacing: 14) {
                Image(systemName: page.icon).font(.system(size: 17)).frame(width: 22)
                Text(page.rawValue).font(.system(size: 14, weight: model.page == page ? .semibold : .regular))
                Spacer()
            }.padding(.horizontal, 12).frame(height: 44).contentShape(Rectangle())
        }.buttonStyle(.plain).background(model.page == page ? sage : Color.clear, in: RoundedRectangle(cornerRadius: 7)).foregroundStyle(model.page == page ? green : ink).padding(.bottom, 5)
    }
    private var header: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("个人工作区  /  \(model.page.rawValue)").font(.system(size: 12)).foregroundStyle(.secondary)
                Spacer()
                Button { Task { await model.refresh() } } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain).help("刷新真实服务状态").disabled(model.busy)
            }
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(model.page.rawValue).font(.system(size: 28, weight: .semibold))
                    Text(subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer()
                if model.page == .credentials {
                    Button { if model.desktopReady { model.showAddCredential = true } else { model.requestDesktopLogin() } } label: { Label("添加 API Key", systemImage: "plus") }.buttonStyle(PrimaryButton()).disabled(!model.unlocked || model.busy)
                } else if model.page == .actions {
                    Button { showActionForm = true } label: { Label("创建操作", systemImage: "plus") }.buttonStyle(PrimaryButton()).disabled(!model.unlocked || model.busy)
                }
            }
        }.padding(28)
    }
    private var subtitle: String {
        switch model.page {
        case .credentials: return "管理 Agent 使用的凭证与关联操作"
        case .actions: return "明确每个 Agent 可以执行的请求"
        case .policy: return "让权限范围、使用次数和有效期都清晰可见"
        case .approvals: return "审阅操作内容，再通过独立签名流程授权"
        case .audit: return "查询本机服务已记录的操作与结果"
        case .backup: return "备份加密数据，验证并恢复到新的目录"
        case .settings: return "管理本机服务与解锁方式"
        }
    }
    @ViewBuilder private var pageContent: some View {
        switch model.page {
        case .credentials: credentialsPage
        case .actions: actionsPage
        case .policy: policyPage
        case .approvals: approvalsPage
        case .audit: auditPage
        case .backup: backupPage
        case .settings: settingsPage
        }
    }
    private var welcome: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "key.horizontal").font(.system(size: 42, weight: .light)).foregroundStyle(green)
            Text("让 Agent 使用权限，\n让凭证留在本机。").font(.system(size: 29, weight: .medium)).lineSpacing(6)
            Text("首次使用只需设置密码，应用会自动创建保险库并启动服务。已有保险库可通过左侧工作区选择目录。").font(.system(size: 14)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text(model.stateDirectory).font(.system(size: 12, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled)
            HStack(spacing: 12) {
                Button(model.needsSetup ? "设置密码并开始" : "启动服务") { model.startService() }.buttonStyle(PrimaryButton())

            }.disabled(model.busy)
            if let error = model.connectionError {
                DisclosureGroup("连接详情") { Text(error).font(.system(size: 11)).foregroundStyle(.secondary).textSelection(.enabled) }.font(.system(size: 12))
            }
            Spacer()
        }.padding(42).frame(maxWidth: 620, maxHeight: .infinity, alignment: .topLeading)
    }
    private var locked: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock").font(.system(size: 42, weight: .light)).foregroundStyle(green)
            Text(model.status?.state == "locked" ? "保险库已锁定" : "服务暂不可用").font(.system(size: 23, weight: .medium))
            Text(model.status?.state == "locked" ? "解锁后查看凭证并管理授权。审计日志仍可查询。" : "当前服务状态：\(model.status?.state ?? "未知")。请停止服务并检查运行状态。").foregroundStyle(.secondary)
            Button("解锁保险库") { unlock() }.buttonStyle(PrimaryButton()).disabled(model.busy || model.status?.state != "locked")
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func unlock() { model.operation = Operation(title: "解锁保险库", detail: "输入密码或选择恢复密钥。", arguments: ["unlock"]) }

    private var filtered: [Credential] {
        model.credentials.filter { (search.isEmpty || $0.label.localizedCaseInsensitiveContains(search)) && (type == "全部类型" || $0.typeName == type) }
    }
    private var credentialsPage: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 16) {
                HStack { Image(systemName: "magnifyingglass").foregroundStyle(.secondary); TextField("搜索凭证名称", text: $search).textFieldStyle(.plain) }.padding(11).background(.white.opacity(0.55), in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.22)))
                Picker("类型", selection: $type) { Text("全部类型").tag("全部类型"); ForEach(Array(Set(model.credentials.map(\.typeName))).sorted(), id: \.self) { Text($0).tag($0) } }.labelsHidden().frame(width: 140)
            }.padding(.bottom, 22)
            HStack { Text("名称").frame(maxWidth: .infinity, alignment: .leading); Text("类型").frame(width: 120, alignment: .leading); Text("版本").frame(width: 50); Text("状态").frame(width: 62) }.font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary).padding(16).background(Color.gray.opacity(0.035))
            if filtered.isEmpty {
                EmptyState(icon: "key.horizontal", title: model.credentials.isEmpty ? "添加你的第一个凭证" : "没有匹配的凭证", detail: model.credentials.isEmpty ? "从固定令牌或已有的服务配置开始。" : "试试其他名称或类型。")
            } else {
                ScrollView {
                    LazyVStack(spacing: 0) {
                        ForEach(filtered) { credential in
                            Button { model.selectedCredential = credential.id } label: {
                                HStack(spacing: 12) {
                                    Image(systemName: credential.icon).font(.system(size: 22, weight: .light)).frame(width: 30)
                                    Text(credential.label).font(.system(size: 14, weight: .medium)).lineLimit(2).frame(maxWidth: .infinity, alignment: .leading)
                                    Text(credential.typeName).font(.system(size: 12)).frame(width: 120, alignment: .leading)
                                    Text("v\(credential.current_version)").font(.system(size: 12, design: .monospaced)).frame(width: 50)
                                    StatusPill(active: credential.active, text: credential.active ? "可用" : "已撤销").frame(width: 62)
                                }.padding(.horizontal, 16).frame(minHeight: 76).background(model.selectedCredential == credential.id ? sage.opacity(0.8) : Color.clear).contentShape(Rectangle())
                            }.buttonStyle(.plain)
                            Divider()
                        }
                    }
                }
            }
            Spacer(minLength: 18)
            Label("已存储的凭证不提供明文查看", systemImage: "lock").font(.system(size: 12)).foregroundStyle(.secondary).padding(.vertical, 18)
            Divider()
            HStack(spacing: 16) {
                step(1, "添加凭证", "接入所需的凭证") { model.showAddCredential = true }
                step(2, "配置固定操作", "注册允许执行的请求") { model.page = .actions }
                step(3, "授予 Agent 权限", "设置范围与有效期") { model.page = .policy }
            }.padding(.vertical, 24)
        }.padding(.horizontal, 28)
    }
    private func step(_ number: Int, _ title: String, _ detail: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 9) {
                Text(String(number)).font(.system(size: 13, weight: .medium)).frame(width: 26, height: 26).overlay(Circle().stroke(.gray.opacity(0.5)))
                VStack(alignment: .leading, spacing: 5) { Text(title).font(.system(size: 12, weight: .medium)); Text(detail).font(.system(size: 10)).foregroundStyle(.secondary) }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.buttonStyle(.plain).disabled(model.busy)
    }
    private func credentialDetail(_ item: Credential) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack { Text("凭证详情").font(.system(size: 15, weight: .semibold)); Spacer(); Button { model.selectedCredential = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).foregroundStyle(.secondary) }
            HStack { Image(systemName: item.icon).font(.system(size: 24)); Text(item.label).font(.system(size: 22, weight: .semibold)).lineLimit(3) }.padding(.top, 10)
            StatusPill(active: item.active, text: item.active ? "可用" : "已撤销")
            info("类型", item.typeName)
            info("当前版本", "v\(item.current_version)")
            Text(model.visibleSecret ?? "••••••••••••••••").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            HStack {
                Button(model.visibleSecret == nil ? "显示密钥" : "隐藏密钥") {
                    if model.visibleSecret != nil { model.visibleSecret = nil }
                    else { Task { await model.revealCredential(item.id, copy: false) } }
                }
                Button(model.copiedCredential == item.id ? "已复制" : "复制密钥") { Task { await model.revealCredential(item.id, copy: true) } }
            }.disabled(!item.active || model.busy)
            Text("复制后 30 秒清理本次剪贴板内容；剪贴板历史工具可能保留副本。").font(.system(size: 11)).foregroundStyle(.secondary)
            Divider().padding(.vertical, 4)
            Text("关联操作").font(.system(size: 14, weight: .semibold))
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    let linked = model.actions.filter { $0.credential_id == item.id }
                    if linked.isEmpty { Text("尚未配置关联操作").font(.system(size: 12)).foregroundStyle(.secondary) }
                    ForEach(linked) { action in
                        VStack(alignment: .leading, spacing: 8) { Text(action.name).font(.system(size: 13, weight: .medium)); Text("\(action.method) \(action.exact_path)").font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled) }.frame(maxWidth: .infinity, alignment: .leading).padding(14).background(.white.opacity(0.4), in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.18)))
                    }
                }
            }
            Label("Agent 通过已授权操作使用凭证，无法读取凭证内容。", systemImage: "info.circle").font(.system(size: 11)).foregroundStyle(.secondary).padding(13).background(sage.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
            Spacer(minLength: 12)
            HStack {
                Button("轮换凭证") { rotate(item) }.buttonStyle(SecondaryButton())
                Spacer()
                Button("撤销凭证", role: .destructive) { model.operation = Operation(title: "撤销凭证", detail: "撤销“\(item.label)”后，关联操作将无法继续使用此凭证。", arguments: ["credential", "revoke", item.id]) }.buttonStyle(.plain).foregroundStyle(.red)
            }.disabled(!item.active || model.busy)
            Text("敏感操作需再次验证身份").font(.system(size: 11)).foregroundStyle(.secondary)
        }.padding(23).frame(maxHeight: .infinity, alignment: .topLeading)
    }
    private func rotate(_ item: Credential) {
        if item.kind == "opaque-token" {
            model.operation = Operation(title: "轮换凭证", detail: "替换“\(item.label)”的凭证值。", arguments: ["credential", "rotate", item.id], newSecret: true)
        } else if let file = chooseFile() {
            let commands = ["github-app-installation": "rotate-github-app", "vault-kv-v2-source": "rotate-vault-kv", "vault-dynamic-source": "rotate-vault-dynamic", "keycloak-token-exchange": "rotate-keycloak"]
            guard let command = commands[item.kind] else { model.error = "当前客户端不支持此凭证类型。"; return }
            model.operation = Operation(title: "轮换凭证", detail: "用所选私有配置文件替换“\(item.label)”的配置。", arguments: ["credential", command, item.id, "--file", file.path])
        }
    }
    private var actionsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack { Text("操作固定了目标、方法和路径，Agent 无法任意改写。").font(.system(size: 12)).foregroundStyle(.secondary); Spacer(); Button("导入定义") { importAction() }.disabled(!model.unlocked || model.busy) }
                if model.actions.isEmpty { EmptyState(icon: "play.rectangle", title: "还没有固定操作", detail: "创建一个操作，选择凭证并设置请求目标。") }
                ForEach(model.actions) { action in
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { Text(action.name).font(.system(size: 17, weight: .medium)); Text("v\(action.version)").foregroundStyle(.secondary); Spacer(); StatusPill(active: action.enabled, text: action.enabled ? "已启用" : "已禁用") }
                        Text("\(action.method) \(action.origin)\(action.exact_path)").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        HStack { Text(model.credentials.first { $0.id == action.credential_id }?.label ?? action.credential_id).font(.system(size: 12)).foregroundStyle(.secondary); Spacer(); Button("更新定义") { importAction(action.id) }; Button("禁用", role: .destructive) { model.operation = Operation(title: "禁用操作", detail: "禁止后续执行“\(action.name)”。", arguments: ["action", "disable", action.id]) }.disabled(!action.enabled) }.disabled(model.busy)
                    }.padding(20).background(.white.opacity(0.55), in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(.gray.opacity(0.16)))
                }
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
    private func importAction(_ id: String? = nil) {
        guard let file = chooseFile() else { return }
        let args = id.map { ["action", "update", $0, "--file", file.path] } ?? ["action", "create", "--file", file.path]
        model.operation = Operation(title: id == nil ? "导入操作" : "更新操作", detail: "导入 \(file.lastPathComponent)。服务会验证目标、权限和请求限制。", arguments: args)
    }
    private var policyPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 25) {
                SectionCard(title: "当前策略", icon: "checkmark.shield") {
                    if let policy = model.policy {
                        info("状态", policy.status == "active" ? "已生效" : policy.status == "expired" ? "已过期" : policy.bundle_persisted ? "已保存，解锁后加载" : "尚未激活")
                        info("信任根", policy.trust_installed ? "已安装" : "未安装")
                        if let version = policy.version { info("生效版本", "v\(version)") }
                        if let expires = policy.expires_at_ms { info("有效期至", displayDate(expires)) }
                    }
                    HStack {
                        Button("安装信任根") { importPolicy(trust: true) }
                        Button("激活签名策略") { importPolicy(trust: false) }
                    }.disabled(!model.unlocked || model.busy)
                    Text("导入由外部签名工具生成的文件。创建授权本身不会绕过默认拒绝策略。").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                SectionCard(title: "Agent 授权", icon: "person.badge.key") {
                    Text("按固定操作授予短期权限，限制有效期与使用次数。授权令牌只在创建完成时显示。").font(.system(size: 13)).foregroundStyle(.secondary)
                    HStack {
                        Button("创建授权") { model.showSession = true }.buttonStyle(PrimaryButton())
                        Button("撤销授权") { model.operation = Operation(title: "撤销授权", detail: "输入需要撤销的会话 ID。", arguments: ["session", "revoke"]) }.buttonStyle(SecondaryButton())
                    }.disabled(!model.unlocked || model.busy)
                    Text("服务锁定或重启会撤销会话。MCP 与 shell 接入使用同一套固定操作权限。").font(.system(size: 12)).foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
    private func importPolicy(trust: Bool) {
        guard let file = chooseFile() else { return }
        model.operation = Operation(title: trust ? "安装信任根" : "激活策略", detail: "使用 \(file.lastPathComponent)。信任根每个保险库只能安装一次。", arguments: trust ? ["policy", "trust", "install", "--file", file.path] : ["policy", "activate", "--file", file.path], proofFlag: "--step-up-stdin")
    }
    private var approvalsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 15) {
                if model.approvals.isEmpty { EmptyState(icon: "tray", title: "没有待审批请求", detail: "Agent 提交的有效审批请求会出现在这里。") }
                ForEach(model.approvals) { item in
                    SectionCard(title: model.actions.first { $0.id == item.action_id }?.name ?? "固定操作", icon: "doc.text.magnifyingglass") {
                        info("会话", item.session_id)
                        info("所需签名", "\(item.quorum) 人")
                        info("有效期至", displayDate(item.max_expires_at_ms))
                        Text("参数摘要 \(item.parameter_sha256)").font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        Button("导出签名信封") { Task { await model.exportApproval(item) } }.disabled(model.busy)
                    }
                }
                Text("导出后，使用独立审批签名工具审阅具体请求并签发 grant；本窗口不保管审批私钥。").font(.system(size: 12)).foregroundStyle(.secondary)
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
    private var auditPage: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Picker("结果", selection: $model.auditOutcome) { Text("全部结果").tag(""); Text("成功").tag("success"); Text("拒绝").tag("denied"); Text("失败").tag("failure"); Text("不确定").tag("indeterminate") }.frame(width: 190)
                    .onChange(of: model.auditOutcome) { _, _ in Task { await model.refresh() } }
                Spacer()
                Button("导出 JSONL") {
                    if let file = chooseSave("rekey-audit.jsonl") {
                        var args = ["audit", "export", "--output", file.path]
                        if !model.auditOutcome.isEmpty { args += ["--outcome", model.auditOutcome] }
                        let op = Operation(title: "导出审计", detail: "", arguments: args, proof: false)
                        Task { await model.perform(op) }
                    }
                }.disabled(model.busy)
            }
            ScrollView {
                LazyVStack(spacing: 0) {
                    ForEach(model.audit?.events ?? []) { event in
                        VStack(alignment: .leading, spacing: 8) {
                            HStack { Text(event.event_type).font(.system(size: 13, weight: .medium, design: .monospaced)); Spacer(); Text(event.outcome).font(.system(size: 11)).foregroundStyle(event.outcome == "success" ? green : .secondary) }
                            HStack { Text(displayDate(event.created_at_ms)); Spacer(); Text(event.reason_code).lineLimit(2) }.font(.system(size: 11)).foregroundStyle(.secondary)
                        }.padding(.vertical, 14)
                        Divider()
                    }
                }
            }
            HStack { Text("稳定快照 · 每页最多 50 条").font(.system(size: 11)).foregroundStyle(.secondary); Spacer(); Button("最新记录") { Task { await model.refresh() } }; Button("下一页") { Task { await model.refresh(nextAuditPage: true) } }.disabled(model.audit?.next_before_sequence == nil) }.disabled(model.busy).padding(.bottom, 24)
        }.padding(.horizontal, 28)
    }
    private var backupPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                SectionCard(title: "创建加密备份", icon: "externaldrive.badge.plus") {
                    Text("导出保险库的加密快照。请同时保存完成后的 SHA-256 回执，用于恢复校验。").font(.system(size: 13)).foregroundStyle(.secondary)
                    Button("选择备份位置") { if let file = chooseSave("rekey-backup.sqlite") { model.operation = Operation(title: "创建备份", detail: "备份到 \(file.path)。目标必须是新文件。", arguments: ["backup", "--output", file.path]) } }.buttonStyle(PrimaryButton()).disabled(!model.unlocked || model.busy)
                }
                SectionCard(title: "从备份恢复", icon: "arrow.counterclockwise") {
                    Text("选择备份，再选择一个新的空目录。恢复需要匹配版本的备份、校验值与解锁证明，不会覆盖当前保险库。").font(.system(size: 13)).foregroundStyle(.secondary)
                    Button("选择备份文件") { if let file = chooseFile() { model.operation = Operation(title: "恢复备份", detail: "恢复 \(file.lastPathComponent)。请输入回执中的 SHA-256，并选择空目录。", arguments: ["restore", "--input", file.path]) } }.buttonStyle(SecondaryButton()).disabled(model.busy)
                }
            }.padding(.horizontal, 28)
        }
    }
    private var settingsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 22) {
                SectionCard(title: "本机工作区", icon: "folder") {
                    Text(model.stateDirectory).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    Button("切换数据目录") { if let url = chooseFile(directory: true) { model.changeDirectory(url.path) } }.disabled(model.busy)
                    if let status = model.status { info("服务版本", status.runtime_version); info("数据格式", "v\(status.format_version)") }
                    HStack { Button("启动服务") { model.startService() }.disabled(model.status != nil); Button("停止服务") {
                        let op = Operation(title: "停止服务", detail: "正在执行的操作会按服务的退出规则收尾。", arguments: ["shutdown"], proof: model.unlocked)
                        if model.unlocked { model.operation = op } else { Task { await model.perform(op) } }
                    }.disabled(model.status == nil) }.disabled(model.busy)
                    Text("关闭窗口不会停止服务；服务会继续按空闲锁定规则运行。").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                SectionCard(title: "解锁与恢复", icon: "lock.rotation") {
                    Button("修改密码") { model.operation = Operation(title: "修改密码", detail: "旧密码将不再解锁当前保险库。历史备份不受这次修改影响。", arguments: ["password", "change"], newSecret: true, confirmSecret: true) }
                    Button("轮换恢复密钥") { model.operation = Operation(title: "轮换恢复密钥", detail: "必须使用当前密码。新恢复密钥只显示一次，请安全保存。", arguments: ["recovery", "rotate"], sensitiveResult: true, recoveryAllowed: false) }
                }.disabled(!model.unlocked || model.busy)
                Text("Rekey 本地管理 · macOS 源码预览\n凭证、策略与审计由本机服务持有。").font(.system(size: 12)).foregroundStyle(.secondary)
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
}

func info(_ label: String, _ value: String) -> some View {
    HStack(alignment: .top) { Text(label).foregroundStyle(.secondary); Spacer(minLength: 18); Text(value).multilineTextAlignment(.trailing).textSelection(.enabled) }.font(.system(size: 12))
}
struct StatusPill: View {
    let active: Bool
    let text: String
    var body: some View { Text(text).font(.system(size: 11, weight: .medium)).padding(.horizontal, 9).padding(.vertical, 4).foregroundStyle(active ? green : Color.red).background(active ? sage : Color.red.opacity(0.08), in: Capsule()) }
}
struct PrimaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View { configuration.label.font(.system(size: 13, weight: .medium)).padding(.horizontal, 16).padding(.vertical, 10).foregroundStyle(.white).background(green.opacity(!enabled ? 0.4 : configuration.isPressed ? 0.8 : 1), in: RoundedRectangle(cornerRadius: 7)) }
}
struct SecondaryButton: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { configuration.label.font(.system(size: 13, weight: .medium)).padding(.horizontal, 14).padding(.vertical, 9).foregroundStyle(green).background(configuration.isPressed ? sage : .clear, in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(green.opacity(0.6))) }
}
struct EmptyState: View {
    let icon: String, title: String, detail: String
    var body: some View { VStack(spacing: 13) { Image(systemName: icon).font(.system(size: 34, weight: .light)).foregroundStyle(green.opacity(0.75)); Text(title).font(.system(size: 18, weight: .medium)); Text(detail).font(.system(size: 12)).foregroundStyle(.secondary) }.frame(maxWidth: .infinity).padding(.vertical, 70) }
}
struct SectionCard<Content: View>: View {
    let title: String
    let icon: String
    @ViewBuilder let content: Content
    var body: some View { VStack(alignment: .leading, spacing: 17) { Label(title, systemImage: icon).font(.system(size: 17, weight: .medium)); content }.padding(22).frame(maxWidth: .infinity, alignment: .leading).background(.white.opacity(0.65), in: RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(.gray.opacity(0.17))) }
}
