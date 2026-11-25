import SwiftUI
import AppKit
import UserNotifications

/// One color per appearance; the App follows the system light or dark setting.
func adaptive(_ light: (CGFloat, CGFloat, CGFloat), _ dark: (CGFloat, CGFloat, CGFloat)) -> Color {
    Color(nsColor: NSColor(name: nil) { appearance in
        let c = appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua ? dark : light
        return NSColor(srgbRed: c.0, green: c.1, blue: c.2, alpha: 1)
    })
}
let ink = adaptive((0.10, 0.17, 0.15), (0.90, 0.93, 0.91))
let green = adaptive((0.10, 0.36, 0.24), (0.45, 0.78, 0.60))
let canvas = adaptive((0.975, 0.98, 0.966), (0.11, 0.12, 0.115))
let sage = adaptive((0.92, 0.95, 0.92), (0.17, 0.23, 0.20))
let surface = adaptive((1, 1, 1), (0.15, 0.165, 0.158))
/// Filled buttons keep white text readable in both appearances.
let buttonFill = adaptive((0.10, 0.36, 0.24), (0.16, 0.48, 0.33))

/// Opening a request notification only brings the inbox forward; it never approves anything.
final class NotificationRouter: NSObject, UNUserNotificationCenterDelegate {
    weak var model: AppModel?
    static let inboxURL = URL(string: "rekey://inbox")!
    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        await MainActor.run {
            // With every window closed, only an external event recreates the
            // SwiftUI window; the URL handler then selects the inbox.
            if NSApp.windows.contains(where: { $0.isVisible }) {
                model?.page = .approvals
                NSApp.activate(ignoringOtherApps: true)
            } else {
                NSWorkspace.shared.open(Self.inboxURL)
            }
        }
    }
}
let notificationRouter = NotificationRouter()

@main
struct RekeyApp: App {
    @StateObject private var model = AppModel()
    var body: some Scene {
        WindowGroup("rekey") {
            RootView().environmentObject(model)
                .frame(minWidth: 1040, minHeight: 700)
                .handlesExternalEvents(preferring: ["*"], allowing: ["*"])
        }
        .handlesExternalEvents(matching: ["*"])
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
    @State private var activityDetail:ActivityRow?
    @State private var showConnectGuide = false
    private var lab: Bool { model.status?.lab_enabled == true }
    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Spacer(); Text("Rekey").font(.system(size: 12, weight: .semibold)); Spacer()
            }.frame(height: 30).background(canvas)
            Divider()
            HStack(spacing: 0) {
                sidebar
                Divider()
                VStack(alignment: .leading, spacing: 0) {
                    // Before a vault exists the page header has nothing to act on.
                    if model.status != nil || model.page == .settings || model.page == .backup { header }
                    if let error = model.error {
                        HStack(alignment: .top) {
                            Image(systemName: "exclamationmark.circle")
                            Text(error).font(.system(size: 12)).textSelection(.enabled)
                            Spacer()
                            Button { model.error = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("关闭错误提示")
                        }.foregroundStyle(Color.red).padding(14).background(Color.red.opacity(0.05)).padding(.horizontal, 28).padding(.bottom, 16)
                    }
                    if let warning = model.warning {
                        HStack(alignment: .top) {
                            Image(systemName: "exclamationmark.triangle")
                            Text(warning).font(.system(size: 12)).textSelection(.enabled)
                            Spacer()
                            Button { model.warning = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).accessibilityLabel("关闭警告")
                        }.foregroundStyle(Color.orange).padding(14).background(Color.orange.opacity(0.06)).padding(.horizontal, 28).padding(.bottom, 16)
                    }
                    if model.status?.state == "rollback-suspected", model.page != .backup, model.page != .settings {
                        locked
                    } else if model.desktopLocked, model.status != nil, model.page != .settings, model.page != .backup {
                        locked
                    } else if let route = model.onboardingRoute {
                        OnboardingView(route: route).id(route.rawValue)
                    } else if model.page == .settings || model.page == .backup {
                        pageContent
                    } else if model.status == nil {
                        welcome
                    } else if !model.unlocked && model.page != .audit && model.page != .activity && model.page != .policy {
                        locked
                    } else {
                        pageContent
                    }
                }.frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                if model.onboardingRoute == nil, model.page == .credentials, model.unlocked, let credential = model.selected, filtered.contains(where: { $0.id == credential.id }) {
                    Divider()
                    credentialDetail(credential).frame(width: 306)
                }
            }
        }
        .background(canvas).foregroundStyle(ink).tint(green)
        .task {
            notificationRouter.model = model
            if RequestAlert.available { UNUserNotificationCenter.current().delegate = notificationRouter }
            model.startSecurityMonitoring(); model.startRequestPolling(); await model.connectOnOpen()
        }
        .onOpenURL { url in
            if url == NotificationRouter.inboxURL { model.page = .approvals } else { model.openOnboarding(url) }
            NSApp.activate(ignoringOtherApps: true)
        }
        .onDisappear { model.lockDesktop(reason: "窗口已关闭，请重新验证身份。") }
        .onReceive(Timer.publish(every: 15, on: .main, in: .common).autoconnect()) { _ in
            // Background request alerts and the Dock badge come from AppModel.startRequestPolling.
            if phase == .active && !model.busy && model.operation == nil && model.result == nil && !model.showAddCredential && !model.showSession && !showActionForm && !model.showTemplate && !model.showPolicyDraft && model.onboardingRoute == nil {
                Task { await model.refresh(passive: true) }
            }
        }
        .onChange(of: model.desktopLocked) { _, locked in if locked { showActionForm = false; activityDetail = nil } }
        .onChange(of: search) { _, _ in model.selectedCredential = filtered.first?.id }
        .onChange(of: type) { _, _ in model.selectedCredential = filtered.first?.id }
        .onChange(of: model.page) { _, _ in model.onboardingRoute = nil; model.clearNativeFlow(); Task { await model.refresh() } }
        .onChange(of: phase) { _, value in if value == .active { model.checkDesktopIdle(); Task { await model.refresh() } } else { model.nativeFlowBecameInactive() } }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didResignActiveNotification)) { _ in model.nativeFlowBecameInactive() }
        .sheet(isPresented: $model.showPolicyDraft) { PolicyDraftForm().environmentObject(model) }
        .sheet(item: $model.operation) { OperationForm(operation: $0).environmentObject(model) }
        .sheet(isPresented: $model.showAddCredential) { AddCredentialForm().environmentObject(model) }
        .sheet(isPresented: $showActionForm) { ActionForm().environmentObject(model) }
        .sheet(isPresented: $model.showTemplate) { TemplateForm().environmentObject(model) }
        .sheet(isPresented: $model.showSession) { SessionForm().environmentObject(model) }
        .sheet(isPresented: $showConnectGuide) { ConnectAgentGuide().environmentObject(model) }
        .sheet(item: $model.result, onDismiss: { model.result = nil }) { ResultView(result: $0).environmentObject(model) }
        .sheet(item: $model.approvalDetails) { ApprovalDetailView(details: $0).environmentObject(model) }
        .sheet(item: $model.localApprovalDetails) { _ in LocalApprovalView().environmentObject(model) }
        .sheet(item:$activityDetail){ActivityRecentView(row:$0).environmentObject(model)}
        .alert(model.startupFailure?.title ?? "", isPresented: startupAlert, presenting: model.startupFailure) { failure in
            // Guidance only: the App never edits service.json, reads the vault or rebuilds it.
            switch failure.kind {
            case .portInUse: Button("在 Finder 中显示 service.json") { failure.revealServiceFile() }
            case .unsupportedFormat: Button("选择新的空目录") { if let url = chooseFile(directory: true) { model.changeDirectory(url.path) } }
            case .other: EmptyView()
            }
            if failure.kind != .unsupportedFormat { Button("重试") { Task { await model.connectOnOpen() } } }
            Button("关闭", role: .cancel) {}
        } message: { failure in Text(failure.detail) }
    }
    private var startupAlert: Binding<Bool> {
        Binding(get: { model.startupFailure != nil }, set: { if !$0 { model.startupFailure = nil } })
    }

    private var sidebar: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 10) { Image(systemName: "key.horizontal").font(.system(size: 30, weight: .medium)); Text("rekey").font(.system(size: 31, weight: .bold, design: .rounded)) }.foregroundStyle(green)
            Text("本机凭证管理").font(.system(size: 12)).foregroundStyle(.secondary).padding(.leading, 43).padding(.top, 3)
            Button { if let url = chooseFile(directory: true) { model.changeDirectory(url.path) } } label: {
                HStack { Image(systemName: "person.crop.square"); Text("个人工作区"); Spacer(); Image(systemName: "chevron.down").font(.system(size: 10)) }.padding(12)
            }.buttonStyle(.plain).background(surface.opacity(0.65), in: RoundedRectangle(cornerRadius: 7)).overlay(RoundedRectangle(cornerRadius: 7).stroke(.gray.opacity(0.2))).padding(.vertical, 28).help(model.stateDirectory).disabled(model.busy)
            ForEach(Page.allCases.filter { $0 != .settings && ($0 != .actions || model.status?.lab_enabled == true) }) { page in nav(page) }
            Spacer()
            nav(.settings)
            Divider().padding(.vertical, 15)
            HStack(spacing: 6) {
                Circle().fill(model.status == nil ? Color.gray : green).frame(width: 7, height: 7)
                Text(model.status.map { $0.unlocked ? (model.desktopLocked ? "保险库已解锁 · 界面已锁" : "保险库已解锁") : $0.label } ?? "未连接").font(.system(size: 11))
                Spacer()
                if model.busy { ProgressView().controlSize(.small) }
                Button(model.desktopReady ? "锁定界面" : "解锁界面") {
                    if model.desktopReady { model.lockDesktop() } else { unlock() }
                }.font(.system(size: 11, weight: .medium)).disabled(model.busy || model.status == nil || model.pendingDesktopLocks > 0)
                .help("只锁定这个管理界面；已签署的 Agent 调用继续工作。要停用 Agent，在设置里锁定整个保险库。")
            }
            if let status = model.status {
                Text(status.protectionLabel).font(.system(size: 11)).foregroundStyle(.secondary).padding(.top, 7)
                    .help(status.protectionDetail)
                Text(status.identityLabel).font(.system(size: 11)).foregroundStyle(.secondary)
            }
        }.padding(.horizontal, 20).padding(.top, 24).padding(.bottom, 20).frame(width: 210).background(sage.opacity(0.45))
    }
    private func nav(_ page: Page) -> some View {
        Button { model.page = page } label: {
            HStack(spacing: 12) {
                Image(systemName: page.icon).font(.system(size: 17)).frame(width: 22)
                Text(page.rawValue).font(.system(size: 14, weight: model.page == page ? .semibold : .regular)).lineLimit(1).fixedSize()
                Spacer(minLength: 4)
                if page == .approvals, !model.desktopLocked, model.inboxCount > 0 {
                    Text(String(model.inboxCount)).font(.system(size: 11, weight: .semibold)).foregroundStyle(.white)
                        .padding(.horizontal, 7).padding(.vertical, 2).background(Color.orange, in: Capsule()).fixedSize()
                        .accessibilityLabel("\(model.inboxCount) 项待处理")
                }
            }.padding(.horizontal, 12).frame(height: 44).contentShape(Rectangle())
        }.buttonStyle(.plain).background(model.page == page ? sage : Color.clear, in: RoundedRectangle(cornerRadius: 7)).foregroundStyle(model.page == page ? green : ink).padding(.bottom, 5)
            .accessibilityAddTraits(model.page == page ? .isSelected : [])
    }
    private var header: some View {
        VStack(alignment: .leading, spacing: 18) {
            HStack {
                Text("个人工作区  /  \(model.page.rawValue)").font(.system(size: 12)).foregroundStyle(.secondary)
                if !model.desktopLocked && model.inboxCount > 0 && model.page != .approvals {
                    Button("\(model.inboxCount) 项待你处理") { model.page = .approvals }.font(.caption)
                }
                Spacer()
                Button { Task { await model.refresh() } } label: { Image(systemName: "arrow.clockwise") }.buttonStyle(.plain).help("刷新").accessibilityLabel("刷新").keyboardShortcut("r").disabled(model.busy)
            }
            HStack(alignment: .center) {
                VStack(alignment: .leading, spacing: 7) {
                    Text(model.page.rawValue).font(.system(size: 28, weight: .semibold))
                    Text(subtitle).font(.system(size: 13)).foregroundStyle(.secondary)
                }
                Spacer()
                if model.page == .credentials {
                    if !lab { Button { showConnectGuide = true } label: { Label("接入 Agent", systemImage: "terminal") }.buttonStyle(SecondaryButton()) }
                    if model.policy?.mode == .personal && model.policy?.trust_installed == false {
                        Button { model.beginPersonalPolicySetup() } label: { Label("先设置本机签名", systemImage: "signature") }.buttonStyle(PrimaryButton()).disabled(!model.unlocked || model.busy)
                            .help("添加 Key 前需要一次性创建本机签名密钥，用来签署规则")
                    } else {
                        Button { if model.desktopReady { model.showAddCredential = true } else { model.requestDesktopLogin() } } label: { Label("添加 API Key", systemImage: "plus") }.buttonStyle(PrimaryButton()).disabled(!model.unlocked || model.busy)
                    }
                } else if model.page == .actions {
                    Button("固定操作") { showActionForm = true }.disabled(!model.unlocked || model.busy)
                    Button { model.showTemplate = true } label: { Label("从模板安装", systemImage: "plus") }.buttonStyle(PrimaryButton()).disabled(!model.unlocked || model.busy)
                }
            }
        }.padding(28)
    }
    private var subtitle: String {
        switch model.page {
        case .credentials: return "保存在 Rekey 的 API Key；Agent 只能通过已签署的连接使用，读不到 Key 本身"
        case .actions: return "明确每个 Agent 可以执行的请求"
        case .policy: return lab ? "让权限范围、使用次数和有效期都清晰可见" : "每个连接允许 Agent 做什么：读取直接放行，写入需要你批准"
        case .approvals: return lab ? "查看审批绑定信息，再通过独立工具核对原始请求并签名" : "Agent 的写操作和访问申请在这里等你决定"
        case .activity: return "今天（UTC）各 Agent 通过 Rekey 发出的调用"
        case .audit: return "Rekey 记录的每一次解锁、调用、审批和改动"
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
        case .activity: activityPage
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
                if model.needsSetup {
                    Button("设置密码并开始") { model.beginSetup() }.buttonStyle(PrimaryButton())
                } else if model.busy {
                    ProgressView("正在连接保险库…")
                } else if model.backgroundServiceNeedsApproval {
                    Button("允许后台运行") { BackgroundService.openSettings() }.buttonStyle(PrimaryButton())
                } else {
                    Button("重新连接") { Task { await model.connectOnOpen() } }.buttonStyle(PrimaryButton())
                }

            }.disabled(model.busy)
            if model.needsSetup {
                VStack(alignment: .leading, spacing: 10) {
                    Text("三步开始").font(.system(size: 13, weight: .semibold))
                    Label("设置保险库密码，保存好只显示一次的恢复密钥；再设置一次本机规则签名", systemImage: "1.circle")
                    Label("添加 API Key，审阅并签署它的规则（读取放行、写入需批准）", systemImage: "2.circle")
                    Label("在项目里运行 rekey connect codex 或 claude-code 接入 Agent，让它试一次读取", systemImage: "3.circle")
                }.font(.system(size: 13)).foregroundStyle(.secondary).padding(.top, 8)
            }
            if let error = model.connectionError {
                DisclosureGroup("技术详情") { Text(error).font(.system(size: 11)).foregroundStyle(.secondary).textSelection(.enabled) }.font(.system(size: 12))
            }
            Spacer()
        }.padding(42).frame(maxWidth: 620, maxHeight: .infinity, alignment: .topLeading)
    }
    private var locked: some View {
        VStack(spacing: 18) {
            Image(systemName: "lock").font(.system(size: 42, weight: .light)).foregroundStyle(green)
            if model.status?.state == "rollback-suspected" {
                Text("检测到疑似回滚").font(.system(size: 23, weight: .medium))
                if let context = model.status?.rollback {
                    Text(context.summary).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    Text("自动解锁与操作已停止。请审阅快照与历史上限，单独用密码或恢复密钥确认；确认后仍保持锁定。")
                    Button("审阅并确认此快照") { model.requestRollbackConfirmation() }.buttonStyle(PrimaryButton()).disabled(model.busy)
                } else { Text("缺少回滚上下文，不能确认。请刷新状态。") }
            } else {
            Text(model.status?.unlocked == true ? "管理界面已锁定" : model.status?.state == "locked" ? "保险库已锁定" : "服务暂不可用").font(.system(size: 23, weight: .medium))
            Text(model.desktopLockReason).foregroundStyle(.secondary)
            Button("输入保险库密码") { unlock() }.buttonStyle(PrimaryButton()).disabled(model.busy || model.pendingDesktopLocks > 0 || !(model.status?.unlocked == true || model.status?.state == "locked"))
            Button("用系统认证解锁") {
                let revision = model.nativeFlowRevision
                Task { await model.unlockWithPresence(revision: revision) }
            }.disabled(model.busy || model.pendingDesktopLocks > 0 || model.securitySettings.passwordInterval == .everyUnlock || !(model.status?.unlocked == true || model.status?.state == "locked"))
            if model.pendingDesktopLocks > 0 { Button("重试服务端锁定") { model.retryDesktopLock() }.disabled(model.busy) }
            if model.status?.unlocked == true { Button("锁定整个保险库并撤销 Agent 授权") { Task { await model.lock() } }.disabled(model.busy) }
            }
        }.frame(maxWidth: .infinity, maxHeight: .infinity)
    }
    private func unlock() { model.operation = Operation(title: "解锁保险库", detail: "输入密码或选择恢复密钥。", arguments: ["unlock"]) }

    private var filtered: [Credential] {
        model.credentials.filter { (search.isEmpty || $0.label.localizedCaseInsensitiveContains(search)) && (type == "全部类型" || $0.typeName == type) }
    }
    private var credentialsPage: some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 16) {
                HStack { Image(systemName: "magnifyingglass").foregroundStyle(.secondary); TextField("搜索凭证名称", text: $search).textFieldStyle(.plain) }.padding(11).background(surface.opacity(0.55), in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.22)))
                Picker("类型", selection: $type) { Text("全部类型").tag("全部类型"); ForEach(Array(Set(model.credentials.map(\.typeName))).sorted(), id: \.self) { Text($0).tag($0) } }.labelsHidden().frame(width: 140)
            }.padding(.bottom, 22)
            HStack { Text("名称").frame(maxWidth: .infinity, alignment: .leading); Text("类型").frame(width: 120, alignment: .leading); Text("版本").frame(width: 50); Text("状态").frame(width: 92) }.font(.system(size: 12, weight: .medium)).foregroundStyle(.secondary).padding(16).background(Color.gray.opacity(0.035))
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
                                    keyStatus(credential).frame(width: 92)
                                }.padding(.horizontal, 16).frame(minHeight: 76).background(model.selectedCredential == credential.id ? sage.opacity(0.8) : Color.clear).contentShape(Rectangle())
                            }.buttonStyle(.plain)
                            Divider()
                        }
                    }
                }
            }
            Spacer(minLength: 18)
            Label("密钥已保存在 Rekey，可通过连接调用", systemImage: "lock").font(.system(size: 12)).foregroundStyle(.secondary).padding(.vertical, 18)
            Divider()
            HStack(spacing: 16) {
                step(1, "添加 API Key", model.credentials.isEmpty ? "选择服务并粘贴 Key" : "已添加 \(model.credentials.count) 个", done: !model.credentials.isEmpty) {
                    if model.desktopReady { model.showAddCredential = true } else { model.requestDesktopLogin() }
                }
                if lab {
                    step(2, "配置固定操作", "注册允许执行的请求") { model.page = .actions }
                } else {
                    let active = model.connections.filter(\.enabled).count
                    step(2, "审阅连接规则", active == 0 ? "签署后 Agent 才能调用" : "\(active) 个连接已生效", done: active > 0) { model.page = .policy }
                }
                step(3, "接入 Agent", "在项目里运行 rekey connect") { showConnectGuide = true }
            }.padding(.vertical, 24)
        }.padding(.horizontal, 28)
    }
    private func step(_ number: Int, _ title: String, _ detail: String, done: Bool = false, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: 9) {
                Group { if done { Image(systemName: "checkmark").foregroundStyle(green) } else { Text(String(number)) } }
                    .font(.system(size: 13, weight: .medium)).frame(width: 26, height: 26).overlay(Circle().stroke(done ? green : .gray.opacity(0.5)))
                VStack(alignment: .leading, spacing: 5) { Text(title).font(.system(size: 13, weight: .medium)); Text(detail).font(.system(size: 12)).foregroundStyle(.secondary) }
            }.frame(maxWidth: .infinity, alignment: .leading)
        }.buttonStyle(.plain).disabled(model.busy)
    }
    /// Saved is not the same as usable: a key works for Agents only through a signed Connection.
    private func keyStatus(_ item: Credential) -> some View {
        let mine = model.connections.filter { $0.credential_id == item.id }
        let text = !item.active ? "已撤销" : lab ? "可用" : model.connectionsUnavailable ? "连接状态未知" : mine.contains(where: \.enabled) ? "可调用" : mine.isEmpty ? "待签署连接" : "连接已停用"
        return StatusPill(active: text == "可用" || text == "可调用", text: text, warning: item.active)
    }
    private func credentialDetail(_ item: Credential) -> some View {
        VStack(alignment: .leading, spacing: 20) {
            HStack { Text("凭证详情").font(.system(size: 15, weight: .semibold)); Spacer(); Button { model.selectedCredential = nil } label: { Image(systemName: "xmark") }.buttonStyle(.plain).foregroundStyle(.secondary).accessibilityLabel("关闭详情").keyboardShortcut(.cancelAction) }
            HStack { Image(systemName: item.icon).font(.system(size: 24)); Text(item.label).font(.system(size: 22, weight: .semibold)).lineLimit(3) }.padding(.top, 10)
            keyStatus(item)
            info("类型", item.typeName)
            info("当前版本", "v\(item.current_version)")
            Text("密钥已保存在 Rekey，可通过连接调用").font(.system(size: 12)).foregroundStyle(.secondary)
            Divider().padding(.vertical, 4)
            Text(lab ? "关联操作" : "使用此 Key 的连接").font(.system(size: 14, weight: .semibold))
            ScrollView {
                VStack(alignment: .leading, spacing: 10) {
                    if !lab {
                        let linked = model.connections.filter { $0.credential_id == item.id }
                        if model.connectionsUnavailable {
                            Text("无法读取连接列表，请刷新。").font(.system(size: 12)).foregroundStyle(.red)
                        } else if linked.isEmpty {
                            Text("还没有生效的连接，Agent 暂时不能用这个 Key。").font(.system(size: 12)).foregroundStyle(.secondary)
                            Button("为此 Key 添加连接") { model.addCredentialID = item.id; if model.desktopReady { model.showAddCredential = true } else { model.requestDesktopLogin() } }.buttonStyle(PrimaryButton())
                        }
                        ForEach(linked) { connection in
                            ConnectionRulesSummary(connection: connection, compact: true).padding(12)
                                .background(surface.opacity(0.4), in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.18)))
                        }
                    }
                    let linked = lab ? model.actions.filter { $0.credential_id == item.id } : []
                    if lab && linked.isEmpty { Text("尚未配置关联操作").font(.system(size: 12)).foregroundStyle(.secondary) }
                    ForEach(linked) { action in
                        VStack(alignment: .leading, spacing: 8) { Text(action.name).font(.system(size: 13, weight: .medium)); Text("\(action.method) \(action.target.summary)").font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).textSelection(.enabled) }.frame(maxWidth: .infinity, alignment: .leading).padding(14).background(surface.opacity(0.4), in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.18)))
                    }
                }
            }
            Label("Agent 通过已授权操作使用凭证，无法读取凭证内容。", systemImage: "info.circle").font(.system(size: 11)).foregroundStyle(.secondary).padding(13).background(sage.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
            Spacer(minLength: 12)
            HStack {
                Button(item.kind == "opaque-token" ? "更换 Key" : "轮换凭证") { rotate(item) }.buttonStyle(SecondaryButton())
                Spacer()
                Button("撤销", role: .destructive) { model.operation = Operation(title: "撤销 Key", detail: "撤销“\(item.label)”后，使用它的连接将无法再调用上游服务。", arguments: ["credential", "revoke", item.id]) }.buttonStyle(.plain).foregroundStyle(.red)
            }.disabled(!item.active || model.busy)
            Text("敏感操作需再次验证身份").font(.system(size: 11)).foregroundStyle(.secondary)
        }.padding(23).frame(maxHeight: .infinity, alignment: .topLeading)
    }
    private func rotate(_ item: Credential) {
        if item.kind == "opaque-token" {
            model.operation = Operation(title: "更换 Key", detail: "用新的 Key 替换“\(item.label)”。使用它的连接和规则不变，下一次调用起生效。", arguments: ["credential", "rotate", item.id], newSecret: true)
        } else if let file = chooseFile() {
            let commands = ["github-app-installation": "rotate-github-app", "vault-kv-v2-source": "rotate-vault-kv", "vault-dynamic-source": "rotate-vault-dynamic", "keycloak-token-exchange": "rotate-keycloak"]
            guard let command = commands[item.kind] else { model.error = "当前客户端不支持此凭证类型。"; return }
            model.operation = Operation(title: "轮换凭证", detail: "用所选私有配置文件替换“\(item.label)”的配置。", arguments: ["credential", command, item.id, "--file", file.path])
        }
    }
    private var actionsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack { Text("操作固定了目标和方法，路径参数受已声明的规则限制。").font(.system(size: 12)).foregroundStyle(.secondary); Spacer(); Button("导入定义") { importAction() }.disabled(!model.unlocked || model.busy) }
                if model.actions.isEmpty { EmptyState(icon: "play.rectangle", title: "还没有固定操作", detail: "创建一个操作，选择凭证并设置请求目标。") }
                ForEach(model.actions) { action in
                    VStack(alignment: .leading, spacing: 12) {
                        HStack { Text(action.name).font(.system(size: 17, weight: .medium)); Text("v\(action.version)").foregroundStyle(.secondary); Spacer(); StatusPill(active: action.enabled, text: action.enabled ? "已启用" : "已禁用") }
                        Text("\(action.method) \(action.origin)\(action.target.summary)").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        HStack { Text(model.credentials.first { $0.id == action.credential_id }?.label ?? action.credential_id).font(.system(size: 12)).foregroundStyle(.secondary); Spacer(); Button("更新定义") { importAction(action.id) }; Button("禁用", role: .destructive) { model.operation = Operation(title: "禁用操作", detail: "禁止后续执行“\(action.name)”。", arguments: ["action", "disable", action.id]) }.disabled(!action.enabled) }.disabled(model.busy)
                    }.padding(20).background(surface.opacity(0.55), in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(.gray.opacity(0.16)))
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
                if model.policy?.mode == .personal {
                    SectionCard(title: "连接与规则", icon: "point.3.connected.trianglepath.dotted") {
                        if model.connectionsUnavailable {
                            HStack { Text("无法读取连接列表。").foregroundStyle(.red); Button("重试") { Task { await model.refresh() } } }.font(.system(size: 13))
                        } else if model.connections.isEmpty {
                            Text("还没有生效的连接。先在“凭证”页添加 API Key，再在这里审阅并签署它的规则。").font(.system(size: 13)).foregroundStyle(.secondary)
                        }
                        ForEach(model.connections) { connection in
                            ConnectionRulesSummary(connection: connection)
                            if connection.id != model.connections.last?.id { Divider() }
                        }
                        HStack {
                            Button("编辑并签署规则") { model.showPolicyDraft = true }.buttonStyle(PrimaryButton())
                                .disabled(model.busy || !model.unlocked || model.policy?.trust_installed != true)
                            Text("改动会先完整展示，签署后才生效；规则只能比预设更严格。").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                    }
                } else if model.policy?.mode == .team {
                    SectionCard(title: "团队连接与外部签名", icon: "doc.text") {
                        Text("选择外部编写的原始草稿，完整审阅并导出；随后使用独立签名工具，再导入签名策略。")
                        Button("查看连接与外部草稿") { model.showPolicyDraft = true }.disabled(model.busy)
                    }
                }
                SectionCard(title: lab ? "当前策略" : "签署状态", icon: "checkmark.shield") {
                    if let policy = model.policy {
                        info("签名模式", policy.mode == .personal ? "个人" : policy.mode == .team ? "团队" : "解锁后验证")
                        info("状态", policy.status == "active" ? "已生效" : policy.status == "expired" ? "已过期" : policy.bundle_persisted ? "已保存，解锁后加载" : "尚未激活")
                        info(lab ? "信任根" : "签名密钥", policy.trust_installed ? "已安装" : "未安装")
                        if let version = policy.version { info("规则版本", "v\(version)") }
                        if let expires = policy.expires_at_ms { info("有效期至", displayDate(expires) + "（到期后需重新签署）") }
                    }
                    HStack {
                        if model.policy?.mode == .personal {
                            if model.policy?.trust_installed == false { Button("创建本机签名密钥") { model.beginPersonalPolicySetup() }.buttonStyle(PrimaryButton()) }
                        } else if model.policy?.mode == .team {
                            Button("安装信任根") { importPolicy(trust: true) }
                            Button("激活签名策略") { importPolicy(trust: false) }
                        }
                    }.disabled(!model.unlocked || model.busy)
                    Text(model.policy?.mode == .personal ? "签名方式会在审阅页显示。系统认证授权有效时，无需重复输入保险库密码；每次激活仍需明确确认。" : "导入由外部签名工具生成的文件。创建授权本身不会绕过默认拒绝策略。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }
                if model.status?.lab_enabled == true { SectionCard(title: "工作负载授权", icon: "person.badge.key") {
                    Text("按固定操作授予短期权限，限制有效期与使用次数。授权令牌只在创建完成时显示。").font(.system(size: 13)).foregroundStyle(.secondary)
                    HStack {
                        Button("创建授权") { model.showSession = true }.buttonStyle(PrimaryButton())
                        Button("撤销授权") { model.operation = Operation(title: "撤销授权", detail: "输入需要撤销的会话 ID。", arguments: ["session", "revoke"]) }.buttonStyle(SecondaryButton())
                    }.disabled(!model.unlocked || model.busy)
                    Text("服务锁定或重启会撤销会话。MCP 与 shell 接入使用同一套固定操作权限。").font(.system(size: 12)).foregroundStyle(.secondary)
                } }
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
    private func importPolicy(trust: Bool) {
        guard let file = chooseFile() else { return }
        var arguments = ["policy", "trust", "install", "--file", file.path]
        if !trust {
            guard let target = model.policy, let root = target.trust_sha256 else {
                model.error = "请先解锁保险库并安装信任根，再刷新策略状态。"
                return
            }
            arguments = ["policy", "activate", "--file", file.path,
                         "--expected-vault-id", target.vault_id, "--expected-trust-sha256", root]
        }
        model.operation = Operation(title: trust ? "安装信任根" : "激活策略", detail: "使用 \(file.lastPathComponent)。信任根每个保险库只能安装一次。", arguments: arguments, proofFlag: "--step-up-stdin")
    }
    private var approvalsPage: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 15) {
                ForEach(model.approvals.filter { if case .localPresence = $0.approver { return !lab }; return false }) { item in
                    ApprovalSummaryCard(item: item)
                }
                AccessRequestsPanel()
                HStack {
                    Button(model.approvalNotificationsEnabled ? "关闭请求提醒" : "启用请求提醒") {
                        Task { await model.setApprovalNotifications(!model.approvalNotificationsEnabled) }
                    }.disabled(model.approvalNotificationBusy)
                    Text("后台每 15 秒检查一次；提醒不含请求内容，也不会自动批准。").font(.system(size: 12)).foregroundStyle(.secondary)
                }
                if let message = model.approvalNotificationMessage { Text(message).font(.system(size: 12)).foregroundStyle(.secondary) }
                if model.approvals.isEmpty { EmptyState(icon: "tray", title: "没有待审批请求", detail: "Agent 提交的有效审批请求会出现在这里。") }
                ForEach(model.approvals.filter { item in if case .localPresence = item.approver { return lab }; return true }) { item in
                    SectionCard(title: model.actions.first { $0.id == item.action_id }?.name ?? "固定操作", icon: "doc.text.magnifyingglass") {
                        info("会话", item.session_id)
                        info("审批方式", item.approver.summary)
                        info("有效期至", displayDate(item.max_expires_at_ms))
                        Text("参数摘要 \(item.parameter_sha256)").font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                        HStack {
                            Button("查看审批详情") { Task { await model.reviewApproval(item) } }
                            if case .ed25519 = item.approver { Button("导出签名信封") { Task { await model.exportApproval(item) } } }
                        }.disabled(model.busy)
                    }
                }
                if lab { Text("本机审批需在完整审阅后进行系统认证；外部签名请求继续使用独立审批工具。").font(.system(size: 12)).foregroundStyle(.secondary) }
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
    private var activityPage: some View {
        ScrollView([.horizontal, .vertical]) {
            VStack(alignment: .leading, spacing: 18) {
                if let message = model.activityError {
                    Label(message, systemImage: "exclamationmark.circle").foregroundStyle(.red)
                }
                if let activity = model.activity {
                    HStack { Text("UTC 当日 · 更新于 \(displayDate(activity.untilMs))").font(.system(size: 12)).foregroundStyle(.secondary); Button("刷新活动") { Task { model.clearActivity(); await model.refresh() } }.disabled(model.busy) }
                    if activity.complete {
                        if !activity.reauthorization.connections.isEmpty { reauthorization(activity.reauthorization.connections) }
                        HStack(spacing: 28) {
                            activityMetric("已开始执行", activity.totals.admitted)
                            activityMetric("被拒绝", activity.totals.denied)
                            activityMetric("请求批准", activity.totals.approvals)
                            if activity.totals.measuredTokens + activity.totals.estimatedTokens > 0 {
                                activityMetric("输出 token", activity.totals.measuredTokens)
                                activityMetric("预估 token（未测得）", activity.totals.estimatedTokens)
                            }
                        }
                        RecentCalls(rows: activity.rows)
                        Divider()
                        if activity.rows.isEmpty { Text("今天还没有调用。让 Agent 做一次读取，然后点“刷新活动”。").foregroundStyle(.secondary) }
                        let tokens = activity.totals.measuredTokens + activity.totals.estimatedTokens > 0
                        Grid(alignment: .leading, horizontalSpacing: 24, verticalSpacing: 15) {
                            GridRow {
                                Text("Agent"); Text("连接 / 读写")
                                Text("开始执行"); Text("被拒绝"); Text("请求批准")
                                if tokens { Text("输出 token"); Text("预估 token") }
                            }.font(.system(size: 12, weight: .semibold))
                            ForEach(activity.rows) { row in
                                GridRow {
                                    VStack(alignment: .leading, spacing: 4) {
                                        Text(row.context?.caller ?? row.context?.profile_name ?? "未记录调用方")
                                        if let hash = row.context?.policy_sha256 {
                                            Text(String(hash.prefix(12))).font(.system(size: 10, design: .monospaced)).foregroundStyle(.secondary).help(hash)
                                        }
                                    }
                                    VStack(alignment: .leading, spacing: 4) {
                                        Button {activityDetail=row} label:{Text(row.context.map { "\($0.connection ?? $0.instance_slug ?? "—") / \($0.classification) · 查看最近调用" } ?? "上下文未记录")}.buttonStyle(.link).disabled(row.recent.isEmpty).help("查看最近 50 条调用")
                                        Text(row.context?.model ?? "—").foregroundStyle(.secondary)
                                    }
                                    Text(String(row.counts.admitted)); Text(String(row.counts.denied)); Text(String(row.counts.approvals))
                                    if tokens { Text(String(row.counts.measuredTokens)); Text(String(row.counts.estimatedTokens)) }
                                }.font(.system(size: 12))
                            }
                        }
                        Text("统计只含 Rekey 仍保留的记录（读取 \(activity.pages) 页）。点连接名查看最近的调用；“开始执行”不代表上游一定成功，结果以明细为准。")
                            .font(.system(size: 11)).foregroundStyle(.secondary).frame(maxWidth: 820, alignment: .leading)
                    } else {
                        HStack {
                            if model.busy { ProgressView().controlSize(.small) }
                            Text("已读取 \(activity.pages) 页；尚未完成，暂不显示汇总。")
                        }
                    }
                } else if model.activityError == nil {
                    Text("刷新以读取今日活动。").foregroundStyle(.secondary)
                }
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
    private func activityMetric(_ label: String, _ value: UInt64) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(label).font(.system(size: 11)).foregroundStyle(.secondary)
            Text(String(value)).font(.system(size: 22, weight: .semibold, design: .rounded))
        }
    }
    // Provider refusals only (agent-call §7.4). The browser authorization still asks for fresh presence.
    private func reauthorization(_ connections: [String]) -> some View {
        SectionCard(title: "需重新授权", icon: "exclamationmark.triangle") {
            Text("提供方已撤销授权或拒绝刷新。这些连接的调用会返回 NEEDS_REAUTH，直到在浏览器中重新授权；网络或服务端错误不会显示在这里。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            ForEach(connections, id: \.self) { name in
                HStack {
                    Text(name).font(.system(size: 13, weight: .medium))
                    Spacer()
                    Button("在浏览器重新授权") { model.onboardingRoute = .oauth(name) }.disabled(model.busy || !model.desktopReady)
                }
            }
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
                            HStack {
                                Text(auditLabels[event.event_type] ?? event.event_type).font(.system(size: 13, weight: .medium))
                                Spacer()
                                Text(auditOutcomeLabels[event.outcome] ?? event.outcome).font(.system(size: 11)).foregroundStyle(event.outcome == "success" ? green : event.outcome == "denied" || event.outcome == "failure" ? .red : .secondary)
                            }
                            HStack { Text(displayDate(event.created_at_ms)); Text(event.event_type).font(.system(size: 11, design: .monospaced)); Spacer(); Text(event.reason_code).lineLimit(2) }.font(.system(size: 11)).foregroundStyle(.secondary)
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
                    Text("选择备份，再选择一个新的空目录。先只读验证源代数与历史上限，再明确确认所示输入与目标。恢复需要源备份的密码或恢复密钥；失败可能保留未完成状态，不自动清理或重试。").font(.system(size: 13)).foregroundStyle(.secondary)
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
                    Button("切换数据目录") { if let url = chooseFile(directory: true) { model.changeDirectory(url.path) } }.disabled(model.busy || model.oidcBusy)
                    if let status = model.status { info("服务版本", status.runtime_version); info("数据格式", "v\(status.format_version)") }
                    HStack { Button(model.serviceStartTitle) { model.startService() }.disabled(model.status != nil); Button("停止服务") { model.requestShutdown() }.disabled(model.status == nil) }.disabled(model.busy)
                    Text("关闭窗口不会停止服务；服务会继续按空闲锁定规则运行。").font(.system(size: 12)).foregroundStyle(.secondary)
                    if let registration = model.backgroundServiceDescription {
                        Text(registration).font(.system(size: 12)).foregroundStyle(.secondary)
                        if model.backgroundServiceNeedsApproval {
                            Button("打开系统登录项设置") { BackgroundService.openSettings() }
                        }
                        Button("停止并停用登录启动") { model.requestDisableBackgroundService() }.disabled(model.status == nil || model.busy)
                    }
                }
                DesktopSecurityForm().environmentObject(model)
                SectionCard(title: "检查更新", icon: "arrow.down.circle") { UpdateSection() }
                SectionCard(title: "解锁与恢复", icon: "lock.rotation") {
                    Button("修改密码") { model.operation = Operation(title: "修改密码", detail: "旧密码将不再解锁当前保险库。历史备份不受这次修改影响。", arguments: ["password", "change"], newSecret: true, confirmSecret: true) }
                    Button("轮换恢复密钥") { model.operation = Operation(title: "轮换恢复密钥", detail: "仅使用当前密码验证。新恢复密钥只显示一次，请安全保存。", arguments: ["recovery", "rotate"], sensitiveResult: true, recoveryAllowed: false) }
                }.disabled(!model.desktopReady || model.busy)
                if model.status?.lab_enabled == true {
                  SectionCard(title: "机构登录", icon: "person.badge.key") {
                    Text("先解锁本机，再完成机构登录。登录不会替代管理操作的本机密码确认。").font(.system(size: 13)).foregroundStyle(.secondary)
                    if let profile = model.oidcProfileFile { info("服务配置", profile) }
                    HStack {
                        Button("选择机构配置") { if let file = chooseFile() { model.oidcProfileFile = file.path } }.disabled(model.serviceIsRunning || model.busy || model.oidcBusy)
                        Button("选择已有会话文件") { if let file = chooseFile() { model.oidcSessionFile = file.path } }.disabled((model.busy || model.oidcBusy))
                    }
                    if let session = model.oidcSessionFile { info("会话文件", session) }
                    if let identity = model.oidcIdentity {
                        info("管理主体", identity.principal_id)
                        info("会话到期", Date(timeIntervalSince1970: Double(identity.expires_at_ms) / 1000).formatted())
                    }
                    HStack {
                        Button("开始机构登录") { Task { await model.beginOIDCLogin() } }.disabled(!model.unlocked || (model.busy || model.oidcBusy) || model.oidcFlow != nil)
                        Button("退出机构会话") { Task { await model.logoutOIDC() } }.disabled((model.busy || model.oidcBusy) || model.oidcSessionFile == nil)
                    }
                    if let flow = model.oidcFlow {
                        Text("在浏览器完成登录后，选择新会话文件以接收结果。文件需存入已存在的受保护目录。").font(.system(size: 13)).foregroundStyle(.secondary)
                        HStack {
                            Button("在浏览器打开") { if let url = flow.browserURL { NSWorkspace.shared.open(url) } }.disabled((model.busy || model.oidcBusy))
                            Button("接收登录结果") {
                                let panel = NSSavePanel()
                                panel.nameFieldStringValue = "oidc-session-\(UUID().uuidString).token"
                                panel.directoryURL = URL(fileURLWithPath: model.stateDirectory).appendingPathComponent("runtime")
                                panel.canCreateDirectories = false
                                if panel.runModal() == .OK, let file = panel.url { Task { await model.finishOIDCLogin(to: file) } }
                            }.disabled((model.busy || model.oidcBusy))
                            Button("取消登录") { Task { await model.cancelOIDCLogin() } }
                        }
                    }
                }
                  }
                Text("Rekey 本地管理 · macOS 源码预览\n凭证、策略与审计由本机服务持有。").font(.system(size: 12)).foregroundStyle(.secondary)
            }.padding(.horizontal, 28).padding(.bottom, 28)
        }
    }
}

func info(_ label: String, _ value: String) -> some View {
    // Values sit next to their labels so wide cards still read row by row.
    HStack(alignment: .top, spacing: 12) { Text(label).foregroundStyle(.secondary).frame(width: 96, alignment: .leading); Text(value).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }.font(.system(size: 13))
}
struct StatusPill: View {
    let active: Bool
    let text: String
    var warning = false
    var body: some View {
        let color: Color = active ? green : warning ? .orange : .red
        Text(text).font(.system(size: 11, weight: .medium)).lineLimit(1).padding(.horizontal, 9).padding(.vertical, 4).foregroundStyle(color).background(active ? sage : color.opacity(0.1), in: Capsule())
    }
}
struct PrimaryButton: ButtonStyle {
    @Environment(\.isEnabled) private var enabled
    func makeBody(configuration: Configuration) -> some View { configuration.label.font(.system(size: 13, weight: .medium)).padding(.horizontal, 16).padding(.vertical, 10).foregroundStyle(.white).background(buttonFill.opacity(!enabled ? 0.4 : configuration.isPressed ? 0.8 : 1), in: RoundedRectangle(cornerRadius: 7)) }
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
    var body: some View { VStack(alignment: .leading, spacing: 17) { Label(title, systemImage: icon).font(.system(size: 17, weight: .medium)); content }.padding(22).frame(maxWidth: .infinity, alignment: .leading).background(surface.opacity(0.65), in: RoundedRectangle(cornerRadius: 9)).overlay(RoundedRectangle(cornerRadius: 9).stroke(.gray.opacity(0.17))) }
}
