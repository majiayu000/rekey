import Foundation
import SwiftUI
import AppKit
import Security
import Darwin
import LocalAuthentication
import CoreGraphics

struct UIError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct RememberedUnlock: Codable {
    let key: String
    let expiresAt: Date
    // QA bundles and standalone contract tests must never query the app's entries.
    static var keychainService: String {
        (Bundle.main.bundleIdentifier ?? "com.starlight.rekey.unbundled-tests") + ".remembered-unlock"
    }

    static func receipt(_ data: Data) throws -> RememberedUnlock {
        guard let text = String(data: data, encoding: .utf8) else { throw UIError(message: "恢复授权响应无效。") }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 2, let milliseconds = Double(lines[0]), milliseconds.isFinite,
              lines[1].count == 64, lines[1].allSatisfy(\.isHexDigit) else { throw UIError(message: "恢复授权响应无效。") }
        return RememberedUnlock(key: String(lines[1]), expiresAt: Date(timeIntervalSince1970: milliseconds / 1000))
    }
    private static func query(_ directory: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: keychainService,
         kSecAttrAccount as String: URL(fileURLWithPath: directory).standardizedFileURL.resolvingSymlinksInPath().path,
         kSecAttrSynchronizable as String: false]
    }
    static func forget(_ directory: String) throws {
        let code = SecItemDelete(query(directory) as CFDictionary)
        guard code == errSecSuccess || code == errSecItemNotFound else { throw UIError(message: "无法清除钥匙串中的解锁授权（\(code)）。") }
    }
    func save(_ directory: String) throws {
        try Self.forget(directory)
        var attributes = Self.query(directory)
        attributes[kSecAttrLabel as String] = (Bundle.main.object(forInfoDictionaryKey: "CFBundleName") as? String ?? "Rekey Test") + " · 本机解锁授权"
        attributes[kSecValueData as String] = try JSONEncoder().encode(self)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let code = SecItemAdd(attributes as CFDictionary, nil)
        guard code == errSecSuccess else { throw UIError(message: "已解锁，但无法保存恢复授权到钥匙串（\(code)）。") }
    }
    static func load(_ directory: String) throws -> RememberedUnlock? {
        var attributes = query(directory)
        attributes[kSecReturnData as String] = true
        attributes[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let code = SecItemCopyMatching(attributes as CFDictionary, &item)
        if code == errSecItemNotFound { return nil }
        guard code == errSecSuccess, let data = item as? Data else { throw UIError(message: "无法读取钥匙串中的解锁授权（\(code)）。") }
        let record = try JSONDecoder().decode(RememberedUnlock.self, from: data)
        guard record.expiresAt > Date() else { try forget(directory); return nil }
        return record
    }
}

enum DesktopIdleInterval: Int, Codable, CaseIterable, Identifiable {
    case disabled = 0, oneMinute = 60, fiveMinutes = 300, fifteenMinutes = 900, thirtyMinutes = 1800, oneHour = 3600
    var id: Int { rawValue }
    var label: String { self == .disabled ? "不因空闲锁定" : "\(rawValue / 60) 分钟" }
}

enum DesktopPasswordInterval: Int, Codable, CaseIterable, Identifiable {
    case everyUnlock = 0, oneDay = 24, sevenDays = 168, thirtyDays = 720
    var id: Int { rawValue }
    var label: String { self == .everyUnlock ? "每次解锁都输入" : "\(rawValue / 24) 天" }
}

struct DesktopSecuritySettings: Codable, Equatable {
    var idle: DesktopIdleInterval = .fiveMinutes
    var lockWithDevice = true
    var passwordInterval: DesktopPasswordInterval = .sevenDays

    func idleLockDue(_ elapsed: TimeInterval) -> Bool {
        idle != .disabled && elapsed.isFinite && elapsed >= Double(idle.rawValue)
    }
}

// Each child receives fixed argv and a private stdin pipe. Nothing invokes a shell.
struct CLI: Sendable {
    let binary: URL
    let stateDirectory: String
    var adminSessionFile: String? = nil

    func commandArguments(_ arguments: [String]) -> [String] {
        var result = ["--state-dir", stateDirectory]
        if let file = adminSessionFile { result += ["--admin-session-file", file] }
        return result + arguments
    }

    func run(_ arguments: [String], input: String = "", redacting: [String] = []) throws -> Data {
        guard FileManager.default.isExecutableFile(atPath: binary.path) else {
            throw UIError(message: "找不到随应用安装的 rekey，请重新构建应用。")
        }
        let process = Process()
        process.executableURL = binary
        process.arguments = commandArguments(arguments)
        // Do not forward the host's API keys or other ambient credentials.
        process.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        let stdin = Pipe(), stdout = Pipe(), stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr
        let errors = OutputCapture()
        let group = DispatchGroup()
        try process.run()
        group.enter()
        DispatchQueue.global().async {
            defer { group.leave() }
            errors.read(stderr.fileHandleForReading, process: process)
        }
        let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + (arguments.first == "backup" ? 310 : 150), execute: timeout)
        defer { timeout.cancel() }
        do {
            try stdin.fileHandleForWriting.write(contentsOf: Data(input.utf8))
            try stdin.fileHandleForWriting.close()
        } catch {
            if process.isRunning { process.terminate() }
            throw UIError(message: "无法传递输入。操作结果未确认，请刷新后检查，勿自动重试。")
        }
        let output = OutputCapture()
        output.read(stdout.fileHandleForReading, process: process)
        process.waitUntilExit()
        group.wait()
        guard !output.failed && !errors.failed else {
            throw UIError(message: "命令输出读取失败或超过上限。操作结果未确认，请刷新后检查。")
        }
        guard process.terminationReason == .exit else {
            throw UIError(message: "命令中断或超时。操作结果未确认，请刷新后检查，勿自动重试。")
        }
        guard process.terminationStatus == 0 else {
            var detail = String(data: errors.data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "CLI 未返回错误说明"
            let protectedValues = redacting.flatMap { [$0, $0.trimmingCharacters(in: .whitespacesAndNewlines)] }.sorted { $0.count > $1.count }
            for value in protectedValues where !value.isEmpty { detail = detail.replacingOccurrences(of: value, with: "[已隐藏]") }
            throw UIError(message: "操作未完成（\(process.terminationStatus)）\n\(detail)")
        }
        return output.data
    }

    func decode<T: Decodable>(_ type: T.Type, _ arguments: [String]) throws -> T {
        let output = try run(arguments)
        do { return try JSONDecoder().decode(type, from: output) }
        catch { throw UIError(message: "服务返回了无法识别的数据，请确认客户端与服务版本一致。") }
    }

    func approvalDetails(_ id: String) throws -> ApprovalDetails {
        let data = try run(["approval", "get", id])
        let envelope: ApprovalEnvelope
        do { envelope = try JSONDecoder().decode(ApprovalEnvelope.self, from: data) }
        catch { throw UIError(message: "审批信封数据无法识别，请确认客户端与服务版本一致。") }
        guard envelope.challenge.approval_request_id == id else {
            throw UIError(message: "返回的审批请求与所选条目不一致，请刷新收件箱。")
        }
        let origin = try decode(ApprovalOrigin.self, ["approval", "origin"])
        return ApprovalDetails(envelope: envelope, origin: origin, data: data)
    }
}

private final class OutputCapture: @unchecked Sendable {
    // Written by one reader and inspected only after joining that reader.
    var data = Data()
    var failed = false
    func read(_ file: FileHandle, process: Process) {
        do {
            while let chunk = try file.read(upToCount: 16384), !chunk.isEmpty {
                if data.count + chunk.count > 2 * 1024 * 1024 {
                    failed = true
                    if process.isRunning { process.terminate() }
                    break
                }
                data.append(chunk)
            }
            try file.close()
        } catch {
            failed = true
            if process.isRunning { process.terminate() }
        }
    }
}

struct ServiceStatus: Decodable {
    let state: String
    let format_version: Int
    let runtime_version: String
    let sessions_active: Int
    var unlocked: Bool { state == "unlocked" }
    var label: String {
        switch state {
        case "unlocked": return "已解锁"
        case "locked": return "已锁定"
        case "faulted": return "服务故障"
        default: return "状态：" + state
        }
    }
}
struct Credential: Decodable, Identifiable {
    let id: String
    let label: String
    let kind: String
    let state: String
    let current_version: Int
    var active: Bool { state == "active" }
    var typeName: String {
        switch kind {
        case "opaque-token": return "固定令牌"
        case "github-app-installation": return "GitHub App"
        case "vault-kv-v2-source": return "Vault KV v2"
        case "vault-dynamic-source": return "动态租约"
        case "keycloak-token-exchange": return "Keycloak"
        case "gcp-secret-manager-source": return "GCP Secret Manager"
        case "aws-secrets-manager-source": return "AWS Secrets Manager"
        case "azure-key-vault-source": return "Azure Key Vault"
        case "onepassword-connect-source": return "1Password Connect"
        case "macos-keychain-source": return "macOS Keychain"
        default: return kind
        }
    }
    var icon: String {
        switch kind {
        case "github-app-installation": return "chevron.left.forwardslash.chevron.right"
        case "vault-kv-v2-source", "vault-dynamic-source": return "externaldrive"
        default: return "key.horizontal"
        }
    }
}
struct CredentialList: Decodable { let credentials: [Credential] }
struct FixedAction: Decodable, Identifiable {
    struct RequestPolicy: Decodable { let max_body_bytes: Int }
    let id: String
    let name: String
    let version: Int
    let enabled: Bool
    let credential_id: String
    let origin: String
    let method: String
    let exact_path: String
    let request_policy: RequestPolicy
    var request_max_bytes: Int { request_policy.max_body_bytes }
    var reference: String { "\(id)@\(version)" }
}
struct ActionList: Decodable { let actions: [FixedAction] }
struct PolicyStatus: Decodable {
    let vault_id: String
    let trust_sha256: String?
    let bundle_persisted: Bool
    let trust_installed: Bool
    let status: String
    let version: Int?
    let signer_id: String?
    let expires_at_ms: Int64?
}
struct PendingApproval: Decodable, Identifiable {
    let approval_request_id: String
    let action_id: String
    let action_version: Int
    let session_id: String
    let max_expires_at_ms: Int64
    let parameter_sha256: String
    let quorum: Int
    var id: String { approval_request_id }
}
struct PendingList: Decodable { let challenges: [PendingApproval] }
struct ApprovalChallenge: Decodable {
    struct Resource: Decodable { let type: String; let id: String }
    let record_type: String
    let approval_request_id: String
    let tenant_id: String
    let principal_id: String
    let session_id: String
    let action_id: String
    let action_version: UInt64
    let resource: Resource
    let schema_id: String
    let parameter_sha256: String
    let policy_version: UInt64
    let policy_sha256: String
    let policy_rule_id: String
    let mode: String
    let quorum: UInt8
    let approver_ids: [String]
    let max_uses: UInt32
    let created_at_ms: Int64
    let max_expires_at_ms: Int64
}
struct ApprovalEnvelope: Decodable {
    let record_type: String
    let challenge: ApprovalChallenge
    let signature: String
}
struct ApprovalOrigin: Decodable { let algorithm: String; let public_key: String }
struct ApprovalDetails: Identifiable {
    let envelope: ApprovalEnvelope
    let origin: ApprovalOrigin
    let data: Data
    var id: String { envelope.challenge.approval_request_id }
    func matchingAction(in actions: [FixedAction]) -> FixedAction? {
        actions.first { $0.id == envelope.challenge.action_id && $0.version > 0 && UInt64($0.version) == envelope.challenge.action_version }
    }
}
struct AuditEvent: Decodable, Identifiable {
    let sequence: Int
    let event_type: String
    let outcome: String
    let reason_code: String
    let created_at_ms: Int64
    let request_id: String?
    var id: Int { sequence }
}
struct AuditPage: Decodable {
    let snapshot_max_sequence: Int
    let next_before_sequence: Int?
    let events: [AuditEvent]
}

enum Page: String, CaseIterable, Identifiable {
    case credentials = "凭证", actions = "固定操作", policy = "授权与策略", approvals = "审批收件箱", audit = "审计日志", backup = "备份与恢复", settings = "设置"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .credentials: return "doc.text"
        case .actions: return "play"
        case .policy: return "checkmark.shield"
        case .approvals: return "tray"
        case .audit: return "list.bullet.rectangle"
        case .backup: return "externaldrive"
        case .settings: return "gearshape"
        }
    }
}

struct Operation: Identifiable {
    let id = UUID()
    let title: String
    let detail: String
    let arguments: [String]
    var proof = true
    var proofFlag = "--password-stdin"
    var newSecret = false
    var confirmSecret = false
    var sensitiveResult = false
    var recoveryAllowed = true
    var targetDirectory: String?
    var temporaryFile: URL?
}
struct ResultMessage: Identifiable {
    let id = UUID()
    let title: String
    let text: String
    var sensitive: Bool = false
}

struct OIDCLoginBegin: Decodable, Sendable {
    let flow_id: String
    let authorization_url: String
    let expires_at_ms: Int64

    var browserURL: URL? {
        guard let url = URL(string: authorization_url), url.scheme == "https",
              url.host != nil, url.user == nil, url.password == nil else { return nil }
        return url
    }
}

struct OIDCLoginIdentity: Decodable, Sendable {
    let principal_id: String
    let expires_at_ms: Int64
    let mapping_sha256: String
}

@MainActor
final class AppModel: ObservableObject {
    @Published var page: Page = .credentials
    @Published var status: ServiceStatus?
    @Published var credentials: [Credential] = []
    @Published var actions: [FixedAction] = []
    @Published var policy: PolicyStatus?
    @Published var approvals: [PendingApproval] = []
    @Published var approvalDetails: ApprovalDetails?
    @Published var showPolicyDraft = false
    @Published private(set) var nativeFlowRevision = UUID()
    @Published var audit: AuditPage?
    @Published var desktopToken: String?
    @Published var copiedCredential: String?
    @Published var visibleSecret: String?
    private var desktopExpiry = Date.distantPast
    @Published private(set) var desktopLocked = true
    @Published private(set) var desktopLockReason = "请输入保险库密码，或使用已设置的 Mac 身份验证。"
    @Published private(set) var securitySettings: DesktopSecuritySettings
    @Published private(set) var pendingDesktopLocks = 0
    private var desktopRevision = UUID()
    private var authenticationContext: LAContext?
    private var securityTimer: Timer?
    private var securityObservers: [(NotificationCenter, NSObjectProtocol)] = []
    private var pendingRevocations: [String: CLI] = [:]
    private var revocationsRunning: Set<String> = []
    private var ownedClipboardChangeCount: Int?
    private let preferences: UserDefaults
    private let cliBinary: URL?
    private let clipboard: NSPasteboard
    @Published var selectedCredential: String? { didSet { visibleSecret = nil; copiedCredential = nil } }
    @Published var busy = false
    @Published var error: String?
    @Published var connectionError: String?
    @Published var operation: Operation?
    @Published var result: ResultMessage?
    @Published var oidcProfileFile: String?
    @Published var oidcSessionFile: String? { didSet { if oldValue != oidcSessionFile { oidcIdentity = nil } } }
    @Published private(set) var oidcFlow: OIDCLoginBegin?
    @Published private(set) var oidcFlowRevision = UUID()
    @Published private(set) var oidcBusy = false
    @Published var oidcIdentity: OIDCLoginIdentity?
    @Published var showAddCredential = false
    @Published var showSession = false
    @Published var auditOutcome = ""
    @Published var stateDirectory: String { didSet {
        if oldValue != stateDirectory {
            clearNativeFlow(); clearOIDCLogin(); oidcProfileFile = nil; oidcSessionFile = nil; oidcIdentity = nil
        }
    } }
    private var launchedService: Process?
    private var launchedServiceDirectory: String?
    var cli: CLI {
        CLI(binary: cliBinary ?? Bundle.main.resourceURL!.appendingPathComponent("bin/rekey"), stateDirectory: stateDirectory, adminSessionFile: oidcSessionFile)
    }
    var unlocked: Bool { status?.unlocked == true }
    var serviceIsRunning: Bool { status != nil || (launchedServiceDirectory == stateDirectory && launchedService?.isRunning == true) }
    var selected: Credential? { credentials.first { $0.id == selectedCredential } }
    init(stateDirectory: String? = nil, preferences: UserDefaults = .standard, binary: URL? = nil, clipboard: NSPasteboard = .general) {
        self.preferences = preferences; self.cliBinary = binary; self.clipboard = clipboard
        self.stateDirectory = stateDirectory ?? (preferences.string(forKey: "stateDirectory") ?? NSHomeDirectory() + "/.rekey")
        self.securitySettings = preferences.data(forKey: "desktopSecurity").flatMap { try? JSONDecoder().decode(DesktopSecuritySettings.self, from: $0) } ?? DesktopSecuritySettings()
    }
    deinit {
        securityTimer?.invalidate()
        for (center, observer) in securityObservers { center.removeObserver(observer) }
    }

    func startSecurityMonitoring(workspace: NotificationCenter = NSWorkspace.shared.notificationCenter,
                                 distributed: NotificationCenter = DistributedNotificationCenter.default()) {
        guard securityTimer == nil else { return }
        for name in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            let observer = workspace.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                Task { @MainActor in self?.deviceLocked() }
            }
            securityObservers.append((workspace, observer))
        }
        // This signal only reduces access; it is never accepted as authentication.
        let observer = distributed.addObserver(forName: Notification.Name("com.apple.screenIsLocked"), object: nil, queue: .main) { [weak self] _ in
            Task { @MainActor in self?.deviceLocked() }
        }
        securityObservers.append((distributed, observer))
        securityTimer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkDesktopIdle() }
        }
        if let timer = securityTimer { RunLoop.main.add(timer, forMode: .common) }
    }
    func deviceLocked() {
        if securitySettings.lockWithDevice { lockDesktop(reason: "电脑已锁屏、休眠或切换用户。") }
    }
    func checkDesktopIdle(elapsed: TimeInterval? = nil) {
        let elapsed = elapsed ?? CGEventSource.secondsSinceLastEventType(.combinedSessionState, eventType: CGEventType(rawValue: UInt32.max)!)
        if securitySettings.idleLockDue(elapsed) && (!desktopLocked || busy || operation != nil || result != nil) {
            lockDesktop(reason: "电脑已空闲 \(securitySettings.idle.label)，管理界面已锁定。")
        }
        if desktopToken != nil && Date() >= desktopExpiry {
            lockDesktop(reason: "解锁授权已到期，请重新验证身份。")
        }
    }
    private func clearDesktopPresentation() {
        desktopLocked = true; desktopRevision = UUID()
        authenticationContext?.invalidate(); authenticationContext = nil
        desktopToken = nil; desktopExpiry = .distantPast; visibleSecret = nil; copiedCredential = nil
        if let count = ownedClipboardChangeCount, clipboard.changeCount == count { clipboard.clearContents() }
        ownedClipboardChangeCount = nil
        operation = nil; result = nil; showAddCredential = false; showSession = false
        clearNativeFlow(); clearOIDCLogin()
        credentials = []; actions = []; approvals = []; approvalDetails = nil; policy = nil; audit = nil; selectedCredential = nil
    }
    func lockDesktop(reason: String = "管理界面已锁定；已授权的 Agent 继续工作。") {
        let token = desktopToken, client = cli
        clearDesktopPresentation(); desktopLockReason = reason
        if let token { revokeDesktop(token, client: client) }
    }
    private func revokeDesktop(_ token: String, client: CLI) {
        pendingRevocations[token] = client; pendingDesktopLocks = pendingRevocations.count
        retryDesktopLock()
    }
    func retryDesktopLock() {
        for (token, client) in pendingRevocations where !revocationsRunning.contains(token) {
            revocationsRunning.insert(token)
            Task {
                defer { revocationsRunning.remove(token) }
                do {
                    _ = try await Task.detached { try client.run(["desktop-lock"], input: token + "\n") }.value
                    pendingRevocations.removeValue(forKey: token)
                } catch {
                    // A rejected token is already unable to reveal a credential.
                    if error.localizedDescription.contains("INVALID_UNLOCK_CREDENTIAL") {
                        pendingRevocations.removeValue(forKey: token)
                    } else { self.error = "管理界面已锁定，但服务端会话撤销尚未确认。请重试完成锁定。\n" + error.localizedDescription }
                }
                pendingDesktopLocks = pendingRevocations.count
            }
        }
    }
    func acceptDesktopSession(_ token: String, expiry: Date) {
        desktopToken = token; desktopExpiry = expiry; desktopLocked = false; desktopLockReason = ""
    }
    func unlockWithMac(authenticate: ((LAContext) async throws -> Void)? = nil,
                       loadRemembered: ((String) throws -> RememberedUnlock?)? = nil) async {
        guard !busy, pendingDesktopLocks == 0, securitySettings.passwordInterval != .everyUnlock else { return }
        let revision = desktopRevision, workspace = stateDirectory, client = cli
        let context = LAContext(); context.localizedCancelTitle = "取消"
        authenticationContext = context; busy = true; error = nil
        defer { busy = false; if authenticationContext === context { authenticationContext = nil } }
        do {
            if let authenticate { try await authenticate(context) }
            else {
                var error: NSError?
                guard context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
                    throw UIError(message: "此 Mac 无法验证设备身份，请使用保险库密码。")
                }
                try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "解锁 Rekey 密钥管理界面")
            }
            guard revision == desktopRevision, workspace == stateDirectory else { return }
            guard let record = try (loadRemembered ?? RememberedUnlock.load)(workspace) else {
                throw UIError(message: "未保存有效的本机授权，请输入保险库密码。")
            }
            let data = try await Task.detached { try client.run(["desktop-resume"], input: record.key + "\n") }.value
            let session = try RememberedUnlock.receipt(data)
            guard revision == desktopRevision, workspace == stateDirectory else { revokeDesktop(session.key, client: client); return }
            acceptDesktopSession(session.key, expiry: session.expiresAt)
        } catch {
            if revision == desktopRevision {
                if let auth = error as? LAError, [.userCancel, .appCancel, .systemCancel].contains(auth.code) { return }
                self.error = error.localizedDescription
            }
        }
        busy = false
        if !desktopLocked { await refresh() }
    }
    func saveSecuritySettings(_ settings: DesktopSecuritySettings, forgetRemembered: ((String) throws -> Void)? = nil) async {
        guard desktopReady, !busy, let token = desktopToken else { return }
        let client = cli, workspace = stateDirectory, revision = desktopRevision
        busy = true; error = nil
        defer { busy = false }
        do {
            _ = try await Task.detached { try client.run(["desktop-lock", "--forget-remembered"], input: token + "\n") }.value
            guard revision == desktopRevision, workspace == stateDirectory else { return }
            clearDesktopPresentation()
            preferences.set(try JSONEncoder().encode(settings), forKey: "desktopSecurity")
            securitySettings = settings
            desktopLockReason = "安全设置已保存。请重新输入保险库密码以应用新的记住期限。"
            // The Authority has already invalidated the grant, even if OS cleanup fails.
            try (forgetRemembered ?? RememberedUnlock.forget)(workspace)
        } catch {
            lockDesktop(reason: "安全设置的保存结果尚未确认，请先完成会话撤销。")
            self.error = error.localizedDescription
        }
    }
    func beginOIDCLogin() async {
        guard !busy, !oidcBusy, unlocked else { return }
        let client = cli, revision = oidcFlowRevision, workspace = stateDirectory
        oidcBusy = true; error = nil
        defer { if revision == oidcFlowRevision && workspace == stateDirectory { oidcBusy = false } }
        do {
            let flow = try await Task.detached { try client.decode(OIDCLoginBegin.self, ["oidc-login", "begin"]) }.value
            guard acceptsOIDCCompletion(revision, workspace: workspace) else { return }
            guard flow.browserURL != nil else { throw UIError(message: "登录授权地址无效。") }
            oidcFlow = flow
        } catch {
            if revision == oidcFlowRevision && workspace == stateDirectory { self.error = error.localizedDescription }
        }
    }
    func finishOIDCLogin(to file: URL) async {
        guard !busy, !oidcBusy, unlocked, let flow = oidcFlow else { return }
        let client = cli, revision = oidcFlowRevision, workspace = stateDirectory
        oidcBusy = true; error = nil
        defer { if revision == oidcFlowRevision && workspace == stateDirectory { oidcBusy = false } }
        do {
            let identity = try await Task.detached {
                try client.decode(OIDCLoginIdentity.self, ["oidc-login", "finish", "--flow-id", flow.flow_id, "--session-file", file.path])
            }.value
            guard acceptsOIDCCompletion(revision, workspace: workspace), oidcFlow?.flow_id == flow.flow_id else {
                do { _ = try await Task.detached { try client.run(["oidc-login", "logout", "--session-file", file.path]) }.value }
                catch { self.error = "旧工作区登录结果未采用，且无法确认其会话退出。\n" + error.localizedDescription }
                return
            }
            oidcSessionFile = file.path; oidcIdentity = identity; oidcFlow = nil
            oidcBusy = false
            await refresh()
            return
        } catch {
            if revision == oidcFlowRevision && workspace == stateDirectory { self.error = error.localizedDescription }
        }
    }
    func cancelOIDCLogin() async {
        guard let flow = oidcFlow else { return }
        let client = cli, workspace = stateDirectory
        clearOIDCLogin()
        let revision = oidcFlowRevision
        oidcBusy = true
        defer { if revision == oidcFlowRevision && workspace == stateDirectory { oidcBusy = false } }
        do { _ = try await Task.detached { try client.run(["oidc-login", "cancel", "--flow-id", flow.flow_id]) }.value }
        catch { if revision == oidcFlowRevision && workspace == stateDirectory { self.error = error.localizedDescription } }
    }
    func logoutOIDC() async {
        guard !busy, !oidcBusy, let file = oidcSessionFile else { return }
        let client = cli, workspace = stateDirectory
        clearOIDCLogin()
        let revision = oidcFlowRevision
        oidcBusy = true; error = nil
        defer { if revision == oidcFlowRevision && workspace == stateDirectory { oidcBusy = false } }
        do {
            let data = try await Task.detached { try client.run(["oidc-login", "logout", "--session-file", file]) }.value
            guard revision == oidcFlowRevision && workspace == stateDirectory else { return }
            oidcSessionFile = nil; oidcIdentity = nil
            result = ResultMessage(title: "机构会话已退出", text: String(decoding: data, as: UTF8.self))
        } catch {
            if revision == oidcFlowRevision && workspace == stateDirectory { self.error = error.localizedDescription }
        }
    }
    func clearOIDCLogin() {
        oidcFlowRevision = UUID(); oidcFlow = nil; oidcBusy = false
    }
    func acceptsOIDCCompletion(_ revision: UUID, workspace: String) -> Bool {
        revision == oidcFlowRevision && workspace == stateDirectory && unlocked && !desktopLocked
    }
    func clearNativeFlow() {
        nativeFlowRevision = UUID(); showPolicyDraft = false; approvalDetails = nil
    }
    func acceptsNativeCompletion(_ revision: UUID, workspace: String) -> Bool {
        revision == nativeFlowRevision && workspace == stateDirectory && unlocked && !desktopLocked
    }
    var needsSetup: Bool {
        !FileManager.default.fileExists(atPath: stateDirectory + "/vault.sqlite3")
    }
    func beginSetup() {
        operation = Operation(title: "创建保险库", detail: "设置并确认密码后，应用会自动创建保险库并启动服务。请保存随后显示的恢复密钥。", arguments: ["init"], confirmSecret: true, sensitiveResult: true, recoveryAllowed: false)
    }
    var desktopReady: Bool { desktopToken != nil && Date() < desktopExpiry && unlocked && !desktopLocked && pendingDesktopLocks == 0 }
    func requestDesktopLogin() {
        operation = Operation(title: "解锁管理会话", detail: "解锁后可以保存、查看和复制密钥。记住期限与自动锁定方式可在安全设置中修改。", arguments: ["unlock"])
    }
    func addAPIKey(label: String, secret: String) async -> Bool {
        guard desktopReady, let token = desktopToken else {
            lockDesktop(reason: "管理会话已过期，请重新解锁。")
            error = "管理会话已过期，请重新解锁。"; return false
        }
        guard !busy else { return false }
        busy = true; error = nil
        let client = cli
        do {
            _ = try await Task.detached { try client.run(["desktop-add", label], input: token + "\n" + secret + "\n") }.value
            busy = false; await refresh(); return true
        } catch { rejectDesktopSession(error); self.error = error.localizedDescription; busy = false; return false }
    }
    func revealCredential(_ id: String, copy: Bool) async {
        guard desktopReady, let token = desktopToken else { requestDesktopLogin(); return }
        guard !busy else { return }
        busy = true; error = nil
        defer { busy = false }
        let client = cli, revision = desktopRevision
        do {
            let data = try await Task.detached { try client.run(["desktop-reveal", id], input: token + "\n") }.value
            guard revision == desktopRevision, desktopReady, selectedCredential == id, NSApp.isActive else { return }
            guard let text = String(data: data, encoding: .utf8) else { throw UIError(message: "此凭证不是可显示的 UTF-8 文本。") }
            if copy { try copyToClipboard(text, credential: id) }
            else { visibleSecret = text }
        } catch { rejectDesktopSession(error); visibleSecret = nil; self.error = error.localizedDescription }
    }
    func copyToClipboard(_ text: String, credential: String) throws {
        let board = clipboard
        board.clearContents()
        guard board.setString(text, forType: .string) else { throw UIError(message: "写入剪贴板失败。") }
        copiedCredential = credential
        let revision = board.changeCount
        ownedClipboardChangeCount = revision
        DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
            if board.changeCount == revision { board.clearContents() }
        }
    }
    func rejectDesktopSession(_ error: Error) {
        let message = error.localizedDescription
        if message.contains("INVALID_UNLOCK_CREDENTIAL") || message.contains("LOCKED") || message.contains("FAULTED") {
            lockDesktop(reason: "管理会话已失效，请重新验证身份。")
        }
    }
    func clearCache() {
        clearDesktopPresentation()
        oidcSessionFile = nil; oidcIdentity = nil
    }
    func changeDirectory(_ path: String) {
        guard !busy, !oidcBusy else { return }
        lockDesktop()
        stateDirectory = path
        preferences.set(path, forKey: "stateDirectory")
        status = nil; clearCache(); result = nil; error = nil
        Task { await refresh() }
    }
    func refresh(nextAuditPage: Bool = false, passive: Bool = false) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        let client = cli
        let revision = desktopRevision, workspace = stateDirectory
        do {
            let current = try await Task.detached { try client.decode(ServiceStatus.self, ["status", "--passive"]) }.value
            guard revision == desktopRevision, workspace == stateDirectory else { return }
            status = current; connectionError = nil
            if !current.unlocked { clearCache() }
            if desktopLocked { return }
        } catch {
            lockDesktop(); status = nil; connectionError = error.localizedDescription
            return
        }
        do {
            if unlocked {
                let pending = try await Task.detached { try client.decode(PendingList.self, ["approval", "pending"]) }.value.challenges
                guard revision == desktopRevision, workspace == stateDirectory else { return }
                approvals = pending
            }
            if passive { return }
            if unlocked {
                let lists = try await Task.detached {
                    (try client.decode(CredentialList.self, ["credential", "list"]),
                     try client.decode(ActionList.self, ["action", "list"]))
                }.value
                guard revision == desktopRevision, workspace == stateDirectory else { return }
                credentials = lists.0.credentials; actions = lists.1.actions
                if !credentials.contains(where: { $0.id == selectedCredential }) { selectedCredential = credentials.first?.id }
            }
            switch page {
            case .policy:
                let value = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
                guard revision == desktopRevision, workspace == stateDirectory else { return }
                policy = value
            case .audit:
                var args = ["audit", "list", "--limit", "50"]
                if !auditOutcome.isEmpty { args += ["--outcome", auditOutcome] }
                if nextAuditPage, let prior = audit, let cursor = prior.next_before_sequence {
                    args += ["--snapshot-max-sequence", String(prior.snapshot_max_sequence), "--before-sequence", String(cursor)]
                }
                let command = args
                let value = try await Task.detached { try client.decode(AuditPage.self, command) }.value
                guard revision == desktopRevision, workspace == stateDirectory else { return }
                audit = value
            default: break
            }
        } catch {
            lockDesktop()
            self.error = error.localizedDescription
        }
    }
    func perform(_ op: Operation, proof: String = "", secret: String = "", recovery: Bool = false) async {
        guard !busy else { return }
        busy = true; error = nil
        let client = CLI(binary: cli.binary, stateDirectory: op.targetDirectory ?? stateDirectory, adminSessionFile: oidcSessionFile)
        let desktopLogin = op.arguments == ["unlock"]
        guard !desktopLogin || pendingDesktopLocks == 0 else { busy = false; return }
        let revision = desktopRevision, workspace = stateDirectory
        let passwordInterval = securitySettings.passwordInterval
        var args = desktopLogin ? ["desktop-login"] : op.arguments
        var input = ""
        if op.proof {
            if !desktopLogin { args.append(op.newSecret ? "--stdin-secrets" : op.proofFlag) }
            input = proof + "\n"
            if op.newSecret { input += secret + "\n" }
            if recovery && op.recoveryAllowed { args.append("--recovery") }
        }
        let command = args, body = input
        var operationError: String?
        do {
            let data = try await Task.detached { try client.run(command, input: body) }.value
            guard let output = String(data: data, encoding: .utf8) else { throw UIError(message: "命令返回了无法解码的内容，操作结果需重新确认。") }
            if desktopLogin {
                guard output.count == 64 && output.allSatisfy(\.isHexDigit) else { throw UIError(message: "管理会话响应无效。") }
                guard revision == desktopRevision, workspace == stateDirectory else {
                    revokeDesktop(output, client: client); busy = false; return
                }
                acceptDesktopSession(output, expiry: Date().addingTimeInterval(7 * 24 * 60 * 60))
                if passwordInterval != .everyUnlock && (oidcProfileFile == nil || oidcSessionFile != nil) {
                    var rememberArgs = ["desktop-remember", "--ttl", "\(passwordInterval.rawValue)h"]
                    if recovery { rememberArgs.append("--recovery") }
                    let rememberCommand = rememberArgs
                    let rememberedData = try await Task.detached { try client.run(rememberCommand, input: body) }.value
                    guard revision == desktopRevision, workspace == stateDirectory else {
                        revokeDesktop(output, client: client); busy = false; return
                    }
                    let remembered = try RememberedUnlock.receipt(rememberedData)
                    desktopExpiry = min(desktopExpiry, remembered.expiresAt)
                    try remembered.save(workspace)
                }
            } else if revision == desktopRevision && workspace == stateDirectory {
                result = ResultMessage(title: op.title + "完成", text: output, sensitive: op.sensitiveResult)
            }
        } catch { operationError = error.localizedDescription }
        if let file = op.temporaryFile {
            do { try FileManager.default.removeItem(at: file) }
            catch { operationError = (operationError.map { $0 + "\n" } ?? "") + "无法删除临时操作定义：\(file.path)" }
        }
        busy = false
        await refresh()
        if let operationError { self.error = operationError }
        else if op.arguments == ["init"] { startService() }
    }
    func startExistingService() {
        guard status == nil && !needsSetup else { return }
        startService()
    }
    func startService() {
        guard !busy else { return }
        guard !needsSetup else { beginSetup(); return }
        guard launchedService?.isRunning != true || launchedServiceDirectory != stateDirectory else {
            error = "由此窗口启动的服务仍在运行，请刷新状态。"; return
        }
        let child = Process()
        child.executableURL = cli.binary
        var arguments = ["--state-dir", stateDirectory, "serve"]
        if let profile = oidcProfileFile { arguments += ["--oidc-admin-profile", profile] }
        child.arguments = arguments
        child.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        child.standardInput = FileHandle.nullDevice
        child.standardOutput = FileHandle.nullDevice
        let errors = Pipe()
        child.standardError = errors
        do {
            try child.run()
            launchedService = child
            launchedServiceDirectory = stateDirectory
            let serviceDirectory = stateDirectory
            busy = true
            // Drain stderr while the service lives; only bounded diagnostics remain in memory.
            let captured = ServiceDiagnostic()
            errors.fileHandleForReading.readabilityHandler = { file in captured.append(file.availableData) }
            child.terminationHandler = { process in
                errors.fileHandleForReading.readabilityHandler = nil
                Task { @MainActor [weak self] in
                    guard let self, self.stateDirectory == serviceDirectory else { return }
                    if process.terminationStatus != 0 { self.error = "服务已退出。\n" + captured.text }
                    await self.refresh()
                }
            }
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.6) {
                self.busy = false
                Task { await self.refresh() }
            }
        } catch { self.error = "无法启动服务：\(error.localizedDescription)" }
    }
    func lock() async {
        guard !busy else { return }
        busy = true
        let client = cli, workspace = stateDirectory
        lockDesktop(reason: "正在锁定整个保险库。")
        do {
            _ = try await Task.detached { try client.run(["lock"]) }.value
            desktopLockReason = "整个保险库已锁定，Agent 授权已撤销。"
            try RememberedUnlock.forget(workspace)
        } catch { self.error = "锁定全部的结果尚未确认。\n" + error.localizedDescription }
        busy = false
        await refresh()
    }
    func exportApproval(_ item: PendingApproval) async {
        guard let destination = chooseSave("approval-\(item.id).json") else { return }
        guard !busy else { return }
        busy = true
        let client = cli
        do {
            let data = try await Task.detached { try client.run(["approval", "get", item.id]) }.value
            try writePrivateNew(data, to: destination)
            result = ResultMessage(title: "审批信封已导出", text: destination.path)
        } catch { self.error = error.localizedDescription }
        busy = false
    }
    func reviewApproval(_ item: PendingApproval) async {
        guard !busy, unlocked else { return }
        busy = true; error = nil; approvalDetails = nil
        defer { busy = false }
        let client = cli, revision = nativeFlowRevision
        do {
            let details = try await Task.detached { try client.approvalDetails(item.id) }.value
            finishApprovalReview(.success(details), revision: revision, workspace: client.stateDirectory, active: NSApp.isActive)
        } catch {
            finishApprovalReview(.failure(error), revision: revision, workspace: client.stateDirectory, active: NSApp.isActive)
        }
    }
    @discardableResult
    func finishApprovalReview(_ outcome: Result<ApprovalDetails, Error>, revision: UUID, workspace: String, active: Bool) -> Bool {
        guard active, acceptsNativeCompletion(revision, workspace: workspace) else { return false }
        switch outcome {
        case .success(let details): approvalDetails = details
        case .failure(let failure): approvalDetails = nil; error = failure.localizedDescription
        }
        return true
    }
}

private final class ServiceDiagnostic: @unchecked Sendable {
    private let lock = NSLock()
    private var data = Data()
    func append(_ chunk: Data) { lock.lock(); defer { lock.unlock() }; data.append(chunk.prefix(max(0, 65536 - data.count))) }
    var text: String { lock.lock(); defer { lock.unlock() }; return String(data: data, encoding: .utf8) ?? "服务输出无法解码" }
}

@MainActor func chooseFile(directory: Bool = false) -> URL? {
    let panel = NSOpenPanel()
    panel.canChooseDirectories = directory; panel.canChooseFiles = !directory
    panel.allowsMultipleSelection = false
    panel.canCreateDirectories = directory
    return panel.runModal() == .OK ? panel.url : nil
}
@MainActor func chooseSave(_ filename: String) -> URL? {
    let panel = NSSavePanel()
    panel.nameFieldStringValue = filename
    panel.canCreateDirectories = true
    return panel.runModal() == .OK ? panel.url : nil
}
func writePrivateNew(_ data: Data, to url: URL) throws {
    let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
    guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    do {
        guard fchmod(fd, 0o600) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        try handle.write(contentsOf: data); try handle.synchronize(); try handle.close()
    } catch {
        throw UIError(message: "文件写入未完成，目标可能留下不完整文件：" + error.localizedDescription)
    }
}

struct PolicyDraftApprover: Identifiable {
    var id = UUID()
    var approverID = UUID().uuidString.lowercased()
    var publicKey = ""
}

struct PolicyDraftRule: Identifiable {
    var id = UUID()
    var action = ""
    var principal = ""
    var resourceType = ""
    var resourceID = ""
    var schemaID = ""
    var schema = "{\"type\": \"object\"}"
    var effect = "require-approval"
    var exactHash = ""
    var approvers = ""
    var quorum = 1
    var mode = "one-time"
    var maxUses = 1
    var windowSeconds = 300
}

struct PolicyDraftEditor {
    var version: UInt64 = 1
    var expiry = Date().addingTimeInterval(86400)
    var approvers: [PolicyDraftApprover] = []
    var rules: [PolicyDraftRule] = []

    func generate(actions: [FixedAction]) throws -> String {
        func json(_ value: Any) throws -> String {
            String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys, .fragmentsAllowed]), as: UTF8.self)
        }
        var bindings: [String: String] = [:]
        var renderedRules: [String] = []
        for rule in rules {
            guard let action = actions.first(where: { $0.reference == rule.action }) else {
                throw UIError(message: "请选择每条规则对应的固定操作及版本。")
            }
            let resource: [String: String] = ["type": rule.resourceType, "id": rule.resourceID]
            // Preserve raw schema JSON: the Rust signer remains the only policy
            // validator and must still see duplicate keys or malformed syntax.
            let binding = "{\"action_id\":\(try json(action.id)),\"version\":\(action.version),\"resource\":\(try json(resource)),\"parameter_schema_id\":\(try json(rule.schemaID)),\"parameter_schema\":\(rule.schema)}"
            if let previous = bindings[rule.action], previous != binding {
                throw UIError(message: "同一操作版本的资源与参数结构必须一致，请核对规则。")
            }
            bindings[rule.action] = binding
            var value: [String: Any] = ["id": rule.id.uuidString.lowercased(), "effect": rule.effect,
                "principal_id": rule.principal, "action_id": action.id, "version": action.version,
                "resource": resource, "parameters": rule.exactHash.isEmpty
                    ? ["kind": "any_validated"] : ["kind": "exact_hash", "sha256": rule.exactHash]]
            if rule.effect == "require-approval" {
                var requirement: [String: Any] = ["approver_ids": rule.approvers.split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) },
                    "quorum": rule.quorum, "mode": rule.mode, "max_uses": rule.mode == "one-time" ? 1 : rule.maxUses]
                if rule.mode == "time-window" { requirement["max_window_ms"] = Int64(rule.windowSeconds) * 1000 }
                value["approval"] = requirement
            }
            renderedRules.append(try json(value))
        }
        let expiryMS = expiry.timeIntervalSince1970 * 1000
        guard expiryMS.isFinite, expiryMS >= 0, expiryMS < Double(Int64.max) else { throw UIError(message: "有效期无效。") }
        let publicApprovers = approvers.map { ["approver_id": $0.approverID, "algorithm": "ed25519", "public_key": $0.publicKey] }
        let text = """
        {
          "format_version": 3,
          "version": \(version),
          "expires_at_ms": \(Int64(expiryMS)),
          "approvers": \(try json(publicApprovers)),
          "workload_identities": [],
          "bindings": [\(bindings.keys.sorted().compactMap { bindings[$0] }.joined(separator: ",\n"))],
          "rules": [\(renderedRules.joined(separator: ",\n"))]
        }

        """
        _ = try Self.snapshot(text)
        return text
    }

    static func snapshot(_ text: String) throws -> NativeFileSnapshot {
        let data = Data(text.utf8)
        guard !data.isEmpty, data.count <= 65536 else { throw UIError(message: "草稿不能为空，且最多为 64 KiB。") }
        return NativeFileSnapshot(data: data, text: text)
    }
}

struct NativeFileSnapshot: Sendable {
    let data: Data
    let text: String
    static func read(_ url: URL, limit: Int, json: Bool = false) throws -> NativeFileSnapshot {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        defer { try? handle.close() }
        var statbuf = stat()
        guard fstat(fd, &statbuf) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        guard (statbuf.st_mode & S_IFMT) == S_IFREG else { throw UIError(message: "请选择普通文件。") }
        guard limit >= 0, statbuf.st_size >= 0, statbuf.st_size <= limit else { throw UIError(message: "文件超过本操作的大小上限。") }
        var bytes = Data()
        while let chunk = try handle.read(upToCount: min(16384, limit + 1 - bytes.count)), !chunk.isEmpty {
            bytes.append(chunk)
            guard bytes.count <= limit else { throw UIError(message: "文件超过本操作的大小上限。") }
        }
        guard let text = String(data: bytes, encoding: .utf8) else { throw UIError(message: "文件不是有效的 UTF-8 文本。") }
        if json {
            do { _ = try JSONSerialization.jsonObject(with: bytes, options: [.fragmentsAllowed]) }
            catch { throw UIError(message: "原始正文不是有效的 UTF-8 JSON。") }
        }
        return NativeFileSnapshot(data: bytes, text: text)
    }
}

struct NativeExecuteResult: Sendable {
    struct Metadata: Decodable, Sendable {
        let upstream_status: UInt16
        let headers: [[String]]
        let body_len: UInt32
    }
    let metadata: Metadata
    let metadataText: String
    let body: Data
    static func parse(_ output: Data) throws -> NativeExecuteResult {
        // print_json emits one fixed pretty object: only its root closer has column zero.
        guard output.count <= 2 * 1024 * 1024, output.starts(with: Data("{\n".utf8)),
              let rootEnd = output.range(of: Data("\n}\n".utf8)) else {
            throw UIError(message: "执行响应边界无效；结果未确认，请检查审计，勿自动重试。")
        }
        let line = Data(output[..<rootEnd.upperBound])
        let meta: Metadata
        do { meta = try JSONDecoder().decode(Metadata.self, from: line) }
        catch { throw UIError(message: "执行响应元数据无效；结果未确认，请检查审计，勿自动重试。") }
        let payload = output[rootEnd.upperBound...]
        let length = Int(meta.body_len)
        guard meta.upstream_status >= 100, meta.upstream_status <= 599,
              meta.headers.allSatisfy({ $0.count == 2 }),
              (length == 0 && payload.isEmpty) || (length > 0 && payload.count == length + 1 && payload.last == 10) else {
            throw UIError(message: "执行响应长度或元数据无效；结果未确认，请检查审计，勿自动重试。")
        }
        return NativeExecuteResult(metadata: meta, metadataText: String(decoding: line, as: UTF8.self), body: Data(payload.prefix(length)))
    }
}

func approvalHandoff(_ details: ApprovalDetails, body: NativeFileSnapshot) throws -> Data {
    // Envelope structure was decoded at the existing read boundary; no UI signature verification.
    let envelope = try JSONSerialization.jsonObject(with: details.data)
    return try JSONSerialization.data(withJSONObject: ["challenge": envelope, "content_type": "application/json", "headers": [], "body": body.text], options: [.prettyPrinted, .sortedKeys])
}

extension CLI {
    func executeApproval(_ details: ApprovalDetails, body: NativeFileSnapshot, grants: [NativeFileSnapshot], capability: String) throws -> NativeExecuteResult {
        guard (1...2).contains(grants.count), !capability.isEmpty, !capability.contains("\n"), !capability.contains("\r") else {
            throw UIError(message: "请选择一或两个签名 grant，并输入单行 capability。")
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rekey-execute-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let redacting = [capability, body.text] + grants.map(\.text)
        let outcome: Result<NativeExecuteResult, Error>
        do {
            let bodyFile = directory.appendingPathComponent("body.json")
            try writePrivateNew(body.data, to: bodyFile)
            let challenge = details.envelope.challenge
            var args = ["execute", "\(challenge.action_id)@\(challenge.action_version)", "--capability", "-", "--body-file", bodyFile.path, "--content-type", "application/json"]
            for (index, grant) in grants.enumerated() {
                let path = directory.appendingPathComponent("grant-\(index).json")
                try writePrivateNew(grant.data, to: path)
                args += ["--approval", path.path]
            }
            let dirfd = open(directory.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW)
            guard dirfd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
            let synced = fsync(dirfd); let syncError = errno; close(dirfd)
            guard synced == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(syncError)) }
            outcome = .success(try NativeExecuteResult.parse(run(args, input: capability + "\n", redacting: redacting)))
        } catch { outcome = .failure(error) }
        do { try FileManager.default.removeItem(at: directory) }
        catch {
            let prior: String
            switch outcome { case .success: prior = "执行已返回；"; case .failure(let failure): prior = failure.localizedDescription + "\n" }
            throw UIError(message: prior + "私有快照清理失败（不表示安全擦除）：" + error.localizedDescription)
        }
        return try outcome.get()
    }
}

func displayDate(_ milliseconds: Int64) -> String {
    Date(timeIntervalSince1970: Double(milliseconds) / 1000).formatted(date: .abbreviated, time: .shortened)
}
