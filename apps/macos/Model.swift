import Foundation
import SwiftUI
import AppKit
import Security
import Darwin

struct UIError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

struct RememberedUnlock: Codable {
    let key: String
    let expiresAt: Date

    static func receipt(_ data: Data) throws -> RememberedUnlock {
        guard let text = String(data: data, encoding: .utf8) else { throw UIError(message: "恢复授权响应无效。") }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 2, let milliseconds = Double(lines[0]), milliseconds.isFinite,
              lines[1].count == 64, lines[1].allSatisfy(\.isHexDigit) else { throw UIError(message: "恢复授权响应无效。") }
        return RememberedUnlock(key: String(lines[1]), expiresAt: Date(timeIntervalSince1970: milliseconds / 1000))
    }
    private static func query(_ directory: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "com.starlight.rekey.remembered-unlock",
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
        attributes[kSecValueData as String] = try JSONEncoder().encode(self)
        attributes[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let code = SecItemAdd(attributes as CFDictionary, nil)
        guard code == errSecSuccess else { throw UIError(message: "已解锁，但无法保存 7 天恢复授权到钥匙串（\(code)）。") }
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

    func revealCredential(_ id: String, proof: String, recovery: Bool) throws -> Data {
        var arguments = ["desktop-reveal", id, "--password-stdin"]
        if recovery { arguments.append("--recovery") }
        return try run(arguments, input: proof + "\n", redacting: [proof])
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
    let peer_security: String
    let lab_enabled: Bool
    var identityLabel: String {
        peer_security == "verified_signature" ? "服务签名已校验" : "L1-dev · 服务签名未校验"
    }
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
    enum Target: Decodable {
        struct TemplatePath: Decodable {
            let path: String
            let params: [String: String]
            let query: [String: String]
        }
        case fixed(String)
        case template(TemplatePath)
        private enum CodingKeys: String, CodingKey { case kind, path, target }
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            switch try fields.decode(String.self, forKey: .kind) {
            case "fixed": self = .fixed(try fields.decode(String.self, forKey: .path))
            case "template": self = .template(try fields.decode(TemplatePath.self, forKey: .target))
            default:
                throw DecodingError.dataCorruptedError(forKey: .kind, in: fields, debugDescription: "Unknown Action target kind")
            }
        }
        var summary: String {
            switch self {
            case .fixed(let path): return path
            case .template(let target):
                let query = target.query.isEmpty ? "" : "；可选查询：" + target.query.keys.sorted().joined(separator: ", ")
                return target.path + "（路径规则" + query + "）"
            }
        }
    }
    let target: Target
    let request_policy: RequestPolicy
    var request_max_bytes: Int { request_policy.max_body_bytes }
    var reference: String { "\(id)@\(version)" }
}
struct ActionList: Decodable { let actions: [FixedAction] }
struct PolicyStatus: Decodable {
    enum Mode: String, Decodable { case personal, team }
    enum Algorithm: String, Decodable { case ed25519, secureEnclaveP256 = "secure-enclave-p256" }
    let vault_id: String
    let mode: Mode?
    let algorithm: Algorithm?
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

struct CredentialReveal {
    let id: String
    let copy: Bool
    let workspace: String
    let revision: UUID
}

struct ProviderTemplateCatalog: Decodable, Sendable {
    struct Declaration: Decodable, Sendable {
        struct BindingRule: Decodable, Sendable {
            let max: Int?
        }
        struct Capability: Decodable, Identifiable, Sendable {
            struct Action: Decodable, Sendable {
                let method: String
                let path: String
            }
            let id: String
            let risk: String
            let default_rule: String?
            let actions: [Action]
            var suggestedRule: String { default_rule ?? (risk == "high" ? "require-approval" : "allow") }
        }
        let template: String
        let display: String
        let origin: String
        let bindings: [String: BindingRule]
        let capabilities: [Capability]
    }
    let template: Declaration
}

extension CLI {
    func templateCatalog(source: Data) throws -> ProviderTemplateCatalog {
        guard let request = String(data: source, encoding: .utf8) else { throw UIError(message: "模板请求编码无效。") }
        return try JSONDecoder().decode(ProviderTemplateCatalog.self, from: run(["template", "catalog", "--stdin-request"], input: request + "\n"))
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
    var templateRequest: Data?
    var personalTrustVaultID: UUID?
    var reveal: CredentialReveal?
    var unregisterBackgroundService = false
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
    @Published var showTemplate = false
    @Published private(set) var nativeFlowRevision = UUID()
    @Published var audit: AuditPage?
    @Published var desktopToken: String?
    @Published var copiedCredential: String?
    @Published var visibleSecret: String?
    private var desktopExpiry = Date.distantPast
    private var resumeAttempted = false
    @Published var selectedCredential: String? { didSet {
        visibleSecret = nil; copiedCredential = nil
        if oldValue != selectedCredential { nativeFlowRevision = UUID() }
    } }
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
        CLI(binary: Bundle.main.resourceURL!.appendingPathComponent("bin/rekey"), stateDirectory: stateDirectory, adminSessionFile: oidcSessionFile)
    }
    var unlocked: Bool { status?.unlocked == true }
    var serviceIsRunning: Bool { status != nil || (launchedServiceDirectory == stateDirectory && launchedService?.isRunning == true) }
    var selected: Credential? { credentials.first { $0.id == selectedCredential } }
    init(stateDirectory: String? = nil) {
        self.stateDirectory = stateDirectory ?? (UserDefaults.standard.string(forKey: "stateDirectory") ?? NSHomeDirectory() + "/.rekey")
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
        revision == oidcFlowRevision && workspace == stateDirectory && unlocked
    }
    func clearNativeFlow() {
        nativeFlowRevision = UUID(); showPolicyDraft = false; approvalDetails = nil
        showTemplate = false
        if operation?.reveal != nil { operation = nil }
    }
    func acceptsNativeCompletion(_ revision: UUID, workspace: String) -> Bool {
        revision == nativeFlowRevision && workspace == stateDirectory && unlocked
    }
    var needsSetup: Bool {
        !FileManager.default.fileExists(atPath: stateDirectory + "/vault.sqlite3")
    }
    func beginSetup() {
        let startup = managesBackgroundService ? "同时启用本用户登录启动并启动服务。" : "随后启动服务。"
        operation = Operation(title: "创建保险库", detail: "设置并确认密码后，应用会创建保险库，" + startup + "请保存随后显示的恢复密钥。", arguments: ["init"], confirmSecret: true, sensitiveResult: true, recoveryAllowed: false)
    }
    func beginPersonalPolicySetup() {
        guard unlocked, let policy, policy.mode == .personal, !policy.trust_installed,
              let vaultID = UUID(uuidString: policy.vault_id) else {
            error = "请先解锁尚未安装信任根的个人保险库。"; return
        }
        var request = Operation(title: "创建个人策略信任根", detail: "在此设备的 Secure Enclave 中创建策略签名密钥。以后签名需要系统在场认证；此私钥不会随备份转移到其他设备。", arguments: ["policy", "trust", "install", "--stdin-request"], proofFlag: "--step-up-stdin", targetDirectory: stateDirectory)
        request.personalTrustVaultID = vaultID
        operation = request
    }
    var managesBackgroundService: Bool {
        BackgroundService.isInstalledApplication && BackgroundService.usesDefaultState(stateDirectory) && oidcProfileFile == nil
    }
    var serviceStartTitle: String { managesBackgroundService ? "启用登录启动并启动服务" : "启动服务" }
    var backgroundServiceDescription: String? { managesBackgroundService ? BackgroundService.statusDescription : nil }
    var backgroundServiceNeedsApproval: Bool { managesBackgroundService && BackgroundService.requiresApproval }
    var desktopReady: Bool { desktopToken != nil && Date() < desktopExpiry && unlocked }
    func requestDesktopLogin() {
        operation = Operation(title: "解锁管理会话", detail: "验证后，7 天内可连续保存密钥。每次查看或复制密钥仍需单独验证。手动锁定会取消管理授权。", arguments: ["unlock"])
    }
    func addAPIKey(label: String, secret: String) async -> Bool {
        guard desktopReady, let token = desktopToken else { desktopToken = nil; error = "管理会话已过期，请关闭窗口并重新解锁。"; return false }
        guard !busy else { return false }
        busy = true; error = nil
        let client = cli
        do {
            _ = try await Task.detached { try client.run(["desktop-add", label], input: token + "\n" + secret + "\n") }.value
            busy = false; await refresh(); return true
        } catch { rejectDesktopSession(error); self.error = error.localizedDescription; busy = false; return false }
    }
    func requestRevealCredential(_ id: String, copy: Bool) {
        guard !busy, unlocked, selectedCredential == id else { return }
        visibleSecret = nil; copiedCredential = nil
        let detail = copy ? "请验证本次复制。密钥会写入系统剪贴板，并在 30 秒后清除本应用的那次写入。" : "请验证本次查看。切换条目、锁定或离开窗口后会隐藏密钥。"
        operation = Operation(title: copy ? "复制密钥" : "显示密钥", detail: detail, arguments: ["desktop-reveal", id], reveal: CredentialReveal(id: id, copy: copy, workspace: stateDirectory, revision: nativeFlowRevision))
    }
    func requestShutdown() {
        guard !busy, status != nil else { return }
        operation = Operation(title: "停止服务", detail: "请输入当前密码或恢复密钥。正在执行的操作会按服务的退出规则收尾。登录启动设置保持不变。", arguments: ["shutdown"], targetDirectory: stateDirectory)
    }
    func requestDisableBackgroundService() {
        guard !busy, status != nil, managesBackgroundService else { return }
        operation = Operation(title: "停止并停用登录启动", detail: "验证后先让服务收尾停止，再取消本用户的登录启动。保险库文件会保留。", arguments: ["shutdown"], targetDirectory: stateDirectory, unregisterBackgroundService: true)
    }
    private func acceptsCredentialReveal(_ request: CredentialReveal) -> Bool {
        acceptsNativeCompletion(request.revision, workspace: request.workspace) && selectedCredential == request.id
    }
    private func performReveal(_ request: CredentialReveal, proof: String, recovery: Bool) async {
        guard !busy, acceptsCredentialReveal(request), NSApp.isActive else { return }
        busy = true; error = nil
        defer { busy = false }
        let client = cli
        let outcome = await Task.detached { Result { try client.revealCredential(request.id, proof: proof, recovery: recovery) } }.value
        _ = finishCredentialReveal(outcome, request: request, active: NSApp.isActive)
    }
    @discardableResult
    func finishCredentialReveal(_ outcome: Result<Data, Error>, request: CredentialReveal, active: Bool) -> Bool {
        guard acceptsCredentialReveal(request), active else { return false }
        do {
            let data = try outcome.get()
            guard let text = String(data: data, encoding: .utf8) else { throw UIError(message: "此凭证不是可显示的 UTF-8 文本。") }
            if request.copy {
                let board = NSPasteboard.general
                board.clearContents()
                guard board.setString(text, forType: .string) else { throw UIError(message: "写入剪贴板失败。") }
                copiedCredential = request.id
                let revision = board.changeCount
                DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                    if board.changeCount == revision { board.clearContents() }
                }
            } else { visibleSecret = text }
        } catch { visibleSecret = nil; self.error = error.localizedDescription }
        return true
    }
    func rejectDesktopSession(_ error: Error) {
        let message = error.localizedDescription
        if message.contains("INVALID_UNLOCK_CREDENTIAL") || message.contains("LOCKED") || message.contains("FAULTED") {
            desktopToken = nil; desktopExpiry = .distantPast; visibleSecret = nil; copiedCredential = nil
        }
    }
    func clearCache() {
        clearNativeFlow(); clearOIDCLogin()
        oidcSessionFile = nil; oidcIdentity = nil
        desktopToken = nil; visibleSecret = nil; copiedCredential = nil
        credentials = []; actions = []; approvals = []; approvalDetails = nil; policy = nil; audit = nil; selectedCredential = nil
    }
    func changeDirectory(_ path: String) {
        guard !busy, !oidcBusy else { return }
        resumeAttempted = false
        stateDirectory = path
        UserDefaults.standard.set(path, forKey: "stateDirectory")
        status = nil; clearCache(); result = nil; error = nil
        Task { await refresh() }
    }
    func refresh(nextAuditPage: Bool = false, passive: Bool = false) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        let client = cli
        var resumedAccess = false
        do {
            let current = try await Task.detached { try client.decode(ServiceStatus.self, passive ? ["status", "--passive"] : ["status"]) }.value
            if status?.unlocked == true && !current.unlocked { resumeAttempted = false }
            status = current; connectionError = nil
            if Date() >= desktopExpiry { desktopToken = nil; visibleSecret = nil; copiedCredential = nil }
            if !current.unlocked { clearCache() }
            if !desktopReady && !resumeAttempted {
                resumeAttempted = true
                do {
                    if let remembered = try RememberedUnlock.load(stateDirectory) {
                        let data = try await Task.detached { try client.run(["desktop-resume"], input: remembered.key + "\n") }.value
                        let resumed = try RememberedUnlock.receipt(data)
                        desktopToken = resumed.key; desktopExpiry = resumed.expiresAt
                        resumedAccess = true
                        self.error = nil
                        status = try await Task.detached { try client.decode(ServiceStatus.self, ["status", "--passive"]) }.value
                    }
                } catch {
                    desktopToken = nil; desktopExpiry = .distantPast
                    let retryable = error.localizedDescription.contains("AUTHORITY_BUSY") || error.localizedDescription.contains("DRAINING") || error.localizedDescription.contains("IPC_UNAVAILABLE")
                    if retryable { resumeAttempted = false }
                    self.error = (retryable ? "服务暂时忙碌，稍后会自动重试。\n" : "自动解锁失败，请重新输入保险库密码。\n") + error.localizedDescription
                    if error.localizedDescription.contains("INVALID_UNLOCK_CREDENTIAL") {
                        do { try RememberedUnlock.forget(stateDirectory) }
                        catch { self.error = error.localizedDescription }
                    }
                }
            }
        } catch {
            status = nil; clearCache(); resumeAttempted = false; connectionError = error.localizedDescription
            return
        }
        if passive && !resumedAccess { return }
        do {
            if unlocked {
                let lists = try await Task.detached {
                    (try client.decode(CredentialList.self, ["credential", "list"]),
                     try client.decode(ActionList.self, ["action", "list"]))
                }.value
                credentials = lists.0.credentials; actions = lists.1.actions
                if !credentials.contains(where: { $0.id == selectedCredential }) { selectedCredential = credentials.first?.id }
            }
            switch page {
            case .policy:
                policy = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
            case .approvals where unlocked:
                approvals = try await Task.detached { try client.decode(PendingList.self, ["approval", "pending"]) }.value.challenges
            case .audit:
                var args = ["audit", "list", "--limit", "50"]
                if !auditOutcome.isEmpty { args += ["--outcome", auditOutcome] }
                if nextAuditPage, let prior = audit, let cursor = prior.next_before_sequence {
                    args += ["--snapshot-max-sequence", String(prior.snapshot_max_sequence), "--before-sequence", String(cursor)]
                }
                let command = args
                audit = try await Task.detached { try client.decode(AuditPage.self, command) }.value
            default: break
            }
        } catch {
            clearCache()
            self.error = error.localizedDescription
        }
    }
    func perform(_ op: Operation, proof: String = "", secret: String = "", recovery: Bool = false) async {
        if let request = op.reveal {
            await performReveal(request, proof: proof, recovery: recovery)
            return
        }
        guard !busy else {
            if op.temporaryFile != nil || op.templateRequest != nil || op.personalTrustVaultID != nil {
                var message = "当前操作尚未完成，本次请求未提交，请稍后重试。"
                if let file = op.temporaryFile {
                    do { try FileManager.default.removeItem(at: file) }
                    catch { message += "\n无法删除临时操作定义：\(file.path)" }
                }
                error = message
            }
            return
        }
        busy = true; error = nil
        let client = CLI(binary: cli.binary, stateDirectory: op.targetDirectory ?? stateDirectory, adminSessionFile: oidcSessionFile)
        let desktopLogin = op.arguments == ["unlock"]
        var args = desktopLogin ? ["desktop-login"] : op.arguments
        var input = ""
        if op.proof {
            if !desktopLogin { args.append(op.newSecret ? "--stdin-secrets" : op.proofFlag) }
            input = proof + "\n"
            if op.newSecret { input += secret + "\n" }
            if recovery && op.recoveryAllowed { args.append("--recovery") }
        }
        if let request = op.templateRequest {
            guard let json = String(data: request, encoding: .utf8) else {
                busy = false; error = "模板请求编码无效。"; return
            }
            input += json + "\n"
        }
        let command = args
        var body = input
        var operationError: String?
        do {
            if let vaultID = op.personalTrustVaultID {
                let current = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
                guard current.mode == .personal, !current.trust_installed,
                      UUID(uuidString: current.vault_id) == vaultID else {
                    throw UIError(message: "保险库或信任根状态已改变，请重新检查后操作。")
                }
                let publicKey = try await Task.detached { try PolicySigning.createOrLoadPublicKey(vaultID: vaultID) }.value
                let trust: [String: Any] = ["format_version": 1, "signer_id": vaultID.uuidString.lowercased(), "algorithm": "secure-enclave-p256", "public_key": publicKey.map { String(format: "%02x", $0) }.joined()]
                body += String(decoding: try JSONSerialization.data(withJSONObject: trust, options: [.sortedKeys]), as: UTF8.self) + "\n"
            }
            let requestInput = body
            let data = try await Task.detached { try client.run(command, input: requestInput) }.value
            guard let output = String(data: data, encoding: .utf8) else { throw UIError(message: "命令返回了无法解码的内容，操作结果需重新确认。") }
            if desktopLogin {
                guard output.count == 64 && output.allSatisfy(\.isHexDigit) else { throw UIError(message: "管理会话响应无效。") }
                desktopToken = output; desktopExpiry = Date().addingTimeInterval(7 * 24 * 60 * 60)
                if oidcProfileFile == nil || oidcSessionFile != nil {
                    let rememberArgs = recovery ? ["desktop-remember", "--recovery"] : ["desktop-remember"]
                    let rememberedData = try await Task.detached { try client.run(rememberArgs, input: requestInput) }.value
                    let remembered = try RememberedUnlock.receipt(rememberedData)
                    try remembered.save(stateDirectory)
                }
                resumeAttempted = true
            } else {
                if op.unregisterBackgroundService {
                    // Reached only after this operation's fresh-proof SHUTDOWN succeeded.
                    do { try await BackgroundService.unregisterAfterAuthorizedShutdown() }
                    catch { throw UIError(message: "服务已停止，但未能停用登录启动：" + error.localizedDescription) }
                }
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
        else if op.arguments.first == "init" { startService() }
    }
    func startRememberedService() {
        // An installed app never registers or starts its managed job while refreshing.
        guard !BackgroundService.isInstalledApplication, status == nil && !needsSetup else { return }
        do { if try RememberedUnlock.load(stateDirectory) != nil { startService() } }
        catch { self.error = error.localizedDescription }
    }
    func startService() {
        guard !busy else { return }
        if BackgroundService.isInstalledApplication {
            guard managesBackgroundService else {
                error = "登录启动仅支持默认保险库目录。自定义目录或机构配置请先通过 CLI 启动服务，再在应用中连接。"; return
            }
            guard !needsSetup else { beginSetup(); return }
            busy = true; error = nil
            Task {
                do {
                    try await BackgroundService.start()
                    busy = false
                    await refresh()
                    if backgroundServiceNeedsApproval { error = BackgroundService.statusDescription }
                } catch { busy = false; self.error = error.localizedDescription }
            }
            return
        }
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
        clearNativeFlow()
        resumeAttempted = true
        var keychainError: String?
        do { try RememberedUnlock.forget(stateDirectory) } catch { keychainError = error.localizedDescription }
        await perform(Operation(title: "锁定", detail: "", arguments: ["lock"], proof: false))
        result = nil
        if let keychainError { error = keychainError }
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
