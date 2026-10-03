import Foundation
import SwiftUI
import AppKit
import Security
import Darwin

struct UIError: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

// desktop-resume returns an A1 session token, never the presence key K.
struct DesktopReceipt {
    let token: String
    let expiresAt: Date
    static func parse(_ data: Data) throws -> DesktopReceipt {
        guard let text = String(data: data, encoding: .utf8) else { throw UIError(message: "管理会话响应无效。") }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 2, let expiry = Int64(lines[0]), expiry > 0 else { throw UIError(message: "管理会话响应无效。") }
        return DesktopReceipt(token: try PresenceKey.validated(String(lines[1])), expiresAt: Date(timeIntervalSince1970: Double(expiry) / 1000))
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

    func revealCredential(_ id: String, proof: String, recovery: Bool, presence: Bool = false) throws -> Data {
        var arguments = ["desktop-reveal", id, "--password-stdin"]
        if presence { arguments.append("--presence") }
        else if recovery { arguments.append("--recovery") }
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
    let version: UInt64?
    let signer_id: String?
    let expires_at_ms: Int64?
}

// A review owns the daemon's exact signing bytes. JSON below is only decoded
// for display/identity checks; it is never recanonicalized by the App.
struct PersonalPolicyDraft: Sendable {
    struct Metadata: Decodable, Sendable {
        let vault_id: UUID
        let trust_sha256: String
        let public_key: String
        let base_version: UInt64?
        let next_version: UInt64
        let policy_sha256: String
    }
    private struct Response: Decodable { let metadata: Metadata; let sign_bytes: String }
    private struct Envelope: Decodable {
        struct Snapshot: Decodable { let version: UInt64; let expires_at_ms: Int64 }
        let snapshot: Snapshot
        let signer_id: String
    }
    private static let prefix = Data("RKPOLICY\0\u{01}".utf8)
    let metadata: Metadata
    let signBytes: Data
    let publicKey: Data
    let changesText: String
    let actionsText: String
    let principal: UUID
    let expiresAtMs: Int64
    let workspace: String
    let revision: UUID

    init(response data: Data, principal: UUID, expiresAtMs: Int64, workspace: String, revision: UUID) throws {
        let response = try JSONDecoder().decode(Response.self, from: data)
        let bytes = Data(response.sign_bytes.utf8)
        guard bytes.count <= 65536, bytes.starts(with: Self.prefix),
              bytes.last == UInt8(ascii: "}"),
              !bytes.contains(10), !bytes.contains(13),
              let object = try JSONSerialization.jsonObject(with: Data(bytes.dropFirst(Self.prefix.count))) as? [String: Any],
              Set(object.keys) == ["format_version", "signer_id", "snapshot"],
              object["format_version"] as? Int == 1,
              let outer = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              let metadata = outer["metadata"] as? [String: Any],
              let changes = metadata["changes"] as? [[String: Any]],
              let actions = metadata["actions"] as? [[String: Any]],
              Self.isLowerHex(response.metadata.trust_sha256, count: 64),
              Self.isLowerHex(response.metadata.policy_sha256, count: 64),
              Self.isLowerHex(response.metadata.public_key, count: 130),
              response.metadata.public_key.hasPrefix("04") else {
            throw UIError(message: "个人策略草稿响应无效，请重新生成。")
        }
        let envelope = try JSONDecoder().decode(Envelope.self, from: Data(bytes.dropFirst(Self.prefix.count)))
        guard envelope.snapshot.version == response.metadata.next_version,
              envelope.snapshot.expires_at_ms == expiresAtMs else {
            throw UIError(message: "策略草稿的版本或有效期不一致。")
        }
        self.metadata = response.metadata; signBytes = bytes
        let hex = Array(response.metadata.public_key.utf8)
        publicKey = Data(stride(from: 0, to: hex.count, by: 2).map {
            UInt8(String(decoding: hex[$0..<$0 + 2], as: UTF8.self), radix: 16)!
        })
        changesText = String(decoding: try JSONSerialization.data(withJSONObject: changes, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
        actionsText = String(decoding: try JSONSerialization.data(withJSONObject: actions, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
        self.principal = principal; self.expiresAtMs = expiresAtMs
        self.workspace = workspace; self.revision = revision
    }

    func validate(current: PolicyStatus, now: Date = Date()) throws {
        guard current.mode == .personal, current.algorithm == .secureEnclaveP256,
              current.trust_installed, UUID(uuidString: current.vault_id) == metadata.vault_id,
              current.trust_sha256 == metadata.trust_sha256, current.version == metadata.base_version,
              Double(expiresAtMs) > now.timeIntervalSince1970 * 1000 else {
            throw UIError(message: "保险库、模式、信任根、策略版本或有效期已改变，请重新生成并审阅草稿。")
        }
    }

    func signedBundle(signature: String) throws -> String {
        guard !signature.isEmpty, signature.utf8.count <= 96,
              signature.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 || $0 == 95 }) else {
            throw UIError(message: "策略签名编码无效，未提交激活。")
        }
        var bundle = Data(signBytes.dropFirst(Self.prefix.count).dropLast())
        bundle.append(Data(",\"signature\":\"\(signature)\"}".utf8))
        guard bundle.count <= 65536, let text = String(data: bundle, encoding: .utf8) else {
            throw UIError(message: "策略签名信封超过上限或编码无效。")
        }
        return text
    }

    private static func isLowerHex(_ text: String, count: Int) -> Bool {
        text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

extension CLI {
    func personalPolicyDraft(principal: UUID, expiresAtMs: Int64, actions: [String], revision: UUID) throws -> PersonalPolicyDraft {
        var args = ["policy", "draft", "--principal", principal.uuidString.lowercased(), "--expires-at-ms", String(expiresAtMs)]
        for action in actions.sorted() { args += ["--action", action] }
        return try PersonalPolicyDraft(response: run(args), principal: principal, expiresAtMs: expiresAtMs, workspace: stateDirectory, revision: revision)
    }

    func activatePersonalPolicy(_ draft: PersonalPolicyDraft, signature: String, proof: String, recovery: Bool, presence: Bool = false) throws -> Data {
        guard !proof.isEmpty, !proof.contains("\n"), !proof.contains("\r"), stateDirectory == draft.workspace else {
            throw UIError(message: "当前验证信息或工作区无效，未提交激活。")
        }
        var args = ["policy", "activate", "--stdin-request", "--expected-vault-id", draft.metadata.vault_id.uuidString.lowercased(),
                    "--expected-trust-sha256", draft.metadata.trust_sha256, "--step-up-stdin"]
        if presence { args.append("--presence") }
        else if recovery { args.append("--recovery") }
        let bundle = try draft.signedBundle(signature: signature)
        return try run(args, input: proof + "\n" + bundle + "\n", redacting: [proof, signature, bundle])
    }
}
enum Approver: Decodable {
    case localPresence
    case ed25519(keys: [String], threshold: UInt8)
    private enum CodingKeys: String, CodingKey { case kind, keys, threshold }
    init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        switch try fields.decode(String.self, forKey: .kind) {
        case "local-presence": self = .localPresence
        case "ed25519": self = .ed25519(keys: try fields.decode([String].self, forKey: .keys),
                                        threshold: try fields.decode(UInt8.self, forKey: .threshold))
        default: throw DecodingError.dataCorruptedError(forKey: .kind, in: fields, debugDescription: "Unsupported approver")
        }
    }
    var summary: String {
        switch self {
        case .localPresence: return "本机系统认证"
        case .ed25519(_, let threshold): return "外部签名 · \(threshold) 人"
        }
    }
}
struct PendingApproval: Decodable, Identifiable {
    let approval_request_id: String
    let action_id: String
    let action_version: Int
    let session_id: String
    let max_expires_at_ms: Int64
    let parameter_sha256: String
    let approver: Approver
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
    let approver: Approver
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
    var presenceAllowed: Bool {
        guard proof else { return false }
        let command = arguments.prefix(2).joined(separator: " ")
        if ["backup", "shutdown"].contains(arguments.first ?? "") { return true }
        if arguments.first == "desktop-reveal" { return true }
        if ["policy trust install", "audit retention set"].contains(arguments.prefix(3).joined(separator: " ")) { return true }
        return ["credential add", "credential rotate", "credential revoke", "credential add-github-app", "credential rotate-github-app",
                "credential add-vault-kv", "credential rotate-vault-kv", "credential add-vault-dynamic", "credential rotate-vault-dynamic",
                "credential add-keycloak", "credential rotate-keycloak", "action create", "action update", "action disable",
                "template install", "session create", "session revoke", "policy activate",
                "password change", "recovery rotate", "key rotate-dek", "audit prune"].contains(command)
    }
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
    @Published private(set) var personalPolicySigning = false
    @Published private(set) var presenceAuthenticating = false
    @Published var audit: AuditPage?
    @Published var desktopToken: String?
    @Published var copiedCredential: String?
    @Published var visibleSecret: String?
    private var desktopExpiry = Date.distantPast
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
        if operation?.reveal != nil || presenceAuthenticating { operation = nil }
    }
    func nativeFlowBecameInactive() {
        visibleSecret = nil
        // A system authentication dialog may deactivate the App. Only the
        // explicit signing interval survives that event; lock/path changes do not.
        if !personalPolicySigning && !presenceAuthenticating { clearNativeFlow() }
    }
    func acceptsNativeCompletion(_ revision: UUID, workspace: String) -> Bool {
        revision == nativeFlowRevision && workspace == stateDirectory && unlocked
    }
    func acceptsPresenceCompletion(_ revision: UUID, workspace: String, allowLocked: Bool = false) -> Bool {
        revision == nativeFlowRevision && workspace == stateDirectory &&
            (unlocked || (allowLocked && status?.state == "locked"))
    }
    func readPresenceProof(client: CLI, revision: UUID, allowLocked: Bool = false,
                           read: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async throws -> (String, PolicyStatus) {
        guard acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: allowLocked), !Task.isCancelled else {
            throw UIError(message: "系统认证上下文已失效，未提交操作。")
        }
        let current = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
        guard let vaultID = UUID(uuidString: current.vault_id), allowLocked || current.mode != nil,
              acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: allowLocked), !Task.isCancelled else {
            throw UIError(message: "保险库状态已改变，未请求系统认证。")
        }
        presenceAuthenticating = true
        defer { presenceAuthenticating = false }
        let key = try await Task.detached { try PresenceKey.validated(read(vaultID)) }.value
        presenceAuthenticating = false
        guard acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: allowLocked), !Task.isCancelled else {
            throw UIError(message: "系统认证等待期间上下文已改变，结果已丢弃。")
        }
        let latest = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
        guard UUID(uuidString: latest.vault_id) == vaultID, latest.mode == current.mode,
              acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: allowLocked), !Task.isCancelled else {
            throw UIError(message: "保险库状态已改变，系统认证结果未采用。")
        }
        return (key, latest)
    }
    func unlockWithPresence(revision: UUID, client injectedClient: CLI? = nil,
                            read: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async {
        guard !busy else { return }
        busy = true; error = nil
        let client = injectedClient ?? cli
        do {
            let (key, _) = try await readPresenceProof(client: client, revision: revision, allowLocked: true, read: read)
            let data = try await Task.detached { try client.run(["desktop-resume"], input: key + "\n", redacting: [key]) }.value
            guard acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: true), !Task.isCancelled else {
                busy = false; return
            }
            let receipt = try DesktopReceipt.parse(data)
            desktopToken = receipt.token; desktopExpiry = receipt.expiresAt
        } catch {
            if revision == nativeFlowRevision && client.stateDirectory == stateDirectory { self.error = error.localizedDescription }
        }
        busy = false
        if injectedClient == nil { await refresh() }
    }
    func personalPolicyDraft(principal: UUID, expiresAtMs: Int64, actions: [String]) async throws -> PersonalPolicyDraft {
        guard !busy, unlocked, policy?.mode == .personal else { throw UIError(message: "请先解锁个人保险库并等待当前操作完成。") }
        busy = true
        defer { busy = false }
        let client = cli, revision = nativeFlowRevision
        let draft = try await Task.detached { try client.personalPolicyDraft(principal: principal, expiresAtMs: expiresAtMs, actions: actions, revision: revision) }.value
        guard acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else {
            throw UIError(message: "草稿读取期间上下文已改变，请重新生成。")
        }
        return draft
    }
    func activatePersonalPolicy(_ draft: PersonalPolicyDraft, proof: String, recovery: Bool, presence: Bool = false,
                                client injectedClient: CLI? = nil,
                                readPresence: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) },
                                sign: @escaping @Sendable (UUID, Data, Data) throws -> String = { try PolicySigning.sign(vaultID: $0, message: $1, expectedPublicKey: $2) }) async throws {
        guard !busy, acceptsNativeCompletion(draft.revision, workspace: draft.workspace),
              presence || (!proof.isEmpty && !proof.contains("\n") && !proof.contains("\r")) else {
            throw UIError(message: "草稿上下文或验证信息已失效，未提交激活。")
        }
        busy = true
        defer { personalPolicySigning = false; busy = false }
        let client = injectedClient ?? cli
        guard client.stateDirectory == draft.workspace else { throw UIError(message: "草稿工作区已改变。") }
        let current: PolicyStatus
        let operationProof: String
        if presence {
            (operationProof, current) = try await readPresenceProof(client: client, revision: draft.revision, read: readPresence)
        } else {
            current = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
            operationProof = proof
        }
        try draft.validate(current: current)
        guard acceptsNativeCompletion(draft.revision, workspace: draft.workspace), !Task.isCancelled else {
            throw UIError(message: "草稿上下文已失效，未请求签名。")
        }
        personalPolicySigning = true
        let signature = try await Task.detached { try sign(draft.metadata.vault_id, draft.signBytes, draft.publicKey) }.value
        personalPolicySigning = false
        guard acceptsNativeCompletion(draft.revision, workspace: draft.workspace), !Task.isCancelled else {
            throw UIError(message: "签名等待期间上下文已改变，结果已丢弃，未激活。")
        }
        let latest = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
        try draft.validate(current: latest)
        guard acceptsNativeCompletion(draft.revision, workspace: draft.workspace), !Task.isCancelled else {
            throw UIError(message: "签名完成后上下文已改变，未激活。")
        }
        _ = try await Task.detached { try client.activatePersonalPolicy(draft, signature: signature, proof: operationProof, recovery: recovery, presence: presence) }.value
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
    private func performReveal(_ request: CredentialReveal, proof: String, recovery: Bool, presence: Bool = false,
                               readPresence: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async {
        guard !busy, acceptsCredentialReveal(request), NSApp.isActive else { return }
        busy = true; error = nil
        defer { busy = false }
        let client = cli
        let outcome: Result<Data, Error>
        do {
            let operationProof: String
            if presence { (operationProof, _) = try await readPresenceProof(client: client, revision: request.revision, read: readPresence) }
            else { operationProof = proof }
            guard acceptsCredentialReveal(request), !Task.isCancelled else { return }
            outcome = await Task.detached { Result { try client.revealCredential(request.id, proof: operationProof, recovery: recovery, presence: presence) } }.value
        } catch { outcome = .failure(error) }
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
        stateDirectory = path
        UserDefaults.standard.set(path, forKey: "stateDirectory")
        status = nil; clearCache(); result = nil; error = nil
        Task { await refresh() }
    }
    func refresh(nextAuditPage: Bool = false, passive: Bool = false, client injectedClient: CLI? = nil) async {
        guard !busy else { return }
        busy = true
        defer { busy = false }
        let client = injectedClient ?? cli
        do {
            let current = try await Task.detached { try client.decode(ServiceStatus.self, passive ? ["status", "--passive"] : ["status"]) }.value
            status = current; connectionError = nil
            if Date() >= desktopExpiry { desktopToken = nil; visibleSecret = nil; copiedCredential = nil }
            if !current.unlocked { clearCache() }

        } catch {
            status = nil; clearCache(); connectionError = error.localizedDescription
            return
        }
        if passive { return }
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
    func perform(_ op: Operation, proof: String = "", secret: String = "", recovery: Bool = false,
                 presence: Bool = false, rememberPresence: Bool = false, presenceRevision: UUID? = nil,
                 client injectedClient: CLI? = nil,
                 readPresence: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async {
        if let request = op.reveal {
            await performReveal(request, proof: proof, recovery: recovery, presence: presence, readPresence: readPresence)
            return
        }
        guard !busy else {
            if presence || op.temporaryFile != nil || op.templateRequest != nil || op.personalTrustVaultID != nil {
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
        let client = injectedClient ?? CLI(binary: cli.binary, stateDirectory: op.targetDirectory ?? stateDirectory, adminSessionFile: oidcSessionFile)
        let desktopLogin = op.arguments == ["unlock"]
        let revision = presenceRevision ?? nativeFlowRevision
        let guarded = presence || rememberPresence
        var operationError: String?
        do {
            guard !presence || op.presenceAllowed,
                  !rememberPresence || desktopLogin,
                  !guarded || (presenceRevision == nativeFlowRevision && client.stateDirectory == stateDirectory) else {
                throw UIError(message: "此操作不支持系统认证，或操作上下文已失效，未提交。")
            }
            let operationProof: String
            if presence { (operationProof, _) = try await readPresenceProof(client: client, revision: revision, read: readPresence) }
            else { operationProof = proof }
            var args = desktopLogin ? ["desktop-login"] : op.arguments
            var body = ""
            if op.proof {
                if !desktopLogin { args.append(op.newSecret ? "--stdin-secrets" : op.proofFlag) }
                body = operationProof + "\n"
                if op.newSecret { body += secret + "\n" }
                if presence { args.append("--presence") }
                else if recovery && op.recoveryAllowed { args.append("--recovery") }
            }
            if let request = op.templateRequest {
                guard let json = String(data: request, encoding: .utf8) else { throw UIError(message: "模板请求编码无效。") }
                body += json + "\n"
            }
            var issuingVault: UUID?
            if rememberPresence {
                let current = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
                guard let vaultID = UUID(uuidString: current.vault_id) else { throw UIError(message: "保险库身份无效。") }
                issuingVault = vaultID
            }
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
            guard !guarded || (acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: desktopLogin) && !Task.isCancelled) else {
                throw UIError(message: "系统认证操作上下文已改变，未提交。")
            }
            let command = args, requestInput = body
            let data = try await Task.detached { try client.run(command, input: requestInput, redacting: [operationProof, secret]) }.value
            guard !guarded || acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: desktopLogin) else {
                throw UIError(message: "操作上下文已改变，结果未展示；请检查审计，不要自动重试。")
            }
            guard let output = String(data: data, encoding: .utf8) else { throw UIError(message: "命令返回了无法解码的内容，操作结果需重新确认。") }
            if desktopLogin {
                desktopToken = try PresenceKey.validated(output)
                desktopExpiry = Date().addingTimeInterval(7 * 24 * 60 * 60)
                if let vaultID = issuingVault {
                    let current = try await Task.detached { try client.decode(PolicyStatus.self, ["policy", "status"]) }.value
                    guard UUID(uuidString: current.vault_id) == vaultID, current.mode != nil,
                          acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: true), !Task.isCancelled else {
                        throw UIError(message: "保险库或操作上下文已改变，未签发系统认证授权。")
                    }
                    let rememberArgs = recovery ? ["desktop-remember", "--recovery"] : ["desktop-remember"]
                    let receipt = try await Task.detached { try client.run(rememberArgs, input: requestInput, redacting: [operationProof]) }.value
                    let key = try PresenceKey.issuedKey(receipt)
                    guard acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: true), !Task.isCancelled else {
                        throw UIError(message: "操作上下文已改变，新授权未保存，请重新用密码解锁。")
                    }
                    presenceAuthenticating = true
                    do { try await Task.detached { try PresenceKey.save(key, vaultID: vaultID) }.value }
                    catch { presenceAuthenticating = false; throw error }
                    presenceAuthenticating = false
                }
            } else {
                if op.unregisterBackgroundService {
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
        if let operationError {
            if !guarded || (revision == nativeFlowRevision && client.stateDirectory == stateDirectory) { self.error = operationError }
        }
        busy = false
        if injectedClient == nil { await refresh() }
        if operationError == nil && op.arguments.first == "init" { startService() }
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
        await perform(Operation(title: "锁定", detail: "", arguments: ["lock"], proof: false))
        result = nil
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
