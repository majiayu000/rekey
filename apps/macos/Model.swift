import Foundation
import SwiftUI
import AppKit
import Security
import Darwin
import CryptoKit
import UserNotifications

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
        let output = OutputCapture(limit: arguments.prefix(2) == ["approval", "review"] ? LocalApprovalDetails.stdoutLimit : arguments == ["profile", "list"] ? ProfileList.stdoutLimit : arguments.prefix(2) == ["audit", "list"] ? AuditPage.stdoutLimit : 2 * 1024 * 1024)
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
            let rebuild = Self.rebuildGuidance(stderr: detail).map { "\n" + $0 } ?? ""
            throw UIError(message: "操作未完成（\(process.terminationStatus)）\n\(detail)\(rebuild)")
        }
        return output.data
    }

    static func rebuildGuidance(stderr: String) -> String? {
        guard stderr.hasPrefix("error [UNSUPPORTED_FORMAT_VERSION]:") ||
              stderr.hasPrefix("error [UNSUPPORTED_VAULT_LAYOUT]:") else { return nil }
        return "此版本无法读取这个格式，不提供迁移。请保留原工作区和备份，在左侧“个人工作区”中选择一个新建的空目录，再创建保险库并重新添加密钥。不要覆盖或清空旧目录；本次操作不会自动重建。"
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
    private let limit: Int
    init(limit: Int = 2 * 1024 * 1024) { self.limit = limit }
    func read(_ file: FileHandle, process: Process) {
        do {
            while let chunk = try file.read(upToCount: 16384), !chunk.isEmpty {
                if data.count + chunk.count > limit {
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
    let rollback: RollbackContext?
    var identityLabel: String {
        peer_security == "verified_signature" ? "服务签名已校验" : "服务签名未校验"
    }
    var protectionLabel: String {
        switch state {
        case "locked" where sessions_active == 0: return "L0 · Agent 访问已锁定"
        case "unlocked": return "L1-dev · 已确认的保护下限"
        default: return "保护状态未确认 · 禁止执行"
        }
    }
    var protectionDetail: String {
        "L0 表示只保存凭据。L1-dev 表示 Agent 接口不返回密钥；当前构建的钥匙串访问和同用户内存隔离仍待设备验收，服务签名通过也不宣称 L1。L2 还需要经验证的 L1 与实际启用的隔离、拒绝其它网络访问；Profile 中的隔离声明不能单独证明 L2。"
    }
    var unlocked: Bool { state == "unlocked" }
    var label: String {
        switch state {
        case "unlocked": return "已解锁"
        case "locked": return "已锁定"
        case "faulted": return "服务故障"
        case "rollback-suspected": return "疑似回滚 · 需明确确认"
        default: return "状态：" + state
        }
    }
}
extension ServiceStatus {
    private enum CodingKeys: String, CodingKey { case state, format_version, runtime_version, sessions_active, peer_security, lab_enabled, rollback }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = try c.decode(String.self, forKey: .state)
        format_version = try c.decode(Int.self, forKey: .format_version)
        runtime_version = try c.decode(String.self, forKey: .runtime_version)
        sessions_active = try c.decode(Int.self, forKey: .sessions_active)
        peer_security = try c.decode(String.self, forKey: .peer_security)
        lab_enabled = try c.decode(Bool.self, forKey: .lab_enabled)
        rollback = try c.decode(RollbackContext?.self, forKey: .rollback)
    }
}
struct RollbackContext: Codable, Equatable, Sendable {
    let vault_id: UUID
    let source_generation: UInt64
    let high_water: UInt64?
    let history_missing: Bool
    var summary: String {
        "保险库：" + vault_id.uuidString.lowercased() + "\n源代数：" + String(source_generation) +
        "\n已知历史上限：" + (high_water.map(String.init) ?? "无已知历史") +
        "\n历史是否缺失：" + (history_missing ? "是 · 历史不可用，不能声称找回丢失历史" : "否")
    }
    func encodedArgument() throws -> String { String(decoding: try JSONEncoder().encode(self), as: UTF8.self) }
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(vault_id.uuidString.lowercased(), forKey: .vault_id)
        try c.encode(source_generation, forKey: .source_generation)
        try c.encode(high_water, forKey: .high_water)
        try c.encode(history_missing, forKey: .history_missing)
    }
}
extension RollbackContext {
    private enum CodingKeys: String, CodingKey { case vault_id, source_generation, high_water, history_missing }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        vault_id = try c.decode(UUID.self, forKey: .vault_id)
        source_generation = try c.decode(UInt64.self, forKey: .source_generation)
        high_water = try c.decode(UInt64?.self, forKey: .high_water)
        history_missing = try c.decode(Bool.self, forKey: .history_missing)
    }
}
struct SnapshotCut: Decodable, Sendable {
    struct Policy: Decodable, Sendable { let version: UInt64; let bundle_sha256: String }
    let audit_sequence: UInt64
    let policy: Policy?
    private enum CodingKeys: String, CodingKey { case audit_sequence, policy }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        audit_sequence = try c.decode(UInt64.self, forKey: .audit_sequence)
        policy = try c.decode(Policy?.self, forKey: .policy)
    }
}
struct BackupReceipt: Decodable, Sendable {
    let vault_id: UUID; let format_version: UInt32; let created_at_ms: Int64
    let sha256_hex: String; let output_path: String; let snapshot_cut: SnapshotCut; let generation: UInt64
}
struct RestoreReceipt: Decodable, Sendable {
    let vault_id: UUID; let format_version: UInt32; let input_sha256_hex: String
    let output_path: String; let snapshot_cut: SnapshotCut; let generation: UInt64
}
struct RestoreSelection: Equatable, Sendable {
    let input: String; let sha256: String; let target: String; let recovery: Bool
    var arguments: [String] { ["restore", "--input", input, "--sha256", sha256] }
}
struct RestorePreview: Sendable {
    let selection: RestoreSelection; let context: RollbackContext
    let workspace: String; let revision: UUID
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
struct FixedAction: Decodable, Identifiable, Sendable {
    struct RequestPolicy: Decodable, Sendable { let max_body_bytes: Int }
    let id: String
    let name: String
    let version: UInt64
    let enabled: Bool
    let credential_id: String
    let origin: String
    let method: String
    enum Target: Decodable, Sendable {
        struct TemplatePath: Decodable, Sendable {
            let path: String
            let params: [String: String]
            let query: [String: String]
        }
        struct Source: Decodable, Sendable {
            let template: String
            let capability: String
            let action_index: UInt64
            let digest: [UInt8]
            let signer_id: String?
        }
        struct DefaultPolicy: Decodable, Sendable { let rule: String }
        struct Template: Sendable {
            let path: TemplatePath
            let source: Source
            let defaultPolicy: DefaultPolicy
        }
        case fixed(String)
        case template(Template)
        private enum CodingKeys: String, CodingKey { case kind, path, target, source, default_policy }
        init(from decoder: Decoder) throws {
            let fields = try decoder.container(keyedBy: CodingKeys.self)
            switch try fields.decode(String.self, forKey: .kind) {
            case "fixed": self = .fixed(try fields.decode(String.self, forKey: .path))
            case "template": self = .template(Template(path: try fields.decode(TemplatePath.self, forKey: .target),
                source: try fields.decode(Source.self, forKey: .source), defaultPolicy: try fields.decode(DefaultPolicy.self, forKey: .default_policy)))
            default:
                throw DecodingError.dataCorruptedError(forKey: .kind, in: fields, debugDescription: "Unknown Action target kind")
            }
        }
        var summary: String {
            switch self {
            case .fixed(let path): return path
            case .template(let target):
                let query = target.path.query.isEmpty ? "" : "；可选查询：" + target.path.query.keys.sorted().joined(separator: ", ")
                return target.path.path + "（路径规则" + query + "）"
            }
        }
    }
    let target: Target
    let request_policy: RequestPolicy
    var request_max_bytes: Int { request_policy.max_body_bytes }
    var reference: String { "\(id)@\(version)" }
    var template: Target.Template? { if case .template(let value) = target { return value }; return nil }
}
struct ActionList: Decodable { let actions: [FixedAction] }
// These values edit the single signed snapshot. They are never a separate store.
struct AgentProfile: Codable, Equatable, Sendable {
    struct ActionRef: Codable, Equatable, Sendable {
        var action_id: UUID; var version: UInt64
        private enum CodingKeys: String, CodingKey { case action_id, version }
        func encode(to encoder: Encoder) throws {
            var fields = encoder.container(keyedBy: CodingKeys.self)
            try fields.encode(action_id.uuidString.lowercased(), forKey: .action_id)
            try fields.encode(version, forKey: .version)
        }
    }
    enum Rule: String, Codable, CaseIterable, Sendable {
        case templateDefault = "template-default", allow, requireApproval = "require-approval"
        var label: String {
            switch self {
            case .templateDefault: return "使用模板默认规则"
            case .allow: return "允许直接执行"
            case .requireApproval: return "每次请求本机审批"
            }
        }
    }
    struct Capability: Codable, Equatable, Sendable {
        var capability: String; var actions: [ActionRef]
        // This initializer default is only for newly selected capabilities;
        // synthesized Decodable still requires the signed wire field.
        var rule: Rule = .templateDefault
    }
    struct Grant: Codable, Equatable, Sendable { var instance: String; var capabilities: [Capability] }
    struct Session: Codable, Equatable, Sendable { var ttl_ms: Int64; var max_uses: UInt32 }
    struct LlmLimit: Codable, Equatable, Sendable {
        var instance: String; var models: [String]
        var max_output_tokens_per_request: UInt32
        var max_requests_per_day: UInt64
        var max_output_tokens_per_day: UInt64
    }
    enum Isolation: String, Codable, CaseIterable, Sendable { case none, seatbelt, netns }
    enum Egress: String, Codable, CaseIterable, Sendable { case allow, denyOther = "deny-other" }
    var name: String
    var principal_id: UUID
    var grants: [Grant]
    var session: Session
    var confirm_each_run: Bool
    var isolation: Isolation
    var egress: Egress
    var llm_limits: [LlmLimit]

    private enum CodingKeys: String, CodingKey {
        case name, principal_id, grants, session, confirm_each_run, isolation, egress, llm_limits
    }
    func encode(to encoder: Encoder) throws {
        var fields = encoder.container(keyedBy: CodingKeys.self)
        try fields.encode(name, forKey: .name)
        try fields.encode(principal_id.uuidString.lowercased(), forKey: .principal_id)
        try fields.encode(grants, forKey: .grants)
        try fields.encode(session, forKey: .session)
        try fields.encode(confirm_each_run, forKey: .confirm_each_run)
        try fields.encode(isolation, forKey: .isolation)
        try fields.encode(egress, forKey: .egress)
        try fields.encode(llm_limits, forKey: .llm_limits)
    }

    // Called only by the explicit Add action, never during decoding/rendering.
    static func newProfile() -> AgentProfile {
        AgentProfile(name: "", principal_id: UUID(), grants: [], session: Session(ttl_ms: 900_000, max_uses: 100),
                     confirm_each_run: false, isolation: .none, egress: .allow, llm_limits: [])
    }
}
struct ProfileList: Decodable, Sendable {
    static let stdoutLimit = 4 * 1024 * 1024 + 1
    let profiles: [AgentProfile]
    let policy_sha256: String?
    let expires_at_ms: Int64?
    private enum CodingKeys: String, CodingKey { case profiles, policy_sha256, expires_at_ms }
    init(from decoder: Decoder) throws {
        let fields = try decoder.container(keyedBy: CodingKeys.self)
        guard fields.contains(.policy_sha256), fields.contains(.expires_at_ms) else {
            throw UIError(message: "Profile 列表缺少策略基线，未开始编辑。")
        }
        profiles = try fields.decode([AgentProfile].self, forKey: .profiles)
        policy_sha256 = try fields.decodeIfPresent(String.self, forKey: .policy_sha256)
        expires_at_ms = try fields.decodeIfPresent(Int64.self, forKey: .expires_at_ms)
        guard (policy_sha256 == nil) == (expires_at_ms == nil),
              policy_sha256.map({ PersonalPolicyDraft.isLowerHex($0, count: 64) }) ?? profiles.isEmpty else {
            throw UIError(message: "Profile 列表的策略基线无效，未开始编辑。")
        }
    }
}

struct PolicyStatus: Decodable {
    enum Mode: String, Decodable { case personal, team }
    enum Algorithm: String, Decodable { case ed25519, secureEnclaveP256 = "secure-enclave-p256" }
    let vault_id: String
    let mode: Mode?
    let algorithm: Algorithm?
    let trust_sha256: String?
    let policy_sha256: String?
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
        struct Snapshot: Decodable { let version: UInt64; let expires_at_ms: Int64; let profiles: [AgentProfile] }
        let snapshot: Snapshot
        let signer_id: String
    }
    private static let prefix = Data("RKPOLICY\0\u{01}".utf8)
    let metadata: Metadata
    let signBytes: Data
    let publicKey: Data
    let changesText: String
    let actionsText: String
    let profiles: [AgentProfile]
    let expectedPolicySHA256: String?
    let expiresAtMs: Int64
    let workspace: String
    let revision: UUID

    init(response data: Data, expectedPolicySHA256: String?, expiresAtMs: Int64, workspace: String, revision: UUID) throws {
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
              envelope.snapshot.expires_at_ms == expiresAtMs,
              (response.metadata.base_version == nil) == (expectedPolicySHA256 == nil) else {
            throw UIError(message: "策略草稿的版本或有效期不一致。")
        }
        self.metadata = response.metadata; signBytes = bytes
        let hex = Array(response.metadata.public_key.utf8)
        publicKey = Data(stride(from: 0, to: hex.count, by: 2).map {
            UInt8(String(decoding: hex[$0..<$0 + 2], as: UTF8.self), radix: 16)!
        })
        changesText = String(decoding: try JSONSerialization.data(withJSONObject: changes, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
        actionsText = String(decoding: try JSONSerialization.data(withJSONObject: actions, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]), as: UTF8.self)
        profiles = envelope.snapshot.profiles; self.expectedPolicySHA256 = expectedPolicySHA256
        self.expiresAtMs = expiresAtMs
        self.workspace = workspace; self.revision = revision
    }

    func validate(current: PolicyStatus, now: Date = Date()) throws {
        guard current.mode == .personal, current.algorithm == .secureEnclaveP256,
              current.trust_installed, UUID(uuidString: current.vault_id) == metadata.vault_id,
              current.trust_sha256 == metadata.trust_sha256, current.version == metadata.base_version,
              current.policy_sha256 == expectedPolicySHA256,
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

    static func isLowerHex(_ text: String, count: Int) -> Bool {
        text.utf8.count == count && text.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
}

extension CLI {
    func personalPolicyDraft(profiles: [AgentProfile], expectedPolicySHA256: String?, expiresAtMs: Int64, revision: UUID) throws -> PersonalPolicyDraft {
        struct Request: Encodable {
            let profiles: [AgentProfile]; let expires_at_ms: Int64; let expected_policy_sha256: String?
            private enum CodingKeys: String, CodingKey { case profiles, expires_at_ms, expected_policy_sha256 }
            func encode(to encoder: Encoder) throws {
                var fields = encoder.container(keyedBy: CodingKeys.self)
                try fields.encode(profiles, forKey: .profiles)
                try fields.encode(expires_at_ms, forKey: .expires_at_ms)
                try fields.encode(expected_policy_sha256, forKey: .expected_policy_sha256)
            }
        }
        guard expectedPolicySHA256.map({ PersonalPolicyDraft.isLowerHex($0, count: 64) }) ?? true else {
            throw UIError(message: "策略基线摘要无效，请重新加载 Profile。")
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.withoutEscapingSlashes]
        let input = try encoder.encode(profiles)
        let metadata = try encoder.encode(Request(profiles: profiles, expires_at_ms: expiresAtMs, expected_policy_sha256: expectedPolicySHA256))
        guard input.count <= 65536, metadata.count <= 65536 else {
            throw UIError(message: "Profile 草稿请求超过 64 KiB，请缩小授权范围。")
        }
        var args = ["policy", "draft", "--profiles-stdin", "--expires-at-ms", String(expiresAtMs)]
        if let digest = expectedPolicySHA256 { args += ["--expected-policy-sha256", digest] }
        return try PersonalPolicyDraft(response: run(args, input: String(decoding: input, as: UTF8.self)), expectedPolicySHA256: expectedPolicySHA256,
                                       expiresAtMs: expiresAtMs, workspace: stateDirectory, revision: revision)
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
// The daemon owns normalization. Decode only display metadata; retain request JSON bytes.
enum LocalApprovalState: String, Decodable, Sendable {
    case pending, approved, consumed, cancelled, expired
    var terminal: Bool { self == .consumed || self == .cancelled || self == .expired }
    var label: String {
        switch self { case .pending: return "等待决定"; case .approved: return "已批准，等待 Agent"; case .consumed: return "已使用"; case .cancelled: return "已拒绝或取消"; case .expired: return "已过期" }
    }
}
struct LocalApprovalStateResponse: Decodable {
    let approval_request_id: String
    let state: LocalApprovalState
    let expires_at_ms: Int64
}
struct LocalApprovalDetails: Identifiable {
    static let bodyLimit = 4 * 1024 * 1024
    static let stdoutLimit = 8 * 1024 * 1024 + 65536
    struct Metadata: Decodable {
        let record_type: String
        let approval_request_id: String
        let review_sha256: String
        let state: LocalApprovalState
        let body_len: Int
    }
    struct Review: Decodable {
        let record_type: String
        let challenge: ApprovalChallenge
        let action_name: String
        let origin: String
        let method: String
    }
    private struct Response: Decodable { let metadata: Metadata; let review_json: String? }
    let metadata: Metadata
    let review: Review?
    let raw: Data
    let workspace: String
    let revision: UUID
    var state: LocalApprovalState
    var id: String { metadata.approval_request_id }
    var text: String { String(decoding: raw, as: UTF8.self) }
    func canDecide(at now: Date = Date()) -> Bool {
        state == .pending && review.map { now.timeIntervalSince1970 * 1000 < Double($0.challenge.max_expires_at_ms) } == true
    }
    static func parse(_ data: Data, id: String, workspace: String, revision: UUID) throws -> Self {
        guard data.count <= stdoutLimit else { throw UIError(message: "审批响应超过上限。") }
        let value = try JSONDecoder().decode(Response.self, from: data)
        let meta = value.metadata
        guard UUID(uuidString: id) != nil, meta.approval_request_id == id,
              meta.record_type == "rekey.approval.local-review.v1", (0...bodyLimit).contains(meta.body_len),
              meta.review_sha256.utf8.count == 64,
              meta.review_sha256.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw UIError(message: "审批响应与所选请求不一致。")
        }
        let raw = value.review_json.map { Data($0.utf8) } ?? Data()
        guard raw.count == meta.body_len else { throw UIError(message: "审批正文不完整。") }
        let review: Review?
        if raw.isEmpty {
            guard meta.state.terminal, value.review_json == nil else { throw UIError(message: "待处理的审批缺少完整正文。") }
            review = nil
        } else {
            let digest = SHA256.hash(data: Data("RKREVIEW\0\u{1}".utf8) + raw).map { String(format: "%02x", $0) }.joined()
            guard digest == meta.review_sha256 else { throw UIError(message: "审批正文校验失败，请重新读取。") }
            let decoded = try JSONDecoder().decode(Review.self, from: raw)
            guard decoded.record_type == "rekey.approval.review.v1", decoded.challenge.record_type == "rekey.approval.challenge.v2",
                  decoded.challenge.approval_request_id == id, case .localPresence = decoded.challenge.approver else {
                throw UIError(message: "此正文不是所选本机审批请求。")
            }
            review = decoded
        }
        return Self(metadata: meta, review: review, raw: raw, workspace: workspace, revision: revision, state: meta.state)
    }
}
extension CLI {
    func localApprovalReview(_ id: String, revision: UUID) throws -> LocalApprovalDetails {
        try LocalApprovalDetails.parse(run(["approval", "review", id]), id: id, workspace: stateDirectory, revision: revision)
    }
    func decideLocalApproval(_ details: LocalApprovalDetails, approve: Bool, proof: String) throws -> LocalApprovalStateResponse {
        let key = try PresenceKey.validated(proof)
        let data = try run(["approval", approve ? "approve" : "reject", details.id, "--review-sha256", details.metadata.review_sha256,
                            "--presence", "--password-stdin"], input: key + "\n", redacting: [key])
        let response = try JSONDecoder().decode(LocalApprovalStateResponse.self, from: data)
        guard response.approval_request_id == details.id,
              response.expires_at_ms == details.review?.challenge.max_expires_at_ms else {
            throw UIError(message: "审批决定响应不匹配，结果未确认。请查询状态，不要自动重试。")
        }
        return response
    }
}

struct AuditEvent: Decodable, Identifiable {
    let sequence: UInt64
    let event_id: String
    let event_type: String
    let outcome: String
    let reason_code: String
    let created_at_ms: Int64
    let request_id: String?
    let approval_request_id: String?
    let request_context: ActivityContext?
    let usage: ActivityUsage?
    var id: UInt64 { sequence }
}
struct AuditPage: Decodable {
    static let stdoutLimit = 4 * 1024 * 1024 + 1
    let snapshot_max_sequence: UInt64
    let next_before_sequence: UInt64?
    let events: [AuditEvent]
}

struct ActivityContext: Decodable, Hashable {
    let profile_name: String
    let policy_sha256: String
    let instance_slug: String
    let capability: String
    let model: String?
}
struct ActivityUsage: Decodable {
    enum Source: String, Decodable { case measured, indeterminate, notApplicable = "not-applicable" }
    let instance_slug: String
    let utc_day: Int64
    let output_tokens: UInt64
    let source: Source
}
struct ActivityCounts {
    var admitted: UInt64 = 0, denied: UInt64 = 0, approvals: UInt64 = 0
    var measuredTokens: UInt64 = 0, estimatedTokens: UInt64 = 0

    mutating func add(_ other: ActivityCounts) throws {
        func sum(_ a: UInt64, _ b: UInt64) throws -> UInt64 {
            let (value, overflow) = a.addingReportingOverflow(b)
            guard !overflow else { throw UIError(message: "活动统计超出整数范围，未显示不完整的汇总。") }
            return value
        }
        admitted = try sum(admitted, other.admitted); denied = try sum(denied, other.denied)
        approvals = try sum(approvals, other.approvals)
        measuredTokens = try sum(measuredTokens, other.measuredTokens)
        estimatedTokens = try sum(estimatedTokens, other.estimatedTokens)
    }
}
struct ActivityRow: Identifiable {
    let context: ActivityContext?
    var counts = ActivityCounts()
    var id: ActivityContext? { context }
}

// One in-memory view of an existing audit snapshot; never a second usage ledger.
struct ActivitySnapshot {
    let sinceMs: Int64
    let untilMs: Int64
    private(set) var snapshot: UInt64?
    private(set) var cursor: UInt64?
    private(set) var pages = 0
    private(set) var complete = false
    private(set) var totals = ActivityCounts()
    private var groups: [ActivityContext?: ActivityRow] = [:]
    private var sequences = Set<UInt64>(), eventIDs = Set<String>()
    private var approvalIDs = Set<String>(), settledRequests = Set<String>()

    init(nowMs: Int64) {
        untilMs = max(0, nowMs)
        sinceMs = untilMs / 86_400_000 * 86_400_000
    }
    var arguments: [String] {
        var result = ["audit", "list", "--limit", "100", "--since-ms", String(sinceMs), "--until-ms", String(untilMs)]
        if let snapshot, let cursor { result += ["--snapshot-max-sequence", String(snapshot), "--before-sequence", String(cursor)] }
        return result
    }
    var rows: [ActivityRow] {
        groups.values.sorted {
            let a = $0.context, b = $1.context
            return [a?.profile_name ?? "", a?.policy_sha256 ?? "", a?.instance_slug ?? "", a?.capability ?? "", a?.model ?? ""]
                .lexicographicallyPrecedes([b?.profile_name ?? "", b?.policy_sha256 ?? "", b?.instance_slug ?? "", b?.capability ?? "", b?.model ?? ""])
        }
    }
    mutating func ingest(_ page: AuditPage) throws {
        guard !complete, snapshot == nil || snapshot == page.snapshot_max_sequence,
              page.next_before_sequence == nil || (page.next_before_sequence! > 0 && page.next_before_sequence! <= page.snapshot_max_sequence && (cursor == nil || page.next_before_sequence! < cursor!)) else {
            throw UIError(message: "审计快照或分页游标已失效，请重新刷新活动页。")
        }
        // Publish a page atomically, including overflow checks and de-duplication.
        var next = self
        for event in page.events {
            guard !next.sequences.contains(event.sequence), !next.eventIDs.contains(event.event_id) else { continue }
            next.sequences.insert(event.sequence); next.eventIDs.insert(event.event_id)
            var counts = ActivityCounts()
            if event.event_type == "execution.started" { counts.admitted = 1 }
            if event.event_type == "execution.blocked" { counts.denied = 1 }
            if event.event_type == "approval.requested", let id = event.approval_request_id, next.approvalIDs.insert(id).inserted { counts.approvals = 1 }
            if ["execution.finished", "execution.blocked", "execution.indeterminate"].contains(event.event_type),
               let usage = event.usage, let request = event.request_id, next.settledRequests.insert(request).inserted {
                switch usage.source {
                case .measured: counts.measuredTokens = usage.output_tokens
                case .indeterminate: counts.estimatedTokens = usage.output_tokens
                case .notApplicable: break
                }
            }
            guard counts.admitted != 0 || counts.denied != 0 || counts.approvals != 0 || counts.measuredTokens != 0 || counts.estimatedTokens != 0 else { continue }
            var row = next.groups[event.request_context] ?? ActivityRow(context: event.request_context)
            try row.counts.add(counts); try next.totals.add(counts)
            next.groups[event.request_context] = row
        }
        next.snapshot = page.snapshot_max_sequence; next.cursor = page.next_before_sequence
        next.pages += 1; next.complete = page.next_before_sequence == nil
        self = next
    }
}

enum OnboardingRoute: String, Sendable {
    case setup = "rekey://setup"
    case anthropic = "rekey://add/anthropic"
    init?(url: URL) { self.init(rawValue: url.absoluteString) }
}

extension AgentProfile {
    // Only invoked by the explicit Prepare Profile button, not during rendering.
    static func anthropic(actions: [FixedAction], model: String) throws -> AgentProfile {
        guard !model.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { throw UIError(message: "请填写并确认精确模型 ID。") }
        var profile = newProfile()
        profile.name = "claude-code"
        var capabilities: [Capability] = []
        for action in actions {
            guard let source = action.template?.source, let id = UUID(uuidString: action.id) else { throw UIError(message: "安装响应缺少模板操作身份，未准备 Profile。") }
            let reference = ActionRef(action_id: id, version: action.version)
            if let index = capabilities.firstIndex(where: { $0.capability == source.capability }) { capabilities[index].actions.append(reference) }
            else { capabilities.append(.init(capability: source.capability, actions: [reference])) }
        }
        profile.grants = [.init(instance: "anthropic", capabilities: capabilities)]
        profile.llm_limits = [.init(instance: "anthropic", models: [model], max_output_tokens_per_request: 32768, max_requests_per_day: 100, max_output_tokens_per_day: 100_000)]
        return profile
    }
    var claudeLaunchCommand: String? {
        guard llm_limits.count == 1, llm_limits[0].models.count == 1 else { return nil }
        func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\"'\"'") + "'" }
        return "rekey run " + quote(name) + " --client claude-code -- claude --model " + quote(llm_limits[0].models[0])
    }
}

extension ProfileList {
    func addingOnboardingProfile(_ seed: AgentProfile?) throws -> [AgentProfile] {
        guard let seed else { return profiles }
        guard !profiles.contains(where: { $0.name == seed.name || $0.principal_id == seed.principal_id }) else {
            throw UIError(message: "已有同名 Profile。请关闭并另取名称，或前往授权页面明确编辑已有项；不会覆盖旧主体。")
        }
        return profiles + [seed]
    }
}

struct InstalledTemplateActions: Decodable, Sendable {
    struct Item: Decodable, Sendable { let binding_index: UInt64; let action: FixedAction }
    let actions: [Item]
}

enum Page: String, CaseIterable, Identifiable {
    case credentials = "凭证", actions = "固定操作", policy = "授权与策略", approvals = "审批收件箱", activity = "活动", audit = "审计日志", backup = "备份与恢复", settings = "设置"
    var id: String { rawValue }
    var icon: String {
        switch self {
        case .credentials: return "doc.text"
        case .actions: return "play"
        case .policy: return "checkmark.shield"
        case .approvals: return "tray"
        case .activity: return "chart.bar"
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
    let digest: [UInt8]
    let signer_id: String?
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
    var rollbackContext: RollbackContext?
    var rollbackRevision: UUID?
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
                "key rotate-dek", "audit prune"].contains(command)
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
    @Published var page: Page = .credentials { didSet { if oldValue != page { clearActivity() } } }
    @Published var status: ServiceStatus?
    @Published var credentials: [Credential] = []
    @Published var actions: [FixedAction] = []
    @Published var policy: PolicyStatus?
    @Published var approvals: [PendingApproval] = []
    @Published var approvalDetails: ApprovalDetails?
    @Published var localApprovalDetails: LocalApprovalDetails?
    @Published private(set) var localApprovalNeedsRefresh = false
    @Published private(set) var approvalNotificationsEnabled = false
    @Published private(set) var approvalNotificationBusy = false
    @Published private(set) var approvalNotificationMessage: String?
    private(set) var notifiedApprovalIDs = Set<String>()
    private var notificationRevision = UUID()
    @Published var onboardingRoute: OnboardingRoute?
    @Published var onboardingProfile: AgentProfile?
    @Published var onboardingCommand: String?
    @Published var showPolicyDraft = false
    @Published var showTemplate = false
    @Published private(set) var nativeFlowRevision = UUID()
    @Published private(set) var personalPolicySigning = false
    @Published private(set) var presenceAuthenticating = false
    @Published var audit: AuditPage?
    @Published private(set) var activity: ActivitySnapshot?
    @Published private(set) var activityError: String?
    private var activityRevision = UUID()
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
            onboardingRoute = nil; onboardingProfile = nil; onboardingCommand = nil
            clearActivity()
            PresenceKey.invalidateAuthentication()
            notifiedApprovalIDs.removeAll(); clearNativeFlow(); clearOIDCLogin(); oidcProfileFile = nil; oidcSessionFile = nil; oidcIdentity = nil
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
        onboardingProfile = nil
        nativeFlowRevision = UUID(); showPolicyDraft = false; approvalDetails = nil; localApprovalDetails = nil; localApprovalNeedsRefresh = false
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
    func loadProfileEditor(client injectedClient: CLI? = nil) async throws -> (ProfileList, [FixedAction]) {
        guard !busy, unlocked else { throw UIError(message: "请先解锁并等待当前操作完成。") }
        busy = true; defer { busy = false }
        let client = injectedClient ?? cli, revision = nativeFlowRevision
        let loaded = try await Task.detached {
            (try client.decode(ProfileList.self, ["profile", "list"]), try client.decode(ActionList.self, ["action", "list"]).actions)
        }.value
        guard acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else {
            throw UIError(message: "Profile 加载期间上下文已改变，结果已丢弃。")
        }
        return loaded
    }
    func personalPolicyDraft(profiles: [AgentProfile], expectedPolicySHA256: String?, expiresAtMs: Int64,
                             client injectedClient: CLI? = nil) async throws -> PersonalPolicyDraft {
        guard !busy, unlocked, policy?.mode == .personal else { throw UIError(message: "请先解锁个人保险库并等待当前操作完成。") }
        busy = true
        defer { busy = false }
        let client = injectedClient ?? cli, revision = nativeFlowRevision
        let draft = try await Task.detached { try client.personalPolicyDraft(profiles: profiles, expectedPolicySHA256: expectedPolicySHA256, expiresAtMs: expiresAtMs, revision: revision) }.value
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
        if acceptsNativeCompletion(draft.revision, workspace: draft.workspace), let seed = onboardingProfile,
           let activated = draft.profiles.first(where: { $0.principal_id == seed.principal_id }) {
            onboardingCommand = activated.claudeLaunchCommand
        }
    }
    var needsSetup: Bool {
        !FileManager.default.fileExists(atPath: stateDirectory + "/vault.sqlite3")
    }
    func beginSetup() {
        let startup = onboardingRoute == .setup ? "保存恢复密钥后，请明确启动服务。" : managesBackgroundService ? "同时启用本用户登录启动并启动服务。" : "随后启动服务。"
        operation = Operation(title: "创建保险库", detail: "设置并确认密码后，应用会创建保险库，" + startup + "请保存随后显示的恢复密钥。取消、未确认或失败可能保留未完成状态；应用不会删除文件、清除历史锚或自动重试。", arguments: ["init"], confirmSecret: true, sensitiveResult: true, recoveryAllowed: false)
    }
    func requestRollbackConfirmation() {
        guard !busy, status?.state == "rollback-suspected", let context = status?.rollback else { return }
        operation = Operation(title: "确认所示回滚快照", detail: "仅确认当前显示的快照，重新定代后仍保持锁定。不会降低历史上限；确认不能找回缺失历史。", arguments: ["rollback-confirm"], targetDirectory: stateDirectory, rollbackContext: context, rollbackRevision: nativeFlowRevision)
    }
    private func acceptsRecoveryCompletion(_ revision: UUID, workspace: String) -> Bool {
        revision == nativeFlowRevision && workspace == stateDirectory && !Task.isCancelled
    }
    func inspectRestore(_ selection: RestoreSelection, proof: String, client injectedClient: CLI? = nil) async throws -> RestorePreview {
        guard !busy, !proof.isEmpty, !proof.contains("\n"), !proof.contains("\r"), !proof.contains("\0") else { throw UIError(message: "请提供本次备份验证信息，并等待当前操作完成。") }
        busy = true; defer { busy = false }
        let workspace = stateDirectory, revision = nativeFlowRevision
        let client = CLI(binary: injectedClient?.binary ?? cli.binary, stateDirectory: selection.target)
        let args = selection.arguments + ["--inspect", "--password-stdin"] + (selection.recovery ? ["--recovery"] : [])
        let data = try await Task.detached { try client.run(args, input: proof + "\n", redacting: [proof]) }.value
        guard acceptsRecoveryCompletion(revision, workspace: workspace) else { throw UIError(message: "恢复验证期间上下文已改变，预览已丢弃。") }
        return RestorePreview(selection: selection, context: try JSONDecoder().decode(RollbackContext.self, from: data), workspace: workspace, revision: revision)
    }
    func confirmRestore(_ preview: RestorePreview, selection: RestoreSelection, proof: String, client injectedClient: CLI? = nil) async throws {
        guard !busy, !proof.isEmpty, !proof.contains("\n"), !proof.contains("\r"), !proof.contains("\0"), preview.selection == selection,
              acceptsRecoveryCompletion(preview.revision, workspace: preview.workspace) else {
            throw UIError(message: "恢复预览已失效，请重新验证并审阅；未提交恢复。")
        }
        busy = true; defer { busy = false }
        let client = CLI(binary: injectedClient?.binary ?? cli.binary, stateDirectory: selection.target)
        let args = selection.arguments + ["--expected-context", try preview.context.encodedArgument(), "--password-stdin"] + (selection.recovery ? ["--recovery"] : [])
        let data = try await Task.detached { try client.run(args, input: proof + "\n", redacting: [proof]) }.value
        guard acceptsRecoveryCompletion(preview.revision, workspace: preview.workspace) else { throw UIError(message: "恢复结果未展示；提交可能已完成，请检查目标，勿自动重试。") }
        let receipt = try JSONDecoder().decode(RestoreReceipt.self, from: data)
        result = ResultMessage(title: "备份已恢复 · 仍需普通解锁", text: "新目标代数：\(receipt.generation)\n" + String(decoding: data, as: UTF8.self))
    }
    func confirmRollback(_ expected: RollbackContext, workspace: String, revision: UUID, proof: String, recovery: Bool, client injectedClient: CLI? = nil) async throws {
        guard !busy, !proof.isEmpty, !proof.contains("\n"), !proof.contains("\r"), !proof.contains("\0"), status?.state == "rollback-suspected", status?.rollback == expected,
              acceptsRecoveryCompletion(revision, workspace: workspace) else {
            throw UIError(message: "疑似回滚上下文已改变，请重新读取并审阅；未提交确认。")
        }
        busy = true; defer { busy = false }
        let client = injectedClient ?? cli
        let args = ["rollback-confirm", "--expected-context", try expected.encodedArgument(), "--password-stdin"] + (recovery ? ["--recovery"] : [])
        let data = try await Task.detached { try client.run(args, input: proof + "\n", redacting: [proof]) }.value
        guard acceptsRecoveryCompletion(revision, workspace: workspace), status?.rollback == expected else { throw UIError(message: "回滚确认结果未展示；提交可能已完成，请检查状态，勿自动重试。") }
        struct Receipt: Decodable { let locked: Bool }
        guard try JSONDecoder().decode(Receipt.self, from: data).locked, let prior = status else { throw UIError(message: "确认回执未表明锁定状态，请检查服务，勿自动重试。") }
        status = ServiceStatus(state: "locked", format_version: prior.format_version, runtime_version: prior.runtime_version, sessions_active: 0, peer_security: prior.peer_security, lab_enabled: prior.lab_enabled, rollback: nil)
        clearCache()
        result = ResultMessage(title: "回滚快照已确认 · 保持锁定", text: "历史上限未降低。请另行执行普通解锁；本次确认没有提供密钥使用权限。")
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
    func openOnboarding(_ url: URL) {
        guard let route = OnboardingRoute(url: url) else { error = "不支持的 Rekey 页面地址。"; return }
        guard !busy, operation == nil, result == nil, !showPolicyDraft, !showTemplate,
              BackgroundService.usesDefaultState(stateDirectory), oidcProfileFile == nil, oidcSessionFile == nil else {
            error = "请先完成当前操作，并在默认保险库工作区打开设置或接入页面。"; return
        }
        clearNativeFlow(); onboardingProfile = nil; onboardingCommand = nil; onboardingRoute = route
    }
    func saveAPIKey(label: String, secret: String, client injectedClient: CLI? = nil) async throws -> Credential {
        guard desktopReady, let token = desktopToken else { throw UIError(message: "管理会话已过期，请先解锁管理会话。") }
        guard !busy else { throw UIError(message: "当前操作尚未完成，未保存凭据。") }
        busy = true; defer { busy = false }
        let client = injectedClient ?? cli, revision = nativeFlowRevision
        let data = try await Task.detached { try client.run(["desktop-add", label], input: token + "\n" + secret + "\n", redacting: [token, secret]) }.value
        guard acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else { throw UIError(message: "上下文已改变，请检查已保存凭据，勿自动重试。") }
        return try JSONDecoder().decode(Credential.self, from: data)
    }
    func addAPIKey(label: String, secret: String) async -> Bool {
        do { _ = try await saveAPIKey(label: label, secret: secret); await refresh(); return true }
        catch { rejectDesktopSession(error); self.error = error.localizedDescription; return false }
    }
    func loadOnboardingActions(credentialID: String, provider: String = "anthropic", client injectedClient: CLI? = nil) async throws -> [FixedAction] {
        guard !busy, unlocked else { throw UIError(message: "请先解锁并等待当前操作完成。") }
        busy = true; defer { busy = false }
        let client = injectedClient ?? cli, revision = nativeFlowRevision
        let request = try JSONSerialization.data(withJSONObject: ["source": ["kind": provider]], options: [.sortedKeys])
        let (catalog, available) = try await Task.detached {
            (try client.templateCatalog(source: request),
             try client.decode(ActionList.self, ["action", "list"]).actions)
        }.value
        guard acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else { throw UIError(message: "读取期间上下文已改变，结果已丢弃。") }
        return available.filter { action in
            guard action.enabled, action.credential_id == credentialID, let source = action.template?.source else { return false }
            return source.template == catalog.template.template && source.digest == catalog.digest && source.signer_id == catalog.signer_id
        }
    }
    func installOnboardingAnthropic(credentialID: String, capabilities: [String], proof: String, presence: Bool,
                                    provider: String = "anthropic",
                                    client injectedClient: CLI? = nil,
                                    readPresence: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async throws -> [FixedAction] {
        guard !busy, unlocked, policy?.mode == .personal else { throw UIError(message: "请先解锁个人保险库。团队模式请使用现有外部签名流程。") }
        busy = true; defer { busy = false }
        let client = injectedClient ?? cli, revision = nativeFlowRevision
        let operationProof: String
        if presence { (operationProof, _) = try await readPresenceProof(client: client, revision: revision, read: readPresence) }
        else { operationProof = proof }
        guard !operationProof.isEmpty, !operationProof.contains("\n"), !operationProof.contains("\r"),
              acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else { throw UIError(message: "验证信息或接入上下文已失效，未安装。") }
        let request: [String: Any] = ["source": ["kind": provider], "credential_id": credentialID, "bindings": [[:]], "capabilities": capabilities,
            "name_prefix": provider == "glm" ? "GLM" : "Anthropic", "timeout_ms": 30_000, "request_max_bytes": 1024 * 1024, "allowed_extra_headers": ["anthropic-beta"],
            "response_max_bytes": 4 * 1024 * 1024, "allowed_response_headers": ["content-type"]]
        let body = operationProof + "\n" + String(decoding: try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys]), as: UTF8.self) + "\n"
        let args = ["template", "install", "--stdin-request", "--password-stdin"] + (presence ? ["--presence"] : [])
        let data = try await Task.detached { try client.run(args, input: body, redacting: [operationProof]) }.value
        guard acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else { throw UIError(message: "上下文已改变，请检查已安装操作，勿自动重试。") }
        return try JSONDecoder().decode(InstalledTemplateActions.self, from: data).actions.map(\.action)
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
            PresenceKey.invalidateAuthentication()
            desktopToken = nil; desktopExpiry = .distantPast; visibleSecret = nil; copiedCredential = nil
        }
    }
    func clearCache() {
        clearActivity()
        PresenceKey.invalidateAuthentication()
        clearNativeFlow(); clearOIDCLogin()
        oidcSessionFile = nil; oidcIdentity = nil
        desktopToken = nil; visibleSecret = nil; copiedCredential = nil
        notifiedApprovalIDs.removeAll()
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
        if page == .activity { await refreshActivity(passive: passive, client: injectedClient); return }
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
        if passive {
            await refreshApprovalNotifications(client: client)
            return
        }
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
                let items = try await Task.detached { try client.decode(PendingList.self, ["approval", "pending"]) }.value.challenges
                if client.stateDirectory == stateDirectory && unlocked { try await receiveApprovals(items) }
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
    func clearActivity() {
        activityRevision = UUID(); activity = nil; activityError = nil
    }
    func refreshActivity(passive: Bool = false, client injectedClient: CLI? = nil, nowMs: Int64? = nil) async {
        guard !busy, page == .activity else { return }
        busy = true
        defer { busy = false }
        let client = injectedClient ?? cli
        let workspace = stateDirectory
        var revision = activityRevision
        func current() -> Bool { page == .activity && stateDirectory == workspace && activityRevision == revision && !Task.isCancelled }
        do {
            let statusResult = try await Task.detached { try client.decode(ServiceStatus.self, passive ? ["status", "--passive"] : ["status"]) }.value
            guard current() else { return }
            let wasUnlocked = unlocked
            status = statusResult; connectionError = nil
            if !statusResult.unlocked && (wasUnlocked || !passive) { clearCache(); revision = activityRevision }
        } catch {
            guard current() else { return }
            status = nil; clearCache(); connectionError = error.localizedDescription
            return
        }
        let refreshTime = nowMs ?? Int64(Date().timeIntervalSince1970 * 1000)
        if passive {
            await refreshApprovalNotifications(client: client)
            guard current() else { return }
        }
        if passive && activity?.sinceMs == refreshTime / 86_400_000 * 86_400_000 { return }
        activityError = nil
        var value = ActivitySnapshot(nowMs: refreshTime)
        activity = value
        do {
            while !value.complete {
                let args = value.arguments
                let page = try await Task.detached { try client.decode(AuditPage.self, args) }.value
                guard current() else { return }
                try value.ingest(page)
                activity = value
            }
        } catch {
            guard current() else { return }
            activityError = error.localizedDescription + "\n本次汇总未完成，请刷新后重新读取稳定快照。"
        }
    }
    func perform(_ op: Operation, proof: String = "", secret: String = "", recovery: Bool = false,
                 presence: Bool = false, rememberPresence: Bool = false, presenceRevision: UUID? = nil,
                 client injectedClient: CLI? = nil,
                 readPresence: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async {
        if ["restore", "rollback-confirm"].contains(op.arguments.first ?? "") {
            error = "此操作必须先展示恢复上下文，再由专用确认入口提交。"; return
        }
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
        let onboarding = onboardingRoute
        func onboardingCurrent() -> Bool {
            onboarding == nil || (onboarding == onboardingRoute && revision == nativeFlowRevision && client.stateDirectory == stateDirectory && !Task.isCancelled)
        }
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
                guard onboardingCurrent() else { throw UIError(message: "设置上下文已改变，未创建签名密钥。") }
                let publicKey = try await Task.detached { try PolicySigning.createOrLoadPublicKey(vaultID: vaultID) }.value
                let trust: [String: Any] = ["format_version": 1, "signer_id": vaultID.uuidString.lowercased(), "algorithm": "secure-enclave-p256", "public_key": publicKey.map { String(format: "%02x", $0) }.joined()]
                body += String(decoding: try JSONSerialization.data(withJSONObject: trust, options: [.sortedKeys]), as: UTF8.self) + "\n"
            }
            guard !guarded || (acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: desktopLogin) && !Task.isCancelled) else {
                throw UIError(message: "系统认证操作上下文已改变，未提交。")
            }
            guard onboardingCurrent() else { throw UIError(message: "设置上下文已改变，未提交后续操作。") }
            let command = args, requestInput = body
            let data = try await Task.detached { try client.run(command, input: requestInput, redacting: [operationProof, secret]) }.value
            guard !guarded || acceptsPresenceCompletion(revision, workspace: client.stateDirectory, allowLocked: desktopLogin) else {
                throw UIError(message: "操作上下文已改变，结果未展示；请检查审计，不要自动重试。")
            }
            guard onboardingCurrent() else { throw UIError(message: "设置上下文已改变，结果未展示；已提交步骤可能完成，请检查状态，勿自动重试。") }
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
                if op.arguments.first == "backup" { _ = try JSONDecoder().decode(BackupReceipt.self, from: data) }
                if op.unregisterBackgroundService {
                    do { try await BackgroundService.unregisterAfterAuthorizedShutdown() }
                    catch { throw UIError(message: "服务已停止，但未能停用登录启动：" + error.localizedDescription) }
                }
                result = ResultMessage(title: op.title + "完成", text: output, sensitive: op.sensitiveResult)
            }
        } catch {
            operationError = error.localizedDescription + (op.arguments.first == "init" ? "\n初始化可能保留未完成状态；应用未删除文件或清除历史锚，也不会自动重试。" : "")
        }
        if let file = op.temporaryFile {
            do { try FileManager.default.removeItem(at: file) }
            catch { operationError = (operationError.map { $0 + "\n" } ?? "") + "无法删除临时操作定义：\(file.path)" }
        }
        if let operationError {
            if !guarded || (revision == nativeFlowRevision && client.stateDirectory == stateDirectory) { self.error = operationError }
        }
        busy = false
        if injectedClient == nil { await refresh() }
        if operationError == nil && op.arguments.first == "init" && onboarding == nil { startService() }
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
        if case .localPresence = item.approver { await reviewLocalApproval(item.id); return }
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
    func reviewLocalApproval(_ id: String, client injectedClient: CLI? = nil, active: Bool? = nil) async {
        guard !busy, unlocked else { return }
        busy = true; error = nil
        defer { busy = false }
        let client = injectedClient ?? cli, revision = nativeFlowRevision
        do {
            let details = try await Task.detached { try client.localApprovalReview(id, revision: revision) }.value
            guard (active ?? NSApp.isActive), acceptsNativeCompletion(revision, workspace: client.stateDirectory), !Task.isCancelled else { return }
            localApprovalDetails = details; localApprovalNeedsRefresh = false
        } catch {
            if acceptsNativeCompletion(revision, workspace: client.stateDirectory) { self.error = error.localizedDescription }
        }
    }
    func decideLocalApproval(_ details: LocalApprovalDetails, approve: Bool, client injectedClient: CLI? = nil,
                             active: @MainActor () -> Bool = { NSApp?.isActive == true },
                             readPresence: @escaping @Sendable (UUID) throws -> String = { try PresenceKey.read(vaultID: $0) }) async throws {
        guard !busy, localApprovalCurrent(details), !localApprovalNeedsRefresh else { throw UIError(message: "审批上下文已失效，请重新查看请求。") }
        busy = true
        defer { busy = false }
        let client = injectedClient ?? cli
        var submitted = false
        do {
            let (key, _) = try await readPresenceProof(client: client, revision: details.revision, read: readPresence)
            guard localApprovalCurrent(details), active(), !Task.isCancelled else { throw UIError(message: "认证期间审批或窗口状态已改变，未提交决定。") }
            let latest = try await Task.detached { try client.localApprovalReview(details.id, revision: details.revision) }.value
            guard localApprovalCurrent(details), active(), latest.canDecide(), latest.raw == details.raw,
                  latest.metadata.review_sha256 == details.metadata.review_sha256, !Task.isCancelled else {
                throw UIError(message: "审批已过期或状态改变，请重新查看；未提交决定。")
            }
            submitted = true
            let response = try await Task.detached { try client.decideLocalApproval(details, approve: approve, proof: key) }.value
            guard acceptsNativeCompletion(details.revision, workspace: details.workspace), localApprovalDetails?.id == details.id else { return }
            submitted = false
            localApprovalDetails?.state = response.state
            approvals.removeAll { $0.id == details.id }
            if injectedClient == nil {
                let items = try await Task.detached { try client.decode(PendingList.self, ["approval", "pending"]) }.value.challenges
                if acceptsNativeCompletion(details.revision, workspace: details.workspace) { try await receiveApprovals(items) }
            }
        } catch {
            if submitted && acceptsNativeCompletion(details.revision, workspace: details.workspace) {
                localApprovalNeedsRefresh = true
                throw UIError(message: "审批结果未确认，请查询状态，不要自动重试。\n" + error.localizedDescription)
            }
            throw error
        }
    }
    private func localApprovalCurrent(_ details: LocalApprovalDetails) -> Bool {
        acceptsNativeCompletion(details.revision, workspace: details.workspace) && details.canDecide() &&
        localApprovalDetails?.id == details.id && localApprovalDetails?.metadata.review_sha256 == details.metadata.review_sha256 &&
        localApprovalDetails?.state == .pending
    }
    private func refreshApprovalNotifications(client: CLI) async {
        let revision = notificationRevision
        let flowRevision = nativeFlowRevision
        func current() -> Bool {
            client.stateDirectory == stateDirectory && unlocked && approvalNotificationsEnabled && revision == notificationRevision && flowRevision == nativeFlowRevision
        }
        guard current() else { return }
        do {
            let items = try await Task.detached { try client.decode(PendingList.self, ["approval", "pending"]) }.value.challenges
            guard current() else { return }
            try await receiveApprovals(items)
        } catch {
            if current() { approvalNotificationMessage = "无法刷新审批提醒，请手动查看收件箱。" }
        }
    }
    func setApprovalNotifications(_ enabled: Bool,
                                  request: @escaping @Sendable () async throws -> Bool = {
                                      try await UNUserNotificationCenter.current().requestAuthorization(options: [.alert])
                                  }) async {
        notificationRevision = UUID()
        let revision = notificationRevision
        if !enabled { approvalNotificationsEnabled = false; approvalNotificationMessage = nil; return }
        guard !approvalNotificationBusy else { return }
        approvalNotificationBusy = true
        defer { approvalNotificationBusy = false }
        do {
            let granted = try await request()
            guard revision == notificationRevision else { return }
            approvalNotificationsEnabled = granted
            approvalNotificationMessage = granted ? "已启用静态提醒；通知不会批准请求。" : "未获得通知权限，可继续手动查看收件箱。"
        } catch {
            if revision == notificationRevision { approvalNotificationsEnabled = false; approvalNotificationMessage = "通知权限请求失败，请稍后手动开启。" }
        }
    }
    func receiveApprovals(_ items: [PendingApproval],
                          send: @escaping @Sendable (String) async throws -> Void = { id in
                              let center = UNUserNotificationCenter.current()
                              guard await center.notificationSettings().authorizationStatus == .authorized else { throw UIError(message: "通知权限不可用。") }
                              let content = UNMutableNotificationContent()
                              content.title = "Rekey 有待审批请求"
                              content.body = "请打开 Rekey 收件箱，查看完整请求后作出决定。"
                              try await center.add(UNNotificationRequest(identifier: "rekey.approval." + id, content: content, trigger: nil))
                          }) async throws {
        guard items.count <= 128, Set(items.map(\.id)).count == items.count else { throw UIError(message: "审批列表超过上限或包含重复请求。") }
        approvals = items
        let pending = Set(items.filter { if case .localPresence = $0.approver { return true }; return false }.map(\.id))
        notifiedApprovalIDs.formIntersection(pending)
        guard approvalNotificationsEnabled else { return }
        let workspace = stateDirectory, revision = notificationRevision
        for id in pending.sorted() where !notifiedApprovalIDs.contains(id) {
            guard approvalNotificationsEnabled, workspace == stateDirectory, revision == notificationRevision else { return }
            // Mark before awaiting delivery: concurrent refreshes cannot duplicate it.
            notifiedApprovalIDs.insert(id)
            do { try await send(id) }
            catch { approvalNotificationsEnabled = false; approvalNotificationMessage = "审批提醒发送失败，请手动查看收件箱。"; return }
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
