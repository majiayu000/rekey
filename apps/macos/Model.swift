import Foundation
import SwiftUI
import AppKit
import Security

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
         kSecAttrService as String: "io.github.majiayu000.rekey.remembered-unlock",
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

    func run(_ arguments: [String], input: String = "") throws -> Data {
        guard FileManager.default.isExecutableFile(atPath: binary.path) else {
            throw UIError(message: "找不到随应用安装的 rekey，请重新构建应用。")
        }
        let process = Process()
        process.executableURL = binary
        process.arguments = ["--state-dir", stateDirectory] + arguments
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
            let detail = String(data: errors.data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "CLI 未返回错误说明"
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
    let id: String
    let name: String
    let version: Int
    let enabled: Bool
    let credential_id: String
    let origin: String
    let method: String
    let exact_path: String
    var reference: String { "\(id)@\(version)" }
}
struct ActionList: Decodable { let actions: [FixedAction] }
struct PolicyStatus: Decodable {
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

@MainActor
final class AppModel: ObservableObject {
    @Published var page: Page = .credentials
    @Published var status: ServiceStatus?
    @Published var credentials: [Credential] = []
    @Published var actions: [FixedAction] = []
    @Published var policy: PolicyStatus?
    @Published var approvals: [PendingApproval] = []
    @Published var approvalDetails: ApprovalDetails?
    @Published var audit: AuditPage?
    @Published var desktopToken: String?
    @Published var copiedCredential: String?
    @Published var visibleSecret: String?
    private var desktopExpiry = Date.distantPast
    private var resumeAttempted = false
    @Published var selectedCredential: String? { didSet { visibleSecret = nil; copiedCredential = nil } }
    @Published var busy = false
    @Published var error: String?
    @Published var connectionError: String?
    @Published var operation: Operation?
    @Published var result: ResultMessage?
    @Published var showAddCredential = false
    @Published var showSession = false
    @Published var auditOutcome = ""
    @Published var stateDirectory: String
    private var launchedService: Process?
    private var launchedServiceDirectory: String?
    var cli: CLI {
        CLI(binary: Bundle.main.resourceURL!.appendingPathComponent("bin/rekey"), stateDirectory: stateDirectory)
    }
    var unlocked: Bool { status?.unlocked == true }
    var selected: Credential? { credentials.first { $0.id == selectedCredential } }
    init() {
        stateDirectory = UserDefaults.standard.string(forKey: "stateDirectory") ?? NSHomeDirectory() + "/.rekey"
    }
    var needsSetup: Bool {
        !FileManager.default.fileExists(atPath: stateDirectory + "/vault.sqlite3")
    }
    func beginSetup() {
        operation = Operation(title: "创建保险库", detail: "设置并确认密码后，应用会自动创建保险库并启动服务。请保存随后显示的恢复密钥。", arguments: ["init"], confirmSecret: true, sensitiveResult: true, recoveryAllowed: false)
    }
    var desktopReady: Bool { desktopToken != nil && Date() < desktopExpiry && unlocked }
    func requestDesktopLogin() {
        operation = Operation(title: "解锁管理会话", detail: "验证一次后，7 天内可连续保存、查看和复制密钥，重启也能自动解锁。手动锁定会取消此授权。", arguments: ["unlock"])
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
    func revealCredential(_ id: String, copy: Bool) async {
        guard desktopReady, let token = desktopToken else { requestDesktopLogin(); return }
        guard !busy else { return }
        busy = true; error = nil
        defer { busy = false }
        let client = cli
        do {
            let data = try await Task.detached { try client.run(["desktop-reveal", id], input: token + "\n") }.value
            guard unlocked, selectedCredential == id, NSApp.isActive else { return }
            guard let text = String(data: data, encoding: .utf8) else { throw UIError(message: "此凭证不是可显示的 UTF-8 文本。") }
            if copy {
                let board = NSPasteboard.general
                board.clearContents()
                guard board.setString(text, forType: .string) else { throw UIError(message: "写入剪贴板失败。") }
                copiedCredential = id
                let revision = board.changeCount
                DispatchQueue.main.asyncAfter(deadline: .now() + 30) {
                    if board.changeCount == revision { board.clearContents() }
                }
            } else { visibleSecret = text }
        } catch { rejectDesktopSession(error); visibleSecret = nil; self.error = error.localizedDescription }
    }
    func rejectDesktopSession(_ error: Error) {
        let message = error.localizedDescription
        if message.contains("INVALID_UNLOCK_CREDENTIAL") || message.contains("LOCKED") || message.contains("FAULTED") {
            desktopToken = nil; desktopExpiry = .distantPast; visibleSecret = nil; copiedCredential = nil
        }
    }
    func clearCache() {
        desktopToken = nil; visibleSecret = nil; copiedCredential = nil
        credentials = []; actions = []; approvals = []; approvalDetails = nil; policy = nil; audit = nil; selectedCredential = nil
    }
    func changeDirectory(_ path: String) {
        guard !busy else { return }
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
        guard !busy else { return }
        busy = true; error = nil
        let client = CLI(binary: cli.binary, stateDirectory: op.targetDirectory ?? stateDirectory)
        let desktopLogin = op.arguments == ["unlock"]
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
                desktopToken = output; desktopExpiry = Date().addingTimeInterval(7 * 24 * 60 * 60)
                let rememberArgs = recovery ? ["desktop-remember", "--recovery"] : ["desktop-remember"]
                let rememberedData = try await Task.detached { try client.run(rememberArgs, input: body) }.value
                let remembered = try RememberedUnlock.receipt(rememberedData)
                try remembered.save(stateDirectory)
                resumeAttempted = true
            } else { result = ResultMessage(title: op.title + "完成", text: output, sensitive: op.sensitiveResult) }
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
    func startRememberedService() {
        guard status == nil && !needsSetup else { return }
        do { if try RememberedUnlock.load(stateDirectory) != nil { startService() } }
        catch { self.error = error.localizedDescription }
    }
    func startService() {
        guard !busy else { return }
        guard !needsSetup else { beginSetup(); return }
        guard launchedService?.isRunning != true || launchedServiceDirectory != stateDirectory else {
            error = "由此窗口启动的服务仍在运行，请刷新状态。"; return
        }
        let child = Process()
        child.executableURL = cli.binary
        child.arguments = ["--state-dir", stateDirectory, "serve"]
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
        let client = cli
        do {
            let details = try await Task.detached { try client.approvalDetails(item.id) }.value
            guard unlocked, stateDirectory == client.stateDirectory else { return }
            approvalDetails = details
        }
        catch { self.error = error.localizedDescription }
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
    guard fd >= 0 else { throw UIError(message: "无法新建文件，请选择尚不存在的文件名。") }
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    do { try handle.write(contentsOf: data); try handle.synchronize(); try handle.close() }
    catch { throw UIError(message: "文件写入未完成，目标路径可能留下不完整文件：\(url.path)") }
}
func displayDate(_ milliseconds: Int64) -> String {
    Date(timeIntervalSince1970: Double(milliseconds) / 1000).formatted(date: .abbreviated, time: .shortened)
}
