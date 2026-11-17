import Foundation
import AppKit
import Darwin

// `rekey status`: daemon state plus two separate public labels (v3 §3.3). The
// service identity label never doubles as the protection level.
struct ServiceStatus: Decodable {
    let state: String
    let format_version: Int
    let runtime_version: String
    let sessions_active: Int
    let peer_security: String
    let protection_level: String?
    let lab_enabled: Bool
    let rollback: RollbackContext?
    var identityLabel: String {
        peer_security == "verified_signature" ? "服务签名已校验" : "服务签名未校验"
    }
    // Only the CLI's confirmed floor is shown; an unknown or absent level claims none.
    var protectionLabel: String {
        switch protection_level {
        case "L0": return "L0 · Agent 访问已锁定"
        case "L1-dev": return "L1-dev · 已确认的保护下限"
        default: return "保护状态未确认 · 禁止执行"
        }
    }
    var protectionDetail: String {
        "L0 表示只保存凭据。L1-dev 表示 Agent 接口不返回密钥；当前构建的钥匙串访问和同用户内存隔离仍待设备验收，服务签名通过也不宣称 L1。同用户调用方可伪造标注；调用方规则只能收紧，不能扩大已签署权限。"
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
    private enum CodingKeys: String, CodingKey { case state, format_version, runtime_version, sessions_active, peer_security, protection_level, lab_enabled, rollback }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        state = try c.decode(String.self, forKey: .state)
        format_version = try c.decode(Int.self, forKey: .format_version)
        runtime_version = try c.decode(String.self, forKey: .runtime_version)
        sessions_active = try c.decode(Int.self, forKey: .sessions_active)
        peer_security = try c.decode(String.self, forKey: .peer_security)
        protection_level = try c.decode(String?.self, forKey: .protection_level)
        lab_enabled = try c.decode(Bool.self, forKey: .lab_enabled)
        rollback = try c.decode(RollbackContext?.self, forKey: .rollback)
    }
}

/// The public record rekeyd leaves in the state directory after a failed start
/// (agent-call §6.3, v3 §9.3). The App reads only this record, never the vault,
/// and only a record written after its own start attempt.
struct StartupFailure: Identifiable, Equatable, Sendable {
    enum Kind: Equatable, Sendable { case portInUse(Int), unsupportedFormat, other }
    static let fileName = "startup-failure.json"
    static let byteLimit = 4096
    let stateDirectory: String
    let code: String
    let message: String
    let next: String?
    let port: Int?
    let atMs: Int64
    var id: String { stateDirectory + "#" + code + "#" + String(atMs) }
    var kind: Kind {
        if code == "SERVICE_PORT_IN_USE", let port { return .portInUse(port) }
        return CLI.rebuildCodes.contains(code) ? .unsupportedFormat : .other
    }
    var serviceFile: URL { URL(fileURLWithPath: stateDirectory).appendingPathComponent("service.json") }
    var title: String {
        switch kind {
        case .portInUse: return "本机服务端口已被占用"
        case .unsupportedFormat: return "保险库格式与此版本不兼容"
        case .other: return "服务未能启动"
        }
    }
    var detail: String {
        switch kind {
        case .portInUse(let port):
            return "端口 \(port) 已被另一个保险库或程序占用；服务没有启动，也不会自动换端口。请在下面的 service.json 中写入一个空闲端口，例如 {\"port\":\(port < 65535 ? port + 1 : 7788)}（权限 0600），再点“重试”，并相应修改 SDK 的 base URL。\n" + serviceFile.path
        case .unsupportedFormat:
            return CLI.rebuildText + "\n错误代码：" + code
        case .other:
            return "错误代码：" + code + "\n" + message + (next.map { "\n" + $0 } ?? "") + "\n修正后可点“重试”。"
        }
    }
    var summary: String { title + "\n" + detail }

    private struct Record: Decodable { let code: String; let message: String; let next: String?; let port: Int?; let at_ms: Int64 }
    private static let codeCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")

    /// Owner-only regular file, bounded, never followed through a symlink.
    static func read(stateDirectory: String, notBefore attempt: Date) -> StartupFailure? {
        let path = URL(fileURLWithPath: stateDirectory).appendingPathComponent(fileName).path
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0, info.st_size <= off_t(byteLimit),
              let data = try? handle.read(upToCount: byteLimit + 1) else { return nil }
        return parse(data, stateDirectory: stateDirectory, notBefore: attempt)
    }

    /// A record older than the attempt describes an earlier start and is ignored.
    static func parse(_ data: Data, stateDirectory: String, notBefore attempt: Date) -> StartupFailure? {
        guard data.count <= byteLimit, let record = try? JSONDecoder().decode(Record.self, from: data) else { return nil }
        let notBeforeMs = Int64((attempt.timeIntervalSince1970 * 1000).rounded(.down))
        guard (1...64).contains(record.code.count), record.code.unicodeScalars.allSatisfy(codeCharacters.contains),
              record.message.count <= 512, (record.next?.count ?? 0) <= 512,
              record.port.map({ (1...65535).contains($0) }) ?? true, record.at_ms >= notBeforeMs else { return nil }
        return StartupFailure(stateDirectory: stateDirectory, code: record.code, message: record.message,
                              next: record.next, port: record.port, atMs: record.at_ms)
    }

    @MainActor func revealServiceFile() {
        if FileManager.default.fileExists(atPath: serviceFile.path) {
            NSWorkspace.shared.activateFileViewerSelecting([serviceFile])
        } else {
            NSWorkspace.shared.open(URL(fileURLWithPath: stateDirectory))
        }
    }
}

extension CLI {
    static let rebuildCodes: Set<String> = ["UNSUPPORTED_FORMAT_VERSION", "UNSUPPORTED_VAULT_LAYOUT"]
    static let rebuildText = "此版本无法读取这个格式，不提供迁移。请保留原工作区和备份，在左侧“个人工作区”中选择一个新建的空目录，再创建保险库并重新添加密钥。不要覆盖或清空旧目录；本次操作不会自动重建。"

    /// Read-only guidance for an old vault or backup, keyed by the JSON `code`
    /// of a CLI envelope or the `error_code` of a rekeyd failure event.
    static func rebuildGuidance(stderr: String) -> String? {
        CLIDiagnostics.errorCodes(stderr).contains(where: rebuildCodes.contains) ? rebuildText : nil
    }

    /// Successful stdout plus the structured warning codes the CLI wrote to stderr.
    func runReportingWarnings(_ arguments: [String], input: String, redacting: [String]) throws -> (Data, [String]) {
        let output = try execute(binary, commandArguments(arguments), input: Data(input.utf8), redacting: redacting, operation: arguments)
        return (output.stdout, CLIDiagnostics.warnings(output.stderr))
    }
}

/// Parses only the CLI's machine-readable JSON lines; prose is never matched.
enum CLIDiagnostics {
    private static func objects(_ text: String) -> [[String: Any]] {
        text.split(whereSeparator: \.isNewline).compactMap {
            try? JSONSerialization.jsonObject(with: Data($0.utf8)) as? [String: Any]
        }
    }
    static func errorCodes(_ stderr: String) -> [String] {
        objects(stderr).compactMap { ($0["code"] as? String) ?? (($0["fields"] as? [String: Any])?["error_code"] as? String) }
    }
    static func warnings(_ stderr: Data) -> [String] {
        objects(String(decoding: stderr, as: UTF8.self)).flatMap { ($0["warnings"] as? [String]) ?? [] }
    }
    static func notice(_ warnings: [String]) -> String? {
        warnings.contains("SHORT_CREDENTIAL") ? "凭据已保存，但它短于 16 字节：结果遮蔽对其嵌入编码形式的检测有限。请改用服务商提供的完整密钥。" : nil
    }
}

extension AppModel {
    /// SMAppService reports registration only and launchd hands the App no exit
    /// status, so wait briefly for either the service or this attempt's record.
    func awaitServiceStart(since attempt: Date, directory: String, timeout: TimeInterval = 5) async {
        let deadline = Date().addingTimeInterval(timeout)
        while directory == stateDirectory, !Task.isCancelled {
            await refresh()
            if status != nil { startupFailure = nil; return }
            if showStartupFailure(in: directory, since: attempt) || Date() >= deadline { return }
            try? await Task.sleep(nanoseconds: 200_000_000)
        }
    }

    /// Shows this attempt's record; without one keeps the plain diagnostic.
    @discardableResult
    func showStartupFailure(in directory: String, since attempt: Date, exited diagnostic: String? = nil) -> Bool {
        guard directory == stateDirectory else { return false }
        guard let failure = StartupFailure.read(stateDirectory: directory, notBefore: attempt) else {
            if let diagnostic { error = "服务已退出。\n" + diagnostic }
            return false
        }
        startupFailure = failure
        error = failure.summary
        return true
    }
}
