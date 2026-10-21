import Foundation
import ServiceManagement
import Darwin

/// One installed app, one current-user LaunchAgent, and the daemon's default state.
/// Registration status does not establish that IPC is ready or the vault is unlocked.
@MainActor
enum BackgroundService {
    static let label = "com.rekey.rekeyd"
    static var isInstalledApplication: Bool {
        Bundle.main.bundleURL.standardizedFileURL.path == "/Applications/Rekey.app"
    }
    static func usesDefaultState(_ directory: String) -> Bool {
        URL(fileURLWithPath: directory).standardizedFileURL ==
            URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent(".rekey").standardizedFileURL
    }
    private static var agent: SMAppService { .agent(plistName: label + ".plist") }

    static var statusDescription: String {
        switch agent.status {
        case .notRegistered: return "尚未启用登录启动"
        case .enabled: return "已启用登录启动；服务运行状态以当前连接为准"
        case .requiresApproval: return "请在系统登录项中允许 Rekey 后台运行"
        case .notFound: return "系统尚未找到后台服务；重新连接时会尝试注册"
        @unknown default: return "系统返回了未知的后台服务状态"
        }
    }
    static var requiresApproval: Bool { agent.status == .requiresApproval }

    /// Called when the user opens the App, completes setup or retries connection.
    /// Ordinary refresh, remembered credentials and agent requests do not register it.
    static func start() async throws {
        let service = agent
        switch service.status {
        case .notRegistered, .notFound:
            // On a fresh install, notFound can mean BTM has no registration record,
            // even when the bundled plist exists. Let register report actual failures.
            try service.register()
        case .enabled:
            let serviceLabel = label
            let status = try await Task.detached { try kickstart(serviceLabel) }.value
            // 113: BTM still reports enabled but launchd has no such job (for example after
            // a manual bootout). Nothing is running, so re-register instead of asking the user.
            if status == notLoadedStatus {
                try await service.unregister()
                try service.register()
            } else if status != 0 {
                throw UIError(message: "系统未能启动已注册服务（launchctl \(status)），请检查登录项设置。")
            }
        case .requiresApproval:
            throw UIError(message: "请先在系统登录项中允许 Rekey 后台运行。")
        @unknown default:
            throw UIError(message: "无法识别系统后台服务状态。")
        }
    }

    /// The caller must first complete the fresh-proof SHUTDOWN IPC operation.
    /// unregister itself terminates a running job, so it is never a restart tool.
    static func unregisterAfterAuthorizedShutdown() async throws {
        let service = agent
        // A manually started daemon may never have registered login startup.
        // The requested final state is already reached after authorized shutdown.
        if service.status == .notRegistered { return }
        try await service.unregister()
    }

    static func openSettings() { SMAppService.openSystemSettingsLoginItems() }

    nonisolated private static let notLoadedStatus: Int32 = 113

    /// Returns launchctl's exit status; only interruption or timeout throws.
    nonisolated private static func kickstart(_ serviceLabel: String) throws -> Int32 {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        // No -k: starting an existing job must never kill its running process.
        process.arguments = ["kickstart", "gui/\(geteuid())/\(serviceLabel)"]
        process.environment = ["PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let timeout = DispatchWorkItem { if process.isRunning { process.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + 10, execute: timeout)
        defer { timeout.cancel() }
        process.waitUntilExit()
        guard process.terminationReason == .exit else {
            throw UIError(message: "系统启动请求被中断或超时，请刷新服务状态。")
        }
        return process.terminationStatus
    }
}
