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
        case .notFound: return "找不到应用内的后台服务声明，请重新安装"
        @unknown default: return "系统返回了未知的后台服务状态"
        }
    }
    static var requiresApproval: Bool { agent.status == .requiresApproval }

    /// Called when the user opens the App, completes setup or retries connection.
    /// Ordinary refresh, remembered credentials and agent requests do not register it.
    static func start() async throws {
        let service = agent
        switch service.status {
        case .notRegistered:
            try service.register()
        case .enabled:
            let serviceLabel = label
            try await Task.detached { try kickstart(serviceLabel) }.value
        case .requiresApproval:
            throw UIError(message: "请先在系统登录项中允许 Rekey 后台运行。")
        case .notFound:
            throw UIError(message: "应用内缺少后台服务声明，请重新安装 Rekey。")
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

    nonisolated private static func kickstart(_ serviceLabel: String) throws {
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
        guard process.terminationStatus == 0 else {
            throw UIError(message: "系统未能启动已注册服务（launchctl \(process.terminationStatus)），请检查登录项设置。")
        }
    }
}
