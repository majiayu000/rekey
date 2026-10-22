import Foundation
import SwiftUI
import AppKit
import CryptoKit

/// SemVer precedence (build metadata ignored); prereleases sort below their release.
struct ReleaseVersion: Comparable {
    let core: [Int], prerelease: [String]
    init?(_ text: String) {
        let base = text.split(separator: "+", maxSplits: 1).first.map(String.init) ?? text
        let parts = base.split(separator: "-", maxSplits: 1, omittingEmptySubsequences: false).map(String.init)
        let fields = parts[0].split(separator: ".", omittingEmptySubsequences: false)
        let core = fields.compactMap { $0.allSatisfy(\.isASCII) ? Int($0) : nil }
        guard fields.count == 3, core.count == 3 else { return nil }
        self.core = core
        prerelease = parts.count == 2 ? parts[1].split(separator: ".", omittingEmptySubsequences: false).map(String.init) : []
        if prerelease.contains(where: \.isEmpty) { return nil }
    }
    static func < (lhs: ReleaseVersion, rhs: ReleaseVersion) -> Bool {
        if lhs.core != rhs.core { return lhs.core.lexicographicallyPrecedes(rhs.core) }
        if lhs.prerelease.isEmpty || rhs.prerelease.isEmpty { return !lhs.prerelease.isEmpty && rhs.prerelease.isEmpty }
        for (left, right) in zip(lhs.prerelease, rhs.prerelease) where left != right {
            switch (Int(left), Int(right)) {
            case let (l?, r?): return l < r
            case (.some, nil): return true
            case (nil, .some): return false
            default: return left < right
            }
        }
        return lhs.prerelease.count < rhs.prerelease.count
    }
}

struct UpdateRelease: Equatable {
    let version: String, page: URL, package: URL, checksum: URL
    var packageName: String { package.lastPathComponent }
}

enum UpdateFeed {
    static let repository = "majiayu000/rekey"
    /// Developer ID Team that signs release packages (see scripts/build-macos-pkg.sh).
    static let teamID = "C5UWZ934C2"
    /// Tags published before the 0.x renumbering; they are older lines, not upgrades.
    static let legacyTags: Set<String> = ["v2.0.0-alpha.1", "v2.0.0-alpha.2", "v3.0.0-alpha.1", "v3.0.0-alpha.2", "v3.0.0-alpha.3", "v3.0.0-alpha.4"]
    static var releasesURL: URL { URL(string: "https://api.github.com/repos/\(repository)/releases?per_page=30")! }
    static var currentVersion: String {
        let info = Bundle.main.infoDictionary
        return info?["RekeyVersion"] as? String ?? info?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    private struct Release: Decodable { let tag_name: String, html_url: URL, draft: Bool, assets: [Asset] }
    private struct Asset: Decodable { let name: String, browser_download_url: URL }

    /// Newest published release (prereleases included) above `current` that ships a macOS pkg and its checksum.
    /// Pre-renumbering v2/v3 tags are skipped; any later major release is still offered.
    static func newest(_ data: Data, current: String) throws -> UpdateRelease? {
        guard let installed = ReleaseVersion(current) else { throw UIError(message: "无法识别当前版本 \(current)。") }
        let prefix = "https://github.com/\(repository)/releases/download/"
        var best: (ReleaseVersion, UpdateRelease)?
        for release in try JSONDecoder().decode([Release].self, from: data) where !release.draft && !legacyTags.contains(release.tag_name) {
            guard release.tag_name.hasPrefix("v"), let version = ReleaseVersion(String(release.tag_name.dropFirst())), installed < version else { continue }
            let name = "rekey-\(release.tag_name)-macos.pkg"
            func asset(_ file: String) -> URL? {
                release.assets.first { $0.name == file && $0.browser_download_url.absoluteString == prefix + release.tag_name + "/" + file }?.browser_download_url
            }
            guard let package = asset(name), let checksum = asset(name + ".sha256") else { continue }
            if best.map({ $0.0 < version }) ?? true {
                best = (version, UpdateRelease(version: String(release.tag_name.dropFirst()), page: release.html_url, package: package, checksum: checksum))
            }
        }
        return best?.1
    }

    /// Reads the `<hex>  <file>` line written by `shasum -a 256` for exactly this file.
    static func expectedDigest(_ text: String, file: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count == 2, fields[1].trimmingCharacters(in: CharacterSet(charactersIn: "*")) == file else { continue }
            let digest = fields[0].lowercased()
            if digest.count == 64, digest.allSatisfy(\.isHexDigit) { return digest }
        }
        return nil
    }

    /// Accepts `pkgutil --check-signature` output only for an Apple-issued Developer ID Installer leaf of `teamID`.
    static func trustedSignature(_ output: String, status: Int32) -> Bool {
        let lines = output.split(whereSeparator: \.isNewline).map { $0.trimmingCharacters(in: .whitespaces) }
        guard status == 0, lines.contains("Status: signed by a developer certificate issued by Apple for distribution"),
              let leaf = lines.first(where: { $0.hasPrefix("1. ") }) else { return false }
        return leaf.hasPrefix("1. Developer ID Installer: ") && leaf.hasSuffix("(\(teamID))")
    }

    nonisolated static func checkSignature(_ package: URL) throws -> (String, Int32) {
        let process = Process(), pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/pkgutil")
        process.arguments = ["--check-signature", package.path]
        process.standardOutput = pipe
        process.standardError = pipe
        try process.run()
        let output = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (String(decoding: output, as: UTF8.self), process.terminationStatus)
    }

    static func sha256(of file: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: file)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let block = try handle.read(upToCount: 1 << 20), !block.isEmpty { hasher.update(data: block) }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}

@MainActor final class Updater: ObservableObject {
    enum State: Equatable { case idle, checking, upToDate, available(UpdateRelease), downloading(UpdateRelease), ready(UpdateRelease, URL), failed(String) }
    @Published private(set) var state = State.idle

    private func fetch(_ url: URL) async throws -> Data {
        var request = URLRequest(url: url)
        request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
        let (data, response) = try await URLSession.shared.data(for: request)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UIError(message: "GitHub 暂时无法访问，请稍后再试。") }
        return data
    }

    func check() {
        state = .checking
        Task {
            do {
                let release = try UpdateFeed.newest(try await fetch(UpdateFeed.releasesURL), current: UpdateFeed.currentVersion)
                state = release.map(State.available) ?? .upToDate
            } catch { state = .failed((error as? UIError)?.message ?? "检查更新失败：\(error.localizedDescription)") }
        }
    }

    func download(_ release: UpdateRelease) {
        state = .downloading(release)
        Task {
            do {
                let text = String(decoding: try await fetch(release.checksum), as: UTF8.self)
                guard let expected = UpdateFeed.expectedDigest(text, file: release.packageName) else { throw UIError(message: "发布缺少有效的 SHA-256 校验值，已停止。") }
                let (temporary, response) = try await URLSession.shared.download(from: release.package)
                guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UIError(message: "安装包下载失败。") }
                let folder = FileManager.default.temporaryDirectory.appendingPathComponent("RekeyUpdate-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false)
                let package = folder.appendingPathComponent(release.packageName)
                try FileManager.default.moveItem(at: temporary, to: package)
                guard try UpdateFeed.sha256(of: package) == expected else {
                    try? FileManager.default.removeItem(at: folder)
                    throw UIError(message: "安装包 SHA-256 与发布校验值不一致，已删除下载文件。")
                }
                let (output, status) = try await Task.detached { try UpdateFeed.checkSignature(package) }.value
                guard UpdateFeed.trustedSignature(output, status: status) else {
                    try? FileManager.default.removeItem(at: folder)
                    throw UIError(message: "安装包不是 Rekey 发布者（Team \(UpdateFeed.teamID)）签名的，已删除下载文件。")
                }
                state = .ready(release, package)
            } catch { state = .failed((error as? UIError)?.message ?? "下载失败：\(error.localizedDescription)") }
        }
    }

    /// Installer and Gatekeeper verify the Developer ID signature and notarization; the App never installs silently.
    /// The App quits once Installer opens so reopening after installation launches the new bundle, not this process.
    func install(_ package: URL) {
        guard NSWorkspace.shared.open(package) else { state = .failed("无法打开安装器。"); return }
        NSApp.terminate(nil)
    }
}

struct UpdateSection: View {
    @StateObject private var updater = Updater()
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text("当前版本 \(UpdateFeed.currentVersion)").font(.system(size: 13)).foregroundStyle(.secondary)
            switch updater.state {
            case .idle: Button("检查更新") { updater.check() }
            case .checking: ProgressView().controlSize(.small)
            case .upToDate: Text("已是最新版本。").font(.system(size: 13)); Button("重新检查") { updater.check() }
            case .available(let release):
                Text("发现新版本 \(release.version)。").font(.system(size: 13, weight: .medium))
                Link("阅读发布说明", destination: release.page).font(.system(size: 13))
                Button("下载并校验") { updater.download(release) }
            case .downloading: HStack { ProgressView().controlSize(.small); Text("正在下载并校验 SHA-256…").font(.system(size: 13)) }
            case .ready(let release, let package):
                Text("\(release.version) 安装包已通过 SHA-256 与发布者签名校验。安装会替换 Rekey.app 和内嵌后台服务。请先点击本页“停止并停用登录启动”，否则旧进程会继续运行。点击下方按钮后 Rekey 会打开安装器并退出；安装完成后重新打开 Rekey，后台服务会以新版本启动，正在进行的 Agent 请求会中断，需要重新解锁。保险库数据不会被删除。跨版本线升级（如 0.4 → 0.5）可能需要新的保险库，请先阅读发布说明。").font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                Button("打开安装器并退出 Rekey") { updater.install(package) }
            case .failed(let message):
                Label(message, systemImage: "exclamationmark.circle").font(.system(size: 13)).foregroundStyle(.red)
                Button("重试") { updater.check() }
            }
        }
    }
}
