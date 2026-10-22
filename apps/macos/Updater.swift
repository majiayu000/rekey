import Foundation
import SwiftUI
import AppKit

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
    let version: String, page: URL
}

/// Checks GitHub Releases for a newer version and only links to its release page;
/// downloading and installing stay with the user, Installer and Gatekeeper.
enum UpdateFeed {
    static let repository = "majiayu000/rekey"
    /// Tags published before the 0.x renumbering; they are older lines, not upgrades.
    static let legacyTags: Set<String> = ["v2.0.0-alpha.1", "v2.0.0-alpha.2", "v3.0.0-alpha.1", "v3.0.0-alpha.2", "v3.0.0-alpha.3", "v3.0.0-alpha.4"]
    static var releasesURL: URL { URL(string: "https://api.github.com/repos/\(repository)/releases?per_page=30")! }
    static var currentVersion: String {
        let info = Bundle.main.infoDictionary
        return info?["RekeyVersion"] as? String ?? info?["CFBundleShortVersionString"] as? String ?? "0.0.0"
    }

    private struct Release: Decodable { let tag_name: String, html_url: URL, draft: Bool, assets: [Asset] }
    private struct Asset: Decodable { let name: String }

    /// Newest published release (prereleases included) above `current` that ships a macOS pkg.
    /// Pre-renumbering v2/v3 tags are skipped; any later major release is still offered.
    /// Only this repository's own release tag page is ever opened.
    static func newest(_ data: Data, current: String) throws -> UpdateRelease? {
        guard let installed = ReleaseVersion(current) else { throw UIError(message: "无法识别当前版本 \(current)。") }
        var best: (ReleaseVersion, UpdateRelease)?
        for release in try JSONDecoder().decode([Release].self, from: data) where !release.draft && !legacyTags.contains(release.tag_name) {
            guard release.tag_name.hasPrefix("v"), let version = ReleaseVersion(String(release.tag_name.dropFirst())), installed < version,
                  release.html_url.absoluteString == "https://github.com/\(repository)/releases/tag/\(release.tag_name)",
                  release.assets.contains(where: { $0.name == "rekey-\(release.tag_name)-macos.pkg" }) else { continue }
            if best.map({ $0.0 < version }) ?? true {
                best = (version, UpdateRelease(version: String(release.tag_name.dropFirst()), page: release.html_url))
            }
        }
        return best?.1
    }
}

@MainActor final class Updater: ObservableObject {
    enum State: Equatable { case idle, checking, upToDate, available(UpdateRelease), failed(String) }
    @Published private(set) var state = State.idle

    func check() {
        state = .checking
        Task {
            do {
                var request = URLRequest(url: UpdateFeed.releasesURL)
                request.setValue("application/vnd.github+json", forHTTPHeaderField: "Accept")
                let (data, response) = try await URLSession.shared.data(for: request)
                guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw UIError(message: "GitHub 暂时无法访问，请稍后再试。") }
                state = try UpdateFeed.newest(data, current: UpdateFeed.currentVersion).map(State.available) ?? .upToDate
            } catch { state = .failed((error as? UIError)?.message ?? "检查更新失败：\(error.localizedDescription)") }
        }
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
                Text("发现新版本 \(release.version)。请在发布页阅读说明并下载 macOS 安装包；安装前先在本页“停止并停用登录启动”并退出 Rekey。跨版本线升级（如 0.4 → 0.5）可能需要新的保险库。").font(.system(size: 13)).fixedSize(horizontal: false, vertical: true)
                Button("打开发布页") { NSWorkspace.shared.open(release.page) }
            case .failed(let message):
                Label(message, systemImage: "exclamationmark.circle").font(.system(size: 13)).foregroundStyle(.red)
                Button("重试") { updater.check() }
            }
        }
    }
}
