import Foundation

// agent-call 7.3: the daemon reads the .env file. The App sees variable names, the
// recognition result and public receipts only; no value, proof or backup content.
struct EnvPreview:Decodable {
    struct Entry:Decodable,Identifiable {let key:String;let preset_hint:String?;let unsupported_protocol:String?;var id:String{key}}
    struct Unsupported:Decodable {let line:UInt64;let key:String?}
    let entries:[Entry]
    let unsupported:[Unsupported]
}
struct EnvImportSelection:Encodable {let key:String;let label:String}
struct EnvImportReport:Decodable {
    struct Entry:Decodable {let key:String;let credential:Credential}
    let entries:[Entry]
    let unsupported:[EnvPreview.Unsupported]
}
struct EnvReplacement:Encodable {let key:String;let connection:String;let base_url_variable:String}
/// `backup_git` is the CLI's check: ignored, not-ignored, no-repository or unknown.
struct EnvRewriteReport:Decodable {let backup:String;let backup_git:String}
extension CLI {
    func importSelected(path:String,selections:[EnvImportSelection],proof:String)throws->EnvImportReport {
        let key=try PresenceKey.validated(proof)
        let payload=try JSONEncoder().encode(selections)
        return try JSONDecoder().decode(EnvImportReport.self,from:run(["import",path,"--selections-stdin","--presence","--password-stdin"],input:key+"\n"+String(decoding:payload,as:UTF8.self),redacting:[key]))
    }
    func rewriteImported(path:String,replacements:[EnvReplacement],proof:String)throws->EnvRewriteReport {
        let key=try PresenceKey.validated(proof)
        let payload=try JSONEncoder().encode(replacements)
        return try JSONDecoder().decode(EnvRewriteReport.self,from:run(["import",path,"--rewrite-stdin","--presence","--password-stdin"],input:key+"\n"+String(decoding:payload,as:UTF8.self),redacting:[key]))
    }
}
extension AppModel {
    func previewEnv(_ path:String)async throws->EnvPreview {
        guard !busy,unlocked else{throw UIError(message:"请先解锁并等待当前操作完成。")}
        busy=true;defer{busy=false};let client=cli,revision=nativeFlowRevision
        let preview=try await Task.detached{try client.decode(EnvPreview.self,["import",path,"--dry-run"])}.value
        guard acceptsNativeCompletion(revision,workspace:client.stateDirectory),!Task.isCancelled else{throw UIError(message:"导入预览期间上下文已改变。")}
        return preview
    }
    func importSelected(path:String,selections:[EnvImportSelection],authentication:PresenceReadContext)async throws->EnvImportReport {
        guard !busy,unlocked else{throw UIError(message:"请先解锁并等待当前操作完成。")}
        busy=true;defer{busy=false};let client=cli,revision=nativeFlowRevision
        let (proof,_)=try await readPresenceProof(client:client,revision:revision,read:{id in try authentication.read(vaultID:id){try PresenceKey.read(vaultID:id,context:$0)}})
        let report=try await Task.detached{try client.importSelected(path:path,selections:selections,proof:proof)}.value
        guard acceptsNativeCompletion(revision,workspace:client.stateDirectory),!Task.isCancelled else{throw UIError(message:"导入结果的工作区已改变，请检查凭证列表，勿自动重试。")}
        return report
    }
    func rewriteImported(path:String,replacements:[EnvReplacement],revision:UUID,authentication:PresenceReadContext)async throws->EnvRewriteReport {
        guard !busy,acceptsNativeCompletion(revision,workspace:stateDirectory)else{throw UIError(message:"导入上下文已失效，请重新审阅文件替换。")}
        busy=true;defer{busy=false};let client=cli
        let (proof,_)=try await readPresenceProof(client:client,revision:revision,read:{id in try authentication.read(vaultID:id){try PresenceKey.read(vaultID:id,context:$0)}})
        let report=try await Task.detached{try client.rewriteImported(path:path,replacements:replacements,proof:proof)}.value
        guard acceptsNativeCompletion(revision,workspace:client.stateDirectory),!Task.isCancelled else{throw UIError(message:"文件替换结果未确认，请检查原文件及备份，勿自动重试。")}
        return report
    }
}

/// Per entry (agent-call 7.3): import it, skip it (it stays a plaintext secret), or mark it
/// as not a secret. Skipped and non-secret lines both stay unchanged; only the receipt differs.
enum EnvImportChoice: Hashable, Sendable {
    case skip, importKey, nonSecret
}

struct EnvImportItem: Identifiable {
    let key: String
    /// The preview's preset hint, shown as the recognition result.
    let hint: String?
    /// Set when the local service cannot proxy the entry; it is never imported.
    let unsupportedProtocol: String?
    var choice = EnvImportChoice.skip
    var label: String
    var name: String
    var preset: String
    var origin = ""
    var header = "authorization"
    var prefix = "Bearer "
    var id: String { key }
}

struct EnvImportConnection: Identifiable {
    let key: String
    let label: String
    var baseURLVariable: String
    var definition: ConnectionDefinition
    var id: String { key }
}

enum EnvImportPlan {
    /// API-key presets offered for an import; Git smart HTTP has no .env form.
    static let presets = ConnectionPreset.apiKeyPresets.filter { $0 != "github-git" }

    static func items(_ preview: EnvPreview) -> [EnvImportItem] {
        preview.entries.map { entry in
            EnvImportItem(key: entry.key, hint: entry.preset_hint, unsupportedProtocol: entry.unsupported_protocol,
                          label: entry.key, name: entry.key.lowercased().replacingOccurrences(of: "_", with: "-"),
                          preset: entry.preset_hint.flatMap { presets.contains($0) ? $0 : nil } ?? "generic-bearer")
        }
    }

    /// The default `<X>_BASE_URL` for each selected key, in order: drop `_API_KEY`, `_AUTH_TOKEN`,
    /// `_KEY` or `_TOKEN`, so OPENAI_API_KEY → OPENAI_BASE_URL and ANTHROPIC_AUTH_TOKEN →
    /// ANTHROPIC_BASE_URL, the variables the official SDKs read. A name already taken by a
    /// selected key, a reserved name or an earlier choice falls back to `<KEY>_BASE_URL`.
    static func baseURLVariables(_ keys: [String], reserved: Set<String>) -> [String] {
        var taken = reserved.union(keys)
        return keys.map { key in
            let suffix = ["_API_KEY", "_AUTH_TOKEN", "_KEY", "_TOKEN"].first { key.hasSuffix($0) && key.count > $0.count }
            let preferred = (suffix.map { String(key.dropLast($0.count)) } ?? key) + "_BASE_URL"
            let chosen = taken.contains(preferred) ? key + "_BASE_URL" : preferred
            taken.insert(chosen)
            return chosen
        }
    }

    /// An import signs the whole snapshot, so it keeps the signed base's expiry like the
    /// policy editor; without an unexpired base the default is 24 hours.
    static func defaultExpiry(_ base: ConnectionList, now: Date = Date()) -> Date {
        if let expires = base.expires_at_ms, expires > Int64(now.timeIntervalSince1970 * 1000) {
            return Date(timeIntervalSince1970: Double(expires) / 1000)
        }
        return now.addingTimeInterval(86400)
    }

    /// The backup keeps the original values: delete it, or keep it out of git.
    static func backupNotice(_ report: EnvRewriteReport) -> String {
        switch report.backup_git {
        case "ignored": return "备份 \(report.backup) 含原始密钥，已被 git 忽略；确认替换无误后请删除它。"
        case "not-ignored": return "备份 \(report.backup) 含原始密钥，且未被 git 忽略：请删除它，或把它加入 .gitignore，避免提交。"
        case "no-repository": return "备份 \(report.backup) 含原始密钥：确认替换无误后请删除它；若之后纳入 git，请先把它加入 .gitignore。"
        default: return "备份 \(report.backup) 含原始密钥，未能确认 git 是否忽略它：请删除它，或确认它已加入 .gitignore。"
        }
    }

    static func protocolLabel(_ kind: String) -> String {
        switch kind {
        case "aws": return "AWS 签名"
        case "database": return "数据库或消息队列连接串"
        case "password": return "口令"
        default: return kind
        }
    }

    /// The receipt's account of what stays in the file and why.
    static func report(_ items: [EnvImportItem]) -> [String] {
        var lines: [String] = []
        let unproxyable = items.filter { $0.unsupportedProtocol != nil && $0.choice != .nonSecret }
            .map { "\($0.key)（\(protocolLabel($0.unsupportedProtocol ?? ""))）" }
        if !unproxyable.isEmpty { lines.append("未迁移：协议不支持代理：" + unproxyable.joined(separator: "、") + "，原值保留。") }
        let skipped = items.filter { $0.unsupportedProtocol == nil && $0.choice == .skip }.map(\.key)
        if !skipped.isEmpty { lines.append("已跳过，仍以明文留在文件中：" + skipped.joined(separator: "、")) }
        let plain = items.filter { $0.choice == .nonSecret }.map(\.key)
        if !plain.isEmpty { lines.append("已标记为非密钥，原样保留：" + plain.joined(separator: "、")) }
        return lines
    }
}

extension AppModel {
    /// The review step of an import: the signer preflight, the signed base and each preset
    /// come first and nothing is saved. Unproxyable entries are never prepared.
    func prepareEnvImport(_ items: [EnvImportItem], preview: EnvPreview,
                          hardwarePublicKey: @escaping @Sendable (UUID) throws -> Data? = { try PolicySigning.existingPublicKey(vaultID: $0) })
        async throws -> (mode: PolicySigning.Mode, base: ConnectionList, connections: [EnvImportConnection], expiry: Date) {
        let selected = items.filter { $0.choice == .importKey && $0.unsupportedProtocol == nil }
        guard !selected.isEmpty else { throw UIError(message: "请至少选择一个要导入的密钥。") }
        let revision = nativeFlowRevision
        let mode = try await checkPolicySigner(hardwarePublicKey: hardwarePublicKey)
        let base = try await loadConnectionEditor()
        let reserved = Set(preview.unsupported.compactMap(\.key)).union(preview.entries.filter { $0.unsupported_protocol != nil }.map(\.key))
        let variables = EnvImportPlan.baseURLVariables(selected.map(\.key), reserved: reserved)
        var connections: [EnvImportConnection] = []
        for (item, variable) in zip(selected, variables) {
            let custom = item.preset == "generic-header"
            let preset = try await loadPreset(item.preset, origin: item.origin, header: custom ? item.header : "", prefix: custom ? item.prefix : "")
            connections.append(.init(key: item.key, label: item.label, baseURLVariable: variable,
                                     definition: preset.connection(name: item.name, credentialID: UUID().uuidString.lowercased())))
        }
        guard revision == nativeFlowRevision else { throw UIError(message: "导入工作区已改变，请重新预览。") }
        return (mode, base, connections, EnvImportPlan.defaultExpiry(base))
    }
}
