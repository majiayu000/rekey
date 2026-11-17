import Foundation

// `rekey add` hands only public connection options to the App in a rekey:// URL
// (unified-experiments, personal desktop correction); no secret or proof travels in it.
struct OnboardingAddRequest: Equatable, Hashable, Sendable {
    let provider: String
    var name: String? = nil
    var label: String? = nil
    var credentialID: String? = nil
    var origin: String? = nil
    var header: String? = nil
    var prefix: String? = nil
    var validDays: Int? = nil
    var models: [String] = []
}

enum OnboardingRoute: Equatable, Hashable, Sendable {
    case setup
    case add(OnboardingAddRequest)
    case importEnv(String)
    case oauth(String)
    var rawValue: String { switch self { case .setup:return "rekey://setup";case .add(let request):return "rekey://add/"+request.provider;case .importEnv(let path):return "import:"+path;case .oauth(let connection):return "oauth:"+connection } }
    init?(url: URL) {
        guard url.scheme == "rekey", url.fragment == nil, url.user == nil, url.password == nil, url.port == nil, url.absoluteString.utf8.count <= 8192 else { return nil }
        if url.host == "import",url.path.isEmpty,let components=URLComponents(url:url,resolvingAgainstBaseURL:false),let query=components.queryItems,query.count==1,query[0].name=="path",let path=query[0].value,path.hasPrefix("/"),!path.contains("\0") {self = .importEnv(path);return}
        if url.host == "oauth",url.path.isEmpty,let query=URLComponents(url:url,resolvingAgainstBaseURL:false)?.queryItems,query.count==1,query[0].name=="connection",let connection=query[0].value,!connection.isEmpty,connection.utf8.count<=100,connection.utf8.allSatisfy({$0>=48 && $0<=57 || $0>=65 && $0<=90 || $0>=97 && $0<=122 || [45,46,95].contains($0)}) {self = .oauth(connection);return}
        if url.host == "setup", url.query == nil, url.path.isEmpty { self = .setup; return }
        let presets = ConnectionPreset.apiKeyPresets+OAuthSetup.presets
        guard url.host == "add", presets.contains(String(url.path.dropFirst())),url.path.hasPrefix("/") else { return nil }
        var request = OnboardingAddRequest(provider: String(url.path.dropFirst()))
        var seen = Set<String>()
        for item in URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? [] {
            guard let value = item.value, !value.contains("\0"), item.name == "model" || seen.insert(item.name).inserted else { return nil }
            switch item.name {
            case "name": request.name = value
            case "label": request.label = value
            case "credential_id": guard UUID(uuidString: value) != nil else { return nil }; request.credentialID = value.lowercased()
            case "origin": request.origin = value
            case "header": request.header = value
            case "prefix": request.prefix = value
            case "valid_days": guard let days = Int(value), (1...365).contains(days) else { return nil }; request.validDays = days
            case "model": request.models.append(value)
            default: return nil
            }
        }
        self = .add(request)
    }
}

/// The key of one App onboarding step: one saved earlier in this flow, or a new value.
enum OnboardingKey {
    case existing(Credential)
    case new(label: String, secret: String)
}

extension AppModel {
    /// A handoff can arrive while the App is still connecting at cold start. The latest
    /// valid route then waits and, once `busy` ends, passes the same checks as a route
    /// that arrives while idle; a route that fails them is reported, never retried.
    func openOnboarding(_ url: URL) {
        guard let route = OnboardingRoute(url: url) else { error = "不支持的 Rekey 页面地址。"; return }
        if busy { pendingOnboarding = route } else { showOnboarding(route) }
    }
    /// Called when `busy` ends.
    func applyPendingOnboarding() {
        guard !busy, let route = pendingOnboarding else { return }
        pendingOnboarding = nil
        showOnboarding(route)
    }
    private func showOnboarding(_ route: OnboardingRoute) {
        guard operation == nil, result == nil, !showPolicyDraft, !showTemplate,
              BackgroundService.usesDefaultState(stateDirectory), oidcProfileFile == nil, oidcSessionFile == nil else {
            error = "请先完成当前操作，并在默认保险库工作区打开设置或接入页面。"; return
        }
        clearNativeFlow(); onboardingConnection = nil; onboardingCommand = nil; onboardingRoute = route
        if case .add(let request) = route { addPreset = request.provider }
    }

    /// Finds the existing signer that matches the installed trust, with no authentication
    /// prompt and no key generation. Contracts inject the Secure Enclave public key.
    func checkPolicySigner(hardwarePublicKey: @escaping @Sendable (UUID) throws -> Data? = { try PolicySigning.existingPublicKey(vaultID: $0) }) async throws -> PolicySigning.Mode {
        guard !busy, unlocked else { throw UIError(message: "请先解锁并等待当前操作完成。") }
        busy = true; defer { busy = false }
        let client = cli, revision = nativeFlowRevision
        let mode = try await Task.detached {
            try PolicySigning.available(current: client.decode(PolicyStatus.self, ["policy", "status"]), client: client, hardwarePublicKey: hardwarePublicKey)
        }.value
        guard acceptsNativeCompletion(revision, workspace: client.stateDirectory) else { throw UIError(message: "签名检查期间工作区已改变，请重试。") }
        return mode
    }

    /// One onboarding step for an API key. The signer preflight, the preset and the signed
    /// base come first and the key is saved last, so a missing or mismatched signer, a
    /// refused preset or a duplicate connection name saves nothing.
    func prepareKeyConnection(_ key: OnboardingKey, name: String, preset: String, origin: String = "", header: String = "", prefix: String = "",
                              models: [String] = [],
                              hardwarePublicKey: @escaping @Sendable (UUID) throws -> Data? = { try PolicySigning.existingPublicKey(vaultID: $0) })
        async throws -> (mode: PolicySigning.Mode, credential: Credential, connection: ConnectionDefinition) {
        let mode = try await checkPolicySigner(hardwarePublicKey: hardwarePublicKey)
        let custom = preset == "generic-header"
        let definition = try await loadPreset(preset, origin: origin, header: custom ? header : "", prefix: custom ? prefix : "")
        let base = try await loadConnectionEditor()
        guard !base.connections.contains(where: { $0.name == name }) else { throw UIError(message: "已有同名连接，请在授权页编辑现有规则。") }
        let credential: Credential
        switch key {
        case .existing(let saved): credential = saved
        case .new(let label, let secret): credential = try await saveAPIKey(label: label, secret: secret)
        }
        return (mode, credential, definition.connection(name: name, credentialID: credential.id, models: models))
    }
}
