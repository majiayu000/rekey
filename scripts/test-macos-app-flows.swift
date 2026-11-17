import Foundation
import AppKit
import CryptoKit

// Synthetic App flow contracts: device signals, late desktop tokens, a CLI handoff that
// arrives while the App is busy, and the signer preflight before an onboarding key is
// saved. A Python stand-in replaces the CLI; no vault, Keychain or Secure Enclave is used.
extension ConnectionUIContract {
    @MainActor
    static func appFlows() async throws {
        try await deviceSignals()
        try await lateDesktopTokens()
        try await pendingHandoff()
        try await signerPreflight()
        print("PASS: four device signals lock (none when disabled), late resume/remember/login tokens are revoked, a busy-time handoff is applied once idle, and the signer preflight precedes the key save.")
    }

    /// `delay-<name>` holds that command after it touches `<name>-started`; desktop-lock
    /// appends each revoked token to locks.jsonl.
    static func flowFixture() throws -> (URL, URL) {
        let root = try fixture()
        let executable = root.appendingPathComponent("synthetic-cli")
        let script = """
        #!/usr/bin/python3
        import json,pathlib,sys,time
        root=pathlib.Path(__file__).parent
        args=sys.argv[3:]
        lines=sys.stdin.read().splitlines()
        def gate(name):
            (root/(name+'-started')).touch()
            while (root/('delay-'+name)).exists():time.sleep(.01)
        def receipt(fill):sys.stdout.write(str(int(time.time()*1000)+3600000)+'\\n'+fill*64)
        if args==['status']:
            gate('status')
            print(json.dumps({'state':'locked','format_version':27,'runtime_version':'0.5.0-alpha.1','sessions_active':0,'peer_security':'unverified','protection_level':'L0','lab_enabled':False,'rollback':None}))
        elif args[0]=='desktop-login':
            gate('login');sys.stdout.write('a'*64)
        elif args[0]=='desktop-resume':
            gate('resume');receipt('b')
        elif args[0]=='desktop-remember':
            gate('remember');receipt('c')
        elif args[0]=='desktop-lock':
            with open(root/'locks.jsonl','a') as log:log.write(json.dumps({'token':lines[0],'forget':'--forget-remembered' in args})+'\\n')
            print(json.dumps({'locked':True}))
        elif args[:2]==['policy','status']:
            sys.stdout.write((root/'policy.json').read_text())
        elif args[:2]==['connection','preset']:
            print(json.dumps({'name':args[2],'origin':'https://api.example.invalid','auth':{'header_name':'authorization','prefix':'Bearer '},'rules':[{'id':'00000000-0000-4000-8000-0000000000aa','methods':'read','path':'/**','effect':'allow'}],'allowed_headers':[],'fixed_headers':{},'allowed_response_headers':[],'query_allowlist':None,'operations':[]}))
        elif args[:2]==['connection','list']:
            sys.stdout.write((root/'connections.json').read_text())
        elif args[0]=='desktop-add':
            with open(root/'adds.log','a') as log:log.write(args[1]+'\\n')
            print(json.dumps({'id':'00000000-0000-4000-8000-000000000001','label':args[1],'kind':'opaque-token','state':'active','current_version':1}))
        else:sys.exit(2)
        """
        try writePrivateNew(Data(script.utf8), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let policy: [String: Any] = ["vault_id": "00000000-0000-4000-8000-000000000001", "mode": "personal", "bundle_persisted": false, "trust_installed": false, "status": "absent"]
        try JSONSerialization.data(withJSONObject: policy).write(to: root.appendingPathComponent("policy.json"))
        let empty: [String: Any] = ["connections": [], "ssh_keys": [], "derived_credentials": [], "policy_sha256": NSNull(), "expires_at_ms": NSNull()]
        try JSONSerialization.data(withJSONObject: empty).write(to: root.appendingPathComponent("connections.json"))
        return (root, executable)
    }

    static func hold(_ root: URL, _ name: String) throws {
        try? FileManager.default.removeItem(at: root.appendingPathComponent(name + "-started"))
        try Data().write(to: root.appendingPathComponent("delay-" + name))
    }

    static func release(_ root: URL, _ name: String) throws {
        try FileManager.default.removeItem(at: root.appendingPathComponent("delay-" + name))
    }

    @MainActor
    static func eventually(_ label: String, timeout: TimeInterval = 10, _ condition: () throws -> Bool) async throws {
        let deadline = Date().addingTimeInterval(timeout)
        while try !condition() {
            guard Date() < deadline else { throw UIError(message: "FAILED: " + label) }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
    }

    static func revoked(_ root: URL) throws -> [(token: String, forget: Bool)] {
        let file = root.appendingPathComponent("locks.jsonl")
        guard FileManager.default.fileExists(atPath: file.path) else { return [] }
        return try String(contentsOf: file, encoding: .utf8).split(separator: "\n").map {
            let entry = try JSONSerialization.jsonObject(with: Data($0.utf8)) as! [String: Any]
            return (entry["token"] as! String, entry["forget"] as! Bool)
        }
    }

    @MainActor
    static func flowModel(_ root: URL, _ executable: URL, _ settings: DesktopSecuritySettings, home: String? = nil) throws -> (AppModel, CLI, UserDefaults, String) {
        let suite = "rekey.app-flows." + UUID().uuidString
        let preferences = UserDefaults(suiteName: suite)!
        preferences.set(try JSONEncoder().encode(settings), forKey: "desktopSecurity")
        let state = home ?? root.appendingPathComponent("state").path
        let model = AppModel(stateDirectory: state, preferences: preferences, binary: executable)
        model.status = ServiceStatus(state: "unlocked", format_version: 27, runtime_version: "0.5.0-alpha.1", sessions_active: 0, peer_security: "unverified", protection_level: "L1-dev", lab_enabled: false, rollback: nil)
        return (model, CLI(binary: executable, stateDirectory: state), preferences, suite)
    }

    @MainActor
    static func flowLogin(_ model: AppModel, _ client: CLI, remember: Bool = false) async {
        await model.perform(Operation(title: "login", detail: "synthetic", arguments: ["unlock"]), proof: "synthetic-proof",
                            rememberPresence: remember, presenceRevision: model.nativeFlowRevision, client: client)
    }

    @MainActor
    static func settledLocks(_ model: AppModel) async throws {
        try await eventually("synthetic revocation settles: " + (model.error ?? "no failure")) { model.pendingDesktopLocks == 0 }
    }

    // personal-desktop-security: sleep, display sleep, user switch and screen lock each lock
    // the UI by default; signals only reduce access and are ignored when the setting is off.
    @MainActor
    static func deviceSignals() async throws {
        let (root, executable) = try flowFixture()
        // Idle locking is off, so only the posted signals can lock.
        var settings = DesktopSecuritySettings(); settings.idle = .disabled
        let (model, client, preferences, suite) = try flowModel(root, executable, settings)
        settings.lockWithDevice = false
        let (open, _, openPreferences, openSuite) = try flowModel(root, executable, settings)
        defer { preferences.removePersistentDomain(forName: suite); openPreferences.removePersistentDomain(forName: openSuite); cleanup(root) }
        let workspace = NotificationCenter(), distributed = NotificationCenter()
        model.startSecurityMonitoring(workspace: workspace, distributed: distributed)
        let signals = [(workspace, NSWorkspace.willSleepNotification), (workspace, NSWorkspace.screensDidSleepNotification),
                       (workspace, NSWorkspace.sessionDidResignActiveNotification), (distributed, Notification.Name("com.apple.screenIsLocked"))]
        for (center, name) in signals {
            await flowLogin(model, client)
            try require(model.desktopReady, "synthetic login before " + name.rawValue)
            center.post(name: name, object: nil)
            try await eventually(name.rawValue + " locks the desktop") { model.desktopLocked && model.desktopToken == nil && !model.desktopReady }
            try await settledLocks(model)
        }
        let openWorkspace = NotificationCenter(), openDistributed = NotificationCenter()
        open.startSecurityMonitoring(workspace: openWorkspace, distributed: openDistributed)
        await flowLogin(open, client)
        try require(open.desktopReady, "synthetic login with device locking off")
        for (center, name) in signals { (center === workspace ? openWorkspace : openDistributed).post(name: name, object: nil) }
        for _ in 0..<20 { try await Task.sleep(nanoseconds: 10_000_000) }
        try require(open.desktopReady && open.pendingDesktopLocks == 0, "with device locking off the four signals leave the desktop open")
    }

    // personal-desktop-security: late login, resume and remembered grants are revoked when
    // they arrive, and the UI stays locked.
    @MainActor
    static func lateDesktopTokens() async throws {
        let (root, executable) = try flowFixture()
        var settings = DesktopSecuritySettings(); settings.idle = .disabled
        let (model, client, preferences, suite) = try flowModel(root, executable, settings)
        defer { preferences.removePersistentDomain(forName: suite); cleanup(root) }
        let login = String(repeating: "a", count: 64), resumed = String(repeating: "b", count: 64)
        try hold(root, "resume")
        let resume = Task { await model.unlockWithPresence(revision: model.nativeFlowRevision, client: client, read: { _ in String(repeating: "d", count: 64) }) }
        try await eventually("desktop-resume starts") { FileManager.default.fileExists(atPath: root.appendingPathComponent("resume-started").path) }
        model.lockDesktop()
        try release(root, "resume")
        await resume.value; try await settledLocks(model)
        try require(model.desktopLocked && model.desktopToken == nil && revoked(root).contains { $0.token == resumed && !$0.forget }, "a resume that completes after a lock is revoked and the UI stays locked")

        try hold(root, "remember")
        let remember = Task { await flowLogin(model, client, remember: true) }
        try await eventually("desktop-remember starts") { FileManager.default.fileExists(atPath: root.appendingPathComponent("remember-started").path) }
        try require(model.desktopLocked && model.desktopToken == nil, "the UI stays locked until the remembered grant is saved")
        model.lockDesktop()
        try release(root, "remember")
        await remember.value; try await settledLocks(model)
        try require(model.desktopLocked && model.desktopToken == nil && revoked(root).contains { $0.token == login && $0.forget }, "a lock while the grant is issued revokes the login and forgets the late grant")

        try hold(root, "login")
        let changed = Task { await flowLogin(model, client, remember: true) }
        try await eventually("desktop-login starts") { FileManager.default.fileExists(atPath: root.appendingPathComponent("login-started").path) }
        model.clearNativeFlow()
        try release(root, "login")
        await changed.value; try await settledLocks(model)
        try require(model.desktopLocked && model.desktopToken == nil && revoked(root).filter({ $0.token == login && !$0.forget }).count == 1, "a login token that arrives after its context changed is revoked")
    }

    // unified-experiments (desktop correction): `rekey add` may open the App while it is
    // still connecting; the latest valid route waits and passes the usual checks once idle.
    @MainActor
    static func pendingHandoff() async throws {
        let (root, executable) = try flowFixture()
        // NSHomeDirectory() follows CFFIXED_USER_HOME, so the fixture stands in for the
        // default workspace and the real ~/.rekey is never named.
        let previousHome = ProcessInfo.processInfo.environment["CFFIXED_USER_HOME"]
        setenv("CFFIXED_USER_HOME", root.path, 1)
        let state = root.appendingPathComponent(".rekey").path
        let (model, _, preferences, suite) = try flowModel(root, executable, DesktopSecuritySettings(), home: state)
        defer {
            if let previousHome { setenv("CFFIXED_USER_HOME", previousHome, 1) } else { unsetenv("CFFIXED_USER_HOME") }
            preferences.removePersistentDomain(forName: suite); cleanup(root)
        }
        try require(BackgroundService.usesDefaultState(state), "the fixture is the default workspace")
        model.status = nil
        try hold(root, "status")
        let connecting = Task { await model.refresh() }
        try await eventually("the cold-start status read starts") { FileManager.default.fileExists(atPath: root.appendingPathComponent("status-started").path) }
        try require(model.busy, "the App is busy connecting")
        model.openOnboarding(URL(string: "rekey://add/glm?name=first")!)
        model.openOnboarding(URL(string: "rekey://add/anthropic?name=latest&model=claude-synthetic")!)
        try require(model.error == nil && model.onboardingRoute == nil, "a busy App keeps the handoff instead of refusing it")
        try release(root, "status")
        await connecting.value
        var latest = OnboardingAddRequest(provider: "anthropic"); latest.name = "latest"; latest.models = ["claude-synthetic"]
        try require(!model.busy && model.status?.state == "locked" && model.onboardingRoute == .add(latest) && model.addPreset == "anthropic"
                    && model.pendingOnboarding == nil && model.error == nil, "the latest handoff is applied once idle")
        model.onboardingRoute = nil
        model.busy = true
        model.openOnboarding(URL(string: "rekey://add/glm?secret=synthetic")!)
        try require(model.error == "不支持的 Rekey 页面地址。" && model.pendingOnboarding == nil, "a malformed handoff is refused at once")
        model.error = nil
        model.openOnboarding(URL(string: "rekey://setup")!)
        model.result = ResultMessage(title: "synthetic", text: "synthetic")
        model.busy = false
        try require(model.onboardingRoute == nil && model.pendingOnboarding == nil && model.error?.hasPrefix("请先完成当前操作") == true, "a waiting route passes the same checks as one that arrives idle")
    }

    // unified-experiments (desktop correction): a missing or mismatched signer fails before
    // the key is saved; an injected public key exercises the Secure Enclave match.
    @MainActor
    static func signerPreflight() async throws {
        let (root, executable) = try flowFixture()
        var settings = DesktopSecuritySettings(); settings.idle = .disabled
        let (model, client, preferences, suite) = try flowModel(root, executable, settings)
        defer { preferences.removePersistentDomain(forName: suite); cleanup(root) }
        func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
        let signer = UUID().uuidString.lowercased()
        let key = Data([4]) + Data(repeating: 7, count: 64), other = Data([4]) + Data(repeating: 9, count: 64)
        let trust: [String: Any] = ["algorithm": "secure-enclave-p256", "format_version": 1, "public_key": hex(key), "signer_id": signer]
        let digest = hex(Data(SHA256.hash(data: try JSONSerialization.data(withJSONObject: trust, options: [.sortedKeys]))))
        let installed: [String: Any] = ["vault_id": UUID().uuidString.lowercased(), "mode": "personal", "algorithm": "secure-enclave-p256", "trust_sha256": digest,
                                        "bundle_persisted": false, "trust_installed": true, "status": "absent", "signer_id": signer]
        try JSONSerialization.data(withJSONObject: installed).write(to: root.appendingPathComponent("policy.json"))
        let policy = try client.decode(PolicyStatus.self, ["policy", "status"])
        try require(try PolicySigning.available(current: policy, client: client, hardwarePublicKey: { _ in key }) == .secureEnclave, "a Secure Enclave key matching the installed trust is selected")
        try rejected("another hardware key never matches") { _ = try PolicySigning.available(current: policy, client: client, hardwarePublicKey: { _ in other }) }
        model.policy = policy
        await flowLogin(model, client)
        try require(model.desktopReady, "synthetic desktop session")
        func adds() throws -> [String] {
            let file = root.appendingPathComponent("adds.log")
            return FileManager.default.fileExists(atPath: file.path) ? try String(contentsOf: file, encoding: .utf8).split(separator: "\n").map(String.init) : []
        }
        func refused(_ label: String, _ key: OnboardingKey, name: String = "glm-work", hardware: @escaping @Sendable (UUID) throws -> Data?) async throws {
            do {
                _ = try await model.prepareKeyConnection(key, name: name, preset: "glm", models: ["glm-synthetic"], hardwarePublicKey: hardware)
            } catch { return }
            throw UIError(message: "FAILED: " + label + " was accepted")
        }
        let fresh = OnboardingKey.new(label: "synthetic", secret: "synthetic-key-0123456789")
        try await refused("a missing signer", fresh, hardware: { _ in nil })
        try await refused("a mismatched signer", fresh, hardware: { _ in other })
        try require(try adds().isEmpty && model.credentials.isEmpty, "a missing or mismatched signer fails before the key is saved")
        let prepared = try await model.prepareKeyConnection(fresh, name: "glm-work", preset: "glm", models: ["glm-synthetic"], hardwarePublicKey: { _ in key })
        try require(prepared.mode == .secureEnclave && adds() == ["synthetic"] && model.credentials.map(\.id) == [prepared.credential.id]
                    && prepared.connection.name == "glm-work" && prepared.connection.credential_id == prepared.credential.id
                    && prepared.connection.llm?.models == ["glm-synthetic"], "a matching signer lets the key be saved once, then the connection is drafted")
        let base: [String: Any] = ["connections": [try JSONSerialization.jsonObject(with: JSONEncoder().encode(prepared.connection))], "ssh_keys": [], "derived_credentials": [],
                                   "policy_sha256": String(repeating: "ab", count: 32), "expires_at_ms": 4_000_000_000_000]
        try JSONSerialization.data(withJSONObject: base).write(to: root.appendingPathComponent("connections.json"))
        try await refused("a duplicate connection name", .new(label: "again", secret: "synthetic-key-9876543210"), hardware: { _ in key })
        let reused = try await model.prepareKeyConnection(.existing(prepared.credential), name: "glm-second", preset: "glm", models: ["glm-synthetic"], hardwarePublicKey: { _ in key })
        try require(reused.credential.id == prepared.credential.id && adds() == ["synthetic"], "a duplicate name or a reused key saves nothing new")
    }
}
