import Foundation
import Darwin
import CryptoKit
import LocalAuthentication
import SQLite3

// Uses the production App's CLI, Connection and policy models. The software test
// signer proves Swift/Rust interoperability; it does not attest Secure Enclave.
@main
struct ConnectionUIContract {
    @MainActor
    static func main() async throws {
        if CommandLine.arguments == [CommandLine.arguments[0], "--subprocess-boundary-only"] {
            try subprocessBoundary()
            return
        }
        if CommandLine.arguments == [CommandLine.arguments[0], "--privacy-only"] {
            try await privacy()
            try await requestAlerts()
            try await startupRecords()
            return
        }
        if CommandLine.arguments == [CommandLine.arguments[0], "--startup-only"] {
            try await startup()
            return
        }
        guard CommandLine.arguments.count == 2 else {
            throw UIError(message: "usage: test-macos-ui CLI_BINARY | --subprocess-boundary-only | --startup-only")
        }
        try subprocessBoundary()
        try await privacy()
        try await requestAlerts()
        try await startupRecords()
        try await live(binary: URL(fileURLWithPath: CommandLine.arguments[1]))
    }

    static func require(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
        guard try condition() else { throw UIError(message: "FAILED: " + label) }
    }

    static func rejected(_ label: String, _ operation: () throws -> Void) throws {
        do { try operation() } catch { return }
        throw UIError(message: "FAILED: " + label)
    }

    static func fixture() throws -> URL {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appendingPathComponent("rkui-" + UUID().uuidString.prefix(8))
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false,
                                              attributes: [.posixPermissions: 0o700])
        return root
    }

    static func cleanup(_ root: URL) {
        do { try FileManager.default.removeItem(at: root) }
        catch { fputs("test fixture cleanup failed\n", stderr) }
    }

    static func subprocessBoundary() throws {
        let root = try fixture()
        defer { cleanup(root) }
        let executable = root.appendingPathComponent("fixture cli with spaces")
        let script = """
        #!/usr/bin/python3
        import json,os,sys
        args=sys.argv[1:]
        body=sys.stdin.read()
        if args[-1]=='synthetic-error':
            sys.stderr.write(body)
            sys.exit(4)
        if args[-1]=='synthetic-overflow':
            sys.stdout.write('x'*(2*1024*1024+1))
        else:
            print(json.dumps({'args':args,'body':body,'ambient':os.environ.get('REKEY_UI_TEST_AMBIENT')}))
        """
        try writePrivateNew(Data(script.utf8), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        setenv("REKEY_UI_TEST_AMBIENT", "SYNTHETIC-AMBIENT-SECRET", 1)
        defer { unsetenv("REKEY_UI_TEST_AMBIENT") }
        let client = CLI(binary: executable, stateDirectory: root.appendingPathComponent("state with spaces").path)
        let proof = "SYNTHETIC-SUBPROCESS-PROOF", secret = "SYNTHETIC-SUBPROCESS-SECRET"
        let label = "literal $(touch " + root.appendingPathComponent("SHELL-MARKER").path + ")"
        let result = try client.run(["credential", "add", label, "--stdin-secrets"], input: proof + "\n" + secret + "\n")
        let record = try JSONSerialization.jsonObject(with: result) as! [String: Any]
        let argv = record["args"] as! [String]
        try require(argv == ["--state-dir", client.stateDirectory, "credential", "add", label, "--stdin-secrets"], "literal argv preserved")
        try require(record["body"] as? String == proof + "\n" + secret + "\n", "proof and secret travel only through stdin")
        try require(!argv.contains(proof) && !argv.contains(secret), "no secret argv")
        try require(record["ambient"] is NSNull, "ambient credentials removed")
        try require(!FileManager.default.fileExists(atPath: root.appendingPathComponent("SHELL-MARKER").path), "no shell expansion")
        try rejected("invalid status rejected") { _ = try client.decode(ServiceStatus.self, ["status"]) }
        do {
            _ = try client.run(["synthetic-error"], input: proof + "\n" + secret + "\n", redacting: [proof, secret])
            throw UIError(message: "FAILED: synthetic error accepted")
        } catch {
            try require(!error.localizedDescription.contains(proof) && !error.localizedDescription.contains(secret), "secret error output redacted")
            try require(error.localizedDescription.contains("4"), "subprocess error status preserved")
        }
        try rejected("bounded subprocess output") { _ = try client.run(["synthetic-overflow"]) }
        let file = root.appendingPathComponent("private-result")
        try writePrivateNew(Data("synthetic public receipt".utf8), to: file)
        try require((try FileManager.default.attributesOfItem(atPath: file.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private file permissions")
        try rejected("private file cannot overwrite") { try writePrivateNew(Data(), to: file) }
        let alias = root.appendingPathComponent("private-alias")
        try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: file)
        try rejected("private file cannot follow symlink") { try writePrivateNew(Data(), to: alias) }
        print("PASS: production App subprocess argv/stdin/environment, bounded output, error redaction and private-file boundaries.")
    }

    @MainActor
    static func privacy() async throws {
        let root = try fixture()
        let suite = "rekey.privacy-test." + UUID().uuidString
        let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite); cleanup(root) }
        let executable = root.appendingPathComponent("synthetic-cli")
        let fixtureScript = """
        #!/usr/bin/python3
        import json,pathlib,sys,time
        root=pathlib.Path(__file__).parent
        args=sys.argv[3:]
        body=sys.stdin.read()
        if args[0]=='desktop-login':
            (root/'login-started').touch()
            while (root/'delay-login').exists():time.sleep(.01)
            sys.stdout.write('a'*64)
        elif args[0]=='desktop-lock':
            if (root/'locked-reply').exists():
                sys.stderr.write(json.dumps({'code':'LOCKED'},separators=(',',':')))
                sys.exit(5)
            if (root/'fail-lock').exists():
                sys.stderr.write(json.dumps({'code':'IPC_UNAVAILABLE'},separators=(',',':')))
                time.sleep(.2)  # Controlled late failure completion, as on a loaded runner.
                sys.exit(4)
            print(json.dumps({'locked':True}))
        elif args[:2]==['policy','status']:
            print(json.dumps({'vault_id':'00000000-0000-4000-8000-000000000001','mode':'personal','bundle_persisted':False,'trust_installed':False,'status':'absent'}))
        else:sys.exit(2)
        """
        try writePrivateNew(Data(fixtureScript.utf8), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let state = root.appendingPathComponent("state").path
        let model = AppModel(stateDirectory: state, preferences: preferences, binary: executable)
        model.status = ServiceStatus(state: "unlocked", format_version: 27, runtime_version: "0.5.0-alpha.1", sessions_active: 1, peer_security: "unverified", protection_level: "L1-dev", lab_enabled: false, rollback: nil)
        let client = CLI(binary: executable, stateDirectory: state)
        func login() async { await model.perform(Operation(title: "login", detail: "synthetic", arguments: ["unlock"]), proof: "synthetic-proof", presenceRevision: model.nativeFlowRevision, client: client) }
        func settled() async throws {
            let deadline = Date().addingTimeInterval(3)
            while model.pendingDesktopLocks > 0 {
                guard Date() < deadline else { throw UIError(message: "synthetic revocation did not settle: " + (model.error ?? "no failure callback")) }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        try require(model.desktopLocked && !model.unlocked && !model.desktopReady, "startup remains private-locked with an unlocked daemon")
        model.result = ResultMessage(title: "recovery", text: "synthetic-new-vault-recovery", sensitive: true)
        model.clearCache()
        try require(model.result != nil, "an initially locked setup preserves the required recovery-key saving step")
        model.result = nil
        let beforeLock = model.nativeFlowRevision
        model.lockDesktop()
        await model.perform(Operation(title: "stale login", detail: "synthetic", arguments: ["unlock"]), proof: "synthetic-proof", presenceRevision: beforeLock, client: client)
        try require(model.desktopLocked && model.desktopToken == nil && !FileManager.default.fileExists(atPath: root.appendingPathComponent("login-started").path), "a pre-lock form cannot begin a later password command")
        await login()
        try require(model.desktopReady, "explicit password login opens the desktop")
        model.result = ResultMessage(title: "synthetic", text: "synthetic-visible-secret", sensitive: true)
        model.operation = Operation(title: "synthetic", detail: "", arguments: ["backup"])
        model.clearCache(); try await settled()
        try require(model.desktopLocked && model.result == nil && model.operation == nil, "connection loss clears detached sensitive presentation")
        await login()
        model.result = ResultMessage(title: "synthetic", text: "synthetic-visible-secret", sensitive: true)
        model.rejectDesktopSession(UIError(message: "INVALID_UNLOCK_CREDENTIAL")); try await settled()
        try require(model.desktopLocked && model.desktopToken == nil && model.result == nil, "rejected desktop session locks and clears presentation immediately")
        await login()
        model.result = ResultMessage(title: "synthetic", text: "synthetic-visible-secret", sensitive: true)
        let revision = model.nativeFlowRevision
        model.checkDesktopIdle(elapsed: 301)
        try require(model.desktopLocked && model.desktopToken == nil && model.result == nil && model.operation == nil && model.nativeFlowRevision != revision, "idle lock clears sensitive presentation and completion revision")
        try await settled()
        await login(); model.deviceLocked(); try await settled()
        try require(model.desktopLocked, "device signals only lock")
        await login()
        try writePrivateNew(Data(), to: root.appendingPathComponent("locked-reply"))
        model.lockDesktop(); try await settled()
        try require(model.desktopLocked && model.pendingDesktopLocks == 0, "a locked Worker confirms that the old session is already revoked")
        try FileManager.default.removeItem(at: root.appendingPathComponent("locked-reply"))
        try writePrivateNew(Data(), to: root.appendingPathComponent("fail-lock"))
        await login(); model.lockDesktop()
        let failureDeadline = Date().addingTimeInterval(10)
        while model.error?.contains("IPC_UNAVAILABLE") != true {
            guard Date() < failureDeadline else { throw UIError(message: "synthetic revocation failure was not observed") }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        try require(model.pendingDesktopLocks == 1 && model.desktopLocked, "failed server cleanup stays visible and locked")
        await login()
        try require(model.desktopLocked && model.pendingDesktopLocks == 1, "pending cleanup blocks another login")
        try FileManager.default.removeItem(at: root.appendingPathComponent("fail-lock"))
        model.retryDesktopLock(); try await settled()
        try writePrivateNew(Data(), to: root.appendingPathComponent("delay-login"))
        try FileManager.default.removeItem(at: root.appendingPathComponent("login-started"))
        let late = Task { await login() }
        let deadline = Date().addingTimeInterval(3)
        while !FileManager.default.fileExists(atPath: root.appendingPathComponent("login-started").path) {
            guard Date() < deadline else { throw UIError(message: "synthetic login did not start") }
            try await Task.sleep(nanoseconds: 10_000_000)
        }
        model.lockDesktop()
        try FileManager.default.removeItem(at: root.appendingPathComponent("delay-login"))
        await late.value; try await settled()
        try require(model.desktopLocked && model.desktopToken == nil, "late login is revoked instead of reopening the UI")
        await model.unlockWithPresence(revision: model.nativeFlowRevision, client: client, read: { _ in throw UIError(message: "synthetic authentication cancelled") })
        try require(model.desktopLocked && model.desktopToken == nil, "cancelled authentication never opens the UI")
        var disabled = DesktopSecuritySettings(); disabled.idle = .disabled; disabled.lockWithDevice = false
        preferences.set(try JSONEncoder().encode(disabled), forKey: "desktopSecurity")
        let unlocked = AppModel(stateDirectory: state, preferences: preferences, binary: executable)
        unlocked.status = model.status
        await unlocked.perform(Operation(title: "login", detail: "synthetic", arguments: ["unlock"]), proof: "synthetic-proof", client: client)
        unlocked.checkDesktopIdle(elapsed: 999999); unlocked.deviceLocked()
        try require(unlocked.desktopReady, "disabled idle and device settings are respected")
        unlocked.policy = try client.decode(PolicyStatus.self, ["policy", "status"])
        var everyUnlock = DesktopSecuritySettings(); everyUnlock.passwordInterval = .everyUnlock
        await unlocked.saveSecuritySettings(everyUnlock, client: client, forget: { _ in })
        try require(unlocked.desktopLocked && unlocked.securitySettings == everyUnlock && unlocked.pendingDesktopLocks == 0, "settings change revokes session/grant before persisting choices")
        let saved = try JSONDecoder().decode(DesktopSecuritySettings.self, from: preferences.data(forKey: "desktopSecurity")!)
        try require(saved == everyUnlock, "only non-secret choices persist")
        await unlocked.unlockWithPresence(revision: unlocked.nativeFlowRevision, client: client, read: { _ in throw UIError(message: "must not read Keychain") })
        try require(unlocked.desktopLocked && unlocked.error == nil, "every-unlock setting refuses system authentication without reading Keychain")
        let text = " {\"duplicate\":1,\"duplicate\":2}\r\n"
        let bytes = try TeamDraftText.bytes(text)
        try require(bytes == Data(text.utf8), "draft editing preserves exact visible UTF-8 bytes including duplicate keys")
        try rejected("draft byte bound") { _ = try TeamDraftText.bytes(String(repeating: "界", count: 22000)) }
        let draft = try TeamDraftText.empty(version: 3, expiresAt: Date().addingTimeInterval(3600))
        let object = try JSONSerialization.jsonObject(with: Data(draft.utf8)) as! [String: Any]
        try require(object["format_version"] as? Int == 8 && object["version"] as? Int == 3 && object["derived_credentials"] is [Any], "new draft uses current policy8 fields")
        print("PASS: desktop idle/device/disabled controls, failed cleanup, late login, cancelled authentication and exact draft text.")
    }

    final class AlertLog: @unchecked Sendable {
        private let lock = NSLock(); private var items: [RequestAlert] = []; private var asks = 0
        func record(_ alert: RequestAlert) { lock.lock(); items.append(alert); lock.unlock() }
        func ask() { lock.lock(); asks += 1; lock.unlock() }
        var alerts: [RequestAlert] { lock.lock(); defer { lock.unlock() }; return items }
        var requests: Int { lock.lock(); defer { lock.unlock() }; return asks }
    }

    @MainActor
    static func requestAlerts() async throws {
        let root = try fixture()
        let suite = "rekey.request-alerts-test." + UUID().uuidString
        let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite); cleanup(root) }
        let executable = root.appendingPathComponent("synthetic-cli")
        let fixtureScript = """
        #!/usr/bin/python3
        import pathlib,sys
        root=pathlib.Path(__file__).parent
        args=sys.argv[3:]
        name={'access list':'inbox.json','approval pending':'pending.json'}.get(' '.join(args))
        if name is None or not (root/name).exists():sys.exit(2)
        sys.stdout.write((root/name).read_text())
        """
        try writePrivateNew(Data(fixtureScript.utf8), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        let reason = "SYNTHETIC-REQUEST-REASON", requestID = UUID().uuidString.lowercased()
        let inbox = try JSONSerialization.data(withJSONObject: ["requests": [["request_id": requestID, "caller": "codex", "provider": "glm", "connection": NSNull(), "operation": NSNull(), "reason": reason, "created_at_ms": 1, "expires_at_ms": 4000000000000, "status": "PENDING"]], "blocked_callers": []])
        let inboxFile = root.appendingPathComponent("inbox.json")
        try inbox.write(to: inboxFile)
        try Data(#"{"challenges":[]}"#.utf8).write(to: root.appendingPathComponent("pending.json"))
        let state = root.appendingPathComponent("state").path
        let client = CLI(binary: executable, stateDirectory: state)
        let log = AlertLog()
        var badges: [Int] = []
        let model = AppModel(stateDirectory: state, preferences: preferences, binary: executable)
        try require(!model.approvalNotificationsEnabled && preferences.object(forKey: AppModel.requestNotificationsKey) == nil, "fresh install has not decided notifications")
        func poll(_ target: AppModel, grant: Bool = true) async {
            await target.pollPendingRequests(client: client, badge: { badges.append($0) },
                                             request: { log.ask(); return grant }, send: { log.record($0) })
        }
        // The desktop stays locked and no window refresh runs: this is the background path.
        await poll(model)
        try require(model.desktopLocked && log.requests == 1 && model.approvalNotificationsEnabled, "first pending request asks for notification permission once")
        try require(preferences.object(forKey: AppModel.requestNotificationsKey) as? Bool == true, "granted permission persists")
        try require(log.alerts == [RequestAlert(kind: .access, id: requestID)] && badges.last == 1 && model.pendingRequestCount == 1, "locked background App alerts and badges a pending access request")
        try require(log.alerts.allSatisfy { !$0.title.contains(reason) && !$0.body.contains(reason) && !$0.body.contains("glm") }, "alerts carry no request text")
        await poll(model)
        try require(log.alerts.count == 1 && log.requests == 1 && badges.last == 1, "repeated polls neither re-alert nor re-ask")
        try FileManager.default.removeItem(at: inboxFile)
        await poll(model)
        try require(badges.last == 0, "unreadable inbox clears the badge")
        try inbox.write(to: inboxFile)
        await poll(model)
        try require(log.alerts.count == 1 && badges.last == 1, "failed read does not cause a duplicate alert")
        let relaunched = AppModel(stateDirectory: state, preferences: preferences, binary: executable)
        try require(relaunched.approvalNotificationsEnabled, "notification choice survives relaunch")
        await relaunched.setApprovalNotifications(false)
        try require(AppModel(stateDirectory: state, preferences: preferences, binary: executable).approvalNotificationsEnabled == false, "turning alerts off persists")
        let deniedSuite = suite + ".denied", denied = UserDefaults(suiteName: deniedSuite)!
        defer { denied.removePersistentDomain(forName: deniedSuite) }
        let deniedModel = AppModel(stateDirectory: state, preferences: denied, binary: executable)
        await poll(deniedModel, grant: false)
        try require(!deniedModel.approvalNotificationsEnabled && denied.object(forKey: AppModel.requestNotificationsKey) as? Bool == false, "denied permission persists without alerts")
        try require(log.alerts.count == 1 && badges.last == 1, "denied notifications fall back to the Dock badge")
        await poll(deniedModel, grant: false)
        try require(log.requests == 2, "a recorded denial is not asked again")
        print("PASS: background request alerts, persisted notification choice, static alert text and Dock badge fallback.")
    }

    // Synthetic startup-failure records, CLI JSON diagnostics and status labels;
    // no vault is created or read here.
    @MainActor
    static func startupRecords() async throws {
        let root = try fixture()
        let suite = "rekey.startup-records-test." + UUID().uuidString
        let preferences = UserDefaults(suiteName: suite)!
        defer { preferences.removePersistentDomain(forName: suite); cleanup(root) }
        let state = root.appendingPathComponent("state")
        try FileManager.default.createDirectory(at: state, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let attempt = Date(), file = state.appendingPathComponent(StartupFailure.fileName)
        let fresh = Int64(attempt.timeIntervalSince1970 * 1000) + 1
        func write(_ object: [String: Any], mode: Int = 0o600) throws {
            if FileManager.default.fileExists(atPath: file.path) { try FileManager.default.removeItem(at: file) }
            try writePrivateNew(JSONSerialization.data(withJSONObject: object), to: file)
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: file.path)
        }
        func record() -> StartupFailure? { StartupFailure.read(stateDirectory: state.path, notBefore: attempt) }
        let port: [String: Any] = ["code": "SERVICE_PORT_IN_USE", "message": "the local HTTP service port is already in use", "next": "Write a free port to service.json", "port": 7787, "at_ms": fresh]
        try write(port)
        let conflict = record()
        try require(conflict?.kind == .portInUse(7787) && conflict!.detail.contains("7787") && conflict!.detail.contains(state.appendingPathComponent("service.json").path), "port conflict alert names the port and the exact service.json fix")
        try require(StartupFailure.read(stateDirectory: state.path, notBefore: attempt.addingTimeInterval(1)) == nil, "a record from an earlier start attempt is ignored")
        try write(port, mode: 0o644)
        try require(record() == nil, "a record readable by others is ignored")
        try FileManager.default.removeItem(at: file)
        let elsewhere = root.appendingPathComponent("elsewhere.json")
        try writePrivateNew(JSONSerialization.data(withJSONObject: port), to: elsewhere)
        try FileManager.default.createSymbolicLink(at: file, withDestinationURL: elsewhere)
        try require(record() == nil, "a symlinked record is not followed")
        var invalid = port; invalid["message"] = String(repeating: "x", count: 5000)
        try write(invalid); try require(record() == nil, "an oversized record is ignored")
        invalid = port; invalid["code"] = "service port"
        try write(invalid); try require(record() == nil, "a malformed code is ignored")
        invalid = port; invalid.removeValue(forKey: "at_ms")
        try write(invalid); try require(record() == nil, "a record without a timestamp is ignored")
        for code in ["UNSUPPORTED_VAULT_LAYOUT", "UNSUPPORTED_FORMAT_VERSION"] {
            try write(["code": code, "message": "unsupported", "next": NSNull(), "port": NSNull(), "at_ms": fresh])
            let failure = record()
            try require(failure?.kind == .unsupportedFormat && failure!.detail.contains(CLI.rebuildText) && failure!.detail.contains(code), "old format shows only read-only rebuild guidance")
        }
        try write(["code": "STORAGE_UNAVAILABLE", "message": "storage is unavailable", "next": NSNull(), "port": NSNull(), "at_ms": fresh])
        try require(record()?.kind == .other && record()!.summary.contains("STORAGE_UNAVAILABLE"), "other startup failures show their code")

        // The dead `error [CODE]:` prefix is gone; only JSON codes select guidance.
        let envelope = #"{"request_id":null,"code":"UNSUPPORTED_FORMAT_VERSION","message":"unsupported vault format version","next":null,"retryable":false,"approval":null}"#
        try require(CLI.rebuildGuidance(stderr: envelope) == CLI.rebuildText, "CLI envelope code selects rebuild guidance")
        let event = #"{"level":"ERROR","fields":{"event":"rekeyd.command_failed","code":5,"error_code":"UNSUPPORTED_VAULT_LAYOUT","message":"state directory does not contain a supported vault layout"}}"#
        try require(CLI.rebuildGuidance(stderr: #"{"fields":{"event":"runtime.starting"}}"# + "\n" + event) == CLI.rebuildText, "rekeyd error_code selects rebuild guidance")
        try require(CLI.rebuildGuidance(stderr: "error [UNSUPPORTED_FORMAT_VERSION]: unsupported vault format version") == nil && CLI.rebuildGuidance(stderr: #"{"code":"LOCKED"}"#) == nil, "prose and other codes select no guidance")
        let warnings = CLIDiagnostics.warnings(Data((#"{"warnings":["SHORT_CREDENTIAL"]}"# + "\nwarning: prose\n" + #"{"warnings":["L1_DEV_UNVERIFIED_SERVICE"]}"# + "\n").utf8))
        try require(warnings == ["SHORT_CREDENTIAL", "L1_DEV_UNVERIFIED_SERVICE"] && CLIDiagnostics.notice(warnings)?.contains("16 字节") == true && CLIDiagnostics.notice(["L1_DEV_UNVERIFIED_SERVICE"]) == nil, "warning codes come from stderr JSON lines")

        func status(_ fields: [String: Any], without key: String? = nil) throws -> ServiceStatus {
            var object: [String: Any] = ["state": "locked", "format_version": 27, "runtime_version": "0.5.0-alpha.1", "sessions_active": 0, "peer_security": "unverified", "protection_level": "L0", "lab_enabled": false, "rollback": NSNull()]
            for (name, value) in fields { object[name] = value }
            if let key { object.removeValue(forKey: key) }
            return try JSONDecoder().decode(ServiceStatus.self, from: JSONSerialization.data(withJSONObject: object))
        }
        try require(try status([:]).protectionLabel.hasPrefix("L0 ·") && status([:]).identityLabel == "服务签名未校验", "locked shows L0 and a separate identity label")
        let verified = try status(["state": "unlocked", "protection_level": "L1-dev", "peer_security": "verified_signature"])
        try require(verified.protectionLabel.hasPrefix("L1-dev ·") && verified.identityLabel == "服务签名已校验", "a verified signature does not raise the L1-dev floor")
        for fields in [["state": "faulted", "protection_level": NSNull()], ["state": "unlocked", "protection_level": "L2"]] as [[String: Any]] {
            try require(try status(fields).protectionLabel.hasPrefix("保护状态未确认"), "an unknown or absent level claims none")
        }
        try rejected("status without protection_level") { _ = try status([:], without: "protection_level") }

        let executable = root.appendingPathComponent("synthetic-cli")
        let script = """
        #!/usr/bin/python3
        import json,sys
        args=sys.argv[3:]
        lines=sys.stdin.read().splitlines()
        if args==['status']:
            sys.stderr.write(json.dumps({'code':'IPC_UNAVAILABLE'}));sys.exit(7)
        if args[0]=='desktop-login':sys.stdout.write('a'*64)
        elif args[0]=='desktop-lock':print(json.dumps({'locked':True}))
        elif args[0]=='desktop-add':
            print(json.dumps({'id':'00000000-0000-4000-8000-00000000000'+str(len(lines[1])%10),'label':args[1],'kind':'opaque-token','state':'active','current_version':1}))
            if len(lines[1])<16:sys.stderr.write(json.dumps({'warnings':['SHORT_CREDENTIAL']})+'\\n')
        else:sys.exit(2)
        """
        try writePrivateNew(Data(script.utf8), to: executable)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executable.path)
        // SMAppService gives no exit status: the App waits for this attempt's record.
        let model = AppModel(stateDirectory: state.path, preferences: preferences, binary: executable)
        try write(port)
        await model.awaitServiceStart(since: attempt, directory: state.path, timeout: 10)
        try require(model.status == nil && model.startupFailure?.kind == .portInUse(7787) && model.error?.contains("service.json") == true, "a background start surfaces this attempt's port conflict")
        model.startupFailure = nil; model.error = nil
        await model.awaitServiceStart(since: Date().addingTimeInterval(1), directory: state.path, timeout: 0.5)
        try require(model.startupFailure == nil && model.error == nil && model.connectionError != nil, "an earlier attempt's record is not shown as this failure")

        let client = CLI(binary: executable, stateDirectory: state.path)
        model.status = ServiceStatus(state: "unlocked", format_version: 27, runtime_version: "0.5.0-alpha.1", sessions_active: 0, peer_security: "unverified", protection_level: "L1-dev", lab_enabled: false, rollback: nil)
        await model.perform(Operation(title: "login", detail: "synthetic", arguments: ["unlock"]), proof: "synthetic-proof", presenceRevision: model.nativeFlowRevision, client: client)
        try require(model.desktopReady, "synthetic desktop session")
        _ = try await model.saveAPIKey(label: "complete", secret: "synthetic-complete-key-0001", client: client)
        try require(model.warning == nil, "a complete key raises no warning")
        _ = try await model.saveAPIKey(label: "short", secret: "short-key", client: client)
        try require(model.warning == CLIDiagnostics.notice(["SHORT_CREDENTIAL"]) && model.credentials.count == 2, "the App shows the CLI's short-key warning after saving")
        model.lockDesktop()
        let settled = Date().addingTimeInterval(10)
        while model.pendingDesktopLocks > 0 && Date() < settled { try await Task.sleep(nanoseconds: 10_000_000) }
        print("PASS: startup-failure record freshness/ownership/bounds, port/old-format/other alerts, JSON error and warning codes, separate level and identity labels, short-key notice.")
    }

    static func sqlite(_ file: URL, _ sql: String) throws {
        var db: OpaquePointer?
        defer { sqlite3_close(db) }
        guard sqlite3_open(file.path, &db) == SQLITE_OK, sqlite3_exec(db, sql, nil, nil, nil) == SQLITE_OK else {
            throw UIError(message: "fixture SQLite failed: " + String(cString: sqlite3_errmsg(db)))
        }
    }

    /// A synthetic 0.4 layout: vault_header declares format 26 and the vault27 tables are absent.
    static func legacyVault(_ file: URL) throws {
        try sqlite(file, "PRAGMA journal_mode=WAL; CREATE TABLE vault_header (singleton INTEGER PRIMARY KEY CHECK (singleton = 1), format_version INTEGER NOT NULL CHECK (format_version = 26)) STRICT; INSERT INTO vault_header VALUES (1, 26);")
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path)
    }

    @MainActor
    static func startup() async throws {
        let root = try fixture()
        let model = AppModel(stateDirectory: root.appendingPathComponent("state").path)
        let client = model.cli
        let proof = "UI-SYNTHETIC-STARTUP-PROOF"
        defer {
            if model.serviceIsRunning {
                do { _ = try client.run(["shutdown", "--password-stdin"], input: proof + "\n") }
                catch { fputs("startup fixture shutdown failed\n", stderr) }
            }
            cleanup(root)
        }
        await model.connectOnOpen()
        try require(model.needsSetup && !model.serviceIsRunning && model.operation == nil, "opening an empty directory does not initialize a vault")
        await model.perform(Operation(title: "创建保险库", detail: "synthetic setup", arguments: ["init", "--mode", "personal"], sensitiveResult: true), proof: proof)
        try require(model.result?.connectsAfterSaving == true && model.status == nil && !model.serviceIsRunning, "setup waits for recovery-key saving")
        await model.connectOnOpen()
        try require(!model.serviceIsRunning, "opening cannot bypass the recovery-key result")
        model.result = nil
        try writePrivateNew(JSONSerialization.data(withJSONObject: ["port": try reservePort()]), to: URL(fileURLWithPath: client.stateDirectory).appendingPathComponent("service.json"))
        await model.connectOnOpen()
        let deadline = Date().addingTimeInterval(10)
        while model.busy || model.status == nil {
            guard Date() < deadline else { throw UIError(message: "automatic startup failed: " + (model.error ?? model.connectionError ?? "unknown")) }
            try await Task.sleep(nanoseconds: 100_000_000)
            if !model.busy { await model.refresh() }
        }
        try require(model.status?.state == "locked" && !model.desktopReady && model.operation == nil, "opening an existing vault starts service without unlocking or requesting proof")
        let socket = client.stateDirectory + "/runtime/admin.sock"
        let before = try FileManager.default.attributesOfItem(atPath: socket)[.systemFileNumber] as? NSNumber
        await model.connectOnOpen()
        let after = try FileManager.default.attributesOfItem(atPath: socket)[.systemFileNumber] as? NSNumber
        try require(before != nil && before == after && model.error == nil, "repeated opening reuses the live service")
        _ = try client.run(["shutdown", "--password-stdin"], input: proof + "\n")
        try await Task.sleep(nanoseconds: 300_000_000)
        await model.refresh(passive: true)
        try require(model.status == nil && !model.serviceIsRunning, "ordinary refresh does not restart an explicitly stopped service")
        // A held port fails the next start: the App shows this attempt's record and the
        // service.json fix; a retry after the fix starts the service and retires the record.
        let serviceFile = URL(fileURLWithPath: client.stateDirectory).appendingPathComponent("service.json")
        let record = URL(fileURLWithPath: client.stateDirectory).appendingPathComponent(StartupFailure.fileName)
        let (occupant, held) = try occupyPort()
        defer { close(occupant) }
        try FileManager.default.removeItem(at: serviceFile)
        try writePrivateNew(JSONSerialization.data(withJSONObject: ["port": held]), to: serviceFile)
        await model.connectOnOpen()
        // As a person reading the alert would, retry only after the launch's busy window.
        try await waitFor("port conflict alert", model) { $0.startupFailure != nil && !$0.busy }
        try require(model.startupFailure?.kind == .portInUse(held) && model.status == nil && model.error?.contains(serviceFile.path) == true && FileManager.default.fileExists(atPath: record.path), "a held port shows the conflict, the port and the service.json fix")
        try FileManager.default.removeItem(at: serviceFile)
        try writePrivateNew(JSONSerialization.data(withJSONObject: ["port": try reservePort()]), to: serviceFile)
        await model.connectOnOpen()
        try await waitFor("retry after the port fix", model, refreshing: true) { !$0.busy && $0.status != nil }
        try require(model.startupFailure == nil && !FileManager.default.fileExists(atPath: record.path), "a successful retry removes the record")
        _ = try client.run(["shutdown", "--password-stdin"], input: proof + "\n")
        try await waitFor("explicit stop", model, refreshing: true) { !$0.serviceIsRunning }
        // A synthetic 0.4 (vault26) directory gets read-only rebuild guidance; the App never
        // reads, migrates or rebuilds it.
        let legacyDirectory = root.appendingPathComponent("vault26")
        try FileManager.default.createDirectory(at: legacyDirectory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let legacyFile = legacyDirectory.appendingPathComponent("vault.sqlite3")
        try legacyVault(legacyFile)
        let original = try Data(contentsOf: legacyFile)
        let legacy = AppModel(stateDirectory: legacyDirectory.path)
        await legacy.connectOnOpen()
        try await waitFor("old-format alert", legacy) { $0.startupFailure != nil }
        try require(legacy.startupFailure?.kind == .unsupportedFormat && legacy.error?.contains(CLI.rebuildText) == true && legacy.status == nil && legacy.operation == nil && !legacy.needsSetup, "an old vault shows read-only rebuild guidance and offers no setup")
        try require(try Data(contentsOf: legacyFile) == original, "the old vault is neither migrated nor rewritten")
        // A failure before the serve lock (here: a group-readable directory) leaves no record;
        // the App keeps the plain exit diagnostic.
        let malformed = root.appendingPathComponent("invalid")
        try FileManager.default.createDirectory(at: malformed, withIntermediateDirectories: false)
        try writePrivateNew(Data("synthetic-invalid-vault".utf8), to: malformed.appendingPathComponent("vault.sqlite3"))
        let invalid = AppModel(stateDirectory: malformed.path)
        await invalid.connectOnOpen()
        try await waitFor("startup diagnostics", invalid) { $0.error != nil }
        try require(invalid.status == nil && invalid.startupFailure == nil && invalid.error?.hasPrefix("服务已退出") == true, "automatic startup failure remains visible")
        print("PASS: empty-directory setup, automatic locked startup, existing-service reuse, explicit-stop preservation, port-conflict alert and retry, read-only old-format guidance and startup diagnostics.")
    }

    @MainActor
    static func waitFor(_ label: String, _ model: AppModel, refreshing: Bool = false, _ done: (AppModel) -> Bool) async throws {
        let deadline = Date().addingTimeInterval(30)
        while !done(model) {
            guard Date() < deadline else { throw UIError(message: "FAILED: " + label + ": " + (model.error ?? model.connectionError ?? "no diagnostic")) }
            try await Task.sleep(nanoseconds: 100_000_000)
            if refreshing && !model.busy { await model.refresh() }
        }
    }

    static func reservePort() throws -> Int {
        let (descriptor, port) = try occupyPort()
        close(descriptor)
        return port
    }

    /// A listening loopback socket that holds its port until closed.
    static func occupyPort() throws -> (Int32, Int) {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw UIError(message: "fixture port socket failed") }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, length) }
        }
        let inspected = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        guard bound == 0, inspected == 0, listen(descriptor, 1) == 0 else {
            close(descriptor)
            throw UIError(message: "fixture port bind failed")
        }
        return (descriptor, Int(UInt16(bigEndian: address.sin_port)))
    }

    @MainActor
    static func live(binary: URL) async throws {
        let root = try fixture()
        defer { cleanup(root) }
        let state = root.appendingPathComponent("state").path
        let client = CLI(binary: binary, stateDirectory: state)
        let proof = "UI-SYNTHETIC-PERSONAL-PROOF"
        let first = "UI-SYNTHETIC-TOKEN-FIRST", second = "UI-SYNTHETIC-TOKEN-SECOND"
        _ = try client.run(["init", "--mode", "personal", "--password-stdin"], input: proof + "\n")
        try writePrivateNew(JSONSerialization.data(withJSONObject: ["port": try reservePort()]), to: URL(fileURLWithPath: state).appendingPathComponent("service.json"))
        let broker = Process()
        broker.executableURL = binary.deletingLastPathComponent().appendingPathComponent("rekeyd")
        broker.arguments = ["serve", "--state-dir", state]
        broker.environment = ["HOME": NSHomeDirectory(), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"]
        broker.standardInput = FileHandle.nullDevice
        broker.standardOutput = FileHandle.nullDevice
        broker.standardError = FileHandle.nullDevice
        try broker.run()
        defer { if broker.isRunning { broker.terminate() }; broker.waitUntilExit() }
        let deadline = Date().addingTimeInterval(10)
        while !FileManager.default.fileExists(atPath: state + "/runtime/admin.sock") {
            guard Date() < deadline && broker.isRunning else { throw UIError(message: "fixture startup failed") }
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        let lockedStatus = try client.decode(ServiceStatus.self, ["status", "--passive"])
        try require(!lockedStatus.unlocked, "daemon starts locked")
        // The real CLI reports the level and the identity as separate fields.
        try require(lockedStatus.protection_level == "L0" && lockedStatus.protectionLabel.hasPrefix("L0 ·") && ["unverified", "verified_signature"].contains(lockedStatus.peer_security), "real locked status: L0 plus a separate identity label")
        try rejected("locked editing base is an error") { _ = try client.decode(ConnectionList.self, ["connection", "list"]) }
        try rejected("wrong proof rejected") { _ = try client.run(["unlock", "--password-stdin"], input: "synthetic-wrong-proof\n") }
        try await Task.sleep(nanoseconds: 1_100_000_000)
        _ = try client.run(["unlock", "--password-stdin"], input: proof + "\n")
        let unlockedStatus = try client.decode(ServiceStatus.self, ["status", "--passive"])
        try require(unlockedStatus.protection_level == "L1-dev" && unlockedStatus.protectionLabel.hasPrefix("L1-dev ·"), "real unlocked status: the L1-dev floor")
        let absent = try client.decode(ConnectionList.self, ["connection", "list"])
        try require(absent.connections.isEmpty && absent.ssh_keys.isEmpty && absent.derived_credentials.isEmpty && absent.policy_sha256 == nil, "explicit authenticated absent-policy base")
        let label = "UI literal $(touch " + root.appendingPathComponent("SHOULD-NOT-EXIST").path + ")"
        let credential = try JSONDecoder().decode(Credential.self, from: client.run(["credential", "add", label, "--stdin-secrets"], input: proof + "\n" + first + "\n"))
        try require(credential.label == label, "credential label remains literal")
        _ = try client.run(["credential", "rotate", credential.id, "--stdin-secrets"], input: proof + "\n" + second + "\n")
        try require(try client.decode(CredentialList.self, ["credential", "list"]).credentials.first?.current_version == 2, "real rotation visible")
        // The algorithm tag is the production contract; this fixture intentionally
        // uses a software key and never calls Keychain, Touch ID or Secure Enclave.
        // The CLI state path is selected by the fixture, not the real user vault.
        let actualKeyFile = URL(fileURLWithPath: client.stateDirectory).appendingPathComponent("policy-signer-p256.p8")
        _ = try client.policySigner(["software-key", "generate", "--key-file", actualKeyFile.path])
        let signerID = UUID().uuidString.lowercased()
        let trustOutput = try client.policySigner(["software-key", "trust", "--key-file", actualKeyFile.path, "--signer-id", signerID])
        let trustEnvelope = try JSONSerialization.jsonObject(with: trustOutput) as! [String: Any]
        let trust = trustEnvelope["trust"] as! [String: Any]
        let trustJSON = String(decoding: try JSONSerialization.data(withJSONObject: trust), as: UTF8.self)
        _ = try client.run(["policy", "trust", "install", "--stdin-request", "--step-up-stdin"], input: proof + "\n" + trustJSON + "\n")
        let installed = try client.decode(PolicyStatus.self, ["policy", "status"])
        print("CHECK: installed signer before first activation"); fflush(stdout)
        try require(try PolicySigning.available(current: installed, client: client) == .software, "existing basic-mode key selected without Keychain")
        var wrongTrust = try JSONSerialization.jsonObject(with: client.run(["policy", "status"])) as! [String: Any]
        wrongTrust["trust_sha256"] = String(repeating: "0", count: 64)
        let mismatched = try JSONDecoder().decode(PolicyStatus.self, from: JSONSerialization.data(withJSONObject: wrongTrust))
        try rejected("different trust is never replaced") { _ = try PolicySigning.available(current: mismatched, client: client, hardwarePublicKey: { _ in nil }) }
        let holding = actualKeyFile.appendingPathExtension("held")
        try FileManager.default.moveItem(at: actualKeyFile, to: holding)
        try rejected("missing private key is not generated") { _ = try PolicySigning.available(current: installed, client: client, hardwarePublicKey: { _ in nil }) }
        try require(!FileManager.default.fileExists(atPath: actualKeyFile.path), "preflight never generates a key")
        try FileManager.default.moveItem(at: holding, to: actualKeyFile)
        let preset = try client.decode(ConnectionPreset.self, ["connection", "preset", "github-pat"])
        var connection = preset.connection(name: "ui-fixture", credentialID: credential.id)
        connection.bindings = ["owner": ["example"], "repo": ["dedicated-test"]]
        let expires = Int64(Date().addingTimeInterval(600).timeIntervalSince1970 * 1000)
        print("CHECK: signer preflight and unsorted review"); fflush(stdout)
        let preferenceID = "rekey.auth-contract." + UUID().uuidString
        let preferences = UserDefaults(suiteName: preferenceID)!
        defer { preferences.removePersistentDomain(forName: preferenceID) }
        let model = AppModel(stateDirectory: state, preferences: preferences, binary: binary)
        model.status = try client.decode(ServiceStatus.self, ["status", "--passive"])
        model.policy = installed
        let remembered = try client.run(["desktop-remember", "--ttl", "720h"], input: proof + "\n")
        let presenceProof = try PresenceKey.issuedKey(remembered)
        await model.unlockWithPresence(revision: model.nativeFlowRevision, client: client, read: { _ in presenceProof })
        try require(model.desktopReady, "synthetic 30-day grant resumes A1 desktop")
        let otherPreset = try client.decode(ConnectionPreset.self, ["connection", "preset", "generic-bearer", "--origin", "https://example.net"])
        let other = otherPreset.connection(name: "z-last", credentialID: credential.id)
        let draft = try client.personalPolicyDraft(connections: [other, connection], expectedPolicySHA256: nil, expiresAtMs: expires, revision: model.nativeFlowRevision)
        try require(draft.connections == [connection, other], "unsorted input returns exact signed definitions")
        try draft.validate(current: installed)
        do {
            try await model.activatePersonalPolicy(draft, proof: "", recovery: false, presence: true, client: client,
                readPresence: { _, _ in throw UIError(message: "synthetic authentication cancellation") })
            throw UIError(message: "FAILED: cancelled presence activated")
        } catch { try require(error.localizedDescription == "synthetic authentication cancellation", "cancelled presence stops activation") }
        try require(try client.decode(PolicyStatus.self, ["policy", "status"]).bundle_persisted == false, "cancel leaves policy absent")
        let desktopToken = model.desktopToken!
        do {
            try await model.activatePersonalPolicy(draft, proof: "", recovery: false, presence: true, client: client,
                readPresence: { _, _ in desktopToken })
            throw UIError(message: "FAILED: A1 desktop token activated policy")
        } catch { try require(error.localizedDescription.contains("INVALID_UNLOCK_CREDENTIAL"), "A1 session is rejected as A2 presence") }
        try require(try client.decode(PolicyStatus.self, ["policy", "status"]).bundle_persisted == false, "rejected proof leaves policy absent")
        try await model.activatePersonalPolicy(draft, proof: "", recovery: false, presence: true, client: client,
            readPresence: { _, _ in presenceProof })
        let active = try client.decode(ConnectionList.self, ["connection", "list"])
        try require(active.connections == [connection, other] && active.policy_sha256 == draft.metadata.policy_sha256, "App software signature activates exact reviewed connections")
        let afterSigning = try client.decode(PolicyStatus.self, ["policy", "status"])
        try require(afterSigning.trust_sha256 == installed.trust_sha256, "signing retains installed trust")
        print("CHECK: cancelled/A1 proof rejected; fresh presence activated without password; trust unchanged"); fflush(stdout)
        let capabilities = try client.run(["list", "--json"])
        let inventory = try JSONSerialization.jsonObject(with: capabilities) as! [String: Any]
        try require((inventory["connections"] as? [[String: Any]])?.first?["connection"] as? String == "ui-fixture", "token-free discovery")
        try require(inventory["derived_credentials"] as? [Any] != nil, "T1 discovery projection is explicit")
        _ = try client.run(["describe", "github.list_issues"])
        let dryRun = try client.run(["call", "github.list_issues", "--owner", "example", "--repo", "dedicated-test", "--dry-run"])
        try require(!String(decoding: dryRun, as: UTF8.self).contains(second), "dry-run keeps real credential private")
        let scan = try client.run(["scan", "--stdin"], input: "no credential here\n")
        try require(try JSONSerialization.jsonObject(with: scan) as? [Any] != nil, "real scan public projection")
        let auditData = try client.run(["audit", "list"])
        let audit = try JSONDecoder().decode(AuditPage.self, from: auditData)
        try require(!audit.events.isEmpty && audit.events.contains { $0.request_context?.connection == "ui-fixture" }, "Connection audit decoded by production App")
        for secret in [proof, first, second] {
            for output in [capabilities, dryRun, auditData] {
                try require(!String(decoding: output, as: UTF8.self).contains(secret), "public result omits synthetic secrets")
            }
        }
        let backup = root.appendingPathComponent("backup.sqlite")
        let receiptData = try client.run(["backup", "--output", backup.path, "--password-stdin"], input: proof + "\n")
        _ = try JSONDecoder().decode(BackupReceipt.self, from: receiptData)
        let receipt = try JSONSerialization.jsonObject(with: receiptData) as! [String: Any]
        // Restore advances the shared vault's protected generation. Finish the
        // source lifecycle first so the fixture never continues a stale instance.
        _ = try client.run(["credential", "revoke", credential.id, "--password-stdin"], input: proof + "\n")
        try require(!(try client.decode(CredentialList.self, ["credential", "list"])).credentials[0].active, "real revocation")
        let short = "UI-SHORT-KEY"
        let (saved, warnings) = try client.runReportingWarnings(["credential", "add", "UI short", "--stdin-secrets"], input: proof + "\n" + short + "\n", redacting: [proof, short])
        try require(try JSONDecoder().decode(Credential.self, from: saved).label == "UI short" && warnings.contains("SHORT_CREDENTIAL") && CLIDiagnostics.notice(warnings) != nil, "the real CLI reports a short key to the App instead of discarding it")
        _ = try client.run(["lock"])
        try rejected("locked mutation denied") { _ = try client.run(["credential", "add", "blocked", "--stdin-secrets"], input: proof + "\n" + first + "\n") }
        _ = try client.decode(AuditPage.self, ["audit", "list"])
        _ = try client.run(["shutdown", "--password-stdin"], input: proof + "\n")
        broker.waitUntilExit()
        let restored = CLI(binary: binary, stateDirectory: root.appendingPathComponent("restored").path)
        let restoreArguments = ["restore", "--input", backup.path, "--sha256", receipt["sha256_hex"] as! String]
        let preview = try JSONDecoder().decode(RollbackContext.self, from: restored.run(restoreArguments + ["--inspect", "--password-stdin"], input: proof + "\n"))
        _ = try JSONDecoder().decode(RestoreReceipt.self, from: restored.run(restoreArguments + ["--expected-context", try preview.encodedArgument(), "--password-stdin"], input: proof + "\n"))
        // An old backup is refused with read-only rebuild guidance; nothing is restored or rewritten.
        let legacyBackup = root.appendingPathComponent("vault26-backup.sqlite3")
        try legacyVault(legacyBackup)
        let legacyBytes = try Data(contentsOf: legacyBackup)
        let legacyHash = SHA256.hash(data: legacyBytes).map { String(format: "%02x", $0) }.joined()
        let legacyTarget = CLI(binary: binary, stateDirectory: root.appendingPathComponent("restored-legacy").path)
        do {
            _ = try legacyTarget.run(["restore", "--input", legacyBackup.path, "--sha256", legacyHash, "--inspect", "--password-stdin"], input: proof + "\n", redacting: [proof])
            throw UIError(message: "FAILED: old backup inspected")
        } catch { try require(error.localizedDescription.contains(CLI.rebuildText), "an old backup shows the read-only rebuild guidance") }
        try require(try Data(contentsOf: legacyBackup) == legacyBytes && !FileManager.default.fileExists(atPath: legacyTarget.stateDirectory), "the old backup is untouched and nothing is restored")
        print("PASS: real Swift/CLI/Broker Connection signing, discovery, dry-run, credential lifecycle, audit, backup/restore, status labels, short-key warning and old-backup guidance. Software signer only; hardware acceptance remains separate.")
    }
}
