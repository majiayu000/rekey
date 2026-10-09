import Foundation
import Darwin
import CryptoKit

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
        model.status = ServiceStatus(state: "unlocked", format_version: 27, runtime_version: "0.5.0-alpha.1", sessions_active: 1, peer_security: "same-user", lab_enabled: false, rollback: nil)
        let client = CLI(binary: executable, stateDirectory: state)
        func login() async { await model.perform(Operation(title: "login", detail: "synthetic", arguments: ["unlock"]), proof: "synthetic-proof", client: client) }
        func settled() async throws {
            let deadline = Date().addingTimeInterval(3)
            while model.pendingDesktopLocks > 0 {
                guard Date() < deadline else { throw UIError(message: "synthetic revocation did not settle") }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        try require(model.desktopLocked && !model.unlocked && !model.desktopReady, "startup remains private-locked with an unlocked daemon")
        await login()
        try require(model.desktopReady, "explicit password login opens the desktop")
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
        try await Task.sleep(nanoseconds: 100_000_000)
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
        let malformed = root.appendingPathComponent("invalid")
        try FileManager.default.createDirectory(at: malformed, withIntermediateDirectories: false)
        try writePrivateNew(Data("synthetic-invalid-vault".utf8), to: malformed.appendingPathComponent("vault.sqlite3"))
        let invalid = AppModel(stateDirectory: malformed.path)
        await invalid.connectOnOpen()
        try await Task.sleep(nanoseconds: 1_000_000_000)
        try require(invalid.status == nil && invalid.error != nil, "automatic startup failure remains visible")
        print("PASS: empty-directory setup, automatic locked startup, existing-service reuse, explicit-stop preservation and startup diagnostics.")
    }

    static func reservePort() throws -> Int {
        let descriptor = socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw UIError(message: "fixture port socket failed") }
        defer { close(descriptor) }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, length) }
        }
        guard bound == 0 else { throw UIError(message: "fixture port bind failed") }
        let inspected = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        guard inspected == 0 else { throw UIError(message: "fixture port query failed") }
        return Int(UInt16(bigEndian: address.sin_port))
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
        try require(!(try client.decode(ServiceStatus.self, ["status", "--passive"])).unlocked, "daemon starts locked")
        try rejected("locked editing base is an error") { _ = try client.decode(ConnectionList.self, ["connection", "list"]) }
        try rejected("wrong proof rejected") { _ = try client.run(["unlock", "--password-stdin"], input: "synthetic-wrong-proof\n") }
        try await Task.sleep(nanoseconds: 1_100_000_000)
        _ = try client.run(["unlock", "--password-stdin"], input: proof + "\n")
        let absent = try client.decode(ConnectionList.self, ["connection", "list"])
        try require(absent.connections.isEmpty && absent.ssh_keys.isEmpty && absent.derived_credentials.isEmpty && absent.policy_sha256 == nil, "explicit authenticated absent-policy base")
        let label = "UI literal $(touch " + root.appendingPathComponent("SHOULD-NOT-EXIST").path + ")"
        let credential = try JSONDecoder().decode(Credential.self, from: client.run(["credential", "add", label, "--stdin-secrets"], input: proof + "\n" + first + "\n"))
        try require(credential.label == label, "credential label remains literal")
        _ = try client.run(["credential", "rotate", credential.id, "--stdin-secrets"], input: proof + "\n" + second + "\n")
        try require(try client.decode(CredentialList.self, ["credential", "list"]).credentials.first?.current_version == 2, "real rotation visible")
        // The algorithm tag is the production contract; this fixture intentionally
        // uses a software key and never calls Keychain, Touch ID or Secure Enclave.
        let signer = P256.Signing.PrivateKey()
        let trust: [String: Any] = ["format_version": 1, "signer_id": UUID().uuidString.lowercased(), "algorithm": "secure-enclave-p256",
                                  "public_key": signer.publicKey.x963Representation.map { String(format: "%02x", $0) }.joined()]
        let trustJSON = String(decoding: try JSONSerialization.data(withJSONObject: trust), as: UTF8.self)
        _ = try client.run(["policy", "trust", "install", "--stdin-request", "--step-up-stdin"], input: proof + "\n" + trustJSON + "\n")
        let preset = try client.decode(ConnectionPreset.self, ["connection", "preset", "github-pat"])
        var connection = preset.connection(name: "ui-fixture", credentialID: credential.id)
        connection.bindings = ["owner": ["example"], "repo": ["dedicated-test"]]
        let expires = Int64(Date().addingTimeInterval(600).timeIntervalSince1970 * 1000)
        let draft = try client.personalPolicyDraft(connections: [connection], expectedPolicySHA256: nil, expiresAtMs: expires, revision: UUID())
        try require(draft.connections == [connection], "displayed definitions equal actual sign bytes")
        try draft.validate(current: client.decode(PolicyStatus.self, ["policy", "status"]))
        let signature = try signer.signature(for: draft.signBytes).derRepresentation.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        _ = try client.activatePersonalPolicy(draft, signature: signature, proof: proof, recovery: false)
        let active = try client.decode(ConnectionList.self, ["connection", "list"])
        try require(active.connections == [connection] && active.policy_sha256 == draft.metadata.policy_sha256, "real signed Connection activation")
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
        _ = try client.run(["lock"])
        try rejected("locked mutation denied") { _ = try client.run(["credential", "add", "blocked", "--stdin-secrets"], input: proof + "\n" + first + "\n") }
        _ = try client.decode(AuditPage.self, ["audit", "list"])
        _ = try client.run(["shutdown", "--password-stdin"], input: proof + "\n")
        broker.waitUntilExit()
        let restored = CLI(binary: binary, stateDirectory: root.appendingPathComponent("restored").path)
        let restoreArguments = ["restore", "--input", backup.path, "--sha256", receipt["sha256_hex"] as! String]
        let preview = try JSONDecoder().decode(RollbackContext.self, from: restored.run(restoreArguments + ["--inspect", "--password-stdin"], input: proof + "\n"))
        _ = try JSONDecoder().decode(RestoreReceipt.self, from: restored.run(restoreArguments + ["--expected-context", try preview.encodedArgument(), "--password-stdin"], input: proof + "\n"))
        print("PASS: real Swift/CLI/Broker Connection signing, discovery, dry-run, credential lifecycle, audit and backup/restore. Software signer only; hardware acceptance remains separate.")
    }
}
