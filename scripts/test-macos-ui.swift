import Foundation
import Darwin

// Compile with apps/macos/Model.swift; exercises the same subprocess boundary as the app.
@main
struct UIContract {
    @MainActor
    static func main() throws {
        guard CommandLine.arguments.count == 2 else { fatalError("usage: test-macos-ui CLI_BINARY") }
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("rkui-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { do { try FileManager.default.removeItem(at: root) } catch { fputs("test cleanup failed\n", stderr) } }
        let binary = URL(fileURLWithPath: CommandLine.arguments[1])
        let state = root.appendingPathComponent("state").path
        let client = CLI(binary: binary, stateDirectory: state)
        let password = "UI-SYNTHETIC-PROOF-ONLY"
        let secret = "UI-SYNTHETIC-TOKEN-ONE"
        let second = "UI-SYNTHETIC-TOKEN-TWO"
        func require(_ condition: @autoclosure () -> Bool, _ label: String) throws {
            guard condition() else { throw UIError(message: "FAILED: " + label) }
        }
        func denied(_ operation: () throws -> Void, _ label: String) throws {
            do { try operation() } catch { return }
            throw UIError(message: "FAILED: " + label)
        }
        let initialized = try client.run(["init", "--password-stdin"], input: password + "\n")
        try require(String(decoding: initialized, as: UTF8.self).contains("RECOVERY KEY"), "initialization result retained")
        let broker = Process()
        broker.executableURL = binary.deletingLastPathComponent().appendingPathComponent("rekeyd")
        broker.arguments = ["serve", "--state-dir", state]
        broker.standardInput = FileHandle.nullDevice
        broker.standardOutput = FileHandle.nullDevice
        broker.standardError = FileHandle.nullDevice
        try broker.run()
        defer { if broker.isRunning { broker.terminate() }; broker.waitUntilExit() }
        let deadline = Date().addingTimeInterval(10)
        while !FileManager.default.fileExists(atPath: state + "/runtime/admin.sock") {
            guard Date() < deadline && broker.isRunning else { throw UIError(message: "fixture startup failed") }
            Thread.sleep(forTimeInterval: 0.05)
        }
        let locked = try client.decode(ServiceStatus.self, ["status"])
        try require(!locked.unlocked, "locked startup")
        try denied({ _ = try client.run(["unlock", "--password-stdin"], input: "incorrect\n") }, "wrong password denied")
        Thread.sleep(forTimeInterval: 1.1)
        _ = try client.run(["unlock", "--password-stdin"], input: password + "\n")
        let unlocked = try client.decode(ServiceStatus.self, ["status"])
        try require(unlocked.unlocked, "unlocked state decoded")
        let literal = "UI literal $(touch SHOULD_NOT_EXIST)"
        let created = try JSONDecoder().decode(Credential.self, from: client.run(["credential", "add", literal, "--stdin-secrets"], input: password + "\n" + secret + "\n"))
        try require(created.label == literal && created.current_version == 1, "literal argv and metadata decode")
        _ = try client.run(["credential", "rotate", created.id, "--stdin-secrets"], input: password + "\n" + second + "\n")
        let entries = try client.decode(CredentialList.self, ["credential", "list"])
        try require(entries.credentials.count == 1 && entries.credentials[0].current_version == 2, "rotation visible")
        _ = try client.run(["credential", "revoke", created.id, "--password-stdin"], input: password + "\n")
        let revoked = try client.decode(CredentialList.self, ["credential", "list"])
        try require(!revoked.credentials[0].active, "revocation visible")
        let auditData = try client.run(["audit", "list"])
        let audit = try JSONDecoder().decode(AuditPage.self, from: auditData)
        try require(!audit.events.isEmpty, "audit decode")
        for canary in [password, secret, second] {
            try require(!String(decoding: auditData, as: UTF8.self).contains(canary), "audit canary absent")
        }
        let actionFile = root.appendingPathComponent("action.json")
        let definition: [String: Any] = ["name": "UI action", "credential_id": created.id, "origin": "https://example.com", "method": "GET", "exact_path": "/v1/test", "auth_header": "authorization", "auth_prefix": "Bearer ", "timeout_ms": 30000, "request_max_bytes": 65536, "allowed_extra_headers": [], "response_max_bytes": 262144, "allowed_response_headers": ["content-type"]]
        // A revoked credential must not be silently treated as a usable registration.
        let usable = try JSONDecoder().decode(Credential.self, from: client.run(["credential", "add", "usable", "--stdin-secrets"], input: password + "\n" + second + "\n"))
        var actual = definition
        actual["credential_id"] = usable.id
        try writePrivateNew(JSONSerialization.data(withJSONObject: actual), to: actionFile)
        let action = try JSONDecoder().decode(FixedAction.self, from: client.run(["action", "create", "--file", actionFile.path, "--password-stdin"], input: password + "\n"))
        let actionList = try client.decode(ActionList.self, ["action", "list"])
        try require(actionList.actions.first?.credential_id == usable.id, "associated actions decode")
        let sessionData = try client.run(["session", "create", "--action", action.reference, "--ttl", "15m", "--max-uses", "2", "--password-stdin"], input: password + "\n")
        let session = try JSONSerialization.jsonObject(with: sessionData) as! [String: Any]
        try require(session["capability_token"] is String, "session receipt")
        _ = try client.run(["session", "revoke", session["session_id"] as! String, "--password-stdin"], input: password + "\n")
        _ = try client.decode(PolicyStatus.self, ["policy", "status"])
        _ = try client.decode(PendingList.self, ["approval", "pending"])
        let backup = root.appendingPathComponent("backup.sqlite")
        let receiptData = try client.run(["backup", "--output", backup.path, "--password-stdin"], input: password + "\n")
        let receipt = try JSONSerialization.jsonObject(with: receiptData) as! [String: Any]
        let restore = CLI(binary: binary, stateDirectory: root.appendingPathComponent("restored").path)
        _ = try restore.run(["restore", "--input", backup.path, "--sha256", receipt["sha256_hex"] as! String, "--password-stdin"], input: password + "\n")
        _ = try client.run(["audit", "export", "--output", root.appendingPathComponent("audit.jsonl").path])
        _ = try client.run(["lock"])
        try denied({ _ = try client.run(["credential", "add", "blocked", "--stdin-secrets"], input: password + "\n" + secret + "\n") }, "locked mutation denied")
        _ = try client.decode(AuditPage.self, ["audit", "list"])

        let privateFile = root.appendingPathComponent("private-result.txt")
        try writePrivateNew(Data("synthetic receipt".utf8), to: privateFile)
        let attrs = try FileManager.default.attributesOfItem(atPath: privateFile.path)
        try require((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600, "private result permissions")
        try denied({ try writePrivateNew(Data(), to: privateFile) }, "no overwrite")
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: privateFile)
        try denied({ try writePrivateNew(Data(), to: link) }, "no symlink write")

        let fake = root.appendingPathComponent("argv-fixture")
        let script = "#!/usr/bin/python3\nimport json,os,sys\nprint(json.dumps({'args':sys.argv[1:], 'body':sys.stdin.read(), 'ambient':os.environ.get('REKEY_UI_TEST_AMBIENT')}))\n"
        try script.write(to: fake, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
        setenv("REKEY_UI_TEST_AMBIENT", "synthetic-env-value", 1)
        defer { unsetenv("REKEY_UI_TEST_AMBIENT") }
        let boundary = CLI(binary: fake, stateDirectory: state)
        let output = try boundary.run(["unlock", "--password-stdin"], input: password + "\n")
        let json = try JSONSerialization.jsonObject(with: output) as! [String: Any]
        try require(!(json["args"] as! [String]).joined(separator: " ").contains(password), "proof absent from argv")
        try require(json["body"] as? String == password + "\n", "proof reaches stdin exactly")
        try require(json["ambient"] is NSNull, "ambient environment removed")
        try denied({ _ = try boundary.decode(ServiceStatus.self, ["status"]) }, "malformed response fails clearly")
        let model = AppModel()
        model.desktopToken = "stale-token"
        model.visibleSecret = "synthetic-value"
        model.rejectDesktopSession(UIError(message: "INVALID_UNLOCK_CREDENTIAL"))
        try require(model.desktopToken == nil && model.visibleSecret == nil, "rejected desktop session is discarded")
        print("PASS: real vault lifecycle, metadata, actions, session lifecycle, policy/approval reads, backup/restore/export, wrong-proof and locked denial, audit canaries, private new-only result files, literal argv and stdin-only proof, filtered child environment, malformed-response rejection")
    }
}
