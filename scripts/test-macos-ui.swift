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
        let realOrigin = try client.decode(ApprovalOrigin.self, ["approval", "origin"])
        try require(realOrigin.algorithm == "ed25519" && realOrigin.public_key.count == 64, "real origin public key decoded")
        try denied({ _ = try client.approvalDetails(UUID().uuidString.lowercased()) }, "unknown approval is rejected by real broker")
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

        // Exercise the exact production read bridge without signing or executing an action.
        let approvalID = UUID().uuidString.lowercased()
        let challenge: [String: Any] = [
            "record_type": "rekey.approval.challenge.v1", "approval_request_id": approvalID,
            "tenant_id": UUID().uuidString.lowercased(), "principal_id": UUID().uuidString.lowercased(),
            "session_id": UUID().uuidString.lowercased(), "action_id": action.id, "action_version": action.version,
            "resource": ["type": "fixed-http-action", "id": action.id], "schema_id": "ui/request",
            "parameter_sha256": String(repeating: "a", count: 64), "policy_version": 3,
            "policy_sha256": String(repeating: "b", count: 64), "policy_rule_id": UUID().uuidString.lowercased(),
            "mode": "one-time", "quorum": 1, "approver_ids": [UUID().uuidString.lowercased()],
            "max_uses": 1, "created_at_ms": 1000, "max_expires_at_ms": 61000,
        ]
        let envelope: [String: Any] = ["record_type": "rekey.approval.challenge.envelope.v1", "challenge": challenge, "signature": String(repeating: "A", count: 86)]
        let envelopeData = try JSONSerialization.data(withJSONObject: envelope, options: [.prettyPrinted, .sortedKeys])
        let getFile = root.appendingPathComponent("get.json")
        let originFile = root.appendingPathComponent("origin.json")
        try envelopeData.write(to: getFile)
        let originData = try JSONSerialization.data(withJSONObject: ["algorithm": "ed25519", "public_key": String(repeating: "c", count: 64)])
        try originData.write(to: originFile)
        let approvalBinary = root.appendingPathComponent("approval-fixture")
        let approvalScript = """
        #!/usr/bin/python3
        import json,pathlib,sys
        root=pathlib.Path(__file__).parent
        args=sys.argv[3:]
        assert args[:1] == ['approval'] and sys.stdin.read() == ''
        with (root/'approval-calls.jsonl').open('a') as out: out.write(json.dumps(args)+'\\n')
        if args[1] == 'get':
            assert len(args) == 3
        else:
            assert args == ['approval','origin']
        path=root/(args[1]+'.json')
        if not path.exists():
            print('synthetic approval read failure',file=sys.stderr)
            sys.exit(4)
        sys.stdout.buffer.write(path.read_bytes())
        """
        try approvalScript.write(to: approvalBinary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: approvalBinary.path)
        let approvalClient = CLI(binary: approvalBinary, stateDirectory: state)
        let details = try approvalClient.approvalDetails(approvalID)
        try require(details.data == envelopeData && details.id == approvalID, "detail retains exact envelope bytes")
        try require(details.envelope.challenge.schema_id == "ui/request" && details.envelope.challenge.policy_version == 3, "challenge binding fields decoded")
        try require(details.origin.public_key == String(repeating: "c", count: 64), "separate origin key decoded")
        try require(details.matchingAction(in: [action])?.reference == action.reference, "exact action version selected")
        let newerAction = FixedAction(id: action.id, name: action.name, version: action.version + 1, enabled: action.enabled, credential_id: action.credential_id, origin: action.origin, method: action.method, exact_path: action.exact_path)
        try require(details.matchingAction(in: [newerAction]) == nil, "no fallback to newer action definition")
        let calls = try String(contentsOf: root.appendingPathComponent("approval-calls.jsonl"), encoding: .utf8).split(separator: "\n")
        let firstCall = try JSONSerialization.jsonObject(with: Data(calls[0].utf8)) as! [String]
        let secondCall = try JSONSerialization.jsonObject(with: Data(calls[1].utf8)) as! [String]
        try require(firstCall == ["approval", "get", approvalID] && secondCall == ["approval", "origin"], "read-only approval CLI arguments")
        try denied({ _ = try approvalClient.approvalDetails(UUID().uuidString.lowercased()) }, "different request ID rejected")
        try Data("{}".utf8).write(to: getFile)
        try denied({ _ = try approvalClient.approvalDetails(approvalID) }, "missing challenge fields rejected")
        try envelopeData.write(to: getFile)
        try Data("{}".utf8).write(to: originFile)
        try denied({ _ = try approvalClient.approvalDetails(approvalID) }, "missing origin fields rejected")
        try FileManager.default.removeItem(at: originFile)
        try denied({ _ = try approvalClient.approvalDetails(approvalID) }, "origin read failure rejected")
        try originData.write(to: originFile)
        try FileManager.default.removeItem(at: getFile)
        try denied({ _ = try approvalClient.approvalDetails(approvalID) }, "get read failure rejected")
        let model = AppModel()
        model.desktopToken = "stale-token"
        model.visibleSecret = "synthetic-value"
        model.rejectDesktopSession(UIError(message: "INVALID_UNLOCK_CREDENTIAL"))
        try require(model.desktopToken == nil && model.visibleSecret == nil, "rejected desktop session is discarded")
        model.approvalDetails = details
        model.clearCache()
        try require(model.approvalDetails == nil, "approval detail cleared with workspace/lock/disconnect caches")
        print("PASS: real vault lifecycle, metadata, actions, session lifecycle, policy/approval reads, backup/restore/export, wrong-proof and locked denial, audit canaries, private new-only result files, literal argv and stdin-only proof, filtered child environment, malformed-response rejection; approval detail bridge, exact snapshot and action version, origin reads, missing/mismatched responses and command failures, detail cache clearing")
    }
}
