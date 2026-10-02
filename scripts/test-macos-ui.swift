import Foundation
import Darwin

// Compile with apps/macos/Model.swift; exercises the same subprocess boundary as the app.
@main
struct UIContract {
    @MainActor
    static func main() throws {
        if CommandLine.arguments == [CommandLine.arguments[0], "--flow-boundary-only"] { try flowBoundary(); return }
        if CommandLine.arguments == [CommandLine.arguments[0], "--oidc-boundary-only"] { try oidcBoundary(); return }
        guard CommandLine.arguments.count == 2 else { fatalError("usage: test-macos-ui CLI_BINARY | --flow-boundary-only") }
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
        try require(action.request_max_bytes == 65536 && actionList.actions.first?.request_max_bytes == 65536, "registered action request policy limit decoded")
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
        let newerAction = FixedAction(id: action.id, name: action.name, version: action.version + 1, enabled: action.enabled, credential_id: action.credential_id, origin: action.origin, method: action.method, exact_path: action.exact_path, request_policy: action.request_policy)
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

    @MainActor
    static func oidcBoundary() throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("rkui-oidc-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { do { try FileManager.default.removeItem(at: root) } catch { fputs("OIDC fixture cleanup failed\n", stderr) } }
        var assertions = 0
        func require(_ value: @autoclosure () -> Bool, _ label: String) throws {
            guard value() else { throw UIError(message: "FAILED: " + label) }
            assertions += 1
        }
        let fake = root.appendingPathComponent("fake-cli")
        try Data("#!/bin/sh\nprintf '%s\\n' \"$@\"\nprintf 'ENV=%s\\n' \"${REKEY_UI_TEST_SECRET-unset}\"\n".utf8).write(to: fake)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fake.path)
        let session = root.appendingPathComponent("session with space.token")
        try Data("SYNTHETIC-MANAGEMENT-CANARY".utf8).write(to: session)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: session.path)
        let state = root.appendingPathComponent("state").path
        let plain = CLI(binary: fake, stateDirectory: state)
        let managed = CLI(binary: fake, stateDirectory: state, adminSessionFile: session.path)
        let args = ["policy", "status"]
        try require(plain.commandArguments(args) == ["--state-dir", state] + args, "ordinary argv retained")
        try require(managed.commandArguments(args) == ["--state-dir", state, "--admin-session-file", session.path] + args, "managed path forwarded exactly")
        setenv("REKEY_UI_TEST_SECRET", "SYNTHETIC-AMBIENT-CANARY", 1)
        defer { unsetenv("REKEY_UI_TEST_SECRET") }
        let output = String(decoding: try managed.run(args), as: UTF8.self)
        try require(output.split(separator: "\n").map(String.init) == managed.commandArguments(args) + ["ENV=unset"], "actual child argv and no ambient secret")
        try require(!output.contains("SYNTHETIC-MANAGEMENT-CANARY"), "token never read or sent in argv")
        let flowJSON = Data("{\"flow_id\":\"flow\",\"authorization_url\":\"https://idp.example/authorize?state=synthetic\",\"expires_at_ms\":1}".utf8)
        let flow = try JSONDecoder().decode(OIDCLoginBegin.self, from: flowJSON)
        try require(flow.browserURL?.scheme == "https", "trusted public authorization URL decoded")
        let http = OIDCLoginBegin(flow_id: "flow", authorization_url: "http://idp.example/authorize", expires_at_ms: 1)
        try require(http.browserURL == nil, "non HTTPS browser URL rejected")
        let credentials = OIDCLoginBegin(flow_id: "flow", authorization_url: "https://user:secret@idp.example/authorize", expires_at_ms: 1)
        try require(credentials.browserURL == nil, "userinfo browser URL rejected")
        let identity = try JSONDecoder().decode(OIDCLoginIdentity.self, from: Data("{\"principal_id\":\"public-principal\",\"expires_at_ms\":300000,\"mapping_sha256\":\"public-mapping\"}".utf8))
        try require(identity.principal_id == "public-principal" && identity.expires_at_ms == 300000, "public identity response decoded")
        let model = AppModel(stateDirectory: state)
        model.status = ServiceStatus(state: "unlocked", format_version: 19, runtime_version: "fixture", sessions_active: 0, peer_security: "L1-dev", lab_enabled: false)
        model.oidcSessionFile = session.path; model.oidcProfileFile = root.appendingPathComponent("profile.json").path
        let revision = model.oidcFlowRevision
        try require(model.acceptsOIDCCompletion(revision, workspace: state), "current login completion eligible")
        model.oidcIdentity = identity
        model.oidcSessionFile = root.appendingPathComponent("other-session.token").path
        try require(model.oidcIdentity == nil, "switching session file discards previous displayed identity")
        model.clearNativeFlow()
        try require(model.oidcFlowRevision == revision && model.acceptsOIDCCompletion(revision, workspace: state), "browser focus cleanup preserves OIDC login")
        model.stateDirectory = root.appendingPathComponent("other-state").path
        try require(!model.acceptsOIDCCompletion(revision, workspace: state), "cross workspace late login rejected")
        try require(model.oidcSessionFile == nil && model.oidcProfileFile == nil, "old workspace identity pointers dropped")
        let cancelled = model.oidcFlowRevision
        model.clearOIDCLogin()
        try require(!model.acceptsOIDCCompletion(cancelled, workspace: model.stateDirectory), "cancelled completion rejected")
        model.oidcSessionFile = session.path
        model.clearCache()
        try require(model.oidcSessionFile == nil, "disconnect clears token pointer")
        model.status = ServiceStatus(state: "locked", format_version: 19, runtime_version: "fixture", sessions_active: 0, peer_security: "L1-dev", lab_enabled: false)
        try require(!model.acceptsOIDCCompletion(model.oidcFlowRevision, workspace: model.stateDirectory), "locked completion rejected")
        print("OIDC caller boundary: \(assertions) assertions passed; no Keychain or listeners used")
    }

    @MainActor
    static func flowBoundary() throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("rkui-flow-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { do { try FileManager.default.removeItem(at: root) } catch { fputs("flow fixture cleanup failed: \(error.localizedDescription)\n", stderr) } }
        var assertions = 0
        func require(_ condition: @autoclosure () throws -> Bool, _ name: String) throws {
            guard try condition() else { throw UIError(message: "FAILED: " + name) }
            assertions += 1
        }
        func rejected(_ name: String, _ operation: () throws -> Void) throws -> Error {
            do { try operation() } catch { assertions += 1; return error }
            throw UIError(message: "FAILED: " + name)
        }
        let bodyURL = root.appendingPathComponent("body-source.json")
        let originalBody = Data("{\"value\":\"NATIVE-BODY-CANARY\"}\n".utf8)
        try writePrivateNew(originalBody, to: bodyURL)
        let body = try NativeFileSnapshot.read(bodyURL, limit: 1024, json: true)
        try require(body.data == originalBody && Data(body.text.utf8) == originalBody, "original whitespace and UTF8 snapshot retained")
        let draft = root.appendingPathComponent("draft.json")
        try writePrivateNew(Data(" \n{\"unsigned\":true}\n".utf8), to: draft)
        let draftSnapshot = try NativeFileSnapshot.read(draft, limit: 65536)
        let exported = root.appendingPathComponent("draft-export.json")
        try writePrivateNew(draftSnapshot.data, to: exported)
        try require(try Data(contentsOf: exported) == draftSnapshot.data, "draft raw export")
        try require((try FileManager.default.attributesOfItem(atPath: exported.path)[.posixPermissions] as? NSNumber)?.intValue == 0o600, "export private0600")
        _ = try rejected("export never overwrites") { try writePrivateNew(Data(), to: exported) }
        let link = root.appendingPathComponent("link")
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: bodyURL)
        let linkError = try rejected("read nofollow") { _ = try NativeFileSnapshot.read(link, limit: 1024) }
        try require((linkError as NSError).domain == NSPOSIXErrorDomain, "nofollow retains NSError")
        _ = try rejected("new export no symlink") { try writePrivateNew(Data(), to: link) }
        _ = try rejected("read nonregular directory") { _ = try NativeFileSnapshot.read(root, limit: 1024) }
        let fifo = root.appendingPathComponent("fifo")
        guard mkfifo(fifo.path, 0o600) == 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        _ = try rejected("FIFO rejected without blocking") { _ = try NativeFileSnapshot.read(fifo, limit: 1024) }
        _ = try rejected("read bound") { _ = try NativeFileSnapshot.read(bodyURL, limit: originalBody.count - 1) }
        let invalid = root.appendingPathComponent("invalid")
        try writePrivateNew(Data([0xff, 0xfe]), to: invalid)
        _ = try rejected("invalid UTF8") { _ = try NativeFileSnapshot.read(invalid, limit: 64) }
        try Data("NATIVE-BODY-CANARY invalid JSON".utf8).write(to: invalid)
        let invalidError = try rejected("invalid JSON") { _ = try NativeFileSnapshot.read(invalid, limit: 64, json: true) }
        try require(!invalidError.localizedDescription.contains("NATIVE-BODY-CANARY"), "invalid body omitted from diagnostic")
        let missingError = try rejected("missing file NSError") { _ = try NativeFileSnapshot.read(root.appendingPathComponent("absent"), limit: 64) }
        try require((missingError as NSError).domain == NSPOSIXErrorDomain && (missingError as NSError).code == Int(ENOENT), "read underlying errno preserved")

        let actionID = UUID().uuidString.lowercased(), requestID = UUID().uuidString.lowercased()
        let challenge: [String: Any] = ["record_type": "rekey.approval.challenge.v1", "approval_request_id": requestID,
            "tenant_id": "tenant", "principal_id": "principal", "session_id": "session", "action_id": actionID,
            "action_version": 7, "resource": ["type":"fixed-http-action","id":actionID], "schema_id":"request",
            "parameter_sha256":String(repeating:"a",count:64), "policy_version":3, "policy_sha256":String(repeating:"b",count:64),
            "policy_rule_id":"rule", "mode":"one-time", "quorum":2, "approver_ids":["one","two"], "max_uses":1,
            "created_at_ms":1000, "max_expires_at_ms":61000]
        let envelope: [String: Any] = ["record_type":"rekey.approval.challenge.envelope.v1", "challenge":challenge, "signature":"not-verified-by-ui"]
        let envelopeData = try JSONSerialization.data(withJSONObject: envelope)
        let details = ApprovalDetails(envelope: try JSONDecoder().decode(ApprovalEnvelope.self, from: envelopeData), origin: ApprovalOrigin(algorithm: "ed25519", public_key: "separately-pinned"), data: envelopeData)
        let request = try JSONSerialization.jsonObject(with: approvalHandoff(details, body: body)) as! [String:Any]
        try require(request["body"] as? String == body.text && request["content_type"] as? String == "application/json", "handoff exact body and fixed content type")
        try require((request["headers"] as? [String]) == [], "handoff no extra headers")
        let requestEnvelope = request["challenge"] as! [String:Any]
        try require(requestEnvelope["signature"] as? String == "not-verified-by-ui", "handoff envelope retained without UI authorization")
        let grantURL = root.appendingPathComponent("grant-source.json")
        try writePrivateNew(Data("{\"grant\":\"NATIVE-GRANT-CANARY\"}\n".utf8), to: grantURL)
        let grant = try NativeFileSnapshot.read(grantURL, limit: 4096)
        let grantBoundary = root.appendingPathComponent("grant-boundary.json")
        var grant4096 = Data("{\"synthetic\":true}".utf8)
        grant4096.append(Data(repeating: 32, count: 4096 - grant4096.count))
        try writePrivateNew(grant4096, to: grantBoundary)
        let maximumGrant = try NativeFileSnapshot.read(grantBoundary, limit: 4096)
        try require(maximumGrant.data == grant4096 && maximumGrant.data.count == 4096, "4096 byte grant snapshot accepted at file boundary, not authorized")
        try (grant4096 + Data([32])).write(to: grantBoundary)
        let grantLimitError = try rejected("4097 byte grant rejected before preview") { _ = try NativeFileSnapshot.read(grantBoundary, limit: 4096) }
        try require(grantLimitError.localizedDescription.contains("大小上限"), "grant read bound preserves actual failure reason")
        try Data("{\"value\":\"CHANGED-AFTER-PREVIEW\"}".utf8).write(to: bodyURL)
        try Data("CHANGED-GRANT-AFTER-PREVIEW".utf8).write(to: grantURL)
        // The child checks actual snapshots and anonymous stdin; no listener or Broker authorization is faked.
        let fake = root.appendingPathComponent("execute-fixture")
        let script = #"""
        #!/usr/bin/python3
        import json,os,pathlib,stat,sys
        root=pathlib.Path(__file__).parent
        args=sys.argv[1:]
        assert args[:3]==['--state-dir',str(root/'state'),'execute']
        assert args[4:6]==['--capability','-']
        assert args[8:10]==['--content-type','application/json']
        token=sys.stdin.read()
        assert token.endswith('\n') and len(token)>1
        body=pathlib.Path(args[7])
        grantpaths=[pathlib.Path(args[i+1]) for i,x in enumerate(args) if x=='--approval']
        assert len(grantpaths) in (1,2)
        assert stat.S_IMODE(body.parent.stat().st_mode)==0o700
        assert all(stat.S_IMODE(p.stat().st_mode)==0o600 for p in [body]+grantpaths)
        assert body.read_bytes()==(root/'expected-body').read_bytes()
        assert all(p.read_bytes()==(root/'expected-grant').read_bytes() for p in grantpaths)
        assert all(token.strip() not in x for x in args+list(os.environ.values()))
        assert os.environ.get('NATIVE_AMBIENT_CANARY') is None
        with (root/'calls').open('a') as out:out.write(json.dumps({'args':args,'env':dict(os.environ),'snapshots':[str(p) for p in [body]+grantpaths]})+'\n')
        if (root/'failure').exists():
            sys.stderr.write('error [SYNTHETIC_DENIED]: fixed reason '+token+body.read_text()+grantpaths[0].read_text())
            sys.exit(7)
        if (root/'cleanup-failure').exists():body.parent.chmod(0)
        response=bytes([0,255,10,125,10,254])
        sys.stdout.buffer.write(json.dumps({'upstream_status':403,'headers':[['content-type','application/octet-stream'],['x-synthetic','line1\n}\nline2']],'body_len':len(response)},indent=2).encode()+b'\n'+response+b'\n')
        """#
        try writePrivateNew(Data(script.utf8), to: fake)
        try FileManager.default.setAttributes([.posixPermissions:0o700], ofItemAtPath:fake.path)
        try writePrivateNew(body.data, to:root.appendingPathComponent("expected-body"))
        try writePrivateNew(grant.data, to:root.appendingPathComponent("expected-grant"))
        let client = CLI(binary:fake,stateDirectory:root.appendingPathComponent("state").path)
        let token = "NATIVE-CAPABILITY-CANARY"
        setenv("NATIVE_AMBIENT_CANARY", "NATIVE-ENV-CANARY", 1)
        defer { unsetenv("NATIVE_AMBIENT_CANARY") }
        let response = try client.executeApproval(details, body:body, grants:[grant,grant], capability:token)
        try require(response.metadata.upstream_status == 403 && response.body == Data([0,255,10,125,10,254]), "HTTP non2xx remains actual status with binary body")
        try require(response.metadataText.hasPrefix("{\n") && response.metadata.headers[1][1] == "line1\n}\nline2", "real pretty renderer with escaped header newline does not terminate metadata early")
        let binaryExport = root.appendingPathComponent("response.bin")
        try writePrivateNew(response.body, to:binaryExport)
        try require(try Data(contentsOf:binaryExport) == response.body, "binary output saved without UTF8 conversion")
        let callURL = root.appendingPathComponent("calls")
        var calls = try String(contentsOf:callURL,encoding:.utf8).split(separator:"\n")
        try require(calls.count == 1, "one explicit execution no retry")
        let call = try JSONSerialization.jsonObject(with:Data(calls[0].utf8)) as! [String:Any]
        let args = call["args"] as! [String]
        try require(args[3] == "\(actionID)@7" && args.filter { $0 == "--approval" }.count == 2, "exact version and two grants")
        let captured = String(calls[0])
        for canary in [token,"NATIVE-BODY-CANARY","NATIVE-GRANT-CANARY","NATIVE-ENV-CANARY"] { try require(!captured.contains(canary), "canary absent from argv/env capture") }
        for path in call["snapshots"] as! [String] { try require(!FileManager.default.fileExists(atPath:path), "owned snapshots removed") }
        try require(!FileManager.default.fileExists(atPath:URL(fileURLWithPath:(call["snapshots"] as! [String])[0]).deletingLastPathComponent().path), "owned0700 directory removed")
        _ = try client.executeApproval(details, body:body, grants:[grant], capability:token)
        try Data().write(to:root.appendingPathComponent("failure"))
        let cliError = try rejected("CLI error retained without secrets") { _ = try client.executeApproval(details, body:body, grants:[grant], capability:token) }
        try require(cliError.localizedDescription.contains("（7）") && cliError.localizedDescription.contains("SYNTHETIC_DENIED") && cliError.localizedDescription.contains("fixed reason"), "CLI exit/code/reason retained")
        for canary in [token,"NATIVE-BODY-CANARY","NATIVE-GRANT-CANARY"] { try require(!cliError.localizedDescription.contains(canary), "reflected input omitted from diagnostic") }
        calls = try String(contentsOf:callURL,encoding:.utf8).split(separator:"\n")
        try require(calls.count == 3, "failed execution not retried")
        for line in calls {
            let row = try JSONSerialization.jsonObject(with:Data(line.utf8)) as! [String:Any]
            for path in row["snapshots"] as! [String] { try require(!FileManager.default.fileExists(atPath:path), "success and failure snapshots cleaned") }
        }
        try FileManager.default.removeItem(at:root.appendingPathComponent("failure"))
        try Data().write(to:root.appendingPathComponent("cleanup-failure"))
        let cleanupError = try rejected("cleanup failure visible after returned response") { _ = try client.executeApproval(details, body:body, grants:[grant], capability:token) }
        try require(cleanupError.localizedDescription.contains("执行已返回") && cleanupError.localizedDescription.contains("清理失败"), "cleanup error not silent success or remote rollback claim")
        calls = try String(contentsOf:callURL,encoding:.utf8).split(separator:"\n")
        let cleanupCall = try JSONSerialization.jsonObject(with:Data(calls.last!.utf8)) as! [String:Any]
        let leftover = URL(fileURLWithPath:(cleanupCall["snapshots"] as! [String])[0]).deletingLastPathComponent()
        try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:leftover.path)
        try FileManager.default.removeItem(at:leftover)
        try require(calls.count == 4, "cleanup failure never triggers a retry")
        _ = try rejected("newline capability not sent") { _ = try client.executeApproval(details, body:body, grants:[grant], capability:token+"\n") }
        _ = try rejected("zero grants not sent") { _ = try client.executeApproval(details, body:body, grants:[], capability:token) }
        try require(try String(contentsOf:callURL,encoding:.utf8).split(separator:"\n").count == 4, "local rejection performs no child call")
        let empty = Data("{\n  \"upstream_status\": 204,\n  \"headers\": [],\n  \"body_len\": 0\n}\n".utf8)
        let shortBodyMeta = Data("{\n  \"upstream_status\": 200,\n  \"headers\": [],\n  \"body_len\": 3\n}\n".utf8)
        try require(try NativeExecuteResult.parse(empty).body.isEmpty, "real pretty empty response with no extra final LF")
        try require(try NativeExecuteResult.parse(shortBodyMeta + Data("abc\n".utf8)).body == Data("abc".utf8), "real pretty nonempty body requires its actual final LF")
        for invalidOutput in [Data("{\n}\nBODY-SECRET".utf8),
                              shortBodyMeta + Data("raw".utf8), empty + Data("unexpected".utf8),
                              empty + Data([10]), Data("{\"upstream_status\":204,\"headers\":[],\"body_len\":0}\n".utf8),
                              Data(empty.dropLast()), shortBodyMeta + Data("x\n".utf8)] {
            let error = try rejected("malformed actual pretty or mixed response boundary") { _ = try NativeExecuteResult.parse(invalidOutput) }
            try require(!error.localizedDescription.contains("BODY-SECRET"), "invalid response body omitted")
        }
        let model = AppModel(stateDirectory:root.appendingPathComponent("state").path)
        model.status = ServiceStatus(state:"unlocked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security: "L1-dev", lab_enabled: false)
        let revision = model.nativeFlowRevision
        try require(model.acceptsNativeCompletion(revision,workspace:model.stateDirectory), "current completion admitted")
        model.approvalDetails = details; model.showPolicyDraft = true
        model.clearNativeFlow()
        try require(!model.acceptsNativeCompletion(revision,workspace:model.stateDirectory) && model.approvalDetails == nil && !model.showPolicyDraft, "focus/form closure invalidates completion and previews")
        let switched = model.nativeFlowRevision
        model.stateDirectory = root.appendingPathComponent("other-state").path
        try require(!model.acceptsNativeCompletion(switched,workspace:model.stateDirectory), "workspace change invalidates completion")
        let lockedRevision = model.nativeFlowRevision
        model.status = ServiceStatus(state:"locked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security: "L1-dev", lab_enabled: false)
        try require(!model.acceptsNativeCompletion(lockedRevision,workspace:model.stateDirectory), "locked completion rejected")
        model.clearCache()
        try require(model.approvalDetails == nil && !model.showPolicyDraft, "disconnect/cache clearing drops native forms")
        model.status = ServiceStatus(state:"unlocked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security: "L1-dev", lab_enabled: false)
        let reviewRevision = model.nativeFlowRevision, reviewWorkspace = model.stateDirectory
        try require(model.finishApprovalReview(.success(details), revision:reviewRevision, workspace:reviewWorkspace, active:true), "current active read callback publishes actual details")
        model.clearNativeFlow(); model.error = "CURRENT-CONTEXT"
        try require(!model.finishApprovalReview(.success(details), revision:reviewRevision, workspace:reviewWorkspace, active:true) && model.approvalDetails == nil, "late read success after focus clear cannot reopen execute detail")
        try require(!model.finishApprovalReview(.failure(UIError(message:"LATE-FAILURE")), revision:reviewRevision, workspace:reviewWorkspace, active:true) && model.error == "CURRENT-CONTEXT", "late read failure cannot overwrite current context")
        let currentReview = model.nativeFlowRevision
        try require(!model.finishApprovalReview(.success(details), revision:currentReview, workspace:reviewWorkspace, active:false) && model.approvalDetails == nil, "inactive read success cannot show details")
        try require(!model.finishApprovalReview(.failure(UIError(message:"INACTIVE-FAILURE")), revision:currentReview, workspace:reviewWorkspace, active:false) && model.error == "CURRENT-CONTEXT", "inactive read failure cannot show obsolete error")
        try require(model.finishApprovalReview(.failure(UIError(message:"CURRENT-FAILURE")), revision:currentReview, workspace:reviewWorkspace, active:true) && model.error == "CURRENT-FAILURE", "current read failure preserves actual cause")
        print("PASS: \(assertions) native file/process/lifecycle assertions; exact snapshots, private new-only output, anonymous stdin, one-shot argv, non2xx/binary boundaries, typed failures, no retry, cleanup and stale-result rejection. No Broker authorization or GUI click claim.")
    }

}
