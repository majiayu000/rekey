import Foundation
import Darwin
import CryptoKit

// Compile with apps/macos/Model.swift; exercises the same subprocess boundary as the app.
@main
struct UIContract {
    @MainActor
    static func main() async throws {
        if CommandLine.arguments == [CommandLine.arguments[0], "--local-approval-boundary-only"] { try await localApprovalBoundary(); return }
        if CommandLine.arguments == [CommandLine.arguments[0], "--presence-boundary-only"] { try await presenceBoundary(); return }
        if CommandLine.arguments == [CommandLine.arguments[0], "--personal-policy-boundary-only"] { try await personalPolicyBoundary(); return }
        if CommandLine.arguments == [CommandLine.arguments[0], "--flow-boundary-only"] { try await flowBoundary(); return }
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
        let initialized = try client.run(["init", "--mode", "team", "--password-stdin"], input: password + "\n")
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
            try await Task.sleep(nanoseconds: 50_000_000)
        }
        let locked = try client.decode(ServiceStatus.self, ["status"])
        try require(!locked.unlocked, "locked startup")
        try denied({ _ = try client.run(["unlock", "--password-stdin"], input: "incorrect\n") }, "wrong password denied")
        try await Task.sleep(nanoseconds: 1_100_000_000)
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
        let catalogSource = try JSONSerialization.data(withJSONObject: ["source": ["kind": "github-pat"]])
        let github = try client.templateCatalog(source: catalogSource)
        try require(github.template.bindings["owner"]?.max == 39 && github.template.bindings["repo"]?.max == 100, "authenticated binding declarations decode for forms")
        try require(github.template.capabilities.first { $0.id == "merge-pr" }?.suggestedRule == "require-approval", "high-risk template recommendation is preserved")
        let templateDefinition: [String: Any] = ["source": ["kind": "openai"], "credential_id": usable.id, "bindings": [[:]] as [[String: String]], "capabilities": ["models", "responses"], "name_prefix": "UI template", "timeout_ms": 30000, "request_max_bytes": 1048576, "allowed_extra_headers": [] as [String], "response_max_bytes": 4194304, "allowed_response_headers": ["content-type"]]
        let templateRequest = String(decoding: try JSONSerialization.data(withJSONObject: templateDefinition), as: UTF8.self)
        let templateResult = try client.run(["template", "install", "--stdin-request", "--password-stdin"], input: password + "\n" + templateRequest + "\n")
        let templateRows = (try JSONSerialization.jsonObject(with: templateResult) as! [String: Any])["actions"] as! [[String: Any]]
        try require(templateRows.count == 2, "UI-shaped template request installs selected capabilities")
        for row in templateRows {
            let installed = try JSONDecoder().decode(FixedAction.self, from: JSONSerialization.data(withJSONObject: row["action"]!))
            try require(installed.target.summary.contains("路径规则") && installed.credential_id == usable.id, "installed template action decodes with its bound credential")
        }
        let sessionData = try client.run(["session", "create", "--action", action.reference, "--ttl", "15m", "--max-uses", "2", "--password-stdin"], input: password + "\n")
        let session = try JSONSerialization.jsonObject(with: sessionData) as! [String: Any]
        try require(session["capability_token"] is String, "session receipt")
        _ = try client.run(["session", "revoke", session["session_id"] as! String, "--password-stdin"], input: password + "\n")
        let teamPolicy = try client.decode(PolicyStatus.self, ["policy", "status"])
        try require(teamPolicy.mode == .team, "team external signing mode retained")
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
        let currentValue = try client.revealCredential(usable.id, proof: password, recovery: false)
        try require(currentValue == Data(second.utf8), "current value requires per-call proof through real CLI")
        _ = try client.run(["lock"])
        try denied({ _ = try client.run(["credential", "add", "blocked", "--stdin-secrets"], input: password + "\n" + secret + "\n") }, "locked mutation denied")
        _ = try client.decode(AuditPage.self, ["audit", "list"])
        try denied({ _ = try client.run(["shutdown"]) }, "locked shutdown without proof denied")
        _ = try client.run(["shutdown", "--password-stdin"], input: password + "\n")

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
            "record_type": "rekey.approval.challenge.v2", "approval_request_id": approvalID,
            "tenant_id": UUID().uuidString.lowercased(), "principal_id": UUID().uuidString.lowercased(),
            "session_id": UUID().uuidString.lowercased(), "action_id": action.id, "action_version": action.version,
            "resource": ["type": "fixed-http-action", "id": action.id], "schema_id": "ui/request",
            "parameter_sha256": String(repeating: "a", count: 64), "policy_version": 3,
            "policy_sha256": String(repeating: "b", count: 64), "policy_rule_id": UUID().uuidString.lowercased(),
            "mode": "one-time", "approver": ["kind": "ed25519", "keys": [String(repeating: "1", count: 64)], "threshold": 1],
            "max_uses": 1, "created_at_ms": 1000, "max_expires_at_ms": 61000,
        ]
        let envelope: [String: Any] = ["record_type": "rekey.approval.challenge.envelope.v2", "challenge": challenge, "signature": String(repeating: "A", count: 86)]
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
        let newerAction = FixedAction(id: action.id, name: action.name, version: action.version + 1, enabled: action.enabled, credential_id: action.credential_id, origin: action.origin, method: action.method, target: action.target, request_policy: action.request_policy)
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
    static func localApprovalBoundary() async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("rkui-local-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { do { try FileManager.default.removeItem(at: root) } catch { fputs("local fixture cleanup failed\n", stderr) } }
        var assertions = 0
        func require(_ condition: @autoclosure () throws -> Bool, _ label: String) throws {
            guard try condition() else { throw UIError(message: "FAILED: " + label) }; assertions += 1
        }
        func rejected(_ label: String, _ body: () throws -> Void) throws {
            do { try body() } catch { assertions += 1; return }; throw UIError(message: "FAILED: " + label)
        }
        let id = UUID().uuidString.lowercased(), vault = UUID(), key = String(repeating: "a1", count: 32)
        let expiry: Int64 = 4_102_444_800_000
        let challenge: [String: Any] = ["record_type":"rekey.approval.challenge.v2","approval_request_id":id,
            "tenant_id":UUID().uuidString,"principal_id":UUID().uuidString,"session_id":UUID().uuidString,
            "action_id":UUID().uuidString,"action_version":1,"resource":["type":"fixture","id":"SYNTHETIC RESOURCE"],
            "schema_id":"fixture/v1","parameter_sha256":String(repeating:"01",count:32),"policy_version":1,
            "policy_sha256":String(repeating:"02",count:32),"policy_rule_id":UUID().uuidString,"mode":"one-time",
            "approver":["kind":"local-presence"],"max_uses":1,"created_at_ms":1,"max_expires_at_ms":expiry]
        let challengeText = String(decoding: try JSONSerialization.data(withJSONObject: challenge, options:[.sortedKeys]), as:UTF8.self)
        let raw = "{\"record_type\":\"rekey.approval.review.v1\",\"challenge\":" + challengeText + ",\"action_name\":\"Trusted action\",\"origin\":\"https://example.com\",\"method\":\"POST\",\"canonical_request\":{\"body\":{\"n\":9007199254740993,\"text\":\"untrusted text\"},\"target\":{\"path\":\"/test\",\"params\":{},\"query\":{}},\"headers\":[]}}"
        func response(_ text: String? = raw, state: String = "pending", requested: String? = nil) throws -> Data {
            let bytes = Data((text ?? "").utf8)
            let digest = SHA256.hash(data: Data("RKREVIEW\0\u{1}".utf8) + bytes).map { String(format:"%02x",$0) }.joined()
            return try JSONSerialization.data(withJSONObject:["metadata":["record_type":"rekey.approval.local-review.v1",
                "approval_request_id":requested ?? id,"review_sha256":digest,"state":state,"body_len":bytes.count],
                "review_json":text as Any? ?? NSNull()])
        }
        let model = AppModel(stateDirectory: root.path)
        func unlocked() -> ServiceStatus { ServiceStatus(state:"unlocked",format_version:24,runtime_version:"fixture",sessions_active:0,peer_security:"L1-dev",lab_enabled:false) }
        model.status = unlocked()
        func details() throws -> LocalApprovalDetails { try LocalApprovalDetails.parse(response(),id:id,workspace:root.path,revision:model.nativeFlowRevision) }
        let snapshot = try details()
        try require(snapshot.raw == Data(raw.utf8) && snapshot.text.contains("9007199254740993"), "raw review never roundtrips or rounds its number")
        try require(snapshot.canDecide() && !snapshot.canDecide(at:Date(timeIntervalSince1970:Double(expiry)/1000)), "pending decision expires at exact boundary")
        for state in ["approved","consumed","cancelled","expired"] {
            let value = try LocalApprovalDetails.parse(response(state:state),id:id,workspace:root.path,revision:model.nativeFlowRevision)
            try require(!value.canDecide(), "nonpending state cannot decide")
        }
        for state in ["consumed","cancelled","expired"] {
            let value = try LocalApprovalDetails.parse(response(nil,state:state),id:id,workspace:root.path,revision:model.nativeFlowRevision)
            try require(value.raw.isEmpty && !value.canDecide(), "terminal body release accepted without decision")
        }
        for state in ["pending","approved"] { try rejected("active state needs complete body") { _ = try LocalApprovalDetails.parse(response(nil,state:state),id:id,workspace:root.path,revision:model.nativeFlowRevision) } }
        for field in ["body_len","review_sha256","approval_request_id","record_type"] {
            var changed = try JSONSerialization.jsonObject(with:response()) as! [String:Any]
            var meta = changed["metadata"] as! [String:Any]
            meta[field] = field == "body_len" ? 0 : "wrong"
            changed["metadata"] = meta
            try rejected("mismatched metadata rejected") { _ = try LocalApprovalDetails.parse(JSONSerialization.data(withJSONObject:changed),id:id,workspace:root.path,revision:model.nativeFlowRevision) }
        }
        try rejected("changed content cannot reuse hash") {
            var changed = try JSONSerialization.jsonObject(with:response()) as! [String:Any]
            changed["review_json"] = raw.replacingOccurrences(of:"untrusted text",with:"untrusted evil")
            _ = try LocalApprovalDetails.parse(JSONSerialization.data(withJSONObject:changed),id:id,workspace:root.path,revision:model.nativeFlowRevision)
        }
        let large = raw.replacingOccurrences(of:"untrusted text",with:String(repeating:"x",count:2*1024*1024+100))
        let largeResponse = try response(large)
        try require(try LocalApprovalDetails.parse(largeResponse,id:id,workspace:root.path,revision:model.nativeFlowRevision).raw.count > 2*1024*1024, "full review over legacy capture limit remains intact")
        try rejected("decoded review above 4MiB rejected") { _ = try LocalApprovalDetails.parse(response(String(repeating:"x",count:LocalApprovalDetails.bodyLimit+1)),id:id,workspace:root.path,revision:model.nativeFlowRevision) }
        let fixture = root.appendingPathComponent("cli.py"), callsFile = root.appendingPathComponent("calls.jsonl"), reviewFile = root.appendingPathComponent("review.json")
        try response().write(to: reviewFile)
        try JSONSerialization.data(withJSONObject:["vault_id":vault.uuidString,"mode":"personal","trust_installed":true,"bundle_persisted":true,"status":"active","version":1,"trust_sha256":String(repeating:"01",count:32)]).write(to:root.appendingPathComponent("policy.json"))
        let script = """
        #!/usr/bin/python3
        import json,pathlib,sys
        here=pathlib.Path(__file__).parent
        args=sys.argv[3:]; body=sys.stdin.read()
        with (here/'calls.jsonl').open('a') as f: f.write(json.dumps({'args':args,'body':body})+'\\n')
        if args==['policy','status']: print((here/'policy.json').read_text())
        elif args[:2]==['approval','review']: print((here/'review.json').read_text())
        elif args[:2] in [['approval','approve'],['approval','reject']]:
            if (here/'fail').exists(): print('synthetic outcome unknown',file=sys.stderr);sys.exit(2)
            print(json.dumps({'approval_request_id':args[2],'state':'approved' if args[1]=='approve' else 'cancelled','expires_at_ms':4102444800000}))
        else: print((here/'review.json').read_text())
        """
        try Data(script.utf8).write(to:fixture); try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:fixture.path)
        let client = CLI(binary:fixture,stateDirectory:root.path)
        func calls() throws -> [[String:Any]] {
            guard FileManager.default.fileExists(atPath:callsFile.path) else { return [] }
            return try String(contentsOf:callsFile,encoding:.utf8).split(separator:"\n").map { try JSONSerialization.jsonObject(with:Data($0.utf8)) as! [String:Any] }
        }
        func decisions() throws -> [[String:Any]] { try calls().filter { let a=$0["args"] as! [String]; return a.count>1 && ["approve","reject"].contains(a[1]) } }
        try largeResponse.write(to:reviewFile)
        try require(try client.localApprovalReview(id,revision:model.nativeFlowRevision).raw == Data(large.utf8), "actual subprocess review stdout uses enlarged bounded budget")
        try rejected("ordinary command stdout keeps 2MiB limit") { _ = try client.run(["fixture","ordinary"]) }
        try response().write(to:reviewFile)
        await model.reviewLocalApproval(id,client:client,active:true)
        try require(model.localApprovalDetails?.raw == snapshot.raw, "explicit read publishes checked raw snapshot")
        for approve in [false,true] {
            model.localApprovalDetails = try details()
            try await model.decideLocalApproval(model.localApprovalDetails!,approve:approve,client:client,active:{true},readPresence:{ _ in key })
            let row = try decisions().last!, args=row["args"] as! [String]
            try require(args == ["approval",approve ? "approve":"reject",id,"--review-sha256",snapshot.metadata.review_sha256,"--presence","--password-stdin"], "decision exact CLI contract")
            try require(row["body"] as? String == key+"\n" && !args.joined().contains(key), "actual K only enters anonymous stdin")
            try require(model.localApprovalDetails?.state == (approve ? .approved:.cancelled) && !model.busy, "response state prevents repeated decision")
        }
        model.localApprovalDetails = try details()
        let beforeCancel = try decisions().count
        do { try await model.decideLocalApproval(model.localApprovalDetails!,approve:true,client:client,active:{true},readPresence:{ _ in throw UIError(message:"SYNTHETIC CANCEL") }); throw UIError(message:"cancel admitted") }
        catch { try require(error.localizedDescription == "SYNTHETIC CANCEL", "system cancellation remains cancellation") }
        try require(try decisions().count == beforeCancel && !model.busy, "cancel never submits")
        final class Pause: @unchecked Sendable { let entered=DispatchSemaphore(value:0); let release=DispatchSemaphore(value:0) }
        for change in 0..<5 {
            model.stateDirectory=root.path; model.status=unlocked(); model.localApprovalDetails=try details()
            let d=model.localApprovalDetails!, pause=Pause(), count=try decisions().count
            var active = true
            let task=Task { try await model.decideLocalApproval(d,approve:true,client:client,active:{active},readPresence:{ _ in pause.entered.signal();pause.release.wait();return key }) }
            let entered=await withCheckedContinuation { continuation in DispatchQueue.global().async { continuation.resume(returning:pause.entered.wait(timeout:.now()+10) == .success) } }
            try require(entered && model.presenceAuthenticating,"controlled reader reached without hardware")
            model.nativeFlowBecameInactive()
            try require(model.nativeFlowRevision==d.revision,"system authentication focus exception retained")
            switch change { case 0:model.clearNativeFlow(); case 1:model.stateDirectory=root.appendingPathComponent("other").path; case 2:model.status=nil; case 3: model.localApprovalDetails=nil; default: active=false }
            pause.release.signal()
            var denied = false
            do { try await task.value } catch { denied = true }
            try require(denied, "late key result rejected")
            try require(try decisions().count==count && !model.busy,"closed/workspace/lock/selection change drops late K")
        }
        model.stateDirectory=root.path;model.status=unlocked();model.localApprovalDetails=try details()
        try Data().write(to:root.appendingPathComponent("fail"))
        do { try await model.decideLocalApproval(model.localApprovalDetails!,approve:true,client:client,active:{true},readPresence:{ _ in key }); throw UIError(message:"uncertain success") }
        catch { try require(model.localApprovalNeedsRefresh && error.localizedDescription.contains("不要自动重试"),"unknown result requires manual state query") }
        let count=try decisions().count
        var retryDenied = false
        do { try await model.decideLocalApproval(model.localApprovalDetails!,approve:true,client:client,active:{true},readPresence:{ _ in key }) } catch { retryDenied = true }
        try require(retryDenied, "uncertain retry denied before authentication")
        try require(try decisions().count==count,"uncertain decision not repeated")
        try FileManager.default.removeItem(at:root.appendingPathComponent("fail"))
        await model.reviewLocalApproval(id,client:client,active:true)
        try require(!model.localApprovalNeedsRefresh,"explicit state query clears uncertainty gate")
        for nextResponse in [try response(state:"approved"), try response(state:"expired"), try response(raw.replacingOccurrences(of:"untrusted text",with:"changed request"))] {
            model.localApprovalDetails = try details()
            try nextResponse.write(to:reviewFile)
            let before = try decisions().count
            var denied = false
            do { try await model.decideLocalApproval(model.localApprovalDetails!,approve:true,client:client,active:{true},readPresence:{ _ in key }) } catch { denied = true }
            try require(denied && decisions().count == before, "latest state/hash change after authentication never submits")
        }
        try response().write(to:reviewFile)
        model.localApprovalDetails = try details(); model.busy = true
        var busyDenied = false
        do { try await model.decideLocalApproval(model.localApprovalDetails!,approve:true,client:client,active:{true},readPresence:{ _ in throw UIError(message:"reader must not run") }) }
        catch { busyDenied = error.localizedDescription.contains("上下文已失效") }
        try require(busyDenied, "busy reentry rejected before authentication")
        model.busy = false
        let pending = try JSONDecoder().decode(PendingApproval.self,from:JSONSerialization.data(withJSONObject:["approval_request_id":id,"action_id":UUID().uuidString,"action_version":1,"session_id":UUID().uuidString,"max_expires_at_ms":expiry,"parameter_sha256":"canary","approver":["kind":"local-presence"]]))
        final class Counter: @unchecked Sendable {
            private let lock=NSLock();private var n=0
            func add() { lock.lock();n+=1;lock.unlock() };var value:Int { lock.lock();defer{lock.unlock()};return n }
        }
        let permission=Counter(), sent=Counter(), notificationCalls=try calls().count
        try await model.receiveApprovals([pending],send:{ _ in sent.add() })
        try require(sent.value==0 && !model.approvalNotificationsEnabled,"default polling cannot request permission or send")
        await model.setApprovalNotifications(true,request:{ permission.add();return true })
        try await model.receiveApprovals([pending],send:{ _ in sent.add() })
        try await model.receiveApprovals([pending],send:{ _ in sent.add() })
        try require(permission.value==1 && sent.value==1 && model.notifiedApprovalIDs.count==1,"explicit permission and bounded dedup only notify once")
        await model.setApprovalNotifications(false,request:{ permission.add();return true })
        try await model.receiveApprovals([],send:{ _ in sent.add() })
        try require(permission.value==1 && model.notifiedApprovalIDs.isEmpty && calls().count==notificationCalls,"disable/notification polling perform zero CLI proof reads or auth")
        var oversizedDenied = false
        do { try await model.receiveApprovals(Array(repeating:pending,count:129),send:{ _ in sent.add() }) } catch { oversizedDenied = true }
        try require(oversizedDenied, "oversized inbox rejected")
        await model.setApprovalNotifications(true,request:{ false })
        try require(!model.approvalNotificationsEnabled, "denied notification permission stays disabled")
        await model.setApprovalNotifications(true,request:{ true })
        let batch = try (0..<128).map { _ -> PendingApproval in
            let value:[String:Any] = ["approval_request_id":UUID().uuidString,"action_id":pending.action_id,"action_version":1,"session_id":pending.session_id,"max_expires_at_ms":expiry,"parameter_sha256":"canary","approver":["kind":"local-presence"]]
            return try JSONDecoder().decode(PendingApproval.self,from:JSONSerialization.data(withJSONObject:value))
        }
        try await model.receiveApprovals(batch,send:{ _ in sent.add() })
        try require(model.notifiedApprovalIDs.count == 128, "notification dedup is bounded by the exact server inbox cap")
        await model.setApprovalNotifications(false,request:{ throw UIError(message:"must not request") })
        let form = try String(contentsOfFile:"apps/macos/Forms.swift",encoding:.utf8)
        try require(form.contains("Button(\"拒绝\") { decide(details, approve: false) }.keyboardShortcut(.defaultAction).focused($rejectFocused)"),"local default Return/focus is reject")
        try require(form.contains("Text(details.text)") && form.contains(".onDisappear { model.clearNativeFlow() }"),"full raw display and view-close invalidation wired")
        print("PASS: \(assertions) local approval raw-byte/transport/lifecycle/notification assertions. Synthetic only; no Keychain, Secure Enclave or notification center access.")
    }

    @MainActor
    static func presenceBoundary() async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("rkui-presence-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { do { try FileManager.default.removeItem(at: root) } catch { fputs("presence fixture cleanup failed\n", stderr) } }
        var assertions = 0
        func require(_ value: @autoclosure () throws -> Bool, _ label: String) throws {
            guard try value() else { throw UIError(message: "FAILED: " + label) }; assertions += 1
        }
        func rejected(_ label: String, _ operation: () throws -> Void) throws {
            do { try operation() } catch { assertions += 1; return }
            throw UIError(message: "FAILED: " + label)
        }
        // Synthetic transport canaries only. These functions never invoke SecItem or LAContext.
        let key = String(repeating: "a1", count: 32), a1 = String(repeating: "b2", count: 32)
        let vault = UUID(), credential = UUID().uuidString.lowercased()
        try require(try PresenceKey.issuedKey(Data(("4102444800000\n" + key).utf8)) == key, "new key receipt parses exactly")
        for bad in [key.uppercased(), key + "\n", "", String(key.dropLast()), key + "a"] {
            try rejected("noncanonical key rejected") { _ = try PresenceKey.validated(bad) }
        }
        for bad in [key, "0\n" + key, "4102444800000\n" + key + "\n"] {
            try rejected("malformed issuance receipt rejected") { _ = try PresenceKey.issuedKey(Data(bad.utf8)) }
        }
        let receipt = try DesktopReceipt.parse(Data(("4102444800000\n" + a1).utf8))
        try require(receipt.token == a1 && receipt.token != key, "resume receipt is a distinct A1 token")
        for args in [["unlock"], ["desktop-login"], ["desktop-add", "label"], ["init"], ["restore"], ["key", "rotate-vrk"]] {
            try require(!Operation(title:"",detail:"",arguments:args).presenceAllowed, "unsupported operation has no presence option")
        }
        for args in [["credential","rotate"], ["action","create"], ["template","install"], ["session","create"],
                     ["policy","trust","install"], ["policy","activate"], ["password","change"], ["recovery","rotate"],
                     ["audit","retention","set"], ["backup"], ["shutdown"], ["desktop-reveal",credential]] {
            try require(Operation(title:"",detail:"",arguments:args).presenceAllowed, "supported A2 exposes presence")
        }
        let statusFile = root.appendingPathComponent("policy.json"), callsFile = root.appendingPathComponent("calls")
        let current: [String: Any] = ["vault_id":vault.uuidString.lowercased(),"mode":"personal","trust_installed":false,"bundle_persisted":false,"status":"unavailable"]
        func setPolicy(_ value: [String: Any]) throws { try JSONSerialization.data(withJSONObject:value).write(to:statusFile) }
        try setPolicy(current)
        let fixture = root.appendingPathComponent("cli")
        try Data("""
        #!/usr/bin/python3
        import json,pathlib,sys
        here=pathlib.Path(__file__).parent
        args=sys.argv[3:]; body=sys.stdin.read()
        with (here/'calls').open('a') as out: out.write(json.dumps({'args':args,'body':body})+'\\n')
        if args==['policy','status']: print((here/'policy.json').read_text())
        elif args[:1]==['status']: print(json.dumps({'state':'locked','format_version':19,'runtime_version':'fixture','sessions_active':0,'peer_security':'L1-dev','lab_enabled':False}))
        elif args==['desktop-resume']: sys.stdout.write('4102444800000\\n'+'b2'*32)
        elif args==['desktop-login']: sys.stdout.write('b2'*32)
        elif args[:1]==['desktop-reveal']: sys.stdout.write('SYNTHETIC-REVEALED-VALUE')
        else: print('{}')
        """.utf8).write(to:fixture)
        try FileManager.default.setAttributes([.posixPermissions:0o700],ofItemAtPath:fixture.path)
        let client = CLI(binary:fixture,stateDirectory:root.path)
        func calls() throws -> [[String: Any]] {
            guard FileManager.default.fileExists(atPath:callsFile.path) else { return [] }
            return try String(contentsOf:callsFile,encoding:.utf8).split(separator:"\n").map { try JSONSerialization.jsonObject(with:Data($0.utf8)) as! [String:Any] }
        }
        func unlocked() -> ServiceStatus { ServiceStatus(state:"unlocked",format_version:19,runtime_version:"fixture",sessions_active:0,peer_security:"L1-dev",lab_enabled:false) }
        func locked() -> ServiceStatus { ServiceStatus(state:"locked",format_version:19,runtime_version:"fixture",sessions_active:0,peer_security:"L1-dev",lab_enabled:false) }
        let model = AppModel(stateDirectory:root.path)
        model.status = unlocked()
        await model.perform(Operation(title:"",detail:"",arguments:["unlock"]),proof:"SYNTHETIC-PASSWORD",client:client)
        try require(model.desktopToken == a1 && model.desktopReady, "password login keeps A1 management session without issuing K")
        try require(try calls().count == 1 && calls().last?["args"] as? [String] == ["desktop-login"], "password login without explicit opt-in never remembers or reads a key")
        for op in [Operation(title:"",detail:"",arguments:["credential","revoke",credential]),
                   Operation(title:"",detail:"",arguments:["credential","rotate",credential],newSecret:true),
                   Operation(title:"",detail:"",arguments:["policy","activate","--file","synthetic-policy.json"],proofFlag:"--step-up-stdin"),
                   Operation(title:"",detail:"",arguments:["recovery","rotate"],recoveryAllowed:false)] {
            let count = try calls().count
            await model.perform(op,proof:"IGNORED-PASSWORD",secret:op.newSecret ? "SYNTHETIC-NEW-SECRET" : "",recovery:true,
                                presence:true,presenceRevision:model.nativeFlowRevision,client:client,readPresence:{ id in
                guard id == vault else { throw UIError(message:"WRONG-VAULT") }; return key
            })
            let rows = try calls(), last = rows.last!
            let args = last["args"] as! [String]
            try require(rows.count == count + 3 && model.error == nil && !model.busy, "explicit presence does two vault checks and one mutation")
            try require(args == op.arguments + [op.newSecret ? "--stdin-secrets" : op.proofFlag, "--presence"], "presence keeps operation-specific explicit stdin flag and excludes recovery")
            try require(last["body"] as? String == key + "\n" + (op.newSecret ? "SYNTHETIC-NEW-SECRET\n" : ""), "actual K is first stdin line; never cached A1 or password")
            try require(!args.joined().contains(key) && model.desktopToken == a1 && !(model.result?.text.contains(key) ?? false), "K absent argv/result and A1 session remains separate")
        }
        _ = try client.revealCredential(credential,proof:key,recovery:false,presence:true)
        try require(try calls().last?["args"] as? [String] == ["desktop-reveal",credential,"--password-stdin","--presence"] && calls().last?["body"] as? String == key + "\n", "reveal sends actual K with explicit proof kind")
        let op = Operation(title:"",detail:"",arguments:["credential","revoke",credential])
        var count = try calls().count
        await model.perform(op,presence:true,presenceRevision:model.nativeFlowRevision,client:client,readPresence:{ _ in throw UIError(message:"SYNTHETIC-CANCEL") })
        try require(try calls().count == count + 1 && model.error == "SYNTHETIC-CANCEL" && !model.busy && !model.presenceAuthenticating, "cancelled read cannot submit mutation")
        count = try calls().count
        await model.perform(Operation(title:"",detail:"",arguments:["key","rotate-vrk"]),presence:true,presenceRevision:model.nativeFlowRevision,client:client,readPresence:{ _ in throw UIError(message:"UNREACHABLE-READER") })
        try require(try calls().count == count && model.error?.contains("不支持") == true, "unsupported proof refuses before reader or CLI")
        model.busy = true
        await model.perform(op,presence:true,presenceRevision:model.nativeFlowRevision,client:client,readPresence:{ _ in throw UIError(message:"UNREACHABLE-READER") })
        try require(try calls().count == count && model.busy, "busy reentry cannot read a key or clear existing busy")
        model.busy = false
        final class Pause: @unchecked Sendable {
            let entered = DispatchSemaphore(value:0), release = DispatchSemaphore(value:0)
        }
        for change in ["view", "workspace", "lock", "task", "vault", "mode", "focus"] {
            try setPolicy(current); model.stateDirectory = root.path; model.status = unlocked()
            let revision = model.nativeFlowRevision, before = try calls().count, pause = Pause()
            defer { pause.release.signal() }
            let waiting = Task { await model.perform(op,presence:true,presenceRevision:revision,client:client,readPresence:{ _ in
                pause.entered.signal(); pause.release.wait(); return key
            }) }
            let entered = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning:pause.entered.wait(timeout:.now()+10) == .success) }
            }
            try require(entered && model.presenceAuthenticating, "controlled reader entered without Keychain APIs")
            model.nativeFlowBecameInactive()
            try require(model.nativeFlowRevision == revision, "ordinary system dialog focus change retains explicit authentication interval")
            switch change {
            case "view": model.clearNativeFlow()
            case "workspace": model.stateDirectory = root.appendingPathComponent("other").path
            case "lock": model.status = locked()
            case "task": waiting.cancel()
            case "vault": var changed = current; changed["vault_id"] = UUID().uuidString.lowercased(); try setPolicy(changed)
            case "mode": var changed = current; changed["mode"] = "team"; try setPolicy(changed)
            default: break
            }
            pause.release.signal(); await waiting.value
            let after = try calls()
            let expected = change == "focus" ? 3 : (["vault","mode"].contains(change) ? 2 : 1)
            try require(after.count == before + expected && !model.busy && !model.presenceAuthenticating, "late reader discarded on \(change), with no extra calls")
            try require(change == "focus" || after.suffix(expected).allSatisfy { $0["args"] as? [String] == ["policy","status"] }, "cancelled or stale context never submits an operation")
        }
        try setPolicy(current); model.stateDirectory = root.path; model.status = locked()
        count = try calls().count
        await model.unlockWithPresence(revision:model.nativeFlowRevision,client:client,read:{ _ in key })
        try require(try calls().count == count + 3 && calls().last?["args"] as? [String] == ["desktop-resume"] && calls().last?["body"] as? String == key + "\n", "explicit system unlock transports K only to desktop-resume")
        model.status = unlocked()
        try require(model.desktopToken == a1 && model.desktopReady && model.desktopToken != key, "resume keeps returned A1 session, never caches presence K")
        count = try calls().count
        await model.refresh(passive:true,client:client)
        try require(try calls().count == count + 1 && calls().last?["args"] as? [String] == ["status","--passive"] && model.desktopToken == nil, "passive locked refresh never resumes or reads a key and clears A1")
        let revision = model.nativeFlowRevision
        model.nativeFlowBecameInactive()
        try require(model.nativeFlowRevision != revision, "ordinary inactivity outside authentication still invalidates flow")
        print("PASS: \(assertions) synthetic presence transport/lifecycle assertions. No Keychain, system authentication, real vault, service or hardware protection was exercised.")
    }

    @MainActor
    static func personalPolicyBoundary() async throws {
        let root = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("rkui-personal-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { do { try FileManager.default.removeItem(at: root) } catch { fputs("personal fixture cleanup failed\n", stderr) } }
        var assertions = 0
        func require(_ condition: @autoclosure () throws -> Bool, _ name: String) throws {
            guard try condition() else { throw UIError(message: "FAILED: " + name) }; assertions += 1
        }
        func rejected(_ name: String, _ operation: () throws -> Void) throws {
            do { try operation() } catch { assertions += 1; return }
            throw UIError(message: "FAILED: " + name)
        }
        let vault = UUID(), principal = UUID(), revision = UUID()
        let expiry: Int64 = 4_102_444_800_000
        let hash = String(repeating: "a", count: 64), key = "04" + String(repeating: "11", count: 64)
        let unsigned = "{\"format_version\":1,\"signer_id\":\"\(vault.uuidString.lowercased())\",\"snapshot\":{\"version\":3,\"expires_at_ms\":\(expiry),\"exact\":9007199254740993,\"unicode\":\"完整预览/路径\",\"rules\":[],\"bindings\":[]}}"
        let message = "RKPOLICY\0\u{01}" + unsigned
        let complete = String(repeating: "complete-schema ", count: 600)
        let response: [String: Any] = ["metadata": ["vault_id": vault.uuidString.lowercased(), "trust_sha256": hash,
            "public_key": key, "base_version": 2, "next_version": 3, "policy_sha256": hash,
            "changes": [["field": "rules", "before": [["permission": "removed"]], "after": []]],
            "actions": [["target": ["body_schema": ["description": complete]]]]], "sign_bytes": message]
        let responseData = try JSONSerialization.data(withJSONObject: response)
        func makeDraft(_ data: Data = responseData, workspace: String = root.path, revision: UUID = revision) throws -> PersonalPolicyDraft {
            try PersonalPolicyDraft(response: data, principal: principal, expiresAtMs: expiry, workspace: workspace, revision: revision)
        }
        let draft = try makeDraft()
        try require(draft.signBytes == Data(message.utf8), "prefix and exact daemon UTF8 bytes retained")
        try require(draft.actionsText.contains(complete) && draft.changesText.contains("removed") && draft.changesText.contains("after"), "full schema and deleted authorization preview retained")
        let signature = "SYNTHETIC_DER_PLACEHOLDER"
        let bundle = try draft.signedBundle(signature: signature)
        try require(bundle == String(unsigned.dropLast()) + ",\"signature\":\"\(signature)\"}", "only signature inserted; snapshot number/Unicode bytes untouched")
        try require(try (JSONSerialization.jsonObject(with: Data(bundle.utf8)) as? [String: Any])?["signature"] as? String == signature, "result is one JSON object")
        for invalid in ["", "x\ny", "padded=", String(repeating: "a", count: 97)] {
            try rejected("invalid signature never forms request") { _ = try draft.signedBundle(signature: invalid) }
        }
        for invalid in [unsigned, "RKPOLICY\0\u{01}[]", "RKPOLICY\0\u{01}\n" + unsigned, "RKPOLICY\0\u{01}" + String(unsigned.dropLast()) + ",\"signature\":\"old\"}", "RKPOLICY\0\u{01}" + String(repeating: " ", count: 65536) + unsigned] {
            var bad = response; bad["sign_bytes"] = invalid
            try rejected("malformed or already signed envelope rejected") { _ = try makeDraft(JSONSerialization.data(withJSONObject: bad)) }
        }
        var current: [String: Any] = ["vault_id": vault.uuidString.lowercased(), "mode": "personal", "algorithm": "secure-enclave-p256",
            "trust_sha256": hash, "bundle_persisted": true, "trust_installed": true, "status": "expired", "version": 2,
            "signer_id": vault.uuidString.lowercased()]
        func status(_ value: [String: Any]) throws -> PolicyStatus { try JSONDecoder().decode(PolicyStatus.self, from: JSONSerialization.data(withJSONObject: value)) }
        try draft.validate(current: status(current)); assertions += 1
        for (field, value) in [("mode", "team" as Any), ("algorithm", "ed25519"), ("vault_id", UUID().uuidString),
                               ("trust_sha256", String(repeating: "b", count: 64)), ("version", 3), ("version", NSNull()),
                               ("trust_installed", false)] {
            var stale = current; stale[field] = value
            try rejected("changed \(field) rejects before signing") { try draft.validate(current: status(stale)) }
        }
        try rejected("expired draft denied") { try draft.validate(current: status(current), now: Date(timeIntervalSince1970: Double(expiry) / 1000)) }
        var firstResponse = response
        var firstMetadata = response["metadata"] as! [String: Any]
        firstMetadata["base_version"] = NSNull(); firstMetadata["next_version"] = 1; firstResponse["metadata"] = firstMetadata
        firstResponse["sign_bytes"] = message.replacingOccurrences(of: "\"version\":3", with: "\"version\":1")
        var firstStatus = current
        firstStatus["version"] = NSNull(); firstStatus["signer_id"] = NSNull()
        firstStatus["bundle_persisted"] = false; firstStatus["status"] = "unavailable"
        try makeDraft(JSONSerialization.data(withJSONObject: firstResponse)).validate(current: status(firstStatus)); assertions += 1
        let fixture = root.appendingPathComponent("cli"), calls = root.appendingPathComponent("calls"), statusFile = root.appendingPathComponent("status.json")
        try responseData.write(to: root.appendingPathComponent("draft.json"))
        try JSONSerialization.data(withJSONObject: current).write(to: statusFile)
        try Data("""
        #!/usr/bin/python3
        import json,pathlib,sys
        here=pathlib.Path(__file__).parent
        args=sys.argv[1:]; body=sys.stdin.read()
        with (here/'calls').open('a') as f: f.write(json.dumps({'args':args,'body':body})+'\\n')
        if args[2:4]==['policy','status']: print((here/'status.json').read_text())
        elif args[2:4]==['policy','draft']: print((here/'draft.json').read_text())
        else: print(json.dumps({'args':args,'body':body}))
        """.utf8).write(to: fixture)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: fixture.path)
        let client = CLI(binary: fixture, stateDirectory: root.path)
        let fromCLI = try client.personalPolicyDraft(principal: principal, expiresAtMs: expiry, actions: ["b@2", "a@1"], revision: revision)
        try require(fromCLI.signBytes == draft.signBytes, "CLI decoded response preserves sign bytes")
        let first = try JSONSerialization.jsonObject(with: Data(String(contentsOf: calls, encoding: .utf8).split(separator: "\n")[0].utf8)) as! [String: Any]
        try require(first["args"] as? [String] == ["--state-dir", root.path, "policy", "draft", "--principal", principal.uuidString.lowercased(), "--expires-at-ms", String(expiry), "--action", "a@1", "--action", "b@2"] && first["body"] as? String == "", "draft literal argv has explicit principal/expiry/actions and no proof")
        for recovery in [false, true] {
            let output = try client.activatePersonalPolicy(draft, signature: signature, proof: "SYNTHETIC-PROOF", recovery: recovery)
            let capture = try JSONSerialization.jsonObject(with: output) as! [String: Any]
            let args = ["--state-dir", root.path, "policy", "activate", "--stdin-request", "--expected-vault-id", vault.uuidString.lowercased(), "--expected-trust-sha256", hash, "--step-up-stdin"] + (recovery ? ["--recovery"] : [])
            try require(capture["args"] as? [String] == args && capture["body"] as? String == "SYNTHETIC-PROOF\n" + bundle + "\n", "activation exact two stdin lines; proof/signature absent argv")
        }
        for proof in ["", "first\nsecond", "first\rsecond"] {
            try rejected("invalid proof has no child call") { _ = try client.activatePersonalPolicy(draft, signature: signature, proof: proof, recovery: false) }
        }
        try require(try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count == 3, "locally invalid requests never launched")
        let model = AppModel(stateDirectory: root.path)
        model.status = ServiceStatus(state:"unlocked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security:"L1-dev",lab_enabled:false)
        let live = try makeDraft(revision: model.nativeFlowRevision)
        model.busy = true
        do {
            try await model.activatePersonalPolicy(live, proof: "SYNTHETIC-PROOF", recovery: false, client: client, sign: { _, _, _ in throw UIError(message:"UNREACHABLE-SIGNER") })
            throw UIError(message: "busy admitted")
        } catch { try require(model.busy && error.localizedDescription.contains("未提交激活"), "busy reentry refused before CLI/SE and keeps busy") }
        model.busy = false
        do {
            try await model.activatePersonalPolicy(live, proof: "SYNTHETIC-PROOF", recovery: false, client: client, sign: { _, bytes, publicKey in
                guard bytes == draft.signBytes, publicKey == draft.publicKey else { throw UIError(message:"WRONG-SIGNING-BYTES") }
                throw UIError(message:"SYNTHETIC-USER-CANCEL")
            })
            throw UIError(message: "cancel admitted")
        } catch { try require(error.localizedDescription == "SYNTHETIC-USER-CANCEL" && !model.busy && !model.personalPolicySigning, "injected cancellation resets state and cannot activate") }
        try require(try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count == 4, "cancelled signer made status read only; no activation")
        final class Pause: @unchecked Sendable {
            let entered = DispatchSemaphore(value: 0)
            let release = DispatchSemaphore(value: 0)
        }
        for workspaceChange in [true, false] {
            model.stateDirectory = root.path
            let pending = try makeDraft(revision: model.nativeFlowRevision)
            let callsBefore = try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count
            let pause = Pause()
            defer { pause.release.signal() }
            let waiting = Task {
                try await model.activatePersonalPolicy(pending, proof: "SYNTHETIC-PROOF", recovery: false, client: client, sign: { _, _, _ in
                    pause.entered.signal(); pause.release.wait()
                    // Controlled transport fixture, never a hardware success claim.
                    return "SYNTHETIC_SIGNATURE_AFTER_REVIEW_CLOSED"
                })
            }
            let entered: Bool = await withCheckedContinuation { continuation in
                DispatchQueue.global().async { continuation.resume(returning: pause.entered.wait(timeout: .now() + 10) == .success) }
            }
            try require(entered && model.personalPolicySigning, "explicit signing interval entered without any hardware API")
            model.showPolicyDraft = true
            model.nativeFlowBecameInactive()
            try require(model.showPolicyDraft && model.acceptsNativeCompletion(pending.revision, workspace: pending.workspace), "system authentication focus change does not invalidate review")
            if workspaceChange { model.stateDirectory = root.appendingPathComponent("other").path }
            else { model.clearNativeFlow() } // The PersonalPolicyDraftForm.onDisappear hook.
            try require(!model.acceptsNativeCompletion(pending.revision, workspace: pending.workspace) && !model.showPolicyDraft, "workspace switch or review disappearance invalidates revision")
            pause.release.signal()
            do { try await waiting.value; throw UIError(message:"stale signature admitted") }
            catch { try require(error.localizedDescription.contains("结果已丢弃，未激活") && !model.busy && !model.personalPolicySigning, "late synthetic signature is discarded and busy resets") }
            try require(try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count == callsBefore + 1, "closed review permits only initial status read, never activation")
        }
        model.stateDirectory = root.path
        let fresh = model.nativeFlowRevision
        model.status = ServiceStatus(state:"locked",format_version:15,runtime_version:"fixture",sessions_active:0,peer_security:"L1-dev",lab_enabled:false)
        try require(!model.acceptsNativeCompletion(fresh, workspace: root.path), "locked completion refused")
        model.nativeFlowBecameInactive()
        try require(model.nativeFlowRevision != fresh, "normal inactivity clears review")
        current["mode"] = "team"
        try JSONSerialization.data(withJSONObject: current).write(to: statusFile)
        model.status = ServiceStatus(state:"unlocked",format_version:15,runtime_version:"fixture",sessions_active:0,peer_security:"L1-dev",lab_enabled:false)
        let teamDraft = try makeDraft(revision: model.nativeFlowRevision)
        do {
            try await model.activatePersonalPolicy(teamDraft, proof:"SYNTHETIC-PROOF", recovery:false, client:client, sign: { _, _, _ in throw UIError(message:"UNREACHABLE-SIGNER") })
            throw UIError(message:"team admitted")
        } catch { try require(error.localizedDescription.contains("模式"), "changed Team status fails before signer") }
        current["mode"] = "personal"
        try JSONSerialization.data(withJSONObject: current).write(to: statusFile)
        let presenceKey = String(repeating: "a1", count: 32)
        let presenceDraft = try makeDraft(revision: model.nativeFlowRevision)
        let presenceOutput = try client.activatePersonalPolicy(presenceDraft, signature: signature, proof: presenceKey, recovery: true, presence: true)
        let presenceCapture = try JSONSerialization.jsonObject(with: presenceOutput) as! [String: Any]
        let presenceArgs = presenceCapture["args"] as! [String]
        try require(presenceArgs.suffix(2) == ["--step-up-stdin", "--presence"] && !presenceArgs.contains("--recovery") && !presenceArgs.joined().contains(presenceKey), "personal activation presence is explicit and proof never enters argv")
        try require(presenceCapture["body"] as? String == presenceKey + "\n" + bundle + "\n", "personal activation sends real K followed by the exact signed bundle")
        var beforePresence = try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count
        do {
            try await model.activatePersonalPolicy(presenceDraft, proof: "", recovery: false, presence: true, client: client,
                readPresence: { _ in throw UIError(message: "SYNTHETIC-PRESENCE-CANCEL") },
                sign: { _, _, _ in throw UIError(message: "UNREACHABLE-SIGNER") })
            throw UIError(message: "presence cancel admitted")
        } catch { try require(error.localizedDescription == "SYNTHETIC-PRESENCE-CANCEL" && !model.busy, "presence cancellation cannot reach policy signer or activation") }
        try require(try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count == beforePresence + 1, "cancelled presence permits only initial status read")
        beforePresence = try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count
        do {
            try await model.activatePersonalPolicy(presenceDraft, proof: "", recovery: false, presence: true, client: client,
                readPresence: { _ in presenceKey }, sign: { _, bytes, publicKey in
                    guard bytes == draft.signBytes, publicKey == draft.publicKey else { throw UIError(message: "WRONG-SIGNING-BYTES") }
                    throw UIError(message: "SYNTHETIC-POLICY-SIGN-CANCEL")
                })
            throw UIError(message: "policy signer cancel admitted")
        } catch { try require(error.localizedDescription == "SYNTHETIC-POLICY-SIGN-CANCEL" && !model.busy, "A2 presence cannot replace the separate exact-byte policy signature") }
        try require(try String(contentsOf: calls, encoding: .utf8).split(separator: "\n").count == beforePresence + 2, "policy signer cancellation after presence still cannot activate")
        print("PASS: \(assertions) personal draft byte/preview/CLI/state assertions. Controlled synthetic signer results only test transport cancellation. No SE, Keychain, GUI or cryptographic verification claim.")
    }

    @MainActor
    static func flowBoundary() async throws {
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
        let targetDecoder = JSONDecoder()
        let templateTarget = try targetDecoder.decode(FixedAction.Target.self, from: Data(#"{"kind":"template","target":{"path":"/repos/owner/repo/issues/{number}","params":{"number":"int:1..9999"},"query":{"state":"enum:open,closed"}}}"#.utf8))
        try require(templateTarget.summary.contains("{number}") && templateTarget.summary.contains("路径规则") && templateTarget.summary.contains("state"), "template definition is labelled as a rule, not an executed URL")
        _ = try rejected("unknown target variant cannot masquerade as fixed") {
            _ = try targetDecoder.decode(FixedAction.Target.self, from: Data(#"{"kind":"unknown","path":"/safe"}"#.utf8))
        }
        _ = try rejected("old untagged target is not silently loaded") {
            _ = try targetDecoder.decode(FixedAction.Target.self, from: Data(#"{"exact_path":"/safe"}"#.utf8))
        }
        _ = try rejected("template cannot fall back to a supplied fixed path") {
            _ = try targetDecoder.decode(FixedAction.Target.self, from: Data(#"{"kind":"template","path":"/safe"}"#.utf8))
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
        let challenge: [String: Any] = ["record_type": "rekey.approval.challenge.v2", "approval_request_id": requestID,
            "tenant_id": "tenant", "principal_id": "principal", "session_id": "session", "action_id": actionID,
            "action_version": 7, "resource": ["type":"fixed-http-action","id":actionID], "schema_id":"request",
            "parameter_sha256":String(repeating:"a",count:64), "policy_version":3, "policy_sha256":String(repeating:"b",count:64),
            "policy_rule_id":"rule", "mode":"one-time", "approver":["kind":"ed25519", "keys":["one","two"], "threshold":2], "max_uses":1,
            "created_at_ms":1000, "max_expires_at_ms":61000]
        let envelope: [String: Any] = ["record_type":"rekey.approval.challenge.envelope.v2", "challenge":challenge, "signature":"not-verified-by-ui"]
        let envelopeData = try JSONSerialization.data(withJSONObject: envelope)
        let details = ApprovalDetails(envelope: try JSONDecoder().decode(ApprovalEnvelope.self, from: envelopeData), origin: ApprovalOrigin(algorithm: "ed25519", public_key: "separately-pinned"), data: envelopeData)
        try require(details.envelope.challenge.approver.summary == "外部签名 · 2 人", "approval threshold comes from explicit Ed25519 approver")
        var localChallenge = challenge
        localChallenge["approver"] = ["kind": "local-presence"]
        let local = try JSONDecoder().decode(ApprovalChallenge.self, from: JSONSerialization.data(withJSONObject: localChallenge))
        try require(local.approver.summary == "本机系统认证", "local approver has no fabricated signer IDs")
        var oldChallenge = challenge
        oldChallenge.removeValue(forKey: "approver")
        oldChallenge["quorum"] = 1
        oldChallenge["approver_ids"] = ["old-id"]
        _ = try rejected("old approval identity representation") { _ = try JSONDecoder().decode(ApprovalChallenge.self, from: JSONSerialization.data(withJSONObject: oldChallenge)) }
        var unsupported = challenge
        unsupported["approver"] = ["kind": "remote"]
        _ = try rejected("unimplemented remote approval is not an external signer") { _ = try JSONDecoder().decode(ApprovalChallenge.self, from: JSONSerialization.data(withJSONObject: unsupported)) }
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
        let pendingDefinition = root.appendingPathComponent("pending-template.json")
        try writePrivateNew(Data("{}".utf8), to: pendingDefinition)
        var pendingOperation = Operation(title: "模板", detail: "", arguments: ["template", "install"])
        pendingOperation.temporaryFile = pendingDefinition
        model.busy = true
        await model.perform(pendingOperation, proof: "synthetic-proof")
        try require(!FileManager.default.fileExists(atPath: pendingDefinition.path), "busy operation removes owned definition without submitting")
        try require(model.error?.contains("未提交") == true, "busy operation reports that no request was submitted")
        try require(model.busy, "rejected second operation does not clear the active operation")
        pendingOperation.temporaryFile = nil
        pendingOperation.templateRequest = Data("{}".utf8)
        model.error = nil
        await model.perform(pendingOperation, proof: "synthetic-proof")
        try require(model.error?.contains("未提交") == true, "busy stdin template reports that no request was submitted")
        try require(model.busy, "rejected stdin template preserves the active operation")
        model.busy = false
        model.status = ServiceStatus(state:"unlocked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security: "L1-dev", lab_enabled: false)
        let personalVaultID = UUID()
        let personalStatus: [String: Any] = ["vault_id": personalVaultID.uuidString.lowercased(), "mode": "personal", "trust_installed": false, "bundle_persisted": false, "status": "unavailable"]
        model.policy = try JSONDecoder().decode(PolicyStatus.self, from: JSONSerialization.data(withJSONObject: personalStatus))
        model.beginPersonalPolicySetup()
        try require(model.operation?.personalTrustVaultID == personalVaultID, "personal setup captures the verified vault identity")
        try require(model.operation?.targetDirectory == model.stateDirectory, "personal setup pins the selected workspace")
        try require(model.operation?.arguments == ["policy", "trust", "install", "--stdin-request"] && model.operation?.proofFlag == "--step-up-stdin", "personal setup uses the anonymous trust and per-call proof path")
        model.busy = true; model.error = nil
        await model.perform(model.operation!, proof: "synthetic-proof")
        try require(model.error?.contains("未提交") == true && model.busy, "busy personal setup is rejected before any keychain operation")
        model.busy = false; model.operation = nil
        var teamStatus = personalStatus; teamStatus["mode"] = "team"
        model.policy = try JSONDecoder().decode(PolicyStatus.self, from: JSONSerialization.data(withJSONObject: teamStatus))
        model.beginPersonalPolicySetup()
        try require(model.operation == nil && model.error != nil, "team mode cannot open personal key setup")
        model.policy = nil; model.error = nil
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

        let revealID = UUID().uuidString.lowercased()
        model.selectedCredential = revealID
        model.desktopToken = "SYNTHETIC-DESKTOP-TOKEN"
        model.requestRevealCredential(revealID, copy: false)
        guard let revealOperation = model.operation, let reveal = revealOperation.reveal else { throw UIError(message: "missing reveal proof operation") }
        try require(revealOperation.proof && revealOperation.arguments == ["desktop-reveal", revealID], "reveal always queues per-call proof")
        try require(model.visibleSecret == nil && !model.busy, "request alone neither reveals nor starts CLI")
        model.operation = nil
        try require(model.finishCredentialReveal(.success(Data("REVEAL-CANARY".utf8)), request: reveal, active: true) && model.visibleSecret == "REVEAL-CANARY" && model.result == nil, "current reveal stays out of generic result sheet")
        model.requestRevealCredential(revealID, copy: true)
        try require(model.operation?.proof == true && model.operation?.reveal?.copy == true && model.visibleSecret == nil, "copy requires new proof after successful reveal")
        model.clearNativeFlow()
        try require(model.operation == nil, "focus loss dismisses invalidated reveal proof form")
        model.requestRevealCredential(revealID, copy: false)
        try require(model.operation?.reveal?.revision == model.nativeFlowRevision, "fresh reveal after focus change captures current revision")
        try require(!model.finishCredentialReveal(.success(Data("INACTIVE-CANARY".utf8)), request: reveal, active: false), "inactive reveal cannot publish")
        model.selectedCredential = UUID().uuidString.lowercased()
        model.selectedCredential = revealID
        try require(!model.finishCredentialReveal(.success(Data("STALE-CANARY".utf8)), request: reveal, active: true) && model.visibleSecret == nil, "switching away and back invalidates old reveal")
        model.requestRevealCredential(revealID, copy: false)
        let currentReveal = model.operation!.reveal!
        model.stateDirectory = root.appendingPathComponent("reveal-other-state").path
        try require(!model.finishCredentialReveal(.failure(UIError(message:"STALE-ERROR")), request: currentReveal, active: true), "old workspace reveal error is discarded")
        model.requestRevealCredential(revealID, copy: false)
        let lockedReveal = model.operation!.reveal!
        model.status = ServiceStatus(state:"locked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security: "L1-dev", lab_enabled: false)
        try require(!model.finishCredentialReveal(.success(Data("LOCKED-CANARY".utf8)), request: lockedReveal, active: true), "locked reveal cannot publish")
        model.requestShutdown()
        try require(model.operation?.arguments == ["shutdown"] && model.operation?.proof == true, "locked shutdown requests proof")
        model.status = ServiceStatus(state:"unlocked",format_version:15,runtime_version:"fixture",sessions_active:0, peer_security: "L1-dev", lab_enabled: false)
        model.requestShutdown()
        try require(model.operation?.arguments == ["shutdown"] && model.operation?.proof == true, "unlocked shutdown requests proof")

        let revealFixture = root.appendingPathComponent("reveal-cli")
        try Data("#!/usr/bin/python3\nimport json,sys\nprint(json.dumps({'args':sys.argv[1:],'body':sys.stdin.read()}))\n".utf8).write(to: revealFixture)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: revealFixture.path)
        let revealClient = CLI(binary: revealFixture, stateDirectory: root.path)
        for recovery in [false, true] {
            let response = try revealClient.revealCredential(revealID, proof: "PROOF-CANARY", recovery: recovery)
            let captured = try JSONSerialization.jsonObject(with: response) as! [String: Any]
            let expected = ["--state-dir", root.path, "desktop-reveal", revealID, "--password-stdin"] + (recovery ? ["--recovery"] : [])
            try require(captured["args"] as? [String] == expected && captured["body"] as? String == "PROOF-CANARY\n", "reveal proof uses exact stdin and factor flag")
        }
        print("PASS: \(assertions) native file/process/lifecycle assertions; exact snapshots, private new-only output, anonymous stdin, one-shot argv, non2xx/binary boundaries, typed failures, no retry, cleanup and stale-result rejection. No Broker authorization or GUI click claim.")
    }

}
