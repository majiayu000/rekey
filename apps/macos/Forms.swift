import SwiftUI
import AppKit

func singleLine(_ value: String) -> Bool {
    !value.isEmpty && !value.contains("\n") && !value.contains("\r") && !value.contains("\0")
}
struct OperationForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let operation: Operation
    @State private var proof = ""
    @State private var secret = ""
    @State private var confirmation = ""
    @State private var recovery = false
    @State private var sessionID = ""
    @State private var hash = ""
    @State private var destination: URL?
    @State private var policyMode = "personal"
    private var isInit: Bool { operation.arguments.first == "init" }
    private var isRestore: Bool { operation.arguments.first == "restore" }
    private var revokeSession: Bool { operation.arguments == ["session", "revoke"] }
    private var valid: Bool {
        singleLine(proof) && (!operation.newSecret || singleLine(secret)) &&
        (!operation.confirmSecret || confirmation == (operation.newSecret ? secret : proof)) &&
        (!revokeSession || UUID(uuidString: sessionID) != nil) &&
        (!isRestore || (hash.count == 64 && hash.allSatisfy(\.isHexDigit) && destination != nil))
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label(operation.title, systemImage: "lock.shield").font(.system(size: 23, weight: .semibold))
            Text(operation.detail).font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if isInit {
                Picker("策略签名模式", selection: $policyMode) {
                    Text("个人 · 此设备签名").tag("personal")
                    Text("团队 · 外部签名器").tag("team")
                }
                Text("创建后模式不可更改；切换模式需要新建保险库。").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if revokeSession { TextField("会话 ID", text: $sessionID).textFieldStyle(.roundedBorder) }
            if isRestore {
                TextField("备份回执 SHA-256", text: $hash).textFieldStyle(.roundedBorder)
                HStack { Text(destination?.path ?? "请选择空目录").font(.system(size: 11)).lineLimit(2); Spacer(); Button("选择恢复目录") { destination = chooseFile(directory: true) } }
            }
            if operation.recoveryAllowed {
                Toggle("使用恢复密钥", isOn: $recovery).font(.system(size: 12))
            }
            SecureField(recovery ? "恢复密钥" : operation.arguments.first == "init" ? "设置保险库密码" : "当前保险库密码", text: $proof).textFieldStyle(.roundedBorder)
            if operation.newSecret { SecureField(operation.arguments.first == "password" ? "新密码" : "新凭证值", text: $secret).textFieldStyle(.roundedBorder) }
            if operation.confirmSecret { SecureField("再次输入新密码", text: $confirmation).textFieldStyle(.roundedBorder) }
            Text("输入仅用于本次操作，不会保存。").font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                Button("取消") { clear(); dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("确认\(operation.title)") {
                    var op = operation
                    if isInit { op = Operation(title: op.title, detail: op.detail, arguments: op.arguments + ["--mode", policyMode], confirmSecret: true, sensitiveResult: true, recoveryAllowed: false) }
                    if revokeSession { op = Operation(title: op.title, detail: op.detail, arguments: op.arguments + [sessionID]) }
                    if isRestore {
                        op = Operation(title: op.title, detail: op.detail, arguments: op.arguments + ["--sha256", hash])
                        op.targetDirectory = destination!.path
                    }
                    let p = proof, s = secret, useRecovery = recovery
                    clear(); dismiss()
                    Task { await model.perform(op, proof: p, secret: s, recovery: useRecovery) }
                }.buttonStyle(PrimaryButton()).disabled(!valid || model.busy)
            }
        }.padding(30).frame(width: 460).background(canvas).onDisappear { clear() }
    }
    private func clear() { proof = ""; secret = ""; confirmation = "" }
}

struct AddCredentialForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var label = ""
    @State private var kind = "add"
    @State private var secret = ""
    @State private var proof = ""
    @State private var profile: URL?
    private var valid: Bool { !label.trimmingCharacters(in: .whitespaces).isEmpty && (kind == "add" ? singleLine(secret) : singleLine(proof) && profile != nil) }
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Text("添加 API Key").font(.system(size: 24, weight: .semibold))
            Text("先保存密钥，之后随时查看、复制，或配置给 Agent 使用。").font(.system(size: 13)).foregroundStyle(.secondary)
            TextField("名称，例如 智谱 · 个人开发", text: $label).textFieldStyle(.roundedBorder)
            DisclosureGroup("其他凭证类型") { Picker("类型", selection: $kind) {
                Text("API Key / 访问令牌").tag("add")
                Text("GitHub App").tag("add-github-app")
                if model.status?.lab_enabled == true {
                Text("Vault KV v2").tag("add-vault-kv")
                Text("Vault 动态租约").tag("add-vault-dynamic")
                Text("Keycloak Token Exchange").tag("add-keycloak")
                }
            }
            }
            if kind == "add" { SecureField("粘贴 API Key，无需 Bearer 前缀", text: $secret).textFieldStyle(.roundedBorder) }
            else {
                HStack { Text(profile?.lastPathComponent ?? "选择私有 JSON 配置文件").font(.system(size: 12)); Spacer(); Button("选择文件") { profile = chooseFile() } }
                Text("配置文件须归当前用户所有，且不可被其他用户读取。内容与权限由服务验证。").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if kind == "add" && !secret.isEmpty && secret.utf8.count < 16 {
                Text("密钥短于 16 字节，嵌入编码的反射遮蔽覆盖有限。建议使用服务商生成的完整 Key。")
                    .font(.system(size: 11)).foregroundStyle(.orange)
            }
            if kind != "add" { SecureField("当前保险库密码", text: $proof).textFieldStyle(.roundedBorder) }
            if let error = model.error { Text(error).font(.system(size: 12)).foregroundStyle(.red) }
            if kind == "add" && !model.desktopReady { Text("管理会话已过期，请关闭此窗口并重新解锁管理会话。").foregroundStyle(.secondary) }
            HStack {
                Button("取消") { clear(); dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("保存") {
                    if kind == "add" {
                        Task { if await model.addAPIKey(label: label, secret: secret) { clear(); dismiss() } }
                        return
                    }
                    var args = ["credential", kind, label]
                    if let profile, kind != "add" { args += ["--file", profile.path] }
                    let op = Operation(title: "添加凭证", detail: "", arguments: args, newSecret: kind == "add")
                    let p = proof, s = secret
                    clear(); dismiss()
                    Task { await model.perform(op, proof: p, secret: s) }
                }.buttonStyle(PrimaryButton()).disabled(!valid || model.busy || (kind == "add" && !model.desktopReady))
            }
        }.padding(30).frame(width: 480).background(canvas).onDisappear { clear() }
    }
    private func clear() { proof = ""; secret = "" }
}

struct ActionForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var name = ""
    @State private var credential = ""
    @State private var origin = ""
    @State private var path = ""
    @State private var method = "GET"
    @State private var header = "authorization"
    @State private var prefix = "Bearer "
    @State private var proof = ""
    @State private var failure: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 17) {
            Text("创建固定操作").font(.system(size: 24, weight: .semibold))
            Text("固定请求目标与认证方式。更细的请求限制可通过操作定义文件导入。").font(.system(size: 12)).foregroundStyle(.secondary)
            TextField("操作名称", text: $name).textFieldStyle(.roundedBorder)
            Picker("使用凭证", selection: $credential) {
                Text("选择凭证").tag("")
                ForEach(model.credentials.filter(\.active)) { Text($0.label).tag($0.id) }
            }
            TextField("HTTPS Origin，例如 https://api.example.com", text: $origin).textFieldStyle(.roundedBorder)
            HStack { Picker("方法", selection: $method) { ForEach(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"], id: \.self) { Text($0).tag($0) } }.frame(width: 155); TextField("固定路径，例如 /v1/resource", text: $path).textFieldStyle(.roundedBorder) }
            HStack {
                TextField("认证 Header", text: $header).textFieldStyle(.roundedBorder)
                Picker("认证方案", selection: $prefix) {
                    Text("Bearer").tag("Bearer "); Text("token").tag("token "); Text("无前缀").tag("")
                }
            }
            Text("前缀只填写 Bearer 等认证方案，不要填写凭证值。").font(.system(size: 11)).foregroundStyle(.secondary)
            SecureField("当前保险库密码", text: $proof).textFieldStyle(.roundedBorder)
            if let failure { Text(failure).font(.system(size: 12)).foregroundStyle(.red) }
            HStack {
                Button("取消") { proof = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("创建操作") { submit() }.buttonStyle(PrimaryButton()).disabled(name.isEmpty || credential.isEmpty || origin.isEmpty || path.isEmpty || !singleLine(proof) || model.busy)
            }
        }.padding(30).frame(width: 520).background(canvas).onDisappear { proof = "" }
    }
    private func submit() {
        // Only non-secret action metadata is written to this new private file.
        let definition: [String: Any] = ["name": name, "credential_id": credential, "origin": origin, "method": method, "exact_path": path, "auth_header": header, "auth_prefix": prefix, "timeout_ms": 30000, "request_max_bytes": 65536, "allowed_extra_headers": [], "response_max_bytes": 262144, "allowed_response_headers": ["content-type"]]
        do {
            let data = try JSONSerialization.data(withJSONObject: definition, options: [.sortedKeys])
            let file = FileManager.default.temporaryDirectory.appendingPathComponent("rekey-action-\(UUID().uuidString).json")
            try writePrivateNew(data, to: file)
            var op = Operation(title: "创建操作", detail: "", arguments: ["action", "create", "--file", file.path])
            op.temporaryFile = file
            let p = proof; proof = ""; dismiss()
            Task { await model.perform(op, proof: p) }
        } catch { failure = error.localizedDescription }
    }
}

struct TemplateForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var provider = "github-pat"
    @State private var origin = ""
    @State private var targets = "GET /v1/models"
    @State private var credential = ""
    @State private var name = ""
    @State private var selected: Set<String> = []
    @State private var bindings: [[String: String]] = [[:]]
    @State private var catalog: ProviderTemplateCatalog?
    @State private var catalogSource: Data?
    @State private var catalogWorkspace = ""
    @State private var catalogRevision = UUID()
    @State private var loadRevision = UUID()
    @State private var loading = false
    @State private var proof = ""
    @State private var recovery = false
    @State private var failure: String?
    private var sourceRevision: String { provider + "\n" + origin + "\n" + targets }
    private var complete: Bool {
        guard let catalog else { return false }
        return !name.isEmpty && !credential.isEmpty && !selected.isEmpty && singleLine(proof)
            && bindings.allSatisfy { group in catalog.template.bindings.keys.allSatisfy { !(group[$0] ?? "").isEmpty } }
            && model.acceptsNativeCompletion(catalogRevision, workspace: catalogWorkspace)
    }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("从模板安装操作").font(.system(size: 24, weight: .semibold))
            Text("选定能力与固定范围。安装后仍需配置授权策略和 Agent 会话。").font(.system(size: 12)).foregroundStyle(.secondary)
            Picker("服务", selection: $provider) {
                Text("GitHub 个人令牌").tag("github-pat")
                Text("Anthropic").tag("anthropic")
                Text("OpenAI").tag("openai")
                Text("自定义 Bearer").tag("generic-bearer")
            }
            if provider == "generic-bearer" {
                TextField("HTTPS Origin", text: $origin).textFieldStyle(.roundedBorder)
                Text("每行一个固定目标，例如 GET /v1/models，最多 20 个。").font(.system(size: 11)).foregroundStyle(.secondary)
                TextEditor(text: $targets).font(.system(size: 12, design: .monospaced)).frame(height: 64)
                Button("读取能力") { Task { await loadCatalog() } }.disabled(loading || model.busy)
            }
            if loading { ProgressView().controlSize(.small) }
            if let catalog {
                Text(catalog.template.origin).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                TextField("操作名称前缀", text: $name).textFieldStyle(.roundedBorder)
                Picker("使用凭证", selection: $credential) {
                    Text("选择 API Key / 访问令牌").tag("")
                    ForEach(model.credentials.filter { $0.active && $0.kind == "opaque-token" }) { Text($0.label).tag($0.id) }
                }
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        ForEach(catalog.template.capabilities) { capability in
                            Toggle(isOn: Binding(get: { selected.contains(capability.id) }, set: { if $0 { selected.insert(capability.id) } else { selected.remove(capability.id) } })) {
                                VStack(alignment: .leading, spacing: 3) {
                                    Text(capability.id).font(.system(size: 13, weight: .semibold))
                                    Text(capability.suggestedRule == "require-approval" ? "模板建议：每次审批" : "模板建议：授权范围内允许").font(.system(size: 11)).foregroundStyle(.secondary)
                                    ForEach(Array(capability.actions.enumerated()), id: \.offset) { _, action in
                                        Text(action.method + " " + action.path).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                                    }
                                }
                            }
                        }
                        if !catalog.template.bindings.isEmpty {
                            Divider()
                            ForEach(bindings.indices, id: \.self) { index in
                                HStack(alignment: .top) {
                                    VStack(alignment: .leading) {
                                        Text("固定范围 \(index + 1)").font(.system(size: 12, weight: .semibold))
                                        ForEach(catalog.template.bindings.keys.sorted(), id: \.self) { key in
                                            TextField(key, text: Binding(get: { bindings[index][key] ?? "" }, set: { bindings[index][key] = $0 })).textFieldStyle(.roundedBorder)
                                        }
                                    }
                                    if bindings.count > 1 { Button("移除") { bindings.remove(at: index) } }
                                }
                            }
                            Button("添加一组范围") { bindings.append([:]) }
                        }
                    }.padding(.vertical, 4)
                }.frame(maxHeight: 280)
                Toggle("使用恢复密钥", isOn: $recovery).font(.system(size: 12))
                SecureField(recovery ? "恢复密钥" : "当前保险库密码", text: $proof).textFieldStyle(.roundedBorder)
            }
            if let failure { Text(failure).font(.system(size: 12)).foregroundStyle(.red) }
            HStack {
                Button("取消") { proof = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("安装所选能力") { submit() }.buttonStyle(PrimaryButton()).disabled(!complete || loading || model.busy)
            }
        }.padding(26).frame(width: 600).background(canvas)
            .task(id: sourceRevision) {
                loadRevision = UUID(); catalog = nil; catalogSource = nil; selected = []; bindings = [[:]]; proof = ""; loading = false
                if provider != "generic-bearer" { await loadCatalog() }
            }
            .onDisappear { proof = ""; loadRevision = UUID() }
    }
    private func sourceRequest() throws -> Data {
        var source: [String: Any] = ["kind": provider]
        if provider == "generic-bearer" {
            source["origin"] = origin
            source["actions"] = try targets.split(whereSeparator: \.isNewline).map { line -> [String: String] in
                let parts = line.split(maxSplits: 1, whereSeparator: \.isWhitespace)
                guard parts.count == 2 else { throw UIError(message: "每个目标应为 METHOD /path。") }
                return ["method": String(parts[0]), "path": String(parts[1]).trimmingCharacters(in: .whitespaces)]
            }
        }
        return try JSONSerialization.data(withJSONObject: ["source": source], options: [.sortedKeys])
    }
    private func loadCatalog() async {
        let requestID = UUID(), revision = model.nativeFlowRevision, workspace = model.stateDirectory, client = model.cli
        loadRevision = requestID; loading = true; catalog = nil; catalogSource = nil; failure = nil
        defer { if loadRevision == requestID { loading = false } }
        do {
            let source = try sourceRequest()
            let result = try await Task.detached { try client.templateCatalog(source: source) }.value
            guard !Task.isCancelled && loadRevision == requestID && model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
            catalog = result; catalogSource = source; catalogWorkspace = workspace; catalogRevision = revision
            name = result.template.display; selected = []; bindings = [[:]]
        } catch { if loadRevision == requestID { failure = error.localizedDescription } }
    }
    private func submit() {
        guard complete, let source = catalogSource else { return }
        do {
            guard var request = try JSONSerialization.jsonObject(with: source) as? [String: Any] else { throw UIError(message: "模板来源无效。") }
            request["credential_id"] = credential; request["bindings"] = bindings; request["capabilities"] = selected.sorted(); request["name_prefix"] = name
            request["timeout_ms"] = 30000; request["request_max_bytes"] = 1024 * 1024; request["allowed_extra_headers"] = [] as [String]
            request["response_max_bytes"] = 4 * 1024 * 1024; request["allowed_response_headers"] = ["content-type"]
            var operation = Operation(title: "安装模板", detail: "", arguments: ["template", "install", "--stdin-request"], targetDirectory: catalogWorkspace)
            operation.templateRequest = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys])
            let currentProof = proof, useRecovery = recovery
            proof = ""; dismiss()
            Task { await model.perform(operation, proof: currentProof, recovery: useRecovery) }
        } catch { failure = error.localizedDescription }
    }
}

struct SessionForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var selected: Set<String> = []
    @State private var ttl = "15m"
    @State private var uses = "20"
    @State private var principal = ""
    @State private var proof = ""
    var body: some View {
        VStack(alignment: .leading, spacing: 18) {
            Text("创建 Agent 授权").font(.system(size: 24, weight: .semibold))
            Text("选择允许的固定操作。签名策略也必须允许本次授权的主体与操作。").font(.system(size: 12)).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment: .leading, spacing: 12) {
                    ForEach(model.actions.filter(\.enabled)) { action in
                        Toggle(action.name, isOn: Binding(get: { selected.contains(action.reference) }, set: { value in if value { selected.insert(action.reference) } else { selected.remove(action.reference) } }))
                    }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }.frame(maxHeight: 190)
            HStack { Text("有效期"); TextField("例如 15m", text: $ttl); Text("使用次数"); TextField("20", text: $uses) }.textFieldStyle(.roundedBorder)
            TextField("已有策略的主体 UUID（留空创建新主体）", text: $principal).textFieldStyle(.roundedBorder)
            SecureField("当前保险库密码", text: $proof).textFieldStyle(.roundedBorder)
            HStack {
                Button("取消") { proof = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("创建授权") {
                    var args = ["session", "create", "--ttl", ttl, "--max-uses", uses]
                    if !principal.isEmpty { args += ["--principal", principal] }
                    for ref in selected.sorted() { args += ["--action", ref] }
                    let p = proof; proof = ""; dismiss()
                    Task { await model.perform(Operation(title: "创建授权", detail: "", arguments: args, sensitiveResult: true), proof: p) }
                }.buttonStyle(PrimaryButton()).disabled(selected.isEmpty || ttl.isEmpty || (Int(uses) ?? 0) <= 0 || (!principal.isEmpty && UUID(uuidString: principal) == nil) || !singleLine(proof) || model.busy)
            }
        }.padding(30).frame(width: 490).background(canvas).onDisappear { proof = "" }
    }
}

struct ApprovalDetailView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let details: ApprovalDetails
    @State private var exportMessage: String?
    @State private var failure: String?
    private var challenge: ApprovalChallenge { details.envelope.challenge }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("审批请求详情").font(.system(size: 24, weight: .semibold))
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    Text("信封只有参数摘要，不包含原始请求正文、请求头或内容类型。请在独立签名工具中核对原始请求、操作定义与策略后再授权。").font(.system(size: 13)).foregroundStyle(.secondary)
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(context.date.timeIntervalSince1970 * 1000 >= Double(challenge.max_expires_at_ms) ? "此审批已过期；请重新准备请求。" : "这是读取时的快照；请求可能已被撤销或使用。")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    SectionCard(title: "请求与操作", icon: "doc.text.magnifyingglass") {
                        row("请求 ID", challenge.approval_request_id)
                        row("租户", challenge.tenant_id)
                        row("主体", challenge.principal_id)
                        row("会话", challenge.session_id)
                        row("固定操作", "\(challenge.action_id)@\(challenge.action_version)")
                        row("资源类型", challenge.resource.type)
                        row("资源 ID", challenge.resource.id)
                        row("参数 schema", challenge.schema_id)
                        row("参数 SHA-256", challenge.parameter_sha256)
                        if let action = details.matchingAction(in: model.actions) {
                            row("本机当前操作定义（未包含在签名信封内）", "\(action.name)\n\(action.method) \(action.origin)\(action.target.summary)")
                        } else {
                            Text("本机列表中没有相同 ID 与版本的操作定义，无法在此显示 HTTP 目标。").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                    }
                    SectionCard(title: "策略与授权边界", icon: "checkmark.shield") {
                        row("策略版本", String(challenge.policy_version))
                        row("策略 SHA-256", challenge.policy_sha256)
                        row("策略规则", challenge.policy_rule_id)
                        row("审批模式", challenge.mode)
                        row("所需签名", "\(challenge.quorum) 人")
                        row("允许的审批人 ID", challenge.approver_ids.joined(separator: "\n"))
                        row("最大使用次数", String(challenge.max_uses))
                        row("创建时间", "\(displayDate(challenge.created_at_ms)) · \(challenge.created_at_ms) ms")
                        row("有效期至", "\(displayDate(challenge.max_expires_at_ms)) · \(challenge.max_expires_at_ms) ms")
                    }
                    NativeApprovalForm(details: details).environmentObject(model)
                    SectionCard(title: "来源与签名核验", icon: "signature") {
                        Text("本窗口未验证信封签名。下方公钥来自当前本机 Authority；请与独立固定的公钥比较，并使用 rekey-approval-sign 验证信封。审批私钥始终留在独立签名工具中。").font(.system(size: 12)).foregroundStyle(.secondary)
                        row("来源公钥（\(details.origin.algorithm)）", details.origin.public_key)
                        DisclosureGroup("查看原始签名信封") {
                            Text(String(decoding: details.data, as: UTF8.self)).font(.system(size: 11, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }.padding(.trailing, 8)
            }
            if let exportMessage { Text(exportMessage).font(.system(size: 12)).textSelection(.enabled) }
            if let failure { Text(failure).font(.system(size: 12)).foregroundStyle(.red) }
            HStack {
                Button("导出此信封快照") {
                    guard let file = chooseSave("approval-\(details.id).json") else { return }
                    do { try writePrivateNew(details.data, to: file); failure = nil; exportMessage = "已保存：" + file.path }
                    catch { exportMessage = nil; failure = error.localizedDescription }
                }.disabled(model.busy || !model.unlocked)
                Spacer()
                Button("关闭") { model.approvalDetails = nil; dismiss() }.keyboardShortcut(.cancelAction)
            }
        }.padding(28).frame(width: 740, height: 680).background(canvas)
    }
    private func row(_ label: String, _ value: String) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label).font(.system(size: 11)).foregroundStyle(.secondary)
            Text(value).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
        }
    }
}

struct ResultView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let result: ResultMessage
    @State private var saved = false
    @State private var failure: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Label(result.title, systemImage: "checkmark.circle").font(.system(size: 22, weight: .semibold)).foregroundStyle(green)
            if result.sensitive {
                Text("以下内容只在这个窗口显示。请保存到你控制的安全位置，关闭后无法在这里重新查看。").font(.system(size: 13)).foregroundStyle(.secondary)
            }
            ScrollView { Text(result.text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading).padding(15) }.frame(maxHeight: 300).background(sage.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
            if result.sensitive { Toggle("我已安全保存所需内容", isOn: $saved).font(.system(size: 12)) }
            if let failure { Text(failure).foregroundStyle(.red).font(.system(size: 12)) }
            HStack {
                Button("另存为文件") {
                    guard let file = chooseSave(result.sensitive ? "rekey-private-result.txt" : "rekey-receipt.txt") else { return }
                    do { try writePrivateNew(Data(result.text.utf8), to: file); saved = true }
                    catch { failure = error.localizedDescription }
                }
                Spacer()
                Button("完成") { model.result = nil; dismiss() }.buttonStyle(PrimaryButton()).disabled(result.sensitive && !saved)
            }
        }.padding(30).frame(width: 570).background(canvas).interactiveDismissDisabled(result.sensitive)
    }
}


struct PolicyDraftForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var draft: NativeFileSnapshot?
    @State private var message: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("审阅未签名草稿").font(.system(size: 24, weight: .semibold))
            Text("此文本尚未验证或签名。这里只中转原始文件，不编辑规则或保管私钥。")
            Button("选择草稿（最多 64 KiB）") {
                guard let file = chooseFile() else { return }
                draft = nil; message = nil
                do { draft = try NativeFileSnapshot.read(file, limit: 65536) }
                catch { message = error.localizedDescription }
            }
            if let draft {
                ScrollView { Text(draft.text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                Button("原样导出到新私有文件") {
                    guard let destination = chooseSave("DRAFT.json") else { return }
                    do { try writePrivateNew(draft.data, to: destination); message = "原始快照已导出。" }
                    catch { message = error.localizedDescription }
                }
            }
            Text("下一步：在独立工具运行 rekey-policy-sign review DRAFT.json，完整核对后按其 reviewed digest 签名。再回到策略页，分别安装信任根、激活签名策略；这两步仍需 Admin step-up。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            if let message { Text(message).font(.system(size: 12)).textSelection(.enabled) }
            HStack { Spacer(); Button("关闭") { draft = nil; message = nil; model.showPolicyDraft = false; dismiss() }.keyboardShortcut(.cancelAction) }
        }.padding(28).frame(width: 720, height: 620).background(canvas)
        .onChange(of: model.nativeFlowRevision) { _, _ in draft = nil; message = nil }
        .onDisappear { draft = nil; message = nil }
    }
}

struct NativeApprovalForm: View {
    @EnvironmentObject var model: AppModel
    let details: ApprovalDetails
    @State private var requestBody: NativeFileSnapshot?
    @State private var grantOne: NativeFileSnapshot?
    @State private var grantTwo: NativeFileSnapshot?
    @State private var capability = ""
    @State private var confirmed = false
    @State private var submitting = false
    @State private var attempted = false
    @State private var result: NativeExecuteResult?
    @State private var message: String?
    @State private var intent = UUID()
    private var action: FixedAction? { details.matchingAction(in: model.actions) }
    private var bodyLimit: Int { min(1024 * 1024, max(0, action?.request_max_bytes ?? 1024 * 1024)) }
    var body: some View {
        SectionCard(title: "原始正文与独立签名交接", icon: "doc.badge.arrow.up") {
            Text("此流程固定 application/json，无额外请求头。导出文件不是审批或授权；来源公钥必须经独立可信渠道固定。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            Button("选择原始 JSON 正文") {
                guard let file = chooseFile() else { return }
                requestBody = nil; result = nil; message = nil; confirmed = false
                do { requestBody = try NativeFileSnapshot.read(file, limit: bodyLimit, json: true) }
                catch { message = error.localizedDescription }
            }.disabled(submitting)
            if let requestBody {
                Text("原始正文快照 · \(requestBody.data.count) bytes").font(.system(size: 11))
                Text(requestBody.text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                Button("导出私有 REQUEST.json") {
                    guard let destination = chooseSave("REQUEST.json") else { return }
                    do { try writePrivateNew(approvalHandoff(details, body: requestBody), to: destination); message = "请求交接文件已导出；尚未授权。" }
                    catch { message = error.localizedDescription }
                }.disabled(submitting)
            }
            Text("下一步：使用独立 rekey-approval-sign review/sign，另外核对 Action、policy、trust 和固定来源公钥，生成签名 grant。本窗口不调用签名工具。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            Divider()
            Text("使用签名 grant 显式执行一次").font(.system(size: 14, weight: .semibold))
            Text("固定操作：\(details.envelope.challenge.action_id)@\(details.envelope.challenge.action_version)")
                .font(.system(size: 12, design: .monospaced))
            if let action {
                Text("本机相同版本的目标（不是信封中的授权证明）：\(action.method) \(action.origin)\(action.target.summary)").font(.system(size: 12))
            } else { Text("缺少相同版本的本机操作定义；请刷新核对后再执行，不能使用最新版本替代。").foregroundStyle(.secondary) }
            HStack {
                Button("选择 grant 1（最多 4 KiB）") { loadGrant(second: false) }
                Button("选择可选 grant 2（最多 4 KiB）") { loadGrant(second: true) }
                if grantTwo != nil { Button("移除 grant 2") { grantTwo = nil; confirmed = false } }
            }.disabled(submitting)
            if let grantOne { DisclosureGroup("grant 1 原始快照 · \(grantOne.data.count) bytes") { Text(grantOne.text).font(.system(size: 11, design: .monospaced)).textSelection(.enabled) } }
            if let grantTwo { DisclosureGroup("grant 2 原始快照 · \(grantTwo.data.count) bytes") { Text(grantTwo.text).font(.system(size: 11, design: .monospaced)).textSelection(.enabled) } }
            SecureField("当前会话 capability（仅匿名 stdin）", text: $capability).disabled(submitting || attempted)
            Toggle("我已核对原始正文、精确版本和独立签名 grant，确认提交一次", isOn: $confirmed).disabled(submitting || attempted)
            Button(submitting ? "等待执行结果…" : "提交一次执行") { execute() }
                .disabled(!model.unlocked || model.busy || action == nil || requestBody == nil || grantOne == nil || capability.isEmpty || !confirmed || submitting || attempted)
            if let result {
                Text("HTTP \(result.metadata.upstream_status) · CLI 已返回，请核对状态与正文").font(.system(size: 13, weight: .semibold))
                Text(result.metadataText).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                if let text = String(data: result.body, encoding: .utf8) { Text(text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled) }
                else { Text("二进制响应 · \(result.body.count) bytes") }
                Button("将响应原始字节另存为新私有文件") {
                    guard let destination = chooseSave("rekey-response.bin") else { return }
                    do { try writePrivateNew(result.body, to: destination); message = "响应字节已保存。" }
                    catch { message = error.localizedDescription }
                }
            }
            if let message { Text(message).font(.system(size: 12)).textSelection(.enabled) }
            Text("Broker 是唯一授权校验方。关闭、失焦或中断不会撤回已提交的远端效果；结果未确认时检查审计，勿自动重试。私有快照清理不表示安全擦除。")
                .font(.system(size: 11)).foregroundStyle(.secondary)
        }
        .onChange(of: model.nativeFlowRevision) { _, _ in clear() }
        .onDisappear { clear() }
    }
    private func loadGrant(second: Bool) {
        guard let file = chooseFile() else { return }
        if second { grantTwo = nil } else { grantOne = nil }
        result = nil; message = nil; confirmed = false
        do {
            let snapshot = try NativeFileSnapshot.read(file, limit: 4096)
            if second { grantTwo = snapshot } else { grantOne = snapshot }
        } catch { message = error.localizedDescription }
    }
    private func clear() {
        intent = UUID(); capability = ""; requestBody = nil; grantOne = nil; grantTwo = nil
        result = nil; message = nil; confirmed = false
    }
    private func execute() {
        guard model.unlocked, !model.busy, !submitting, !attempted, confirmed, let requestBody, let grantOne, let action,
              requestBody.data.count <= action.request_max_bytes else { return }
        let grants = [grantOne] + (grantTwo.map { [$0] } ?? [])
        let token = capability
        capability = ""; confirmed = false; attempted = true; submitting = true; result = nil; message = nil
        let currentIntent = intent, revision = model.nativeFlowRevision, workspace = model.stateDirectory
        let client = model.cli
        model.busy = true
        Task {
            defer { model.busy = false; submitting = false }
            do {
                let response = try await Task.detached { try client.executeApproval(details, body: requestBody, grants: grants, capability: token) }.value
                guard intent == currentIntent, NSApp.isActive, model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
                result = response
            } catch {
                guard intent == currentIntent, NSApp.isActive, model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
                clear()
                message = error.localizedDescription
            }
        }
    }
}
