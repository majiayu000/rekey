import SwiftUI
import AppKit

func singleLine(_ value: String) -> Bool {
    !value.isEmpty && !value.contains("\n") && !value.contains("\r") && !value.contains("\0")
}
struct PeerSecurityWarning: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if model.status?.peer_security != "verified_signature" {
            Label("L1-dev · 服务签名未校验。密码、恢复密钥或系统认证授权将发送给未验证签名的本地服务，请仅在可信开发环境使用。", systemImage: "exclamationmark.triangle")
                .font(.system(size: 12)).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
        }
    }
}
struct OperationForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    let operation: Operation
    @State private var proof = ""
    @State private var secret = ""
    @State private var confirmation = ""
    @State private var recovery = false
    @State private var presence = false
    @State private var rememberPresence = false
    @State private var protectedFlow = false
    @State private var sessionID = ""
    @State private var hash = ""
    @State private var destination: URL?
    @State private var policyMode = "personal"
    @State private var restorePreview: RestorePreview?
    @State private var recoveryError: String?
    private var isRollback: Bool { operation.arguments.first == "rollback-confirm" }
    private var restoreSelection: RestoreSelection? {
        guard isRestore, operation.arguments.count == 3, let destination else { return nil }
        return RestoreSelection(input: operation.arguments[2], sha256: hash, target: destination.path, recovery: recovery)
    }
    private var isInit: Bool { operation.arguments.first == "init" }
    private var isRestore: Bool { operation.arguments.first == "restore" }
    private var revokeSession: Bool { operation.arguments == ["session", "revoke"] }
    private var valid: Bool {
        (presence || singleLine(proof)) && (!operation.newSecret || singleLine(secret)) &&
        (!operation.confirmSecret || confirmation == (operation.newSecret ? secret : proof)) &&
        (!revokeSession || UUID(uuidString: sessionID) != nil) &&
        (!isRestore || (hash.count == 64 && hash.allSatisfy(\.isHexDigit) && destination != nil)) &&
        (!isRollback || (operation.rollbackRevision == model.nativeFlowRevision && operation.targetDirectory == model.stateDirectory && operation.rollbackContext == model.status?.rollback))
    }
    var body: some View {
        if isRestore || isRollback {
            ScrollView { form }.frame(maxHeight: 640)
        } else { form }
    }
    private var form: some View {
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
                Text("源备份：" + (operation.arguments.last ?? "")).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                HStack { Text(destination?.path ?? "请选择空目录").font(.system(size: 11)).textSelection(.enabled); Spacer(); Button("选择恢复目录") { destination = chooseFile(directory: true) } }
                Text("先只读验证备份，再审阅实际目标并单独确认。验证不会安装备份或更新历史锚；确认后不会自动解锁。")
                if let preview = restorePreview {
                    Text(preview.context.summary).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                    Text("确认目标：" + preview.selection.target + "\n输入：" + preview.selection.input + "\n校验值：" + preview.selection.sha256).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
                    Text("请重新输入源备份的密码或恢复密钥，再确认恢复。")
                }
            }
            if isRollback, let context = operation.rollbackContext {
                Text(context.summary).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                Text("确认目录：" + (operation.targetDirectory ?? "")).font(.system(size: 11, design: .monospaced)).textSelection(.enabled)
            }
            if isRollback && operation.rollbackRevision != model.nativeFlowRevision { Text("上下文已改变，请关闭并重新审阅当前快照。").foregroundStyle(.red) }
            if let recoveryError { Text(recoveryError).foregroundStyle(.red).textSelection(.enabled) }
            if !isInit && !isRestore { PeerSecurityWarning() }
            if operation.presenceAllowed && model.unlocked {
                Toggle("使用系统认证批准本次操作", isOn: $presence).disabled(model.busy)
                    .onChange(of: presence) { _, _ in proof = ""; recovery = false }
            }
            if operation.recoveryAllowed && !presence {
                Toggle("使用恢复密钥", isOn: $recovery).font(.system(size: 12)).disabled(model.busy)
            }
            if !presence { SecureField(recovery ? "恢复密钥" : operation.arguments.first == "init" ? "设置保险库密码" : "当前保险库密码", text: $proof).textFieldStyle(.roundedBorder) }
            if operation.arguments == ["unlock"] {
                Toggle("启用系统认证（授权有效期 7 天）", isOn: $rememberPresence).disabled(model.busy)
                Text("仅在本次解锁成功后保存受系统认证保护的新授权；不会导入旧授权。").font(.system(size: 11)).foregroundStyle(.secondary)
                Button("用系统认证解锁") {
                    let revision = model.nativeFlowRevision
                    protectedFlow = true; clear()
                    Task { await model.unlockWithPresence(revision: revision); dismiss() }
                }.disabled(model.busy)
            }
            if operation.newSecret { SecureField(operation.arguments.first == "password" ? "新密码" : "新凭证值", text: $secret).textFieldStyle(.roundedBorder) }
            if operation.confirmSecret { SecureField("再次输入新密码", text: $confirmation).textFieldStyle(.roundedBorder) }
            Text("输入仅用于本次操作，不会保存。").font(.system(size: 11)).foregroundStyle(.secondary)
            HStack {
                Button("取消") { clear(); if isRestore || isRollback { model.clearNativeFlow() }; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                if isRestore || isRollback {
                    Button(isRestore ? (restorePreview == nil ? "只读验证并预览" : "确认恢复到所示目录") : "确认所示回滚快照") { recover() }
                        .buttonStyle(PrimaryButton()).disabled(!valid || model.busy || (isRollback && operation.rollbackContext == nil))
                } else {
                Button("确认\(operation.title)") {
                    var op = operation
                    if isInit { op = Operation(title: op.title, detail: op.detail, arguments: op.arguments + ["--mode", policyMode], confirmSecret: true, sensitiveResult: true, recoveryAllowed: false) }
                    if revokeSession { op = Operation(title: op.title, detail: op.detail, arguments: op.arguments + [sessionID]) }
                    let p = proof, s = secret, useRecovery = recovery, usePresence = presence, remember = rememberPresence
                    let revision = model.nativeFlowRevision
                    protectedFlow = usePresence || remember
                    clear(); if !protectedFlow { dismiss() }
                    Task {
                        await model.perform(op, proof: p, secret: s, recovery: useRecovery, presence: usePresence, rememberPresence: remember, presenceRevision: revision)
                        if usePresence || remember { dismiss() }
                    }
                }.buttonStyle(PrimaryButton()).disabled(!valid || model.busy)
                }
            }
        }.padding(30).frame(width: isRestore || isRollback ? 620 : 460).background(canvas)
            .onChange(of: hash) { _, _ in if isRestore { model.clearNativeFlow() } }
            .onChange(of: destination) { _, _ in if isRestore { model.clearNativeFlow() } }
            .onChange(of: recovery) { _, _ in proof = ""; if isRestore { model.clearNativeFlow() } }
            .onChange(of: model.nativeFlowRevision) { _, _ in clear(); restorePreview = nil; recoveryError = nil }
            .onDisappear { clear(); restorePreview = nil; if protectedFlow || isRestore || isRollback { model.clearNativeFlow() } }
    }
    private func clear() { proof = ""; secret = ""; confirmation = "" }
    private func recover() {
        let value = proof, useRecovery = recovery, revision = model.nativeFlowRevision, workspace = model.stateDirectory
        let selection = restoreSelection, preview = restorePreview
        clear(); recoveryError = nil
        if preview != nil { restorePreview = nil }
        Task {
            do {
                if isRestore, let selection {
                    if let preview { try await model.confirmRestore(preview, selection: selection, proof: value); dismiss() }
                    else {
                        let received = try await model.inspectRestore(selection, proof: value)
                        guard revision == model.nativeFlowRevision, workspace == model.stateDirectory, restoreSelection == selection else { return }
                        restorePreview = received
                    }
                } else if let context = operation.rollbackContext, let capturedRevision = operation.rollbackRevision, let capturedWorkspace = operation.targetDirectory {
                    try await model.confirmRollback(context, workspace: capturedWorkspace, revision: capturedRevision, proof: value, recovery: useRecovery); dismiss()
                }
            } catch {
                guard revision == model.nativeFlowRevision, workspace == model.stateDirectory else { return }
                recoveryError = error.localizedDescription
            }
        }
    }
}

struct AddCredentialForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var label = ""
    @State private var kind = "add"
    @State private var secret = ""
    @State private var proof = ""
    @State private var presence = false
    @State private var profile: URL?
    private var valid: Bool { !label.trimmingCharacters(in: .whitespaces).isEmpty && (kind == "add" ? singleLine(secret) : (presence || singleLine(proof)) && profile != nil) }
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
            PeerSecurityWarning()
            if kind == "add" { SecureField("粘贴 API Key，无需 Bearer 前缀", text: $secret).textFieldStyle(.roundedBorder) }
            else {
                HStack { Text(profile?.lastPathComponent ?? "选择私有 JSON 配置文件").font(.system(size: 12)); Spacer(); Button("选择文件") { profile = chooseFile() } }
                Text("配置文件须归当前用户所有，且不可被其他用户读取。内容与权限由服务验证。").font(.system(size: 11)).foregroundStyle(.secondary)
            }
            if kind == "add" && !secret.isEmpty && secret.utf8.count < 16 {
                Text("密钥短于 16 字节，嵌入编码的反射遮蔽覆盖有限。建议使用服务商生成的完整 Key。")
                    .font(.system(size: 11)).foregroundStyle(.orange)
            }
            if kind != "add" {
                Toggle("使用系统认证批准本次操作", isOn: $presence).disabled(model.busy)
                if !presence { SecureField("当前保险库密码", text: $proof).textFieldStyle(.roundedBorder) }
            }
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
                    let p = proof, s = secret, usePresence = presence, revision = model.nativeFlowRevision
                    clear(); if !usePresence { dismiss() }
                    Task { await model.perform(op, proof: p, secret: s, presence: usePresence, presenceRevision: revision); if usePresence { dismiss() } }
                }.buttonStyle(PrimaryButton()).disabled(!valid || model.busy || (kind == "add" && !model.desktopReady))
            }
        }.padding(30).frame(width: 480).background(canvas).onDisappear { clear(); if presence { model.clearNativeFlow() } }
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
    @State private var presence = false
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
            Toggle("使用系统认证批准本次操作", isOn: $presence).disabled(model.busy)
            PeerSecurityWarning()
            if !presence { SecureField("当前保险库密码", text: $proof).textFieldStyle(.roundedBorder) }
            if let failure { Text(failure).font(.system(size: 12)).foregroundStyle(.red) }
            HStack {
                Button("取消") { proof = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("创建操作") { submit() }.buttonStyle(PrimaryButton()).disabled(name.isEmpty || credential.isEmpty || origin.isEmpty || path.isEmpty || (!presence && !singleLine(proof)) || model.busy)
            }
        }.padding(30).frame(width: 520).background(canvas).onDisappear { proof = ""; if presence { model.clearNativeFlow() } }
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
            let p = proof, usePresence = presence, revision = model.nativeFlowRevision
            proof = ""; if !usePresence { dismiss() }
            Task { await model.perform(op, proof: p, presence: usePresence, presenceRevision: revision); if usePresence { dismiss() } }
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
    @State private var presence = false
    @State private var failure: String?
    private var sourceRevision: String { provider + "\n" + origin + "\n" + targets }
    private var complete: Bool {
        guard let catalog else { return false }
        return !name.isEmpty && !credential.isEmpty && !selected.isEmpty && (presence || singleLine(proof))
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
                Text("GLM（Anthropic 协议）").tag("glm")
                Text("GLM（Responses 协议）").tag("glm-responses")
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
                                    Text("风险：\(capability.risk)").font(.system(size: 11)).foregroundStyle(.secondary)
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
                Toggle("使用系统认证批准本次操作", isOn: $presence).disabled(model.busy)
                PeerSecurityWarning()
                if !presence {
                    Toggle("使用恢复密钥", isOn: $recovery).font(.system(size: 12))
                    SecureField(recovery ? "恢复密钥" : "当前保险库密码", text: $proof).textFieldStyle(.roundedBorder)
                }
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
            .onDisappear { proof = ""; loadRevision = UUID(); if presence { model.clearNativeFlow() } }
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
            let currentProof = proof, useRecovery = recovery, usePresence = presence, revision = model.nativeFlowRevision
            proof = ""; if !usePresence { dismiss() }
            Task { await model.perform(operation, proof: currentProof, recovery: useRecovery, presence: usePresence, presenceRevision: revision); if usePresence { dismiss() } }
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
    @State private var presence = false
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
            Toggle("使用系统认证批准本次操作", isOn: $presence).disabled(model.busy)
            PeerSecurityWarning()
            if !presence { SecureField("当前保险库密码", text: $proof).textFieldStyle(.roundedBorder) }
            HStack {
                Button("取消") { proof = ""; dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("创建授权") {
                    var args = ["session", "create", "--ttl", ttl, "--max-uses", uses]
                    if !principal.isEmpty { args += ["--principal", principal] }
                    for ref in selected.sorted() { args += ["--action", ref] }
                    let p = proof, usePresence = presence, revision = model.nativeFlowRevision
                    proof = ""; if !usePresence { dismiss() }
                    Task { await model.perform(Operation(title: "创建授权", detail: "", arguments: args, sensitiveResult: true), proof: p, presence: usePresence, presenceRevision: revision); if usePresence { dismiss() } }
                }.buttonStyle(PrimaryButton()).disabled(selected.isEmpty || ttl.isEmpty || (Int(uses) ?? 0) <= 0 || (!principal.isEmpty && UUID(uuidString: principal) == nil) || (!presence && !singleLine(proof)) || model.busy)
            }
        }.padding(30).frame(width: 490).background(canvas).onDisappear { proof = ""; if presence { model.clearNativeFlow() } }
    }
}

struct LocalApprovalView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var failure: String?
    @FocusState private var rejectFocused: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let details = model.localApprovalDetails {
                Text(details.review?.action_name ?? "本机审批").font(.system(size: 22, weight: .semibold))
                TimelineView(.periodic(from: .now, by: 1)) { timeline in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(details.state.label).foregroundStyle(.secondary)
                        if let review = details.review {
                            Text("\(review.method) \(review.origin)").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                            Text("资源：\(review.challenge.resource.type) / \(review.challenge.resource.id)").textSelection(.enabled)
                            Text("有效期至 \(displayDate(review.challenge.max_expires_at_ms))").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                        Text("请完整审阅下方请求。批准只授权这次请求，不会替 Agent 执行。").font(.system(size: 12)).foregroundStyle(.secondary)
                        if !details.raw.isEmpty {
                            ScrollView([.vertical, .horizontal]) {
                                Text(details.text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .topLeading).padding(12)
                            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Color.black.opacity(0.03))
                            Text("正文包含目标、参数、查询、请求体、请求头、策略与会话的完整快照。").font(.system(size: 11)).foregroundStyle(.secondary)
                        } else { Spacer(); Text("此请求已结束，完整正文已释放。"); Spacer() }
                        if let failure { Text(failure).font(.system(size: 12)).foregroundStyle(.red).textSelection(.enabled) }
                        PeerSecurityWarning()
                        HStack {
                            Button("关闭") { model.clearNativeFlow(); dismiss() }.keyboardShortcut(.cancelAction)
                            Button("查询最新状态") { failure = nil; Task { await model.reviewLocalApproval(details.id) } }.disabled(model.busy)
                            Spacer()
                            Button("拒绝") { decide(details, approve: false) }.keyboardShortcut(.defaultAction).focused($rejectFocused)
                                .disabled(!details.canDecide(at: timeline.date) || !model.unlocked || model.busy || model.localApprovalNeedsRefresh)
                            Button("系统认证并批准") { decide(details, approve: true) }
                                .disabled(!details.canDecide(at: timeline.date) || !model.unlocked || model.busy || model.localApprovalNeedsRefresh)
                        }
                    }
                }
            }
        }.padding(28).frame(width: 820, height: 720).background(canvas)
            .onAppear { rejectFocused = true }
            .onDisappear { model.clearNativeFlow() }
    }
    private func decide(_ details: LocalApprovalDetails, approve: Bool) {
        failure = nil
        Task {
            do { try await model.decideLocalApproval(details, approve: approve) }
            catch {
                if model.acceptsNativeCompletion(details.revision, workspace: details.workspace) { failure = error.localizedDescription }
            }
        }
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
                    if case .ed25519 = challenge.approver {
                        Text("信封只有参数摘要，不包含原始请求正文、请求头或内容类型。请在独立签名工具中核对原始请求、操作定义与策略后再授权。").font(.system(size: 13)).foregroundStyle(.secondary)
                    } else {
                        Text("当前详情只有参数摘要，缺少完整请求内容，不能据此批准本机审批。").font(.system(size: 13)).foregroundStyle(.secondary)
                    }
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
                        row("审批方式", challenge.approver.summary)
                        if case let .ed25519(keys, _) = challenge.approver {
                            row("允许的审批公钥", keys.joined(separator: "\n"))
                        }
                        row("最大使用次数", String(challenge.max_uses))
                        row("创建时间", "\(displayDate(challenge.created_at_ms)) · \(challenge.created_at_ms) ms")
                        row("有效期至", "\(displayDate(challenge.max_expires_at_ms)) · \(challenge.max_expires_at_ms) ms")
                    }
                    if case .ed25519 = challenge.approver {
                        NativeApprovalForm(details: details).environmentObject(model)
                    } else {
                        Text("此请求需要本机系统认证，当前暂不可批准。").font(.system(size: 12)).foregroundStyle(.secondary)
                    }
                    SectionCard(title: "来源与签名核验", icon: "signature") {
                        if case .ed25519 = challenge.approver {
                            Text("本窗口未验证信封签名。下方公钥来自当前本机 Authority；请与独立固定的公钥比较，并使用 rekey-approval-sign 验证信封。审批私钥始终留在独立签名工具中。").font(.system(size: 12)).foregroundStyle(.secondary)
                        } else {
                            Text("本窗口未验证信封签名，下方公钥与信封仅供查看。").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
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
    var body: some View {
        if model.policy?.mode == .personal { PersonalPolicyDraftForm(seed: model.onboardingProfile) }
        else if model.policy?.mode == .team { TeamPolicyDraftForm() }
        else { Text("请解锁后重新检查策略模式。").padding(28) }
    }
}

private struct ProfileSummary: View {
    let profile: AgentProfile
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(profile.name).font(.headline)
            Text("主体：\(profile.principal_id.uuidString.lowercased())").textSelection(.enabled)
            Text("会话：\(profile.session.ttl_ms) 毫秒，最多 \(profile.session.max_uses) 次；每次启动确认：\(profile.confirm_each_run ? "是" : "否")")
            Text("隔离声明：\(profile.isolation.rawValue)；网络声明：\(profile.egress.rawValue)")
            ForEach(profile.grants.indices, id: \.self) { index in
                let grant = profile.grants[index]
                Text("实例：\(grant.instance)")
                ForEach(grant.capabilities.indices, id: \.self) { cap in
                    Text("能力：\(grant.capabilities[cap].capability) · 基线：\(grant.capabilities[cap].rule.label)\n" + grant.capabilities[cap].actions.map { "\($0.action_id.uuidString.lowercased())@\($0.version)" }.joined(separator: "\n"))
                        .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                }
            }
            ForEach(profile.llm_limits.indices, id: \.self) { index in
                let limit = profile.llm_limits[index]
                Text("\(limit.instance) 模型：\(limit.models.joined(separator: ", "))\n单次输出：\(limit.max_output_tokens_per_request)；每日请求：\(limit.max_requests_per_day)；每日输出：\(limit.max_output_tokens_per_day)")
                    .textSelection(.enabled)
            }
        }.frame(maxWidth: .infinity, alignment: .leading).padding(12).background(.white.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
    }
}

private struct ProfileEditor: View {
    @Binding var profile: AgentProfile
    let available: [FixedAction]
    private var templates: [FixedAction] { available.filter { $0.enabled && $0.template != nil } }
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("Profile 名称（字母、数字、_、-）", text: $profile.name)
            Text("稳定主体：\(profile.principal_id.uuidString.lowercased())").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            HStack {
                Text("会话时长（毫秒，最多 24 小时）")
                TextField("时长", value: $profile.session.ttl_ms, format: .number.grouping(.never))
                Text("使用次数（最多 10000）")
                TextField("次数", value: $profile.session.max_uses, format: .number.grouping(.never))
            }
            Toggle("每次启动都确认", isOn: $profile.confirm_each_run)
            HStack {
                Picker("隔离", selection: $profile.isolation) {
                    Text("无隔离").tag(AgentProfile.Isolation.none)
                    Text("macOS Seatbelt").tag(AgentProfile.Isolation.seatbelt)
                    Text("Linux 网络命名空间").tag(AgentProfile.Isolation.netns)
                }
                Picker("网络", selection: $profile.egress) {
                    Text("允许").tag(AgentProfile.Egress.allow)
                    Text("拒绝其它目标").tag(AgentProfile.Egress.denyOther)
                }
            }
            Text("这些是签名策略声明。当前启动器不支持的隔离或网络要求会拒绝启动，不会自动降级。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            ForEach(profile.grants.indices, id: \.self) { index in
                VStack(alignment: .leading, spacing: 8) {
                    HStack {
                        TextField("实例名称（稳定路由名称）", text: Binding(get: { profile.grants[index].instance }, set: { name in
                            let old = profile.grants[index].instance
                            profile.grants[index].instance = name
                            for limit in profile.llm_limits.indices where profile.llm_limits[limit].instance == old { profile.llm_limits[limit].instance = name }
                        }))
                        Button("移除此实例", role: .destructive) {
                            let old = profile.grants.remove(at: index).instance
                            profile.llm_limits.removeAll { $0.instance == old }
                        }
                    }
                    ForEach(templates) { action in
                        if let source = action.template?.source, let id = UUID(uuidString: action.id) {
                            let reference = AgentProfile.ActionRef(action_id: id, version: action.version)
                            Toggle(isOn: Binding(get: { profile.grants[index].capabilities.contains { $0.capability == source.capability && $0.actions.contains(reference) } }, set: { selected in
                                if selected {
                                    if let cap = profile.grants[index].capabilities.firstIndex(where: { $0.capability == source.capability }) {
                                        profile.grants[index].capabilities[cap].actions.append(reference)
                                    } else { profile.grants[index].capabilities.append(.init(capability: source.capability, actions: [reference])) }
                                } else {
                                    for cap in profile.grants[index].capabilities.indices { profile.grants[index].capabilities[cap].actions.removeAll { $0 == reference } }
                                    profile.grants[index].capabilities.removeAll { $0.actions.isEmpty }
                                }
                            })) {
                                Text("\(source.capability) · \(action.name) · \(action.reference)\n\(source.template) · 凭据 \(action.credential_id)\n\(action.method) \(action.origin)\(action.target.summary)\n默认规则：\(action.template?.defaultPolicy.rule ?? "")")
                                    .font(.system(size: 12)).textSelection(.enabled)
                            }
                        }
                    }
                    ForEach(profile.grants[index].capabilities.indices, id: \.self) { cap in
                        let selected = profile.grants[index].capabilities[cap]
                        Picker(selected.capability + " · 基线规则", selection: $profile.grants[index].capabilities[cap].rule) {
                            ForEach(AgentProfile.Rule.allCases, id: \.self) { rule in Text(rule.label).tag(rule) }
                        }
                        if selected.rule == .allow && templates.contains(where: { action in
                            selected.actions.contains(where: { $0.action_id.uuidString.lowercased() == action.id.lowercased() && $0.version == action.version }) && action.template?.defaultPolicy.rule == "require-approval"
                        }) {
                            Text("这会取消此能力模板默认的逐次审批，让 Agent 在已签授权范围内直接执行。请在下一步完整差异中核对并明确签名。")
                                .font(.system(size: 12)).foregroundStyle(.orange)
                        }
                    }
                    let missing = profile.grants[index].capabilities.flatMap(\.actions).filter { ref in !templates.contains { $0.id.lowercased() == ref.action_id.uuidString.lowercased() && $0.version == ref.version } }
                    if !missing.isEmpty {
                        Text("此实例含已禁用、退休或不可用的操作引用；不会自动换版本。请移除此实例并重新选择。\n" + missing.map { "\($0.action_id.uuidString.lowercased())@\($0.version)" }.joined(separator: "\n"))
                            .foregroundStyle(.orange).textSelection(.enabled)
                    }
                    if let limit = profile.llm_limits.firstIndex(where: { $0.instance == profile.grants[index].instance }) {
                        Text("允许的模型（每行一个，不能为空）")
                        TextEditor(text: Binding(get: { profile.llm_limits[limit].models.joined(separator: "\n") }, set: { profile.llm_limits[limit].models = $0.components(separatedBy: "\n") })).frame(height: 70)
                        HStack {
                            Text("单次最大输出")
                            TextField("tokens", value: $profile.llm_limits[limit].max_output_tokens_per_request, format: .number.grouping(.never))
                            Text("每日请求数")
                            TextField("次数", value: $profile.llm_limits[limit].max_requests_per_day, format: .number.grouping(.never))
                            Text("每日输出 tokens")
                            TextField("tokens", value: $profile.llm_limits[limit].max_output_tokens_per_day, format: .number.grouping(.never))
                        }
                        Button("移除模型与预算限制", role: .destructive) { profile.llm_limits.remove(at: limit) }
                    } else {
                        Button("设置模型白名单与预算") {
                            profile.llm_limits.append(.init(instance: profile.grants[index].instance, models: [], max_output_tokens_per_request: 4096, max_requests_per_day: 100, max_output_tokens_per_day: 100_000))
                        }.disabled(profile.grants[index].instance.isEmpty)
                    }
                    Text("LLM 实例必须提供白名单和正数上限。服务根据认证的能力校验，缺少限制会拒绝生成。")
                        .font(.system(size: 12)).foregroundStyle(.secondary)
                }.padding(12).background(.white.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
            }
            Button("添加实例") { profile.grants.append(.init(instance: "", capabilities: [])) }
        }
    }
}

struct PersonalPolicyDraftForm: View {
    var seed: AgentProfile? = nil
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var profiles: [AgentProfile] = []
    @State private var baseline: ProfileList?
    @State private var available: [FixedAction] = []
    @State private var selectedIndex: Int?
    @State private var expiry = Date().addingTimeInterval(86400)
    @State private var draft: PersonalPolicyDraft?
    @State private var proof = ""
    @State private var recovery = false
    @State private var presence = false
    @State private var confirmed = false
    @State private var attempted = false
    @State private var message: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("个人策略 · 完整替换").font(.system(size: 24, weight: .semibold))
            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    if let draft {
                        ForEach(draft.profiles.indices, id: \.self) { ProfileSummary(profile: draft.profiles[$0]) }
                        Text("有效期至：\(displayDate(draft.expiresAtMs))")
                        Text("保险库：\(draft.metadata.vault_id.uuidString.lowercased())\n版本：\(draft.metadata.base_version.map(String.init) ?? "无") → \(draft.metadata.next_version)\n策略摘要：\(draft.metadata.policy_sha256)")
                            .font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                        Text("全部变化（before / after，包含删除）").font(.headline)
                        Text(draft.changesText).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        Text("所选操作完整定义（目标与 schema）").font(.headline)
                        Text(draft.actionsText).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                        Text("此草稿完整替换所有 Profile、规则、审批者和工作负载授权。删除的内容已列在前后变化中。")
                        Toggle("我已完整核对前后变化和操作定义，确认替换当前策略", isOn: $confirmed)
                            .disabled(model.busy || attempted)
                        Toggle("使用系统认证批准本次激活", isOn: $presence).disabled(model.busy || attempted)
                        PeerSecurityWarning()
                        if !presence {
                            Toggle("使用恢复密钥验证本次激活", isOn: $recovery).disabled(model.busy || attempted)
                            SecureField(recovery ? "恢复密钥" : "保险库密码", text: $proof).disabled(model.busy || attempted)
                        }
                        Text("策略仍由独立的 Secure Enclave 策略密钥签署；系统认证授权只用于本次激活验证。")
                            .font(.system(size: 12)).foregroundStyle(.secondary)
                        Button(model.personalPolicySigning ? "等待系统认证…" : "签署并激活一次") { activate(draft) }
                            .disabled(model.busy || !model.unlocked || !confirmed || (!presence && proof.isEmpty) || attempted)
                        Button("放弃此草稿，重新选择") { clear() }.disabled(model.busy)
                    } else {
                        if let baseline {
                            Text(baseline.policy_sha256 == nil ? "尚无策略；新增 Profile 后生成第一版策略。" : "已加载完整策略。编辑只在本窗口中保留，未选中的 Profile 不会被删除。")
                            if let prior = baseline.expires_at_ms { Text("当前策略有效期至：\(displayDate(prior))").foregroundStyle(.secondary) }
                            HStack {
                                Button("新增 Profile") { profiles.append(.newProfile()); selectedIndex = profiles.count - 1 }.disabled(model.busy)
                                Button("删除所选 Profile", role: .destructive) {
                                    if let index = selectedIndex, profiles.indices.contains(index) { profiles.remove(at: index); selectedIndex = nil }
                                }.disabled(selectedIndex == nil || model.busy)
                                Spacer()
                                Text("共 \(profiles.count) 个 Profile")
                            }
                            ForEach(profiles.indices, id: \.self) { index in
                                Button { selectedIndex = index } label: {
                                    HStack { Image(systemName: selectedIndex == index ? "checkmark.circle.fill" : "circle")
                                        Text(profiles[index].name.isEmpty ? "未命名 Profile" : profiles[index].name)
                                        Spacer(); Text(profiles[index].principal_id.uuidString.lowercased()).font(.system(size: 11, design: .monospaced))
                                    }
                                }.buttonStyle(.plain)
                            }
                            if let index = selectedIndex, profiles.indices.contains(index) {
                                Divider()
                                ProfileEditor(profile: $profiles[index], available: available).disabled(model.busy)
                            }
                            DatePicker("新策略有效期至", selection: $expiry, displayedComponents: [.date, .hourAndMinute])
                            if profiles.isEmpty { Text("当前列表为空：生成并激活后，将撤销全部 Profile 和旧策略授权。").foregroundStyle(.orange) }
                            HStack {
                                Button("生成完整替换草稿") { generate() }
                                    .disabled(expiry <= Date() || model.busy || !model.unlocked)
                                Button("放弃修改并重新加载") {
                                    clear(); self.baseline = nil; profiles = []; selectedIndex = nil; available = []
                                    Task { await load() }
                                }.disabled(model.busy)
                            }
                        } else {
                            Text("必须先成功加载完整 Profile 列表，才能编辑或生成草稿。")
                            Button("加载 Profile 列表") { Task { await load() } }.disabled(model.busy)
                        }
                    }
                    if let message { Text(message).textSelection(.enabled) }
                }.frame(maxWidth: .infinity, alignment: .leading)
            }
            Text("不自动重签或重试。激活结果未确认时，请检查当前策略与审计，再决定下一步。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            HStack {
                if model.busy { ProgressView().controlSize(.small) }
                Spacer()
                Button("关闭") { clear(); model.showPolicyDraft = false; dismiss(); Task { await model.refresh() } }
                    .keyboardShortcut(.cancelAction).disabled(model.busy)
            }
        }.padding(28).frame(width: 780, height: 720).background(canvas).interactiveDismissDisabled(model.busy)
        .task { await load() }
        .onChange(of: model.nativeFlowRevision) { _, _ in clear(); baseline = nil; profiles = []; selectedIndex = nil; available = [] }
        .onDisappear { clear(); model.clearNativeFlow() }
    }
    private func clear() { draft = nil; proof = ""; confirmed = false; attempted = false; message = nil }
    private func load() async {
        guard baseline == nil, !model.busy else { return }
        let revision = model.nativeFlowRevision, workspace = model.stateDirectory
        do {
            let loaded = try await model.loadProfileEditor()
            guard model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
            let all = try loaded.0.addingOnboardingProfile(seed)
            baseline = loaded.0; profiles = all; available = loaded.1
            selectedIndex = seed == nil ? (profiles.isEmpty ? nil : 0) : profiles.count - 1
            if let expires = loaded.0.expires_at_ms, expires > Int64(Date().timeIntervalSince1970 * 1000) {
                expiry = Date(timeIntervalSince1970: Double(expires) / 1000)
            }
        } catch {
            if model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription }
        }
    }
    private func generate() {
        guard let baseline, !model.busy else { return }
        let expiresAtMs = Int64(expiry.timeIntervalSince1970 * 1000)
        let selectedProfiles = profiles, revision = model.nativeFlowRevision, workspace = model.stateDirectory
        clear()
        Task {
            do {
                let result = try await model.personalPolicyDraft(profiles: selectedProfiles, expectedPolicySHA256: baseline.policy_sha256, expiresAtMs: expiresAtMs)
                guard model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
                draft = result
            } catch {
                guard model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
                message = error.localizedDescription
            }
        }
    }
    private func activate(_ draft: PersonalPolicyDraft) {
        guard confirmed, !attempted, !model.busy else { return }
        let currentProof = proof, useRecovery = recovery, usePresence = presence
        proof = ""; confirmed = false; attempted = true; message = nil
        Task {
            do {
                try await model.activatePersonalPolicy(draft, proof: currentProof, recovery: useRecovery, presence: usePresence)
                guard model.acceptsNativeCompletion(draft.revision, workspace: draft.workspace) else { return }
                message = "策略已激活。关闭窗口后刷新当前状态。"
            } catch {
                guard model.acceptsNativeCompletion(draft.revision, workspace: draft.workspace) else { return }
                message = error.localizedDescription
            }
        }
    }
}

struct TeamPolicyDraftForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var draft: NativeFileSnapshot?
    @State private var profiles: ProfileList?
    @State private var message: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("团队 Profile · 只读与外部签名").font(.system(size: 24, weight: .semibold))
            if let profiles {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        if profiles.profiles.isEmpty { Text("当前策略没有 Profile。") }
                        ForEach(profiles.profiles.indices, id: \.self) { ProfileSummary(profile: profiles.profiles[$0]) }
                        if let expires = profiles.expires_at_ms { Text("当前策略有效期至：\(displayDate(expires))") }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(maxHeight: 240)
            }
            Text("团队 Profile 由外部签名策略管理，本机不编辑或签署。以下文件尚未验证，只中转原始内容。")
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
        .task {
            let revision = model.nativeFlowRevision, workspace = model.stateDirectory
            do {
                let loaded = try await model.loadProfileEditor()
                if model.acceptsNativeCompletion(revision, workspace: workspace) { profiles = loaded.0 }
            } catch {
                if model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription }
            }
        }
        .onChange(of: model.nativeFlowRevision) { _, _ in draft = nil; profiles = nil; message = nil }
        .onDisappear { draft = nil; profiles = nil; message = nil; model.clearNativeFlow() }
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


struct OnboardingView: View {
    @EnvironmentObject var model: AppModel
    let route: OnboardingRoute
    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                HStack {
                    Text(route == .setup ? "开始使用 Rekey" : "接入 LLM 服务").font(.system(size: 25, weight: .semibold))
                    Spacer()
                    Button("关闭设置页面") { model.clearNativeFlow(); model.onboardingRoute = nil; Task { await model.refresh() } }.disabled(model.busy)
                }
                if route == .setup { setup }
                else { AnthropicOnboardingView() }
            }.padding(28).frame(maxWidth: 850, alignment: .leading)
        }
        .onDisappear { model.clearNativeFlow() }
    }
    private var setup: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("每一步由你明确确认。密码不会跨步骤保存；已有保险库和信任根不会被重建。")
            if model.needsSetup {
                Text("1 · 选择个人或团队模式，设置密码并离线保存恢复密钥。模式创建后不可更改。")
                Button("创建保险库") { model.beginSetup() }.buttonStyle(PrimaryButton()).disabled(model.busy)
            } else if model.status == nil {
                Text("2 · 保险库已存在。启用本用户登录启动，并连接已验证的服务。")
                Button(model.serviceStartTitle) { model.startService() }.buttonStyle(PrimaryButton()).disabled(model.busy)
                if model.backgroundServiceNeedsApproval { Button("打开系统登录项设置") { BackgroundService.openSettings() } }
                Button("检查服务状态") { Task { await model.refresh() } }.disabled(model.busy)
                Text(model.backgroundServiceDescription ?? "服务状态尚未确认；系统接受启动请求不代表服务已就绪。")
            } else if !model.unlocked {
                Text("3 · 验证密码后解锁管理会话。此会话只能保存凭据，不能替代后续逐次授权。")
                Button("解锁管理会话") { model.requestDesktopLogin() }.buttonStyle(PrimaryButton()).disabled(model.busy)
            } else if model.policy?.mode == .team {
                Text("团队保险库已就绪。信任根和策略由外部签名器管理；此页面不创建个人签名密钥。")
                Button("打开外部签名入口") { model.page = .policy }
            } else if model.policy?.mode == .personal && model.policy?.trust_installed == false {
                Text("4 · 明确创建此保险库的 Secure Enclave 策略密钥并安装信任根。私钥不可导出，不会随备份转移。")
                Button("创建个人策略信任根") { model.beginPersonalPolicySetup() }.buttonStyle(PrimaryButton()).disabled(model.busy)
            } else if model.policy?.mode == .personal && model.policy?.trust_installed == true {
                Text("个人保险库与已验证的策略信任根已就绪。下一条命令会引导保存密钥并审阅授权。")
                Text("rekey add anthropic").font(.system(.body, design: .monospaced)).textSelection(.enabled)
            } else {
                Text("尚未获得已验证的策略状态，不能判定设置完成。")
                Button("重新检查") { Task { await model.refresh() } }.disabled(model.busy)
            }
        }
    }
}

private struct AnthropicOnboardingView: View {
    @EnvironmentObject var model: AppModel
    @State private var provider = "anthropic"
    @State private var label = "Anthropic"
    @State private var secret = ""
    @State private var credentialID = ""
    @State private var savedLabel: String?
    @State private var catalog: ProviderTemplateCatalog?
    @State private var capabilities = Set<String>()
    @State private var beta = false
    @State private var proof = ""
    @State private var presence = false
    @State private var installed: [FixedAction] = []
    @State private var existing: [FixedAction] = []
    @State private var existingSelection = Set<String>()
    @State private var modelID = ""
    @State private var profile: AgentProfile?
    @State private var message: String?
    @State private var loading = false
    private var ready: Bool { model.unlocked && model.policy?.mode == .personal && model.policy?.trust_installed == true }
    private var responses: Bool { provider == "glm-responses" }
    private var requiredCapability: String { responses ? "responses" : "messages" }
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("保存凭据与授予权限是两个阶段。取消或失败会保留已保存的凭据和操作，但不会自动授予权限或重试。")
            if !ready {
                Text("请先完成个人保险库设置并解锁。团队模式保留外部签名，不使用此个人授权流程。")
                Button("打开设置步骤") { model.openOnboarding(URL(string: OnboardingRoute.setup.rawValue)!) }.disabled(model.busy)
            } else {
                Picker("服务", selection: $provider) {
                    Text("Anthropic").tag("anthropic")
                    Text("GLM · Claude Code").tag("glm")
                    Text("GLM · Codex").tag("glm-responses")
                }.disabled(model.busy || !installed.isEmpty)
                if installed.isEmpty {
                    Text("1 · 保存凭据（只写入，不读取）").font(.headline)
                    if credentialID.isEmpty {
                        TextField("凭据名称", text: $label)
                        SecureField("API Key，无需 Bearer 前缀", text: $secret)
                        if !secret.isEmpty && secret.utf8.count < 16 {
                            Text("密钥短于 16 字节，嵌入编码的反射遮蔽覆盖有限。建议使用服务商生成的完整 Key。")
                                .font(.system(size: 11)).foregroundStyle(.orange)
                        }
                        if model.desktopReady {
                            Button("保存此 API Key") { save() }.disabled(model.busy || !singleLine(secret) || label.isEmpty)
                        } else { Button("解锁保存凭据的管理会话") { model.requestDesktopLogin() }.disabled(model.busy) }
                        Picker("或明确选择已保存的凭据", selection: $credentialID) {
                            Text("未选择").tag("")
                            ForEach(model.credentials.filter { $0.active && $0.kind == "opaque-token" }) { Text($0.label).tag($0.id) }
                        }
                    } else {
                        Text("已选凭据：" + (savedLabel ?? model.credentials.first(where: { $0.id == credentialID })?.label ?? credentialID))
                        Button("另选已保存凭据") { credentialID = ""; savedLabel = nil }.disabled(model.busy)
                    }
                    if !credentialID.isEmpty {
                        DisclosureGroup("使用已安装能力继续") {
                            Text("重新读取此凭据在所选服务的真实操作，明确选择精确版本。沿用已安装的请求头与限制，不会重新安装或修改操作。")
                            Button("读取已安装能力") { Task { await loadExisting() } }.disabled(model.busy)
                            ForEach(existing) { action in
                                Toggle(isOn: Binding(get: { existingSelection.contains(action.reference) }, set: { if $0 { existingSelection.insert(action.reference) } else { existingSelection.remove(action.reference) } })) {
                                    VStack(alignment: .leading) {
                                        Text((action.template?.source.capability ?? "") + " · " + action.reference)
                                        Text(action.method + " " + action.origin + action.target.summary).textSelection(.enabled)
                                    }
                                }
                            }
                            Button("使用所选版本继续，不重新安装") { installed = existing.filter { existingSelection.contains($0.reference) } }
                                .disabled(model.busy || !existing.contains(where: { existingSelection.contains($0.reference) && $0.template?.source.capability == requiredCapability }))
                        }
                    }
                    Divider()
                    Text("2 · 或安装新的所选能力（本次验证）").font(.headline)
                    if let catalog {
                        Text(catalog.template.origin).textSelection(.enabled)
                        ForEach(catalog.template.capabilities) { capability in
                            Toggle(isOn: Binding(get: { capabilities.contains(capability.id) }, set: { if $0 { capabilities.insert(capability.id) } else { capabilities.remove(capability.id) } })) {
                                Text(capability.id + " · " + capability.actions.map { $0.method + " " + $0.path }.joined(separator: "，"))
                            }
                        }
                        if !responses {
                            Toggle("我授权本次安装的操作接受 anthropic-beta 请求头（Claude Code 所需）", isOn: $beta)
                            Text("可选 beta=true 查询由内置模板声明；此选择不会改变全局模板或其它已安装操作。")
                        }
                        Toggle("使用系统认证批准本次安装", isOn: $presence).onChange(of: presence) { _, _ in proof = "" }
                        if !presence { SecureField("当前保险库密码", text: $proof) }
                        Button("安装所选能力") { install() }.disabled(model.busy || credentialID.isEmpty || (!responses && !beta) || !capabilities.contains(requiredCapability) || (!presence && !singleLine(proof)))
                    } else {
                        Button("读取内置能力") { Task { await loadCatalog() } }.disabled(model.busy || loading)
                    }
                } else {
                    Text("已安装 \(installed.count) 个操作；尚未因安装自动授予 Agent 权限。")
                    if let command = model.onboardingCommand {
                        Text("已完成本次策略激活。在该签名策略有效时，用明确的模型启动：").font(.headline)
                        Text(command).font(.system(.body, design: .monospaced)).textSelection(.enabled)
                        Button("复制启动命令") {
                            let board = NSPasteboard.general; board.clearContents()
                            if !board.setString(command, forType: .string) { message = "无法写入剪贴板，请手动选择启动命令。" }
                        }
                    } else if profile != nil {
                        ProfileEditor(profile: Binding(get: { profile! }, set: { profile = $0 }), available: installed).disabled(model.busy)
                        Text("随后加载并保留所有已有 Profile，展示完整替换差异、期限和操作定义；确认后才请求系统签名。")
                        Button("审阅完整策略") { model.onboardingProfile = profile; model.showPolicyDraft = true }.disabled(model.busy)
                    } else {
                        Text("3 · 明确准备 Profile（当前尚不授予权限）").font(.headline)
                        TextField(responses ? "精确模型 ID，例如 glm-5.3-flash" : "精确模型 ID，例如 claude-sonnet-4-6", text: $modelID)
                        Text(responses ? "单次输出上限32768；会话15分钟/100次、每日100次/100000tokens，默认无沙箱。下一步均可审阅修改。" : "建议单次输出上限32768；Claude 本轮实测会请求32000。会话15分钟/100次、每日100次/100000tokens，默认无沙箱。下一步均可审阅修改。")
                        Button("创建 Profile 草稿") {
                            do { profile = try AgentProfile.onboarding(actions: installed, model: modelID) }
                            catch { message = error.localizedDescription }
                        }.disabled(model.busy || modelID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                    }
                }
            }
            if let message { Text(message).foregroundStyle(.red).textSelection(.enabled) }
        }
        .task { if ready { await loadCatalog() } }
        .onChange(of: provider) { _, value in
            secret = ""; proof = ""; credentialID = ""; savedLabel = nil; catalog = nil; capabilities = []; beta = false; existing = []; existingSelection = []; message = nil
            label = value == "anthropic" ? "Anthropic" : "GLM"
            modelID = value == "anthropic" ? "" : "glm-5.3-flash"
            Task { await loadCatalog() }
        }
        .onChange(of: model.nativeFlowRevision) { _, _ in secret = ""; proof = ""; catalog = nil; capabilities = []; beta = false; message = nil; existing = []; existingSelection = [] }
        .onChange(of: credentialID) { _, _ in existing = []; existingSelection = [] }
        .onDisappear { secret = ""; proof = "" }
    }
    private func loadExisting() async {
        let revision = model.nativeFlowRevision, workspace = model.stateDirectory, id = credentialID
        let selectedProvider = provider
        message = nil; existing = []; existingSelection = []
        do {
            let actions = try await model.loadOnboardingActions(credentialID: id, provider: selectedProvider)
            guard provider == selectedProvider, credentialID == id, model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
            existing = actions
            if actions.isEmpty { message = "该凭据没有可继续使用的所选服务操作。" }
        } catch { if model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription } }
    }
    private func loadCatalog() async {
        guard ready, !model.busy else { return }
        let selectedProvider = provider
        loading = true; defer { if provider == selectedProvider { loading = false } }
        let client = model.cli, revision = model.nativeFlowRevision, workspace = model.stateDirectory
        do {
            let request = try JSONSerialization.data(withJSONObject: ["source": ["kind": selectedProvider]], options: [.sortedKeys])
            let result = try await Task.detached { try client.templateCatalog(source: request) }.value
            guard provider == selectedProvider, model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
            catalog = result
        } catch { if provider == selectedProvider, model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription } }
    }
    private func save() {
        let value = secret, name = label, revision = model.nativeFlowRevision, workspace = model.stateDirectory
        let selectedProvider = provider
        secret = ""; message = nil
        Task {
            do {
                let receipt = try await model.saveAPIKey(label: name, secret: value)
                guard provider == selectedProvider, model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
                credentialID = receipt.id; savedLabel = receipt.label
            } catch { if model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription } }
        }
    }
    private func install() {
        let value = proof, usePresence = presence, id = credentialID, selected = capabilities.sorted(), revision = model.nativeFlowRevision, workspace = model.stateDirectory
        let selectedProvider = provider
        proof = ""; message = nil
        Task {
            do {
                let actions = try await model.installOnboardingAnthropic(credentialID: id, capabilities: selected, proof: value, presence: usePresence, provider: selectedProvider)
                guard provider == selectedProvider, model.acceptsNativeCompletion(revision, workspace: workspace) else { return }
                installed = actions
            } catch { if model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription } }
        }
    }
}
