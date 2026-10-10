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
                Toggle("启用系统认证（授权有效期 \(model.securitySettings.passwordInterval.label)）", isOn: $rememberPresence).disabled(model.busy || model.securitySettings.passwordInterval == .everyUnlock)
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
    @EnvironmentObject var model:AppModel
    @Environment(\.dismiss) var dismiss
    @State private var label=""
    @State private var connectionName=""
    @State private var secret=""
    @State private var preset="github-pat"
    @State private var origin=""
    @State private var header="x-api-key"
    @State private var prefix=""
    @State private var saved:Credential?
    @State private var message:String?
    private var generic:Bool {preset.hasPrefix("generic-")}
    var body:some View {
        VStack(alignment:.leading,spacing:18) {
            Text("添加密钥与连接").font(.system(size:24,weight:.semibold))
            Text("密钥只交给 Rekey。选择预设、审阅规则并签署后，Agent 照常启动即可使用。").foregroundStyle(.secondary)
            if !OAuthSetup.presets.contains(preset) {TextField("密钥名称",text:$label).textFieldStyle(.roundedBorder).disabled(saved != nil)
            TextField("连接名称，例如 github-personal",text:$connectionName).textFieldStyle(.roundedBorder)}
            Picker("服务预设",selection:$preset) {
                ForEach(["github-pat","github-git","anthropic","openai","glm","glm-responses","generic-bearer","generic-header"]+OAuthSetup.presets,id:\.self) {Text($0).tag($0)}
            }.disabled(saved != nil)
            if OAuthSetup.presets.contains(preset) {OAuthAddForm(preset:preset).id(preset)} else {
            if generic {
                TextField("固定 origin，例如 https://api.example.com",text:$origin).textFieldStyle(.roundedBorder)
                if preset=="generic-header" {TextField("凭据头名称",text:$header).textFieldStyle(.roundedBorder);TextField("头前缀（可为空）",text:$prefix).textFieldStyle(.roundedBorder)}
                Text("自定义服务默认读和写都需要审批。").font(.caption).foregroundStyle(.secondary)
            }
            if saved==nil {SecureField("粘贴 API Key，无需 Bearer 前缀",text:$secret).textFieldStyle(.roundedBorder)}
            else {Label("密钥已保存；连接尚未激活。继续审阅规则，不会再次添加密钥。",systemImage:"checkmark.shield")}
            PeerSecurityWarning()
            if !model.desktopReady {Text("请先解锁管理会话。").foregroundStyle(.secondary)}
            if model.policy?.trust_installed != true {Text("请先在授权页完成此保险库的一次性签名密钥设置。").foregroundStyle(.secondary)}
            if let message {Text(message).foregroundStyle(.red).textSelection(.enabled)}
            HStack {Button("取消"){secret="";dismiss()}.keyboardShortcut(.cancelAction);Spacer();Button(saved==nil ? "保存并审阅规则":"继续审阅规则"){prepare()}.buttonStyle(PrimaryButton()).disabled(model.busy || !model.desktopReady || model.policy?.trust_installed != true || connectionName.isEmpty || saved==nil && (!singleLine(secret) || label.isEmpty) || generic && origin.isEmpty)}
            }
        }.padding(30).frame(width:530).background(canvas)
        .onAppear{preset=model.addPreset}
        .onDisappear{secret=""}
    }
    private func prepare() {
        let value=secret,name=label,connection=connectionName,selectedPreset=preset,selectedOrigin=origin,selectedHeader=header,selectedPrefix=prefix
        secret="";message=nil
        Task {
            do {
                let credential:Credential
                if let prior=saved {credential=prior}else{credential=try await model.saveAPIKey(label:name,secret:value);saved=credential}
                let definition=try await model.loadPreset(selectedPreset,origin:selectedOrigin,header:selectedPreset=="generic-header" ? selectedHeader:"",prefix:selectedPreset=="generic-header" ? selectedPrefix:"")
                model.onboardingConnection=definition.connection(name:connection,credentialID:credential.id)
                dismiss()
                await Task.yield()
                model.showPolicyDraft=true
            } catch {message=error.localizedDescription}
        }
    }
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
    @State private var window = "once"
    @State private var customMinutes = "30"
    @FocusState private var rejectFocused: Bool
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            if let details = model.localApprovalDetails {
                Text(details.review?.title ?? "本机审批").font(.system(size: 22, weight: .semibold))
                TimelineView(.periodic(from: .now, by: 1)) { timeline in
                    VStack(alignment: .leading, spacing: 8) {
                        Text(details.state.label).foregroundStyle(.secondary)
                        if let review = details.review {
                            if let ssh=review.ssh {
                                Text("用途：\(ssh.purposeLabel) · 用户：\(ssh.use.username ?? "不适用")").textSelection(.enabled)
                                Text("host：\(ssh.host)").textSelection(.enabled)
                                if ssh.bound_host_key==nil || ssh.host=="unknown-host" {Text("目标尚未绑定或未登记；本次批准不能验证 host 身份。").font(.caption).foregroundStyle(.orange)}
                                if let unverified=ssh.use.unverified_host {Text("请求声明的 host key（未经验证）：\(unverified)").font(.caption).textSelection(.enabled)}
                                Text("签名数据 SHA-256：\(ssh.data_sha256)").font(.system(size:11,design:.monospaced)).textSelection(.enabled)
                            } else {Text("\(review.method ?? "") \(review.origin ?? "")").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)}
                            Text("资源：\(review.challenge.resource.type) / \(review.challenge.resource.id)").textSelection(.enabled)
                            Text("有效期至 \(displayDate(review.challenge.max_expires_at_ms))").font(.system(size: 12)).foregroundStyle(.secondary)
                        }
                        Text("请完整审阅下方请求。批准后由 Agent 继续调用。").font(.system(size: 12)).foregroundStyle(.secondary)
                        if details.review?.windowAllowed == true {
                            Picker("批准范围",selection:$window) { Text("仅这次").tag("once");Text("30 分钟").tag("30");Text("自定义").tag("custom") }.pickerStyle(.segmented)
                            if window == "custom" { TextField("分钟（1–480）",text:$customMinutes).textFieldStyle(.roundedBorder) }
                            Text("时间窗只适用于同一连接、规则和调用方；锁定或更改策略后失效，拒绝规则始终有效。").font(.system(size:11)).foregroundStyle(.secondary)
                        }
                        if !details.raw.isEmpty {
                            ScrollView([.vertical, .horizontal]) {
                                Text(details.text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .topLeading).padding(12)
                            }.frame(maxWidth: .infinity, maxHeight: .infinity).background(Color.black.opacity(0.03))
                            Text(details.review?.ssh == nil ? "正文包含目标、参数、查询、请求体、请求头与策略的完整快照。":"正文包含用途、用户、host 绑定、公钥以及完整待签数据 base64；请审阅后明确决定。").font(.system(size: 11)).foregroundStyle(.secondary)
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
                                .disabled(!details.canDecide(at: timeline.date) || !model.unlocked || model.busy || model.localApprovalNeedsRefresh || (details.review?.windowAllowed == true && window == "custom" && !(1...480).contains(Int(customMinutes) ?? 0)))
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
            do { try await model.decideLocalApproval(details, approve: approve,windowSeconds:approve && details.review?.windowAllowed == true ? (window == "once" ? nil : UInt32(window == "30" ? 1800 : (Int(customMinutes) ?? 0) * 60)) : nil) }
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
                    if challenge.schema_id == "rekey.ssh-sign.v1" {
                        Text("此 SSH 请求需要独立签名审批。请使用 rekey approval review 获取完整签名内容，在 rekey-approval-sign 中核对后，通过 rekey approval submit 提交所需签名。").font(.system(size:12)).foregroundStyle(.secondary)
                    } else if case .ed25519 = challenge.approver {
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
                Button("完成") {
                    model.result = nil; dismiss()
                    if result.connectsAfterSaving { Task { await model.connectOnOpen() } }
                }.buttonStyle(PrimaryButton()).disabled(result.sensitive && !saved)
            }
        }.padding(30).frame(width: 570).background(canvas).interactiveDismissDisabled(result.sensitive)
    }
}


struct PolicyDraftForm: View {
    @EnvironmentObject var model: AppModel
    var body: some View {
        if model.policy?.mode == .personal { PersonalPolicyDraftForm(seed: model.onboardingConnection) }
        else if model.policy?.mode == .team { TeamPolicyDraftForm() }
        else { Text("请解锁后重新检查策略模式。").padding(28) }
    }
}

private struct ConnectionSummary:View {
    let connection:ConnectionDefinition
    var body:some View {
        VStack(alignment:.leading,spacing:6) {
            Text(connection.name).font(.headline)
            Text("\(connection.origin) · \(connection.grade)").textSelection(.enabled)
            ForEach(connection.rules) {rule in Text("\(rule.methods.text) \(rule.path) → \(rule.effect)").font(.system(size:12,design:.monospaced))}
            Text("调用方识别用于记录，不是身份认证；覆盖规则只能收紧。").font(.caption).foregroundStyle(.secondary)
            if connection.grade=="T1" {Text("Agent 进程会拿到短期、权限受限的临时凭证。").foregroundStyle(.orange)}
        }.frame(maxWidth:.infinity,alignment:.leading).padding(12).background(.white.opacity(0.6),in:RoundedRectangle(cornerRadius:8))
    }
}
private struct ConnectionEditor:View {
    @Binding var connection:ConnectionDefinition
    @State private var caller="codex"
    @State private var bindingName=""
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            TextField("连接名称",text:$connection.name).textFieldStyle(.roundedBorder)
            Text("\(connection.preset) · \(connection.origin)").textSelection(.enabled)
            Toggle("启用连接",isOn:$connection.enabled)
            Text("规则：read 包括 GET/HEAD 和签名预设声明的语义读；其他调用为 write。具体方法可用逗号列出。deny 优先；未匹配的调用拒绝。").font(.caption).foregroundStyle(.secondary)
            ForEach(connection.rules.indices,id:\.self) {i in
                HStack {
                    TextField("read / write / POST",text:Binding(get:{connection.rules[i].methods.text},set:{connection.rules[i].methods = .init(text:$0)})).frame(width:125)
                    TextField("路径模式",text:$connection.rules[i].path)
                    Picker("判定",selection:$connection.rules[i].effect) {Text("允许").tag("allow");Text("审批").tag("approve");Text("拒绝").tag("deny")}.frame(width:110)
                    Button(role:.destructive){connection.rules.remove(at:i)}label:{Image(systemName:"minus.circle")}
                }
            }
            Button("添加规则"){connection.rules.append(.init(id:UUID().uuidString.lowercased(),methods:.category("write"),path:"/**",effect:"approve"))}
            if !connection.bindings.isEmpty {
                ForEach(connection.bindings.keys.sorted(),id:\.self) {key in
                    TextField(connection.preset=="github-git" ? "\(key) 的固定值（repo 为完整仓库名，如 rekey.git；不允许 *）":"\(key) 的允许值（逗号分隔，* 表示任意 slug）",text:Binding(get:{connection.bindings[key]?.joined(separator:",") ?? ""},set:{connection.bindings[key]=$0.split(separator:",").map{String($0).trimmingCharacters(in:.whitespaces)}}))
                }
            }
            HStack { TextField("路径参数名（如 owner）",text:$bindingName);Button("添加允许值"){connection.bindings[bindingName]=[];bindingName=""}.disabled(bindingName.isEmpty || connection.bindings[bindingName] != nil) }
            HStack {TextField("调用方标注",text:$caller);Button("限制此调用方为只读"){connection.caller_overrides[caller]=[.init(id:UUID().uuidString.lowercased(),methods:.category("write"),path:"/**",effect:"deny")]}}
            ForEach(connection.caller_overrides.keys.sorted(),id:\.self) {label in
                HStack {Text("\(label)：\(connection.caller_overrides[label]?.map{"\($0.methods.text) \($0.path) → \($0.effect)"}.joined(separator:"；") ?? "")");Spacer();Button("移除"){connection.caller_overrides.removeValue(forKey:label)}}.font(.caption)
            }
            Text("调用方识别用于记录，不是身份认证。缺少标注时使用默认规则。").font(.caption).foregroundStyle(.secondary)
            HStack {Text("每小时请求数");TextField("次数",value:$connection.limits.requests_per_hour,format:.number.grouping(.never))}
            if connection.llm != nil {
                Text("允许的精确模型 ID（每行一个）").font(.caption)
                TextEditor(text:Binding(get:{connection.llm?.models.joined(separator:"\n") ?? ""},set:{connection.llm?.models=$0.components(separatedBy:"\n").filter{!$0.isEmpty}})).frame(height:65)
                HStack {Text("每次输出 token 上限");TextField("tokens",value:Binding(get:{connection.llm?.max_tokens ?? 0},set:{connection.llm?.max_tokens=$0}),format:.number.grouping(.never))}
                HStack {Text("每日请求");TextField("次数",value:Binding(get:{connection.llm?.max_requests_per_day ?? 0},set:{connection.llm?.max_requests_per_day=$0}),format:.number.grouping(.never));Text("每日输出 token");TextField("tokens",value:Binding(get:{connection.llm?.max_output_tokens_per_day ?? 0},set:{connection.llm?.max_output_tokens_per_day=$0}),format:.number.grouping(.never))}
            }
            Text("具名操作："+connection.operations.map(\.name).joined(separator:", ")).font(.caption).textSelection(.enabled)
            if let oauth=connection.oauth {Text("已签名 OAuth client ID："+oauth.client_id);Text((oauth.provider=="notion" ? "Portal capabilities：":"Scope ceiling：")+oauth.scopes.joined(separator:", ")).font(.caption).textSelection(.enabled)}
            if connection.preset=="github-git" {Text("Git smart HTTP 固定 owner / repo。GET info/refs 与 POST git-upload-pack 为读，POST git-receive-pack 为写；默认请求正文上限 1 MiB。").font(.caption).foregroundStyle(.secondary)}
        }
    }
}

private struct SSHKeySummary:View {
    let key:SSHKeyDefinition
    var body:some View {
        VStack(alignment:.leading,spacing:6){
            Text("SSH · "+key.name).font(.headline)
            Text(key.publicKeyText).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
            Text("git 签名："+key.git_signing+"；未登记或未绑定 host：审批").font(.caption)
            Text("每个连接最多 \(key.session_budget.max_signatures) 次签名，有效 \(key.session_budget.max_seconds) 秒；"+(key.approver.kind=="ed25519" ? "需 \(key.approver.threshold ?? 0) 名签名审批人":"本机确认")).font(.caption)
            ForEach(key.hosts.indices,id:\.self){i in
                Text(key.hosts[i].host+" · "+key.hosts[i].effect+" · rule "+key.hosts[i].rule_id).font(.caption)
                Text(key.hosts[i].host_key).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
            }
        }
    }
}
private struct SSHKeyEditor:View {
    @Binding var key:SSHKeyDefinition
    var body:some View {
        VStack(alignment:.leading,spacing:10){
            TextField("SSH 连接名称",text:$key.name)
            Text("公钥（可复制到目标服务）").font(.caption)
            Text(key.publicKeyText).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
            Picker("git 签名",selection:$key.git_signing){Text("审批").tag("approve");Text("允许").tag("allow");Text("拒绝").tag("deny")}
            ForEach(key.hosts.indices,id:\.self){i in
                TextField("已登记 host",text:$key.hosts[i].host)
                Text("Host 公钥：base64 wire blob、OpenSSH 公钥或 known_hosts 条目。请从独立可信来源核对；不会自动信任扫描结果。").font(.caption).foregroundStyle(.secondary)
                TextEditor(text:$key.hosts[i].host_key).font(.system(size:11,design:.monospaced)).frame(height:65)
                Picker("此 host 判定",selection:$key.hosts[i].effect){Text("审批").tag("approve");Text("允许").tag("allow");Text("拒绝").tag("deny")}
                Text("规则 ID："+key.hosts[i].rule_id).font(.caption).textSelection(.enabled)
                Button("删除此 host 规则",role:.destructive){key.hosts.remove(at:i)}
            }
            Button("登记 host 公钥"){key.hosts.append(.init(host:"",host_key:"",rule_id:UUID().uuidString.lowercased(),effect:"approve"))}
        }.padding(12).background(.quaternary,in:RoundedRectangle(cornerRadius:8))
    }
}

struct PersonalPolicyDraftForm:View {
    var seed:ConnectionDefinition?=nil
    @EnvironmentObject var model:AppModel
    @Environment(\.dismiss) var dismiss
    @State private var connections:[ConnectionDefinition]=[]
    @State private var derived:[DerivedCredentialDefinition]=[]
    @State private var sshKeys:[SSHKeyDefinition]=[]
    @State private var sshSocket=""
    @State private var sshLabel=""
    @State private var sshMode:SSHKeyMode = .secureEnclave
    @State private var sshPresence=true
    @State private var sshRecovery=false
    @State private var sshProof=""
    @State private var showRootCredential=false
    @State private var derivedCredential=""
    @State private var derivedKind="aws-assume-role"
    @State private var baseline:ConnectionList?
    @State private var selectedIndex:Int?
    @State private var expiry=Date().addingTimeInterval(86400)
    @State private var draft:PersonalPolicyDraft?
    @State private var proof=""
    @State private var recovery=false
    @State private var presence=true
    @State private var confirmed=false
    @State private var attempted=false
    @State private var message:String?
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            Text("连接与规则 · 审阅后签署").font(.system(size:24,weight:.semibold))
            ScrollView {
                VStack(alignment:.leading,spacing:14) {
                    if let draft {
                        ForEach(draft.connections){ConnectionSummary(connection:$0)}
                        ForEach(draft.sshKeys){key in SSHKeySummary(key:key)}
                        ForEach(draft.derivedCredentials){grant in Text("T1 · Agent会拿到 \(grant.max_ttl_seconds/60) 分钟临时值：\n"+grant.publicDescription).font(.system(size:12,design:.monospaced)).foregroundStyle(.orange).textSelection(.enabled)}
                        Text("版本 \(draft.metadata.base_version.map(String.init) ?? "无") → \(draft.metadata.next_version)，有效期至 \(displayDate(draft.expiresAtMs))")
                        Text("完整变化（before / after，包含删除）").font(.headline)
                        Text(draft.changesText).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                        Text("HTTP / SSH / T1 完整签名定义与参数 schema").font(.headline)
                        Text(draft.actionsText).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                        Toggle("我已审阅完整变化，确认替换连接规则",isOn:$confirmed).disabled(model.busy || attempted)
                        Toggle("使用系统认证签署并激活",isOn:$presence).disabled(model.busy || attempted)
                        PeerSecurityWarning()
                        if !presence {Toggle("使用恢复密钥",isOn:$recovery);SecureField(recovery ? "恢复密钥":"保险库密码",text:$proof)}
                        Button(model.personalPolicySigning ? "等待系统认证…":"签署并激活一次"){activate(draft)}.buttonStyle(PrimaryButton()).disabled(model.busy || !confirmed || attempted || !presence && proof.isEmpty)
                        Button("放弃草稿，继续编辑"){clear()}.disabled(model.busy)
                    } else if baseline != nil {
                        Text("编辑完整已签署授权集合。allow 不打扰；approve 进入审批；deny 直接拒绝。HTTP / SSH / T1 将一起审阅并保存。")
                        ForEach(connections.indices,id:\.self){i in Button{selectedIndex=i}label:{HStack{Image(systemName:selectedIndex==i ? "checkmark.circle.fill":"circle");Text(connections[i].name);Spacer();Text(connections[i].origin).font(.caption)}}.buttonStyle(.plain)}
                        if let i=selectedIndex,connections.indices.contains(i){ConnectionEditor(connection:$connections[i]).disabled(model.busy);Button("删除此连接",role:.destructive){connections.remove(at:i);selectedIndex=nil}.disabled(model.busy)}
                        Button("添加连接"){dismiss();model.showAddCredential=true}.disabled(model.busy)
                        if let i=selectedIndex,connections.indices.contains(i),connections[i].oauth != nil {Button("打开浏览器 OAuth 授权"){let name=connections[i].name;dismiss();model.showPolicyDraft=false;model.onboardingRoute = .oauth(name)}}
                        Divider()
                        Text("SSH · 私钥不导出").font(.headline)
                        if !sshSocket.isEmpty {Text("IdentityAgent："+sshSocket).font(.system(size:12,design:.monospaced)).textSelection(.enabled)}
                        Text("已加载完整签名 SSH 集合。删除连接只撤销签名权限；不会删除保险库里的密钥。未知 host 或缺少 session-bind 需要审批，明确 deny 不能用窗口绕过。").font(.caption)
                        ForEach(sshKeys.indices,id:\.self){i in
                            SSHKeyEditor(key:$sshKeys[i]).disabled(model.busy)
                            Button("撤销此 SSH 连接",role:.destructive){sshKeys.remove(at:i)}.disabled(model.busy)
                        }
                        TextField("新 SSH 密钥的凭据名称",text:$sshLabel)
                        Picker("密钥存储",selection:$sshMode){ForEach(SSHKeyMode.allCases,id:\.self){mode in Text(mode.label).tag(mode)}}
                        Text("默认使用 macOS Secure Enclave；不自动回退软件。生成后只显示公钥，仍须审阅并签署 SSH 连接规则。").font(.caption).foregroundStyle(.secondary)
                        Toggle("使用系统认证生成 SSH 密钥",isOn:$sshPresence).disabled(model.busy)
                        if !sshPresence {Toggle("使用恢复密钥生成",isOn:$sshRecovery);SecureField(sshRecovery ? "恢复密钥":"保险库密码",text:$sshProof)}
                        PeerSecurityWarning()
                        Button("生成密钥并添加待签署 SSH 连接"){generateSSH()}.disabled(model.busy || sshLabel.isEmpty || !sshPresence && sshProof.isEmpty)
                        Divider()
                        Text("T1 · 派生临时凭据").font(.headline)
                        ForEach(derived.indices,id:\.self){i in DerivedGrantEditor(grant:$derived[i]);Button("撤销此T1连接",role:.destructive){derived.remove(at:i)}}
                        Picker("根凭据",selection:$derivedCredential){Text("选择已保存的 AWS / GitHub App 根凭据").tag("");ForEach(model.credentials.filter{$0.active && ["aws-static","github-app-installation"].contains($0.kind)}){Text($0.label).tag($0.id)}}
                        Picker("派生方式",selection:$derivedKind){Text("AWS AssumeRole").tag("aws-assume-role");Text("EKS kubectl").tag("kubernetes-eks");Text("GitHub App").tag("github-app")}
                        HStack{Button("添加T1授权"){addDerived()}.disabled(derivedCredential.isEmpty || model.busy);Button("保存派生根凭据"){showRootCredential=true}.disabled(model.busy)}
                        DatePicker("策略有效期至",selection:$expiry,displayedComponents:[.date,.hourAndMinute])
                        if connections.isEmpty {Text("签署空集合将撤销全部 HTTP 连接。").foregroundStyle(.orange)}
                        Button("生成完整审阅草稿"){generate()}.buttonStyle(PrimaryButton()).disabled(model.busy || expiry<=Date())
                    } else {Text("先加载已认证连接列表。");Button("重新加载"){Task{await load()}}.disabled(model.busy)}
                    if let message{Text(message).foregroundStyle(.red).textSelection(.enabled)}
                }.frame(maxWidth:.infinity,alignment:.leading)
            }
            Text("未确认或认证取消时不激活。签名与激活失败不会自动重试。").font(.caption).foregroundStyle(.secondary)
            HStack {if model.busy{ProgressView()};Spacer();Button("关闭"){clear();model.showPolicyDraft=false;dismiss();Task{await model.refresh()}}.disabled(model.busy)}
        }.padding(28).frame(width:780,height:720).background(canvas).interactiveDismissDisabled(model.busy)
        .task{await load()}
        .onChange(of:model.nativeFlowRevision){_,_ in clear();baseline=nil;connections=[];derived=[];sshKeys=[];sshSocket="";selectedIndex=nil}
        .onDisappear{clear();model.clearNativeFlow()}
        .sheet(isPresented:$showRootCredential){RootCredentialForm().environmentObject(model)}
    }
    private func addDerived(){
        guard let credential=model.credentials.first(where:{$0.id==derivedCredential}),credential.kind==(derivedKind=="github-app" ? "github-app-installation":"aws-static")else{message="根凭据类型与派生方式不符。";return}
        var target=DerivedCredentialDefinition.Target(kind:derivedKind)
        if derivedKind=="aws-assume-role"{target.role_arn="";target.region="us-east-1";target.session_policy = .object([:])}
        else if derivedKind=="kubernetes-eks"{target.cluster_id="";target.region="us-east-1"}
        else{target.installation_id=0;target.repository_ids=[];target.permissions=[:]}
        derived.append(.init(name:"t1-"+UUID().uuidString.lowercased().prefix(8),credential_id:credential.id,effect:"approve",max_ttl_seconds:derivedKind=="github-app" ? 3600:900,target:target))
    }
    private func clear(){draft=nil;proof="";sshProof="";confirmed=false;attempted=false;message=nil}
    private func load() async {
        guard baseline==nil,!model.busy else{return}
        let revision=model.nativeFlowRevision,workspace=model.stateDirectory
        do {
            let loaded=try await model.loadConnectionEditor()
            guard model.acceptsNativeCompletion(revision,workspace:workspace)else{return}
            var all=loaded.connections
            if let seed {guard !all.contains(where:{$0.name==seed.name})else{throw UIError(message:"已有同名连接；请关闭后编辑现有项。")};all.append(seed)}
            let sshStatus=try await model.loadSSHStatus()
            guard model.acceptsNativeCompletion(revision,workspace:workspace)else{return}
            baseline=loaded;connections=all;derived=loaded.derived_credentials;sshKeys=loaded.ssh_keys;sshSocket=sshStatus.socket;selectedIndex=all.isEmpty ? nil:all.count-1
            if let expires=loaded.expires_at_ms,expires>Int64(Date().timeIntervalSince1970*1000){expiry=Date(timeIntervalSince1970:Double(expires)/1000)}
        } catch{if model.acceptsNativeCompletion(revision,workspace:workspace){message=error.localizedDescription}}
    }
    private func generate(){
        guard let baseline,!model.busy else{return}
        var keys=sshKeys
        for i in keys.indices {for j in keys[i].hosts.indices {keys[i].hosts[j].host_key=SSHHostDefinition.wireBlob(keys[i].hosts[j].host_key)}}
        let ssh=keys,selected=connections,grants=derived,expires=Int64(expiry.timeIntervalSince1970*1000),revision=model.nativeFlowRevision,workspace=model.stateDirectory
        clear()
        Task{do{let result=try await model.personalPolicyDraft(connections:selected,sshKeys:ssh,derivedCredentials:grants,expectedPolicySHA256:baseline.policy_sha256,expiresAtMs:expires);guard model.acceptsNativeCompletion(revision,workspace:workspace)else{return};draft=result}catch{if model.acceptsNativeCompletion(revision,workspace:workspace){message=error.localizedDescription}}}
    }
    private func generateSSH(){
        guard baseline != nil,!model.busy else{return}
        let label=sshLabel,mode=sshMode,proof=sshProof,usePresence=sshPresence,useRecovery=sshRecovery,revision=model.nativeFlowRevision,workspace=model.stateDirectory
        sshProof="";message=nil
        Task{do{
            let receipt=try await model.generateSSHKey(label:label,mode:mode,proof:proof,recovery:useRecovery,presence:usePresence)
            guard model.acceptsNativeCompletion(revision,workspace:workspace)else{return}
            sshKeys.append(.init(name:"ssh-"+UUID().uuidString.lowercased().prefix(8),credential_id:receipt.credential.id,user_public_key:receipt.public_key,hosts:[],git_signing:"approve"))
            sshLabel="";message="密钥已保存在保险库。请登记并独立核对 host 公钥，审阅完整草稿后签署；尚未启用 SSH 权限。"
        }catch{if model.acceptsNativeCompletion(revision,workspace:workspace){message=error.localizedDescription+"\n结果未知时先检查凭据列表，勿自动重试。"}}}
    }
    private func activate(_ draft:PersonalPolicyDraft){
        guard confirmed,!attempted,!model.busy else{return}
        let value=proof,usePresence=presence,useRecovery=recovery;proof="";attempted=true;confirmed=false
        Task{do{try await model.activatePersonalPolicy(draft,proof:value,recovery:useRecovery,presence:usePresence);guard model.acceptsNativeCompletion(draft.revision,workspace:draft.workspace)else{return};message="规则已激活。运行 rekey connect 完成接入，Agent 照常启动。"}catch{if model.acceptsNativeCompletion(draft.revision,workspace:draft.workspace){message=error.localizedDescription}}}
    }
}

struct TeamPolicyDraftForm: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var draftText = ""
    @State private var version = 1
    @State private var expiry = Date().addingTimeInterval(30 * 24 * 60 * 60)
    @State private var profiles: ConnectionList?
    @State private var message: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("团队策略草稿 · 外部签名").font(.system(size: 24, weight: .semibold))
            if let profiles {
                ScrollView {
                    VStack(alignment: .leading, spacing: 12) {
                        if profiles.connections.isEmpty { Text("当前策略没有连接。") }
                        ForEach(profiles.connections.indices, id: \.self) { ConnectionSummary(connection: profiles.connections[$0]) }
                        if let expires = profiles.expires_at_ms { Text("当前策略有效期至：\(displayDate(expires))") }
                    }.frame(maxWidth: .infinity, alignment: .leading)
                }.frame(maxHeight: 240)
            }
            Text("草稿尚未验证，只在独立签名工具中签署。编辑不会激活策略；导入内容不会经过部分表单重建。")
            HStack {
                TextField("新策略版本", value: $version, format: .number.grouping(.never))
                DatePicker("有效期至", selection: $expiry)
                Button("生成新的空策略草稿") { generateDraft() }
            }
            Text("生成会明确替换下方文本。新草稿没有授权；请填写连接和审批公钥后完整审阅。").font(.caption).foregroundStyle(.secondary)
            Button("选择草稿（最多 64 KiB）") {
                guard let file = chooseFile() else { return }
                draftText = ""; message = nil
                do { draftText = try NativeFileSnapshot.read(file, limit: 65536).text }
                catch { message = error.localizedDescription }
            }
            TextEditor(text: $draftText).font(.system(size: 12, design: .monospaced)).frame(minHeight: 180)
            Button("导出可见 UTF-8 文本到新私有文件") {
                guard let destination = chooseSave("DRAFT.json") else { return }
                do {
                    try writePrivateNew(try TeamDraftText.bytes(draftText), to: destination)
                    message = "可见文本已原样导出；尚未验证或签署。"
                } catch { message = error.localizedDescription }
            }.disabled(draftText.isEmpty)
            Text("下一步：在独立工具运行 rekey-policy-sign review DRAFT.json，完整核对后按其 reviewed digest 签名。再回到策略页，分别安装信任根、激活签名策略；这两步仍需 Admin step-up。")
                .font(.system(size: 12)).foregroundStyle(.secondary)
            if let message { Text(message).font(.system(size: 12)).textSelection(.enabled) }
            HStack { Spacer(); Button("关闭") { draftText = ""; message = nil; model.showPolicyDraft = false; dismiss() }.keyboardShortcut(.cancelAction) }
        }.padding(28).frame(width: 720, height: 620).background(canvas)
        .task {
            let revision = model.nativeFlowRevision, workspace = model.stateDirectory
            do {
                let loaded = try await model.loadConnectionEditor()
                if model.acceptsNativeCompletion(revision, workspace: workspace) { profiles = loaded }
            } catch {
                if model.acceptsNativeCompletion(revision, workspace: workspace) { message = error.localizedDescription }
            }
        }
        .onChange(of: model.nativeFlowRevision) { _, _ in draftText = ""; profiles = nil; message = nil }
        .onDisappear { draftText = ""; profiles = nil; message = nil; model.clearNativeFlow() }
    }
    private func generateDraft() {
        do { draftText = try TeamDraftText.empty(version: version, expiresAt: expiry); message = nil }
        catch { message = error.localizedDescription }
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
                    Text(route == .setup ? "开始使用 Rekey" : "连接服务").font(.system(size: 25, weight: .semibold))
                    Spacer()
                    Button("关闭设置页面") { model.clearNativeFlow(); model.onboardingRoute = nil; Task { await model.refresh() } }.disabled(model.busy)
                }
                if case .importEnv(let path) = route { EnvImportView(path:path) }
                else if case .oauth(let connection)=route {OAuthLoginView(connection:connection)}
                else if route == .setup { setup }
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
                Text("2 · 自动连接保险库；首次使用需允许系统后台运行。")
                if model.busy { ProgressView("正在连接保险库…") }
                else { Button("重新连接") { Task { await model.connectOnOpen() } }.buttonStyle(PrimaryButton()) }
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

private struct AnthropicOnboardingView:View {
    @EnvironmentObject var model:AppModel
    var body:some View {
        VStack(alignment:.leading,spacing:15){
            Text(OAuthSetup.presets.contains(model.addPreset) ? "保存自己的 OAuth client → 审阅并签署 scope 与规则 → 在浏览器授权。":"添加 API Key → 选择预设与规则 → 系统认证激活。")
            Text("Agent 自身连接模型的登录或 Key 由 Agent 自己管理；这里提供 Agent 主动调用的服务连接。").foregroundStyle(.secondary)
            Button("添加密钥并审阅连接"){model.showAddCredential=true}.buttonStyle(PrimaryButton()).disabled(!model.desktopReady || model.busy)
            Text("激活后运行 rekey connect claude-code / codex / cursor；调用方不需要令牌。").font(.system(size:12,design:.monospaced)).textSelection(.enabled)
        }
    }
}

struct AccessRequestsPanel:View {
    @EnvironmentObject var model:AppModel
    var body:some View {
        SectionCard(title:"连接与权限请求",icon:"person.crop.circle.badge.questionmark") {
            Text("理由来自调用方，作为不可信文本展示。调用方识别用于记录，不是身份认证。授权只有在对应规则已签署激活后才能完成。").font(.caption).foregroundStyle(.secondary)
            if let inbox=model.accessInbox {
                let pending=inbox.requests.filter{$0.status=="PENDING"}
                if pending.isEmpty{Text("没有待处理访问请求。").foregroundStyle(.secondary)}
                ForEach(pending){request in
                    VStack(alignment:.leading,spacing:8){
                        Text("\(request.caller) → \(request.connection ?? request.provider ?? "未指定连接")").font(.headline)
                        if let operation=request.operation{Text("操作："+operation)}
                        Text(request.reason).textSelection(.enabled).font(.system(size:12)).padding(8).background(sage.opacity(0.3),in:RoundedRectangle(cornerRadius:6))
                        Text("有效期至："+displayDate(request.expires_at_ms)).font(.caption).foregroundStyle(.secondary)
                        HStack {
                            Button("添加连接"){let provider=request.provider ?? "generic-bearer";model.addPreset=(["anthropic","openai","glm","glm-responses","github-pat","github-git"]+OAuthSetup.presets).contains(provider) ? provider:"generic-bearer";model.showAddCredential=true}
                            Button("编辑规则"){model.onboardingConnection=nil;model.showPolicyDraft=true}
                            Button("规则已激活，完成请求"){Task{await model.resolveAccess(request,granted:true)}}
                            Button("拒绝",role:.destructive){Task{await model.resolveAccess(request,granted:false)}}
                        }.disabled(model.busy)
                        Button("屏蔽此调用方并拒绝",role:.destructive){Task{await model.resolveAccess(request,granted:false,blockCaller:true)}}.font(.caption).disabled(model.busy)
                    }.padding(.vertical,8)
                }
                ForEach(inbox.blocked_callers,id:\.self){caller in HStack{Text("已屏蔽："+caller);Spacer();Button("解除屏蔽"){Task{await model.setAccessBlocked(caller,blocked:false)}}.disabled(model.busy)}}
            } else {Text("访问请求列表尚未加载。").foregroundStyle(.secondary)}
            Button("刷新访问请求"){Task{do{try await model.loadAccessInbox()}catch{model.error=error.localizedDescription}}}.disabled(model.busy)
        }
    }
}

private struct EnvImportItem:Identifiable {
    let key:String
    var selected=false
    var label:String
    var name:String
    var preset:String
    var origin=""
    var header="authorization"
    var prefix="Bearer "
    var id:String{key}
}
private struct EnvImportConnection:Identifiable {
    let key:String
    let label:String
    var baseURLVariable:String
    var definition:ConnectionDefinition
    var id:String{key}
}
struct EnvImportView:View {
    let path:String
    @EnvironmentObject var model:AppModel
    @State private var preview:EnvPreview?
    @State private var items:[EnvImportItem]=[]
    @State private var prepared:[EnvImportConnection]=[]
    @State private var baseline:ConnectionList?
    @State private var report:EnvImportReport?
    @State private var draft:PersonalPolicyDraft?
    @State private var expiry=Date().addingTimeInterval(86400)
    @State private var confirmed=false
    @State private var rewrite=false
    @State private var importAttempted=false
    @State private var activationAttempted=false
    @State private var activated=false
    @State private var message:String?
    @State private var authentication=PresenceReadContext()
    private let presets=["anthropic","openai","glm","glm-responses","github-pat","generic-bearer","generic-header"]
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            Text("从 .env 导入").font(.title2)
            Text(path).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
            Text("这里只显示变量名和服务提示。选择要导入的密钥，审阅并签署连接规则，再明确选择是否替换原文件。").font(.callout)
            if model.policy?.mode != .personal || model.policy?.trust_installed != true {Text("请先解锁个人保险库，并在授权页完成签名密钥设置。").foregroundStyle(.secondary)}
            if let preview {
                if prepared.isEmpty {
                    ForEach(items.indices,id:\.self) {i in
                        VStack(alignment:.leading,spacing:8) {
                            Toggle(items[i].key,isOn:$items[i].selected)
                            if items[i].selected {
                                HStack {TextField("密钥名称",text:$items[i].label);TextField("连接名称",text:$items[i].name)}
                                Picker("预设",selection:$items[i].preset){ForEach(presets,id:\.self){Text($0).tag($0)}}
                                if items[i].preset.hasPrefix("generic-") {
                                    TextField("固定 HTTPS origin",text:$items[i].origin)
                                    if items[i].preset=="generic-header" {TextField("凭据头",text:$items[i].header);TextField("前缀（可为空）",text:$items[i].prefix)}
                                }
                            }
                        }.textFieldStyle(.roundedBorder).padding(12).background(.white.opacity(0.6),in:RoundedRectangle(cornerRadius:8))
                    }
                    Button("读取预设并审阅规则"){prepare()}.buttonStyle(PrimaryButton()).disabled(model.busy || !items.contains(where:{$0.selected}) || model.policy?.mode != .personal || model.policy?.trust_installed != true)
                } else if let draft {
                    Text("完整策略变化（before / after）").font(.headline)
                    Text(draft.changesText).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                    Text("待签署的完整连接定义").font(.headline)
                    Text(draft.actionsText).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                    Toggle("我已审阅所有连接、规则、模型及预算",isOn:$confirmed).disabled(activationAttempted)
                    Toggle("激活后替换 .env 中选中的密钥，并创建备份",isOn:$rewrite).disabled(activationAttempted)
                    if rewrite {
                        Text("所选密钥将替换为 REKEY 占位值，以下变量将指向本机服务。未支持的行保持原样。").font(.caption)
                        ForEach(prepared.indices,id:\.self){i in TextField("base URL 变量名",text:$prepared[i].baseURLVariable).textFieldStyle(.roundedBorder).disabled(activationAttempted)}
                    }
                    Button(activated ? "连接已激活":"系统认证、签署并激活"){activate(draft)}.buttonStyle(PrimaryButton()).disabled(model.busy || !confirmed || activationAttempted || rewrite && prepared.contains(where:{$0.baseURLVariable.isEmpty}))
                } else {
                    ForEach(prepared.indices,id:\.self){i in
                        Text("变量：\(prepared[i].key) · 密钥名称：\(prepared[i].label)").font(.headline)
                        ConnectionEditor(connection:$prepared[i].definition)
                    }
                    DatePicker("策略有效期",selection:$expiry,in:Date()...,displayedComponents:[.date,.hourAndMinute])
                    Text("同名连接将由完整草案替换；保存密钥后仍须审阅并签署草案才会授权调用。").font(.caption).foregroundStyle(.secondary)
                    if report != nil {Text("所选密钥已保存；下次只重新生成草案，不重复导入。").foregroundStyle(.secondary)}
                    Button(report == nil ? "系统认证、保存选择并生成草案":"重新生成连接草案"){saveAndDraft()}.buttonStyle(PrimaryButton()).disabled(model.busy || importAttempted && report == nil)
                    if !importAttempted {Button("返回变量选择"){prepared=[];baseline=nil}}
                }
                if !preview.unsupported.isEmpty {
                    Text("以下行不能自动导入，保留原样：").font(.caption)
                    ForEach(preview.unsupported.indices,id:\.self){i in Text("第 \(preview.unsupported[i].line) 行 · \(preview.unsupported[i].key ?? "无变量名")").font(.caption).foregroundStyle(.secondary)}
                }
            } else {Button("预览变量名"){load()}.disabled(model.busy || !model.unlocked)}
            if let message {Text(message).foregroundStyle(activated ? Color.secondary:Color.red).textSelection(.enabled)}
            Text("每个写操作都有独立的管理证明。系统认证 context 在当前流程内复用；审阅超过有效窗口时会重新认证。").font(.caption).foregroundStyle(.secondary)
        }.onAppear{if model.unlocked {load()}}.onDisappear{authentication.invalidate()}
    }
    private func load(){Task{do{let value=try await model.previewEnv(path);preview=value;items=value.entries.map{entry in EnvImportItem(key:entry.key,label:entry.key,name:entry.key.lowercased().replacingOccurrences(of:"_",with:"-"),preset:presets.contains(entry.preset_hint ?? "") ? entry.preset_hint!:"generic-bearer")}}catch{message=error.localizedDescription}}}
    private func prepare(){
        let selected=items.filter(\.selected);let revision=model.nativeFlowRevision;message=nil
        Task {do{
            let base=try await model.loadConnectionEditor();var next:[EnvImportConnection]=[]
            for item in selected {
                let preset=try await model.loadPreset(item.preset,origin:item.origin,header:item.preset=="generic-header" ? item.header:"",prefix:item.preset=="generic-header" ? item.prefix:"")
                next.append(.init(key:item.key,label:item.label,baseURLVariable:item.key+"_BASE_URL",definition:preset.connection(name:item.name,credentialID:UUID().uuidString.lowercased())))
            }
            guard revision==model.nativeFlowRevision else{throw UIError(message:"导入工作区已改变，请重新预览。")}
            baseline=base;prepared=next
        }catch{message=error.localizedDescription}}
    }
    private func saveAndDraft(){
        guard let baseline else{return};message=nil
        Task {do{
            if report==nil {importAttempted=true;report=try await model.importSelected(path:path,selections:prepared.map{.init(key:$0.key,label:$0.label)},authentication:authentication)}
            guard let report else{return}
            for i in prepared.indices {guard let entry=report.entries.first(where:{$0.key==prepared[i].key})else{throw UIError(message:"导入回执缺少所选变量，请检查凭证列表，勿重复保存。")};prepared[i].definition.credential_id=entry.credential.id}
            let names=Set(prepared.map{ $0.definition.name });let definitions=baseline.connections.filter{!names.contains($0.name)}+prepared.map(\.definition)
            draft=try await model.personalPolicyDraft(connections:definitions,expectedPolicySHA256:baseline.policy_sha256,expiresAtMs:Int64(expiry.timeIntervalSince1970*1000))
        }catch{message=error.localizedDescription}}
    }
    private func activate(_ draft:PersonalPolicyDraft){
        activationAttempted=true;message=nil;let replacements=prepared.map{EnvReplacement(key:$0.key,connection:$0.definition.name,base_url_variable:$0.baseURLVariable)};let replace=rewrite
        Task {do{
            try await model.activatePersonalPolicy(draft,proof:"",recovery:false,presence:true,sharedAuthentication:authentication);activated=true
            if replace {let result=try await model.rewriteImported(path:path,replacements:replacements,revision:draft.revision,authentication:authentication);message="连接已激活，文件已替换。备份："+result.backup}
            else{message="连接已激活；原 .env 文件保持原样。"}
            authentication.invalidate();await model.refresh()
        }catch{authentication.invalidate();message=(activated ? "连接已激活，文件替换结果未确认，请检查文件与备份。\n":"操作结果未确认，请检查凭证与策略状态，勿重复提交。\n")+error.localizedDescription}}
    }
}

struct ActivityRecentView:View {
    let row:ActivityRow
    @EnvironmentObject var model:AppModel
    @Environment(\.dismiss) var dismiss
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            Text("最近 50 条 · \(row.context?.connection ?? "连接")").font(.title2)
            Text("\(row.context?.caller ?? "未知调用方") · \(row.context?.classification ?? "—")").foregroundStyle(.secondary)
            Text("调用方标注只用于记录；展示的是当前活动快照中仍保留的记录。").font(.caption).foregroundStyle(.secondary)
            ScrollView {
                VStack(alignment:.leading,spacing:12) {
                    ForEach(row.recent) {event in
                        DisclosureGroup("\(displayDate(event.created_at_ms)) · \(event.outcome) · \(event.request_context?.normalized_path ?? event.event_type)") {
                            VStack(alignment:.leading,spacing:6) {
                                Text("结果：\(event.event_type) / \(event.reason_code)")
                                Text("请求：\(event.request_id ?? "—")")
                                if let target=event.request_context?.target {
                                    Text("签名目标与权限：\n"+target.text)
                                    Text("实际过期：\(event.request_context?.expires_at_ms.map(displayDate) ?? "尚未签发")")
                                    Text("Agent 进程会拿到临时凭据值。").foregroundStyle(.orange)
                                } else {
                                    Text("路径：\(event.request_context?.normalized_path ?? "—")")
                                    Text("规则：\(event.request_context?.rule_id ?? "—")")
                                }
                                if let id=event.approval_request_id {Button("查看审批详情"){dismiss();Task{await Task.yield();await model.reviewLocalApproval(id)}}.disabled(model.busy || !model.unlocked)}
                            }.font(.system(size:12,design:.monospaced)).textSelection(.enabled).frame(maxWidth:.infinity,alignment:.leading).padding(.top,8)
                        }
                    }
                }.padding(8)
            }
            HStack{Spacer();Button("关闭"){dismiss()}.keyboardShortcut(.cancelAction)}
        }.padding(26).frame(width:760,height:600).background(canvas)
    }
}

private struct OAuthAddForm:View {
    @EnvironmentObject var model:AppModel
    @Environment(\.dismiss) var dismiss
    let preset:String
    @State private var label="";@State private var connection="";@State private var clientID="";@State private var clientSecret=""
    @State private var write=false;@State private var definition:ConnectionPreset?;@State private var saved:Credential?;@State private var message:String?
    private var scopes:[String] {definition.map{OAuthSetup.scopeCeiling($0,write:write)} ?? []}
    var body:some View {
        VStack(alignment:.leading,spacing:12) {
            TextField("凭据名称",text:$label).disabled(saved != nil)
            TextField("连接名称",text:$connection)
            TextField("自己的 OAuth client ID",text:$clientID).disabled(saved != nil)
            if OAuthSetup.provider(preset) != "slack" {SecureField("client secret（Google 可选）",text:$clientSecret).disabled(saved != nil)}
            Text(OAuthSetup.guidance(preset)).font(.caption).foregroundStyle(.secondary)
            Link("服务官方申请说明",destination:OAuthSetup.documentation(preset))
            Toggle("申请写操作所需权限（写操作仍按签名规则审批）",isOn:$write).disabled(saved != nil)
            Text(preset=="notion" ? "需要配置的 Portal capabilities：":"请求的 scope ceiling：").font(.headline)
            Text(scopes.joined(separator:"\n")).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
            PeerSecurityWarning()
            if saved != nil {Text("凭据已加密保存；先签署连接，再从规则页面打开浏览器授权。失败不会重复保存。")}
            if let message{Text(message).foregroundStyle(.red).textSelection(.enabled)}
            HStack{Button("取消"){clientSecret="";dismiss()};Spacer();Button("保存并审阅 OAuth 连接"){prepare()}.buttonStyle(PrimaryButton()).disabled(model.busy || !model.unlocked || model.policy?.trust_installed != true || definition==nil || label.isEmpty || connection.isEmpty || clientID.isEmpty || saved==nil && ["github","notion"].contains(OAuthSetup.provider(preset)) && clientSecret.isEmpty)}
        }.id(preset).task{do{definition=try await model.loadPreset(preset)}catch{message=error.localizedDescription}}.onDisappear{clientSecret=""}
    }
    private func prepare(){
        guard let definition else{return};let chosenScopes=scopes,id=clientID,secret=clientSecret,name=label,connectionName=connection
        clientSecret="";message=nil
        Task{do{
            let credential:Credential
            if let saved{credential=saved}else{
                var payload:[String:Any]=["credential_type":"oauth-grant-v1","provider":OAuthSetup.provider(preset),"client_id":id,"scopes":[]]
                if !secret.isEmpty {payload["client_secret"]=secret}
                let encoded=try JSONSerialization.data(withJSONObject:payload,options:[.sortedKeys,.withoutEscapingSlashes])
                credential=try await model.saveTypedCredential(label:name,kind:"oauth-grant",secret:String(decoding:encoded,as:UTF8.self));saved=credential
            }
            var c=definition.connection(name:connectionName,credentialID:credential.id)
            c.oauth = .init(provider:OAuthSetup.provider(preset),client_id:id,scopes:chosenScopes)
            if !write {c.rules.append(.init(id:UUID().uuidString.lowercased(),methods:.category("write"),path:"/**",effect:"deny"))}
            model.onboardingConnection=c;dismiss();await Task.yield();model.showPolicyDraft=true
        }catch{message=error.localizedDescription}}
    }
}

struct OAuthLoginView:View {
    @EnvironmentObject var model:AppModel
    let connection:String
    @State private var binding:ConnectionDefinition?;@State private var redirectURI="";@State private var login:OAuthLoginResult?;@State private var message:String?
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            Text("在浏览器授权："+connection).font(.headline)
            if let binding,let oauth=binding.oauth {
                Text(OAuthSetup.guidance(binding.preset));Link("官方配置说明",destination:OAuthSetup.documentation(binding.preset))
                Text("已签名 client ID："+oauth.client_id).textSelection(.enabled)
                Text(oauth.provider=="notion" ? "已签名 Portal capabilities：":"已签名 scope ceiling：")
                Text(oauth.scopes.joined(separator:"\n")).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                if ["slack","notion"].contains(oauth.provider) {TextField("已登记本机回调，如 http://localhost:8080/callback",text:$redirectURI).textFieldStyle(.roundedBorder)}
                PeerSecurityWarning()
                Button("验证并打开服务授权页"){begin()}.buttonStyle(PrimaryButton()).disabled(model.busy || login != nil || ["slack","notion"].contains(oauth.provider) && redirectURI.isEmpty)
            }else {Text("先添加 OAuth client，并签署激活此连接。");Button("加载已签名连接"){Task{await load()}}.disabled(model.busy)}
            if let login {Text("授权请求 \(login.request_id)，到期 \(displayDate(login.expires_at_ms))。在浏览器完成授权后，刷新 Activity 查看 oauth 授权结果；此页面收到 URL 只表示授权已开始。");Button("刷新状态"){Task{await model.refresh()}}.disabled(model.busy)}
            if let message{Text(message).foregroundStyle(.red).textSelection(.enabled)}
        }.task{await load()}
    }
    private func load() async {do{let base=try await model.loadConnectionEditor();binding=base.connections.first{$0.name==connection && $0.oauth != nil};if binding==nil{message="没有已激活的 OAuth 连接。"}}catch{message=error.localizedDescription}}
    private func begin(){Task{do{let result=try await model.beginOAuth(connection,redirectURI:redirectURI);guard let url=URL(string:result.authorization_url),url.scheme=="https" else{throw UIError(message:"授权页地址无效。")};login=result;guard NSWorkspace.shared.open(url)else{throw UIError(message:"默认浏览器未打开；授权请求已建立，请检查系统浏览器设置。")}}catch{message=error.localizedDescription}}}
}

private struct RootCredentialForm:View {
    @EnvironmentObject var model:AppModel
    @Environment(\.dismiss) var dismiss
    @State private var kind="aws-static";@State private var label="";@State private var accessID="";@State private var secret=""
    @State private var clientID="";@State private var installationID:UInt64=0;@State private var message:String?
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            Text("保存派生根凭据").font(.title2)
            Picker("类型",selection:$kind){Text("AWS 长期密钥").tag("aws-static");Text("GitHub App 私钥").tag("github-app-installation")}
            TextField("凭据名称",text:$label)
            if kind=="aws-static" {SecureField("Access key ID",text:$accessID);SecureField("Secret access key",text:$secret);Text("EKS 使用长期 key；不添加 session token。IAM 和 EKS RBAC 决定临时身份的上游权限。").font(.caption)}
            else {TextField("GitHub App client ID",text:$clientID);TextField("Installation ID",value:$installationID,format:.number.grouping(.never));SecureField("PKCS#1 RSA 私钥 PEM 或 DER base64",text:$secret);Text("只接受 RSA PRIVATE KEY（PKCS#1）；私钥仅传给 Rekey 并加密，不包含 webhook 配置。").font(.caption)}
            Text("保存后没有派生权限。需要逐个添加 T1 授权、审阅目标和权限，再签名开启。Agent 会拿到临时值，根凭据不会交出。").foregroundStyle(.orange)
            PeerSecurityWarning();if let message{Text(message).foregroundStyle(.red)}
            HStack{Button("取消"){secret="";accessID="";dismiss()};Spacer();Button("验证并加密保存"){save()}.buttonStyle(PrimaryButton()).disabled(model.busy || label.isEmpty || secret.isEmpty || kind=="aws-static" && accessID.isEmpty || kind != "aws-static" && (clientID.isEmpty || installationID==0))}
        }.padding(28).frame(width:560).onDisappear{secret="";accessID=""}
    }
    private func save(){
        let secretValue=secret,access=accessID,client=clientID,installation=installationID,selected=kind,name=label;secret="";accessID=""
        Task{do{
            let payload:[String:Any]
            if selected=="aws-static" {payload=["credential_type":"aws-static-v1","access_key_id":access,"secret_access_key":secretValue]}
            else {let key=secretValue.replacingOccurrences(of:"-----BEGIN RSA PRIVATE KEY-----",with:"").replacingOccurrences(of:"-----END RSA PRIVATE KEY-----",with:"").filter{!$0.isWhitespace};payload=["credential_type":"github-app-root-v1","client_id":client,"installation_id":installation,"private_key_pkcs1_der_base64":key]}
            let encoded=try JSONSerialization.data(withJSONObject:payload,options:[.sortedKeys,.withoutEscapingSlashes]);_=try await model.saveTypedCredential(label:name,kind:selected,secret:String(decoding:encoded,as:UTF8.self));dismiss()
        }catch{message=error.localizedDescription}}
    }
}

private struct DerivedGrantEditor:View {
    @Binding var grant:DerivedCredentialDefinition
    @State private var policyText="";@State private var repositories="";@State private var permissions="";@State private var message:String?
    var body:some View {
        VStack(alignment:.leading,spacing:10) {
            TextField("T1 连接名称",text:$grant.name)
            Text("Agent 进程会拿到 \(grant.max_ttl_seconds/60) 分钟有效的临时凭据；每次签发按以下固定范围判定。").foregroundStyle(.orange)
            Picker("签发判定",selection:$grant.effect){Text("每次审批").tag("approve");Text("允许").tag("allow");Text("拒绝").tag("deny")}
            if grant.target.kind=="aws-assume-role" {
                TextField("Role ARN",text:Binding(get:{grant.target.role_arn ?? ""},set:{grant.target.role_arn=$0}));TextField("区域",text:Binding(get:{grant.target.region ?? ""},set:{grant.target.region=$0}))
                TextField("有效期秒数（900–3600）",value:$grant.max_ttl_seconds,format:.number.grouping(.never))
                Text("显式 session policy JSON（与角色权限求交）");TextEditor(text:$policyText).frame(height:80)
                Button("应用 session policy"){do{grant.target.session_policy=try JSONDecoder().decode(ConnectionJSON.self,from:Data(policyText.utf8));message=nil}catch{message="session policy JSON 无效。"}}
            } else if grant.target.kind=="kubernetes-eks" {TextField("EKS cluster ID",text:Binding(get:{grant.target.cluster_id ?? ""},set:{grant.target.cluster_id=$0}));TextField("区域",text:Binding(get:{grant.target.region ?? ""},set:{grant.target.region=$0}));Text("签名固定15分钟上限；IAM/EKS RBAC限制实际权限。").font(.caption)}
            else {
                TextField("Installation ID",value:Binding(get:{grant.target.installation_id ?? 0},set:{grant.target.installation_id=$0}),format:.number.grouping(.never))
                TextField("明确允许的 repository IDs（逗号分隔）",text:$repositories)
                Text("权限 JSON，例如 {\"issues\":\"read\"}");TextEditor(text:$permissions).frame(height:60)
                Button("应用仓库与权限"){do{let ids=try repositories.split(separator:",").map{value->UInt64 in guard let id=UInt64(value.trimmingCharacters(in:.whitespaces))else{throw UIError(message:"repository ID无效")};return id};let values=try JSONDecoder().decode([String:String].self,from:Data(permissions.utf8));grant.target.repository_ids=ids;grant.target.permissions=values;message=nil}catch{message="仓库 ID 或权限 JSON 无效。"}}
                Text("上游令牌实际有效60分钟；仓库和权限只允许缩小既有 installation 授权。").font(.caption)
            }
            if let message{Text(message).foregroundStyle(.red)}
            Text("实际将签署："+grant.publicDescription).font(.system(size:11,design:.monospaced)).textSelection(.enabled)
        }.onAppear{policyText=grant.target.session_policy.flatMap{try? String(decoding:JSONEncoder().encode($0),as:UTF8.self)} ?? "{}";repositories=grant.target.repository_ids?.map(String.init).joined(separator:",") ?? "";permissions=(try? String(decoding:JSONEncoder().encode(grant.target.permissions ?? [:]),as:UTF8.self)) ?? "{}"}
    }
}

struct DesktopSecurityForm: View {
    @EnvironmentObject var model: AppModel
    @State private var settings = DesktopSecuritySettings()
    var body: some View {
        SectionCard(title: "管理界面隐私锁", icon: "lock.shield") {
            Picker("电脑空闲后锁定", selection: $settings.idle) {
                ForEach(DesktopIdleInterval.allCases) { Text($0.label).tag($0) }
            }
            Toggle("锁屏、休眠或切换用户时锁定界面", isOn: $settings.lockWithDevice)
            Picker("重新输入保险库密码", selection: $settings.passwordInterval) {
                ForEach(DesktopPasswordInterval.allCases) { Text($0.label).tag($0) }
            }
            Text("自动锁定只关闭管理界面，Agent 继续工作。保存设置会撤销当前管理会话和系统认证授权，再次输入密码后应用新期限。").font(.caption).foregroundStyle(.secondary)
            Button("保存并锁定界面") { let value = settings; Task { await model.saveSecuritySettings(value) } }.disabled(model.busy || !model.desktopReady || settings == model.securitySettings)
            Button("锁定整个保险库") { Task { await model.lock() } }.disabled(model.busy || model.status?.unlocked != true)
        }
        .onAppear { settings = model.securitySettings }
        .onChange(of: model.securitySettings) { _, value in settings = value }
    }
}
