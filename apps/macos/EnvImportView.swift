import SwiftUI

// agent-call 7.3 review page. The model steps and the receipt text live in EnvImport.swift,
// where the Swift contracts cover them; this view only binds them.
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
    @State private var signerMode:PolicySigning.Mode?
    private let presets=EnvImportPlan.presets
    var body:some View {
        VStack(alignment:.leading,spacing:14) {
            Text("从 .env 导入").font(.title2)
            if let signerMode {Text(signerMode.label).font(.caption).foregroundStyle(.secondary)}
            Text(path).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
            Text("这里只显示变量名和识别结果。逐项选择导入、跳过或标记为非密钥，审阅并签署连接规则，再明确选择是否替换原文件。").font(.callout)
            if model.policy?.mode != .personal || model.policy?.trust_installed != true {Text("请先解锁个人保险库，并在授权页完成签名密钥设置。").foregroundStyle(.secondary)}
            if let preview {
                if prepared.isEmpty {
                    ForEach(items.indices,id:\.self) {i in
                        VStack(alignment:.leading,spacing:8) {
                            HStack {
                                Text(items[i].key).font(.system(size:13,weight:.semibold,design:.monospaced))
                                Spacer()
                                Picker("处理方式",selection:$items[i].choice) {
                                    if items[i].unsupportedProtocol == nil {Text("导入").tag(EnvImportChoice.importKey)}
                                    Text("跳过").tag(EnvImportChoice.skip)
                                    Text("非密钥").tag(EnvImportChoice.nonSecret)
                                }.pickerStyle(.segmented).labelsHidden().frame(width:items[i].unsupportedProtocol == nil ? 210:140)
                            }
                            if let kind=items[i].unsupportedProtocol {Text("未迁移：协议不支持代理（\(EnvImportPlan.protocolLabel(kind))），原值保留。").font(.caption).foregroundStyle(.orange)}
                            else {Text(items[i].hint.map{"识别为 "+$0} ?? "未识别").font(.caption).foregroundStyle(.secondary)}
                            if items[i].choice == .importKey {
                                HStack {TextField("密钥名称",text:$items[i].label);TextField("连接名称",text:$items[i].name)}
                                Picker("预设",selection:$items[i].preset){ForEach(presets,id:\.self){Text($0).tag($0)}}
                                if items[i].preset.hasPrefix("generic-") {
                                    TextField("固定 HTTPS origin",text:$items[i].origin)
                                    if items[i].preset=="generic-header" {TextField("凭据头",text:$items[i].header);TextField("前缀（可为空）",text:$items[i].prefix)}
                                }
                            }
                        }.textFieldStyle(.roundedBorder).padding(12).background(.white.opacity(0.6),in:RoundedRectangle(cornerRadius:8))
                    }
                    Button("读取预设并审阅规则"){prepare()}.buttonStyle(PrimaryButton()).disabled(model.busy || !items.contains(where:{$0.choice == .importKey}) || model.policy?.mode != .personal || model.policy?.trust_installed != true)
                } else if let draft {
                    Text("完整策略变化（before / after）").font(.headline)
                    Text(draft.changesText).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                    Text("待签署的完整连接定义").font(.headline)
                    Text(draft.actionsText).font(.system(size:12,design:.monospaced)).textSelection(.enabled)
                    Toggle("我已审阅所有连接、规则、模型及预算",isOn:$confirmed).disabled(activationAttempted)
                    Toggle("激活后替换 .env 中选中的密钥，并创建备份",isOn:$rewrite).disabled(activationAttempted)
                    if rewrite {
                        Text("所选密钥将替换为 rekey 占位值，以下变量将指向本机服务。其余行保持原样。原文件存为 0600 备份，备份含原始密钥。").font(.caption)
                        ForEach(prepared.indices,id:\.self){i in HStack {Text(prepared[i].key).font(.system(size:12,design:.monospaced));TextField("base URL 变量名",text:$prepared[i].baseURLVariable).textFieldStyle(.roundedBorder).disabled(activationAttempted)}}
                    }
                    Button(activated ? "连接已激活":"系统认证、签署并激活"){activate(draft)}.buttonStyle(PrimaryButton()).disabled(model.busy || !confirmed || activationAttempted || rewrite && prepared.contains(where:{$0.baseURLVariable.isEmpty}))
                } else {
                    ForEach(prepared.indices,id:\.self){i in
                        Text("变量：\(prepared[i].key) · 密钥名称：\(prepared[i].label)").font(.headline)
                        ConnectionEditor(connection:$prepared[i].definition)
                    }
                    DatePicker("策略有效期",selection:$expiry,in:Date()...,displayedComponents:[.date,.hourAndMinute])
                    Text("有效期默认沿用当前策略；它作用于整份策略。同名连接将由完整草案替换；保存密钥后仍须审阅并签署草案才会授权调用。").font(.caption).foregroundStyle(.secondary)
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
    private func load(){Task{do{let value=try await model.previewEnv(path);preview=value;items=EnvImportPlan.items(value)}catch{message=error.localizedDescription}}}
    private func prepare(){
        guard let preview else{return};let chosen=items;message=nil
        Task {do{
            let result=try await model.prepareEnvImport(chosen,preview:preview)
            signerMode=result.mode;baseline=result.base;prepared=result.connections;expiry=result.expiry
        }catch{message=error.localizedDescription}}
    }
    private func saveAndDraft(){
        guard let baseline else{return};message=nil
        Task {do{
            if report==nil {signerMode=try await model.checkPolicySigner();importAttempted=true;report=try await model.importSelected(path:path,selections:prepared.map{.init(key:$0.key,label:$0.label)},authentication:authentication)}
            guard let report else{return}
            for i in prepared.indices {guard let entry=report.entries.first(where:{$0.key==prepared[i].key})else{throw UIError(message:"导入回执缺少所选变量，请检查凭证列表，勿重复保存。")};prepared[i].definition.credential_id=entry.credential.id}
            let names=Set(prepared.map{ $0.definition.name });let definitions=baseline.connections.filter{!names.contains($0.name)}+prepared.map(\.definition)
            draft=try await model.personalPolicyDraft(connections:definitions,expectedPolicySHA256:baseline.policy_sha256,expiresAtMs:Int64(expiry.timeIntervalSince1970*1000))
        }catch{message=error.localizedDescription}}
    }
    private func activate(_ draft:PersonalPolicyDraft){
        activationAttempted=true;message=nil;let replacements=prepared.map{EnvReplacement(key:$0.key,connection:$0.definition.name,base_url_variable:$0.baseURLVariable)};let replace=rewrite
        let receipt=EnvImportPlan.report(items)
        Task {do{
            try await model.activatePersonalPolicy(draft,proof:"",recovery:false,presence:true,sharedAuthentication:authentication);activated=true
            if replace {let result=try await model.rewriteImported(path:path,replacements:replacements,revision:draft.revision,authentication:authentication);message=(["连接已激活，文件已替换。",EnvImportPlan.backupNotice(result)]+receipt).joined(separator:"\n")}
            else{message=(["连接已激活；原 .env 文件保持原样。"]+receipt).joined(separator:"\n")}
            authentication.invalidate();await model.refresh()
        }catch{authentication.invalidate();message=(activated ? "连接已激活，文件替换结果未确认，请检查文件与备份（备份含原始密钥）。\n":"操作结果未确认，请检查凭证与策略状态，勿重复提交。\n")+error.localizedDescription}}
    }
}
