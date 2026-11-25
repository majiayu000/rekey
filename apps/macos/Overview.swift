import SwiftUI
import AppKit

// Personal-mode overview: what each Connection lets an Agent do, what a pending
// approval would send, and how to connect an Agent. Display only; every decision
// still goes through the full review and the existing proof flows.

extension AppModel {
    /// The named operation whose method and path template match a reviewed request.
    func operation(for review: LocalApprovalDetails.Review) -> ConnectionOperation? {
        guard let name = review.action_name, let connection = connections.first(where: { $0.name == name }),
              let method = review.method, let path = review.requestPath else { return nil }
        return connection.operations.first { $0.method == method && pathMatches(template: $0.path, path: path) }
    }
}

extension AppModel {
    /// The signed rule a reviewed request matched, as "写入 /**".
    func ruleSummary(_ review: LocalApprovalDetails.Review?) -> String {
        guard let review, let connection = connections.first(where: { $0.name == review.challenge.resource.id }),
              let rule = connection.rules.first(where: { $0.id == review.challenge.policy_rule_id }) else { return "此规则" }
        return "\(methodLabel(rule.methods)) \(rule.path)"
    }
    /// Pending decisions: local approvals plus access requests.
    var inboxCount: Int { approvals.count + (accessInbox?.requests.filter { $0.status == "PENDING" }.count ?? 0) }
}

/// Path parameters named by the operation template, in template order.
func pathParameters(template: String, path: String) -> [(String, String)] {
    zip(template.split(separator: "/"), path.split(separator: "/")).compactMap { name, value in
        name.hasPrefix("{") ? (String(name.dropFirst().dropLast()), String(value).removingPercentEncoding ?? String(value)) : nil
    }
}

private func pathMatches(template: String, path: String) -> Bool {
    let expected = template.split(separator: "/"), actual = path.split(separator: "/")
    return expected.count == actual.count && zip(expected, actual).allSatisfy { $0.hasPrefix("{") || $0 == $1 }
}

extension ConnectionJSON {
    var stringValue: String? { if case .string(let value) = self { return value }; return nil }
    subscript(key: String) -> ConnectionJSON? { if case .object(let fields) = self { return fields[key] }; return nil }
}

extension LocalApprovalDetails.Review {
    var requestPath: String? { canonical_request?["path"]?.stringValue }
    /// Method and full URL, with the query in a stable order.
    var target: String {
        var url = (origin ?? "") + (requestPath ?? "")
        if case .object(let query)? = canonical_request?["query"], !query.isEmpty {
            url += "?" + query.keys.sorted().map { "\($0)=\(query[$0]?.stringValue ?? "…")" }.joined(separator: "&")
        }
        return "\(method ?? "") \(url)"
    }
    /// The request body as text, or a short note for an encoded one.
    var bodyPreview: String? {
        guard let body = canonical_request?["body"]?.stringValue, !body.isEmpty else { return nil }
        if canonical_request?["body_encoding"]?.stringValue == "text" { return body.count > 400 ? String(body.prefix(400)) + "…" : body }
        return "已编码的正文，\(body.count) 个字符；完整内容见审阅页"
    }
}

extension LocalApprovalDetails {
    /// Indented for reading; the digest and the decision still bind the raw bytes.
    var displayText: String {
        guard let value = try? JSONSerialization.jsonObject(with: raw),
              let pretty = try? JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]) else { return text }
        return String(decoding: pretty, as: UTF8.self)
    }
}

func remaining(_ expiresMs: Int64, now: Date) -> String {
    let seconds = max(0, Int(Double(expiresMs) / 1000 - now.timeIntervalSince1970))
    return seconds >= 60 ? "剩余 \(seconds / 60) 分钟" : "剩余 \(seconds) 秒"
}

/// The facts a person decides on: operation, target, parameters and body fields.
/// A summary only; the decision still binds the complete request shown below it.
struct ApprovalFacts: View {
    @EnvironmentObject var model: AppModel
    let review: LocalApprovalDetails.Review
    var body: some View {
        let operation = model.operation(for: review)
        VStack(alignment: .leading, spacing: 8) {
            Text(review.target).font(.system(size: 13, design: .monospaced)).textSelection(.enabled).lineLimit(3)
            let rows = (operation.map { pathParameters(template: $0.path, path: review.requestPath ?? "") } ?? []) + bodyFields
            if !rows.isEmpty {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                    ForEach(rows.indices, id: \.self) { i in
                        GridRow {
                            Text(rows[i].0).foregroundStyle(.secondary)
                            Text(rows[i].1).textSelection(.enabled).lineLimit(4)
                        }.font(.system(size: 13))
                    }
                }.padding(12).frame(maxWidth: .infinity, alignment: .leading).background(sage.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
            } else if let body = review.bodyPreview {
                Text(body).font(.system(size: 12, design: .monospaced)).textSelection(.enabled).lineLimit(6)
                    .padding(10).frame(maxWidth: .infinity, alignment: .leading).background(sage.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
            }
        }
    }
    /// Top-level fields of a JSON object body; longer values are cut with an ellipsis.
    private var bodyFields: [(String, String)] {
        guard review.canonical_request?["body_encoding"]?.stringValue == "text",
              let text = review.canonical_request?["body"]?.stringValue,
              let object = (try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any] else { return [] }
        return object.keys.sorted().prefix(12).map { key in
            let value = object[key].map { $0 as? String ?? (try? JSONSerialization.data(withJSONObject: $0, options: [.fragmentsAllowed])).map { String(decoding: $0, as: UTF8.self) } ?? "…" } ?? ""
            return (key, value.count > 200 ? String(value.prefix(200)) + "…（已截断）" : value)
        }
    }
}

/// Pending local approval: what would be sent, then one button into the full review.
struct ApprovalSummaryCard: View {
    @EnvironmentObject var model: AppModel
    let item: PendingApproval
    var body: some View {
        let review = model.approvalReviews[item.id]?.review
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .firstTextBaseline) {
                Image(systemName: review?.ssh == nil ? "arrow.up.forward.app" : "signature").foregroundStyle(green)
                Text(title(review)).font(.system(size: 16, weight: .semibold))
                Spacer()
                TimelineView(.periodic(from: .now, by: 30)) { context in
                    Text(remaining(item.max_expires_at_ms, now: context.date)).font(.system(size: 13, weight: .medium)).foregroundStyle(.orange)
                }
            }
            if let review {
                if let ssh = review.ssh {
                    Text("\(ssh.purposeLabel) · \(ssh.host)").font(.system(size: 13))
                } else {
                    ApprovalFacts(review: review)
                }
            } else {
                Text("摘要未读取，打开后查看完整请求。").font(.system(size: 13)).foregroundStyle(.secondary)
            }
            HStack {
                Button("审阅并决定") { Task { await model.reviewApproval(item) } }.buttonStyle(PrimaryButton()).disabled(model.busy)
                Text("批准前会显示完整请求，并需要系统认证。").font(.system(size: 12)).foregroundStyle(.secondary)
            }
        }.padding(20).frame(maxWidth: .infinity, alignment: .leading)
            .background(surface, in: RoundedRectangle(cornerRadius: 8)).overlay(RoundedRectangle(cornerRadius: 8).stroke(green.opacity(0.35)))
    }
    private func title(_ review: LocalApprovalDetails.Review?) -> String {
        guard let review else { return "Agent 请求批准" }
        if review.ssh != nil { return review.title }
        let operation = model.operation(for: review).map { " · " + $0.name } ?? ""
        return (review.action_name ?? "连接") + operation
    }
}

let effectLabels = ["allow": "直接放行", "approve": "需要你批准", "deny": "拒绝"]
func effectColor(_ effect: String) -> Color { effect == "allow" ? green : effect == "deny" ? .red : .orange }
func methodLabel(_ methods: ConnectionRule.Methods) -> String {
    switch methods {
    case .category("read"): return "读取"
    case .category("write"): return "写入"
    case .exact(["DELETE"]): return "删除"
    default: return methods.text
    }
}

/// One signed Connection: where it sends requests and what each rule does.
struct ConnectionRulesSummary: View {
    let connection: ConnectionDefinition
    var compact = false
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                Text(connection.name).font(.system(size: compact ? 13 : 15, weight: .semibold))
                if !compact { Text(connection.origin).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary) }
                Spacer()
                StatusPill(active: connection.enabled, text: connection.enabled ? "已启用" : "已停用")
            }
            if compact { Text(connection.origin).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary) }
            ForEach(connection.rules) { rule in
                HStack(spacing: 8) {
                    Text(methodLabel(rule.methods)).lineLimit(1).frame(width: 60, alignment: .leading)
                    Text(rule.path).font(.system(size: 11, design: .monospaced)).foregroundStyle(.secondary).lineLimit(1)
                    Spacer()
                    Text(effectLabels[rule.effect] ?? rule.effect).foregroundStyle(effectColor(rule.effect))
                }.font(.system(size: 12))
            }
            if !compact, !connection.operations.isEmpty {
                Text("Agent 可调用：" + connection.operations.map(\.name).joined(separator: "、"))
                    .font(.system(size: 11)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

/// The commands that connect an Agent to this vault, with copy buttons.
struct ConnectCommands: View {
    @EnvironmentObject var model: AppModel
    @State private var copied: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            command("Claude Code", "rekey\(stateFlag) connect claude-code")
            command("Codex", "rekey\(stateFlag) connect codex")
            Text("命令会先显示要写入的 MCP 配置和说明，确认后才写入，不含任何 Key。Codex 第一次在项目里运行时会问是否信任该文件夹，选择信任才会加载 Rekey。")
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            command("验证：在 Agent 里输入", "用 Rekey 列出你能调用的服务和操作")
            Text("Agent 应该列出上面签署的连接。再让它做一次读取（比如列出某个仓库的 issue），“活动”页会出现这次调用。没有反应时，确认 Agent 是在运行命令的项目目录里启动的。")
                .font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
    private var stateFlag: String {
        BackgroundService.usesDefaultState(model.stateDirectory) ? "" : " --state-dir '\(model.stateDirectory.replacingOccurrences(of: "'", with: "'\\''"))'"
    }
    private func command(_ label: String, _ text: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 4) {
                Text(label).font(.system(size: 12, weight: .medium))
                Text(text).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
            }
            Spacer()
            Button(copied == text ? "已复制" : "复制") {
                NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string); copied = text
            }.accessibilityLabel("复制 \(label) 接入命令")
        }.padding(12).background(surface, in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.2)))
    }
}

struct ConnectAgentGuide: View {
    @Environment(\.dismiss) var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("接入 Agent").font(.system(size: 22, weight: .semibold))
            Text("在要使用 Rekey 的项目目录运行一条命令。之后 Agent 读数据直接返回，写操作会出现在审批收件箱。")
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ConnectCommands()
            HStack { Spacer(); Button("完成") { dismiss() }.keyboardShortcut(.defaultAction) }
        }.padding(28).frame(width: 600).background(canvas)
    }
}

/// Agent access requests: add the missing key or edit rules, then tell the Agent.
struct AccessRequestsPanel:View {
    @EnvironmentObject var model:AppModel
    var body:some View {
        SectionCard(title:"Agent 的访问申请",icon:"person.crop.circle.badge.questionmark") {
            Text("Agent 缺少某个服务或权限时会在这里申请。理由由 Agent 自己填写，仅供参考；调用方名称不是身份认证。").font(.system(size:12)).foregroundStyle(.secondary)
            if let inbox=model.accessInbox {
                let pending=inbox.requests.filter{$0.status=="PENDING"}
                if pending.isEmpty{Text("没有待处理的访问申请。").foregroundStyle(.secondary)}
                ForEach(pending){request in
                    VStack(alignment:.leading,spacing:8){
                        HStack {
                            Text("\(request.caller) 想使用 \(request.connection ?? request.provider ?? "未指定的服务")").font(.headline)
                            Spacer()
                            TimelineView(.periodic(from:.now,by:30)){context in Text(remaining(request.expires_at_ms,now:context.date)).font(.system(size:13,weight:.medium)).foregroundStyle(.orange)}
                        }
                        if let operation=request.operation{Text("操作："+operation).font(.system(size:12))}
                        Text(request.reason).textSelection(.enabled).font(.system(size:12)).padding(8).background(sage.opacity(0.3),in:RoundedRectangle(cornerRadius:6))
                        HStack {
                            if request.connection == nil {
                                Button("添加 \(request.suggestedPreset) 的 Key"){model.addPreset=request.suggestedPreset;model.showAddCredential=true}.buttonStyle(PrimaryButton())
                            } else {
                                Button("编辑规则"){model.onboardingConnection=nil;model.showPolicyDraft=true}.buttonStyle(PrimaryButton())
                            }
                            let ready = model.connections.contains { $0.name == request.connection || $0.preset == request.suggestedPreset }
                            Button(ready ? "已签署，通知 Agent" : "签署后再通知 Agent"){Task{await model.resolveAccess(request,granted:true)}}
                                .disabled(!ready).help("对应连接签署生效后，Agent 的等待会返回 GRANTED")
                            Spacer()
                            Menu("拒绝") {
                                Button("拒绝这次申请"){Task{await model.resolveAccess(request,granted:false)}}
                                Button("拒绝并屏蔽 \(request.caller)",role:.destructive){Task{await model.resolveAccess(request,granted:false,blockCaller:true)}}
                            }.fixedSize()
                        }.disabled(model.busy)
                    }.padding(.vertical,8)
                    if request.id != pending.last?.id {Divider()}
                }
                ForEach(inbox.blocked_callers,id:\.self){caller in HStack{Text("已屏蔽："+caller);Spacer();Button("解除屏蔽"){Task{await model.setAccessBlocked(caller,blocked:false)}}.disabled(model.busy)}}
            } else {Text("访问申请尚未加载。").foregroundStyle(.secondary)}
        }
    }
}

/// Readable names for the audit events a personal user meets most; the raw code stays visible.
let auditLabels: [String: String] = [
    "vault.unlocked": "保险库已解锁", "vault.locked": "保险库已锁定", "desktop.locked": "管理界面已锁定",
    "execution.started": "开始调用", "execution.finished": "调用完成", "execution.blocked": "调用被拦截", "execution.failed": "调用失败",
    "approval.requested": "请求批准", "approval.approved": "已批准", "approval.rejected": "已拒绝", "approval.consumed": "批准已使用",
    "access_request.created": "Agent 申请访问", "access_request.resolved": "访问申请已处理",
    "credential.created": "添加了 Key", "credential.rotated": "更换了 Key", "credential.revoked": "撤销了 Key",
    "policy.activated": "规则已签署生效",
]
let auditOutcomeLabels = ["success": "成功", "denied": "拒绝", "failure": "失败", "indeterminate": "结果未知"]
