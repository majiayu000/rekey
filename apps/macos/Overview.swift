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
    /// The review sheet shows every field in full; the inbox card stays short.
    var complete = false
    var body: some View {
        let operation = model.operation(for: review)
        VStack(alignment: .leading, spacing: 8) {
            Text(review.target).font(.system(size: 13, design: .monospaced)).textSelection(.enabled).lineLimit(3)
            let rows = (operation.map { pathParameters(template: $0.path, path: review.requestPath ?? "") } ?? []) + queryFields + bodyFields
            if !rows.isEmpty {
                Grid(alignment: .leading, horizontalSpacing: 14, verticalSpacing: 6) {
                    ForEach(rows.indices, id: \.self) { i in
                        GridRow {
                            Text(rows[i].0).foregroundStyle(.secondary)
                            Text(rows[i].1).textSelection(.enabled).lineLimit(complete ? nil : 3)
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
        let keys = object.keys.sorted()
        var rows: [(String, String)] = (complete ? keys : Array(keys.prefix(6))).map { key in
            let value = object[key].map { $0 as? String ?? (try? JSONSerialization.data(withJSONObject: $0, options: [.fragmentsAllowed, .sortedKeys])).map { String(decoding: $0, as: UTF8.self) } ?? "…" } ?? ""
            return ("正文 · " + key, complete || value.count <= 160 ? value : String(value.prefix(160)) + "…（已截断，打开查看全部）")
        }
        if !complete && keys.count > 6 { rows.append(("…", "还有 \(keys.count - 6) 个字段，打开查看全部")) }
        return rows
    }
    private var queryFields: [(String, String)] {
        guard case .object(let query)? = review.canonical_request?["query"] else { return [] }
        return query.keys.sorted().map { ("查询 · " + $0, query[$0]?.stringValue ?? "…") }
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

/// The commands that connect an Agent to this vault, as three steps with copy buttons.
struct ConnectCommands: View {
    @EnvironmentObject var model: AppModel
    @State private var copied: String?
    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            step(1, "在项目目录的终端里运行（二选一）", "命令会先显示要写入的 MCP 配置和说明，确认后才写入，不含任何 Key。") {
                command("Claude Code", "rekey\(stateFlag) connect claude-code")
                command("Codex", "rekey\(stateFlag) connect codex")
            }
            step(2, "在同一目录启动 Agent，输入", "Codex 第一次会问是否信任该文件夹，选择信任才会加载 Rekey。Agent 应该列出你签署的连接。") {
                command("验证接入", "用 Rekey 列出你能调用的服务和操作，然后做一次只读调用")
            }
            step(3, "到“活动”页确认", "只读调用完成后，“最近调用”里会出现这一条。没有出现时，确认 Agent 是在第 1 步的目录里启动的。") { EmptyView() }
        }
    }
    private func step<Content: View>(_ number: Int, _ title: String, _ note: String, @ViewBuilder content: () -> Content) -> some View {
        HStack(alignment: .top, spacing: 12) {
            Text(String(number)).font(.system(size: 13, weight: .semibold)).frame(width: 24, height: 24).overlay(Circle().stroke(green))
            VStack(alignment: .leading, spacing: 8) {
                Text(title).font(.system(size: 14, weight: .semibold))
                content()
                Text(note).font(.system(size: 12)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
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
            }.accessibilityLabel("复制\(label)命令")
        }.padding(12).background(surface, in: RoundedRectangle(cornerRadius: 6)).overlay(RoundedRectangle(cornerRadius: 6).stroke(.gray.opacity(0.2)))
    }
}

struct ConnectAgentGuide: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("接入 Agent").font(.system(size: 22, weight: .semibold))
            Text("接入后，Agent 读数据直接返回，写操作会出现在审批收件箱等你决定。")
                .font(.system(size: 13)).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            ConnectCommands()
            HStack {
                Button("关闭") { dismiss() }.keyboardShortcut(.cancelAction)
                Spacer()
                Button("查看活动") { dismiss(); model.page = .activity; model.clearActivity(); Task { await model.refresh() } }.buttonStyle(PrimaryButton())
            }
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
                            let match = model.connections.first { connection in
                                connection.enabled && (request.connection.map { $0 == connection.name } ?? (connection.preset == request.suggestedPreset))
                                    && (request.operation.map { op in connection.operations.contains { $0.name == op } } ?? true)
                            }
                            Button(match.map { "已签署 \($0.name)，通知 Agent" } ?? "签署后再通知 Agent"){Task{await model.resolveAccess(request,granted:true)}}
                                .disabled(match == nil).help(match == nil ? "还没有匹配这项申请的已启用连接" : "Rekey 会再次核对这条连接；通过后 Agent 的等待返回 GRANTED")
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

/// Service names people recognize; the preset ID stays visible for the CLI.
func presetDisplayName(_ preset: String) -> String {
    let names = ["github-pat": "GitHub 个人访问令牌", "github-git": "GitHub Git（HTTPS 推送）", "anthropic": "Anthropic", "openai": "OpenAI",
                 "glm": "智谱 GLM", "glm-responses": "智谱 GLM（Responses）", "deepseek": "DeepSeek", "moonshot": "Moonshot", "moonshot-intl": "Moonshot 国际",
                 "qwen": "通义千问", "qwen-intl": "通义千问 国际", "qwen-us": "通义千问 美国", "qwen-hk": "通义千问 香港", "openrouter": "OpenRouter",
                 "gemini": "Google Gemini", "stripe": "Stripe", "generic-bearer": "其他服务（Bearer）", "generic-header": "其他服务（自定义请求头）",
                 "google-drive": "Google Drive", "google-gmail": "Gmail", "google-calendar": "Google 日历", "github-oauth": "GitHub OAuth", "slack": "Slack", "notion": "Notion"]
    return names[preset].map { "\($0) · \(preset)" } ?? preset
}

/// Rule-level differences of one Connection, as short readable lines.
func ruleChanges(_ before: ConnectionDefinition, _ after: ConnectionDefinition) -> [String] {
    func key(_ rule: ConnectionRule) -> String { "\(methodLabel(rule.methods)) \(rule.path)" }
    let old = Dictionary(before.rules.map { (key($0), $0.effect) }, uniquingKeysWith: { first, _ in first })
    let new = Dictionary(after.rules.map { (key($0), $0.effect) }, uniquingKeysWith: { first, _ in first })
    var lines: [String] = []
    if before.enabled != after.enabled { lines.append(after.enabled ? "重新启用连接" : "停用连接（Agent 将不能调用）") }
    for rule in after.rules.map(key) where old[rule] != new[rule] {
        let now = effectLabels[new[rule] ?? ""] ?? ""
        lines.append(old[rule].map { "\(rule)：\(effectLabels[$0] ?? $0) → \(now)" } ?? "新增 \(rule)：\(now)")
    }
    for rule in before.rules.map(key) where new[rule] == nil { lines.append("删除 \(rule)（原为 \(effectLabels[old[rule] ?? ""] ?? "")）") }
    if lines.isEmpty { lines.append("规则判定不变（其他设置有改动，见下方 before / after）") }
    return lines
}

/// What a draft changes, by Connection name, above the full before/after text.
struct DraftChangeSummary: View {
    let before: [ConnectionDefinition]
    let after: [ConnectionDefinition]
    var body: some View {
        let old = Dictionary(uniqueKeysWithValues: before.map { ($0.name, $0) })
        let new = Dictionary(uniqueKeysWithValues: after.map { ($0.name, $0) })
        let added = after.filter { old[$0.name] == nil }.map(\.name)
        let removed = before.filter { new[$0.name] == nil }.map(\.name)
        let changed = after.filter { current in old[current.name].map { $0 != current } ?? false }.map(\.name)
        VStack(alignment: .leading, spacing: 6) {
            Text("本次改动").font(.headline)
            if added.isEmpty && removed.isEmpty && changed.isEmpty { Text("连接没有变化（可能只更新了有效期、SSH 或 T1）。") }
            if !added.isEmpty { Label("新增连接：" + added.joined(separator: "、"), systemImage: "plus.circle").foregroundStyle(green) }
            ForEach(changed, id: \.self) { name in
                Label("修改了 \(name)：", systemImage: "pencil.circle").foregroundStyle(.orange)
                ForEach(ruleChanges(old[name]!, new[name]!), id: \.self) { Text("    " + $0) }
            }
            if !removed.isEmpty { Label("删除连接：" + removed.joined(separator: "、") + "（Agent 将不能再调用）", systemImage: "minus.circle").foregroundStyle(.red) }
            let unchanged = after.count - added.count - changed.count
            if unchanged > 0 { Text("其余 \(unchanged) 个连接不变。").foregroundStyle(.secondary) }
        }.font(.system(size: 13)).padding(12).frame(maxWidth: .infinity, alignment: .leading).background(sage.opacity(0.35), in: RoundedRectangle(cornerRadius: 8))
    }
}

/// The latest finished or refused calls across all rows, newest first.
struct RecentCalls: View {
    let rows: [ActivityRow]
    var body: some View {
        let events = rows.flatMap { row in row.recent.map { (row.context, $0) } }
            .filter { $0.1.event_type != "execution.started" }
            .sorted { $0.1.created_at_ms > $1.1.created_at_ms }.prefix(6)
        VStack(alignment: .leading, spacing: 8) {
            Text("最近调用").font(.system(size: 14, weight: .semibold))
            if events.isEmpty { Text("今天还没有完成的调用。").font(.system(size: 13)).foregroundStyle(.secondary) }
            ForEach(Array(events.enumerated()), id: \.offset) { _, item in
                let (context, event) = item
                let waiting = event.event_type == "approval.requested"
                let ok = event.outcome == "success" && !waiting
                HStack(spacing: 10) {
                    Image(systemName: waiting ? "hourglass" : ok ? "checkmark.circle.fill" : event.outcome == "indeterminate" ? "questionmark.circle" : "xmark.circle.fill")
                        .foregroundStyle(ok ? green : waiting || event.outcome == "indeterminate" ? .orange : .red)
                    Text(displayDate(event.created_at_ms)).foregroundStyle(.secondary)
                    Text(context?.caller ?? "未知 Agent")
                    Text("\(context?.connection ?? "—") \(event.request_context?.normalized_path ?? "")").font(.system(size: 12, design: .monospaced)).lineLimit(1)
                    Spacer()
                    Text(waiting ? "请求批准" : auditLabels[event.event_type] ?? event.event_type).foregroundStyle(ok ? Color.secondary : waiting ? .orange : .red)
                }.font(.system(size: 13))
            }
        }
    }
}
