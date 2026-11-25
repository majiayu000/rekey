import SwiftUI

/// Local approval: what the request does, the scope of the decision, then the full
/// bound request. One vertical scroll; the decision buttons stay in the footer.
struct LocalApprovalView: View {
    @EnvironmentObject var model: AppModel
    @Environment(\.dismiss) var dismiss
    @State private var failure: String?
    @State private var limited = false
    @State private var minutes = "30"
    @State private var customMinutes = "45"
    private var windowMinutes: Int { minutes == "custom" ? Int(customMinutes) ?? 0 : Int(minutes) ?? 0 }
    var body: some View {
        TimelineView(.periodic(from: .now, by: 1)) { timeline in
            if let details = model.localApprovalDetails {
                let windowed = details.review?.windowAllowed == true && limited
                VStack(alignment: .leading, spacing: 0) {
                    ScrollView(.vertical) {
                        VStack(alignment: .leading, spacing: 14) {
                            Text(title(details)).font(.system(size: 22, weight: .semibold))
                            if details.state == .pending && !details.canDecide(at: timeline.date) {
                                Label("请求已过期，不能再批准。请让 Agent 重新发起。", systemImage: "clock.badge.exclamationmark").font(.system(size: 14, weight: .medium)).foregroundStyle(.orange)
                            } else {
                                Text(details.state.label).font(.system(size: 13)).foregroundStyle(.secondary)
                            }
                            if let review = details.review {
                                if let ssh = review.ssh {
                                    Text("用途：\(ssh.purposeLabel) · 用户：\(ssh.use.username ?? "不适用")").textSelection(.enabled)
                                    Text("host：\(ssh.host)").textSelection(.enabled)
                                    if ssh.bound_host_key == nil || ssh.host == "unknown-host" { Text("目标尚未绑定或未登记；本次批准不能验证 host 身份。").foregroundStyle(.orange) }
                                    if let unverified = ssh.use.unverified_host { Text("请求声明的 host key（未经验证）：\(unverified)").textSelection(.enabled) }
                                    Text("签名数据 SHA-256：\(ssh.data_sha256)").font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                                } else {
                                    ApprovalFacts(review: review, complete: true)
                                }
                                Text("连接 \(review.challenge.resource.id) · 有效期至 \(displayDate(review.challenge.max_expires_at_ms))").font(.system(size: 13)).foregroundStyle(.secondary)
                            }
                            if details.review?.windowAllowed == true {
                                VStack(alignment: .leading, spacing: 8) {
                                    Text("批准范围").font(.system(size: 14, weight: .semibold))
                                    Picker("批准范围", selection: $limited) {
                                        Text("仅这一个请求（推荐）").tag(false)
                                        Text("限时放行同一规则…").tag(true)
                                    }.pickerStyle(.radioGroup).labelsHidden()
                                    if limited {
                                        HStack {
                                            Picker("时长", selection: $minutes) { Text("15 分钟").tag("15"); Text("30 分钟").tag("30"); Text("1 小时").tag("60"); Text("2 小时").tag("120"); Text("自定义").tag("custom") }.frame(width: 200)
                                            if minutes == "custom" { TextField("分钟（1–480）", text: $customMinutes).textFieldStyle(.roundedBorder).frame(width: 120) }
                                        }
                                        Text(scopeText(details)).font(.system(size: 13)).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                                    }
                                }.padding(12).background(surface.opacity(0.6), in: RoundedRectangle(cornerRadius: 8))
                            }
                            if !details.raw.isEmpty {
                                Text("完整请求（批准绑定这份内容，此处格式化显示）").font(.system(size: 13, weight: .medium))
                                Text(details.displayText).font(.system(size: 12, design: .monospaced)).textSelection(.enabled)
                                    .frame(maxWidth: .infinity, alignment: .topLeading).padding(12).background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 6))
                            } else { Text("此请求已结束，完整正文已释放。").foregroundStyle(.secondary) }
                        }.padding(28).frame(maxWidth: .infinity, alignment: .leading)
                    }
                    Divider()
                    VStack(alignment: .leading, spacing: 10) {
                        if let failure {
                            Text(failure).font(.system(size: 13)).foregroundStyle(.red).textSelection(.enabled)
                            Button("重新解锁并启用系统认证") { model.clearNativeFlow(); dismiss(); model.requestDesktopLogin() }
                                .help("在 App 里批准需要系统认证；解锁时勾选“启用系统认证”即可")
                        }
                        PeerSecurityWarning()
                        if windowed { Text(scopeText(details)).font(.system(size: 12)).foregroundStyle(.orange).lineLimit(2) }
                        HStack {
                            Button("关闭") { model.clearNativeFlow(); dismiss() }.keyboardShortcut(.cancelAction)
                            Button("查询最新状态") { failure = nil; Task { await model.reviewLocalApproval(details.id) } }.disabled(model.busy)
                            Spacer()
                            let blocked = !details.canDecide(at: timeline.date) || !model.unlocked || model.busy || model.localApprovalNeedsRefresh
                            Button("认证并拒绝") { decide(details, approve: false) }.disabled(blocked)
                            Button(windowed ? "认证并限时放行 \(windowMinutes) 分钟" : "认证并批准这一次") { decide(details, approve: true) }.buttonStyle(PrimaryButton())
                                .disabled(blocked || windowed && !(1...480).contains(windowMinutes))
                        }
                    }.padding(.horizontal, 28).padding(.vertical, 16)
                }
            }
        }.frame(width: 820, height: 720).background(canvas)
            .onDisappear { model.clearNativeFlow() }
    }
    private func title(_ details: LocalApprovalDetails) -> String {
        guard let review = details.review else { return "本机审批" }
        if review.ssh != nil { return review.title }
        return (review.action_name ?? "本机审批") + (model.operation(for: review).map { " · " + $0.name } ?? "")
    }
    private func scopeText(_ details: LocalApprovalDetails) -> String {
        let rule = model.ruleSummary(details.review)
        let broad = rule.contains("**") ? "，也包括这个连接上其他地址（例如其他仓库）的同类请求" : ""
        return "接下来 \(windowMinutes) 分钟内，同一调用方经 \(details.review?.challenge.resource.id ?? "此连接") 发出、匹配“\(rule)”的请求都会直接放行\(broad)。锁定保险库或修改规则后失效，拒绝规则始终有效。"
    }
    private func decide(_ details: LocalApprovalDetails, approve: Bool) {
        failure = nil
        let seconds = approve && details.review?.windowAllowed == true && limited ? UInt32(windowMinutes * 60) : nil
        Task {
            do { try await model.decideLocalApproval(details, approve: approve, windowSeconds: seconds) }
            catch {
                if model.acceptsNativeCompletion(details.revision, workspace: details.workspace) { failure = error.localizedDescription }
            }
        }
    }
}
