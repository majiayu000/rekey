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
                            if details.state == .expired || details.state == .pending && !details.canDecide(at: timeline.date) {
                                Label("请求已过期，不能再批准。请让 Agent 重新发起。", systemImage: "clock.badge.exclamationmark").font(.system(size: 14, weight: .medium)).foregroundStyle(warn)
                            } else {
                                Text(details.state.label).font(.system(size: 13)).foregroundStyle(.secondary)
                            }
                            if details.state == .approved {
                                HStack {
                                    Label("已批准，等待 Agent 带同一个审批 ID 重试并执行。", systemImage: "checkmark.seal").foregroundStyle(green)
                                    Button("查看活动") { model.clearNativeFlow(); dismiss(); model.page = .activity; model.clearActivity(); Task { await model.refresh() } }
                                }.font(.system(size: 14, weight: .medium))
                            }
                            if let review = details.review {
                                if let sentence = model.plainSentence(review) { Text(sentence).font(.system(size: 16, weight: .medium)).textSelection(.enabled) }
                                if let ssh = review.ssh {
                                    Text("用途：\(ssh.purposeLabel) · 用户：\(ssh.use.username ?? "不适用")").textSelection(.enabled)
                                    Text("host：\(ssh.host)").textSelection(.enabled)
                                    if ssh.bound_host_key == nil || ssh.host == "unknown-host" { Text("目标尚未绑定或未登记；本次批准不能验证 host 身份。").foregroundStyle(warn) }
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
                                    let rule = model.ruleSummary(details.review)
                                    Picker("批准范围", selection: $limited) {
                                        Text("仅这一个请求（推荐）").tag(false)
                                        Text("限时放行之后匹配“\(rule)”的请求").tag(true)
                                    }.pickerStyle(.radioGroup).labelsHidden().disabled(rule == "此规则")
                                    if !limited {
                                        Text(rule == "此规则" ? "读不到匹配的规则，只能批准这一次。" : "限时放行会覆盖同一连接上匹配这条规则的其他请求\(rule.contains("**") ? "，例如其他仓库" : "")。").font(.system(size: 12)).foregroundStyle(.secondary)
                                    }
                                    if limited {
                                        HStack {
                                            Picker("时长", selection: $minutes) { Text("15 分钟").tag("15"); Text("30 分钟").tag("30"); Text("1 小时").tag("60"); Text("2 小时").tag("120"); Text("自定义").tag("custom") }.frame(width: 200)
                                            if minutes == "custom" { TextField("分钟（1–480）", text: $customMinutes).textFieldStyle(.roundedBorder).frame(width: 120) }
                                        }
                                        Text(scopeText(details)).font(.system(size: 13)).foregroundStyle(warn).fixedSize(horizontal: false, vertical: true)
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
                            if failure.contains("尚无系统认证授权") {
                                Button("重新解锁并启用系统认证") { model.clearNativeFlow(); dismiss(); model.requestDesktopLogin() }
                            } else if failure.contains("未确认") {
                                Text("结果未知：先点“查询最新状态”，不要重复决定。").font(.system(size: 12, weight: .medium))
                            } else if failure.contains("未完成或已取消") {
                                Text("没有提交任何决定，可以再次认证。").font(.system(size: 12)).foregroundStyle(.secondary)
                            }
                        }
                        PeerSecurityWarning()
                        if windowed { Text(scopeText(details)).font(.system(size: 12)).foregroundStyle(warn).fixedSize(horizontal: false, vertical: true) }
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
        let broad = rule.contains("**") ? "，包括其他地址（例如其他仓库）" : ""
        return "适用范围：连接 \(details.review?.challenge.resource.id ?? "此连接") 上匹配“\(rule)”的请求\(broad)，且调用方标注与这次相同（标注由 Agent 填写，不验证身份）。\n截止时间：\(windowMinutes) 分钟后，或规则到期、保险库锁定、规则修改时，以先到者为准；拒绝规则始终有效。"
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
