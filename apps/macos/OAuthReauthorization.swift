import Foundation

/// OAuth connections whose grant the provider refused (agent-call §7.4): in an activity
/// snapshot, the newest OAuth record for the connection's credential is `oauth.refresh_failed`
/// with reason `oauth-needs-reauth`. A later `oauth.authorized` or `oauth.refreshed` clears
/// it; transient refresh failures and failed browser logins neither raise nor clear it.
/// Only public audit fields are read.
struct OAuthReauthorization {
    static let refusal = "oauth-needs-reauth"
    private var decided = Set<String>()
    private(set) var connections: [String] = []

    /// Pages arrive newest first, so the first decisive record for a credential wins.
    mutating func note(_ event: AuditEvent) {
        guard let credential = event.credential_id, !decided.contains(credential) else { return }
        switch event.event_type {
        case "oauth.authorized", "oauth.refreshed":
            decided.insert(credential)
        case "oauth.refresh_failed" where event.reason_code == Self.refusal:
            decided.insert(credential)
            if let name = event.request_context?.connection, !connections.contains(name) {
                connections.append(name)
                connections.sort()
            }
        default:
            break
        }
    }
}
