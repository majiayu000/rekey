import Foundation
import LocalAuthentication
import Security

// Retain only the authentication context, never the key returned by the read.
final class PresenceReadContext: @unchecked Sendable {
    private let lock = NSLock()
    private var entry: (vaultID: UUID, context: LAContext, expires: ContinuousClock.Instant?)?

    func read(vaultID: UUID, now: () -> ContinuousClock.Instant = { .now },
              operation: (LAContext) throws -> String) throws -> String {
        let context = lock.withLock {
            if let current = entry, current.vaultID != vaultID || current.expires.map({ now() >= $0 }) == true {
                current.context.invalidate(); entry = nil
            }
            if let current = entry { return current.context }
            let context = LAContext()
            context.localizedReason = "批准本次 Rekey 操作"
            context.touchIDAuthenticationAllowableReuseDuration = 0
            entry = (vaultID, context, nil)
            return context
        }
        do {
            let key = try operation(context)
            lock.withLock {
                if entry?.context === context, entry?.expires == nil {
                    entry?.expires = now().advanced(by: .seconds(10))
                }
            }
            return key
        } catch {
            lock.withLock {
                context.invalidate()
                if entry?.context === context { entry = nil }
            }
            throw error
        }
    }

    func invalidate() {
        lock.withLock { entry?.context.invalidate(); entry = nil }
    }
}

// Explicit user operations only. This K is separate from the cached A1 desktop
// session and the Secure Enclave policy-signing private key. No key is cached here.
enum PresenceKey {
    private static let service = "com.rekey.presence-key.v1"
    private static let reads = PresenceReadContext()

    static func invalidateAuthentication() { reads.invalidate() }

    static func issuedKey(_ data: Data) throws -> String {
        guard let text = String(data: data, encoding: .utf8) else { throw invalidReceipt() }
        let lines = text.split(separator: "\n", omittingEmptySubsequences: false)
        guard lines.count == 2, let expiry = Int64(lines[0]), expiry > 0 else { throw invalidReceipt() }
        return try validated(String(lines[1]))
    }

    static func validated(_ key: String) throws -> String {
        guard key.utf8.count == 64, key.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }) else {
            throw invalidReceipt()
        }
        return key
    }

    static func read(vaultID: UUID) throws -> String {
        try reads.read(vaultID: vaultID) { try read(vaultID: vaultID, context: $0) }
    }

    // The policy activation owns this context and shares it with the SE signer.
    static func read(vaultID: UUID, context: LAContext) throws -> String {
        var query = try identity(vaultID: vaultID)
        query[kSecUseAuthenticationContext as String] = context
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        query[kSecReturnData as String] = true
        query[kSecReturnAttributes as String] = true
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { throw failure(status) }
        guard let items = result as? [[String: Any]], items.count == 1,
              let item = items.first,
              item[kSecAttrService as String] as? String == service,
              item[kSecAttrAccount as String] as? String == vaultID.uuidString.lowercased(),
              item[kSecAttrAccessGroup as String] as? String == query[kSecAttrAccessGroup as String] as? String,
              let bytes = item[kSecValueData as String] as? Data,
              let key = String(data: bytes, encoding: .utf8) else {
            throw UIError(message: "系统认证授权记录不唯一或身份不符，已停止操作。")
        }
        // Public APIs do not expose the original ACL flags. This new namespace
        // is written only by save; we do not migrate or trust the legacy item.
        return try validated(key)
    }

    static func save(_ key: String, vaultID: UUID) throws {
        reads.invalidate()
        let bytes = Data(try validated(key).utf8)
        let context = authenticationContext("保存 Rekey 系统认证授权")
        defer { context.invalidate() }
        var query = try identity(vaultID: vaultID)
        query[kSecUseAuthenticationContext as String] = context
        var lookup = query
        lookup[kSecMatchLimit as String] = kSecMatchLimitAll
        lookup[kSecReturnAttributes as String] = true
        var found: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &found)
        if status == errSecSuccess {
            guard let items = found as? [[String: Any]], items.count == 1 else {
                throw UIError(message: "系统认证授权记录不唯一，未替换任何记录。")
            }
        } else if status != errSecItemNotFound { throw failure(status) }
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error) else {
            throw failure(error?.takeRetainedValue())
        }
        if status == errSecSuccess {
            let removed = SecItemDelete(query as CFDictionary)
            guard removed == errSecSuccess else { throw failure(removed) }
        }
        query[kSecAttrAccessControl as String] = access
        query[kSecValueData as String] = bytes
        let added = SecItemAdd(query as CFDictionary, nil)
        guard added == errSecSuccess else { throw failure(added) }
    }

    private static func authenticationContext(_ reason: String) -> LAContext {
        let context = LAContext()
        context.localizedReason = reason
        context.touchIDAuthenticationAllowableReuseDuration = 0
        return context
    }

    private static func identity(vaultID: UUID) throws -> [String: Any] {
        var code: SecCode?
        var requirement: SecRequirement?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code,
              SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement) == errSecSuccess,
              let requirement, SecCodeCheckValidity(code, [], requirement) == errSecSuccess else {
            throw UIError(message: "系统认证需要有效的 Apple 开发者签名；当前应用不能使用受保护授权。")
        }
        var information: CFDictionary?
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode,
              SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let fields = information as? [String: Any],
              let team = fields[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty,
              let entitlements = fields[kSecCodeInfoEntitlementsDict as String] as? [String: Any],
              let groups = entitlements["keychain-access-groups"] as? [String], groups.contains(team + ".com.rekey") else {
            throw UIError(message: "应用缺少系统认证所需的钥匙串授权；请使用带正确签名、权限与描述文件的 Rekey。")
        }
        return [kSecClass as String: kSecClassGenericPassword,
                kSecUseDataProtectionKeychain as String: true,
                kSecAttrAccessGroup as String: team + ".com.rekey",
                kSecAttrService as String: service,
                kSecAttrAccount as String: vaultID.uuidString.lowercased(),
                kSecAttrSynchronizable as String: false]
    }

    private static func invalidReceipt() -> UIError { UIError(message: "系统认证授权响应无效，未采用。") }
    private static func failure(_ error: CFError?) -> UIError {
        guard let error else { return UIError(message: "无法创建系统认证保护，未保存授权。") }
        return UIError(message: "无法创建系统认证保护（系统代码 \(CFErrorGetCode(error))）。")
    }
    private static func failure(_ status: OSStatus) -> UIError {
        switch status {
        case errSecItemNotFound: return UIError(message: "尚无系统认证授权，请先用密码解锁并选择启用系统认证。")
        case errSecUserCanceled, errSecAuthFailed: return UIError(message: "系统认证未完成或已取消，未自动重试。")
        case errSecInteractionNotAllowed: return UIError(message: "设备已锁定或当前无法进行系统认证，请解锁后重试。")
        case errSecMissingEntitlement, errSecNoAccessForItem: return UIError(message: "应用没有数据保护钥匙串访问权限，请检查签名、权限与描述文件。")
        default: return UIError(message: "系统认证授权不可用（系统代码 \(status)），请使用保险库密码。")
        }
    }
}
