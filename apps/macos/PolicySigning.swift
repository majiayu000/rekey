import Foundation
import LocalAuthentication
import Security
import CryptoKit

// Call only from an explicit setup/sign action, off the UI thread. No method
// exports private key bytes, removes a key, retries, or replaces installed trust.
enum PolicySigning {
    private static let prefix = Data("RKPOLICY\0\u{01}".utf8)

    enum Mode: Sendable {
        case secureEnclave, software
        var label: String {
            switch self {
            case .secureEnclave: return "Secure Enclave 签名 · 私钥不可导出"
            case .software: return "基础模式 · 使用已有软件签名密钥，同一用户的进程可读取此密钥"
            }
        }
    }

    private struct SoftwareTrust: Decodable {
        struct Trust: Decodable { let public_key: String }
        let trust: Trust
        let trust_sha256: String
    }

    private static func softwareTrust(current: PolicyStatus, client: CLI) throws -> SoftwareTrust {
        guard let signer = current.signer_id else { throw UIError(message: "保险库尚未设置签名信任根。") }
        return try JSONDecoder().decode(SoftwareTrust.self, from: client.policySigner([
            "software-key", "trust", "--key-file", client.stateDirectory + "/policy-signer-p256.p8", "--signer-id", signer
        ]))
    }

    // No authentication prompt or key generation during preflight. The algorithm
    // label alone cannot distinguish hardware from the existing basic-mode key.
    static func available(current: PolicyStatus, client: CLI, expectedPublicKey: Data? = nil,
                          hardwarePublicKey: (UUID) throws -> Data? = existingPublicKey) throws -> Mode {
        guard current.mode == .personal, current.trust_installed, current.algorithm == .secureEnclaveP256,
              let vault = UUID(uuidString: current.vault_id), let signer = current.signer_id,
              let digest = current.trust_sha256 else { throw UIError(message: "请先完成个人保险库的签名信任根设置。") }
        // Existing basic-mode files can be checked without accessing Keychain.
        if FileManager.default.fileExists(atPath: client.stateDirectory + "/policy-signer-p256.p8") {
            let software = try softwareTrust(current: current, client: client)
            if software.trust_sha256 == digest {
                if let expectedPublicKey, software.trust.public_key != expectedPublicKey.map({ String(format: "%02x", $0) }).joined() {
                    throw UIError(message: "软件签名密钥与草稿不一致，未签署。")
                }
                return .software
            }
        }
        if let key = try hardwarePublicKey(vault) {
            let trust: [String: Any] = ["algorithm": "secure-enclave-p256", "format_version": 1,
                                       "public_key": key.map { String(format: "%02x", $0) }.joined(), "signer_id": signer]
            // All four fields are ASCII strings/integers; sorted JSON is JCS here.
            let canonical = try JSONSerialization.data(withJSONObject: trust, options: [.sortedKeys])
            if SHA256.hash(data: canonical).map({ String(format: "%02x", $0) }).joined() == digest { return .secureEnclave }
        }
        throw UIError(message: "找不到与此保险库信任根匹配的签名密钥。请使用原签名设备；不会创建替代密钥。")
    }

    static func signExisting(current: PolicyStatus, client: CLI, message: Data, expectedPublicKey: Data, context: LAContext) throws -> String {
        switch try available(current: current, client: client, expectedPublicKey: expectedPublicKey) {
        case .secureEnclave:
            guard let vault = UUID(uuidString: current.vault_id) else { throw UIError(message: "保险库标识无效。") }
            return try sign(vaultID: vault, message: message, expectedPublicKey: expectedPublicKey, context: context)
        case .software:
            let output = try client.policySigner(["software-key", "sign", "--key-file", client.stateDirectory + "/policy-signer-p256.p8"], input: message)
            return String(decoding: output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
        }
    }

    private static func existingPublicKey(vaultID: UUID) throws -> Data? {
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        guard let key = try load(vaultID: vaultID, context: context) else { return nil }
        return try publicKey(key)
    }

    static func createOrLoadPublicKey(vaultID: UUID) throws -> Data {
        let context = LAContext()
        context.interactionNotAllowed = true
        defer { context.invalidate() }
        if let key = try load(vaultID: vaultID, context: context) {
            return try publicKey(key)
        }

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &error
        ) else { throw failure(error) }
        let attributes: [String: Any] = [
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag(vaultID),
                kSecAttrAccessControl as String: access
            ]
        ]
        guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw failure(error)
        }
        return try publicKey(key)
    }

    // message is the daemon's exact prefix + JCS bytes, after displaying its diff.
    // expectedPublicKey must come from the daemon's verified installed trust.
    static func sign(vaultID: UUID, message: Data, expectedPublicKey: Data, context: LAContext) throws -> String {
        guard message.starts(with: prefix), message.count > prefix.count,
              message.count <= 65_536 + prefix.count,
              expectedPublicKey.count == 65, expectedPublicKey.first == 4 else {
            throw UIError(message: "策略签名内容或已安装信任根无效，请重新获取策略草稿。")
        }
        context.interactionNotAllowed = true
        context.touchIDAuthenticationAllowableReuseDuration = 0
        context.localizedReason = "批准已审阅的 Rekey 策略"
        guard let key = try load(vaultID: vaultID, context: context) else {
            throw UIError(message: "此保险库的策略私钥不在本机；不会生成替代密钥。")
        }
        guard try publicKey(key) == expectedPublicKey else {
            throw UIError(message: "本机策略密钥与已安装信任根不一致，已拒绝签名。")
        }
        context.interactionNotAllowed = false
        var error: Unmanaged<CFError>?
        guard let signature = SecKeyCreateSignature(
            key, .ecdsaSignatureMessageX962SHA256, message as CFData, &error
        ) else { throw failure(error) }
        return (signature as Data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    private static func tag(_ vaultID: UUID) -> Data {
        Data("com.rekey.policy-signing.\(vaultID.uuidString.lowercased())".utf8)
    }

    private static func load(vaultID: UUID, context: LAContext) throws -> SecKey? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrApplicationTag as String: tag(vaultID),
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: context,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else {
            throw systemError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        guard let keys = result as? [SecKey], keys.count == 1 else {
            throw UIError(message: "此保险库的策略密钥记录不唯一或无效；不会自动替换。")
        }
        return keys[0]
    }

    private static func publicKey(_ key: SecKey) throws -> Data {
        // These are documented SecKeyCopyAttributes fields. Public APIs do not
        // expose the original ACL flags; this check does not attest userPresence.
        guard let attributes = SecKeyCopyAttributes(key) as? [String: Any],
              attributes[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String,
              attributes[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              attributes[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attributes[kSecAttrKeySizeInBits as String] as? Int == 256,
              attributes[kSecAttrCanSign as String] as? Bool == true,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256),
              let publicKey = SecKeyCopyPublicKey(key) else {
            throw UIError(message: "策略密钥不是可核实的 Secure Enclave P-256 私钥，已停止操作。")
        }
        var error: Unmanaged<CFError>?
        guard let encoded = SecKeyCopyExternalRepresentation(publicKey, &error) else {
            throw failure(error)
        }
        let bytes = encoded as Data
        guard bytes.count == 65, bytes.first == 4 else {
            throw UIError(message: "策略公钥编码无效，已停止操作。")
        }
        return bytes
    }

    private static func failure(_ error: Unmanaged<CFError>?) -> UIError {
        guard let value = error?.takeRetainedValue() else {
            return UIError(message: "策略密钥操作失败，未自动重试。")
        }
        return systemError(domain: CFErrorGetDomain(value) as String, code: CFErrorGetCode(value))
    }

    private static func systemError(domain: String, code: Int) -> UIError {
        switch (domain, code) {
        case (NSOSStatusErrorDomain, Int(errSecUserCanceled)),
             (LAError.errorDomain, LAError.Code.userCancel.rawValue),
             (LAError.errorDomain, LAError.Code.appCancel.rawValue),
             (LAError.errorDomain, LAError.Code.systemCancel.rawValue):
            return UIError(message: "策略密钥操作已取消，未自动重试。")
        case (NSOSStatusErrorDomain, Int(errSecInteractionNotAllowed)),
             (LAError.errorDomain, LAError.Code.notInteractive.rawValue):
            return UIError(message: "设备已锁定或系统当前不允许认证；请解锁后手动重试。")
        case (NSOSStatusErrorDomain, Int(errSecMissingEntitlement)),
             (NSOSStatusErrorDomain, Int(errSecNoAccessForItem)):
            return UIError(message: "应用没有所需钥匙串访问权限；请检查应用签名与授权配置。")
        case (NSOSStatusErrorDomain, Int(errSecNotAvailable)),
             (NSOSStatusErrorDomain, Int(errSecUnimplemented)):
            return UIError(message: "Secure Enclave 或钥匙串当前不可用；不会使用软件密钥替代。")
        case (NSOSStatusErrorDomain, Int(errSecAuthFailed)),
             (LAError.errorDomain, LAError.Code.authenticationFailed.rawValue):
            return UIError(message: "系统在场认证未完成，未产生策略签名。")
        default:
            return UIError(message: "策略密钥操作失败（系统代码 \(code)），未自动重试。")
        }
    }
}
