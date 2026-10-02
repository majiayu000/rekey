// V1 prototype only. Compile with: xcrun swiftc keychain_probe.swift -o keychain_probe
// Usage: keychain_probe create|read-no-ui|read-with-ui|cleanup UUID TeamID.com.rekey
// Read modes also accept '-' to omit the query's access group. The executable's
// signing entitlements remain a separate test input; this tool does not sign.
// Generate a fresh UUID per run. Its hash is a public, synthetic 32-byte canary,
// never a credential. No canary bytes, encodings, or hashes are printed.
// Exit: 0 = operation succeeded, 1 = authentication denied, 2 = inconclusive/error.
// OSStatus is always preserved; a denial alone does not establish that an item exists.
import CryptoKit
import Foundation
import LocalAuthentication
import Security

func emit(_ record: [String: Any], exitCode: Int32) -> Never {
    do {
        let data = try JSONSerialization.data(withJSONObject: record, options: [.sortedKeys])
        FileHandle.standardOutput.write(data)
        FileHandle.standardOutput.write(Data([10]))
    } catch {
        print("{\"outcome\":\"json_encoding_error\",\"os_status\":null}")
        exit(2)
    }
    exit(exitCode)
}

let args = CommandLine.arguments
let modes = ["create", "read-no-ui", "read-with-ui", "cleanup"]
guard args.count == 4, modes.contains(args[1]),
      let uuid = UUID(uuidString: args[2]), !args[3].isEmpty,
      args[3] != "-" || args[1].hasPrefix("read-") else {
    emit([
        "outcome": "usage_error", "os_status": NSNull(),
        "usage": "keychain_probe create|read-no-ui|read-with-ui|cleanup UUID TeamID.com.rekey (- allowed for reads)"
    ], exitCode: 2)
}

let mode = args[1]
let id = uuid.uuidString.lowercased()
let group = args[3] == "-" ? nil : args[3]
let service = "com.rekey.v3-v1.\(id)"
let account = "canary-\(id)"
let isRead = mode.hasPrefix("read-")
let allowsUI = mode == "read-with-ui"
let canary = Data(SHA256.hash(data: Data("rekey-v3-v1-synthetic-canary:\(id)".utf8)))
var record: [String: Any] = [
    "mode": mode, "id": id, "service": service, "account": account,
    "access_group": group as Any? ?? NSNull(),
    "authentication_ui_allowed": allowsUI, "os_status": NSNull()
]

// Fresh, unauthenticated context per process. Apple's SDK documents that
// interactionNotAllowed returns errSecInteractionNotAllowed instead of a UI.
// Do not call evaluatePolicy/canEvaluatePolicy before this keychain operation.
let context = LAContext()
context.interactionNotAllowed = !allowsUI
context.touchIDAuthenticationAllowableReuseDuration = 0
context.localizedReason = "Read Rekey V1 synthetic test canary"
var query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrService as String: service,
    kSecAttrAccount as String: account,
    kSecAttrLabel as String: "Rekey V1 SYNTHETIC CANARY ONLY",
    kSecAttrSynchronizable as String: false,
    kSecUseDataProtectionKeychain as String: true,
    kSecUseAuthenticationContext as String: context
]
if let group { query[kSecAttrAccessGroup as String] = group }

let status: OSStatus
var result: CFTypeRef?
switch mode {
case "create":
    var error: Unmanaged<CFError>?
    guard let control = SecAccessControlCreateWithFlags(
        nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error
    ) else {
        context.invalidate()
        record["outcome"] = "access_control_error"
        if let error = error?.takeRetainedValue() {
            record["error_domain"] = CFErrorGetDomain(error) as String
            record["error_code"] = CFErrorGetCode(error)
            record["error_description"] = CFErrorCopyDescription(error) as String
        }
        emit(record, exitCode: 2)
    }
    query[kSecAttrAccessControl as String] = control
    query[kSecValueData as String] = canary
    status = SecItemAdd(query as CFDictionary, nil)
case "cleanup":
    // Exact class + UUID service + UUID account + label + group only. Never
    // enumerate, delete a group, or remove an existing item before create.
    status = SecItemDelete(query as CFDictionary)
default:
    query[kSecReturnData as String] = true
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    status = SecItemCopyMatching(query as CFDictionary, &result)
}
context.invalidate()
record["os_status"] = status
record["os_status_message"] = SecCopyErrorMessageString(status, nil) as String? ?? "Unknown OSStatus"

if status == errSecSuccess {
    if isRead {
        let matches = (result as? Data) == canary
        record["canary_match"] = matches
        record["outcome"] = matches ? "read_success" : "canary_mismatch"
        emit(record, exitCode: matches ? 0 : 2)
    }
    record["outcome"] = mode == "create" ? "created" : "deleted"
    emit(record, exitCode: 0)
}

let exitCode: Int32
switch status {
case errSecMissingEntitlement:
    record["outcome"] = "environment_missing_entitlement"
    exitCode = 2
case errSecInteractionNotAllowed:
    record["outcome"] = "authentication_ui_disabled"
    exitCode = 1
case errSecAuthFailed:
    record["outcome"] = "authentication_denied"
    exitCode = 1
case errSecUserCanceled:
    record["outcome"] = "authentication_canceled"
    exitCode = 1
case errSecItemNotFound:
    record["outcome"] = mode == "cleanup" ? "already_absent" : "item_not_found"
    exitCode = mode == "cleanup" ? 0 : 2
case errSecNotAvailable:
    record["outcome"] = "environment_keychain_unavailable"
    exitCode = 2
default:
    record["outcome"] = "keychain_error"
    exitCode = 2
}
emit(record, exitCode: exitCode)
