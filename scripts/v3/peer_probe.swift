// Bounded V3 experiment; no production IPC, credentials, or Keychain access.
// Build: xcrun swiftc scripts/v3/peer_probe.swift -o <output>
// Sign copies externally, then run one server and one client per case:
//   peer_probe server --socket <new-path-in-private-temp-directory>
//   peer_probe client --socket <same-path> --team-id <expected-TeamID>
// Client exit: 0 verified/sent, 2 rejected/zero sent, 3 inconclusive, 64 usage.
// Server stdout: ready + observation JSONL; never prints received content.
// Public APIs: Security/SecCode.h, sys/un.h, and
// https://developer.apple.com/documentation/security/ksecguestattributeaudit
// https://developer.apple.com/library/archive/documentation/Security/Conceptual/CodeSigningGuide/RequirementLang/RequirementLang.html

import Darwin
import Foundation
import Security

let canary = Data("REKEY_V3_SYNTHETIC_PROOF_ONLY\n".utf8)
let timeoutSeconds: Double = 15

struct ProbeError: Error {
    let stage: String
    let number: Int32
}

func emit(_ fields: [String: Any]) {
    do {
        let data = try JSONSerialization.data(withJSONObject: fields, options: [.sortedKeys])
        try FileHandle.standardOutput.write(contentsOf: data + Data([10]))
    } catch {
        fputs("probe JSON output failed\n", stderr)
        exit(3)
    }
}

func socketAddress<T>(_ path: String, _ body: (UnsafePointer<sockaddr>, socklen_t) throws -> T) throws -> T {
    var address = sockaddr_un()
    let bytes = Array(path.utf8)
    guard path.hasPrefix("/"), !bytes.contains(0), bytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
        throw ProbeError(stage: "socket_path", number: EINVAL)
    }
    address.sun_family = sa_family_t(AF_UNIX)
    address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
    withUnsafeMutableBytes(of: &address.sun_path) { buffer in
        buffer.copyBytes(from: bytes + [0])
    }
    return try withUnsafePointer(to: &address) { pointer in
        try pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            try body($0, socklen_t(MemoryLayout<sockaddr_un>.size))
        }
    }
}

func makeSocket() throws -> Int32 {
    let fd = socket(AF_UNIX, SOCK_STREAM, 0)
    guard fd >= 0 else { throw ProbeError(stage: "socket", number: errno) }
    return fd
}

func waitReadable(_ fd: Int32, deadline: Double) throws {
    while true {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        guard remaining > 0 else { throw ProbeError(stage: "timeout", number: ETIMEDOUT) }
        var item = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        let result = poll(&item, 1, Int32(ceil(remaining * 1_000)))
        if result > 0 { return }
        if result < 0 && errno == EINTR { continue }
        throw ProbeError(stage: result == 0 ? "timeout" : "poll", number: result == 0 ? ETIMEDOUT : errno)
    }
}

func serve(_ path: String) -> Int32 {
    var received = Data()
    var eof = false
    do {
        let listener = try makeSocket()
        defer { close(listener) }
        let oldMask = umask(0o077)
        defer { umask(oldMask) }
        try socketAddress(path) {
            guard bind(listener, $0, $1) == 0 else { throw ProbeError(stage: "bind", number: errno) }
        }
        // Never unlink an existing path before bind; remove only this socket.
        defer { unlink(path) }
        guard listen(listener, 1) == 0 else { throw ProbeError(stage: "listen", number: errno) }
        emit(["event": "ready", "timeout_seconds": timeoutSeconds])
        let deadline = ProcessInfo.processInfo.systemUptime + timeoutSeconds
        try waitReadable(listener, deadline: deadline)
        let peer = accept(listener, nil, nil)
        guard peer >= 0 else { throw ProbeError(stage: "accept", number: errno) }
        defer { close(peer) }
        var buffer = [UInt8](repeating: 0, count: 256)
        while true {
            try waitReadable(peer, deadline: deadline)
            let count = recv(peer, &buffer, buffer.count, 0)
            if count == 0 { eof = true; break }
            if count < 0 && errno == EINTR { continue }
            guard count > 0 else { throw ProbeError(stage: "recv", number: errno) }
            received.append(contentsOf: buffer.prefix(count))
            guard received.count <= 4096 else { throw ProbeError(stage: "observation_limit", number: EMSGSIZE) }
        }
        emit(["event": "observation", "outcome": "observed", "received_bytes": received.count,
              "canary_match": received == canary, "eof": eof])
        return 0
    } catch let error as ProbeError {
        emit(["event": "observation", "outcome": "inconclusive", "stage": error.stage, "errno": error.number,
              "received_bytes": received.count, "canary_match": received == canary, "eof": eof])
        return 3
    } catch {
        emit(["event": "observation", "outcome": "inconclusive", "stage": "unexpected_error",
              "received_bytes": received.count, "eof": eof])
        return 3
    }
}

func client(_ path: String, team: String) -> Int32 {
    var metadata: [String: Any] = ["event": "result", "outcome": "inconclusive", "sent_bytes": 0,
                                   "local_peertoken": false, "pid_fallback": false]
    do {
        // TeamID is coordinator-supplied public metadata, never a credential.
        let quotedTeam = team.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let requirementText = "anchor apple generic and anchor trusted and certificate leaf[subject.OU] = \"\(quotedTeam)\" and identifier \"com.rekey.rekeyd\""
        var requirement: SecRequirement?
        let parsed = SecRequirementCreateWithString(requirementText as CFString, [], &requirement)
        guard parsed == errSecSuccess, let requirement else {
            metadata["stage"] = "requirement_parse"
            metadata["osstatus"] = parsed
            emit(metadata)
            return 3
        }
        let fd = try makeSocket()
        defer { close(fd) }
        try socketAddress(path) {
            guard connect(fd, $0, $1) == 0 else { throw ProbeError(stage: "connect", number: errno) }
        }
        var token = audit_token_t()
        var tokenSize = socklen_t(MemoryLayout<audit_token_t>.size)
        guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &tokenSize) == 0 else {
            throw ProbeError(stage: "LOCAL_PEERTOKEN", number: errno)
        }
        guard tokenSize == MemoryLayout<audit_token_t>.size else {
            throw ProbeError(stage: "audit_token_size", number: EINVAL)
        }
        metadata["local_peertoken"] = true
        metadata["audit_token_bytes"] = Int(tokenSize)
        // Bind the dynamic guest to the full kernel-supplied token, including
        // the PID version. Do not resolve a PID or validate a file on disk.
        let tokenData = withUnsafeBytes(of: token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit as String: tokenData] as CFDictionary
        var guest: SecCode?
        let lookup = SecCodeCopyGuestWithAttributes(nil, attributes, [], &guest)
        guard lookup == errSecSuccess, let guest else {
            metadata["stage"] = "SecCodeCopyGuestWithAttributes"
            metadata["osstatus"] = lookup
            // Unsupported APIs or an exited peer are inconclusive, fail closed.
            // A genuinely unsigned executable can be explicitly rejected here.
            if lookup == errSecCSUnsigned { metadata["outcome"] = "rejected" }
            emit(metadata)
            return lookup == errSecCSUnsigned ? 2 : 3
        }
        let validity = SecCodeCheckValidity(guest, [], requirement)
        metadata["osstatus"] = validity
        guard validity == errSecSuccess else {
            metadata["stage"] = "SecCodeCheckValidity"
            // Requirement mismatch/invalid signature reject; API failures remain
            // inconclusive. Every non-success takes the same zero-send path.
            let rejected = validity == errSecCSReqFailed || validity == errSecCSUnsigned || validity == errSecCSSignatureFailed
            metadata["outcome"] = rejected ? "rejected" : "inconclusive"
            emit(metadata)
            return rejected ? 2 : 3
        }
        // The first send in this process is below successful dynamic validation.
        var noSIGPIPE: Int32 = 1
        guard setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSIGPIPE, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw ProbeError(stage: "SO_NOSIGPIPE", number: errno)
        }
        var sent = 0
        try canary.withUnsafeBytes { bytes in
            while sent < bytes.count {
                let count = send(fd, bytes.baseAddress!.advanced(by: sent), bytes.count - sent, 0)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { throw ProbeError(stage: "send", number: count < 0 ? errno : EIO) }
                sent += count
                metadata["sent_bytes"] = sent
            }
        }
        guard shutdown(fd, SHUT_WR) == 0 else { throw ProbeError(stage: "shutdown", number: errno) }
        metadata["outcome"] = "verified"
        metadata["stage"] = "synthetic_canary_sent"
        emit(metadata)
        return 0
    } catch let error as ProbeError {
        metadata["stage"] = error.stage
        metadata["errno"] = error.number
        emit(metadata)
        return 3
    } catch {
        metadata["stage"] = "unexpected_error"
        emit(metadata)
        return 3
    }
}

let args = Array(CommandLine.arguments.dropFirst())
if args.count == 3, args[0] == "server", args[1] == "--socket" {
    exit(serve(args[2]))
}
if args.count == 5, args[0] == "client", args[1] == "--socket", args[3] == "--team-id", !args[4].isEmpty {
    exit(client(args[2], team: args[4]))
}
emit(["event": "result", "outcome": "usage", "sent_bytes": 0,
      "usage": "peer_probe server --socket PATH | peer_probe client --socket PATH --team-id TEAMID"])
exit(64)
