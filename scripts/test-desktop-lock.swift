import Foundation
import AppKit
import LocalAuthentication

// Real production AppModel lifecycle; device authentication and Keychain access
// are injected, and the private CLI fixture synchronizes in-flight replies.
@main
struct DesktopLockContract {
    @MainActor
    static func main() async throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("rekey-desktop-lock-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        let suite = "rekey-desktop-lock-" + UUID().uuidString
        let preferences = UserDefaults(suiteName: suite)!
        defer {
            preferences.removePersistentDomain(forName: suite)
            do { try FileManager.default.removeItem(at: root) } catch { fputs("desktop fixture cleanup failed\n", stderr) }
        }
        let binary = root.appendingPathComponent("cli-fixture")
        try """
        #!/usr/bin/python3
        import json, pathlib, sys, time
        args = sys.argv[1:]
        state = pathlib.Path(args[args.index('--state-dir')+1])
        command = args[2:]
        body = sys.stdin.buffer.read()
        with (state/'calls').open('a') as f:
            f.write(json.dumps({'args': command, 'body_lines': len(body.splitlines())})+'\\n')
        op = command[0]
        if op in ('desktop-login', 'desktop-resume', 'desktop-reveal'):
            (state/(op+'-started')).touch()
            deadline = time.monotonic()+8
            while (state/('gate-'+op)).exists() and not (state/('release-'+op)).exists():
                if time.monotonic()>deadline: sys.exit(2)
                time.sleep(.01)
        if op == 'desktop-lock':
            if (state/'fail-lock').exists():
                sys.stderr.write('IPC_UNAVAILABLE'); sys.exit(1)
            print('{"locked":true}')
        elif op == 'desktop-login': sys.stdout.write('aa'*32)
        elif op == 'desktop-resume': sys.stdout.write(str(int(time.time()*1000)+86400000)+'\\n'+'cc'*32)
        elif op == 'desktop-reveal': sys.stdout.write('synthetic-credential-body')
        elif op == 'status': print('{"state":"unlocked","format_version":20,"runtime_version":"fixture","sessions_active":1}')
        elif op == 'approval': print('{"challenges":[]}')
        elif op == 'credential': print('{"credentials":[]}')
        elif op == 'action': print('{"actions":[]}')
        else: sys.exit(3)
        """.write(to: binary, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: binary.path)
        var assertions = 0
        func require(_ value: @autoclosure () -> Bool, _ name: String) throws {
            guard value() else { throw UIError(message: "FAILED: " + name) }; assertions += 1
        }
        func waitFor(_ condition: () -> Bool) async throws {
            let deadline = Date().addingTimeInterval(8)
            while !condition() {
                guard Date() < deadline else { throw UIError(message: "fixture synchronization timed out") }
                try await Task.sleep(nanoseconds: 10_000_000)
            }
        }
        func model(_ settings: DesktopSecuritySettings = .init()) throws -> (AppModel, URL, NSPasteboard) {
            let directory = root.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
            preferences.set(try JSONEncoder().encode(settings), forKey: "desktopSecurity")
            let board = NSPasteboard(name: .init("rekey-test-" + UUID().uuidString))
            let model = AppModel(stateDirectory: directory.path, preferences: preferences, binary: binary, clipboard: board)
            model.status = ServiceStatus(state: "unlocked", format_version: 20, runtime_version: "fixture", sessions_active: 1)
            return (model, directory, board)
        }
        func calls(_ path: URL) -> String { (try? String(contentsOf: path.appendingPathComponent("calls"), encoding: .utf8)) ?? "" }
        func touch(_ directory: URL, _ name: String) throws { try Data().write(to: directory.appendingPathComponent(name)) }

        let defaults = DesktopSecuritySettings()
        try require(defaults.idle == .fiveMinutes && defaults.lockWithDevice && defaults.passwordInterval == .sevenDays, "independent defaults")
        try require(!defaults.idleLockDue(299.9) && defaults.idleLockDue(300), "idle threshold")
        var disabled = defaults; disabled.idle = .disabled; disabled.lockWithDevice = false
        try require(!disabled.idleLockDue(100000), "disabled idle")
        let (first, firstPath, board) = try model()
        try require(first.desktopLocked && first.desktopToken == nil, "app starts locked")
        await first.refresh()
        try require(!calls(firstPath).contains("desktop-resume") && first.desktopLocked, "startup cannot auto-resume")
        first.requestDesktopLogin()
        first.checkDesktopIdle(elapsed: 300)
        try require(first.operation == nil && first.desktopLocked, "idle closes a login form even before authentication")
        first.acceptDesktopSession("synthetic-token", expiry: Date().addingTimeInterval(3600))
        first.visibleSecret = "synthetic-visible"; first.showAddCredential = true; first.showSession = true
        first.result = ResultMessage(title: "sensitive", text: "synthetic-result", sensitive: true)
        try first.copyToClipboard("synthetic-copy", credential: "id")
        await first.refresh(passive: true)
        first.checkDesktopIdle(elapsed: 300)
        try require(first.desktopLocked && first.desktopToken == nil && first.visibleSecret == nil, "passive polling cannot postpone idle lock")
        try require(!first.showAddCredential && !first.showSession && first.result == nil, "forms and sensitive results close")
        try require(board.string(forType: .string) == nil, "owned clipboard cleared on lock")
        try await waitFor { first.pendingDesktopLocks == 0 }
        try require(calls(firstPath).contains("desktop-lock") && !calls(firstPath).contains("synthetic-token"), "server revocation uses body, not argv")

        first.acceptDesktopSession("next-token", expiry: Date().addingTimeInterval(3600))
        try first.copyToClipboard("our-copy", credential: "id")
        board.clearContents(); board.setString("new-user-copy", forType: .string)
        first.lockDesktop(); try await waitFor { first.pendingDesktopLocks == 0 }
        try require(board.string(forType: .string) == "new-user-copy", "later clipboard value preserved")

        let (optOut, _, _) = try model(disabled)
        optOut.acceptDesktopSession("optout", expiry: Date().addingTimeInterval(3600))
        optOut.deviceLocked(); optOut.checkDesktopIdle(elapsed: 100000)
        try require(!optOut.desktopLocked, "device and idle opt-outs respected")
        optOut.clearCache()

        var noIdle = defaults; noIdle.idle = .disabled
        let (events, _, _) = try model(noIdle)
        let workspace = NotificationCenter(), distributed = NotificationCenter()
        events.startSecurityMonitoring(workspace: workspace, distributed: distributed)
        for notification in [NSWorkspace.willSleepNotification, NSWorkspace.screensDidSleepNotification, NSWorkspace.sessionDidResignActiveNotification] {
            events.acceptDesktopSession("event-token", expiry: Date().addingTimeInterval(3600))
            workspace.post(name: notification, object: nil)
            try await waitFor { events.desktopLocked && events.pendingDesktopLocks == 0 }
            try require(events.desktopLocked, "workspace signal locks: " + notification.rawValue)
        }
        events.acceptDesktopSession("event-token", expiry: Date().addingTimeInterval(3600))
        distributed.post(name: .init("com.apple.screenIsLocked"), object: nil)
        try await waitFor { events.desktopLocked && events.pendingDesktopLocks == 0 }
        try require(events.desktopLocked, "screen-lock signal locks")

        let (revealing, revealPath, revealBoard) = try model()
        revealing.acceptDesktopSession("reveal-token", expiry: Date().addingTimeInterval(3600)); revealing.selectedCredential = "item"
        try touch(revealPath, "gate-desktop-reveal")
        let reveal = Task { await revealing.revealCredential("item", copy: true) }
        try await waitFor { FileManager.default.fileExists(atPath: revealPath.appendingPathComponent("desktop-reveal-started").path) }
        revealing.deviceLocked(); try touch(revealPath, "release-desktop-reveal")
        await reveal.value; try await waitFor { revealing.pendingDesktopLocks == 0 }
        try require(revealing.desktopLocked && revealing.visibleSecret == nil && revealBoard.string(forType: .string) == nil, "late secret response cannot reveal or copy")

        var everyTime = defaults; everyTime.passwordInterval = .everyUnlock
        let (loggingIn, loginPath, _) = try model(everyTime)
        try touch(loginPath, "gate-desktop-login")
        let login = Task { await loggingIn.perform(Operation(title: "unlock", detail: "", arguments: ["unlock"]), proof: "synthetic-password") }
        try await waitFor { FileManager.default.fileExists(atPath: loginPath.appendingPathComponent("desktop-login-started").path) }
        loggingIn.deviceLocked(); try touch(loginPath, "release-desktop-login")
        await login.value; try await waitFor { loggingIn.pendingDesktopLocks == 0 }
        try require(loggingIn.desktopLocked && loggingIn.desktopToken == nil, "late login cannot reopen UI")
        try require(calls(loginPath).contains("desktop-lock") && !calls(loginPath).contains("desktop-remember"), "late login token revoked without saving a grant")

        let (mac, macPath, _) = try model()
        var keychainReads = 0
        await mac.unlockWithMac(authenticate: { _ in throw LAError(.userCancel) }, loadRemembered: { _ in keychainReads += 1; return nil })
        try require(mac.desktopLocked && keychainReads == 0 && calls(macPath).isEmpty, "cancelled authentication never reads Keychain or IPC")
        var authenticated = false
        await mac.unlockWithMac(authenticate: { _ in authenticated = true }, loadRemembered: { _ in
            try require(authenticated, "authentication precedes Keychain")
            keychainReads += 1
            return RememberedUnlock(key: String(repeating: "bb", count: 32), expiresAt: Date().addingTimeInterval(3600))
        })
        try require(!mac.desktopLocked && mac.desktopReady && keychainReads == 1, "explicit authenticated resume succeeds")
        mac.lockDesktop(); try await waitFor { mac.pendingDesktopLocks == 0 }

        let (resuming, resumePath, _) = try model()
        try touch(resumePath, "gate-desktop-resume")
        let resume = Task { await resuming.unlockWithMac(authenticate: { _ in }, loadRemembered: { _ in RememberedUnlock(key: "synthetic-key", expiresAt: Date().addingTimeInterval(3600)) }) }
        try await waitFor { FileManager.default.fileExists(atPath: resumePath.appendingPathComponent("desktop-resume-started").path) }
        resuming.deviceLocked(); try touch(resumePath, "release-desktop-resume")
        await resume.value; try await waitFor { resuming.pendingDesktopLocks == 0 }
        try require(resuming.desktopLocked && calls(resumePath).contains("desktop-lock"), "late resumed session revoked")

        let (failed, failPath, _) = try model()
        failed.acceptDesktopSession("failed-token", expiry: Date().addingTimeInterval(3600))
        try touch(failPath, "fail-lock"); failed.lockDesktop()
        try await waitFor { failed.error != nil }
        var authCalls = 0
        await failed.unlockWithMac(authenticate: { _ in authCalls += 1 })
        try require(failed.desktopLocked && failed.pendingDesktopLocks == 1 && authCalls == 0, "unconfirmed revocation blocks another unlock")
        try FileManager.default.removeItem(at: failPath.appendingPathComponent("fail-lock"))
        // Allow the failed attempt's deferred bookkeeping to finish.
        await Task.yield(); failed.retryDesktopLock()
        try await waitFor { failed.pendingDesktopLocks == 0 }
        try require(failed.desktopLocked, "retry confirms revocation without unlocking")

        let (settings, settingsPath, _) = try model()
        settings.acceptDesktopSession("settings-token", expiry: Date().addingTimeInterval(3600))
        var changed = defaults; changed.passwordInterval = .oneDay; changed.idle = .fifteenMinutes
        var deletions = 0
        await settings.saveSecuritySettings(changed, forgetRemembered: { _ in deletions += 1 })
        try require(settings.desktopLocked && settings.securitySettings == changed && deletions == 1, "settings change revokes old grant and locks")
        try require(calls(settingsPath).contains("--forget-remembered"), "settings request durable grant revocation")
        let restarted = AppModel(stateDirectory: settingsPath.path, preferences: preferences, binary: binary)
        try require(restarted.securitySettings == changed && restarted.desktopLocked, "settings persist without unlocking")
        settings.acceptDesktopSession("rejected-token", expiry: Date().addingTimeInterval(3600))
        settings.visibleSecret = "synthetic-visible"
        settings.rejectDesktopSession(UIError(message: "INVALID_UNLOCK_CREDENTIAL"))
        try require(settings.desktopLocked && settings.visibleSecret == nil, "rejected session closes the desktop presentation")
        try await waitFor { settings.pendingDesktopLocks == 0 }

        settings.acceptDesktopSession("save-failed-token", expiry: Date().addingTimeInterval(3600))
        try touch(settingsPath, "fail-lock")
        await settings.saveSecuritySettings(defaults, forgetRemembered: { _ in deletions += 1 })
        try require(settings.desktopLocked && settings.securitySettings == changed && deletions == 1, "failed settings save stays locked and preserves preferences")
        try await waitFor { settings.error?.contains("撤销尚未确认") == true }
        try FileManager.default.removeItem(at: settingsPath.appendingPathComponent("fail-lock"))
        await Task.yield(); settings.retryDesktopLock()
        try await waitFor { settings.pendingDesktopLocks == 0 }
        print("PASS: \(assertions) desktop-lock assertions; no real Keychain, Mac authentication, user clipboard or OS lock/sleep actions")
    }
}
