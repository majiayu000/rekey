import Foundation

@main
struct KeychainContract {
    static func main() throws {
        if CommandLine.arguments.count == 2 {
            guard let record = try RememberedUnlock.load(CommandLine.arguments[1]),
                  record.key == String(repeating: "ab", count: 32) else {
                throw UIError(message: "Keychain did not survive process restart")
            }
            return
        }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("rekey-keychain-test-" + UUID().uuidString).path
        defer {
            do { try RememberedUnlock.forget(directory) }
            catch { fputs("Keychain test cleanup failed\n", stderr) }
        }
        try RememberedUnlock(key: String(repeating: "ab", count: 32), expiresAt: Date().addingTimeInterval(60)).save(directory)
        let child = Process()
        child.executableURL = URL(fileURLWithPath: CommandLine.arguments[0])
        child.arguments = [directory]
        try child.run(); child.waitUntilExit()
        guard child.terminationStatus == 0 else { throw UIError(message: "Keychain child failed") }
        try RememberedUnlock(key: String(repeating: "ab", count: 32), expiresAt: Date.distantPast).save(directory)
        guard try RememberedUnlock.load(directory) == nil else { throw UIError(message: "Expired Keychain entry was accepted") }
        guard try RememberedUnlock.load(directory) == nil else { throw UIError(message: "Expired Keychain entry was not deleted") }
        print("PASS: Keychain survives process restart; expired entries are deleted")
    }
}
