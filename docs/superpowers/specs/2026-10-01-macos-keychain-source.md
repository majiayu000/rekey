# EXT-06: one macOS file-Keychain generic-password source

Frozen 2026-10-01 before code. Minimal accepted slice: one encrypted exact
reference and native lookup inside the sole Authority Worker. Two new source
modules maximum (reference/native adapter and its focused private test seam),
existing typed kind/AAD/schema/IPC/CLI/connector/executor changes. No daemon,
platform plugin, shell helper, generic provider registry or extra config mode.
One SDK-backed constant binding fills the cached framework wrapper omission;
no handwritten ABI guesses, private value strings or native-library replacement.

## Closed reference and formats
Assign MacosKeychainSource kind/AAD tag10, current format20, protected typed rotate
opcode49. All older nonempty state and backups are rejected, no migrations.
Retain binary AAD84. Existing add mechanism and new typed CLI add/rotate commands
carry proof and whole reference only in protected frame bodies/explicit stdin.
No real value, password or arbitrary Keychain attribute in argv/env/metadata/logs.
CLI remains pure IPC, no crypto/SQLite/native dependency.

Exact marker macos-keychain-source-v1 and required fields keychain_path, service,
account, reference_expires_at_ms. No unknown/duplicate/null fields or aliases.
Path is an explicit absolute UTF8 file-Keychain path, not ambient login/default
search list; service/account are exact nonempty strings without NUL/control,
not patterns. Reject reserved com.starlight.rekey.remembered-unlock service.
Expiry is a future checked Unix-ms timestamp under existing timestamp limits,
not an OS item TTL. Validate once at Authority import/rotate boundary; encrypted
reference is immutable per credential version. Native item replacement and
service ownership are administrator responsibilities. No read/scan at import.

## Execution and secrecy boundary
Generic prepare_credential must refuse this source kind, since GitHub webhook
uses it before kind checking. Introduce an internal execution-only prepare path
for the broker after committed execution.started. Native preparation requires
an actual persisted execution.started row for admitted request/credential/Action
identity, and no terminal completion for that request. Do not add an Agent API
or public source-value method. Existing eligibility/revocation/versions/seals
remain; plain fixed-header credentials retain their current preparation behavior.

Worker decrypts only reference then emits safe source-start audit before native
query, with actual credential ID/version and reference digest only. The native
result is immediately held in wipe-on-drop bytes, result audit commits before
PreparedCredential escapes; audit failure faults/closes result. Return consume-once
PreparedCredential keeping source kind and actual version; broker injects value
into existing fixed target and uses the same full value/prefix/header/body/decoded
sealing. Never persist native value or return it through Agent/Admin IPC.
Known source failure maps to existing safe CREDENTIAL_UNAVAILABLE; no OS error
text/Debug/attributes. Reject zero/multiple/wrong-type, empty, oversized or unsafe
header value and protect all copied bytes on failure. Apple immutable CFData is
released per ownership; do not promise erasure of OS/library internal buffers.

Use cached Security/CoreFoundation APIs: open exactly specified file Keychain,
SecItemCopyMatching class generic-password, search-list exactly that one item,
exact service/account, case-insensitive=false, numeric match-limit2, data only,
kSecUseAuthenticationUIFail. SDK SecItem.h documents exported CFStringRef and
Security.tbd exports it; one cfg(macos) official extern constant is allowed.
No Skip, ambient search, interaction fallback, OS item enumeration or shell
security output. API requiring UI fails rather than hiding protected matches.
All statuses deny; actual identity/locked/denied/duplicate behavior needs field
validation. Non-macOS native source execution fails unavailable.

Check supplied original execution deadline before/after native call and audits,
and reference expiry before/after. Late result never starts business or resets
capability/Action time. Synchronous Worker owns native call; timeout of awaiting
Broker does not cancel it. No hard realtime native-syscall guarantee or thread
kill workaround. Lock/fault still deny eventual result through existing lifecycle.

## Verification and boundaries
Private Worker construction fixture provider, cfg(test) only, no production mode
or global mutable provider. Pure query/status/value/reference cases; real Actor/
SQLite prove unstarted/terminal/revoked/locked/expired requests do not query, admitted
request queries once, no persistent plaintext, actual identity/version audit and
audit failure closes result, late provider value denies. Broker fake transport
proves injected value and all existing reflected sealing paths; these fixtures
do not exercise actual Keychain. Native adapter/query construction compile/link
against SDK without invoking item APIs. Current full workspace/TLS/UDS/TTY and
actual item creation/deletion/application signing remain unpassed/deferred.
Run locked offline checks, focused tests, Clippy/fmt/mechanical/CLI dependency gate,
independent final actual-source SHA review. No commit/publish or real Keychain use.
