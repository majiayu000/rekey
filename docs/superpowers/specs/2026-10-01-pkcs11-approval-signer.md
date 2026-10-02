# Fixed PKCS#11 Ed25519 approval signer

Status: selected minimal EXT05 implementation contract, frozen before code. This supplements the existing independent operator approval signer. It does not expose signing or private keys through the Broker, Agent API or credential store. Physical HSM acceptance remains required.

## Identity and review

Add only `--pkcs11-profile PRIVATE.json` to the existing review/sign modes, mutually exclusive with key-file and Transit. A bounded 64 KiB current-user-owned regular 0600 file with no symlink or extra hard links contains a fixed record type, absolute canonical library path, SHA-256 of its pinned regular file, expected library version, exact slot ID and token serial, bounded nonempty hexadecimal key ID, and a 32-byte Ed25519 public key. No PIN is stored in the profile. Unknown fields and unsupported profiles fail closed.

The public identity participates in the existing reviewed digest and must match the signed policy approver key. Review performs no module load, token access or PIN request. Sign validates the reviewed digest before any of those effects. Recheck library identity before loading; trusted native code can still act with operator privileges, so this is the G1 operator trust boundary, not hostile-library containment.

## Fixed hardware operation

Use the normal, exact `cryptoki = 0.12.1` registry dependency and its cryptoki-sys 0.5.0 SDK. This patch closes [RUSTSEC-2026-0286](https://rustsec.org/advisories/RUSTSEC-2026-0286), an out-of-bounds read in allowed-mechanism attribute decoding; do not suppress the advisory. No handwritten PKCS#11 ABI or vendored SDK. The selected pure operation is `Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Ed25519))`, without prehash or context. Sign exactly the existing RKAPPROVAL domain prefix and JCS grant bytes. One sign attempt; never retry an ambiguous hardware operation or fall back to software.

Match the exact slot, serial and library version. Enumerate at most two matching private signing objects by class, Edwards key type and exact ID; require exactly one. Require token/private/sign/sensitive/always-sensitive/never-extractable properties and non-extractable key, exact supported Ed25519 curve parameters; reject always-authenticate and protected-authentication-path profiles in this slice. Never request a private-key value. Validate the returned signature length and verify it with the policy public key locally. Recheck grant and policy expiration before writing the existing create-new protected output.

## PIN and blocking native calls

Prompt only through the operator controlling `/dev/tty`, with echo disabled before input. PIN never appears in argv, environment, profile, metadata, logs, audit or arbitrary stdin. Use zeroizing memory, bounded UTF-8 input of at most 128 bytes, and a deadline bounded by the grant expiration. Restore TTY attributes on ordinary errors, timeout and handled interruption; inability to establish or restore the trusted TTY is a failure. No credential cache.

Execute native library calls in a private self-exec child of this existing binary. No additional public binary, provider abstraction or long-lived service. An inherited private bounded frame transports PIN, message and validated public profile only in the body; an internal child mode is not a public PIN injection interface. The child joins a fresh process group, raw stdout/stderr is suppressed, and a parent guard sends process-group kill on errors, cancellation or a maximum ten-second budget bounded by grant expiration. Reaping must use nonblocking checks along that original deadline, never an unconditional wait; an unreaped child or device operation remains uncertain and cannot produce a grant. OS scheduling or uninterruptible driver calls are outside an application hard wall-clock guarantee. Child success returns only a fixed bounded status/signature frame. Malformed, late, failed or interrupted results never create a grant. Terminating the process cannot prove cancellation of a submitted device operation; report uncertainty and do not retry.

## Tests and evidence

Meaningful local tests cover private profile validation and digest binding, wrong policy public key, no effect before review agreement, bounded object selection and key restrictions, signature verification, deadlines, malformed child results, protected output, and TTY failures/restoration where the host permits PTY operations. Pure or injected contracts do not count as actual token tests. A real software-token/HSM module, exact mechanism support and physical device behavior need separately recorded evidence; absence remains unvalidated, not skipped PASS. No global installs, real credentials or native Keychain calls.

## Review fixes selected before repair

The final signal-handler restoration boundary must recheck the same deadline and handled-interruption flag before a successful result can reach protected grant publication. A signal caught between the previous check and restoration must reject success. Ordinary tests of immediately killable children do not prove uninterruptible hardware recovery; deterministic budget/cancellation contract tests and actual normal-child cleanup are separate evidence.
