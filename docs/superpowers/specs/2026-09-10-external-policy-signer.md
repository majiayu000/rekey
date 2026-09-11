# External operator policy signer (POL-08)

Status: implemented scope; secret-handling implementation requires human review before production use.

`rekey-policy-sign` is a standalone Unix operator executable hosted in the existing
policy package. The policy library remains free of IO and the agent-facing `rekey`
CLI does not link the signer or its cryptography. Run it in the operator's external
trust domain, never in an agent container or the Broker's service account.

The operator supplies an existing Ed25519 private key as DER PKCS#8 in a regular,
current-user-owned file with no group/other permissions. The executable opens it
without following a final symlink, validates the opened descriptor before reading,
bounds the read, and zeroizes the DER buffer. It accepts a path, never key bytes,
in arguments. No key generation, persistence, environment transport, secret
printing, online admin calls, or policy activation is provided. File mode checks
are POSIX checks; operators must independently control ACLs, parent directories,
backups and who can run processes in their trust domain.

1. `rekey-policy-sign review DRAFT.json` validates the existing typed snapshot,
   rejects duplicate keys, unknown fields and expired policies, and prints the
   complete validated snapshot plus its RFC 8785 canonical SHA-256 digest as JSON.
   Review all rules, bindings, identities, version and expiry, then retain the digest.
2. `rekey-policy-sign sign DRAFT.json --reviewed-sha256 DIGEST --signer-id UUID
   --key-file KEY.der --output NEW_DIRECTORY` revalidates and compares the canonical
   snapshot digest before opening the private key. The explicit digest binds the
   signed content to the reviewed snapshot; it is not proof of human approval.
   Any semantic draft change requires a new review. Whitespace changes do not.
3. Sign the RFC 8785 unsigned envelope with the existing `RKPOLICY\0\x01` domain
   prefix. Derive the public trust file from the supplied key and signer UUID.
   Verify the resulting bundle using the existing production verifier before
   writing anything. Create NEW_DIRECTORY exclusively (0700), then `trust.json`
   and `policy.json` exclusively (0600). Never replace an existing directory/file.
   A filesystem error may leave an incomplete new directory; report failure and
   do not use its contents. No auto-cleanup removes operator files.
4. The operator separately reviews/imports `trust.json` with `rekey policy trust
   install`, then `policy.json` with `rekey policy activate`, using existing admin
   step-up proofs. The signer never contacts Broker or Agent, changes active policy,
   or makes a policy version decision for the operator.

The existing test-only Python signer remains test-only. This tool provides no
approver signer, remote KMS adapter, rollover workflow, or managed signing service.
