# Continuous fuzzing

Nine libFuzzer targets cover IPC frame/body decoding (`ipc`), Action
normalization (`action`), typed policy parsing (`policy`), production response
sealing (`response_sealing`), offline backup/restore admission (`restore`),
the signed Connection rule path matcher (`connection_rules`), the dotenv
preview parser (`dotenv`), complete-value secret scanning (`secret_scan`), and
the SSH agent wire parser (`ssh_agent`). Each target has its own committed seed
corpus under `fuzz/corpus/<target>/`; every seed is synthetic and contains no
credential.
The IPC harness exercises both arbitrary decoders and constructed valid
frames/bodies on every input. Action and policy corpora include valid aggregate
definitions. Restore decodes one committed initialized-vault snapshot, then
applies input-driven byte changes, truncation, or extension; the fixed bytes
make crash replay and minimization deterministic, while separate seeds prove
both password and recovery-key restore paths. Failed restores assert that no
installed, staging, sidecar, or incomplete-marker artifact remains, and a
failure seed proves same-directory retry. Response sealing asserts that every
supported raw or encoded credential and full authorization reflection is
detected in bodies, header values, and header names, and that unrelated
responses are not rejected.

The `connection_rules` input is `<rule pattern>\0<request path>` (without a NUL
byte the text is both); it asserts that a caller override can only tighten the
signed decision. Its seeds cover exact, `*`, `{capture}` and trailing `**`
patterns, the 100-byte segment limit, and rejected inner `**`, dot and empty
segments. `dotenv` seeds cover supported quoting, `export` and comments, every
unsupported form that must be reported (missing `=`, invalid names, empty,
interpolated, escaped, unterminated, trailing text, duplicates), CRLF and
invalid UTF-8. `secret_scan` treats the first half of the input as the value
and the second half as the scanned bytes; seeds cover a raw and a JSON-escaped
match, the percent-escape projection, an unrelated pair, one byte and binary
input. `ssh_agent` seeds are built from fixed synthetic Ed25519 and P-256 keys
(public halves and signatures only): valid Ed25519 and ECDSA
`session-bind@openssh.com`, a rejected forwarded bind, user-authentication and
host-bound sign requests, a Git `SSHSIG` request, `REQUEST_IDENTITIES`, a
length overflow, a bare key blob and a leading-zero scalar.

CI runs 2,000 inputs for pull requests and relevant pushes. The Monday schedule
runs for 15 minutes. Both modes cap inputs at 64 KiB, each unit at 10 seconds,
and RSS at 2 GiB so a hang or resource-bound violation fails clearly.
The fuzz lock starts from the production lock and adds only fuzz-only packages;
root `Cargo.lock` changes trigger these jobs; the IPC lane compares both
resolved graphs and fails when any shared fuzz package version is absent from
the shipped graph.

Run the same smoke locally for each target:

```bash
cargo install cargo-fuzz --locked --version 0.13.2
for target in ipc action policy response_sealing restore \
    connection_rules dotenv secret_scan ssh_agent; do
  cargo +nightly-2026-09-01 fuzz run "$target" -- \
    -runs=2000 -max_len=65536 -timeout=10 -rss_limit_mb=2048
done
```

`cargo fuzz run TARGET` adds every new interesting input to
`fuzz/corpus/TARGET/`. To replay only the committed seeds without changing
them, name a scratch corpus first and the seed directory second:

```bash
mkdir -p /tmp/rekey-fuzz/TARGET
cargo +nightly-2026-09-01 fuzz run TARGET /tmp/rekey-fuzz/TARGET \
  fuzz/corpus/TARGET -- -runs=0
```

Add a seed only when it reaches a boundary the existing seeds miss, and keep
it synthetic. Seeds are exact bytes: `fuzz/.gitattributes` turns off
end-of-line conversion and whitespace checks under `fuzz/corpus/`.

For a crash, preserve the generated artifact before changing code, minimize it,
and reproduce it against the exact commit:

```bash
cargo +nightly-2026-09-01 fuzz tmin TARGET fuzz/artifacts/TARGET/CRASH
cargo +nightly-2026-09-01 fuzz run TARGET fuzz/artifacts/TARGET/CRASH
```

Copy the minimized input into the corpus and add a stable unit or integration
regression test for the affected boundary. A crash is closed only after that
test and the fuzz target both pass. Corpus inputs must never contain production
credentials or other secrets.
