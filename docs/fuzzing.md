# Continuous fuzzing

Five libFuzzer targets cover IPC frame/body decoding (`ipc`), Action
normalization (`action`), typed policy parsing (`policy`), production response
sealing (`response_sealing`), and offline backup/restore admission (`restore`).
Each target has its own seed corpus under `fuzz/corpus/<target>/`.

CI runs 2,000 inputs for pull requests and relevant pushes. The Monday schedule
runs for 15 minutes. Both modes cap inputs at 64 KiB, each unit at 10 seconds,
and RSS at 2 GiB so a hang or resource-bound violation fails clearly.

Run the same smoke locally for each target:

```bash
cargo install cargo-fuzz --locked --version 0.13.2
for target in ipc action policy response_sealing restore; do
  cargo +nightly-2026-09-01 fuzz run "$target" -- \
    -runs=2000 -max_len=65536 -timeout=10 -rss_limit_mb=2048
done
```

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
