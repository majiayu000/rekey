# rekey — Project Rules

## What is this

Single-binary Rust MITM proxy that injects API keys for AI agents. Agents never touch real credentials.

## Build

- `cargo check --workspace` after every change
- `cargo test --workspace` before commit
- `cargo fmt --all` before commit

## Architecture

Cargo workspace with 5 crates:
- `rekey-vault` — SQLite + AES-256-GCM encrypted storage
- `rekey-ca` — CA generation + leaf certificate cache
- `rekey-proxy` — MITM proxy + API gateway + TCP tunnel
- `rekey-web` — Embedded web dashboard (rust-embed)
- `rekey-cli` — CLI entry point (clap)

## Key Design Decisions

- Single port (10800) serves proxy + gateway + dashboard
- MITM via CONNECT tunnel + dynamic leaf certs (rcgen)
- Unmatched hosts → pure TCP passthrough (no inspection)
- Master key derived from password via Argon2id, never persisted
- Predefined providers (anthropic, openai, github) auto-generate injection rules

## Spec & Plan

- Design: `docs/superpowers/specs/2026-04-01-rekey-design.md`
- Implementation: `docs/superpowers/plans/2026-04-01-rekey-implementation.md`
