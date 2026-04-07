# rekey

Universal credential proxy & requester — single binary, zero dependencies, 30-second setup.

Clients never touch your real credentials directly. rekey intercepts HTTPS requests via MITM proxy and injects secrets at the transport layer, or sends authenticated requests via CLI.

## Install

```bash
cargo install rekey
```

## Quick Start

```bash
rekey init                          # Set password, generate CA
rekey add anthropic sk-ant-xxx      # Add a predefined provider key
rekey add internal-api s3cr3t --host api.example.com --header x-api-key
rekey start                         # Start proxy on :10800

# In your client/tool terminal:
eval $(rekey env)                   # Set proxy + placeholder keys
```

## How It Works

1. Client sends requests through `HTTPS_PROXY=localhost:10800`
2. Client uses placeholder env vars (`REKEY_PLACEHOLDER`)
3. rekey intercepts via MITM, replaces placeholders with real keys
4. Real secrets never enter the client process memory as plaintext env vars

## Architecture

```
Client ──CONNECT──▶ rekey:10800
                      │
                      ├─ matched host? ──▶ MITM: TLS terminate, inject key, forward
                      └─ unmatched?    ──▶ TCP passthrough (no inspection)
```

- **Vault**: SQLite + AES-256-GCM encrypted storage, Argon2id key derivation
- **CA**: Auto-generated local CA with per-host leaf cert cache (DashMap)
- **Proxy**: CONNECT tunnel routing, header injection, audit logging
- **Gateway**: REST API mode at `/proxy/{provider}/{path}` for predefined providers
- **Requester**: `rekey request` for direct authenticated calls (basic/bearer/api-key/custom)
- **Dashboard**: Embedded web UI at `/dashboard`
  - REST: `/api/secrets`, `/api/audit`, `/api/stats`
  - SSE: `/api/traffic/stream`

## Commands

| Command | Description |
|---------|-------------|
| `rekey init` | Set master password, generate CA, create vault |
| `rekey add <name> <key>` | Add a single-value secret (auto-detects known providers) |
| `rekey store <name>` | Store multi-field credentials (`api-key` / `basic` / `bearer` / `custom`) |
| `rekey request <name> <url>` | Send an authenticated HTTP request using stored credentials |
| `rekey list` | List configured secrets |
| `rekey remove <name>` | Remove a secret |
| `rekey rotate <name> <key>` | Rotate a secret value |
| `rekey start` | Start the proxy server |
| `rekey stop` | Stop the daemonized proxy |
| `rekey status` | Show running status, pid, port, uptime, request count |
| `rekey env` | Print shell exports for client/tool configuration |
| `rekey dashboard` | Open web dashboard in browser |
| `rekey destroy` | Remove all rekey data and CA from system |

Runtime state is stored at `~/.rekey/runtime.json` and `~/.rekey/rekey.pid`.

## Built-in Provider Presets

| Provider | Host | Header |
|----------|------|--------|
| Anthropic | `api.anthropic.com` | `x-api-key: {value}` |
| OpenAI | `api.openai.com` | `Authorization: Bearer {value}` |
| GitHub | `api.github.com` | `Authorization: Bearer {value}` |
| Custom | `--host <host>` | `--header <name>` |

rekey is not limited to these presets. Use:
- `rekey add <name> <value> --host <host> --header <header>` for arbitrary host+header injection.
- `rekey store` + `rekey request` for services that use basic auth, bearer tokens, or custom multi-header credentials.

## License

MIT
