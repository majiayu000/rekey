# rekey

AI agent API key proxy — single binary, zero dependencies, 30-second setup.

Agents never touch your real API keys. rekey intercepts HTTPS requests via MITM proxy and injects credentials at the transport layer.

## Install

```bash
cargo install rekey
```

## Quick Start

```bash
rekey init                          # Set password, generate CA
rekey add anthropic sk-ant-xxx      # Add your API key
rekey add openai sk-proj-xxx        # Add another
rekey start                         # Start proxy on :10800

# In your agent's terminal:
eval $(rekey env)                   # Set proxy + placeholder keys
```

## How It Works

1. Agent sends requests through `HTTPS_PROXY=localhost:10800`
2. Agent uses placeholder API keys (`REKEY_PLACEHOLDER`)
3. rekey intercepts via MITM, replaces placeholders with real keys
4. Real keys never enter the agent's process memory

## Architecture

```
Agent ──CONNECT──▶ rekey:10800
                      │
                      ├─ matched host? ──▶ MITM: TLS terminate, inject key, forward
                      └─ unmatched?    ──▶ TCP passthrough (no inspection)
```

- **Vault**: SQLite + AES-256-GCM encrypted storage, Argon2id key derivation
- **CA**: Auto-generated local CA with per-host leaf cert cache (DashMap)
- **Proxy**: CONNECT tunnel routing, header injection, audit logging
- **Gateway**: REST API mode at `/proxy/{provider}/{path}`
- **Dashboard**: Embedded web UI at `/dashboard`
  - REST: `/api/secrets`, `/api/audit`, `/api/stats`
  - SSE: `/api/traffic/stream`

## Commands

| Command | Description |
|---------|-------------|
| `rekey init` | Set master password, generate CA, create vault |
| `rekey add <name> <key>` | Add an API key (auto-detects known providers) |
| `rekey list` | List configured secrets |
| `rekey remove <name>` | Remove a secret |
| `rekey rotate <name> <key>` | Rotate a secret value |
| `rekey start` | Start the proxy server |
| `rekey stop` | Stop the daemonized proxy |
| `rekey status` | Show running status, pid, port, uptime, request count |
| `rekey env` | Print shell exports for agent configuration |
| `rekey dashboard` | Open web dashboard in browser |
| `rekey destroy` | Remove all rekey data and CA from system |

Runtime state is stored at `~/.rekey/runtime.json` and `~/.rekey/rekey.pid`.

## Supported Providers

| Provider | Host | Header |
|----------|------|--------|
| Anthropic | `api.anthropic.com` | `x-api-key: {value}` |
| OpenAI | `api.openai.com` | `Authorization: Bearer {value}` |
| GitHub | `api.github.com` | `Authorization: Bearer {value}` |
| Custom | `--host <host>` | `--header <name>` |

## License

MIT
