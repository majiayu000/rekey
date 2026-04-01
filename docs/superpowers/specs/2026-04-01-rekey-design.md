# rekey — AI Agent API Key Proxy

> Single-binary, zero-dependency credential proxy for AI agents.
> Agents never touch real API keys.

## Problem

93% of open-source AI agent projects store API keys in plaintext `.env` files. AI agents are non-deterministic — they can leak keys into generated code, commit messages, PR descriptions, or even send them to LLM providers via prompts. Existing solutions (OneCLI, AgentKeys) require PostgreSQL, Node.js, or complex setup.

## Solution

`rekey` is a lightweight MITM HTTP proxy that intercepts agent requests and injects real API keys at the transport layer. The agent only ever sees a placeholder value (`REKEY_PLACEHOLDER`). A single Rust binary handles proxy, API gateway, and web dashboard.

## Architecture

```
                         rekey (single binary)
                    +-----------------------------+
                    |                             |
   agent --CONNECT-->  MITM Proxy (:10800)       |---> api.anthropic.com
                    |    | shared vault           |---> api.openai.com
   agent --GET/POST->  API Gateway (/proxy/*)    |---> ...
                    |    |                        |
   browser -------->  Web UI (/dashboard)        |
                    |    |                        |
                    |  SQLite (vault.db)           |
                    +-----------------------------+
```

Single process, single port, three entry points sharing one SQLite store:

1. **MITM Proxy** — Handles CONNECT tunnels, dynamically generates leaf certificates, intercepts and injects keys
2. **API Gateway** — HTTP routes at `/proxy/{provider}/...`, forwards with key injection (fallback for tools that don't respect `HTTPS_PROXY`)
3. **Web UI** — Embedded static assets at `/dashboard`, manages secrets + shows traffic

## Key Storage

**Database**: `~/.rekey/vault.db` (SQLite)

**Encryption**:
- `rekey init` prompts for master password
- Master password derived to 256-bit key via Argon2id
- Each secret encrypted independently with AES-256-GCM (unique IV + auth tag)
- Master key never persisted to disk; derived on each `rekey start`

**Schema**:

```sql
secrets (
  id          TEXT PRIMARY KEY,
  name        TEXT UNIQUE,         -- "anthropic", "openai", "github"
  provider    TEXT,                -- predefined provider or "generic"
  ciphertext  BLOB,
  iv          BLOB,
  host_pattern TEXT,               -- "api.anthropic.com", "*.openai.com"
  created_at  INTEGER,
  updated_at  INTEGER
)

injection_rules (
  id          TEXT PRIMARY KEY,
  secret_id   TEXT REFERENCES secrets(id),
  header_name TEXT,                -- "x-api-key", "authorization"
  value_format TEXT,               -- "{value}" or "Bearer {value}"
  path_pattern TEXT,               -- "/v1/*" or "*"
  method      TEXT                 -- "*" or "POST"
)

audit_log (
  id          INTEGER PRIMARY KEY,
  timestamp   INTEGER,
  secret_name TEXT,
  target_host TEXT,
  target_path TEXT,
  status_code INTEGER,
  latency_ms  INTEGER,
  source      TEXT                 -- "proxy" or "gateway"
)
```

**Predefined providers** auto-generate injection rules:

| Provider | host_pattern | header | format |
|----------|-------------|--------|--------|
| anthropic | api.anthropic.com | x-api-key | {value} |
| openai | api.openai.com | authorization | Bearer {value} |
| github | api.github.com | authorization | Bearer {value} |

## MITM Proxy Flow

### Initialization (`rekey init`)

1. User sets master password
2. Argon2id derives master key
3. Creates `~/.rekey/vault.db`
4. Generates CA key pair (`~/.rekey/ca.key`, `~/.rekey/ca.pem`), ECDSA P-256, 10-year validity
5. Installs CA to system trust store (macOS: `security add-trusted-cert`, Linux: `update-ca-certificates`)

### Request Flow

1. Agent sends `CONNECT api.anthropic.com:443`
2. rekey extracts hostname from request
3. Queries SQLite: host_pattern matches `api.anthropic.com` → finds secret + injection_rule
4. **Match found → MITM mode**:
   a. Replies `200 OK`
   b. Generates leaf certificate for `api.anthropic.com` via rcgen (CA-signed, 24h cached)
   c. Completes TLS handshake with agent using leaf cert
   d. Reads plaintext request
   e. Decrypts secret (AES-256-GCM)
   f. Injects header per injection_rule (replaces FAKE_KEY → real key)
   g. Forwards to real target via reqwest
   h. Streams response back (SSE-compatible)
   i. Writes audit log
5. **No match → pure TCP tunnel** (transparent passthrough, no MITM, no logging)

### API Gateway Mode (fallback entry)

```
agent → POST http://localhost:10800/proxy/anthropic/v1/messages
```

1. Extracts provider from path
2. Queries SQLite for secret + target host
3. Injects key into header
4. Forwards to `https://api.anthropic.com/v1/messages`
5. Streams response back

## CLI Commands

```bash
# Initialize
rekey init                          # Set password + generate CA + install + create vault

# Secret management
rekey add anthropic sk-ant-xxx      # Predefined provider, auto injection rules
rekey add openai sk-proj-xxx
rekey add generic myapi --host api.example.com --header x-api-key
rekey list                          # List secrets (names only, no values)
rekey remove anthropic
rekey rotate anthropic sk-ant-new   # Replace secret value

# Service
rekey start                         # Enter password → start proxy (foreground)
rekey start -d                      # Daemon mode (background)
rekey stop
rekey status                        # Running state + port + request count

# Dashboard
rekey dashboard                     # Open browser to Web UI

# Helper
rekey env                           # Output env vars for agent configuration
  # export HTTPS_PROXY=http://localhost:10800
  # export HTTP_PROXY=http://localhost:10800
  # export ANTHROPIC_API_KEY=REKEY_PLACEHOLDER
  # export OPENAI_API_KEY=REKEY_PLACEHOLDER

# Cleanup
rekey destroy                       # Remove CA from trust store + delete all data
```

## Web Dashboard

Embedded in binary via `rust-embed`. Accessible at `http://localhost:10800/dashboard`.

### Pages

**Secrets Management**
- Secret list (name, provider, host_pattern, created_at)
- Add / edit / delete
- Values always masked (`sk-ant-****`), never exposed in UI

**Traffic Monitor**
- Real-time request stream (timestamp, host, path, secret used, status code, latency)
- Stats panel: today's requests, distribution by provider, error rate
- No request/response body logging (security)

**Audit Log**
- Reverse-chronological key usage records
- Filter by provider / time range
- Export JSON

### Tech

- Frontend: static HTML + vanilla JS (or Alpine.js), zero Node.js
- Backend API: axum routes (`/api/secrets`, `/api/audit`, `/api/stats`)
- Real-time: SSE push to frontend

## Security Model

### Protection Layers

| Layer | Threat | Defense |
|-------|--------|---------|
| Storage | Disk read | AES-256-GCM, master key not on disk |
| Memory | Process dump | `secrecy::Secret<String>`, zero-fill on Drop |
| Transport | Agent sees key | MITM proxy injection, agent only holds FAKE_KEY |
| Output | Key leaks to code | Agent never contacts real value, nothing to leak |
| Dashboard | Unauthorized access | localhost only, optional basic auth |

### Unmatched Request Handling

Requests to hosts not in the secret table → pure TCP tunnel passthrough. No MITM, no decryption, no logging. rekey is not a traffic monitor — it only intercepts configured targets.

### CA Security

- CA private key file permission `0o600` (owner-only)
- Leaf certs dynamically generated, 24h expiry, in-memory cache
- `rekey destroy`: removes CA from trust store + deletes vault.db

### Explicit Non-Goals (v1)

- No request/response body logging
- No remote access (127.0.0.1 only)
- No multi-user / multi-agent auth (single-user tool)

## Crate Structure

```
rekey/
├── Cargo.toml              # workspace
├── crates/
│   ├── rekey-cli/          # CLI entry, clap command parsing
│   ├── rekey-proxy/        # MITM proxy + API gateway core
│   ├── rekey-vault/        # SQLite + encrypted storage
│   ├── rekey-ca/           # CA generation + leaf cert management
│   └── rekey-web/          # Embedded Web UI + API routes
```

### Dependencies

| Purpose | Crate |
|---------|-------|
| CLI | clap |
| HTTP server | axum + hyper |
| TLS | rustls + tokio-rustls |
| Certificate generation | rcgen |
| HTTP client (forwarding) | reqwest (rustls backend) |
| SQLite | rusqlite |
| Encryption | aes-gcm + argon2 |
| Memory protection | secrecy |
| Static asset embedding | rust-embed |
| Async runtime | tokio |

**Build output**: single binary `rekey`, ~10-15MB.

## Differentiation vs OneCLI

| | OneCLI | rekey |
|---|---|---|
| Install | Docker Compose or 3 manual services | `cargo install rekey` |
| Storage | PostgreSQL | SQLite single file |
| Dashboard | Separate Next.js process | Embedded in binary |
| Config | Web panel click-through | CLI-first: `rekey add anthropic sk-xxx` |
| Setup | Create Account → Agent → Secret → Assign | `rekey init && rekey add anthropic sk-xxx && rekey start` |
| Target users | Teams / enterprise | Individual devs + small teams |

**One-liner**: OneCLI's lightweight alternative — single binary, zero deps, 30-second setup.
