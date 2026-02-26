# apes — Privilege Elevation via OpenApe Grants

`apes` is a setuid-root binary that replaces traditional `sudo` with a grant-based approval workflow. Instead of a password, each privileged command requires real-time approval from an admin through an [OpenApe](https://docs.openape.at) Identity Provider (IdP).

```
User runs:  apes -- systemctl restart nginx
                │
                ▼
         ┌─────────────┐     challenge/response     ┌────────────────┐
         │  apes agent  │ ◄─────────────────────────►│  OpenApe IdP   │
         │  (setuid)    │ ── create grant ──────────►│  (nuxt-grants) │
         │              │ ── poll status ───────────►│                │
         │              │ ◄── approved + JWT ────────│                │
         └──────┬───────┘                            └───────┬────────┘
                │ verify JWT, elevate, exec                  │
                ▼                                     Admin approves
         Command runs as root                         in browser UI
```

**Key properties:**

- Ed25519 challenge-response authentication (no passwords stored)
- Every command is individually approved or denied by an admin
- JWT-based authorization with cmd_hash integrity check
- Privileges are dropped for all network I/O, re-elevated only after verification
- Environment is sanitized before exec (LD_PRELOAD, PATH, etc.)
- Full audit log in JSONL format

## Prerequisites

- **Rust toolchain** (stable, 1.70+) — install via [rustup](https://rustup.rs)
- **A running OpenApe IdP** with the `nuxt-grants` module — see [docs.openape.at](https://docs.openape.at)
- **Linux** (setuid + execvp; macOS works for development but is not recommended for production)

## Build

```bash
cargo build --release
```

The binary is at `target/release/apes`.

## Install

```bash
sudo make install
```

This installs `apes` to `/usr/local/bin/apes` with the setuid bit set (`mode 4755`, owner `root`). The setuid bit is required so that `apes` can elevate privileges after grant approval.

To install to a different prefix:

```bash
sudo make install PREFIX=/opt
```

### Manual install (without Make)

```bash
sudo install -m 4755 -o root target/release/apes /usr/local/bin/apes
```

## Enrollment

Enrollment registers this machine as an agent with your OpenApe IdP. Run this once per machine:

```bash
sudo apes enroll --server https://id.example.com --agent-email server01@example.com
```

The `--agent-email` is used as the agent's identifier on the IdP. Optionally pass `--agent-name` to set a display name (defaults to the machine's hostname).

### What happens

1. `apes` generates an Ed25519 keypair and writes it to `/etc/apes/agent.key`
2. A `config.toml` is written to `/etc/apes/config.toml` with the server URL, a new agent UUID, and the key path
3. The output includes an enrollment URL:

```
  Agent enrolled locally.

  Agent ID:    a1b2c3d4-...
  Agent Name:  server01
  Config:      /etc/apes/config.toml
  Key:         /etc/apes/agent.key
  Public Key:  ssh-ed25519 AAAA...

  Share this URL with your admin to complete enrollment:
  https://id.example.com/enroll?email=server01@example.com&name=server01&key=ssh-ed25519%20AAAA...&id=a1b2c3d4-...

  The agent is ready to use once the admin approves.
```

4. Copy the enrollment URL and open it in a browser
5. An admin logs into the IdP and confirms the agent
6. The agent is now active and can request grants

## Usage

Run any command with privilege elevation:

```bash
apes -- systemctl restart nginx
```

With a reason (visible to the admin in the approval UI):

```bash
apes --reason "deploy v2.1" -- systemctl restart app
```

Override the poll timeout (in seconds):

```bash
apes --timeout 60 -- apt update
```

Use a custom config file:

```bash
apes --config /path/to/config.toml -- whoami
```

### What happens when you run a command

1. `apes` loads the config and signing key (as root)
2. Computes a SHA-256 hash of the command
3. **Drops privileges** to the real user's UID
4. Authenticates with the IdP via Ed25519 challenge-response
5. Creates a grant request (includes command, cmd_hash, target, optional reason)
6. Polls the IdP for approval:
   ```
   ⏳ Waiting for approval… (grant a1b2c3d4)
      Approve at: id.example.com
   ```
7. On approval: receives a JWT containing the cmd_hash
8. Verifies the JWT locally and checks that the cmd_hash matches
9. **Re-elevates** to root
10. Sanitizes the environment (removes `LD_PRELOAD`, `LD_LIBRARY_PATH`, etc.; resets `PATH`)
11. Writes an audit log entry
12. Replaces the process with the command via `execvp`

If denied: `apes` prints `Denied by <admin>` and exits with code 3.
If no response within the timeout: prints `Timed out after <N>s` and exits with code 4.

## Configuration Reference

After enrollment, the config lives at `/etc/apes/config.toml` (permissions `0600`, owned by root).

```toml
# Required
server_url = "https://id.example.com"
agent_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
key_path = "/etc/apes/agent.key"

# Optional — override hostname as the target identifier
# target = "server01"

# Optional — custom audit log path (default: /var/log/apes/audit.log)
# audit_log = "/var/log/apes/audit.log"

[poll]
# How often to check for grant approval (default: 2)
interval_secs = 2
# Maximum time to wait for approval (default: 300)
timeout_secs = 300

[tls]
# Custom CA bundle for self-signed certificates
# ca_bundle = "/etc/apes/ca.pem"
```

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `server_url` | yes | — | OpenApe IdP base URL |
| `agent_id` | yes | — | Agent UUID (set during enrollment) |
| `key_path` | yes | — | Path to Ed25519 private key |
| `target` | no | hostname | Machine identifier shown in grant requests |
| `audit_log` | no | `/var/log/apes/audit.log` | Path to the JSONL audit log |
| `poll.interval_secs` | no | `2` | Poll interval in seconds |
| `poll.timeout_secs` | no | `300` | Poll timeout in seconds (5 minutes) |
| `tls.ca_bundle` | no | system default | Custom CA bundle path |

## Connecting to a Local vs Remote IdP

For **development**, point at your local instance:

```bash
sudo apes enroll --server http://localhost:3000 --agent-email dev@localhost
```

For **production**, use the HTTPS URL of your IdP:

```bash
sudo apes enroll --server https://id.example.com --agent-email server01@example.com
```

If your IdP uses a **self-signed certificate**, add the CA bundle to the config after enrollment:

```toml
[tls]
ca_bundle = "/etc/apes/ca.pem"
```

For IdP setup instructions, see [docs.openape.at](https://docs.openape.at).

## Audit Log

Every command execution, denial, timeout, and error is logged in JSONL format. Default location: `/var/log/apes/audit.log` (configurable via `audit_log` in config).

The directory is created automatically if it doesn't exist. The log is append-only. If writing fails, a warning is printed to stderr but the command still runs.

### Event types

**`run`** — command approved and executed:
```json
{"ts":"2026-01-15T10:30:00Z","event":"run","real_uid":1000,"command":["systemctl","restart","nginx"],"cmd_hash":"ab12...","grant_id":"...","grant_type":"once","agent_id":"...","decided_by":"admin@example.com","target":"server01","cwd":"/home/user"}
```

**`denied`** — grant denied by admin:
```json
{"ts":"...","event":"denied","real_uid":1000,"command":["rm","-rf","/"],"cmd_hash":"...","grant_id":"...","agent_id":"...","decided_by":"admin@example.com","target":"server01"}
```

**`timeout`** — no response within timeout:
```json
{"ts":"...","event":"timeout","real_uid":1000,"command":["apt","update"],"cmd_hash":"...","grant_id":"...","agent_id":"...","target":"server01","timeout_secs":300}
```

**`error`** — unexpected failure:
```json
{"ts":"...","event":"error","real_uid":1000,"command":["..."],"agent_id":"...","target":"server01","message":"..."}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (command ran) |
| 1 | Configuration error, HTTP error, I/O error, or JSON parse error |
| 2 | Authentication failure or wrong key type |
| 3 | Grant denied |
| 4 | Grant timed out (no approval within timeout) |
| 5 | JWT verification failed or cmd_hash mismatch |
| 126 | Exec failed or privilege elevation error |
| 127 | Command not found |

## Uninstall

```bash
sudo make uninstall
```

This removes `/usr/local/bin/apes`. To also remove the agent config and key:

```bash
sudo rm -rf /etc/apes
```

## License

MIT
