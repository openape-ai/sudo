# openape-sudo — Agent Privilege Elevation via OpenApe Grants

Use `apes` to run commands with elevated (root) privileges. Instead of direct sudo access, agents authenticate through the OpenApe grant system: a human approves every privileged command before it executes.

## Prerequisites

Before using `apes`, verify the setup:

```bash
# Binary installed?
which apes

# Already enrolled? Check config exists and is valid
apes --help

# Full status check — loads config, verifies key
apes -- echo "ready"
```

Required files after enrollment:
- `/etc/apes/config.toml` — server URL, agent ID, poll settings
- `/etc/apes/agent.key` — Ed25519 private key (OpenSSH format)

Both are `0600 root:root`. The `apes` binary is setuid-root (mode `4755`).

## Enrollment

Enrollment generates a keypair, writes the config, and produces a URL for admin approval.

```bash
sudo apes enroll \
  --server <OPENAPE_SERVER_URL> \
  --agent-email <EMAIL> \
  [--agent-name <NAME>]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--server` | Yes | OpenApe IdP URL (e.g. `https://id.example.com`) |
| `--agent-email` | Yes | Agent identifier on the IdP |
| `--agent-name` | No | Display name (defaults to hostname) |

**What happens:**
1. Creates `/etc/apes/` (mode `0700`) if missing
2. Generates Ed25519 keypair → writes `/etc/apes/agent.key` (mode `0600`)
3. Writes `/etc/apes/config.toml` (mode `0600`) with a new UUID agent ID
4. Prints an enrollment URL in the format:
   `<server>/enroll?email=<email>&name=<name>&key=<pubkey>&id=<agent_id>`

**After enrollment:** Share the printed URL with the admin. The agent is usable once the admin approves the enrollment on the IdP.

## Using Grants

Run a command with elevated privileges:

```bash
apes [--reason <TEXT>] [--timeout <SECS>] -- <COMMAND> [ARGS...]
```

| Flag | Required | Description |
|------|----------|-------------|
| `--reason` | No | Human-readable justification for the request |
| `--timeout` | No | Poll timeout in seconds (overrides config, default: 300) |
| `--config` | No | Path to config file (default: `/etc/apes/config.toml`) |

**The `--` separator is mandatory** — everything after it is the command to execute.

### Examples

```bash
# Install a package
apes --reason "dependency for build" -- apt-get install -y libssl-dev

# Restart a service
apes --reason "deploy v2.3.1" -- systemctl restart myapp

# Quick file edit with shorter timeout
apes --timeout 60 -- cp /tmp/config.new /etc/myapp/config.toml
```

### What happens under the hood

1. **Load config + key** — reads `/etc/apes/config.toml` and `/etc/apes/agent.key` (as root)
2. **Compute cmd_hash** — SHA-256 of the command + arguments
3. **Drop privileges** — all network I/O runs as the real (non-root) user
4. **Authenticate** — challenge-response against the IdP using the Ed25519 key
5. **Create grant** — sends command, cmd_hash, target hostname, and reason to the IdP
6. **Poll for approval** — polls every 2s (configurable), prints `⏳ Waiting for approval…`
7. **Get authorization token** — fetches AuthZ-JWT from the IdP after approval
8. **Verify JWT** — checks signature and confirms cmd_hash matches locally
9. **Elevate + execute** — regains root, sanitizes environment, writes audit log, `exec`s the command

The command replaces the `apes` process (via `exec`), so the exit code is the command's exit code on success.

## Rules for Agents

1. **Never use `sudo` directly** — always use `apes` for privilege elevation
2. **Never manage keys manually** — enrollment handles key generation; do not read, copy, or modify `/etc/apes/agent.key`
3. **Always provide `--reason`** — explain why the command needs root
4. **Respect denials** — if a grant is denied (exit code 3), do not retry the same command. Inform the user and ask for guidance
5. **Handle timeouts gracefully** — if approval times out (exit code 4), tell the user no approver responded and suggest next steps
6. **One command per grant** — each `apes` invocation creates a separate grant. Do not chain commands with `&&` or `;` inside a single `apes` call; use separate invocations

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Config file not found: /etc/apes/config.toml` | Not enrolled or wrong path | Run `sudo apes enroll ...` or use `--config` |
| `Key file not found` | Key deleted or path mismatch in config | Re-enroll |
| `Wrong key type: expected Ed25519` | Key file contains non-Ed25519 key | Re-enroll to regenerate |
| `Auth failed` | Agent not approved on IdP, or key mismatch | Check enrollment status with admin |
| `Grant denied by <user>` | Human rejected the request | Do not retry — ask the user for guidance |
| `Timed out after <N>s` | No approver responded | Increase `--timeout` or contact an approver |
| `cmd_hash mismatch` | Server-side command tampering detected | Indicates a serious integrity issue — report to admin |
| `HTTP error` / connection errors | Network or IdP unreachable | Check connectivity to the server URL in config |
| `Exec failed` / `Command not found` | Target command missing or not executable | Verify the command exists and is in PATH |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (command ran and exited 0) |
| 1 | Config error, HTTP error, I/O error, or JSON parse error |
| 2 | Authentication failed or wrong key type |
| 3 | Grant denied |
| 4 | Grant timed out (no approval within timeout) |
| 5 | JWT verification failed or cmd_hash mismatch |
| 126 | Exec failed or privilege elevation error |
| 127 | Command not found |

On success, the exit code is that of the executed command (apes replaces itself via `exec`).

## Config Reference

`/etc/apes/config.toml`:

```toml
server_url = "https://id.example.com"
agent_id = "uuid-generated-at-enrollment"
key_path = "/etc/apes/agent.key"
# target = "my-server"          # Override hostname
# audit_log = "/var/log/apes/audit.log"

[poll]
interval_secs = 2
timeout_secs = 300

[tls]
# ca_bundle = "/path/to/ca.pem"  # Custom CA for IdP connection
```

## Audit Log

All grant outcomes are logged to `/var/log/apes/audit.log` (JSONL format, configurable via `audit_log` in config). Entries include: user, command, cmd_hash, grant ID, outcome (approved/denied/timeout/error).
