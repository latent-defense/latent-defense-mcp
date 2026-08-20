---
name: setup-headless
description: "Automatic MCP server setup — configures .mcp.json, triggers device flow, installs skills, and verifies the connection with no user interaction."
user-invocable: true
disable-model-invocation: false
---

# Setup (Automatic) — Latent Defense MCP Server

Configure the Latent Defense MCP server automatically. This skill writes all config files, triggers authentication, and verifies the connection.

## Input

The portal URL must be provided as the argument (e.g., `https://portal.acme-corp.com`). If not provided, ask for it.

## Step 1 — Validate the endpoint

Before writing any config, verify the portal is reachable. Try with SSL verification first:

```bash
curl -sf "<PORTAL_URL>/auth/providers"
```

**If this succeeds**, the portal is reachable with a trusted certificate. Continue to Step 2.

**If this fails with an SSL error** (certificate verify failed, unable to get local issuer certificate, SSL_ERROR_SYSCALL), the portal's TLS certificate is not in the system trust store. This is common with private CA deployments or corporate proxies. Run the same request without SSL verification to confirm the portal itself is up:

```bash
curl -sfk "<PORTAL_URL>/auth/providers"
```

If the `-k` request succeeds, tell the user:

> Your portal is reachable but its TLS certificate is not trusted by your system. This means either:
> - Your deployment uses a private Certificate Authority (common in enterprise environments)
> - A corporate proxy is intercepting TLS with its own certificate
>
> **Recommended fix:** Ask your admin for the CA certificate and add it to your system trust store (macOS Keychain, `/etc/ssl/certs`, or `SSL_CERT_FILE`). This is a one-time setup.
>
> **Workaround for testing:** I can disable SSL verification in the MCP server config. This is NOT recommended for production — it makes the connection vulnerable to man-in-the-middle attacks.

Ask the user: "Should I disable SSL verification as a temporary workaround, or would you prefer to fix the certificate first?"

If they choose the workaround, add `"LATENT_DEFENSE_VERIFY_SSL": "false"` to the env block in Step 2. If they choose to fix it, stop and tell them to re-run `/setup` after installing the CA cert.

**If both requests fail:**
- Connection refused → check the URL, it should be the portal hostname (not a backend service)
- DNS resolution failure → the hostname doesn't resolve; check with the admin
- 404 → the URL might be wrong; it should include the protocol (`https://`)

## Step 2 — Find the binary

Find the `latent-defense-mcp` binary. Check these locations in order — use the FIRST one that exists:

```bash
# 1. On PATH
which latent-defense-mcp 2>/dev/null

# 2. In a .venv in the current directory or parent directories
find . -path './.venv/bin/latent-defense-mcp' -maxdepth 3 2>/dev/null
find .. -path '*/.venv/bin/latent-defense-mcp' -maxdepth 4 2>/dev/null

# 3. In the latent_defense_mcp package location
python3 -c "from pathlib import Path; import latent_defense_mcp; print(Path(latent_defense_mcp.__file__).resolve().parent.parent / '.venv' / 'bin' / 'latent-defense-mcp')" 2>/dev/null
```

**Verify the path exists** before using it:

```bash
test -x "<FOUND_PATH>" && echo "OK" || echo "NOT_FOUND"
```

Do NOT use `sysconfig.get_path('scripts')` — it returns the global scripts directory which may not contain the binary if the package was installed in a virtualenv.

If no binary is found, tell the user to install the package first:
```
pip install git+https://github.com/latent-defense/mcp-server.git
```

## Step 3 — Write .mcp.json

Check if `.mcp.json` exists in the project root.

**If it does not exist**, write:

```json
{
  "mcpServers": {
    "latent-defense": {
      "command": "<FULL_PATH_TO_BINARY>",
      "env": {
        "LATENT_DEFENSE_URL": "<PORTAL_URL>"
      }
    }
  }
}
```

Always use the full absolute path to the binary in the `command` field — never a bare command name. This avoids PATH issues when Claude Code spawns the server.

**If it exists**, read it and merge the `latent-defense` entry into the existing `mcpServers` object. Do NOT overwrite other MCP server entries. If a `latent-defense` entry already exists, update `command` and `LATENT_DEFENSE_URL` but leave other env vars intact.

**Never write an API key into .mcp.json.** Authentication uses the device flow — the MCP server obtains and stores tokens in the OS keychain automatically.

## Step 4 — Install skills

Run the init command to copy skill files into the project:

```bash
latent-defense-mcp-init .
```

If the command is not on PATH, run it via Python:

```bash
python3 -m latent_defense_mcp.init .
```

This creates `.claude/skills/` directories with guided workflow skills.

## Step 5 — Authenticate before restart

**CRITICAL: Do NOT just tell the user to restart and hope they see the device flow prompt.** Claude Code does not surface MCP server stderr. The device flow code will be invisible and tool calls will hang.

Instead, use the dedicated login command. Find it next to the main binary:

```bash
LOGIN_CMD="$(dirname <FULL_PATH_TO_BINARY>)/latent-defense-mcp-login"
test -x "$LOGIN_CMD" && echo "OK" || echo "NOT_FOUND"
```

If not found, fall back to the Python module:

```bash
LOGIN_CMD="python3 -m latent_defense_mcp.login"
```

**Run it in the background and read the output immediately.** The login command blocks until the user approves in the browser — if you run it synchronously, the conversation hangs and the user never sees the code.

```bash
# Run in background, capture output to a log file
$LOGIN_CMD <PORTAL_URL> --no-verify > /tmp/ld-login.log 2>&1 &
LOGIN_PID=$!
sleep 3
cat /tmp/ld-login.log
```

(Add `--no-verify` if SSL verification was disabled in Step 3, omit it otherwise.)

Read `/tmp/ld-login.log` — it will contain the device code and URL. Show the user:

> **Authenticate now:**
> 1. Open: `<URL from log>`
> 2. Enter code: `<CODE from log>`
> 3. Sign in with your work account and click **Approve**

Then wait for the user to confirm they approved. After confirmation, check the log again:

```bash
cat /tmp/ld-login.log
```

Look for "Authenticated successfully." If present, the token is saved. Kill the process if it's still running:

```bash
kill $LOGIN_PID 2>/dev/null
```

**Do NOT run the login command multiple times.** Each run generates a new device code that invalidates the previous one. If the user needs a new code, kill the old process first.

## Step 6 — Restart and verify

Tell the user:

> Authentication complete — your token is stored in the keychain. Restart Claude Code to load the MCP server.

After the user restarts:

1. Call `connection_status()` — all services should be `ok`
2. Call `whoami()` — should show the authenticated identity and scopes

If both pass, tell the user:

> Setup complete. Your available skills:
> - `/map` — scan infrastructure
> - `/research` — explore the graph and discover attack paths
> - `/investigate` — answer security posture questions
> - `/triage` — structural triage of scanner findings at scale
> - `/build` — integrations — webhooks, scan schedules, SIEM export, connectors
> - `/status` — deployment health check (`/status deep` for full validation)

If `connection_status()` or `whoami()` fail, troubleshoot:
- 401 → token may not have saved; re-run the auth step above
- Connection error → check `LATENT_DEFENSE_URL` in `.mcp.json`
- Service errors → the deployment may have issues; suggest contacting their admin

## Error recovery

If any step fails, do NOT leave partial state. If `.mcp.json` was written but auth failed, tell the user the config is in place and walk them through the authentication step again.
