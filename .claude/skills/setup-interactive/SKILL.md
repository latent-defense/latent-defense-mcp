---
name: setup-interactive
description: "Step-by-step MCP server setup — walks the user through each configuration decision with explanations and confirmations."
user-invocable: true
disable-model-invocation: false
---

# Setup (Interactive) — Latent Defense MCP Server

Walk the user through connecting to Latent Defense step by step, explaining each decision and waiting for confirmation before making changes.

## Input

The portal URL must be provided as the argument (e.g., `https://portal.acme-corp.com`). If not provided, ask for it.

## Step 1 — Validate the endpoint

Explain what you're about to do:

> I'll check that your Latent Defense portal is reachable at `<PORTAL_URL>` and that TLS is properly configured.

First, try with SSL verification:

```bash
curl -sf "<PORTAL_URL>/auth/providers"
```

**If it succeeds**, report: "Portal is reachable. SSO is configured with `<provider_name>`." and ask "Ready to continue?"

**If it fails with an SSL error** (certificate verify failed, unable to get local issuer certificate), try without verification to confirm the portal is up:

```bash
curl -sfk "<PORTAL_URL>/auth/providers"
```

If the `-k` request succeeds, explain:

> Your portal is reachable, but its TLS certificate is **not trusted** by your system. This happens when:
> - Your deployment uses a **private Certificate Authority** (common in enterprise environments)
> - A **corporate proxy** is intercepting TLS with its own certificate
>
> **The right fix** is to add the CA certificate to your system trust store:
> - **macOS:** Import the `.crt` file into Keychain Access → System → Certificates, then mark it as "Always Trust"
> - **Linux:** Copy to `/usr/local/share/ca-certificates/` and run `sudo update-ca-certificates`
> - **Environment variable:** Set `SSL_CERT_FILE=/path/to/ca-bundle.crt` (a PEM bundle that includes the private CA)
>
> Ask your admin for the CA certificate if you don't have it.
>
> **Temporary workaround:** I can disable SSL verification in the MCP server config so you can proceed now. This is fine for initial testing but **not recommended for production** — it disables certificate validation and makes the connection vulnerable to interception.

Ask: "Would you like to (1) fix the certificate first, or (2) proceed with SSL verification disabled as a temporary workaround?"

If they choose option 1, tell them to re-run `/setup` after installing the CA cert.
If they choose option 2, note that `"LATENT_DEFENSE_VERIFY_SSL": "false"` will be added to `.mcp.json` in Step 2. Remind them to remove it once the CA cert is installed.

**If both requests fail**, explain:
- Connection refused → the URL is wrong or the deployment is down
- DNS resolution failure → the hostname doesn't resolve
- 404 → the URL might be an API endpoint, not the portal

Ask: "Ready to continue?"

## Step 2 — Find the binary

Explain:

> I need to find where `latent-defense-mcp` is installed so I can point Claude Code's config at the right binary.

Find the binary by checking these locations in order — use the FIRST one that exists:

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

Show the user which path was found. If none found, tell them to install:
```
pip install git+https://github.com/latent-defense/mcp-server.git
```

Ask: "Ready to continue?"

## Step 3 — Review .mcp.json

Explain what `.mcp.json` does:

> `.mcp.json` tells Claude Code where to find the Latent Defense MCP server. It configures the server command, the portal URL, and authentication method.
>
> Authentication uses the **OAuth device flow** — no API keys are stored in config files. When you first use a tool, the server prompts you to approve access in your browser. The token is stored in your OS keychain.

Show the user what will be written or merged:

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

Always use the full absolute path to the binary — never a bare command name. This avoids PATH issues when Claude Code spawns the server.

If `.mcp.json` already exists, show the diff — what's being added vs what already exists. Call out that existing MCP servers will NOT be affected.

Ask: "Should I write this config?" Wait for confirmation before writing.

**Never write an API key into .mcp.json.** If the user asks about API keys, explain that device flow is the default and recommended method. Service account keys are for CI/unattended use and are created in the portal Integrations page — they go in `LATENT_DEFENSE_API_KEY` only when explicitly needed.

## Step 4 — Install skills

Explain what skills are:

> Skills are guided workflows for common tasks. Each one is a `.claude/skills/<name>/SKILL.md` file that teaches Claude how to walk you through a specific workflow using the MCP tools.

List the skills that will be installed:

| Skill | What it does |
|-------|-------------|
| `/map` | Scan infrastructure — select scope, credentials, run mapping |
| `/research` | Explore the graph, run structural queries, discover attack paths |
| `/investigate` | Answer security posture questions, triage detections/CVEs |
| `/triage` | Structural triage of scanner findings at scale |
| `/build` | Integrations — webhooks, scan schedules, SIEM export, connectors |
| `/status` | Deployment health check (`/status deep` for full validation) |

Ask: "Should I install these skills?" Wait for confirmation.

If confirmed, run:

```bash
latent-defense-mcp-init .
```

If the command is not on PATH, fall back to:

```bash
python3 -m latent_defense_mcp.init .
```

Show the output — which skills were created, which were skipped (already exist).

## Step 5 — Authenticate before restart

Explain:

> Before restarting, I need to authenticate with your deployment. This is done separately because Claude Code's MCP server runner doesn't show the server's output — if we wait until after restart, you won't see the authentication prompt and tool calls will hang.
>
> I'll run the login command in the background, grab the device code, and show it to you. You'll open a URL in your browser, sign in, and enter the code.

Find the login command next to the main binary:

```bash
LOGIN_CMD="$(dirname <FULL_PATH_TO_BINARY>)/latent-defense-mcp-login"
test -x "$LOGIN_CMD" && echo "OK" || echo "NOT_FOUND"
```

If not found, fall back to:

```bash
LOGIN_CMD="python3 -m latent_defense_mcp.login"
```

**Run it in the background and read the output immediately.** The login command blocks until approval — if you run it synchronously, the conversation hangs and the user never sees the code.

```bash
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

Ask: "Let me know when you've approved it in the browser."

After the user confirms, check the log again:

```bash
cat /tmp/ld-login.log
```

Look for "Authenticated successfully." If present, the token is saved. Clean up:

```bash
kill $LOGIN_PID 2>/dev/null
```

**Do NOT run the login command multiple times.** Each run generates a new device code that invalidates the previous one. If the user needs a new code, kill the old process first.

## Step 6 — Restart and verify

Tell the user:

> Authentication complete — your token is stored in the keychain. Restart Claude Code to load the MCP server. After restart, tool calls will use the stored token automatically — no more prompts.

After the user restarts:

Call `whoami()` and show the result:

> **Authenticated as:** `<email>`
> **Token type:** `<type>`
> **Scopes:** `<scope_list>`
> **Expires:** `<expiry>`

Call `connection_status()` and show the result:

> **Deployment:** `<url>`
> **Services:**
> - Infrastructure Graph: `<status>`
> - Mapping: `<status>`
> - Scan Trigger: `<status>`
> - Inference: `<status>`
> - Triage: `<status>`
> - Ticketing: `<status>`
> - Connectors: `<status>`
> - Validator: `<status>`

If everything is healthy:

> Setup complete. You're connected to Latent Defense. Try one of these to get started:
> - `/status` — see what's in your deployment right now
> - `/map` — run your first infrastructure scan
> - `/status deep` — full deployment validation

If there are issues, explain each one and how to fix it.

## Error table

| Error | Cause | Fix |
|-------|-------|-----|
| Connection refused | Portal URL wrong or deployment down | Double-check the URL with your admin |
| SSL certificate error | Private CA or corporate proxy | Add CA cert to system trust store, or set `LATENT_DEFENSE_VERIFY_SSL=false` in `.mcp.json` as a temporary workaround |
| 404 on /auth/providers | Wrong URL (maybe API endpoint instead of portal) | The URL should be the portal hostname, not a backend service |
| 401 after device flow | Token expired or revoked | Re-run the login command from Step 5 to get a new token |
| 403 on tool calls | Key lacks required scopes | Check your token scopes with `whoami()` — you may need operator-level access |
| Tool calls hang after restart | Token not stored before restart | Re-run the login command from Step 5 before restarting |
