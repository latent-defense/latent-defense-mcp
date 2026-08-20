---
name: setup
description: "Set up the Latent Defense MCP server in Cursor. Configures authentication and verifies connection."
user-invocable: true
disable-model-invocation: true
---

# Setup — Latent Defense MCP Server (Cursor)

Configure the Latent Defense MCP server in Cursor. This skill checks or creates `.cursor/mcp.json`, authenticates with the deployment, and verifies the connection.

## Step 1 — Check existing configuration

Check if `.cursor/mcp.json` exists in the project root.

**If it exists** and contains a `latent-defense` entry under `mcpServers`:

Try calling `whoami()` and `connection_status()`.

- **If both succeed**: report the authenticated identity and service health. Skip to Step 5.
- **If `whoami` fails with 401**: the token has expired or was never obtained. Skip to Step 3 (authentication).
- **If connection fails**: the server is not running. Tell the user:

> The MCP server is configured in `.cursor/mcp.json` but not responding. Try:
> 1. Open **Cursor Settings → MCP** and check that `latent-defense` shows as connected
> 2. Click the refresh button next to the server entry
> 3. If it still fails, restart Cursor

**If `.cursor/mcp.json` does not exist**, proceed to Step 2.

## Step 2 — Create configuration

Ask for the portal URL:

> What is your Latent Defense portal URL?
>
> It looks like `https://portal-<name>.latentdefense.ai` or a custom domain your admin configured.
> Default: `https://portal.latentdefense.ai`

Validate the endpoint:

```bash
curl -sf "<PORTAL_URL>/auth/providers"
```

If it fails with an SSL error, try with `-k`. If the insecure request succeeds, explain:

> Your portal is reachable but its TLS certificate is not trusted by your system. This is common with private CA deployments. Ask your admin for the CA certificate and add it to your system trust store.
>
> As a temporary workaround, I can disable SSL verification in the config.

Ask: "Should I disable SSL verification as a temporary workaround?"

If they agree, include `"LATENT_DEFENSE_VERIFY_SSL": "false"` in the env block below.

Find the binary:

```bash
# 1. On PATH
which latent-defense-mcp 2>/dev/null

# 2. In a .venv in the project or parent directories
find . -path './.venv/bin/latent-defense-mcp' -maxdepth 3 2>/dev/null
find .. -path '*/.venv/bin/latent-defense-mcp' -maxdepth 4 2>/dev/null

# 3. Via Python package
python3 -c "from pathlib import Path; import latent_defense_mcp; print(Path(latent_defense_mcp.__file__).resolve().parent.parent / '.venv' / 'bin' / 'latent-defense-mcp')" 2>/dev/null
```

Verify the found path exists:

```bash
test -x "<FOUND_PATH>" && echo "OK" || echo "NOT_FOUND"
```

If no binary is found, tell the user to install:

```
pip install git+https://github.com/latent-defense/mcp-server.git
```

Write `.cursor/mcp.json`. If the file already exists, merge the `latent-defense` entry — do NOT overwrite other server entries.

```json
{
  "mcpServers": {
    "latent-defense": {
      "command": "<FULL_PATH_TO_BINARY>",
      "env": {
        "LATENT_DEFENSE_URL": "<PORTAL_URL>"
      },
      "autoApprove": [
        "read_node",
        "read_edge",
        "get_connected_edges",
        "get_graph_statistics",
        "grep_nodes",
        "grep_edges",
        "find_nodes_by_type",
        "find_edges_by_type",
        "energy_node_scores",
        "energy_edge_scores",
        "energy_momentum_path",
        "energy_lowest_hop",
        "energy_lowest_paths",
        "energy_trace_to_target",
        "energy_compare_paths",
        "energy_node_neighborhood",
        "energy_entry_points",
        "energy_defenses",
        "energy_top_attack_paths",
        "energy_chokepoints",
        "load_graph_energies",
        "load_branch",
        "wait_for_load",
        "whoami",
        "connection_status",
        "list_repositories",
        "get_repository",
        "list_branches",
        "get_branch",
        "get_graph",
        "list_commits",
        "infra_stats",
        "list_attack_paths",
        "get_attack_path",
        "triage_stats",
        "get_triage_config",
        "list_inference_runs",
        "get_inference_run",
        "list_mapping_runs",
        "get_mapping_run",
        "list_mapping_agents",
        "list_scan_schedules",
        "list_inference_schedules",
        "list_connectors",
        "list_connector_types",
        "get_connector",
        "connector_health",
        "list_webhooks",
        "get_validation_status",
        "list_path_history",
        "search_nodes",
        "ingest_stats",
        "trigger_stats",
        "list_trigger_events",
        "get_trigger_event",
        "triage_load_user",
        "triage_list_projects",
        "triage_load_project",
        "triage_project_status",
        "triage_get_workflow_args",
        "diff_commits"
      ]
    }
  }
}
```

Use the full absolute path to the binary in `command` — Cursor resolves `${workspaceFolder}` but an absolute path is more reliable across workspace configurations.

**Never write an API key into `.cursor/mcp.json`.** Authentication uses the device flow.

Tell the user:

> Configuration written to `.cursor/mcp.json`. Next I need to authenticate before you restart Cursor.

## Step 3 — Authenticate

Find the login command next to the main binary:

```bash
LOGIN_CMD="$(dirname <FULL_PATH_TO_BINARY>)/latent-defense-mcp-login"
test -x "$LOGIN_CMD" && echo "OK" || echo "NOT_FOUND"
```

If not found, fall back to:

```bash
LOGIN_CMD="python3 -m latent_defense_mcp.login"
```

Run the login in the background and capture the device code:

```bash
$LOGIN_CMD <PORTAL_URL> > /tmp/ld-login.log 2>&1 &
LOGIN_PID=$!
sleep 3
cat /tmp/ld-login.log
```

Add `--no-verify` after the portal URL if SSL verification was disabled.

Read the log for the device code and URL. Show the user:

> **Authenticate now:**
> 1. Open: `<URL from log>`
> 2. Enter code: `<CODE from log>`
> 3. Sign in with your work account and click **Approve**

Wait for the user to confirm. Then check:

```bash
cat /tmp/ld-login.log
```

Look for "Authenticated successfully." Clean up:

```bash
kill $LOGIN_PID 2>/dev/null
```

**Do NOT run the login command multiple times.** Each run generates a new device code that invalidates the previous one.

## Step 4 — Restart and verify

Tell the user:

> Authentication complete — your token is stored in the keychain.
>
> **Restart Cursor** to load the MCP server. After restart, open this project and tool calls will authenticate automatically.
>
> Alternatively, open **Cursor Settings → MCP** and click refresh next to `latent-defense`.

After the user confirms they restarted:

1. Call `whoami()` — should show the authenticated identity
2. Call `connection_status()` — all services should be `ok`

If both pass, proceed to Step 5.

If either fails:
- **401**: token may not have saved — re-run Step 3
- **Connection error**: check `LATENT_DEFENSE_URL` in `.cursor/mcp.json`
- **Server not found**: verify the binary path in `.cursor/mcp.json` is correct

## Step 5 — Profile setup (optional)

Ask:

> Would you like to configure your profile? This helps skills personalize output for your role and integrations.

**If yes**, ask for:

- **Name**: display name
- **Role**: e.g., security engineer, platform engineer, CISO, developer
- **Pain points**: what security challenges they face (e.g., "too many scanner findings", "no visibility into cloud attack paths")
- **Ticketing integration**: e.g., Jira, Linear, GitHub Issues, or none

Save with `triage_save_user()` using the collected information.

**If no**, skip.

Then show available skills:

> **Setup complete.** Here are your available skills:
>
> | Skill | What it does |
> |-------|-------------|
> | `/tutorial` | Interactive walkthrough — learn energy scores and path tracing |
> | `/my-data` | See everything in your deployment |
> | `/explore` | Browse the graph — entry points, crown jewels, choke points |
> | `/investigate` | Investigate a CVE, detection, or finding against your graph |
> | `/triage` | Scanner finding triage at scale with parallel agents |
> | `/research` | Proactive attack path discovery |
> | `/review` | Walk the attack path triage queue |
> | `/map` | Run an infrastructure mapping scan |
> | `/status` | Deployment health check (`/status deep` for full validation) |
>
> **Suggested next steps:**
> - New to Latent Defense? Start with `/tutorial`
> - Have infrastructure mapped? Try `/explore` or `/research`
> - Have scanner findings to process? Use `/triage`
> - Just want to see what's there? Run `/my-data`
