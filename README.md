# Latent Defense MCP Server

MCP server that connects [Claude Code](https://docs.anthropic.com/en/docs/claude-code) to your Latent Defense deployment. Map infrastructure into a semantic graph, discover attack paths, investigate security posture, and manage remediation — all from your terminal.

## Quick start

```bash
# 1. Install
pip install git+https://github.com/latent-defense/mcp-server.git

# 2. Scaffold config and skills into your project
cd your-project
python3 -m latent_defense_mcp.init

# 3. Edit .mcp.json — set LATENT_DEFENSE_URL to your portal
#    (looks like https://portal.your-deployment.com)

# 4. Authenticate before restarting Claude Code
latent-defense-mcp-login https://portal.your-deployment.com

# 5. Restart Claude Code — tools are ready to use
```

The login step stores your token in the OS keychain so the MCP server authenticates silently on startup. Type `/status` to verify the connection, or `/map` to start mapping infrastructure.

> **Tip:** Use `/setup <url>` instead of steps 3-4 if you prefer a guided walkthrough that handles configuration and authentication for you.

Run `latent-defense-mcp-login <url>` to authenticate before your first session — the token is stored in your OS keychain and refreshes automatically.

> **Note:** Use `python3 -m latent_defense_mcp.init` instead of `latent-defense-mcp-init` if the entry point isn't on your PATH (common with virtualenv installs).

## Setup

### Option 1: Use the `/setup` skill (recommended)

After installing and running `python3 -m latent_defense_mcp.init`, edit `.mcp.json` to set your portal URL, then run `latent-defense-mcp-login <url>` to authenticate. Restart Claude Code and your tools are ready.

Alternatively, type `/setup <url>` for a guided walkthrough that handles configuration and authentication step by step.

> **Important:** `/setup` won't be available until you run the init command and restart Claude Code. The init command copies the skill files into your project's `.claude/skills/` directory where Claude Code can find them.

### Option 2: Manual setup

#### 1. Install

```bash
pip install git+https://github.com/latent-defense/mcp-server.git
```

#### 2. Scaffold config and skills

```bash
cd your-project
python3 -m latent_defense_mcp.init
```

This creates:
- `.mcp.json` — MCP server configuration with the binary path auto-detected
- `.claude/skills/` — 19 guided workflow skills (13 top-level + sub-skills)

#### 3. Set your portal URL

Edit `.mcp.json` and replace the placeholder portal URL:

```json
{
  "mcpServers": {
    "latent-defense": {
      "command": "/path/to/latent-defense-mcp",
      "env": {
        "LATENT_DEFENSE_URL": "https://portal.your-deployment.com"
      }
    }
  }
}
```

The `command` should be the full path to the binary (auto-detected by init). If you need to find it manually:

```bash
python3 -c "import shutil; print(shutil.which('latent-defense-mcp'))"
```

#### 4. Authenticate

Before restarting Claude Code, authenticate with the login command:

```bash
latent-defense-mcp-login https://portal.your-deployment.com
```

This opens a device flow: you'll see a URL and code. Open the URL in your browser, sign in with your work account (SSO), and enter the code. The token is stored in your OS keychain and refreshes automatically.

#### 5. Restart Claude Code

After authentication, restart Claude Code. The MCP server uses the stored token — no prompts during tool calls. Type `/status` to verify the connection.

> **Troubleshooting:** If your portal uses a private CA certificate and you get SSL errors, add `"LATENT_DEFENSE_VERIFY_SSL": "false"` to the `env` block in `.mcp.json` as a temporary workaround. See the setup-interactive skill for proper CA cert installation instructions.

## Authentication

### Device flow (default)

No API keys in config files. The MCP server authenticates via the [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628):

1. MCP server requests a device code from your portal
2. You approve in the browser (SSO login + code entry)
3. MCP server receives a JWT and stores it in the OS keychain
4. Token refreshes automatically; keychain persists across sessions

### Token lifetime

The access token defaults to 8 hours. After expiry, the MCP server automatically refreshes using a 30-day refresh token — you won't be re-prompted unless the refresh token expires.

To change the access token lifetime (affects all users on the cluster):

| Duration | Value | Use case |
|----------|-------|----------|
| 8 hours | `28800` | Default — good balance of security and convenience |
| 24 hours | `86400` | Full workday without refresh |
| 7 days | `604800` | Weekly re-auth |
| 30 days | `2592000` | Maximum — match refresh token lifetime |

Configure via Claude Code after setup:

```
Set my access token TTL to 7 days
```

Or configure it in the portal under **Settings → Security**.

### Service account keys (CI / unattended)

For CI pipelines, scheduled agents, or headless environments where browser-based auth isn't possible:

1. Create a service account in the portal: **API & MCP** → New Service Account
2. Select the scopes your integration needs (principle of least privilege)
3. Copy the key (shown only once — starts with `sk_ld_svc_`)
4. Add it to your environment:

```json
{
  "mcpServers": {
    "latent-defense": {
      "command": "latent-defense-mcp",
      "env": {
        "LATENT_DEFENSE_URL": "https://portal.your-deployment.com",
        "LATENT_DEFENSE_API_KEY": "sk_ld_svc_..."
      }
    }
  }
}
```

### Introspection

| Tool | What it does |
|------|-------------|
| `whoami()` | Show authenticated identity, scopes, token type, and expiry |
| `connection_status()` | Test connectivity to all backend services |

Use `whoami()` when a tool returns a permissions error to see what scopes your token has.

## Skills

Skills are guided workflows that walk Claude through multi-step tasks. They're installed as `.claude/skills/<name>/SKILL.md` files by the init script.

| Skill | Command | What it does |
|-------|---------|-------------|
| **Setup** | `/setup <url>` | Connect to a Latent Defense deployment (automatic or interactive mode) |
| **Tutorial** | `/tutorial` | Interactive walkthrough of energy scores, risk bands, and path tracing |
| **My Data** | `/my-data` | See everything in your deployment — repos, graphs, paths, connectors |
| **Explore** | `/explore` | Browse infrastructure graph — entry points, crown jewels, choke points |
| **Investigate** | `/investigate` | Investigate specific CVEs, detections, or security posture questions |
| **Triage** | `/triage` | Structural security triage at scale with parallel sub-agents |
| **Research** | `/research` | Proactive attack path discovery against the energy graph |
| **Review** | `/review` | Review attack paths in the triage queue with energy context |
| **Diff** | `/diff` | Compare two graph snapshots — see what changed between commits or branches |
| **Map** | `/map` | Scan infrastructure — select scope, credentials, monitor progress |
| **Rerun Inference** | `/rerun-inference` | Re-run JEPA inference after remapping or remediation |
| **Build** | `/build` | Build integrations — webhooks, scan schedules, connectors, SIEM |
| **Status** | `/status` | Deployment health check (use `/status deep` for full validation) |

> `/setup-headless` and `/setup-interactive` are sub-modes of `/setup` and are also available as standalone skills.

## Scoped access

API keys and device flow tokens are scoped. The portal's scope picker groups them into presets:

| Preset | Scopes | Use case |
|--------|--------|----------|
| **Read Only** | `infra:read`, `triage:read`, `inference:read`, `map:read`, `tickets:read`, `connectors:read` | Dashboards, SIEM integration, compliance export |
| **Operator** | All except `admin` | Day-to-day security operations, mapping, triage |
| **Full Access** | All 18 scopes | Administration, key management |

Individual scopes can be selected granularly. When a tool requires a scope you don't have, the error message tells you which scope is missing and where to update it.

## Mapping infrastructure

Tell Claude what to map:

```
Map all repositories in the acme-corp GitHub org
```

Or use `/map` for the guided workflow. Claude will ask for repositories, credential profile, and scope, then monitor the run to completion.

### What gets mapped

The mapper builds a semantic graph from your infrastructure:

- **IaC** (Terraform, CloudFormation, Helm) → cloud resources, networking, IAM
- **Kubernetes manifests** → deployments, services, RBAC, network policies
- **CI/CD pipelines** (GitHub Actions, GitLab CI) → workflows, secrets, deployment targets
- **Application code** → HTTP endpoints, service calls, auth checks
- **Dockerfiles** → container images, base images, exposed ports
- **Configuration** → environment variables, secret references, database connections

## Investigating security posture

Use `/investigate` or ask directly:

```
How hard is it to get from the public internet to our production database?
```

Claude will:
1. Load your infrastructure graph for analysis
2. Search for relevant nodes (entry points, targets, controls)
3. Build threat models and match them against the real graph
4. Score each hop for attack feasibility (lower difficulty = easier for an attacker)
5. Identify compensating controls on difficult hops (network policies, RBAC, pod security)
6. Report a clear answer with the specific controls that protect (or expose) the path

### Difficulty scores

The model scores attack feasibility based on your infrastructure's security controls — network policies, RBAC, pod security, firewall rules. **Lower difficulty means easier for an attacker.**

Use difficulty as a ranking signal to prioritize paths relative to each other within your deployment. The absolute numbers depend on graph structure and are not comparable across different deployments.

| Difficulty | What it means |
|------------|---------------|
| Trivial | No meaningful security barriers detected on this path |
| Easy | Minimal controls — few barriers for an attacker |
| Moderate | Some controls present — attacker needs to bypass specific defenses |
| Hard | Significant controls detected — multiple security layers in place |

## Environment variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LATENT_DEFENSE_URL` | Yes | — | Portal base URL |
| `LATENT_DEFENSE_API_KEY` | No | — | Service account key (skips device flow) |
| `LATENT_DEFENSE_VERIFY_SSL` | No | `true` | Set to `false` for self-signed certs |

## Tool reference

### Mapping

| Tool | Description |
|------|-------------|
| `create_mapping_run` | Create a mapping run — accepts repos, cloud accounts, k8s clusters, domains, CIDRs |
| `get_mapping_run` | Get run status and agent progress |
| `list_mapping_runs` | List recent mapping runs |
| `list_mapping_agents` | List agents spawned by a run with per-agent status |
| `cancel_mapping_run` | Cancel a running mapping run |
| `list_trigger_events` | List recent trigger events |
| `trigger_stats` | Active runs, rate limiting state, failure counts |
| `list_scan_schedules` | List recurring scan schedules |
| `run_scan_schedule` | Manually trigger a scheduled scan |
| `get_trigger_event` | Get details of a specific trigger event |

### Infrastructure graph

| Tool | Description |
|------|-------------|
| `list_repositories` | List repositories with node/edge counts |
| `get_repository` | Get repository details |
| `list_branches` | List branches in a repository |
| `get_branch` | Get branch details — head commit, graph stats |
| `get_graph` | Get the full materialized graph for a branch |
| `create_branch` | Fork a branch for analysis |
| `list_commits` | List commits on a branch |
| `diff_commits` | Diff two commits — added/removed/modified nodes and edges |
| `search_nodes` | Search nodes by name substring (use grep_nodes for local cache search or energy_node_scores for energy-aware search) |
| `infra_stats` | Overall stats — repo count, total nodes/edges |

### Attack path analysis

| Tool | Description |
|------|-------------|
| `run_inference` | Run attack path analysis on a branch |
| `list_inference_runs` | List recent inference runs |
| `get_inference_run` | Get inference run status and results |
| `ingest_detection` | Ingest a detection from an external tool to trigger targeted inference |
| `list_inference_schedules` | List inference schedules |
| `create_inference_schedule` | Create a recurring inference schedule |
| `delete_inference_schedule` | Delete an inference schedule |

### Triage

| Tool | Description |
|------|-------------|
| `list_attack_paths` | List attack paths — filter by status and risk score |
| `get_attack_path` | Get full path details with MITRE ATT&CK mappings and energy breakdown |
| `update_path_status` | Update triage status |
| `validate_path` | Dispatch for sandbox validation |
| `get_validation_status` | Check sandbox validation progress |
| `dismiss_path` | Dismiss an attack path from active triage |
| `undismiss_path` | Restore a dismissed path to active triage |
| `override_risk_score` | Manually override a path's risk score |
| `clear_risk_override` | Remove a manual risk score override |
| `add_path_comment` | Add a comment to an attack path |
| `edit_path_comment` | Edit an existing path comment |
| `bulk_update_paths` | Batch-update status on multiple paths |
| `list_path_history` | Audit log of status changes on a path |
| `submit_attack_path` | Submit a discovered attack path for scoring and triage |
| `get_triage_config` | Get triage configuration (thresholds, auto-dismiss rules) |
| `triage_stats` | Counts by status, severity, repository |

### Webhooks

| Tool | Description |
|------|-------------|
| `register_webhook` | Register a webhook for triage events |
| `list_webhooks` | List registered webhooks |
| `delete_webhook` | Delete a webhook |
| `test_webhook` | Send a test event |
| `webhook_deliveries` | Delivery history |
| `validate_webhook_template` | Validate a Jinja2 webhook template against sample data |

### Connectors

| Tool | Description |
|------|-------------|
| `list_connectors` | List data source connectors |
| `create_connector` | Create a connector for automated ingestion |
| `connector_health` | Health summary across all connectors |
| `list_connector_types` | Available connector types and config fields |
| `get_connector` | Get connector details including status and last poll |
| `update_connector` | Update a connector's configuration |
| `delete_connector` | Delete a data source connector |
| `poll_connector` | Trigger an immediate poll on a connector |
| `ingest_stats` | Get ingestion statistics |
| `test_connector` | Test a connector without persisting data |

### Foundation

| Tool | Description |
|------|-------------|
| `load_graph_energies` | Load a graph and fetch JEPA energy scores into a local cache — required before any graph or energy tool |
| `load_branch` | Load a branch into the JEPA encoder (use `load_graph_energies` for the full workflow) |
| `wait_for_load` | Wait for graph encoding to complete after `load_branch()` |

### Energy analysis

The platform provides energy analysis tools for structural scoring and path tracing. Load a graph with `load_graph_energies(branch_id)`, then use the energy tools for structural analysis, path tracing, and chokepoint discovery.

| Tool | Description |
|------|-------------|
| `energy_node_scores` | Energy scores for a set of nodes |
| `energy_edge_scores` | Energy scores for edges between nodes |
| `energy_momentum_path` | Score a path using the momentum model (0–100 risk) |
| `energy_lowest_hop` | Find the lowest-energy hop from a node |
| `energy_lowest_paths` | Discover lowest-energy paths between nodes |
| `energy_trace_to_target` | Trace energy-guided paths to a target |
| `energy_compare_paths` | Compare energy profiles of multiple paths |
| `energy_node_neighborhood` | Energy landscape around a node |
| `energy_entry_points` | Find entry points with lowest energy barriers |
| `energy_defenses` | Identify defensive controls (braking energy) |
| `energy_top_attack_paths` | Discover top attack paths by energy |
| `energy_chokepoints` | Find infrastructure chokepoints |

### Graph tools

| Tool | Description |
|------|-------------|
| `read_node` | Read a node's full details from the cached graph |
| `read_edge` | Read an edge's details |
| `get_connected_edges` | Get all edges connected to a node |
| `get_graph_statistics` | Graph summary — node/edge counts by type |
| `grep_nodes` | Search nodes by name or description in the local cache |
| `grep_edges` | Search edges in the local cache |
| `find_nodes_by_type` | Find all nodes of a given type |
| `find_edges_by_type` | Find all edges of a given type |

### Session state

| Tool | Description |
|------|-------------|
| `triage_save_user` | Save user profile (role, preferences, integrations) |
| `triage_load_user` | Load user profile |
| `triage_save_project` | Save project state (branch, findings, verdicts) |
| `triage_load_project` | Load project state |
| `triage_list_projects` | List all triage projects |
| `triage_project_status` | Project status summary |
| `triage_update_finding_group` | Update a finding group's status |
| `triage_add_work_item` | Add a work item to a project |
| `triage_add_decision` | Record a risk decision |
| `triage_get_workflow_args` | Get workflow arguments for pipeline execution |

### Introspection

| Tool | Description |
|------|-------------|
| `whoami` | Authenticated identity, scopes, token type, expiry |
| `connection_status` | Connectivity check to all backend services |
