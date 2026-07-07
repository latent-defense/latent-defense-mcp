---
name: map
description: "Run an infrastructure mapping scan via the Latent Defense MCP server. Guides scope selection, credential profile, run creation, progress monitoring, and result inspection."
user-invocable: true
disable-model-invocation: false
---

# Map — Infrastructure Mapping Skill

Map repositories, cloud accounts, Kubernetes clusters, domains, and network targets into a versioned infrastructure graph.

## Prerequisites

- The `latent-defense` MCP server must be connected (check that `latent-defense` tools are available)
- Credentials must be configured in the portal under **Settings → Credentials** for the targets you want to map (e.g. a GitHub PAT for private repos, AWS credentials for cloud accounts)

If the MCP server is not connected, tell the user to check their `.mcp.json` configuration and restart the session. The README in this repository has full setup instructions.

## Workflow

### Step 1 — Determine what to map

If the user hasn't specified what to map, ask them. Supported scope types:

| Scope type | Input format | What it maps |
|------------|-------------|--------------|
| Repositories | GitHub/GitLab URLs | IaC (Terraform, CloudFormation, Helm), CI/CD pipelines, dependencies, secrets, Dockerfiles |
| Cloud accounts | `{"provider": "aws", "account_id": "123456789012", "regions": ["us-east-1"]}` | Live cloud resources via API |
| Kubernetes clusters | kubeconfig context names | Workloads, RBAC, network policies, service mesh |
| Domains | domain strings | DNS, subdomains, certificate transparency |
| Web endpoints | URLs | HTTP probing, technology fingerprinting |
| CIDRs | network ranges | Port scanning, service discovery |

### Step 2 — Determine the credential profile

The mapper needs credentials to access the targets. Ask the user which credential profile to use. They can find their profiles in **Settings → Credentials** in the portal.

Common profiles:
- `github` — GitHub PAT for private repository access
- `default` — default profile, often has cloud credentials
- Custom names like `aws-prod`, `azure-staging`, etc.

If the user doesn't know their profile name, suggest they check the portal.

### Step 3 — Create the mapping run

Call `create_mapping_run` with the scope and credential profile. Examples:

**Repositories:**
```
create_mapping_run(
  description="Map ACME Corp GitHub repositories",
  repositories='["https://github.com/acme/api-service", "https://github.com/acme/infra"]',
  credentials_profile="github"
)
```

**Cloud account:**
```
create_mapping_run(
  description="Map AWS production account",
  cloud_accounts='[{"provider": "aws", "account_id": "123456789012", "regions": ["us-east-1", "us-west-2"]}]',
  credentials_profile="default"
)
```

**Mixed scope:**
```
create_mapping_run(
  description="Map full ACME infrastructure",
  repositories='["https://github.com/acme/infra", "https://github.com/acme/api"]',
  cloud_accounts='[{"provider": "aws", "account_id": "123456789012", "regions": ["us-east-1"]}]',
  domains='["acme.com"]',
  credentials_profile="default"
)
```

Save the returned `map_run_id`.

For large scopes (50+ repos, multiple clouds), a single run is fine. The mapper's planner decomposes it into parallel agents automatically.

### Step 4 — Monitor progress

Poll with `get_mapping_run(run_id)` every 30-60 seconds. Report status to the user.

Status progression: `routing` → `planning` → `running` → `committing` → `completed` or `failed`

Key fields to report:
- `status` — current phase
- `routing_decision` — which repository the graph is being committed to and why
- `total_agents` / `agents_completed` / `agents_in_progress` / `agents_failed`
- `skipped_targets` — targets that couldn't be mapped (usually credential issues)
- `credential_warnings` — credential problems to flag

Use `list_mapping_agents(run_id)` if the user wants per-agent detail.

Use `cancel_mapping_run(run_id)` if something goes wrong and the user wants to abort.

Typical durations:
- 1-5 repos: 3-10 minutes
- 10-50 repos: 15-30 minutes
- Cloud accounts: 10-20 minutes per account

### Step 5 — Inspect results

Once status is `completed`, find the graph:

```
list_repositories()        → find the repo (match source_graph_id to the run, or look for the newest)
list_branches(repo_id)     → get the main branch
get_branch(repo_id, branch_id)  → see node/edge counts
search_nodes(repo_id, "...")     → find resources by name substring (use short terms like "postgres", not phrases)
```

Report the final graph stats to the user (node count, edge count).

### Step 6 — Next steps (suggest to user)

After mapping completes, suggest these follow-up actions:

1. **Run attack path analysis** to discover attack paths:
   ```
   run_inference(branch_id)
   ```

2. **Triage attack paths** — review and validate findings:
   ```
   list_attack_paths()
   ```

3. **Match threat model templates** — check for known attack patterns:
   ```
   oracle_load_branch(branch_id)
   oracle_tm_list_templates()
   oracle_tm_load_template("iam-privilege-escalation")
   oracle_tm_match_refine()
   ```

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| "Repository not accessible without a VCS credential" | No GitHub PAT/App in the credential profile | Add a GitHub credential in **Settings → Credentials** under the correct profile |
| "No scope target is accessible" | None of the targets could be reached | Check credential profile name and that credentials are verified in the portal |
| 401 Unauthorized | Bad or expired API key | Generate a new key in **API & MCP** and update `.mcp.json` |
| 422 Unprocessable Entity | Invalid request body | Check that cloud_accounts entries have `provider` and `account_id` fields |
| Timeout / stuck in `routing` | Large scope takes time for the planner | Wait — routing 50+ repos can take 2-5 minutes. Only flag if stuck >10 minutes |

## Important notes

- For production scheduled scans, use `trigger_scan` instead of `create_mapping_run` — it adds dedup and rate limiting.
- The `credentials_profile` parameter must match a profile name configured in the portal. This is the most common source of errors.
- The `model` parameter uses the deployment's default model. Override only if specifically instructed by your admin.
