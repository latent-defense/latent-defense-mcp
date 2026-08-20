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

## Steps

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

### Step 2 — Credential profile

All mapping runs use the `default` credential profile. This profile is configured in the customer's deployment with all necessary credentials (GitHub, AWS, Azure, GCP). Do not ask the user to specify a profile — always use `"default"`.

### Step 3 — Create the mapping run

Call `create_mapping_run` with the scope. **Always use `credentials_profile="default"`** — this is the profile configured in the customer's deployment.

**The `description` field is a planner prompt, not just a label.** Use it to guide what the mapper focuses on. Include:
- What aspects of the infrastructure to prioritize
- Specific areas to map deeply (CI/CD, credential handling, Docker architecture, IAM, etc.)
- The goal of the mapping (security analysis, compliance review, etc.)

**Repositories:**
```
create_mapping_run(
  description="Map the ACME API service repository with focus on: 1) CI/CD pipeline infrastructure — GitHub Actions workflows, secrets, OIDC federation 2) Authentication and credential handling — how API keys and tokens flow between services 3) Docker container configuration — Dockerfiles, compose files, runtime security 4) Dependency tree with attention to supply chain risk surface 5) API endpoints and authentication boundaries",
  repositories='["https://github.com/acme/api-service"]',
  credentials_profile="default"
)
```

**Cloud account:**
```
create_mapping_run(
  description="Map AWS production account focusing on: IAM role relationships and trust policies, S3 bucket access patterns, Lambda execution roles, VPC and security group configuration, cross-service credential chains",
  cloud_accounts='[{"provider": "aws", "account_id": "123456789012", "regions": ["us-east-1", "us-west-2"]}]',
  credentials_profile="default"
)
```

**Mixed scope:**
```
create_mapping_run(
  description="Full infrastructure mapping of ACME — map both code and cloud infrastructure, focus on how deployment pipelines connect to production resources, credential flow from CI/CD to cloud services, and trust boundaries between environments",
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
get_branch(branch_id)  → see node/edge counts
search_nodes(repo_id, "...")     → find resources by name substring (use short terms like "postgres", not phrases)
```

Report the final graph stats to the user (node count, edge count).

### Step 6 — Next steps

After mapping completes, suggest:

- "Want to explore what was mapped?" → `/explore` to browse entry points, crown jewels, security boundaries
- "Want to find attack paths?" → `/research` for proactive attack path discovery
- "Want to investigate a specific CVE or finding?" → `/investigate` with the finding
- "Want to process scanner results against this graph?" → `/triage` with scanner JSON
- "Want to run JEPA inference?" → `run_inference(branch_id)` to discover paths automatically, then `/review` to review results
- "Want to learn how to read the model's signals?" → `/tutorial`

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| "Repository not accessible without a VCS credential" | No GitHub PAT/App in the credential profile | Add a GitHub credential in **Settings → Credentials** under the correct profile |
| "No scope target is accessible" | None of the targets could be reached | Check credential profile name and that credentials are verified in the portal |
| 401 Unauthorized | Bad or expired API key | Generate a new key in **API & MCP** and update `.mcp.json` |
| 422 Unprocessable Entity | Invalid request body | Check that cloud_accounts entries have `provider` and `account_id` fields |
| Timeout / stuck in `routing` | Large scope takes time for the planner | Wait — routing 50+ repos can take 2-5 minutes. Only flag if stuck >10 minutes |

## Important notes

- For production scheduled scans, set up a scan schedule via `/build`.
- The `credentials_profile` parameter must match a profile name configured in the portal. This is the most common source of errors.
- The `model` parameter uses the deployment's default model. Override only if specifically instructed by your admin.
