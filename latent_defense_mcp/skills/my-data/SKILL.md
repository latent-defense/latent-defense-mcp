---
name: my-data
description: "See everything in your Latent Defense deployment — repositories, graphs, branches, attack paths, inference runs, connectors, scan schedules. The 'what do I have?' skill."
user-invocable: true
disable-model-invocation: false
---

# My Data — Deployment Inventory

Show the user everything in their Latent Defense deployment. This is the starting point when they need to find a graph to load, review what's been mapped, or understand their deployment's current state.

Other skills reference this skill when they need the user to select a graph or branch.

## Prerequisites

- The `latent-defense` MCP server must be connected

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

| Tool | Purpose |
|------|---------|
| `list_repositories()` | All infrastructure graphs with node/edge counts |
| `list_branches(repo_id)` | Branches within a repository |
| `list_commits(branch_id, limit)` | Commit history for a branch |
| `infra_stats()` | Aggregate stats (repo count, total nodes/edges, attack paths) |
| `list_attack_paths(status, limit, summary)` | Attack paths by status |
| `triage_stats(repository_id)` | Path counts by status, severity, repository |
| `list_inference_runs(limit)` | Recent JEPA inference runs |
| `list_mapping_runs(limit)` | Recent mapping runs |
| `list_scan_schedules()` | Configured scan schedules |
| `list_inference_schedules()` | Configured inference schedules |
| `list_connectors()` | Data source connectors |
| `connector_health()` | Connector status |
| `list_webhooks()` | Registered triage webhooks |
| `ticket_stats()` | Remediation ticket summary |
| `trigger_stats()` | Scan trigger summary |

---

## Workflow

### Step 1 — Gather everything

Call these in parallel (they're independent):

```
infra_stats()
list_repositories()
triage_stats()
list_mapping_runs(limit=5)
list_inference_runs(limit=5)
list_scan_schedules()
list_inference_schedules()
list_connectors()
connector_health()
list_webhooks()
ticket_stats()
trigger_stats()
```

### Step 2 — Present the overview

#### Infrastructure graphs

For each repository, show:
- **Repository ID** and name
- **Node count / edge count** — how large the graph is
- **Source metadata** — what was mapped (repos, cloud accounts, etc.)
- **Status** — completed, in_progress, failed
- **Created date** — when it was first mapped
- **Branches** — call `list_branches(repo_id)` if the user wants detail

Sort by node count descending (largest first). Flag repos with 0 nodes (failed or empty mappings).

```
## Infrastructure Graphs

| Repository | Nodes | Edges | Source | Last mapped |
|------------|-------|-------|--------|-------------|
| repo_abc   | 10,790 | 25,814 | github.com/org/repo | 2026-07-07 |
| repo_def   | 2,117  | 4,260  | AWS account 123456 | 2026-07-07 |
```

#### Security posture

```
## Security Posture

Attack paths: [total] ([new] new, [validated] validated, [ticketed] ticketed, [closed] closed, [false_positive] false positive, [failed] failed)
Tickets: [total] ([patched] patched, [open] open)
```

#### Activity

```
## Recent Activity

Last 5 mapping runs: [list with status, trigger_type, date]
Last 5 inference runs: [list with status, branch, date]
```

#### Monitoring

```
## Monitoring

Scan schedules: [N] configured ([enabled] enabled)
Inference schedules: [N] configured ([enabled] enabled)
Webhooks: [N] registered
Connectors: [N] configured ([healthy] healthy)
```

### Step 3 — Help them navigate

Based on what they see:
- "Want to explore a specific graph?" → ask which repo, then suggest `/explore` with the branch_id
- "Want to run inference on a graph?" → `/rerun-inference` with the branch_id
- "Want to map something new?" → `/map`
- "Want to review attack paths?" → `/review-paths` or `/triage`
- "Want to investigate a specific finding?" → `/investigate`
- "Want to check service health?" → `/health-check`

### Helping other skills select a graph

When another skill needs a graph (e.g., `/explore`, `/research`, `/investigate`), it should direct the user here if the graph isn't specified:

"Which graph do you want to work with? Run `/my-data` to see all available graphs, or tell me the repository or branch ID."

If the user provides a repo URL or description instead of an ID, use `list_repositories()` to find the matching repo by source metadata.
