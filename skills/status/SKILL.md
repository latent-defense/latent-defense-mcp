---
name: status
description: "Deployment health check. Default: compact dashboard. Use `/status deep` for full validation of auth, connectors, repositories, and service health."
user-invocable: true
disable-model-invocation: false
---

# Status — Deployment Health Dashboard

Two modes:
- **Default** (`/status`): compact dashboard, completes in under 30 seconds
- **Deep** (`/status deep`): full deployment validation — auth, connectors, repositories, service reachability

Detect which mode the user wants. If they say "deep", "full", "detailed", "validate", or "health check", run deep mode. Otherwise run default mode.

## Prerequisites

- The `latent-defense` MCP server must be connected

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

---

## Default Mode — Compact Dashboard

### Gather data

Call ALL of these in parallel (they are independent):

1. `infra_stats()` — infrastructure graph size
2. `list_mapping_runs(limit=5)` — recent mapping scans
3. `list_inference_runs(limit=5)` — recent attack path analysis runs
4. `trigger_stats()` — trigger pipeline health
5. `triage_stats()` — attack path counts by status
6. `ingest_stats()` — data source ingestion stats
7. `connector_health()` — connector health summary

### Present the dashboard

Format as a compact dashboard. One section per area, 1-2 lines each. Highlight anything that needs attention.

**Infrastructure**
- `infra_stats` fields: `repositories`, `branches_total`, `branches_completed`, `attack_paths`, `total_nodes`, `total_edges`
- Example: "30 repositories (12,450 nodes, 28,300 edges), 92 branches, 114 attack paths"

**Recent Mapping Runs**
- `list_mapping_runs` returns array of:
  ```json
  {
    "map_run_id": "run_abc",
    "status": "completed",
    "trigger_type": "manual",
    "total_agents": 5,
    "agents_completed": 5,
    "created_at": "2026-06-23T02:00:00Z"
  }
  ```
- Show last 3 runs: status, trigger type, timestamp
- Flag any `failed` runs

**Recent Inference Runs**
- `list_inference_runs` returns array of:
  ```json
  {
    "run_id": "inference_run_abc",
    "branch_id": "branch_main",
    "status": "completed",
    "phase": "completed",
    "trigger_source": "map_complete",
    "created_at": "2026-06-23T02:15:00Z"
  }
  ```
- Show last 3 runs: status, branch, trigger source, timestamp
- A `null` phase on a pending run is normal — the phase populates once analysis begins
- Flag any `failed` runs

**Trigger Pipeline**
- `trigger_stats` fields: `total_events`, `events_last_hour`, `active_runs`, `deduplicated`, `rate_limited`, `failed`, `max_concurrent_runs`, `headroom`
- Example: "142 total events, 3 in last hour. 1 active run (4 headroom). 2 failed."
- Flag `failed > 0` or `headroom == 0`

**Security Posture**
- `triage_stats` fields: `total`, `by_status` dict
- Example: "47 paths total: 12 new, 5 acknowledged, 2 validating, 8 validated, 10 ticketed, 7 closed"
- Flag `by_status.new > 0` as "N paths need triage"

**Data Sources**
- `ingest_stats` fields: `total_artifacts`, `by_type` dict, `by_source` dict
- `connector_health` returns sorted list with `health`, `name`, `connector_type`, `last_poll_error`
- Example: "3 connectors (2 healthy, 1 unhealthy). 1,247 artifacts ingested."
- Flag any `unhealthy` or `degraded` connectors by name and error

### Highlight issues

At the end, list anything that needs attention:
- Failed mapping or inference runs
- Unhealthy connectors with their error messages
- New attack paths awaiting triage
- Rate-limited or failed trigger events
- Zero headroom in the trigger pipeline

If everything is healthy, say: "All systems operational. No issues detected."

---

## Deep Mode — Full Deployment Validation

Run the default dashboard first (all the above), then continue with the additional validation steps below.

### Step 1 — Verify authentication and connectivity

Call `whoami()` and `connection_status()` in parallel.

`whoami()` confirms your identity and token:
- If authenticated: show email, auth method, scopes, and token expiry
- If not authenticated: guide the user to re-authenticate (see the README for setup instructions)

`connection_status()` tests reachability of every backend service:
- Report each service status (Infrastructure Graph, Mapping, Scan Trigger, Inference, Triage, Connectors, Validator)
- Flag any services showing errors or unreachable

If authentication fails, note the failure but continue with other checks — partial results are still useful.

### Step 2 — Repository validation

Call `list_repositories()`.

`list_repositories()` returns a JSON array of repositories. Each has:
- `repository_id` / `id` — unique identifier
- `name` — display name
- `node_count`, `edge_count` — graph size

Show a summary table: name, node count, edge count. Check that branches have nodes — a repository with branches but zero nodes may indicate a failed or incomplete mapping run.

If no repositories exist, tell the user they need to run `/map` to scan their infrastructure.

### Step 3 — Connector details

Call `list_connectors()` and `list_connector_types()` in parallel.

`list_connectors()` returns configured connectors with:
- `id`, `name`, `connector_type`
- `enabled` — whether polling is active
- `health` — one of `healthy`, `degraded`, `unhealthy`, `disabled`
- `last_poll_at`, `last_poll_status`, `last_poll_error`

`list_connector_types()` returns available connector types with:
- `type` — e.g. `aws_guardduty`, `aws_inspector`, `qualys`, `tenable`
- `description` — what the connector does

For each configured connector, test it:

```
test_connector(connector_id)
```

Report detailed results: health, last poll time, last error, test result. If any connectors are unhealthy, show the specific `last_poll_error` (usually credential expiry or network issues).

If no connectors are configured, suggest adding connectors for the user's security tools and list the available types.

### Step 4 — Ticketing note

Ticketing is handled through native IDE integrations (Linear, Jira, GitHub Issues). If the user needs ticketing, suggest they configure it through their IDE's native integration rather than through the MCP server.

### Step 5 — Deep mode summary

Present a full deployment health report:

| Area | Status | Details |
|------|--------|---------|
| Authentication | OK/FAIL | email, scopes, expiry |
| Services | N/M reachable | list any unreachable |
| Repositories | N repos, X nodes | list any with 0 nodes |
| Connectors | N healthy, M unhealthy | list unhealthy with errors |
| Security Posture | N paths (X new) | breakdown by status |
| Pipeline | healthy/degraded | active runs, headroom, failures |

### Suggest next steps based on findings

| Condition | Suggestion |
|-----------|-----------|
| Authentication failed | Re-authenticate: regenerate API key in portal, update `.mcp.json` |
| Services unreachable | Check deployment health in portal admin panel |
| No repositories | "Run `/map` to scan your infrastructure" |
| Repositories with 0 nodes | "Re-run `/map` — these repos may have had mapping failures" |
| Repos exist, no attack paths | "Run `/research` to discover attack paths" |
| Attack paths exist, none triaged | "Run `/triage` to review and validate findings" |
| Unhealthy connectors | Fix credentials or network config in portal |
| Everything healthy | "Deployment is fully operational." |

---

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| 403 Forbidden | API key lacks required scopes | Check key permissions in portal |
| Connection refused | MCP server cannot reach deployment | Verify portal URL in `.mcp.json` |
| Any tool returning an error | That specific service may be down | Report the service as unreachable; continue with other tools |

If any individual tool call fails, report that section as "unavailable" and continue with the rest. Neither mode should fail entirely because one backend service is down.

## Next steps

Based on what the dashboard shows:
- New attack paths to review → `/triage`
- No infrastructure mapped yet → `/map`
- Want to explore the graph → `/explore`
- Need to set up monitoring or integrations → `/build`
- Not sure what to do → `/latent-defense` for the full menu
