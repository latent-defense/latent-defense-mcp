---
name: status
description: "Quick deployment health check. Shows service health, infrastructure stats, recent activity, security posture, and remediation status in a compact dashboard."
user-invocable: true
disable-model-invocation: false
---

# Status — Deployment Health Dashboard

Run a quick health check across all Latent Defense components. Designed to complete in under 30 seconds.

## Prerequisites

- The `latent-defense` MCP server must be connected

## Workflow

### Gather data

Call ALL of these in parallel (they are independent):

1. `infra_stats()` — infrastructure graph size
2. `list_mapping_runs(limit=5)` — recent mapping scans
3. `list_inference_runs(limit=5)` — recent attack path analysis runs
4. `trigger_stats()` — trigger pipeline health
5. `triage_stats()` — attack path counts by status
6. `ticket_stats()` — remediation ticket counts
7. `ingest_stats()` — data source ingestion stats
8. `connector_health()` — connector health summary

### Present the dashboard

Format as a compact dashboard. One section per area, 1-2 lines each. Highlight anything that needs attention.

**Infrastructure**
- `infra_stats` fields: `repositories`, `branches_total`, `branches_completed`, `attack_paths`
- Example: "30 repositories, 92 branches, 114 attack paths"

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
- Example: "47 paths total: 12 new, 5 acknowledged, 2 validating, 8 validated, 3 escalated, 10 ticketed, 7 closed"
- Flag `by_status.new > 0` as "N paths need triage"

**Remediation**
- `ticket_stats` fields: `total`, `patched`, `by_status` dict, `mean_iterations`, `by_outcome` dict, `failed_by_stage` dict
- Example: "15 tickets (8 patched, 4 failed). Mean 1.8 iterations."
- Flag `by_status.failed > 0` and show `failed_by_stage` breakdown

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
- Failed remediation tickets
- Rate-limited or failed trigger events
- Zero headroom in the trigger pipeline

If everything is healthy, say: "All systems operational. No issues detected."

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| Any tool returning an error | That specific service may be down | Report the service as unreachable in the dashboard; continue with other tools |

If any individual tool call fails, report that section as "unavailable" and continue with the rest. The dashboard should never fail entirely because one backend service is down.
