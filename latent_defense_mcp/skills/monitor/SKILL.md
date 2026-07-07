---
name: monitor
description: "Set up ongoing automated scanning, inference, and alerting. Configure scan schedules, inference schedules, and triage webhooks."
user-invocable: true
disable-model-invocation: false
---

# Monitor — Automated Scanning and Alerting

Configure recurring infrastructure scans, inference runs, and webhook-based alerting so attack paths are discovered and surfaced automatically.

## Prerequisites

- The `latent-defense` MCP server must be connected
- At least one infrastructure repository should exist (run `/map` first)

## Quick reference — tool names

### Scan schedules

| Tool | What it does |
|------|-------------|
| `list_scan_schedules()` | List all recurring mapping scan schedules |
| `run_scan_schedule(schedule_id)` | Manually trigger a scheduled scan to run now |

### Inference schedules

| Tool | What it does |
|------|-------------|
| `list_inference_schedules()` | List inference schedules |
| `create_inference_schedule(name, cron, branch_labels, all_branches)` | Create a recurring inference schedule |
| `delete_inference_schedule(schedule_id)` | Delete an inference schedule |

### Triage webhooks

| Tool | What it does |
|------|-------------|
| `register_webhook(url, events, template, secret, headers)` | Register a webhook for attack path events |
| `list_webhooks()` | List registered webhooks |
| `delete_webhook(webhook_id)` | Delete a webhook |
| `test_webhook(webhook_id)` | Send a synthetic test event |
| `validate_webhook_template(template, sample_event_type)` | Validate a Jinja2 template without registering |
| `webhook_deliveries(webhook_id, limit, status)` | View delivery history for a webhook |

### Health

| Tool | What it does |
|------|-------------|
| `connector_health()` | Data source connector health summary |
| `trigger_stats()` | Trigger service stats (active runs, rate limiting) |

## Workflow

### Step 1 — Review current automation

Call these in parallel:
- `list_scan_schedules()`
- `list_inference_schedules()`
- `list_webhooks()`

**Scan schedules** return:
```json
[
  {
    "schedule_id": "sched_daily_prod",
    "name": "daily-prod-scan",
    "cron": "0 2 * * *",
    "credentials_profile": "default",
    "enabled": true,
    "next_run": "2026-06-24T02:00:00Z",
    "warning": null
  }
]
```

**Inference schedules** return:
```json
[
  {
    "schedule_id": "inf_sched_abc",
    "name": "nightly-inference",
    "cron": "0 3 * * *",
    "scope": { "all_branches": true },
    "enabled": true,
    "next_run": "2026-06-24T03:00:00Z"
  }
]
```

**Webhooks** return:
```json
[
  {
    "webhook_id": "wh_abc123",
    "url": "https://hooks.slack.com/services/...",
    "events": ["new_path", "validation_complete"],
    "created_at": "2026-06-15T10:00:00Z"
  }
]
```

Present a summary table of what is configured.

### Step 2 — Configure scan schedules (if needed)

Scan schedules are managed through the portal. The MCP server provides read-only access (`list_scan_schedules`) and manual trigger (`run_scan_schedule`).

If no scan schedules exist, explain:
- Schedules are configured in the portal under **Settings > Schedules**
- Recommend a daily scan at off-peak hours (e.g. `0 2 * * *` for 2 AM UTC)
- Webhook-based scanning (GitHub push events trigger automatic scans) is configured via GitHub App in the portal

If schedules exist but the user wants to trigger one immediately: `run_scan_schedule(schedule_id)`.

### Step 3 — Configure inference schedules

If no inference schedules exist, set one up:

1. Ask: "Which branches should the attack path model analyze? All branches, or specific ones?"

2. Ask: "How often? Recommendation: run inference after every scan completes. A daily schedule at 3 AM (one hour after a 2 AM scan) works well."

3. Create the schedule:

   **All branches, daily at 3 AM:**
   ```
   create_inference_schedule(
     name="nightly-inference",
     cron="0 3 * * *",
     all_branches=true
   )
   ```

   **Specific branches by label:**
   ```
   create_inference_schedule(
     name="prod-inference",
     cron="0 3 * * *",
     branch_labels='["production", "staging"]'
   )
   ```

   Returns the created schedule with `schedule_id`.

Note: When a mapping scan completes, inference automatically runs on the scanned branch (this is the `auto_run_on_map_complete` feature, enabled by default). The schedule is a safety net for branches that don't change often.

### Step 4 — Configure alert webhooks

If no webhooks exist, set one up:

1. Ask: "Where should attack path alerts go? Common options: Slack webhook URL, PagerDuty events API, or a custom HTTP endpoint."

2. Ask which events to subscribe to. Available event types:
   - `new_path` — a new attack path was discovered
   - `status_change` — a path's triage status changed
   - `validation_complete` — sandbox validation finished

3. **Optionally customize the payload** with a Jinja2 template. Default is the full event JSON. Template variables:
   - `{{ event_type }}` — event type string (e.g., "new_path")
   - `{{ path_id }}` — attack path ID
   - `{{ timestamp }}` — ISO timestamp
   - `{{ data }}` — event payload (for `new_path` events, this is the full path object with fields like `data.entry_node`, `data.target_node`, `data.risk_score`, `data.mitre_techniques`)

   Example Slack template:
   ```
   {"text": "Attack path found: {{ data.entry_node }} → {{ data.target_node }} (risk: {{ data.risk_score }}). {{ data.step_count }} steps via {{ data.mitre_techniques | join(', ') }}"}
   ```

   Validate before registering:
   ```
   validate_webhook_template(
     template='{"text": "Attack path: {{ data.entry_node }} → {{ data.target_node }}"}',
     sample_event_type="new_path"
   )
   ```

   Returns `{"valid": true, "rendered": "..."}` or `{"valid": false, "error": "..."}`.

4. Register the webhook:
   ```
   register_webhook(
     url="https://hooks.slack.com/services/T00/B00/xxx",
     events='["new_path", "validation_complete"]',
     template='{"text": "Attack path: {{ data.entry_node }} → {{ data.target_node }} (risk {{ data.risk_score }})"}',
     secret="optional-hmac-secret"
   )
   ```

   Returns:
   ```json
   {
     "webhook_id": "wh_abc123",
     "url": "https://hooks.slack.com/...",
     "events": ["new_path", "validation_complete"],
     "created_at": "2026-06-23T12:00:00Z"
   }
   ```

5. Test the webhook: `test_webhook(webhook_id)`.

   Returns delivery result with per-attempt status codes. If the test fails, check the URL and any authentication headers.

6. Check delivery history: `webhook_deliveries(webhook_id, limit=10)` to see recent deliveries and their success/failure status.

### Step 5 — Review data source health

Call `connector_health()`.

Returns connectors sorted unhealthy-first:
```json
[
  {
    "connector_id": "conn_abc",
    "name": "aws-guardduty-prod",
    "connector_type": "aws_guardduty",
    "health": "unhealthy",
    "enabled": true,
    "last_poll_at": "2026-06-22T14:00:00Z",
    "last_poll_error": "InvalidAccessKeyId: The AWS Access Key Id does not exist"
  },
  {
    "connector_id": "conn_def",
    "name": "qualys-scanner",
    "connector_type": "qualys",
    "health": "healthy",
    "enabled": true,
    "last_poll_at": "2026-06-23T08:00:00Z",
    "last_poll_error": null
  }
]
```

Report any unhealthy or degraded connectors. For unhealthy connectors, the `last_poll_error` explains what went wrong (usually credential expiry or network issues).

Also call `trigger_stats()`:
```json
{
  "total_events": 142,
  "events_last_hour": 3,
  "active_runs": 1,
  "deduplicated": 12,
  "rate_limited": 0,
  "failed": 2,
  "max_concurrent_runs": 5,
  "headroom": 4
}
```

Report any concerning stats: failed events, rate limiting, low headroom.

### Step 6 — Summary

Present the full automation setup:
- Scan schedules: N configured, next run at ...
- Inference schedules: N configured, covering N branches
- Webhooks: N registered, targeting [Slack/PagerDuty/custom]
- Connectors: N healthy, M unhealthy
- Trigger pipeline: N events/hour, M active runs

Recommend minimum setup:
- 1 daily scan schedule
- 1 inference schedule (or rely on auto_run_on_map_complete)
- 1 webhook for `new_path` events
- All connectors healthy

## The trigger pipeline

Scans flow automatically through the pipeline: trigger → graph update → inference → triage.

Scan schedules feed the top of this pipeline. Inference schedules feed the middle (inference only, no re-scan). Triage webhooks fire at the end when paths are discovered.

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| 422 on `create_inference_schedule` | Invalid cron expression or missing scope | Use standard 5-field cron (e.g. `0 3 * * *`) and set `all_branches=true` or `branch_labels` |
| 422 on `register_webhook` | Invalid event type or malformed events JSON | Events must be a JSON array of strings from the supported set |
| 422 on `validate_webhook_template` | Jinja2 syntax error in template | Fix the template syntax and re-validate |
| Test webhook returns non-2xx | Target endpoint rejected the delivery | Check the URL, auth headers, and that the endpoint accepts POST |
