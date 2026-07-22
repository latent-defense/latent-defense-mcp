---
name: build
description: "Build automations and integrations with the Latent Defense API. Detection ingestion, webhooks, scan scheduling, and integration patterns."
user-invocable: true
disable-model-invocation: false
---

# Build — Integrations & Automations

Guide the user through building automations on top of the Latent Defense API via MCP tools. Detection ingestion from external scanners, webhook-driven alerting, scheduled scanning, and common integration patterns.

## Prerequisites

- The `latent-defense` MCP server must be connected

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Detection ingestion**: `ingest_detection(source, severity, affected_resource_type, affected_resource_id, title, cve)`
**Webhooks**: `register_webhook(url, events, template, secret, headers)`, `list_webhooks`, `delete_webhook`, `test_webhook`, `webhook_deliveries`, `validate_webhook_template`
**Scheduling**: `list_scan_schedules`, `create_inference_schedule(name, cron, branch_labels, all_branches)`, `list_inference_schedules`, `delete_inference_schedule`
**Scanning**: `trigger_scan`, `create_mapping_run`
**Connectors**: `list_connector_types`, `create_connector`, `list_connectors`, `test_connector`, `poll_connector`, `connector_health`

---

## Ask what they want to build

"What kind of integration are you building?"

### Pattern 1: Scanner → World Model enrichment

Your scanner produces findings. You want the world model to tell you which ones matter.

```
# 1. Ingest a finding from your scanner
ingest_detection(
  source="trivy",                        # or "qualys", "snyk", "guardduty", etc.
  severity="critical",                   # critical, high, medium, low, info
  affected_resource_type="python_package",
  affected_resource_id="litellm==1.83.10",
  title="CVE-2026-49468: LiteLLM auth bypass",
  cve="CVE-2026-49468"
)

# 2. The system runs JEPA inference automatically on the affected graph
# 3. New attack paths appear in the triage queue
# 4. Set up a webhook to get notified:

register_webhook(
  url="https://your-app.com/hooks/latent-defense",
  events='["new_path", "validation_complete"]',
  secret="your-hmac-secret"
)
```

**Events available**: `new_path`, `status_change`, `validation_complete`, `path_acknowledged`, `path_dispatched_to_validator`, `path_escalated_to_ticketing`, `severity_change`

### Pattern 2: Scheduled scanning + inference

Map infrastructure on a schedule and automatically discover new attack paths.

```
# List existing schedules
list_scan_schedules()

# Create an inference schedule (run JEPA on all completed branches every 12 hours)
create_inference_schedule(
  name="nightly-inference",
  cron="0 */12 * * *",
  all_branches=true
)

# Pair with a webhook to get alerts on new paths
register_webhook(
  url="https://hooks.slack.com/services/...",
  events='["new_path"]',
  template='{"text": "New attack path found: {{data.description}} (risk: {{data.risk_score}}/100)"}'
)
```

### Pattern 3: External data source connectors

Connect security tools that push data continuously (GuardDuty, Inspector, Qualys, Tenable).

```
# See available connector types
list_connector_types()

# Create a connector
create_connector(
  name="guardduty-prod",
  connector_type="aws_guardduty",
  connection_config='{"region": "us-east-1", "detector_id": "abc123"}',
  poll_config='{"interval_minutes": 15}'
)

# Test it
test_connector(connector_id)

# Check health
connector_health()
```

### Pattern 4: Custom webhook payloads

Use Jinja2 templates to format webhook payloads for any downstream system.

```
# Validate a template before registering
validate_webhook_template(
  template='{"channel": "#security", "text": "🔴 {{data.description}}\nRisk: {{data.risk_score}}/100\nDifficulty: {{data.difficulty}}"}',
  sample_event_type="new_path"
)

# Register with the validated template
register_webhook(
  url="https://hooks.slack.com/services/...",
  events='["new_path", "validation_complete"]',
  template='...',
  secret="hmac-secret-for-verification"
)
```

**Template variables**: `event_type`, `path_id`, `timestamp`, `data` (full path object for new_path events)

### Pattern 5: CI/CD integration

Trigger a mapping run on PR merge or deployment.

```
# From a CI pipeline, call the trigger endpoint:
trigger_scan(
  description="Post-merge scan of main branch",
  repositories='["https://github.com/your-org/your-repo"]',
  credentials_profile="github"
)

# The trigger endpoint adds dedup and rate limiting automatically
```

## Webhook debugging

```
# List all webhooks
list_webhooks()

# Check delivery history
webhook_deliveries(webhook_id, limit=10)

# Send a test event
test_webhook(webhook_id)
```

## After setup

- "Want to test the pipeline end-to-end? Ingest a test detection and watch for the webhook." → Run `ingest_detection` with a test finding, then check `webhook_deliveries`
- "Want to review what's been ingested?" → Run `ingest_stats()`
- "Want to see the paths that resulted from ingestion?" → Run `list_attack_paths(status="new")`
- "Need help with something more complex?" → `/latent-defense` for the full menu
