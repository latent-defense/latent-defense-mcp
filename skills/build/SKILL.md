---
name: build
description: "Build integrations, set up monitoring, and configure SIEM exports. Webhooks, scan schedules, inference schedules, detection ingestion, connectors, and SIEM integration."
user-invocable: true
disable-model-invocation: false
---

# Build — Integrations, Monitoring & SIEM

One skill for building automations on top of the Latent Defense platform. Three modes:

1. **Integrations** — webhooks, detection ingestion, connectors, CI/CD triggers, custom automations
2. **Monitoring** — scan schedules, inference schedules, webhook alerts, health checks
3. **SIEM** — export attack paths to your SIEM via polling (CEF syslog) or webhooks (HTTP push)

## Prerequisites

- The `latent-defense` MCP server must be connected
- For monitoring and SIEM modes: at least one infrastructure repository should exist (run `/map` first)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Detection ingestion**: `ingest_detection(source, severity, affected_resource_type, affected_resource_id, title, cve)`
**Webhooks**: `register_webhook(url, events, template, secret, headers)`, `list_webhooks`, `delete_webhook`, `test_webhook`, `webhook_deliveries`, `validate_webhook_template`
**Scheduling**: `list_scan_schedules`, `run_scan_schedule`, `create_inference_schedule(name, cron, branch_labels, all_branches)`, `list_inference_schedules`, `delete_inference_schedule`
**Scanning**: `create_mapping_run`
**Connectors**: `list_connector_types`, `create_connector`, `list_connectors`, `test_connector`, `poll_connector`, `connector_health`
**Health**: `trigger_stats`, `triage_stats`, `ingest_stats`
**Paths**: `list_attack_paths`

---

## Detect the user's intent

If the user's request clearly maps to a mode, go directly there. Otherwise, ask:

"What would you like to set up?"
1. **Integrations** — connect scanners, webhooks, CI/CD pipelines, or data source connectors
2. **Monitoring** — recurring scans, inference schedules, and alert webhooks
3. **SIEM** — export attack paths to Splunk, Sentinel, Elastic, QRadar, or another SIEM

Auto-detect based on keywords:
- "scan schedule", "inference schedule", "recurring", "automated", "alerts", "notifications" → Monitoring
- "SIEM", "Splunk", "Sentinel", "Elastic", "QRadar", "syslog", "CEF" → SIEM
- "webhook", "ingestion", "connector", "CI/CD", "integration", "scanner" → Integrations

---

## Mode 1: Integrations

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

**Events available**: `new_path`, `status_change`, `validation_complete`, `path_acknowledged`, `path_dispatched_to_validator`, `severity_change`

### Pattern 2: External data source connectors

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

### Pattern 3: Custom webhook payloads

Use Jinja2 templates to format webhook payloads for any downstream system.

```
# Validate a template before registering
validate_webhook_template(
  template='{"channel": "#security", "text": "{{data.description}}\nRisk: {{data.risk_score}}/100\nDifficulty: {{data.difficulty}}"}',
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

### Pattern 4: CI/CD integration

Trigger a mapping run on PR merge or deployment.

```
# From a CI pipeline:
create_mapping_run(
  description="Post-merge scan of main branch",
  repositories='["https://github.com/your-org/your-repo"]',
  credentials_profile="github"
)

# The trigger endpoint adds dedup and rate limiting automatically
```

### Webhook debugging

```
# List all webhooks
list_webhooks()

# Check delivery history
webhook_deliveries(webhook_id, limit=10)

# Send a test event
test_webhook(webhook_id)
```

---

## Mode 2: Monitoring

Set up recurring infrastructure scans, inference runs, and webhook-based alerting so attack paths are discovered and surfaced automatically.

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
   - `path_acknowledged` — a path was acknowledged
   - `path_dispatched_to_validator` — a path was sent for sandbox validation
   - `severity_change` — a path's severity changed

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

5. Test the webhook: `test_webhook(webhook_id)`.

6. Check delivery history: `webhook_deliveries(webhook_id, limit=10)` to see recent deliveries and their success/failure status.

### Step 5 — Review data source health

Call `connector_health()` and `trigger_stats()` in parallel.

Report any unhealthy or degraded connectors. For unhealthy connectors, the `last_poll_error` explains what went wrong (usually credential expiry or network issues).

Report any concerning trigger stats: failed events, rate limiting, low headroom.

### Step 6 — Monitoring summary

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

### The trigger pipeline

Scans flow automatically through the pipeline: trigger → graph update → inference → triage.

Scan schedules feed the top of this pipeline. Inference schedules feed the middle (inference only, no re-scan). Triage webhooks fire at the end when paths are discovered.

---

## Mode 3: SIEM

Export attack path data to your SIEM. Two approaches: polling with CEF syslog, or real-time webhooks via HTTP push.

### Step 1 — Check prerequisites

```
triage_stats()
list_attack_paths(status="validated", limit=5, summary=true)
```

Verify that validated or ticketed paths exist. If none: "No validated attack paths to export. Run `/research` or `/triage` first to discover and validate paths, then come back."

### Step 2 — Choose the approach

Ask the user which approach fits their SIEM:

| Approach | Best for | How it works |
|----------|----------|-------------|
| **Polling script** | QRadar, ArcSight, Splunk via syslog, any syslog receiver | Standalone Python script polls the API on a schedule, converts paths to CEF, sends via syslog |
| **Webhooks** | Splunk HEC, Elastic, Sentinel, any HTTP collector | Latent Defense pushes events to your SIEM's HTTP endpoint in real time |

### Approach A: Polling Script (CEF Syslog)

A standalone Python script that:
1. Polls the triage API for validated/ticketed attack paths
2. Converts each path to CEF (Common Event Format)
3. Sends via syslog (UDP or TCP)
4. Tracks sent paths to avoid duplicates (idempotent)

**Service account key**: The script needs an API key with `triage:read` scope. Guide the user to create one: "Create a service account key in your portal under **API & MCP > New Service Account**. Grant only the `triage:read` scope."

**Provide the script**:

```python
#!/usr/bin/env python3
"""Latent Defense -> SIEM connector.

Polls for validated/ticketed attack paths, converts to CEF, sends via syslog.
Requires: Python 3.9+, requests (pip install requests).
"""

import json, logging, os, socket, sys, time
from datetime import datetime, timezone
from pathlib import Path
import requests

# --- CONFIGURATION ---
PORTAL_URL = "https://portal.your-deployment.com"
API_KEY = "sk_ld_svc_..."
SIEM_HOST = "siem.internal.example.com"
SIEM_PORT = 514
SIEM_PROTOCOL = "udp"  # "udp" or "tcp"
POLL_INTERVAL_SECONDS = 300
STATE_FILE = ".ld-siem-state.json"
# --- END CONFIGURATION ---

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ld-siem")

SESSION = requests.Session()
SESSION.headers.update({"Authorization": f"Bearer {API_KEY}", "Accept": "application/json"})

def load_state():
    path = Path(STATE_FILE)
    if path.exists():
        try: return json.loads(path.read_text())
        except: pass
    return {"sent": {}}

def save_state(state):
    tmp = Path(STATE_FILE + ".tmp")
    tmp.write_text(json.dumps(state, indent=2))
    tmp.rename(STATE_FILE)

def fetch_paths():
    resp = SESSION.get(f"{PORTAL_URL}/api/triage/paths", params={"status": "validated,ticketed"}, timeout=30)
    resp.raise_for_status()
    return resp.json().get("items", [])

def risk_to_severity(risk_score):
    if risk_score >= 75: return 10
    if risk_score >= 50: return 7
    if risk_score >= 25: return 5
    return 3

def build_cef(path):
    pid = path.get("path_id", "unknown")
    risk = path.get("risk_score", 0)
    sev = risk_to_severity(risk)
    name = f"{path.get('entry_node', '?')} -> {path.get('target_node', '?')}"
    header = f"CEF:0|Latent Defense|Attack Path|1.0|{pid}|{name}|{sev}|"
    ext = " ".join([
        f"risk={risk}", f"mitreTechniques={','.join(path.get('mitre_techniques', []))}",
        f"difficulty={path.get('difficulty', '?')}", f"status={path.get('status', '?')}",
        f"entryNode={path.get('entry_node', '?')}", f"targetNode={path.get('target_node', '?')}",
        f"stepCount={path.get('step_count', 0)}"
    ])
    return f"{header}{ext}"

def send_syslog(message):
    msg = f"<134>{datetime.now(timezone.utc).strftime('%b %d %H:%M:%S')} latent-defense {message}".encode()
    if SIEM_PROTOCOL == "tcp":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(10); s.connect((SIEM_HOST, SIEM_PORT)); s.sendall(msg + b"\n")
    else:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(msg, (SIEM_HOST, SIEM_PORT))

def main():
    log.info("Starting: Portal=%s SIEM=%s:%d/%s", PORTAL_URL, SIEM_HOST, SIEM_PORT, SIEM_PROTOCOL)
    while True:
        state = load_state()
        paths = fetch_paths()
        new = 0
        for p in paths:
            key = f"{p.get('path_id')}:{p.get('updated_at')}"
            if key not in state["sent"]:
                send_syslog(build_cef(p))
                state["sent"][key] = datetime.now(timezone.utc).isoformat()
                new += 1
        save_state(state)
        log.info("Cycle: %d new, %d tracked", new, len(state["sent"]))
        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    main()
```

Tell the user to:
1. Replace `PORTAL_URL`, `API_KEY`, `SIEM_HOST`, `SIEM_PORT` with their values
2. Test with `python3 ld_siem_connector.py` (point at localhost + `nc -u -l 514` to see CEF output)
3. Deploy as a systemd service or cron job for production

### Approach B: Webhooks (HTTP Push)

#### Design the template

Ask the user which SIEM they use, then provide the right template:

**Splunk HEC:**
```jinja2
{"sourcetype": "latent_defense", "source": "latent-defense-triage", "event": {"path_id": "{{ path_id }}", "risk_score": {{ data.risk_score }}, "status": "{{ data.status }}", "difficulty": "{{ data.difficulty }}", "entry_node": "{{ data.entry_node }}", "target_node": "{{ data.target_node }}", "mitre_techniques": {{ data.mitre_techniques | tojson }}, "step_count": {{ data.step_count }}}}
```

**Generic JSON (Elastic, Sentinel, custom):**
```jinja2
{"event": "{{ event_type }}", "path_id": "{{ path_id }}", "risk_score": {{ data.risk_score }}, "status": "{{ data.status }}", "difficulty": "{{ data.difficulty }}", "entry_node": "{{ data.entry_node }}", "target_node": "{{ data.target_node }}", "mitre_techniques": {{ data.mitre_techniques | tojson }}, "step_count": {{ data.step_count }}, "timestamp": "{{ timestamp }}"}
```

#### Validate, register, test

```
# Validate the template
validate_webhook_template(template="<template>", sample_event_type="new_path")

# Register the webhook
register_webhook(
  url="https://siem.internal.example.com/api/events",
  events='["new_path", "validation_complete", "status_change"]',
  template="<validated template>",
  secret="<user's HMAC secret>"
)

# Test it
test_webhook(webhook_id)

# Check delivery history
webhook_deliveries(webhook_id, limit=5)
```

Available events: `new_path`, `status_change`, `validation_complete`, `path_acknowledged`, `path_dispatched_to_validator`, `severity_change`.

#### Verify signature (recommend to user)

Every delivery includes an `X-LD-Signature-256` header with HMAC-SHA256 of the body. Share this verification snippet:

```python
import hashlib, hmac

def verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    expected = hmac.HMAC(secret.encode(), body, hashlib.sha256).hexdigest()
    received = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)
```

### SIEM-specific notes

| SIEM | Approach | Notes |
|------|----------|-------|
| **QRadar** | Polling (CEF syslog) | Native CEF parsing. Auto-discovers log source after first events. |
| **Splunk** | Webhook (HEC) | Point webhook at `https://splunk:8088/services/collector/event`. Include HEC token in headers. |
| **Sentinel** | Webhook (Data Collector API) | URL: `https://<workspace-id>.ods.opinsights.azure.com/api/logs`. Set `Log-Type: LatentDefense` header. |
| **Elastic** | Either | Webhook to `/_bulk` endpoint (NDJSON), or polling script writing JSON lines for Filebeat. |

---

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| 422 on `create_inference_schedule` | Invalid cron expression or missing scope | Use standard 5-field cron (e.g. `0 3 * * *`) and set `all_branches=true` or `branch_labels` |
| 422 on `register_webhook` | Invalid event type or malformed events JSON | Events must be a JSON array of strings from the supported set |
| 422 on `validate_webhook_template` | Jinja2 syntax error in template | Fix the template syntax and re-validate |
| Test webhook returns non-2xx | Target endpoint rejected the delivery | Check the URL, auth headers, and that the endpoint accepts POST |

## After setup

- "Want to test the pipeline end-to-end? Ingest a test detection and watch for the webhook." → Run `ingest_detection` with a test finding, then check `webhook_deliveries`
- "Want to review what's been ingested?" → Run `ingest_stats()`
- "Want to see the paths that resulted from ingestion?" → Run `list_attack_paths(status="new")`
- "Want to review existing attack paths?" → `/triage`
- "Want to explore the graph?" → `/explore`
- "Not sure what to do?" → `/latent-defense` for the full menu
