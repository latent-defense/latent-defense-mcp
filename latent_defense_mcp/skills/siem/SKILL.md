---
name: siem
description: "Set up SIEM integration — export attack paths to your SIEM via polling (CEF syslog) or webhooks (HTTP push). Supports Splunk, Sentinel, Elastic, QRadar."
user-invocable: true
disable-model-invocation: false
---

# SIEM Integration

Guide the user through integrating Latent Defense attack path data into their SIEM. Two approaches: polling with CEF syslog, or real-time webhooks via HTTP push.

## Prerequisites

- The `latent-defense` MCP server must be connected
- At least one completed mapping and inference cycle (attack paths must exist)
- Network connectivity from the deployment (webhooks) or a script host (polling) to the SIEM collector

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

| Tool | Purpose |
|------|---------|
| `register_webhook(url, events, template, secret, headers)` | Register a webhook for push-based delivery |
| `list_webhooks()` | List registered webhooks |
| `test_webhook(webhook_id)` | Send a test event |
| `webhook_deliveries(webhook_id, limit, status)` | Check delivery history |
| `validate_webhook_template(template, sample_event_type)` | Dry-validate a Jinja template |
| `delete_webhook(webhook_id)` | Remove a webhook |
| `list_attack_paths(status, limit, summary)` | Check that paths exist to export |
| `triage_stats()` | Verify paths are in validated/ticketed status |

---

## Step 1 — Check prerequisites

```
triage_stats()
list_attack_paths(status="validated", limit=5, summary=true)
```

Verify that validated or ticketed paths exist. If none: "No validated attack paths to export. Run `/research` or `/triage` first to discover and validate paths, then come back."

## Step 2 — Choose the approach

Ask the user which approach fits their SIEM:

| Approach | Best for | How it works |
|----------|----------|-------------|
| **Polling script** | QRadar, ArcSight, Splunk via syslog, any syslog receiver | Standalone Python script polls the API on a schedule, converts paths to CEF, sends via syslog |
| **Webhooks** | Splunk HEC, Elastic, Sentinel, any HTTP collector | Latent Defense pushes events to your SIEM's HTTP endpoint in real time |

---

## Approach 1: Polling Script (CEF Syslog)

### What it does

A standalone Python script that:
1. Polls the triage API for validated/ticketed attack paths
2. Converts each path to CEF (Common Event Format)
3. Sends via syslog (UDP or TCP)
4. Tracks sent paths to avoid duplicates (idempotent)

### Create a service account key

The script needs an API key with `triage:read` scope. Guide the user to create one:

"Create a service account key in your portal under **API & MCP > New Service Account**. Grant only the `triage:read` scope."

### Provide the script

Share this script with the user. It's a complete, self-contained connector:

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

---

## Approach 2: Webhooks (HTTP Push)

### Step A — Design the template

Ask the user which SIEM they use, then provide the right template:

**Splunk HEC:**
```jinja2
{"sourcetype": "latent_defense", "source": "latent-defense-triage", "event": {"path_id": "{{ path_id }}", "risk_score": {{ data.risk_score }}, "status": "{{ data.status }}", "difficulty": "{{ data.difficulty }}", "entry_node": "{{ data.entry_node }}", "target_node": "{{ data.target_node }}", "mitre_techniques": {{ data.mitre_techniques | tojson }}, "step_count": {{ data.step_count }}}}
```

**Generic JSON (Elastic, Sentinel, custom):**
```jinja2
{"event": "{{ event_type }}", "path_id": "{{ path_id }}", "risk_score": {{ data.risk_score }}, "status": "{{ data.status }}", "difficulty": "{{ data.difficulty }}", "entry_node": "{{ data.entry_node }}", "target_node": "{{ data.target_node }}", "mitre_techniques": {{ data.mitre_techniques | tojson }}, "step_count": {{ data.step_count }}, "timestamp": "{{ timestamp }}"}
```

### Step B — Validate the template

```
validate_webhook_template(
  template="<the template from above>",
  sample_event_type="new_path"
)
```

Show the user the rendered output. If it has errors, fix the template and re-validate.

### Step C — Register the webhook

```
register_webhook(
  url="https://siem.internal.example.com/api/events",
  events='["new_path", "validation_complete", "status_change"]',
  template="<the validated template>",
  secret="<user's HMAC secret>"
)
```

Available events: `new_path`, `status_change`, `validation_complete`, `path_acknowledged`, `path_dispatched_to_validator`, `severity_change`.

### Step D — Test the webhook

```
test_webhook(webhook_id)
```

Check delivery status. If it fails, troubleshoot:
- 4xx: SIEM endpoint misconfigured or template produces invalid payload
- 5xx: SIEM is down or overloaded
- Connection refused: firewall blocking, or wrong URL

```
webhook_deliveries(webhook_id, limit=5)
```

### Step E — Verify signature (recommend to user)

Every delivery includes an `X-LD-Signature-256` header with HMAC-SHA256 of the body. Share this verification snippet:

```python
import hashlib, hmac

def verify_signature(body: bytes, signature_header: str, secret: str) -> bool:
    expected = hmac.HMAC(secret.encode(), body, hashlib.sha256).hexdigest()
    received = signature_header.removeprefix("sha256=")
    return hmac.compare_digest(expected, received)
```

---

## SIEM-specific notes

| SIEM | Approach | Notes |
|------|----------|-------|
| **QRadar** | Polling (CEF syslog) | Native CEF parsing. Auto-discovers log source after first events. |
| **Splunk** | Webhook (HEC) | Point webhook at `https://splunk:8088/services/collector/event`. Include HEC token in headers. |
| **Sentinel** | Webhook (Data Collector API) | URL: `https://<workspace-id>.ods.opinsights.azure.com/api/logs`. Set `Log-Type: LatentDefense` header. |
| **Elastic** | Either | Webhook to `/_bulk` endpoint (NDJSON), or polling script writing JSON lines for Filebeat. |

## After setup

- "Want to review which paths are being exported?" → `/review-paths`
- "Want to set up recurring scans so new paths are discovered automatically?" → `/monitor`
- "Want to build other integrations?" → `/build`
- "Not sure what to do next?" → `/latent-defense`
