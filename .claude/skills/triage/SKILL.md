---
name: triage
description: "Guided attack path triage queue. Review, validate, escalate, or dismiss attack paths discovered by inference."
user-invocable: true
disable-model-invocation: false
---

# Triage — Attack Path Queue

Work through the attack path triage queue. For each path: review the details, decide whether to validate it in a sandbox, acknowledge it, dismiss it, or escalate it to ticketing.

## Prerequisites

- The `latent-defense` MCP server must be connected
- Attack paths must exist — discovered via `/research`, `/investigate`, or batch inference after `/map`

## Quick reference — tool names

| Tool | What it does |
|------|-------------|
| `list_attack_paths(status, min_risk_score, limit, offset)` | Query attack paths with optional filters |
| `get_attack_path(path_id)` | Full path details: steps, MITRE mappings, risk score, difficulty |
| `update_path_status(path_id, status, reason)` | Change a path's triage status |
| `validate_path(path_id)` | Dispatch to sandbox validation |
| `escalate_path(path_id)` | Send a validated path to the ticketing system |
| `get_validation_status(run_id)` | Check sandbox validation progress |
| `triage_stats(repository_id)` | Aggregate counts by status |

## Workflow

### Step 1 — Load the queue

Call `list_attack_paths(status="new", limit=20)` and `triage_stats()` in parallel.

`list_attack_paths` returns:
```json
{
  "items": [
    {
      "path_id": "path_abc123",
      "entry_node": "public-api-gateway",
      "target_node": "production-database",
      "step_count": 4,
      "risk_score": 82.5,
      "difficulty": "easy",
      "mitre_techniques": ["T1190", "T1078", "T1552"],
      "status": "new",
      "source": "unconstrained",
      "repository_id": "repo_xyz",
      "branch_id": "branch_main",
      "created_at": "2026-06-20T14:30:00Z"
    }
  ],
  "total": 12,
  "limit": 20,
  "offset": 0
}
```

`triage_stats` returns:
```json
{
  "total": 47,
  "by_status": {
    "new": 12,
    "acknowledged": 5,
    "validating": 2,
    "validated": 8,
    "escalated": 3,
    "ticketed": 10,
    "closed": 7
  },
  "by_severity": { ... },
  "by_repository": { ... }
}
```

Present a summary: "12 new paths, 47 total. 8 validated, 10 ticketed, 7 closed."

Sort the queue by `risk_score` descending (highest risk first).

### Step 2 — Walk each path

For each path in the queue (highest `risk_score` first):

**2a. Load full details.** Call `get_attack_path(path_id)`.

Returns the full `TriagePath` object:
```json
{
  "path_id": "path_abc123",
  "entry_node": "public-api-gateway",
  "target_node": "production-database",
  "steps": [
    {
      "source_node": "public-api-gateway",
      "target_node": "auth-service",
      "edge_type": "exploits",
      "tactic": "initial_access",
      "technique": "T1190",
      "description": "Exploit public-facing application"
    }
  ],
  "step_count": 4,
  "risk_score": 82.5,
  "difficulty": "easy",
  "mitre_techniques": ["T1190", "T1078", "T1552", "T1210"],
  "status": "new",
  "validation_run_id": null,
  "validation_verdict": null,
  "source": "unconstrained",
  "repository_id": "repo_xyz",
  "branch_id": "branch_main"
}
```

**2b. Present the path.** Show:
- Entry → Target with step count
- Risk score and difficulty (see "How to read difficulty scores" below)
- MITRE techniques (list technique IDs with brief names)
- Each step: source → target, edge type, tactic/technique, description

**2c. Ask the user what to do.**

| Action | Tool call | When to use |
|--------|----------|-------------|
| **Validate** | `validate_path(path_id)` | Path looks plausible, send to sandbox for real exploit attempt |
| **Acknowledge** | `update_path_status(path_id, "acknowledged")` | Path is real but not urgent, mark as seen |
| **Dismiss** | `update_path_status(path_id, "closed", reason="...")` | False positive or acceptable risk. Ask for a reason. |
| **Escalate** | `escalate_path(path_id)` | Path is validated and needs remediation NOW |
| **Skip** | (no call) | Move to next path without changing status |

### Step 3 — Monitor validation

When the user chooses **Validate**:

1. Call `validate_path(path_id)`. Returns the updated `TriagePath` with `status: "validating"` and `validation_run_id`.

2. Tell the user: "Validation dispatched. This dispatches to sandbox validation, which attempts the exploit steps and independently verifies the result. This typically takes 5-15 minutes."

3. Poll `get_validation_status(run_id)` every 45 seconds.

   `get_validation_status` returns:
   ```json
   {
     "run_id": "val_run_abc123",
     "status": "running",
     "total_steps": 4,
     "steps_completed": 2,
     "steps_exploitable": 1,
     "steps_dead_end": 1,
     "current_step": 3,
     "current_phase": "exploit_attempt"
   }
   ```

   Status progression: `pending` → `running` → `completed` | `failed`

   While running, report: "Step 2/4 completed (1 exploitable, 1 dead end). Currently on step 3, exploit agent active."

4. When `status` is `completed`:
   - If `steps_exploitable > 0`: "Validation confirmed: N of M steps are exploitable. The path is real." The triage service automatically moves the path to `validated`.
   - If `steps_dead_end == total_steps`: "All steps are dead ends. The path is not currently exploitable." The path moves to `validated` with a dead-end verdict.

5. When `status` is `failed`: "Validation failed (sandbox error). The path remains in 'validating' and the reconciler will retry automatically."

6. After validation completes, ask the user whether to **escalate** the path to ticketing or **continue** to the next path.

### Step 4 — Track progress

After each action, show the remaining count: "11 new paths remaining."

When the queue is empty or the user wants to stop, show a session summary:
- Paths reviewed: N
- Validated: N (M exploitable, K dead end)
- Acknowledged: N
- Dismissed: N
- Escalated: N
- Skipped: N

### Next steps

After completing triage:
- For validated paths that need remediation, use `/remediate` to create tickets
- For ongoing monitoring, use `/monitor` to set up automated scanning and alerting

## How to read difficulty scores

The attack path model scores attack feasibility from full graph structure -- network policies, RBAC bindings, pod security contexts, firewall rules, service exposure. **Lower difficulty = easier traversal = higher risk.**

Rank paths by difficulty score to prioritize triage -- compare within the queue rather than against fixed bands. A path with the lowest difficulty in your queue is the easiest for an attacker to exploit and should be reviewed first.

## How to read MITRE techniques

Common techniques you'll see in attack paths:

| ID | Name | Category |
|----|------|----------|
| T1190 | Exploit Public-Facing Application | Initial Access |
| T1078 | Valid Accounts | Persistence / Privilege Escalation |
| T1552 | Unsecured Credentials | Credential Access |
| T1210 | Exploitation of Remote Services | Lateral Movement |
| T1068 | Exploitation for Privilege Escalation | Privilege Escalation |
| T1048 | Exfiltration Over Alternative Protocol | Exfiltration |

Full mapping at https://attack.mitre.org/techniques/enterprise/.

## What validation actually does

Validation dispatches to sandbox validation, which attempts the exploit steps and independently verifies the result. Each step runs in an isolated sandbox container with controlled egress. The verdict for each step is one of: `approved` (exploit confirmed), `rejected` (could not reproduce), or `dead_end` (step is not feasible).

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| 404 Not Found on `get_attack_path` | Path was deleted or ID is wrong | Re-query with `list_attack_paths` |
| 422 on `update_path_status` | Invalid status transition (e.g. `new` → `ticketed` without validation) | Follow the status machine: new → acknowledged/validating/closed |
| 502 on `validate_path` | Validator service unreachable | Check deployment health; the reconciler will retry automatically |
| 502 on `escalate_path` | Ticketing service unreachable | Retry later or create ticket manually via `/remediate` |
