---
name: triage
description: "Guided attack path triage queue. Review, validate, dismiss, or ticket attack paths discovered by inference."
user-invocable: true
disable-model-invocation: false
---

# Triage — Attack Path Queue

Work through the attack path triage queue. For each path: review the details, decide whether to validate it in a sandbox, acknowledge it, dismiss it, or create a remediation ticket.

## Prerequisites

- The `latent-defense` MCP server must be connected
- Attack paths must exist — discovered via `/research`, `/investigate`, or batch inference after `/map`

## Quick reference — tool names

| Tool | What it does |
|------|-------------|
| `list_attack_paths(status, min_risk_score, limit, offset, order, repository_id, mitre_technique, source_detection_id, rescored, rescored_window_hours)` | Query attack paths with optional filters. Use `rescored=True` for re-scored queue. Use `status="superseded"` for system-dismissed paths. |
| `paths_through_node(node_id, status, min_risk_score, ...)` | Find attack paths that flow through a specific node (chokepoint analysis, CVE exposure) |
| `get_attack_path(path_id)` | Full path details: steps, MITRE mappings, risk score, difficulty, reassessment history |
| `update_path_status(path_id, status, note)` | Change a path's triage status |
| `validate_path(path_id)` | Dispatch to sandbox validation |
| `dismiss_path(path_id, reason, note, expires_at)` | Dismiss a path as false positive with structured reason. Not for superseded paths. |
| `undismiss_path(path_id, reason, note)` | Reopen a dismissed path back into the queue |
| `bulk_update_paths(action, status_filter, repository_id, reason, note, limit)` | Apply acknowledge/dismiss/close to multiple matching paths |
| `override_risk_score(path_id, risk_score, reason)` | Set a user risk score (0–100); model score preserved alongside |
| `clear_risk_override(path_id)` | Remove user score override; sorting reverts to model score |
| `add_path_comment(path_id, text, author, parent_comment_id, parent_event_id)` | Add a comment (threaded — use parent_comment_id to reply). Agent attribution automatic. |
| `edit_path_comment(path_id, comment_id, text)` | Edit a comment (append-only revision). Server enforces author-only. |
| `list_path_comments(path_id)` | All comments with threading (parent_comment_id, parent_event_id), author_kind, agent_name |
| `list_path_history(path_id)` | Unified timeline: status changes, score changes, comments |
| `get_validation_status(run_id)` | Check sandbox validation progress |
| `triage_stats(repository_id)` | Aggregate counts by status |
| `get_triage_config()` | Display config (rescore_display_threshold) — for RE-SCORED badge logic |
| `get_classification_stats(repository_id)` | Classification breakdown |

## Prompts

| Prompt | What it does |
|--------|-------------|
| `triage_queue_review(repository_id, min_risk_score, status)` | Interactive triage queue walkthrough |
| `assess_cve(cve_id, repository_id)` | Assess exposure of a CVE across the infrastructure graph |
| `chokepoint_report(repository_id, min_paths)` | Identify chokepoint nodes where many attack paths converge |

## Workflow

### Step 1 — Load the queue

Call `list_attack_paths(status="new", limit=20)` and `triage_stats()` in parallel.

Present a summary: "12 new paths, 47 total. 8 validated, 10 ticketed, 7 closed."

Sort the queue by `risk_score` descending (highest risk first).

Check for re-scored paths: `list_attack_paths(rescored=True)`. If any, note "N findings were recently re-scored" and check `get_triage_config()` for the display threshold.

### Step 2 — Walk each path

For each path in the queue (highest `risk_score` first):

**2a. Load full details.** Call `get_attack_path(path_id)`.

**2b. Present the path.** Show:
- Entry → Target with step count
- Risk score and difficulty
- MITRE techniques (list technique IDs with brief names)
- Each step: source → target, edge type, tactic/technique, description
- Reassessment history if present (risk_before → risk_after, applied_at)

**2c. Ask the user what to do.**

| Action | Tool call | When to use |
|--------|----------|-------------|
| **Validate** | `validate_path(path_id)` | Path looks plausible, send to sandbox |
| **Acknowledge** | `update_path_status(path_id, "acknowledged")` | Path is real but not urgent |
| **Dismiss** | `dismiss_path(path_id, reason="...", note="...")` | False positive or accepted risk |
| **Undismiss** | `undismiss_path(path_id, reason="...")` | Reopen a dismissed path |
| **Override score** | `override_risk_score(path_id, risk_score, reason)` | User believes risk differs |
| **Comment** | `add_path_comment(path_id, text="...")` | Annotate investigation notes |
| **Reply** | `add_path_comment(path_id, text="...", parent_comment_id="...")` | Reply to an existing comment |
| **Ticket** | (use `/remediate`) | Path is validated and needs remediation |
| **Skip** | (no call) | Move to next path |

### Step 3 — Monitor validation

When the user chooses **Validate**:

1. Call `validate_path(path_id)`. Returns `status: "validating"` and `validation_run_id`.
2. Tell the user: "Validation dispatched. Takes 5-15 minutes."
3. Poll `get_validation_status(run_id)` every 45 seconds.
4. When completed: report exploitable/dead-end counts.
5. After validation, ask whether to create a remediation ticket or continue.

### Step 4 — Track progress

After each action, show the remaining count.

When done, show a session summary: paths reviewed, validated, acknowledged, dismissed, ticketed, skipped.

### Superseded paths

Paths with `status=superseded` were eliminated by re-scoring (system-dismissed). They should NOT be acted on with `dismiss_path` (that's for operator dismissals). View them with `list_attack_paths(status="superseded")` — they appear in the Dismissed tab, distinct from operator dismissals.

## How to read risk scores and difficulty

**Risk scores are 0–100** (momentum model). Bands:
- **0–20**: strong structural resistance. Well-defended.
- **20–40**: moderate resistance. Mixed signal.
- **40–60**: low resistance. Deserves attention.
- **60–80**: little resistance. High priority.
- **80–100**: almost no resistance.

**Severity labels** (canonical bands, LD-2187/2310):
- Critical: 80+
- High: 61–79
- Medium: 41–60
- Low: 21–40
- Info: 0–20

**Difficulty labels** (trivial/easy/medium/hard/extreme) describe attacker economics, not skill.

**Per-hop energy**: negative = accelerating (low resistance), positive = braking (control detected). When you see braking energy, the path description often identifies the specific control.

## How to read MITRE techniques

Common techniques in attack paths:

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

## Next steps

After completing triage:
- "Want to create remediation tickets?" → `/remediate`
- "Want to investigate a specific path deeper?" → `/investigate` with the path's entry node or target
- "Want to explore the graph around a finding?" → `/explore`
- "Want to find more paths proactively?" → `/research`
- "Want to process scanner output against this graph?" → `/triage-report`

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| 404 Not Found | Path deleted or wrong ID | Re-query with `list_attack_paths` |
| 422 on `update_path_status` | Invalid status transition | Follow state machine: new → acknowledged/validating/closed |
| 422 on `dismiss_path` | Path not in acknowledged/validated state | Transition first |
| 422 on `override_risk_score` | risk_score outside 0–100 | Clamp to [0, 100] |
| 403 on `edit_path_comment` | Not the comment author | Server-side author-only enforcement |
| 502 on `validate_path` | Validator unreachable | Reconciler retries automatically |

## Intentionally excluded from MCP

| Capability | Reason |
|---|---|
| Evidence attachments (images) | Binary payload doesn't fit MCP; agents have graph/tool output |
| Reassessment review (accept/reject) | ADR-002: re-grades auto-apply. Review queue deleted. |
| Revalidation trigger | `require_internal` auth; use `validate_path` for initial validation |
| Path graph snapshot | Visualization primitive; agents have `get_attack_path` + graph tools |
| Comment deletion | Append-only model (portal doesn't support deletion either) |
