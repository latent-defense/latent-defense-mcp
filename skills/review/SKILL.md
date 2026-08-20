---
name: review
description: "Review attack paths in the triage queue. Understand risk scores in context, see energy breakdowns per hop, identify compensating controls, and take action — acknowledge, validate, dismiss, override, or ticket through your native integration."
user-invocable: true
disable-model-invocation: false
---

# Attack Path Review

Review attack paths discovered by inference or submitted through research. For each path: understand the risk score in structural context, see per-hop energy breakdowns, identify compensating controls, and decide what to do.

## Session Start

```
triage_load_user()
triage_list_projects()
```

**Profile exists:** Greet by name. List all projects with `triage_list_projects`. Show a one-line status per project. Ask which project to review paths for, or whether to start a new one.

**Profile not found but `available_users` returned:** Call `triage_load_user(name=<first_available_user>)` to load that profile instead.

**No profile and no available users:** Ask for name, role, and ticketing integration (Linear, Jira, GitHub Issues, etc.). Save with `triage_save_user`.

**After project selection or creation:**

```
load_graph_energies(branch_id)
```

Use `list_repositories` and `list_branches(repo_id)` to help users find their branch ID if needed.

## Overview

Load the queue in parallel:

```
triage_stats()
list_attack_paths(status="new", limit=20, summary=true)
```

Present:
- Total paths by status (new, acknowledged, validated, ticketed, closed)
- Risk score range across new paths
- "You have [N] new paths to review. Risk scores range from [min] to [max] out of 100. Here's the queue ranked by risk score."

Sort the queue by `risk_score` descending (highest risk first).

If all paths score under 20: **"Your infrastructure is well defended on these paths. All scores fall in the 0-20 band, meaning strong structural resistance across every path. These are not priority findings — consider acknowledging or dismissing them and investigating other areas."**

## Individual Review

For each path (highest risk first):

### Load details

```
get_attack_path(path_id)
```

### Present the path

- **The chain**: entry node → each intermediate → target, with step descriptions
- **Risk score**: [X]/100 with band label:
  - 0-20: strong structural resistance — well defended
  - 20-40: moderate resistance — investigate the controls
  - 40-60: low resistance — deserves attention
  - 60-80: little resistance — high priority
  - 80-100: almost no resistance
- **Difficulty**: label (trivial/easy/medium/hard/extreme) and what it means — attacker economics, not skill requirements. "Easy" = an attacker would continue rather than pivot. "Extreme" = pivoting elsewhere is more rational.
- **Per-hop energy breakdown**: for each step, whether it accelerates (low resistance) or brakes (control detected). Show the direction and relative magnitude, not raw energy values.
- **Compensating controls**: when braking energy is detected on a hop, use `read_node` on both endpoints to identify the specific security boundary, auth check, or network policy creating resistance. Note any documented limitations in the control's description.
- **MITRE ATT&CK techniques**: technique IDs with brief names for each step
- **Validation status**: if validated, verdict and how many steps were exploitable

### What the score does NOT tell you

Always include: "Risk scores measure structural resistance — how much the infrastructure's topology resists this path. They do not measure exploitability certainty, attacker motivation, or business impact. A high score means the infrastructure provides little structural defense along this path; a low score means strong structural defense."

## Actions

After presenting each path, ask the user what to do:

| Action | Tool Call | When to use |
|--------|----------|-------------|
| **Acknowledge** | `update_path_status(path_id, "acknowledged")` | Path is real but not urgent, mark as seen |
| **Validate** | `validate_path(path_id)` | Path looks plausible, send to sandbox for real exploit attempt |
| **Dismiss** | `dismiss_path(path_id, reason, note)` | False positive or accepted risk |
| **Override score** | `override_risk_score(path_id, score, reason)` | User believes risk is higher/lower than model scored |
| **Comment** | `add_path_comment(path_id, text, author)` | Annotate investigation notes or decisions |
| **Ticket** | Guide user to native ticketing integration | Path needs a remediation ticket |
| **Skip** | (no call) | Move to next path without changing status |

### Dismiss reasons

When dismissing, use structured reasons:
- `compensating_control` — a control not in the graph mitigates this path
- `network_segmentation` — network controls prevent this path in practice
- `service_decommissioned` — the affected service is being retired
- `risk_accepted` — risk acknowledged and accepted by the organization
- `not_applicable` — path does not apply to this deployment model
- `other` — free-form with required note

### Validation monitoring

When the user chooses Validate:

1. Call `validate_path(path_id)`. Returns the updated path with `status: "validating"` and `validation_run_id`.
2. Tell the user: "Validation dispatched. Sandbox validation attempts each exploit step independently. This typically takes 5-15 minutes."
3. Poll `get_validation_status(run_id)` every 45 seconds.

   Status progression: `pending` → `running` → `completed` | `failed`

   While running, report: "Step [N]/[M] completed ([X] exploitable, [Y] dead end). Currently on step [Z]."

4. On `completed`:
   - If `steps_exploitable > 0`: "Validation confirmed: [N] of [M] steps are exploitable. The path is real."
   - If all dead ends: "All steps are dead ends. The path is not currently exploitable."

5. On `failed`: "Validation failed (sandbox error). The reconciler will retry automatically."

6. After validation, ask whether to create a ticket through native integration or continue to next path.

### Ticketing

Do not call MCP ticketing tools. Instead, reference the ticketing integration from the user's profile (saved during onboarding). Guide the user to create tickets through their native integration — Linear, Jira, GitHub Issues, or whatever they have configured in their IDE.

### Progress tracking

After each action, show remaining count: "[N] new paths remaining."

When the queue is empty or the user stops, show a session summary:
- Paths reviewed: N
- Validated: N (M exploitable, K dead end)
- Acknowledged: N
- Dismissed: N
- Skipped: N

Save review decisions to the project with `triage_add_decision` for risk acceptances and `triage_add_work_item` for remediation actions.

## Energy Signal Reference

**Entry energy** — structural exposure. Lower = more reachable from external input. Not just network endpoints — K8s reconcile events, client SDK inputs, CI triggers all count.
- < 0.1: directly accessible. 0.1-0.5: entry-facing. 0.5-2.0: near-surface. 2.0-4.0: interior. > 4.0: deep interior.

**Transition energy** — per-edge resistance. Negative = accelerating (easy), positive = braking (barrier).
- Edge type patterns: `contains`/`calls` accelerate. `owns`/`member_of` brake. `has_permission`/`assumes_role` 100% accelerate. `protects`: 76% brake, 24% accelerate — an accelerating `protects` edge means the model sees the control as structurally transparent. Most reliable signal for investigation.

**Momentum** — cumulative path score integrating per-hop energy. Risk score 0-100.
- 0-20: strong structural resistance. Infrastructure is well defended. Not a finding.
- 20-40: moderate resistance. Mixed signal — investigate what's braking.
- 40-60: low resistance. Multiple accelerating hops. Deserves attention.
- 60-80: little resistance. Most hops accelerate. High priority.
- 80-100: almost no resistance across the path.

**The key rule:** Low resistance does not equal security problem. Authorized flows accelerate by design. The signal is low resistance WHERE IT SHOULD NOT BE.

**Implicit vs explicit edges:** Explicit edges (confirmed in the graph) have smaller energy magnitudes. Implicit edges (model-inferred, not confirmed) have much larger magnitudes. Never compare them on the same scale.

**Model strengths:** Structural transparency in controls, co-location anti-patterns, missing boundaries, chokepoints.

**Model blind spots:** Runtime behavior (RLS, RBAC), cryptographic backing of checks, protocol-layer auth.

## Graph Tools

- `read_node(name)`, `read_edge(name)`, `get_connected_edges(node, direction)` — read specific graph elements
- `grep_nodes(pattern, field, limit)`, `grep_edges(pattern, field, limit)` — search by substring
- `find_nodes_by_type(node_type, limit)`, `find_edges_by_type(edge_type, limit)` — search by type
- `get_graph_statistics()` — node/edge counts and type distributions

## Energy Tools

**Granular** (start here):
- `energy_node_scores(node_query)` — what is this node, what's connected
- `energy_lowest_hop(node_query)` — single least-resistance connection
- `energy_node_neighborhood(node_query, hops)` — local context including nearby controls
- `energy_edge_scores(source_query, target_query)` — specific connection energies

**Exploration** (after understanding the neighborhood):
- `energy_lowest_paths(node_query, max_hops, top_k)` — lowest-energy paths at each depth
- `energy_trace_to_target(source_query, target_query)` — least-resistance route between two points
- `energy_compare_paths(path_a, path_b)` — why one route is less defended
- `energy_momentum_path(node_names)` — momentum along a specific path

**Structural overview** (broad picture):
- `energy_top_attack_paths(limit)` — highest-momentum paths
- `energy_chokepoints(limit)` — nodes with most path flow
- `energy_entry_points(threshold, limit)` — exposed surface
- `energy_defenses(limit)` — structural resistance nodes

## Path Queue Tools

- `list_attack_paths(status, min_risk_score, limit, offset, order, repository_id, node_id, mitre_technique, summary)` — query paths with filters; `node_id` filters to paths through a specific infrastructure node
- `get_attack_path(path_id)` — full path details with steps, MITRE mappings, risk score, difficulty
- `update_path_status(path_id, status, note)` — change triage status
- `validate_path(path_id)` — dispatch to sandbox validation
- `get_validation_status(run_id)` — check sandbox validation progress
- `dismiss_path(path_id, reason, note, expires_at)` — dismiss with structured reason
- `undismiss_path(path_id, reason, note)` — restore a dismissed path
- `bulk_update_paths(action, status_filter, repository_id, reason, note, limit)` — batch operations
- `override_risk_score(path_id, risk_score, reason)` — set user risk score (0-100); model score preserved
- `clear_risk_override(path_id)` — remove user score override
- `add_path_comment(path_id, text, author)` — attach investigation notes
- `list_path_history(path_id)` — unified timeline: status changes, score changes, comments

## State Management

- `triage_save_user` / `triage_load_user` — identity, role, pain points, ticketing integration, team
- `triage_save_project` / `triage_load_project` / `triage_list_projects` — project lifecycle
- `triage_project_status` — current state summary
- `triage_stats(repository_id)` — aggregate counts by status
- `triage_add_work_item` — create actionable items assigned to people
- `triage_add_decision` — record risk decisions with justification and review dates

## Error Handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid | Regenerate in portal |
| 404 Not Found on `get_attack_path` | Path was deleted or ID is wrong | Re-query with `list_attack_paths` |
| 422 on `update_path_status` | Invalid status transition (e.g. `new` → `ticketed` without validation) | Follow the status machine: new → acknowledged/validating/closed |
| 502 on `validate_path` | Validator service unreachable | Check deployment health; the reconciler will retry automatically |
| 422 on `dismiss_path` | Path not in dismissable state | Check current status with `get_attack_path`; transition first if needed |
| 422 on `override_risk_score` | risk_score outside 0-100 | Clamp value to [0, 100] before calling |
