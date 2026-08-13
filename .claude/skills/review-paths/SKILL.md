---
name: review-paths
description: "Review existing attack paths — understand risk scores in context, see energy breakdowns, update statuses, compare paths across repositories."
user-invocable: true
disable-model-invocation: false
---

# Review Paths — Attack Path Review

Review attack paths that have been discovered by inference or submitted through research. Understand what the risk scores mean in context, see per-hop energy breakdowns, and take action (acknowledge, dismiss, validate, ticket).

## Prerequisites

- The `latent-defense` MCP server must be connected

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Path listing**: `list_attack_paths(status, min_risk_score, limit, offset, summary)`, `triage_stats(repository_id)`
**Path detail**: `get_attack_path(path_id)`
**Path actions**: `update_path_status(path_id, status, note)`, `validate_path(path_id)`, `dismiss_path(path_id, reason, note, expires_at)`
**Score overrides**: `override_risk_score(path_id, risk_score, reason)`, `clear_risk_override(path_id)`
**Comments + history**: `add_path_comment(path_id, author, text)`, `list_path_history(path_id)`
**Validation monitoring**: `get_validation_status(run_id)` — check sandbox validation progress
**Graph context**: `oracle_load_branch`, `oracle_wait_for_load`, `oracle_get_node`

---

## Step 1 — Get the overview

```
triage_stats()
```

Show the user:
- Total paths by status (new, acknowledged, validated, ticketed, closed, false_positive)
- Severity distribution
- Paths by repository

```
list_attack_paths(status="new", limit=20, summary=true)
```

Present the queue: "You have [N] new paths to review. Risk scores range from [min] to [max] out of 100. Here's the queue ranked by risk score."

## Step 2 — Review individual paths

For each path the user wants to review:

```
get_attack_path(path_id)
```

Present:
- **The chain**: entry node → intermediate → target, with descriptions
- **Risk score**: [X]/100 — explain where it falls (0-20 strong resistance / well defended, 20-40 moderate, 40-60 low resistance / deserves attention, 60-80 little resistance / high priority, 80-100 almost no resistance)
- **Difficulty**: the label and what it means (attacker economics, not skill)
- **Per-hop energy**: for each step, energy value and accelerate/brake label
- **Compensating controls**: braking hops indicate controls — name them if visible in the step descriptions
- **MITRE ATT&CK techniques**: what tactics are mapped to each step
- **Validation status**: if validated, what was the verdict? How many steps were exploitable?

### Contextual ranking

"This path scores [X]/100. [Under 20: the infrastructure is well defended here — this path has strong structural resistance and is not a priority. 20-40: moderate — controls exist but investigate their gaps. Over 40: this path has low resistance and deserves attention. Over 60: high priority for remediation.]"

## Step 3 — Take action

Based on the review, the user can:

| Action | When | Command |
|--------|------|---------|
| **Acknowledge** | "I've seen this, will investigate" | `update_path_status(path_id, "acknowledged")` |
| **Validate** | "Send to sandbox for exploit testing" | `validate_path(path_id)` — takes 5-15 min. Poll `get_validation_status(run_id)` every 30-60s for progress. |
| **Dismiss** | "This is a false positive or accepted risk" | `dismiss_path(path_id, reason="risk_accepted", note="reason")` |
| **Ticket** | "Create a remediation ticket" | Use `/remediate` |
| **Close** | "This has been remediated" | `update_path_status(path_id, "closed", note="what was fixed")` |

## Step 4 — Deeper investigation

If the user wants to understand a path better:

- "Want to explore the graph around this path?" → Load the branch and use `oracle_get_node` on each node in the chain
- "Want to see what controls are between the entry and target?" → Point to `/explore` to find security boundaries
- "Want to find similar paths?" → Point to `/research` to build threat models around the same target
- "Want to create a remediation ticket?" → Point to `/remediate`

---

## How to present risk scores

Always include context:
- The score (X/100)
- The band (0-20 well defended, 20-40 moderate, 40-60 deserves attention, 60-80 high priority, 80-100 almost no resistance)
- The energy breakdown (how many hops accelerate vs brake)
- What the risk score does NOT tell you (it's structural resistance, not exploitability certainty)
- If all paths score under 20: "Your infrastructure is well defended — these paths are not priority findings"
