---
name: triage-investigate
description: "Investigate one finding group against the infrastructure graph. Two-stage: energy exploration then code/config verification. Reads findings from the store."
user-invocable: true
disable-model-invocation: false
---

# Triage Investigate

Investigate a single finding group against the infrastructure graph. This is the two-stage investigation pipeline from Phase 5 of the triage workflow. Each invocation handles ONE group.

Follow each step exactly.

## CRITICAL: Two stages, both mandatory

- **Stage 1 (Energy Exploration)** maps the structural position. It is screening, not investigation.
- **Stage 2 (Code/Config Verification)** is the actual investigation. It is NOT optional.

A verdict based only on energies, scores or graph topology is invalid. What the map recorded from code, config and cloud state (node and edge descriptions) is evidence and can support any verdict; tag it (map) and note "not checked against the running system". Energies, scores and topology alone are not evidence.

## Prerequisites

- `load_graph_energies(branch_id)` MUST have been called. Do NOT call it again.
- Findings must be loaded into the store via `load_findings`.

## Resume check — always run first

Call `pipeline_status(project_id)` to see the investigation state. If this group already has a verdict (check `get_investigation`), skip it and report the existing result. The skill is idempotent — running it twice on the same group doesn't create duplicate work.

## Input

- `project_id`: Triage project identifier
- `group_id`: The group to investigate (findings are read from the store)
- `branch_id`: the graph branch (already loaded)
- `verification_channels` (optional): how to verify — source code paths, cloud CLI access, kubectl contexts

If invoked independently, ask the user for the project ID, group ID, and verification access.

## Load Group Data

```
query_findings(project_id, group_id=<your group ID>)
```

Read all findings in this group. Use `get_finding(project_id, idx)` for full details on specific findings.

## Stage 1: Energy Exploration (structural map)

### Energy interpretation

**Entry energy** = structural exposure. < 0.1: directly accessible. 0.1-0.5: entry-facing. 0.5-2.0: near-surface. 2.0-4.0: interior. > 4.0: deep interior.

**Transition energy** = per-edge resistance. Negative = accelerating. Positive = braking.

**Key rule:** Low resistance ≠ security problem. Auth happy paths accelerate by design. The signal is low resistance WHERE IT SHOULD NOT BE.

### Investigation method

If the group's code isn't in the graph, read it and add the node and its edges first ("When the code isn't in the graph" in `/investigate`), and record what you added in `graph_corrections`. Don't commit; the orchestrator does.


1. `energy_node_scores` — what is this node, what are its connections?
2. `energy_lowest_hop` — single easiest connection, follow it
3. `energy_edge_scores` — specific transition energies on key edges
4. `energy_trace_to_target` — reachability from entry points
5. `read_node` for full details, `grep_nodes` to find related nodes

Every energy value MUST become a concrete statement.

### Save exploration results

```
save_investigation(project_id, group_id, explore_result=<JSON of your structural findings>)
```

## Stage 2: Code/Config Verification

This is the investigation. Energy exploration was screening.

Use the configured verification channels (source_code, cloud_cli, kubernetes, iac).
If no channels are available, verify against what the map recorded from code, config and cloud state (node and edge descriptions), tag it (map), and note "not checked against the running system".

### Verification rules

1. Read at least one source file, config file or cloud resource, or, with no channels, the map's description of one
2. Cite the specific file, line, API response or recorded description
3. Never base a verdict on energies or scores alone

### Verdict

Use the four verdicts every Latent Defense report uses (defined in `/investigate`):
- **confirmed**: every step holds from a realistic attacker position
- **conditional**: every step holds except one named condition
- **inconclusive**: the graph and your checks can't settle whether it's reachable; say what's missing
- **refuted**: a step fails for every attacker position; name the control (this is a success)

### Resolution categories

- **eliminable**: clear fix → engineering
- **reducible**: partial fix, add controls → engineering
- **constrained**: design limitation → product decision
- **drift_prone**: recurring → automation
- **mitigated**: fix friction > risk under controls → accept with review date

### Save verdict

```
save_investigation(project_id, group_id, verdict=<confirmed|conditional|inconclusive|refuted>, evidence=<citation>, graph_corrections=<JSON of any graph corrections made>)
update_group(project_id, group_id, resolution=<category>, action=<what to fix>, status="investigated", primary_audience=<who>)
```

## After completing

Report the verdict summary to the orchestrator: group ID, verdict, resolution, primary audience, one-line action.

The orchestrator must collect ALL verdicts before proceeding to delivery.
