---
name: triage-discover
description: "Cluster scanner findings into remediation groups using energy analysis. Phases 1-3 of the triage pipeline: Discover clusters, Group with energy-guided splits, Sweep unclaimed."
user-invocable: true
disable-model-invocation: false
---

# Triage Discover

Discover, Group, and Sweep scanner findings into remediation groups. This skill covers Phases 2-4 of the triage pipeline. Follow each step exactly — an agent executing this step-by-step produces the same result as the triage pipeline.

**The fundamental unit of triage is not "a vulnerability" but "a remediation action."** Thirty CVEs fixed by one base image rebuild are one item. Four services needing the same auth middleware are one design decision. This skill discovers those structural groups.

## Prerequisites

- `load_graph_energies(branch_id)` MUST have been called before invoking this skill. The graph is already loaded. Do NOT call `load_graph_energies` again.
- Findings source files must be accessible at the provided paths.

## Input

- `sources`: array of `{path, type, name, authority}` — findings files (scanner output)
- `branch_id`: the graph branch (already loaded)
- `project_id` (optional): for state persistence via `triage_save_project`

If invoked independently (not by the `/triage` orchestrator), ask the user for findings file paths and branch ID.

## Phase 1: Discover Clusters

Read ALL findings from all source files. Parse each finding to extract: package/resource name, severity, CVE identifier, affected resource, scanner source.

Count the total findings. This count is the denominator for all coverage tracking.

Produce **8-20 clusters** grouped by REMEDIATION ACTION — not by service, scanner, or CVE.

Ask: **"If I were fixing these, what batches of work would I create?"** Each batch is a cluster.

Common cluster patterns:
- Package CVEs per container base image (one `docker build` fixes 30 CVEs)
- Missing authentication across multiple services (one middleware fixes all)
- CI/CD supply chain issues (one pipeline change fixes several)
- Dockerfile hygiene (one best-practices pass)
- Default credentials across services
- Missing network policies per namespace
- IaC drift per resource type
- Attack paths per entry point
- Code defects per class

For each cluster, produce:

```json
{
  "id": "short-identifier",
  "description": "what the fix is, not what the findings are",
  "estimated_findings": 42,
  "hint": "search hint for finding graph nodes",
  "canonical_type": "version_update | config_change | architecture_change | policy_update | dependency_replacement | code_fix | image_rebuild | pipeline_change",
  "remediation_class": "more specific fix description (optional)"
}
```

## Phase 2: Group (one pass per cluster)

For each cluster, run the grouping logic. If the platform supports it, run clusters in parallel.

### Energy-guided decisions

The graph is ALREADY LOADED. Do NOT call load_graph_energies.
Use energy tools to inform split/merge decisions. This is not optional.

**For split decisions:**
After claiming findings, call `energy_node_scores` for each finding's subject (service name, file path, resource ID). Record entry energies.
- Spread > 2.0 → SPLIT by exposure zone (exposed < 2.0 vs interior > 3.0)
- Spread <= 2.0 → keep together
- `energy_trace_to_target` returns "not reachable" between anchors → SPLIT (disconnected)

**Tool rules (large graphs):**
- USE: `energy_node_scores`, `energy_lowest_hop`, `energy_edge_scores`, `energy_trace_to_target` (max_hops=4)
- AVOID: `energy_node_neighborhood` (too slow on large graphs)

### Grouping procedure

For each cluster:

1. **Read findings.** Read the source files and find ALL findings belonging to this cluster based on the cluster description and hint.

2. **Score structural position.** Call `energy_node_scores` for each finding's subject. Most scanner findings (OS package CVEs) do not have direct graph nodes — search for the containing service or image with `grep_nodes` instead. Record entry energies for each anchor.

3. **Apply split rules:**
   - Compute entry energy spread (max - min) across the cluster's anchors
   - Entry energy spread > 2.0 → **SPLIT** by exposure zone:
     - Exposed findings (entry energy < 2.0) → one sub-group
     - Interior findings (entry energy > 3.0) → separate sub-group
   - Call `energy_trace_to_target` between anchor nodes. If any pair returns "not reachable" → **SPLIT** (structurally disconnected components need different priorities)
   - Spread <= 2.0 and all anchors reachable → **keep together** as a leaf group

4. **Claim findings.** Assign each finding by its 0-based index to exactly ONE group. Track claims globally — a finding belongs to exactly one group across all clusters.

5. **Report cross-refs.** For findings that could plausibly belong to another cluster, record a cross-reference: `{finding_idx, target_group, reason}`. These help the sweep phase.

6. **Recursion limit.** Maximum recursion depth: 3 levels. At the depth limit, force `is_leaf=true` regardless of energy spread.

7. **Edge cases:**
   - If a cluster produces `is_leaf=false` but has no children, force it to `is_leaf=true`
   - If a cluster claims findings already claimed by another cluster, drop the duplicates and log a warning

### Per-group output schema

Each leaf group must conform to this structure:

```json
{
  "group_id": "cluster-path/sub-group",
  "is_leaf": true,
  "claimed_findings": [0, 3, 7, 12],
  "children": [],
  "cross_refs": [
    {"finding_idx": 5, "target_group": "other-cluster", "reason": "also affected by this fix"}
  ],
  "energy_analysis": {
    "anchor_nodes": [
      {"finding_idx": 0, "node_id": "service-a", "node_type": "service", "entry_energy": 2.5}
    ],
    "entry_energy_min": 2.0,
    "entry_energy_max": 3.0,
    "entry_energy_spread": 1.0,
    "split_reason": "spread <= 2.0, kept together",
    "structural_zone": "interior"
  },
  "annotation": {
    "title": "Human-readable group title",
    "canonical_type": "image_rebuild",
    "remediation_class": "Update Python base image",
    "affected_services": ["service-a", "service-b"],
    "graph_search_hints": ["python", "base-image"],
    "severity_summary": "12 high, 3 medium"
  },
  "warnings": []
}
```

## Phase 3: Sweep Unclaimed

After all clusters are grouped, identify every finding (by 0-based index from 0 to total_findings-1) that is not claimed by any leaf group.

For each unclaimed finding:

1. Use `grep_nodes` to find related graph nodes for the finding's subject
2. Call `energy_node_scores` on the finding's subject
3. Call `energy_trace_to_target` from the finding's anchor to each existing group's anchor node (use `max_hops=4`)
4. **Assign** to the group with the shortest accelerating path
5. If no path exists within 4 hops → **create a new group** for this finding

Use cross-references from the Group phase to guide assignments — if a Group agent noted that finding X belongs to cluster Y, try that assignment first.

### Post-sweep accounting

After sweep, verify:
- Every finding index from 0 to total_findings-1 is claimed by exactly one group
- No finding is claimed by more than one group
- Unclaimed count is 0

Log:
```
After sweep: {claimed}/{total} claimed, {unclaimed} unclaimed, {double_claimed} double-claimed
```

## Output

Produce the final group list as structured output:

```json
{
  "groups": [
    {
      "group_id": "string",
      "is_leaf": true,
      "claimed_findings": [0, 3, 7],
      "annotation": {
        "title": "...",
        "canonical_type": "...",
        "affected_services": ["..."],
        "severity_summary": "..."
      },
      "energy_analysis": {
        "anchor_nodes": [{"finding_idx": 0, "node_id": "...", "node_type": "...", "entry_energy": 2.5}],
        "entry_energy_min": 2.0,
        "entry_energy_max": 3.0,
        "entry_energy_spread": 1.0,
        "split_reason": "...",
        "structural_zone": "..."
      }
    }
  ],
  "total_findings": 883,
  "unclaimed": 0,
  "double_claimed": 0,
  "cross_refs": []
}
```

If a project ID was provided, save the group list with `triage_save_project`.

## After completing

Tell the orchestrator to invoke `/triage-investigate` for EACH group. ALL groups must be investigated — no exceptions. List every group with its ID, title, finding count, and anchor nodes so the orchestrator can dispatch investigation agents.
