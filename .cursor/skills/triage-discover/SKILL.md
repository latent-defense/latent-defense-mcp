---
name: triage-discover
description: "Load findings into the store, cluster by remediation action, claim via MCP tools. Phases 1-4 of the triage pipeline."
user-invocable: true
disable-model-invocation: false
---

# Triage Discover

Load, cluster, and claim scanner findings into remediation groups. This skill covers Phases 2-4 of the triage pipeline. Follow each step exactly.

**The fundamental unit of triage is not "a vulnerability" but "a remediation action."** Thirty CVEs fixed by one base image rebuild are one item. Four services needing the same auth middleware are one design decision. This skill discovers those structural groups.

## Prerequisites

- `load_graph_energies(branch_id)` MUST have been called before invoking this skill. The graph is already loaded. Do NOT call `load_graph_energies` again.
- Findings source files must be accessible at the provided paths.

## Resume check — always run first

Call `pipeline_status(project_id)` to see what's already done. If findings are loaded and groups exist, report the current state to the user and ask whether to re-discover or skip to the next phase. Do NOT blindly reload findings and re-create groups if prior work exists.

## Input

- `sources`: array of `{path, scanner, count}` — findings files
- `branch_id`: the graph branch (already loaded)
- `project_id`: triage project identifier (for findings store)

If invoked independently (not by the `/triage` orchestrator), ask the user for findings file paths, branch ID, and project ID.

## Phase 1: Load Findings into Store

If `pipeline_status` shows findings already loaded (total > 0), **skip this step** unless the user explicitly asks to reload. Previous claims are preserved across reloads.

Otherwise, call `load_findings(project_id, path)` for each source file. This parses the JSON array into a queryable SQLite store with indexed columns for scanner, severity, repo, category.

Call `findings_stats(project_id)` to see the distribution by severity, scanner, and category.

## Phase 2: Create Remediation Groups

Review the distribution. Ask: **"If I were fixing these, what batches of work would I create?"**

Produce **8-20 groups** based on REMEDIATION ACTION — not by service, scanner, or CVE.

Common group patterns:
- Package CVEs per container base image (one `docker build` fixes 30 CVEs)
- Missing authentication across multiple services (one middleware fixes all)
- CI/CD supply chain issues (one pipeline change fixes several)
- Dockerfile hygiene (one best-practices pass)
- Default credentials across services
- Missing network policies per namespace
- IaC drift per resource type
- Attack paths per entry point
- Code defects per class

For each group, call:
```
create_group(project_id, group_id="short-identifier", description="what the fix is")
```

## Phase 3: Claim Findings

For each group, claim its findings using the query-based tools:

### Preview first (dry_run=true, the default)
```
claim_findings_by_query(project_id, group_id, scanner="trivy", keyword="libssl", dry_run=true)
```
Review the sample — are these the right findings for this group?

### Claim (dry_run=false)
```
claim_findings_by_query(project_id, group_id, scanner="trivy", keyword="libssl", dry_run=false)
```

### For contiguous scanner blocks
```
claim_findings_range(project_id, group_id, start=4500, end=15000, dry_run=true)
```
Review. Then: `dry_run=false`

### For specific findings
```
claim_findings(project_id, group_id, indices="0,3,7,12")
```

The store prevents double-claims automatically. A finding can only belong to one group.

## Phase 4: Energy Refinement

For each group's anchor nodes:
```
energy_node_scores(node_ids=<anchor node IDs>)
energy_trace_to_target(source_id=<anchor>, target_types="credential,data_store,database")
```

Use energy scores to:
- Split groups where energy reveals different risk profiles (spread > 2.0)
- Update group anchor: `update_group(project_id, group_id, anchor_node=<node_id>)`

### Energy tool rules (large graphs):
- USE: `energy_node_scores`, `energy_lowest_hop`, `energy_edge_scores`, `energy_trace_to_target` (max_hops=4)
- AVOID: `energy_node_neighborhood` (too slow on large graphs)

## Phase 5: Sweep Unclaimed

Call `query_findings(project_id, unclaimed_only=true)` to see what's left.

For each unclaimed finding:
1. Read it with `get_finding`
2. Find the best matching group by keyword or structural proximity
3. Claim it: `claim_findings(project_id, group_id, indices="<idx>")`
4. If no group fits, `create_group` then claim

After sweep, call `findings_stats` and verify unclaimed count is 0.

## Output

Call `list_groups(project_id)` to present the final grouping.
Call `findings_stats(project_id)` for the summary.

## After completing

Tell the orchestrator to invoke `/triage-investigate` for EACH group. ALL groups must be investigated — no exceptions. List every group with its ID, description, finding count, and anchor node.
