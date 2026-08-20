---
name: investigate
description: "Investigate a specific CVE, detection, alert, or security question against your infrastructure graph. Enriches one finding with the world model's structural assessment. For processing a full scanner report, use /triage."
user-invocable: true
disable-model-invocation: false
---

# Investigate — Single Finding Investigation

You have a specific security question, CVE, detection, or alert. You're investigating it against an infrastructure graph using the JEPA world model's energy scores to determine if it's a real attack chain, a false positive, or compensated by controls.

This is focused and fast — one question, one answer, grounded in the model's structural evidence.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must be loaded (run `/map` first if needed)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Graph loading**: `load_graph_energies`, `list_repositories`, `list_branches`
**Graph structure**: `read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`
**Energy analysis**: `energy_node_scores`, `energy_edge_scores`, `energy_node_neighborhood`, `energy_entry_points`, `energy_trace_to_target`, `energy_lowest_paths`, `energy_momentum_path`, `energy_compare_paths`, `energy_top_attack_paths`
**Submission**: `submit_attack_path`
**Triage state**: `triage_load_user`, `triage_save_user`, `triage_list_projects`, `triage_load_project`, `triage_save_project`, `triage_update_finding_group`, `triage_add_decision`

## Energy & Momentum — What the Numbers Mean

Energy is structural resistance — how much the infrastructure resists an attacker at each step.
- **Negative energy** (accelerating): low resistance, clear path forward
- **Positive energy** (braking): a control, boundary, or check creates friction
- **Magnitude matters**: -3.0 is much less resistance than -0.5

Momentum is the cumulative effect along a path. It uses a sigmoid model:
- Accelerating edges (negative energy) increase momentum
- Braking edges (positive energy) decrease momentum
- The final momentum maps to a risk score (0–100)

Risk score bands:
- **0–20**: well defended. Not a finding. If everything scores here, the infra is solid.
- **20–40**: moderate resistance. Worth investigating specific controls.
- **40–60**: low resistance. Needs attention.
- **60–80**: high priority. Little structural defense.
- **80–100**: almost no resistance.

When you see braking energy, use `read_node` on both endpoints to identify the specific control. The graph often captures both what a control does AND its gaps.

**CRITICAL: Energy scores tell you WHERE to look. They are NOT conclusions. Verify everything against source code, config files, and cloud API state. Energy scores are the input to investigation, never the output.**

## Session Start

1. Call `mcp__latent-defense__triage_load_user()`
   - If it returns a profile: use it — greet by name, use their role/pain_points to focus the session
   - If it returns an error with `available_users`: call `triage_load_user(name=<first_available_user>)` to load that profile
   - If no users exist at all: ask name, role, biggest security concern. Save with `triage_save_user()`

2. Call `mcp__latent-defense__triage_list_projects()`
   - If active project for this engagement: load it with `triage_load_project()`
   - If user specifies a branch: create a new project
   - If neither: call `list_repositories()` → `list_branches()` → user picks

3. Call `mcp__latent-defense__load_graph_energies(branch_id)`
   - Report node/edge counts when loaded

4. Begin investigation, informed by profile + project context

---

## Understand the Question

Determine the mode:

| User says | Mode |
|-----------|------|
| A specific CVE, detection, or alert | **Finding investigation** — use the Five Moves |
| "Is X reachable from Y?", "How exposed is our DB?" | **Posture query** — streamlined trace |

---

## The Five Moves — Finding Investigation

### Move 1 — Ground

Find the real nodes related to the finding in the graph.

```
grep_nodes(pattern="finding_name or cve_id")
find_nodes_by_type(node_type="affected_component_type")
```

For each match, call `read_node(node_name)` to inspect:
- **Version**: does the node description contain a pinned version? Compare to the CVE's affected range.
- **Usage**: does the description reveal which features are used? A CVE in a feature that isn't used is a false positive.
- **Neighbors**: call `get_connected_edges(node_name)` — what connects to and from this node?

If the resource is not in the graph: "This resource is not in the infrastructure graph. The model cannot assess attack chains through it. Check whether the mapping covers this component — you may need to re-map with `/map`."

### Move 2 — Position

Understand each affected node's structural role in the graph.

```
energy_node_scores(node_name)       — entry energy, aggregate scores
energy_node_neighborhood(node_name, hops=2) — local terrain around the node
get_connected_edges(node_name)      — who connects, what edge types
```

Key questions to answer:
- Is this node near an entry point (low entry energy) or deep in the interior?
- How many services connect to it? Is it a choke point?
- Are there defensive nodes (braking energy) between it and the exterior?
- What sensitive targets (data stores, credentials) are nearby?

### Move 3 — Trace

Find paths to and from sensitive targets through the affected node.

**Specific pair** — when you know both source and destination:
```
energy_trace_to_target(source, target)
```

**Discovery** — when you want to find what an attacker could reach:
```
energy_lowest_paths(node, max_hops=6)
```

**Global context** — see where this node fits in the overall risk landscape:
```
energy_top_attack_paths()
```

Try multiple trace directions:
- From entry points TO the affected node (can an attacker reach it?)
- From the affected node TO sensitive targets (what can they access if they compromise it?)
- Through the affected node (is it a waypoint in existing high-risk paths?)

### Move 4 — Score

Evaluate the risk of each discovered path.

```
energy_momentum_path(node_names)    — risk score 0-100 for an explicit path
energy_compare_paths(path_a, path_b) — side-by-side comparison
```

Apply the bands:
- **Under 20**: strong resistance. The infrastructure defends this chain. Report the controls, not the risk.
- **20-40**: moderate. Investigate the specific controls and their gaps.
- **Over 40**: real signal. This path deserves attention.
- **Over 60**: high priority. Little structural defense.

For paths with braking energy on specific hops, identify the control:
```
read_node(braking_hop_source)
read_node(braking_hop_target)
```
Look for security boundaries, auth checks, network policies. Note their documented limitations.

### Move 5 — Verify

Check real systems to confirm or refute the energy signal.

**Evidence hierarchy** (strongest to weakest):
1. Source code — read the actual implementation
2. Config files — IaC, Dockerfiles, k8s manifests, CI configs
3. Cloud API state — actual runtime configuration
4. Semantic context — what the graph's node descriptions say
5. Graph structure — connections and edge types
6. Energy scores — the model's assessment of structural resistance

Use verification channels from the user's profile if available:
- **source_code**: check the repository for the actual implementation
- **cloud_cli**: query AWS/Azure/GCP APIs for runtime state
- **kubernetes**: check pod specs, network policies, RBAC
- **iac**: review Terraform/CloudFormation for intended state

"Energy tells you where to look. Verification tells you what's real."

---

## Posture Query

For questions like "Is X reachable from Y?" or "How exposed is our DB?":

### Find the components

```
grep_nodes(pattern="what the user asked about")
```

For each relevant node:
```
read_node(node_name)
get_connected_edges(node_name)
energy_node_neighborhood(node_name, hops=2)
```

### Trace and score

```
energy_trace_to_target(source, target)   — if specific pair
energy_lowest_paths(node, max_hops=6)     — if open-ended discovery
energy_momentum_path(node_names)          — score the discovered path
```

### Answer directly

"Yes, [target] is reachable from [entry point] — the lowest-energy path scores [X]/100 with [N] accelerating hops and [M] braking hops. The key accelerating edge is [description]. The only control in the path is [control] but it has [limitation]."

OR: "No, [target] is well-protected — energy tracing found paths but all show strong resistance (scores under 20). The key controls are: [list with energy scores]."

A well-evidenced "no" is a valuable answer.

---

## Deliver the Verdict

Report:
- **What the finding claims** — the CVE, alert, or question as stated
- **What the graph shows** — node, neighbors, version, usage context
- **What the energy reveals** — paths tested, energy per hop, risk scores
- **What controls were detected** — braking hops mapped to specific boundaries, with their limitations
- **The verdict** — real chain / false positive / compensated / structurally isolated
- **What to do about it** — may differ from the scanner's recommendation
- **What you could NOT verify** — flag explicitly. Energy is structural evidence, not proof of exploitability.

## Saving Verdicts

Save investigation results to the active project:

```
triage_update_finding_group(project_id, group_id, updates={
  "status": "investigated",
  "verdict": "real_chain | false_positive | compensated | isolated",
  "risk_score": score,
  "notes": "Investigation summary"
})

triage_add_decision(project_id, decision={
  "finding": "finding description",
  "verdict": "verdict",
  "rationale": "why — cite energy scores and verification evidence",
  "verified_by": "source_code | cloud_cli | graph_only"
})
```

---

## After the Investigation

- "Want to explore the graph around this finding?" → `/explore`
- "Want to find more paths to this same target?" → `/research`
- "Want to process a full scanner report?" → `/triage`
- "Want to review existing attack paths?" → `/review`
