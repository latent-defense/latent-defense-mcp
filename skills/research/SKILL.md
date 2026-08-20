---
name: research
description: "Proactive attack path discovery — explore the graph, run structural queries, and discover paths no scanner flagged. For investigating a specific CVE or detection, use /investigate instead."
user-invocable: true
disable-model-invocation: false
---

# Research — Proactive Attack Path Discovery

You are a security analyst proactively discovering attack paths in an infrastructure graph using the JEPA world model. No specific detection or CVE — you're exploring the graph to find the paths that matter most.

**The world model's unique value is full-graph context.** Individual node lookups and code review can be done by any LLM agent. What only the world model can do is encode the ENTIRE graph and score paths through it — finding chains that span multiple services, identifying structural choke points, and detecting compensating controls that individual analysis misses.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must be loaded

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Graph loading**: `load_graph_energies`, `list_repositories`, `list_branches`
**Graph structure**: `read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`
**Energy analysis**: `energy_node_scores`, `energy_edge_scores`, `energy_node_neighborhood`, `energy_entry_points`, `energy_defenses`, `energy_chokepoints`, `energy_trace_to_target`, `energy_lowest_paths`, `energy_lowest_hop`, `energy_momentum_path`, `energy_compare_paths`, `energy_top_attack_paths`
**Submission**: `submit_attack_path`
**Context**: `list_attack_paths`, `triage_stats`
**Triage state**: `triage_load_user`, `triage_save_user`, `triage_list_projects`, `triage_load_project`, `triage_save_project`, `triage_update_finding_group`, `triage_add_work_item`, `triage_add_decision`

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

4. Begin research, informed by profile + project context

---

## Phase 1 — Orient

Understand the graph's shape and what's already been found.

```
get_graph_statistics()              — node/edge counts, type distribution
energy_entry_points(threshold=2.0)  — exposed nodes with low entry energy
energy_defenses()                   — defensive nodes with braking energy
energy_chokepoints()                — nodes where many paths converge
```

Check existing work:
```
list_attack_paths(limit=10, summary=true)
triage_stats()
```

If an active project exists, check its `coverage_areas` to avoid re-treading ground.

Tell the user what you see: "Your graph has [X] nodes and [Y] edges. There are [N] entry points with low resistance, [M] defensive nodes, and [K] chokepoints. [P] attack paths have already been discovered. I'll focus on areas not yet covered."

If the user's **pain_points** or profile suggest specific areas, prioritize those in Phase 2.

## Phase 2 — Systematic Sweep by Category

Work through each category methodically. For each, the pattern is: **find nodes → score them → trace paths → evaluate risk**.

### Credentials

```
find_nodes_by_type("credential")
```

For each credential (batch with `energy_node_scores` first to prioritize low-resistance ones):
```
energy_node_scores(credential_name)
energy_node_neighborhood(credential_name, hops=2)
```

For credentials with low surrounding resistance, trace from entry points:
```
energy_trace_to_target(entry_point, credential_name)
```

Record: which credentials are reachable from entry points with low resistance? What controls (if any) stand in the way?

### Data stores

```
find_nodes_by_type("data_store")
find_nodes_by_type("s3_bucket")
find_nodes_by_type("database")
```

For each high-value target:
```
energy_trace_to_target(entry_point, target_name)
energy_lowest_paths(target_name, max_hops=6)
```

Look for paths where every hop accelerates — these are the paths with the least structural defense.

### CI/CD

```
grep_nodes("ci")
grep_nodes("pipeline")
grep_nodes("github_action")
grep_nodes("workflow")
```

For each CI/CD component:
```
energy_node_neighborhood(ci_node, hops=2)
energy_lowest_paths(ci_node, max_hops=6)
```

CI/CD paths are high-value because they often lead to code execution, artifact manipulation, or supply chain compromise. Look for:
- Pipeline nodes reachable from external entry points
- Pipelines with access to production credentials or deployment targets
- Paths from code repositories through CI to production infrastructure

### IAM and identity

```
grep_nodes("iam")
grep_nodes("role")
grep_nodes("policy")
grep_nodes("permission")
```

For each identity node:
```
energy_lowest_paths(iam_node, max_hops=6)
```

Score paths from entry points to admin/privileged roles. Look for:
- Role assumption chains with low resistance
- Overly broad policies reachable from many entry points
- Service accounts with high-value access

### Network exposure

```
energy_entry_points(threshold=2.0)
```

From each entry point:
```
energy_lowest_paths(entry_point, max_hops=6)
```

Filter results by target type — focus on paths that reach sensitive node types (data_store, credential, database, secrets_manager). Paths that reach only internal services are less interesting than paths that reach crown jewels.

## Phase 3 — Score and Evaluate

For every promising path discovered in Phase 2:

```
energy_momentum_path(node_names)
```

Apply the bands strictly:
- **Under 20**: well defended. Record as a positive finding (good defense). Do NOT submit.
- **20-40**: moderate risk. Investigate the specific controls with `read_node` on braking hops. Note their limitations.
- **Over 40**: real signal. Investigate thoroughly. Check for compensating controls the graph might have missed.
- **Over 60**: high priority. Document and submit.

For the most interesting paths, compare them:
```
energy_compare_paths(path_a, path_b)
```

"This path scores 55 — the next-best alternative scores 18. The difference is [specific edge] where [control] provides resistance on path B but is absent on path A."

When you find braking energy, always identify the specific control:
```
read_node(braking_hop_source)
read_node(braking_hop_target)
```

Look for the control's **limitations** in the node description. A defense with a documented bypass is still a finding.

## Phase 4 — Submit

### Submission criteria

- **Submit** paths scoring above 20/100 with mostly accelerating energy. These paths present real structural risk.
- **Report but don't submit** paths where the model sees strong resistance (risk score under 20, mostly braking). These demonstrate the model working — it found the defenses. Report which controls create the resistance.
- **If ALL paths score under 20**: this is a positive finding. Report: "The model tested [N] chains across [M] categories. All scored under 20/100 — strong structural resistance across the board. Key controls: [list]." Don't submit low-score paths to flood the triage queue.

For paths that meet submission criteria:
```
submit_attack_path(nodes="entry_node -> intermediate -> target_node", description="[plain language: why it matters]", report="[detailed analysis with energy evidence]")
```

Note: `nodes` is mandatory — a string with node names separated by ` -> `. The `load_graph_energies` call handles graph loading, but if submission fails with "no_graph_loaded", call `load_branch(branch_id)` first.

## Phase 5 — Report

Summarize:

1. **Paths submitted**: [N] paths with risk scores [range]. The highest-risk path is [description] at [score]/100.
2. **Structural defenses found**: [list defensive nodes and what they protect]. These create [X-Y] braking energy on paths through them.
3. **Gaps in defenses**: [any controls with documented limitations, bypass paths, or inconsistent coverage].
4. **Unreachable targets**: [targets with no viable low-resistance path from any entry point — this is good news].
5. **Coverage**: categories swept (credentials, data stores, CI/CD, IAM, network). Any categories not covered and why.

## Saving Research State

Save research progress to the active project after each phase:

```
triage_save_project(project_id, updates={
  "coverage_areas": ["credentials", "data_stores", "ci_cd", "iam", "network"],
  "notes": "Research summary: [N] paths discovered, [M] submitted, [K] defensive controls identified"
})
```

For each submitted path:
```
triage_add_work_item(project_id, work_item={
  "type": "attack_path",
  "description": "path description",
  "risk_score": score,
  "status": "submitted"
})
```

For risk decisions (including decisions NOT to submit):
```
triage_add_decision(project_id, decision={
  "finding": "category or specific path",
  "verdict": "submit | well_defended | needs_verification",
  "rationale": "why — cite energy scores and structural evidence"
})
```

---

## Next Steps

- "Want to review the submitted paths?" → `/review`
- "Want to investigate a specific path deeper?" → `/investigate`
- "Want to explore the graph around a finding?" → `/explore`
- "Want to set up continuous monitoring?" → `/build`
- "Want to process a scanner report against this graph?" → `/triage`

## Key Rules

1. **Discover first, then score.** Use energy tools to find what exists in the graph, then score what you find. Don't guess at paths — let the energy guide you to them.
2. **Don't submit everything.** Only submit paths that score above 20 AND have mostly accelerating energy. Low-score paths with strong resistance are positive findings, not triage items.
3. **Find defenses, not just risks.** The model's ability to detect compensating controls is a core value. Report what's working.
4. **Compare paths to each other.** "This path scores 35, the next-best scores 12" is actionable. "This path scores 35" alone is not.
5. **Verify claims.** Energy scores are structural evidence. For exploitability decisions, verify version numbers, feature usage, and runtime configuration against actual systems. Energy tells you where to look. Verification tells you what's real.
