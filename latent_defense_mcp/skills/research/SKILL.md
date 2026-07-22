---
name: research
description: "Proactive attack path discovery — explore the graph, build threat models, test hypotheses against real infrastructure, and discover paths no scanner flagged. For investigating a specific CVE or detection, use /investigate instead."
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

**Graph loading**: `list_repositories`, `list_branches`, `oracle_load_branch`, `oracle_wait_for_load`
**Graph exploration**: `oracle_graph_info`, `oracle_list_nodes`, `oracle_search_nodes`, `oracle_get_node`
**World model**: `oracle_tm_clear`, `oracle_tm_add_node`, `oracle_tm_add_edge`, `oracle_tm_show`, `oracle_tm_match`, `oracle_tm_match_refine`, `oracle_tm_list_templates`, `oracle_tm_load_template`, `oracle_tm_save`
**Submission**: `oracle_submit_matched_path`, `oracle_submit_attack_path`
**Context**: `list_attack_paths`, `triage_stats`

---

## Phase 1 — Orient

Load the graph and understand its shape. If the user doesn't know which graph to use, suggest `/my-data` to see all available graphs.

```
oracle_graph_info()  → node/edge counts, type distribution
```

Survey the key types:
```
oracle_list_nodes(node_type="http_endpoint", limit=20)   → entry points
oracle_list_nodes(node_type="data_store", limit=20)      → targets
oracle_list_nodes(node_type="credential", limit=30)      → secrets
oracle_list_nodes(node_type="security_boundary", limit=20) → defenses
oracle_list_nodes(node_type="s3_bucket", limit=10)       → storage
```

Check what's already been found:
```
list_attack_paths(limit=10, summary=true)
triage_stats()
```

Tell the user what you see: "Your graph has [X] entry points, [Y] high-value targets, [Z] security boundaries. [N] paths have already been discovered. I'll look for what's not been found yet."

## Phase 2 — Template sweep

Load and match EVERY relevant template. This is the systemic capability — testing known attack patterns against the real graph.

```
oracle_tm_list_templates()
```

For each template that matches the infrastructure's tech stack (check the graph's node types — if it has K8s nodes, try K8s templates; if it has IAM roles, try cloud templates):

```
oracle_tm_load_template(name)
oracle_tm_match(top_k=5)
// Record: coverage, confirmed paths, difficulty, whether it found something new
oracle_tm_clear()
```

Track results:
- Templates with high coverage (>70%) → promising, refine these
- Templates with moderate coverage (40-70%) → partial matches, investigate
- Templates with low coverage (<40%) → this pattern doesn't exist here

## Phase 3 — Deep dive on promising matches

For each template that showed high coverage:

```
oracle_tm_load_template(name)
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

Read the per-hop energy:
- **Accelerating hops**: what makes these connections frictionless?
- **Braking hops**: use `oracle_get_node` to find the specific control creating resistance. Note its documented limitations.

Record the risk score and compare across all templates tested.

## Phase 4 — Custom threat models

Build threat models for patterns the templates didn't cover. Focus on:

1. **Entry point → crown jewel chains**: for each major entry point, build a chain to each major target. How many hops? What's in between?

2. **Credential harvest paths**: for each credential in the graph, is there a path from an entry point to it? What controls stand in the way?

3. **Lateral movement**: from any compromised service, what else is reachable? Look for services with many `accesses` edges.

4. **Security boundary bypass**: for each security boundary, is there a path that goes AROUND it rather than through it?

Build each as a threat model:
```
oracle_tm_clear()
oracle_tm_add_node(...)  // entry
oracle_tm_add_node(...)  // pivot or vulnerable service
oracle_tm_add_node(...)  // target
oracle_tm_add_edge(...)  // connections
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

Use descriptions from REAL graph nodes (found via `oracle_search_nodes` or `oracle_get_node`). The model matches by semantic similarity.

## Phase 5 — Rank and submit

Rank ALL paths found (from templates and custom models) by risk score.

### Submission criteria

- **Submit** paths scoring above 20/100 with mostly accelerating energy. These paths present real structural risk.
- **Report but don't submit** paths where the model sees strong resistance (risk score under 20, mostly braking). These demonstrate the model working — it found the defenses. Report which controls create the resistance.
- **If ALL paths score under 20**: this is a positive finding. Report: "The model tested [N] chains. All scored under 20/100 — strong structural resistance across the board. Key controls: [list]." Don't submit low-score paths to flood the triage queue.

For paths that meet submission criteria:
```
oracle_submit_matched_path(description="[plain language: entry → path → target. Why it matters.]")
```

Save novel patterns as templates:
```
oracle_tm_save(name="descriptive-kebab-case", description="what this template tests", category="appropriate_category")
```

## Phase 6 — Report

Summarize:

1. **Paths submitted**: [N] paths with risk scores [range]. The highest-risk path is [description] at [score]/100.
2. **Structural defenses found**: [list security boundaries and what they protect]. These create [X-Y] braking energy on paths through them.
3. **Gaps in defenses**: [any controls with documented limitations or bypass paths].
4. **What the model couldn't reach**: [targets with no viable path from any entry point — this is good news].
5. **Templates matched vs not**: [N] of [M] templates found matches. The unmatched templates represent attack patterns not present in this infrastructure.

### Next steps
- "Want to review the submitted paths?" → `/review-paths`
- "Want to investigate a specific path deeper?" → `/investigate`
- "Want to explore the graph around a finding?" → `/explore`
- "Want to set up continuous monitoring?" → `/monitor`

---

## Energy interpretation

- **Negative energy (accelerating)**: low structural resistance. The infrastructure has a clear connection here.
- **Positive energy (braking)**: the model detected a barrier — find the specific control with `oracle_get_node`.
- **Risk scores 0-100**: under 20 = well defended (not a finding), 20-40 = moderate (investigate controls), over 40 = real signal, over 60 = high priority. If all paths score under 20, the infrastructure is well defended — pivot to other investigation areas.
- **Implicit edges**: have inflated energy magnitudes. Don't compare to explicit edge energy.
- **Difficulty labels**: attacker economics (will they keep going or pivot?), not skill requirements.

## Key rules

1. **Run the template sweep first.** Templates test known patterns systematically. Custom models fill gaps the templates miss.
2. **Use the model for every hypothesis.** Don't reason about exploitability from node descriptions alone — build a threat model and match it.
3. **Don't submit everything.** Only submit paths that rank highly AND have mostly accelerating energy. Low-score paths with strong resistance are positive findings, not triage items.
4. **Find defenses, not just risks.** The model's ability to detect compensating controls is a core value. Report what's working.
5. **Compare paths to each other.** "This path scores 35, the next-best scores 12" is actionable. "This path scores 35" alone is not.
