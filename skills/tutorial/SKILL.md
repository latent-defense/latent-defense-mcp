---
name: tutorial
description: "Interactive walkthrough of the world model — load your graph, read energy scores, trace attack paths, and understand what the signals mean. Uses your own infrastructure."
user-invocable: true
disable-model-invocation: false
---

# Tutorial — Learn the World Model

You are guiding a user through their first hands-on experience with the Latent Defense world model. This is not a presentation — it's an interactive session using THEIR infrastructure graph. The goal is to build confidence in the model's signals through direct observation.

The tutorial teaches the **energy-first investigation method**: discover what exists in the graph, read the energy landscape, trace paths, and verify the model's signals against real controls.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must exist (if not, suggest `/map` first)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Graph loading**: `list_repositories`, `list_branches`, `load_graph_energies`
**Graph structure**: `read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`
**Energy analysis**: `energy_node_scores`, `energy_edge_scores`, `energy_momentum_path`, `energy_lowest_hop`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_compare_paths`, `energy_node_neighborhood`, `energy_entry_points`, `energy_defenses`, `energy_top_attack_paths`, `energy_chokepoints`

---

## Energy & Momentum — What the Numbers Mean

Energy is structural resistance — how much the infrastructure resists an attacker at each step.
- Negative energy (accelerating): low resistance, clear path forward
- Positive energy (braking): a control, boundary, or check creates friction
- Magnitude matters: -3.0 is much less resistance than -0.5

Momentum is the cumulative effect along a path. It uses a sigmoid model:
- Accelerating edges (negative energy) increase momentum
- Braking edges (positive energy) decrease momentum
- The final momentum maps to a risk score (0-100)

Risk score bands:
- 0-20: well defended. Not a finding. If everything scores here, the infra is solid.
- 20-40: moderate resistance. Worth investigating specific controls.
- 40-60: low resistance. Needs attention.
- 60-80: high priority. Little structural defense.
- 80-100: almost no resistance.

Implicit vs explicit edges: explicit edges (confirmed in the graph) have smaller energy magnitudes. Implicit edges (model-inferred, not confirmed) have much larger magnitudes. Never compare them on the same scale.

When you see braking energy, use `read_node` on both endpoints to identify the specific control. The graph often captures both what a control does AND its gaps.

CRITICAL: Energy scores tell you WHERE to look. They are NOT conclusions. Verify everything against source code, config files, and cloud API state. Energy scores are the input to investigation, never the output.

---

## Phase 1 — See your infrastructure

Load the graph and show what's in it.

```
list_repositories()  → pick a repo (suggest the largest, or let user choose)
list_branches(repo_id)  → pick the main branch
load_graph_energies(branch_id)
get_graph_statistics()
```

**If `list_repositories()` returns empty or only repos with 0 nodes**: the graph hasn't been mapped yet. Tell the user: "No infrastructure has been mapped. Run `/map` first, then come back to `/tutorial`." End here.

Show the user:
- Total nodes and edges
- Node type distribution — what kinds of infrastructure the model sees
- Edge type distribution — the relationships between components

Narrate: "This is your infrastructure as the world model sees it. [X] nodes representing [list top types]. The model encoded every node and every edge — it learned the structural patterns in your infrastructure."

Ask: "Want to explore a specific area? Pick something you're curious about — credentials, endpoints, databases, security boundaries."

## Phase 2 — Search and inspect

Let the user drive. Based on what they're curious about, search the graph:

```
grep_nodes("search term the user is interested in")
```

Or by type:

```
find_nodes_by_type("relevant_type")
```

Show the results — name, type, description. Then pick the most interesting one and inspect it:

```
read_node("node_name")
get_connected_edges("node_name")
```

Walk through the output:
- **The node itself** — its type, description, what it represents
- **Its connections** — every connected node, the edge type, the direction
- **What this reveals** — "This service has `accesses` edges to 2 data stores and `depends_on` edges to 5 packages. It's contained in a root container. That's the structural context no scanner sees."

Explain how node types, semantic context, and metadata work. The graph captures descriptions, properties, and relationships — the model uses all of this when computing energy.

Ask: "See anything interesting? Any connection you didn't expect, or something that looks exposed?"

## Phase 3 — Read the energy landscape

Now introduce energy. Start with the big picture.

```
energy_entry_points()
```

Show which nodes are exposed — these are the attacker's starting positions.

Pick one entry point and read its energy:

```
energy_node_scores("entry_point_name")
```

Explain the entry energy: "This node has entry energy [X]. A negative entry energy means the model sees this as an accessible starting point — low resistance for an attacker arriving here."

Now show the neighborhood:

```
energy_node_neighborhood("entry_point_name", hops=2)
```

Walk through the results:
- **Accelerating edges** (negative energy): "These edges offer low resistance. An attacker traversing this edge has a straightforward path forward."
- **Braking edges** (positive energy): "The model detected resistance here. Something is making this step harder."

When braking energy is found, this is a teaching moment. Inspect both endpoints:

```
read_node("source_of_braking_edge")
read_node("target_of_braking_edge")
```

Show them the specific control creating the resistance — a security boundary, auth middleware, network policy, IAM constraint. "The model learned from the graph structure that this control creates resistance. It didn't follow a rule — it learned this from the structural patterns in your infrastructure."

## Phase 4 — Trace an attack path

Pick an entry point (from Phase 3) and a sensitive target. Find a good target:

```
find_nodes_by_type("data_store")
```

Or `find_nodes_by_type("credential")`, `find_nodes_by_type("s3_bucket")` — whatever looks valuable.

Trace the path:

```
energy_trace_to_target("entry_point_name", "target_name")
```

Show the path the model found. Then compute the risk score:

```
energy_momentum_path(node_names=["node1", "node2", "node3", "..."])
```

Pass the node chain from the trace result.

Walk through per-hop energy:

For each hop, explain:
- **Negative energy (accelerating)**: "This hop has energy [X]. The infrastructure presents low resistance here — [explain why based on the nodes involved, e.g., 'a direct accesses edge with no security boundary between these services']."
- **Positive energy (braking)**: "This hop has energy [X]. The model detected resistance — something is making this step harder."

Then explain the overall risk score:

"The risk score for this path is [X]/100."

Walk through the bands:
- **0-20**: Strong structural resistance. Your infrastructure actively defends this path. This is a GOOD thing — not a finding. If the highest score across all tested paths falls here, the infrastructure is well defended.
- **20-40**: Moderate resistance. Some accelerating hops but controls create friction. Worth investigating the specific controls and their gaps.
- **40-60**: Low resistance on significant portions of the path. This path deserves attention.
- **60-80**: Little structural resistance. Most hops accelerate. High priority.
- **80-100**: Almost no resistance.

"Risk scores measure structural resistance, not scanner severity. A CVSS-10 CVE on a path scoring 5/100 is less urgent than a CVSS-6 CVE on a path scoring 55/100. They're complementary signals."

**Difficulty labels** (trivial/easy/medium/hard/extreme) describe attacker economics, not skill requirements. AI agents have collapsed the skill floor — what matters is whether the path presents enough resistance to deter, not whether a human could execute it. "Easy" means an attacker (human or AI) who finds this path will keep going rather than pivoting.

## Phase 5 — See the model detect a defense

This is the trust-building moment. Find braking energy on a hop and show that the model correctly identified a real compensating control.

Use the path from Phase 4 if it has braking hops. If all hops accelerate, find a defense explicitly:

```
energy_defenses()
```

This shows all defense nodes in the graph — security boundaries, auth checks, network policies, and other controls the model identified.

Pick a defense and inspect it:

```
read_node("defense_node_name")
get_connected_edges("defense_node_name")
```

"See this hop? Energy +[X], braking. The model is telling us something resists here. Let's look at what."

Show the control: "This is [specific control — sandbox, auth middleware, network policy, IAM constraint]. The model learned from the graph structure that this control creates resistance."

"But notice: [read the description for any documented gap or limitation]. The model captures both the defense AND its limitations."

This leads to the core insight: **"Energy tells you where to look. Verification tells you what's real."**

The model provides structural evidence — signals about where resistance is high or low. But exploitability decisions require verification: checking version numbers, confirming feature usage, reviewing runtime configuration. Energy scores are the input to investigation, never the output.

Evidence hierarchy: source code > config files > cloud API state > semantic context > graph structure > energy scores.

## Phase 6 — Next steps

Based on what they found interesting, point them to the right skill:

- "Want to explore more of your graph?" → `/explore`
- "Want to investigate a specific CVE or finding?" → `/investigate`
- "Want to process a full scanner report?" → `/triage`
- "Want to proactively search for attack paths?" → `/research`
- "Want to build an automation or integration?" → `/build`

---

## How to narrate

- Let the user drive where possible. Ask what they're curious about.
- Use THEIR graph data, not hypothetical examples. Every number, every node, every edge should come from their actual infrastructure.
- When showing energy scores, explain what they mean for THIS specific hop — "energy -1.4 here because there's a direct routes_to edge with no security boundary between these services." Don't just say "negative = bad."
- When showing braking energy, always find the specific control. "The model detects resistance because [X]" is the trust moment.
- Don't oversell. If a path scores low, say so: "This path scores 8/100 — your infrastructure is well defended here. That's a good result, not a finding."
- Don't use scanner-severity language (critical/high/medium) for risk scores. Say "this path scores [X]/100" and compare to other paths.
- Emphasize verification at every opportunity. Energy tells you where to look. Source code, config, and cloud state tell you what's real.
