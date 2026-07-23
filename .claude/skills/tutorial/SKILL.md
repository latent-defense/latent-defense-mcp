---
name: tutorial
description: "Interactive walkthrough of the world model — load your graph, explore it, build a threat model, read energy scores, and understand what the signals mean. Uses your own infrastructure."
user-invocable: true
disable-model-invocation: false
---

# Tutorial — Learn the World Model

You are guiding a user through their first hands-on experience with the Latent Defense world model. This is not a presentation — it's an interactive session using THEIR infrastructure graph. The goal is to build confidence in the model's signals through direct observation.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must exist (if not, suggest `/map` first)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Graph loading**: `list_repositories`, `list_branches`, `oracle_load_branch`, `oracle_wait_for_load`
**Graph exploration**: `oracle_graph_info`, `oracle_list_nodes`, `oracle_search_nodes`, `oracle_get_node`
**Threat modeling**: `oracle_tm_clear`, `oracle_tm_add_node`, `oracle_tm_add_edge`, `oracle_tm_show`, `oracle_tm_match`, `oracle_tm_match_refine`, `oracle_tm_list_templates`, `oracle_tm_load_template`

---

## Phase 1 — See your infrastructure

Load the graph and show what's in it.

```
list_repositories()  → pick a repo (suggest the largest, or let user choose)
list_branches(repo_id)  → pick the main branch
oracle_load_branch(branch_id)
oracle_wait_for_load()
oracle_graph_info()
```

**If `list_repositories()` returns empty or only repos with 0 nodes**: the graph hasn't been mapped yet. Tell the user: "No infrastructure has been mapped. Run `/map` first, then come back to `/tutorial`." End here.

**If `oracle_wait_for_load()` times out**: suggest trying again in a few minutes or checking `/status` for service health.

Show the user:
- Total nodes and edges
- Node type distribution — what kinds of infrastructure the model sees
- Available edge types — the relationships between components

Narrate: "This is your infrastructure as the world model sees it. [X] nodes representing [list top types]. The model encoded every node and every edge — it learned the structural patterns in your infrastructure."

Ask: "Want to explore a specific area? Pick something you're curious about — credentials, endpoints, databases, security boundaries."

## Phase 2 — Search and inspect

Let the user drive. Based on what they're curious about, search the graph:

```
oracle_search_nodes("description of what they want to find", node_type="relevant_type", top_k=5)
```

Show the results — name, type, similarity score, description. Then pick the most interesting one and inspect it:

```
oracle_get_node("name or description of the node")
```

Walk through the output:
- **The node itself** — its type, description, what it represents
- **Its neighbors** — every connected node, the edge type, the direction
- **What this reveals** — "This service has `accesses` edges to 2 data stores and `depends_on` edges to 5 packages. It's contained in a root container. That's the structural context no scanner sees."

Ask: "See anything interesting? Any connection you didn't expect, or something that looks exposed?"

## Phase 3 — Build your first threat model

Guide them through building a simple attack hypothesis and testing it.

"Let's test a hypothesis against your real infrastructure. Think of a question: 'Could an attacker reach [something valuable] from [an entry point]?' We'll describe that chain abstractly, and the model will tell us if it exists and how much resistance each step presents."

```
oracle_tm_clear()
oracle_tm_add_node("entry", "description matching a real entry point", "http_endpoint")
oracle_tm_add_node("target", "description matching a real target", "data_store")
oracle_tm_add_edge("entry", "target", "accesses", "how they might connect")
```

Use descriptions that mirror the real graph node descriptions from Phase 2. The model matches by semantic similarity — vague descriptions produce poor matches.

```
oracle_tm_match(top_k=5)
```

## Phase 4 — Read the results

Walk through the match output:

"The model searched your real infrastructure for components matching our hypothesis."

- **Matched nodes** (dotted arrows): "It found [real node] as a match for our abstract [entry point]. The similarity score is [X] — [high/moderate match]."
- **Confirmed paths** (solid arrows): "There IS a real path between these nodes in your graph. The difficulty score tells us how much resistance the infrastructure presents."
- **Coverage**: "Our 2-node hypothesis matched [N/M] nodes. [High/low coverage] means [the chain exists/doesn't exist] in your infrastructure."

If coverage is reasonable, refine:

```
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

Now walk through the energy scores:

"Here's what the model learned about each step in this path:"

For each hop, explain:
- **Negative energy (accelerating)**: "This hop has energy [X]. The infrastructure presents low resistance here — [explain why based on the nodes involved, e.g., 'a direct routes_to edge with no auth check between them']."
- **Positive energy (braking)**: "This hop has energy [X]. The model detected resistance — something is making this step harder. Let's find out what."
  → Use `oracle_get_node` on both endpoints to find the security boundary or auth check creating the resistance.
  → "The model found [specific control]. That's why this hop brakes. But notice the description also says [limitation/gap if any]."

"The risk score for this path is [X]/100. A score under 20 means your infrastructure has strong structural resistance along this path — that's a good thing, not a finding. Over 40 means this path deserves attention."

**Important: implicit vs explicit edges.** If you see a hop with energy magnitude of 10+ next to one with magnitude 1.4, they're on different scales. Confirmed paths (explicit edges) have smaller energy magnitudes. Model-inferred paths (implicit edges, shown as dashed lines) have inflated magnitudes — never compare them directly.

**Difficulty labels** (trivial/easy/medium/hard/extreme) describe attacker economics, not skill requirements. "Easy" means an attacker (or AI agent) who finds this path will keep going rather than pivoting. "Extreme" means the structural resistance makes pivoting elsewhere more rational. AI agents have collapsed the skill floor — what matters is whether the path presents enough resistance to deter, not whether a human could execute it.

## Phase 5 — See the model detect a defense

This is the trust-building moment. Find a path with braking energy and show that the model correctly identified a real compensating control.

Either use the path from Phase 4 if it has braking hops, or build a new threat model targeting a well-defended area:

```
oracle_tm_clear()
// Build a chain through a security boundary
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

"See hop 3? Energy +4.2, braking. The model is telling us something resists here. Let's look:"

```
oracle_get_node("the security boundary node")
```

"This is [specific control — sandbox, auth middleware, network policy]. The model learned from the graph structure that this control creates resistance. It didn't follow a rule — it learned this from the patterns in your infrastructure."

"But notice: [read the description for any documented gap]. The model captures both the defense AND its limitations."

## Phase 6 — Next steps

Based on what they found interesting, point them to the right skill:

- "Want to explore more of your graph?" → `/explore`
- "Want to investigate a specific CVE or finding?" → `/investigate`
- "Want to process a full scanner report?" → `/triage-report`
- "Want to proactively search for attack paths?" → `/research`
- "Want to build an automation on top of this?" → `/build`

---

## How to narrate

- Let the user drive where possible. Ask what they're curious about.
- Use THEIR graph data, not hypothetical examples. Every number, every node, every edge should come from their actual infrastructure.
- When showing energy scores, explain what they mean for THIS specific hop — "energy -1.4 here because there's a direct routes_to edge with no security boundary between these services." Don't just say "negative = bad."
- When showing braking energy, always find the specific control. "The model detects resistance because [X]" is the trust moment.
- Don't oversell. If coverage is low, say so: "The model couldn't find this chain in your graph — which is actually useful information."
- Don't use scanner-severity language (critical/high/medium) for risk scores. Say "this path scores [X]/100" and compare to other paths.
