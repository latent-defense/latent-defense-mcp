---
name: world-model-guide
description: "Context-only skill — loads instructions on how to use the JEPA world model, interpret energy scores, build threat models, and read match results. No actions, just knowledge. Used by workflow agents."
user-invocable: true
disable-model-invocation: false
---

# World Model Guide — How to Use the JEPA Model

This skill loads context on how to correctly use the Latent Defense JEPA world model. It does not perform any actions — it teaches you how to interpret the model's signals and use the threat modeling tools correctly.

**Use this when:** you're an agent in a workflow that needs to interact with the world model, or a user who wants a reference without running a full tutorial.

---

## What the world model is

The JEPA (Joint Embedding Predictive Architecture) model encodes your entire infrastructure graph — every node, every edge, every relationship — and learns structural patterns. You access it through **threat model matching**: describe an abstract attack chain, and the model tells you which parts exist in your real infrastructure and how much resistance each step presents.

## Tools you use

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

### Graph loading (required before anything else)
- `oracle_load_branch(branch_id)` — load a graph into the session. Returns immediately; use `oracle_wait_for_load` after.
- `oracle_wait_for_load(timeout_secs, poll_interval)` — block until the graph finishes loading
- `oracle_reset_session()` — destroy the session and start fresh (needed to switch graphs)

### Graph exploration (structural data, no energy scores)
- `oracle_graph_info()` — node/edge counts, type distribution, available edge types. **Call this to discover valid node types for your graph.**
- `oracle_search_nodes(node_description, node_type, top_k)` — semantic search
- `oracle_get_node(query)` — full node detail with all neighbors and edge types
- `oracle_list_nodes(node_type, limit)` — browse by type

### Threat model matching (THIS is where you get energy scores)
- `oracle_tm_clear()` — reset the threat model
- `oracle_tm_add_node(name, description, node_type)` — add a node to your hypothesis
- `oracle_tm_add_edge(source, target, edge_type, description)` — add an edge
- `oracle_tm_show()` — view current threat model
- `oracle_tm_match(top_k)` — match against the real graph → coverage + Mermaid diagram
- `oracle_tm_match_refine(top_k, max_iterations)` — iterative refinement → per-hop energy scores
- `oracle_tm_list_templates(category)` — list pre-built templates
- `oracle_tm_load_template(name)` — load a template (replaces current TM)

### Submission and saving
- `oracle_submit_matched_path(description)` — submit a scored path from the current threat model to triage
- `oracle_submit_attack_path(nodes, description)` — submit a node chain to triage. `nodes` is a string with descriptions separated by ` -> ` (e.g., `"public API gateway -> auth service -> production database"`)
- `oracle_tm_save(name, description, category, source_template)` — save the current threat model as a reusable template. Categories: `identity`, `network`, `data`, `supply_chain`, `cloud_services`

---

## How to build a threat model

A threat model is an **abstract kill chain** — it describes what WOULD happen if an attack succeeded. The model then tells you if the chain exists in the real graph.

### Step 1: Find real nodes first

Before building the threat model, use `oracle_search_nodes` and `oracle_get_node` to find the real infrastructure components. Read their descriptions — you'll need to mirror that language.

### Step 2: Build the abstract chain

```
oracle_tm_clear()

oracle_tm_add_node("entry", "description matching a real entry point you found", "http_endpoint")
oracle_tm_add_node("service", "description matching a service you found", "service")
oracle_tm_add_node("target", "description matching a high-value target", "data_store")

oracle_tm_add_edge("entry", "service", "calls", "how entry reaches the service")
oracle_tm_add_edge("service", "target", "accesses", "how the service accesses the target")
```

**Node types must be valid.** Common types: `http_endpoint`, `service`, `package`, `credential`, `data_store`, `s3_bucket`, `container`, `security_boundary`, `function`, `cloud_resource`, `iam_role`, `user_account`

**Edge types.** Use types that match the graph. Call `oracle_graph_info()` to see available edge types. Common ones: `calls`, `accesses`, `reads_from`, `writes_to`, `depends_on`, `contains`, `uses`, `authenticates_with`, `connected_to`, `data_flows_to`

**Descriptions matter.** The model matches by semantic similarity. "PostgreSQL database storing application state" matches better than "database". Mirror the language from real graph node descriptions.

### Step 3: Match and refine

```
oracle_tm_match(top_k=5)          // Get coverage and Mermaid diagram
oracle_tm_match_refine(top_k=5, max_iterations=3)  // Get per-hop energy
```

---

## How to read `oracle_tm_match` output

The output is a Mermaid diagram showing:

- **Dotted arrows (-.->)** with scores: your abstract node matched a real graph node. Higher score = better match. **Always verify the matched node has the correct type** — text similarity can cross types.
- **Solid arrows (-->)** with difficulty: confirmed paths between matched nodes. Real graph edges with real energy. **This is the most trustworthy signal.**
- **Dashed orange arrows**: inferred connections — the model predicts a relationship but it's not a confirmed edge. Treat as hypotheses.
- **Coverage**: `nodes: N/M matched | edges: X/Y hit`. High coverage (≥70%) means the chain exists. Low coverage (<50%) means it doesn't.

## How to read `oracle_tm_match_refine` output

The refinement gives you:

### Entry candidates
Nodes the model thinks are viable entry points:
- `energy: -0.77` = low resistance (exposed entry point)
- `energy: 0.44` = some resistance (less exposed)
- `classifier: 0.46` = model's confidence this is an entry point

### Per-hop energy breakdown
```
| # | hop | energy | effect |
| 1 | gateway → service | -1.44 | accelerate |
| 2 | service → middleware | +2.77 | brake |
| 3 | middleware → database | -0.68 | accelerate |
```

### Risk score (momentum model)
An integrated score from 0-100:
- **0–20**: strong structural resistance. Well defended. Not a finding.
- **20–40**: moderate resistance. Investigate controls and their gaps.
- **40–60**: low resistance. Deserves attention.
- **60–80**: little resistance. High priority.
- **80–100**: almost no resistance.

If all paths score under 20, the infrastructure is well defended. Pivot to other areas rather than treating low-score paths as findings.

---

## Energy interpretation

**Energy = structural resistance.** How much the infrastructure resists an attacker at each edge.

- **Negative (accelerating)**: low resistance. Clear, unobstructed connection. The attacker has a straightforward path forward.
- **Positive (braking)**: the infrastructure resists. A security boundary, auth check, or structural barrier creates friction. Use `oracle_get_node` on both endpoints to find the specific control.
- **Magnitude**: -3.0 is much less resistance than -0.5. +4.5 is a strong barrier.
- **Implicit edges**: have inflated energy magnitudes. Never compare implicit edge energy to explicit edge energy.

Energy is NOT confidence, certainty, or probability.

## Difficulty interpretation

Difficulty labels (trivial, easy, medium, hard, extreme) describe **attacker economics**, not skill requirements. AI agents have made skill-based difficulty nearly obsolete.

- **Easy/trivial**: an attacker who finds this path will keep going. Low structural resistance.
- **Hard/extreme**: structural resistance makes pivoting elsewhere more rational.

## Compensating controls

Braking energy means the model detected a barrier. Always:
1. Find the specific control with `oracle_get_node` on the braking hop's endpoints
2. Read the control's description for documented limitations/gaps
3. Report both what the control does AND what it doesn't cover

## Common mistakes to avoid

1. **Using only graph lookups without `tm_match`/`tm_match_refine`**: graph lookups give structure, not energy. You MUST use threat model matching to get the model's assessment.
2. **Calling a 7/100 risk score "critical"**: under 20 means well defended. The infrastructure is doing its job.
3. **Comparing implicit edge energy to explicit edge energy**: they're on different scales. A +4.6 implicit hop is not 4x harder than a +1.2 explicit hop.
4. **Building threat models without grounding in real nodes**: always search/get_node first, then build your TM with descriptions that mirror real graph language.
5. **Submitting every path you find**: only submit paths scoring above 20/100 with mostly accelerating energy. Low-score paths flood the triage queue.
6. **Interpreting difficulty as skill requirement**: it's about attacker economics (will they continue or pivot?), not whether a human could do it.
