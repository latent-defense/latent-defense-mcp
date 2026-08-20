---
name: world-model-guide
description: "Context-only skill — loads instructions on how to use the JEPA world model, interpret energy scores, investigate with the energy method, and read results. No actions, just knowledge. Used by workflow agents."
user-invocable: true
disable-model-invocation: false
---

# World Model Guide — How to Use the JEPA Model

This skill loads context on how to correctly use the Latent Defense JEPA world model. It does not perform any actions — it teaches you how to interpret the model's signals and investigate using the energy-first method.

**Use this when:** you're an agent in a workflow that needs to interact with the world model, or a user who wants a reference without running a full tutorial.

---

## What the world model is

The JEPA (Joint Embedding Predictive Architecture) model encodes your entire infrastructure graph — every node, every edge, every relationship — and learns structural patterns. You access it through **energy analysis**: load the graph into a local SQLite cache, query structural data and energy scores, trace paths, and score resistance. The model tells you where infrastructure accelerates or resists an attacker at every step.

## Tools you use

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

### Graph loading (required before anything else)
- `load_graph_energies(branch_id)` — load the full graph and energy scores into a local SQLite database. This is the single entry point — it handles JEPA warm-up, polling, and data fetch internally. The cache survives process restarts; subsequent loads are instant.

### Graph structure (read the infrastructure)
- `read_node(name)` — full node detail: type, description, properties, metadata
- `read_edge(edge_id)` — edge detail: source, target, type, description
- `get_connected_edges(name)` — all edges connected to a node, with neighbors
- `get_graph_statistics()` — node/edge counts, type distribution, available edge types. **Call this to discover valid node types for your graph.**
- `grep_nodes(pattern)` — substring search across node names and descriptions
- `grep_edges(pattern)` — substring search across edge descriptions
- `find_nodes_by_type(node_type)` — list all nodes of a given type
- `find_edges_by_type(edge_type)` — list all edges of a given type

### Energy analysis (read the model's assessment)
- `energy_node_scores(name)` — entry energy and connected edge energies for a node
- `energy_edge_scores(source_query, target_query)` — energy for a specific edge
- `energy_momentum_path(node_names)` — compute the momentum-based risk score (0-100) along a specific node sequence
- `energy_lowest_hop(name)` — find the lowest-energy (most accelerating) edge from a node
- `energy_lowest_paths(name)` — beam-search discovery of low-resistance paths from a node
- `energy_trace_to_target(source, target)` — find the lowest-energy path between two specific nodes
- `energy_compare_paths(path_a, path_b)` — side-by-side comparison of two paths
- `energy_node_neighborhood(name, hops)` — map the energy landscape around a node within N hops
- `energy_entry_points()` — find exposed nodes (attacker starting positions)
- `energy_defenses()` — find defense nodes (controls creating resistance)
- `energy_top_attack_paths()` — global most-dangerous paths across the graph
- `energy_chokepoints()` — nodes where many attack paths converge

### Submission
- `submit_attack_path(nodes, description)` — submit a discovered path to the triage queue. `nodes` is a string with node names separated by ` -> ` (e.g., `"public API gateway -> auth service -> production database"`)

---

## The Five Moves

Every investigation — whether it's a CVE, a scanner finding, or proactive discovery — follows the same five moves. Skills differ in which move they emphasize, not in the method.

### Move 1: Ground

Find the real infrastructure nodes related to your question.

- `grep_nodes(pattern)` — for known names, package names, service names
- `find_nodes_by_type(type)` — for categories (all credentials, all data stores, all endpoints)
- `get_graph_statistics()` — for orientation (what types exist, how many)

**Never start from abstraction.** Find what actually exists in the graph first.

### Move 2: Position

Understand each node's structural role.

- `energy_node_scores(name)` — shows entry energy and connected edge energies. Is this node exposed? Is it heavily connected? Are its edges mostly accelerating or braking?
- `energy_node_neighborhood(name, hops=2)` — maps the local terrain. How many accelerating vs braking edges surround it? What's the energy landscape?
- `get_connected_edges(name)` — shows who connects to what, with edge types and directions

### Move 3: Trace

Find paths through the infrastructure.

- `energy_trace_to_target(source, target)` — for a specific source-to-target pair. Returns the lowest-energy path with per-hop energy.
- `energy_lowest_paths(name)` — beam-search discovery from a node. Finds multiple low-resistance paths radiating outward.
- `energy_top_attack_paths()` — global view of the most dangerous paths across the entire graph.

Each path comes with per-hop energy scores showing which steps accelerate and which brake.

### Move 4: Score

Evaluate paths quantitatively.

- `energy_momentum_path(node_names)` — computes the momentum-based risk score (0-100) along a specific node sequence
- `energy_compare_paths(path_a, path_b)` — puts two paths side-by-side for comparison

Apply the risk score bands to determine significance (see below).

### Move 5: Verify

**Energy tells you where to look. Verification tells you what's real.**

Agents use their access to verify what the energy signals surfaced:

Evidence hierarchy (strongest to weakest):
1. **Source code** — read the actual code via GitHub API
2. **Config files** — check Dockerfiles, Kubernetes manifests, IAM policies, CI configs
3. **Cloud API state** — query AWS/Azure/GCP APIs for live configuration
4. **Semantic context** — the graph node descriptions capture what mapping found
5. **Graph structure** — the relationships between nodes
6. **Energy scores** — the model's structural assessment

Verification examples:
- Check that the CVE actually applies to the deployed version
- Check that the IAM role actually has those permissions
- Check that the config actually exposes what the graph says it exposes
- Check that the security boundary described in the node is actually enforced

Energy scores are the input to investigation, never the output.

---

## Energy interpretation

### Entry energy

Every node has an entry energy score representing how accessible it is as an attacker's starting point.
- **Negative entry energy**: low resistance to initial access. The node is exposed.
- **Positive entry energy**: resistance to initial access. The node is not easily reachable from outside.

### Transition energy (per-edge)

Each edge has an energy score representing structural resistance along that connection.
- **Negative (accelerating)**: low resistance. Clear, unobstructed connection. The attacker has a straightforward path forward.
- **Positive (braking)**: the infrastructure resists. A security boundary, auth check, or structural barrier creates friction.
- **Magnitude matters**: -3.0 is much less resistance than -0.5. +4.5 is a strong barrier.

Energy is NOT confidence, certainty, or probability. It is a structural property of the graph that the model learned.

### Momentum model

Momentum is the cumulative effect of energy along a path. It uses a sigmoid model:
- Accelerating edges (negative energy) increase momentum — the attacker gains speed
- Braking edges (positive energy) decrease momentum — controls slow the attacker down
- The final momentum maps to a risk score (0-100)

The sigmoid means early hops have outsized influence — a strong entry with low resistance creates momentum that subsequent controls must overcome.

### Risk score bands

- **0-20**: Strong structural resistance. Well defended. Not a finding. If all paths score here, the infrastructure is solid — pivot to investigating other areas.
- **20-40**: Moderate resistance. Some accelerating hops but controls create friction. Investigate the specific controls and their gaps.
- **40-60**: Low resistance on significant portions. This path deserves attention.
- **60-80**: Little structural resistance. Most hops accelerate. High priority for remediation.
- **80-100**: Almost no resistance. The infrastructure accelerates the attacker across nearly every hop.

These bands are empirically derived. A score of 7 means the infrastructure is well defended on this path — full stop.

Risk scores measure structural resistance, not scanner severity (critical/high/medium). They are complementary signals — a CVSS-10 CVE on a path scoring 5/100 is less urgent than a CVSS-6 CVE on a path scoring 55/100.

### Implicit vs explicit edge energy

- **Explicit edges** (confirmed in the graph): smaller energy magnitudes (typically -3 to +5)
- **Implicit edges** (model-inferred, not confirmed): much larger energy magnitudes (10+)

Never compare them on the same scale. A +4.6 implicit hop is NOT 4x harder than a +1.2 explicit hop — they operate on fundamentally different scales.

### Difficulty labels

Difficulty labels (trivial, easy, medium, hard, extreme) describe **attacker economics**, not skill requirements. AI agents have made skill-based difficulty nearly obsolete.

- **Easy/trivial**: an attacker who finds this path will keep going. Low structural resistance makes continuing more rational than pivoting.
- **Hard/extreme**: structural resistance makes pivoting elsewhere more rational.

### Compensating controls

Braking energy means the model detected a barrier. Always:
1. Use `read_node` on both endpoints of the braking hop to find the specific control
2. Read the control's description for documented limitations/gaps
3. Report both what the control does AND what it doesn't cover

The graph often captures both the defense and its gaps (e.g., "sandbox restricts filesystem but VCA retains network access to localhost").

---

## When to submit paths

Submit paths to the triage queue when:
- Risk score > 20/100 (paths at or above moderate resistance)
- Mostly accelerating energy along the path
- The path reaches a valuable target (data store, credential, admin access)

Do NOT submit:
- Paths scoring under 20 — these are well defended, not findings
- Paths where braking controls adequately cover the attack scenario
- Every path you discover — only submit paths that warrant human review

Use `submit_attack_path(nodes, description)` with a clear description of the attack scenario.

---

## Structural query patterns

Each pattern is a sequence of tool calls that answers a common security question directly from the graph.

### Credential theft
```
find_nodes_by_type("credential")
→ energy_node_scores on each credential
→ energy_trace_to_target from entry points to exposed credentials
→ energy_momentum_path on discovered paths
```

### Lateral movement
```
energy_entry_points()
→ energy_lowest_paths from each entry point
→ filter paths reaching sensitive targets (data stores, admin nodes)
→ energy_momentum_path on candidate paths
```

### Data exfiltration
```
find_nodes_by_type("data_store") + find_nodes_by_type("s3_bucket")
→ energy_trace_to_target from entry points to each data store
→ energy_momentum_path on discovered paths
```

### Supply chain
```
grep_nodes("ci") + grep_nodes("pipeline") + grep_nodes("github")
→ energy_node_neighborhood on CI/CD nodes
→ energy_lowest_paths from CI nodes toward production
→ energy_momentum_path on candidate paths
```

### Privilege escalation
```
grep_nodes("iam") + grep_nodes("role") + grep_nodes("admin")
→ energy_lowest_paths from low-privilege nodes
→ filter paths reaching admin/root/owner nodes
→ energy_momentum_path on candidate paths
```

---

## Common mistakes to avoid

1. **Treating energy scores as conclusions**: energy scores tell you WHERE to look. They are signals for investigation, not verdicts. Always verify against source code, config, and cloud API state before reporting a finding.

2. **Calling low scores "critical"**: a score of 7/100 means well defended. Under 20 means the infrastructure is doing its job. Don't treat the highest-scoring low path as a finding just because it's the highest — if everything is under 20, the conclusion is "well defended."

3. **Comparing implicit and explicit edge energy on the same scale**: implicit edges have inflated energy magnitudes by design. A +12 implicit hop is not comparable to a +1.2 explicit hop. Only compare edges of the same type.

4. **Skipping verification**: energy tells you where to look. You MUST verify with source code, config files, or cloud API state before drawing conclusions. The evidence hierarchy is: source code > config > cloud API > semantic context > graph > energy.

5. **Submitting every path found**: only submit paths scoring above 20/100 with mostly accelerating energy. Low-score paths flood the triage queue with non-findings. If every path scores under 20, report "well defended infrastructure" rather than submitting the highest-scoring low path.

6. **Treating risk score as scanner severity**: risk scores (0-100, structural resistance) and scanner severity (critical/high/medium/low) are complementary, not interchangeable. A CVSS-10 CVE on a path scoring 5 is less urgent than a CVSS-6 CVE on a path scoring 55.

7. **Starting from abstraction instead of grounding**: always find real nodes first with `grep_nodes` or `find_nodes_by_type`. Starting with imagined attack scenarios and hoping the graph confirms them produces poor results. Discover what exists, then assess it.

8. **Ignoring braking energy**: when the model shows braking (positive energy), that is a defense finding. Always identify the specific control with `read_node` on both endpoints, document what it does and what gaps it has. Defenses are findings too.
