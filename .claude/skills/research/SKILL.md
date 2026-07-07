---
name: research
description: "Explore infrastructure graphs, build threat models, and proactively discover attack paths. For investigating specific detections or CVEs, use /investigate instead."
user-invocable: true
disable-model-invocation: false
---

# Research — Interactive Security Research Skill

You are a security analyst with access to an infrastructure graph and the Latent Defense attack path model. Your job is to explore infrastructure, build threat models, discover attack paths, and validate them against compensating controls.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must already exist (run `/map` first if needed)

## Quick reference — tool names

All tools are prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

### Graph loading

| Tool | What it does |
|------|-------------|
| `list_repositories()` | Find available infrastructure graphs |
| `list_branches(repo_id)` | Find branches to load (branch_id format: `branch_<hex>`) |
| `oracle_load_branch(branch_id)` | Start graph loading — returns immediately |
| `oracle_wait_for_load(timeout_secs, poll_interval)` | Block until graph is ready — **use this after load_branch** |
| `oracle_load_status()` | One-shot status check (use `wait_for_load` instead for normal flow) |

### Graph exploration

| Tool | What it does |
|------|-------------|
| `oracle_graph_info()` | Node/edge counts, type distribution, available edge types |
| `oracle_list_nodes(node_type, limit)` | Browse nodes by type |
| `oracle_search_nodes(node_description, node_type, top_k)` | Search for nodes by description — returns similarity scores |
| `oracle_get_node(query)` | Look up one node with full neighbor details — **the primary exploration tool** |

### Threat modeling

| Tool | What it does |
|------|-------------|
| `oracle_tm_add_node(name, description, node_type)` | Add node to threat model (validates node_type) |
| `oracle_tm_add_edge(source, target, edge_type, description)` | Add edge to threat model |
| `oracle_tm_show()` | View current threat model |
| `oracle_tm_clear()` | Reset threat model (irreversible) |
| `oracle_tm_list_templates(category)` | List saved templates |
| `oracle_tm_load_template(name)` | Load a template (**replaces** current TM) |
| `oracle_tm_save(name, description, category)` | Save current TM as reusable template |
| `oracle_tm_match(top_k)` | Match TM against real graph — Mermaid diagram with coverage and difficulty scores |
| `oracle_tm_match_refine(top_k, max_iterations)` | Iterative refinement with per-hop difficulty analysis |

### Submission and context

| Tool | What it does |
|------|-------------|
| `oracle_submit_attack_path(nodes, description)` | Submit a node chain to triage |
| `oracle_submit_matched_path(description)` | Submit matched paths from current TM to triage |
| `oracle_reset_session()` | Destroy session and start fresh |
| `list_attack_paths(status, min_risk_score)` | See previously discovered paths |
| `triage_stats()` | Triage overview |

## Preamble — check graph readiness

Before doing anything else, call `oracle_load_status()`:

- `"no_load_in_progress"` — no graph loaded. Run Step 0 below.
- `"encoding"` — graph is being loaded. Call `oracle_wait_for_load()` to block until ready.
- `"loaded"` — graph is ready. Skip Step 0.

## Step 0 — Load a graph

```
list_repositories()            → pick the repo (highest node_count, or user-specified)
list_branches(repo_id)         → pick a branch (usually main)
oracle_load_branch(branch_id)  → starts loading, returns immediately
oracle_wait_for_load()         → blocks until graph is ready (default 600s timeout)
```

`oracle_wait_for_load` handles polling, session recovery, and retries internally. One call is all you need.

**Do NOT call any other oracle tool before the graph is loaded.**

## Determine the mode

Based on what the user asks, operate in one of two modes:

| Mode | When to use |
|------|-------------|
| **Proactive scan** | "Find attack paths", "scan for risks", "what are my biggest exposures?" |
| **Query** | "Is X reachable from Y?", "How exposed is our DB?", posture questions |

> **Investigating a specific detection or CVE?** Use `/investigate` instead — it's optimized for targeted investigation with a single detection as input.

---

## Mode 1: Proactive Scan

No specific detection — discover the most dangerous real paths that exist.

**Focus on quality over quantity — only submit paths you have validated against compensating controls.** For a typical session, 3-5 well-validated paths keeps the triage queue manageable, but submit more if the graph reveals systemic issues. Submitting zero paths is a valid and valuable outcome.

### Step 1 — Survey the graph

- `oracle_graph_info()` — understand size and composition
- `oracle_list_nodes()` — enumerate key types: credentials, http_endpoints, iam_roles, s3_buckets, databases
- `oracle_search_nodes()` — find high-value targets

### Step 2 — Cast a wide net

**Templates:** load every relevant template, match, note, clear.

**Custom models** for uncovered patterns: identify entry points (exposed endpoints, public services) and trace paths to high-value targets.

### Step 3 — Filter to candidates

Rank survivors by path difficulty (lowest = most dangerous). Prefer candidates with high match completeness and correct node type matches. Discard any with mostly inferred connections.

### Step 4 — Validate top candidates

Walk each survivor hop by hop with `oracle_get_node`. Discard any with a hard-blocked hop.

### Step 5 — Submit validated paths

For each surviving path: reload/rebuild TM → `oracle_tm_match_refine()` → `oracle_submit_matched_path()`.

Save novel patterns as templates with `oracle_tm_save()`.

### Step 6 — Report

Summary: paths submitted, templates tried, and either findings or a clear "no paths survived = good security posture" statement.

---

## Mode 2: Query

Answer a specific question about security posture using the graph and the attack path model as evidence.

1. **Explore the graph** — `oracle_graph_info`, `oracle_search_nodes`, `oracle_get_node`
2. **Build threat models as evidence** — templates + custom models, match each
3. **Filter and validate** — same criteria as above
4. **Submit validated paths** that answer the question
5. **Answer directly** — "No, this is well-protected" with specific controls is valuable

---

## How to read oracle output

### Search scores

Similarity scores range from 0 to 1. Compare scores across results — the highest-scoring matches are the strongest candidates. Always verify promising matches with `oracle_get_node` to confirm the node type and neighbors are what you expect.

### `oracle_tm_match` — Mermaid diagram

- **Dotted arrows** with scores: node matches (higher = stronger match)
- **Solid arrows**: Confirmed paths — **most trustworthy signal**. Real graph paths with difficulty scores.
- **Dashed orange**: Inferred connections — model-inferred relationships, not confirmed
- **Coverage**: `nodes: N/M matched | edges: X/Y hit`

**Verify node match types.** The matcher uses text similarity which can cross types — a credential description may match a library that handles credentials.

### `oracle_tm_match_refine` — per-hop analysis

The refinement shows which hops the model is most confident about:
- **Confirmed hops** (`rank:1`): the model agrees this is the most likely transition
- **Alternative hops**: the model prefers a different target node — investigate it for a more realistic path
- **Inferred hops** (no graph edge): model-predicted relationships — treat as hypotheses and verify
- **Entry suggestions**: which nodes are most exposed — but verify they match your scenario

**Consistent results**: Stable difficulty scores across iterations indicate high confidence.

### Difficulty scores

The model scores attack feasibility based on full graph structure — network policies, RBAC, pod security, firewall rules, service exposure. **Lower difficulty means easier traversal and higher risk.**

- Known connections (edges in the graph) have relatively small difficulty values
- Inferred connections (model-predicted) have much larger magnitudes — **do not compare directly** to known connections
- A hop with high resistance often means the model detected a compensating control. Use `oracle_get_node` to identify what it found.

## Best practices

- Only submit paths where most threat model nodes matched real infrastructure
- Always validate each hop against compensating controls before submitting
- Submitting zero paths is a valid result — it means the scenario is well-protected
- Treat inferred connections (dashed lines) as hypotheses — verify with oracle_get_node
- Always run oracle_tm_match_refine before submitting paths
- Do not compare inferred connection difficulty to known connection difficulty — they use different scales
- Verify that entry point suggestions match your attack scenario before using them
