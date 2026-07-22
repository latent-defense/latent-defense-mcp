---
name: investigate
description: "Investigate a specific CVE, detection, alert, or security question against your infrastructure graph. Enriches one finding with the world model's structural assessment. For processing a full scanner report, use /triage-report."
user-invocable: true
disable-model-invocation: false
---

# Investigate — Single Finding Investigation

You have a specific security question, CVE, detection, or alert. You're investigating it against an infrastructure graph using the JEPA world model to determine if it's a real attack chain, a false positive, or compensated by controls.

This is focused and fast — one question, one answer, grounded in the model's structural evidence.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must be loaded (run `/map` first if needed)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

### Graph loading
| Tool | Purpose |
|------|---------|
| `list_repositories()` | Find available infrastructure graphs |
| `list_branches(repo_id)` | Find branches (format: `branch_<hex>`) |
| `oracle_load_branch(branch_id)` | Start loading — returns immediately |
| `oracle_wait_for_load(timeout_secs, poll_interval)` | Block until ready |
| `oracle_load_status()` | One-shot status check (prefer `oracle_wait_for_load` for normal flow) |

### Graph exploration
| Tool | Purpose |
|------|---------|
| `oracle_graph_info()` | Graph overview |
| `oracle_search_nodes(node_description, node_type, top_k)` | Semantic search for nodes |
| `oracle_get_node(query)` | Full node detail with neighbors |
| `oracle_list_nodes(node_type, limit)` | Browse by type |

### World model
| Tool | Purpose |
|------|---------|
| `oracle_tm_clear()` | Reset threat model |
| `oracle_tm_add_node(name, description, node_type)` | Add node to hypothesis |
| `oracle_tm_add_edge(source, target, edge_type, description)` | Add edge to hypothesis |
| `oracle_tm_show()` | View current threat model |
| `oracle_tm_match(top_k)` | Match hypothesis against real graph |
| `oracle_tm_match_refine(top_k, max_iterations)` | Get per-hop energy scores |
| `oracle_tm_list_templates(category)` | Find relevant templates |
| `oracle_tm_load_template(name)` | Load a template |

### Submission
| Tool | Purpose |
|------|---------|
| `oracle_submit_matched_path(description)` | Submit scored path to triage |

---

## Step 0 — Load the graph

Check `oracle_load_status()`. If not loaded, and the user doesn't specify a graph, suggest `/my-data` to see all available graphs.
```
list_repositories() → list_branches(repo_id) → oracle_load_branch(branch_id) → oracle_wait_for_load()
```

## Step 1 — Understand the question

Determine the mode:

| User says | Mode |
|-----------|------|
| A specific CVE, detection, or alert | **Finding investigation** |
| "Is X reachable from Y?", "How exposed is our DB?" | **Posture query** |

---

## Mode 1: Finding Investigation

### Step 2 — Locate the affected resource

```
oracle_search_nodes("description of affected resource", node_type="likely_type", top_k=5)
oracle_get_node("best match")
```

Note the node's type, description, and ALL neighbors. For CVEs, check:
- **Version**: does the node description contain a pinned version? Compare to the CVE's affected range.
- **Usage**: does the description reveal which features are used? A CVE in a feature that isn't used is a false positive.

If the resource is not in the graph: "This resource is not in the infrastructure graph. The model cannot assess attack chains through it."

### Step 3 — Build and test hypotheses with the world model

**Check templates first:**
```
oracle_tm_list_templates()
```
For each relevant template: load it, match it, note coverage and difficulty, then clear before loading the next one. (`oracle_tm_load_template` replaces the current model entirely.)

**Build custom hypotheses** — describe abstract attack chains through the affected resource:

```
oracle_tm_clear()
oracle_tm_add_node(name="entry", description="description matching a real entry point", node_type="http_endpoint")
oracle_tm_add_node(name="vuln", description="description matching the affected resource", node_type="service")
oracle_tm_add_node(name="target", description="description matching a high-value target", node_type="data_store")
oracle_tm_add_edge(source="entry", target="vuln", edge_type="calls", description="how entry reaches the vulnerable component")
oracle_tm_add_edge(source="vuln", target="target", edge_type="accesses", description="how the component accesses the target")
oracle_tm_match(top_k=5)
```

Use descriptions from REAL graph nodes found in Step 2. The model matches by semantic similarity.

**Coverage** = percentage of your threat model nodes that matched real graph nodes. It appears in the `oracle_tm_match` output as `nodes: N/M matched`.

If coverage >= 50% (at least half your threat model nodes found matches):
```
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

The risk score (0-100, momentum model) appears in the `oracle_tm_match_refine` output.

**Try 2-3 different chains** — different entry points, different targets. **Always `oracle_tm_clear()` between hypotheses** — nodes are additive, so not clearing creates an ever-growing model.

**If zero matches / no coverage**: the model couldn't find this chain in your graph. This IS evidence — it means the finding is structurally isolated. Try one alternative hypothesis with a different entry point. If that also fails, report: "The model found no viable chain from this finding to any target."

### Step 4 — Interpret the model's signal

**Path found with mostly accelerating energy**: real chain. The infrastructure offers low resistance. Report the chain, the energy per hop, and the risk score.

**Path found with mostly braking energy**: compensated. Find the specific controls with `oracle_get_node` on the braking hops. Report the controls AND their documented gaps.

**No path found (low coverage)**: the model couldn't connect this finding to a target. This is the model's false positive signal — the finding exists but doesn't chain.

**Risk score context**: report the score (0-100) and where it falls relative to other paths in this graph. Under 20 = strong resistance. Never assign severity labels from the score.

### Step 5 — Deliver the verdict

Report:
- What the finding claims
- What the graph shows (node, neighbors, version, usage)
- What the model assessed (chain tested, coverage, energy per hop, risk score)
- What controls were detected (braking hops → specific boundaries)
- What the verdict is (real chain / false positive / compensated / isolated)
- What to do about it (may differ from the scanner's recommendation)
- What you could NOT verify (flag explicitly)

---

## Mode 2: Posture Query

### Step 2 — Explore the graph

Find the components relevant to the question:
```
oracle_graph_info()
oracle_search_nodes("what the user asked about", top_k=10)
oracle_get_node("most relevant match")
```

### Step 3 — Build threat models as evidence

Build 2-3 threat models relevant to the question. Match each. The model's energy scores are the evidence for your answer.

### Step 4 — Answer directly

"Yes, [target] is reachable from [entry point] — the model found a path scoring [X]/100 with [N/M] hops accelerating."

OR: "No, [target] is well-protected — the model found paths but all show strong resistance. The key controls are: [list with energy scores]."

A well-evidenced "no" is a valuable answer.

---

## After the investigation

- "Want to explore the graph around this finding?" → `/explore`
- "Want to find more paths to this same target?" → `/research`
- "Want to process a full scanner report?" → `/triage-report`
- "Want to review existing attack paths?" → `/review-paths`

## Energy interpretation

- **Negative energy** = low structural resistance (accelerating)
- **Positive energy** = barrier detected (braking) — find the specific control
- **Risk scores 0-100** = under 20 means well defended, over 40 deserves attention, over 60 is high priority
- **Implicit edges** = model-inferred, inflated energy — don't compare to explicit edges
- **Difficulty labels** = attacker economics (will they keep going or pivot?), not skill
