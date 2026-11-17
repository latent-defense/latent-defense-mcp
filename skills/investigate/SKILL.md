---
name: investigate
description: "Investigate a specific CVE, detection, alert, or security question against your infrastructure graph. Enriches one finding with the world model's structural assessment. For processing a full scanner report, use /triage."
user-invocable: true
disable-model-invocation: false
---

# Investigate — Single Finding Investigation

You have a specific security question, CVE, detection, or alert. You're investigating it against an infrastructure graph using the JEPA world model's energy scores to reach one of four verdicts: Confirmed, Conditional, Inconclusive or Refuted.

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
   - If it returns a profile: use their role and pain_points to focus the investigation. Don't greet; this skill is often called by another agent, and its output starts with the verdict block.
   - If it returns an error with `available_users`: call `triage_load_user(name=<first_available_user>)` to load that profile
   - If no users exist at all: ask name, role, biggest security concern. Save with `triage_save_user()`

2. Call `mcp__latent-defense__triage_list_projects()`
   - If there's an active project for this graph: load it with `triage_load_project()`
   - Otherwise don't create one. Use the branch the user or the finding names; if there's none, call `list_repositories()` → `list_branches()` and ask which graph

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

#### When the code isn't in the graph

The mapper records what matters for attack paths (endpoints, services, identities, credentials, data stores, the network), not every script, job or log call. Before deciding something is missing, search descriptions as well as names (`grep_nodes(pattern, field="all")`) and walk the neighborhood of the closest node you did find.

If it's really missing and you can read the code (usually in the user's current repository), add it yourself instead of stopping at "not in the graph":

1. Read what it does: what calls it or schedules it, what it reads and writes, which credentials it uses, how it's exposed.
2. Read a similar node (`find_nodes_by_type`, then `read_node`) and name yours the same way.
3. `add_node(name, type, metadata, semantic_context, reason)`, with the file and lines in `reason`. Then `add_edge` from it to the nodes it touches that are already in the graph.
4. Trace through it as usual. Added nodes have no energy until the graph is re-encoded, so paths through them can't be scored: write "Not scored: <component> was added from code in this session" for Risk score.
5. Tag facts that rest on what you added **(added from code)**, and list every node and edge you added in the full report.
6. Don't commit. At the end, ask whether to save the additions to the shared graph: `commit_graph(message)`, then `load_graph_energies(branch_id, force_refresh=true)` so they get scores.

If you can't read the code, don't add anything. Propose a targeted mapping run (the repository URL, and a description naming the exact paths and what to capture) and start it only if the user says yes: `create_mapping_run(description=..., repositories='["<repo URL>"]', credentials_profile="default")`. Until then the verdict is Inconclusive, with the missing component under Unknowns.

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

Only score paths an attacker can actually walk. Drop hops that only describe how things are built or packaged: containment (`contains`), a deployment's helm chart or module, an image's source repository, a repository's CI identity. The Risk score in the output block is the highest-scoring path that's left; if none is left, write "Not scored" with the reason.

A score never overrides evidence. The model reads calls inside a cluster or network as authorized and doesn't see a missing network policy or missing service-to-service auth, so a path can score under 20 while the map's recorded config shows every step holds. Then the verdict follows the evidence, and the Risk score cell says in a few words why the score is low.

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

A finding investigation always ends with the output block below, in this order. It is often read by another agent (for example a coordinator that called this skill as a subagent), so keep the shape exact and the fields short. A posture query can answer directly instead.

### What the reader sees and doesn't see

The block is for people outside Latent Defense. Leave out:
- per-hop energies, momentum values, entry energies and other raw model numbers (the 0–100 risk score and its band are the only model numbers shown)
- tool names, cache paths, attack path ids, branch or commit ids, and anything else that exists only in this session
- graph node names as the main label. Name things the way their owners would: "telemetry service", "SafeBase public API". Put the graph node name in the full report only.

### Verdict values

These are the same four verdicts every Latent Defense report uses, with the same meanings. Write each after its emoji.

| Verdict | Meaning |
|---------|---------|
| 🔴 **Confirmed** | Every step holds: reachable from a realistic attacker position, and it gives the attacker something. |
| 🟡 **Conditional** | Every step checks out except one named condition: a non-default setting, another foothold, a control failing. Say what the condition is. |
| ⚪ **Inconclusive** | The graph and your checks can't settle whether it's reachable. Say what's missing. |
| 🟢 **Refuted** | A step fails: not reachable, not deployed, the feature isn't used, or a control blocks it. Say which. |

Pick the verdict with these rules, in order:
1. **Refuted** needs a reason that holds for every attacker position, not just the internet. Not deployed, the affected feature isn't used, or a control you can name blocks it from every position the graph shows. "Not reachable from the internet" alone is not enough when it's reachable from inside.
2. If it's reachable from some position (inside the network, a compromised workload, a CI job, a user with an account), the verdict is **Confirmed** or **Conditional**, even when impact is low. Low impact goes in the Impact row, not in the verdict.
3. **Confirmed** when that position is realistic without anything extra: internet, any authenticated user, any workload in the same network.
4. **Conditional** when every step checks out except one thing the attacker needs: another foothold, a non-default setting, a control failing. Name that condition in the verdict sentence.
5. **Inconclusive** only when the graph and your checks can't settle reachability. Put what's missing under Unknowns. Don't guess Confirmed or Refuted.

The graph alone can support any verdict. What the map recorded from code, config and cloud state (node and edge descriptions) is evidence; energies and scores are not. When nothing was checked beyond the graph, tag the evidence (map) and put "not checked against the running system" under Unknowns; that doesn't lower the verdict.

### Evidence tags

Tag every item under Key evidence with where it came from:
- **(map)**: the infrastructure graph
- **(verified)**: a source code, config or cloud check you ran in this session
- **(added from code)**: a node or edge you added this session from code you read (see "When the code isn't in the graph")
- **(per the finding)**: stated by the finding or ticket and not checked
- **(general knowledge)**: CVE, product or exploit knowledge not taken from the map

### Output block

```
**Verdict:** <🔴 Confirmed | 🟡 Conditional | ⚪ Inconclusive | 🟢 Refuted>: <one plain sentence, max ~30 words: what it is, how bad, what to do>

| Field | Value |
| -- | -- |
| Risk score | <0–100> (<band>: well defended / moderate / low resistance / high priority / almost no resistance), or "Not scored" with the reason. If the score disagrees with the verdict, add why in a few words |
| Exploitability | High / Medium / Low, plus a few words why |
| Impact | High / Medium / Low / Unknown, rated on what the finding itself gives the attacker |
| What it is | plain-language name of the affected component |
| Product line | the product or environment it belongs to (from account, repo, namespace or labels), or "Unknown" |
| Front door | how an attacker would first reach it, in a few words |
| Key evidence | 2–4 short items separated by "; ", each tagged |
| Unknowns | what the map and checks couldn't settle, separated by "; ", or "None" |
| Fix | 1–2 short actions |

**How it is reached**

<mermaid flowchart LR: attacker starting position → each control that matters → the component; gating condition on each edge; controls that hold as dashed edges labelled "blocked: ...">

**What it reaches**

<mermaid flowchart LR: the position the finding gives the attacker → the identities, data, secrets and systems it reaches; controls that hold as dashed edges labelled "blocked: ...">
```

Rules for the block:
- Table cells stay under ~20 words (Key evidence and Fix up to ~35). No paragraphs.
- Rate impact on what the finding itself gives the attacker, not on everything the component could reach if it were compromised some other way.
- Charts: a control that holds is always a dashed edge (`-.->`) labelled "blocked: ...", in both charts; every other edge is solid. At most ~12 nodes, short quoted labels on every node and edge, no parentheses or `#` outside quotes. They render wherever the markdown is pasted. Don't try to render them yourself.

### Full report

Also write the full investigation to `~/.latent-defense/reports/<YYYY-MM-DD>-<short-finding-slug>.md`: the output block, then everything behind it (graph node names, paths tested with their scores, controls found and their limits, checks run). Put the file path on the line after the block, so a calling agent can store or link it.

## Saving Verdicts

Save investigation results to the active project:

```
triage_update_finding_group(project_id, group_id, updates={
  "status": "investigated",
  "verdict": "confirmed | conditional | inconclusive | refuted",
  "risk_score": score,
  "notes": "the one-sentence verdict"
})

triage_add_decision(project_id, decision={
  "finding": "finding description",
  "verdict": "confirmed | conditional | inconclusive | refuted",
  "rationale": "the key evidence, with its tags",
  "verified_by": "source_code | cloud_cli | graph_only"
})
```

---

## After the Investigation

- "Want to explore the graph around this finding?" → `/explore`
- "Want to find more paths to this same target?" → `/research`
- "Want to process a full scanner report?" → `/triage`
- "Want to review existing attack paths?" → `/review`
