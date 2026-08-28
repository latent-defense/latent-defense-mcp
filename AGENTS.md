# Latent Defense

Latent Defense maps infrastructure into a semantic graph and uses a learned energy-based model (JEPA) to discover multi-step attack paths. It scores how much structural resistance your infrastructure presents to an attacker at every step — a signal no scanner or code review tool can produce.

## How the world model works

The JEPA model encodes your entire infrastructure graph — every node, every edge, every relationship — and learns the structural patterns that make attack paths possible. You interact with it through energy-based analysis: load the graph, discover what exists, and score how much resistance each path presents.

### Energy

Energy is the model's core signal. It represents **structural resistance** — how much the infrastructure resists or accelerates an attacker along each edge.

- **Negative energy (accelerating)**: low resistance. The infrastructure has a clear, unobstructed connection here. An attacker traversing this edge has a straightforward path forward.
- **Positive energy (braking)**: the infrastructure resists. A security boundary, authentication check, network segmentation, or structural barrier creates friction. The model detected something that makes this step harder.
- **Magnitude matters**: -3.0 is much less resistance than -0.5. +4.5 is a strong barrier. Compare magnitudes to understand relative resistance.
- **Implicit vs explicit edges**: explicit edges (confirmed in the graph) have smaller energy magnitudes. Implicit edges (model-inferred, not confirmed) have much larger magnitudes. Never compare them on the same scale.

Energy is NOT confidence, certainty, or probability. It's a structural property of the graph that the model learned.

### Risk scores

Risk scores range from **0 to 100** using the momentum model. They integrate per-hop energy along a path into a single number. The bands have real meaning:

- **0–20**: strong structural resistance. The infrastructure actively defends this path. If the highest score across all tested paths falls here, the infrastructure is well defended — these paths are not risky and you should pivot to investigating other areas.
- **20–40**: moderate resistance. Some accelerating hops but controls create friction. Worth investigating the specific controls and their gaps.
- **40–60**: low resistance on significant portions of the path. This path deserves attention — the infrastructure is not providing enough structural defense here.
- **60–80**: little structural resistance. Most hops accelerate. High priority for remediation.
- **80–100**: almost no resistance. The infrastructure accelerates the attacker across nearly every hop.

These bands are empirically derived. A score of 7 means the infrastructure is well defended on this path — full stop. If every path in a graph scores under 20, the conclusion is "well defended infrastructure" and you should look elsewhere for real signal rather than treating the highest-scoring low path as a finding.

Risk scores measure structural resistance, not scanner severity (critical/high/medium). They are complementary signals — a CVSS-10 CVE on a path scoring 5/100 is less urgent than a CVSS-6 CVE on a path scoring 55/100.

### Difficulty

Difficulty labels (trivial, easy, medium, hard, extreme) describe **attacker economics**, not skill requirements. AI agents have made traditional "skill-based difficulty" nearly obsolete. What matters is:

- Will an attacker who finds this path keep going, or pivot elsewhere?
- Is the next step obvious, or does it require exploration?
- Is the structural resistance high enough to make a different path more rational?

"Easy" means low structural resistance — an attacker (human or AI) would continue along this path rather than abandoning it. "Extreme" means high resistance — pivoting elsewhere is more rational.

### Investigation method — Five Moves

Every investigation follows five moves:

1. **Ground** — find real nodes (`grep_nodes`, `find_nodes_by_type`)
2. **Position** — understand structural role (`energy_node_scores`, `energy_node_neighborhood`)
3. **Trace** — find paths (`energy_trace_to_target`, `energy_lowest_paths`)
4. **Score** — evaluate risk (`energy_momentum_path`, 0-100 bands)
5. **Verify** — check source code, config, cloud state

Energy scores tell you WHERE to look. They are the input to investigation, never the output.

### Keeping the graph accurate

**When you verify something against a source of truth and the graph is wrong, fix it.** This is not optional — a graph that lies about infrastructure is worse than an incomplete graph. If you read a node, check the real state via `kubectl` / `az` / `aws` / `gh api`, and find the graph's metadata is stale, its description is inaccurate, or a relationship is missing — update the graph right then using the observation tools. Every investigation that touches a node either confirms it or corrects it.

The observation tools are: `add_node`, `edit_node`, `delete_node`, `add_edge`, `edit_edge`, `delete_edge`, `edit_subgraph`, `bulk_edit_edges`, `pending_changes`, `rollback_changes`, `commit_graph`, `rollback_to_commit`.

This only applies when you have **grounded evidence** — output from a CLI command, a file you read, an API response. Never correct the graph based on your own assumptions or expectations. The graph was built from real infrastructure; when it contradicts you, verify before concluding it's wrong.

**How:**
- `read_node` or `read_edge` before editing (the tools enforce this).
- Verify against the user's `verification_channels` in their profile (`triage_load_user`). If no channels are configured, ask the user how to verify. Never guess.
- `edit_node` sparse-merges metadata — only the keys you provide change, everything else survives.
- Before adding a node or edge, check a peer of the same type for naming and metadata conventions (`find_nodes_by_type`, then `read_node` on one).
- New nodes have no energy scores until inference re-runs. That's expected.
- In parallel pipelines (triage), accumulate corrections and apply as a batch after all agents complete.

**Tool capabilities:**
- `edit_node` deep-merges metadata recursively — `{"resources": {"cpu": "200m"}}` merges into `{"resources": {"cpu": "100m", "memory": "256Mi"}}` preserving `memory`. Use `remove_keys` with dot-paths (e.g. `["resources.cpu", "labels.env"]`) to delete specific metadata keys. You can also change a node's `type` directly.
- `edit_edge` supports changing `source` and `target` to rewire connections, plus the same deep merge and `remove_keys` as `edit_node`.
- `edit_subgraph` applies multiple add/remove/modify operations atomically — the graph equivalent of rewriting a file.
- `bulk_edit_edges` edits all edges matching a filter (type, source, target). Default is `dry_run=true` to preview before committing.

**Persisting changes:**
- Every mutation auto-saves the delta to `~/.latent-defense/graph-cache/<branch>.delta.json`. The delta survives MCP server restarts — `load_graph_energies` restores it and reports pending changes.
- Call `commit_graph(message)` to persist accumulated changes to infradb. On success the delta is cleared. On failure the delta is preserved for retry.
- Call `rollback_changes()` to discard all pending changes without persisting.
- In the triage pipeline, graph corrections accumulate during investigation and are committed as a batch between the Investigate and Route phases.
- **After `commit_graph`, re-encode the graph** by calling `load_graph_energies(branch_id, force_refresh=true)`. This deletes the stale local cache, fetches the updated graph from infradb, and triggers JEPA re-encoding so new/modified nodes and edges get fresh energy scores. Without this step, new nodes have null energy and energy tools can't score paths through them. Do NOT use `run_inference` — that spawns a server-side attack path pipeline, not a local re-encoding.

### Compensating controls

When the model shows braking energy on a hop, it detected a structural barrier. Use `read_node` on both endpoints to identify the specific control — a security boundary, an auth check, a network policy. The model finds defenses, not just risks.

Always look for the control's **limitations** in the node description. The graph often captures both what a control does AND its gaps (e.g., "sandbox restricts filesystem but VCA retains network access to localhost").

### What the model can and cannot do

**Can do:**
- Encode the full graph and score paths through it (systemic, full-context analysis)
- Find multi-step attack chains that scanners miss (they find points, the model finds paths)
- Detect compensating controls and their gaps
- Score structural resistance at every hop
- Find entry points, choke points, and high-value targets
- Match abstract attack hypotheses against real infrastructure

**Cannot do:**
- Verify source code at the line level (use code review for that)
- Confirm runtime behavior (the graph captures static structure)
- Know about controls not represented in the graph
- Guarantee completeness (the graph is only as complete as the mapping)
- Replace human judgment on exploitability (it provides structural evidence, not verdicts)

## Before you start

**Check authentication before doing anything that touches the deployment.** Call `connection_status()` or `whoami()` at the start of any session that needs remote access (loading graphs, running inference, triggering scans). If auth has expired, tell the user immediately — don't proceed and fail silently. Graph tools that read from the local disk cache work without auth, but anything that hits the remote server requires it.

## Quick start

```
1. connection_status()                  # Verify auth is live
2. load_graph_energies(branch_id)      # Load graph + JEPA energies into local cache
3. grep_nodes("keyword")               # Find nodes by name/description
   energy_entry_points(branch_id)      # Or discover entry points
4. energy_trace_to_target(             # Trace paths from entry to target
     branch_id, source_id, target_id)
5. energy_momentum_path(               # Score the path (0–100)
     branch_id, node_ids)
6. submit_attack_path(...)             # Submit a validated finding
```

All graph and energy tools require `load_graph_energies` to be called first. The cache persists across sessions.

## Evidence hierarchy

When interpreting results, weight evidence in this order:

1. **Source code** — the definitive truth
2. **Configuration files** — what is configured
3. **Cloud API state** — what is deployed
4. **Semantic context** — graph node descriptions
5. **Graph structure** — relationships and topology
6. **Energy scores** — structural resistance signals

Energy is the input to investigation, never the output. Always verify energy-highlighted areas against higher-tier evidence before drawing conclusions.

## Available skills

Type `/latent-defense` for guided navigation, or invoke any skill directly:

| Skill | When to use |
|-------|-------------|
| `/tutorial` | First time using the product. Interactive walkthrough of energy, risk scores, and path tracing. |
| `/my-data` | See everything in your deployment. |
| `/explore` | Browse infrastructure graph — entry points, crown jewels, choke points, credentials. |
| `/investigate` | Investigate a specific CVE, detection, alert, or finding against your graph. |
| `/triage` | Scanner finding triage at scale. Orchestrates parallel sub-agents in both Claude Code and Cursor. |
| `/research` | Proactive attack path discovery. |
| `/review` | Walk the attack path triage queue. Review, validate, dismiss paths. |
| `/diff` | Compare two graph snapshots. |
| `/map` | Map new infrastructure. |
| `/rerun-inference` | Re-run JEPA inference after changes. |
| `/build` | Integrations hub — webhooks, scan schedules, SIEM export, connectors. |
| `/status` | Deployment health check. `/status deep` for full validation. |

### Cursor-specific skills

| Skill | When to use |
|-------|-------------|
| `/setup` | Set up MCP server in Cursor. Configure auth and verify connection. |
| `/triage-discover` | Cluster findings into remediation groups (triage sub-phase). |
| `/triage-investigate` | Investigate one finding group (triage sub-phase). |
| `/triage-deliver` | Generate audience-specific report (triage sub-phase). |

The three triage sub-skills are used by `/triage` to orchestrate parallel agents in Cursor. They can also be invoked directly.

## Workflows

| Workflow | When to use |
|----------|-------------|
| `triage-pipeline` | Fan-out structural triage at scale. Seven phases: Load → Discover → Group → Sweep → Investigate → Route → Deliver. Invoked by `/triage` for large finding sets. Each phase runs parallel agents operating against the shared energy graph cache. |

Both Claude Code and Cursor support parallel sub-agents. In Claude Code, `/triage` can use the workflow for optimized orchestration (model selection per phase, structured output schemas). In Cursor, `/triage` orchestrates the same pipeline using sub-skills (`/triage-discover`, `/triage-investigate`, `/triage-deliver`) with parallel agents within each phase.

## Prompts

Eight agentic prompts expand into structured instructions for the calling agent:

| Prompt | What it does |
|--------|-------------|
| `triage_queue_review` | Walk the triage queue. |
| `assess_cve` | Assess CVE exposure (uses energy tools). |
| `chokepoint_report` | Find infrastructure chokepoints (uses `energy_chokepoints`). |
| `investigate_finding` | Investigate a single finding using the Five Moves. |
| `research_sweep` | Systematic attack path discovery. |
| `triage_discover` | Cluster findings into remediation groups. |
| `triage_investigate_group` | Investigate one finding group. |
| `triage_deliver` | Generate an audience-specific report. |

## Energy graph cache

`load_graph_energies(branch_id)` is the single entry point for all graph exploration and energy analysis. It fetches the full graph and energy scores from the inference server into a local SQLite database (`~/.latent-defense/graph-cache/<branch>.db`). All graph read/search and energy analysis tools require this to be called first.

For large graphs (1000+ nodes), `load_graph_energies` handles JEPA warm-up internally. The SQLite cache survives process restarts — subsequent loads are instant.

### Tool tiers

**Foundation** — load and cache before any analysis:

| Tool | Purpose |
|------|---------|
| `load_graph_energies` | Load graph + JEPA energies into local SQLite cache. Required first. |
| `load_branch` | Load a branch without energies (graph-only). |
| `wait_for_load` | Wait for async load to complete. |

**Read** (8): `read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`

**Analyze** (12): `energy_node_scores`, `energy_edge_scores`, `energy_momentum_path`, `energy_lowest_hop`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_compare_paths`, `energy_node_neighborhood`, `energy_entry_points`, `energy_defenses`, `energy_top_attack_paths`, `energy_chokepoints`

**Observe** (12): `add_node`, `edit_node`, `delete_node`, `add_edge`, `edit_edge`, `delete_edge`, `edit_subgraph`, `bulk_edit_edges`, `pending_changes`, `rollback_changes`, `commit_graph`, `rollback_to_commit` — correct the graph when investigation reveals inaccuracies. See "Keeping the graph accurate" above.

**Act** (11): `submit_attack_path`, `validate_path`, `dismiss_path`, `undismiss_path`, `update_path_status`, `override_risk_score`, `clear_risk_override`, `add_path_comment`, `edit_path_comment`, `bulk_update_paths`, `ingest_detection`

**Manage** (12): `create_mapping_run`, `cancel_mapping_run`, `run_inference`, `create_connector`, `update_connector`, `delete_connector`, `test_connector`, `poll_connector`, `register_webhook`, `delete_webhook`, `test_webhook`, `validate_webhook_template`

**Triage** (13): `load_findings`, `query_findings`, `get_finding`, `findings_stats`, `claim_findings`, `claim_findings_range`, `claim_findings_by_query`, `unclaim_findings`, `create_group`, `update_group`, `list_groups`, `save_investigation`, `get_investigation` — SQLite-backed findings store for the triage pipeline. Agents query and claim findings via tools instead of passing index arrays.

## Session state

Local filesystem persistence (`~/.latent-defense/triage-state/`) for cross-session user profiles and project state. State survives process restarts and works offline. Used by all investigation skills, not just triage.

### Profiles and projects

Every investigation skill loads user context and project state at session start.

**User profiles** (`triage_save_user`, `triage_load_user`): identity, role, pain points, team, verification channels, ticketing integration. Persists forever. The `verification_channels` field defines how this user's infrastructure claims should be verified (source code access, cloud CLI, kubernetes contexts). If a profile has no verification channels, ask the user to provide them before making graph corrections.

**Projects** (`triage_save_project`, `triage_load_project`): per-engagement state — branch, findings, verdicts, work items, decisions. Survives session boundaries.

**Findings store** (`load_findings`, `query_findings`, `claim_findings_by_query`, etc.): SQLite database at `~/.latent-defense/triage-state/findings-<project>.db`. Stores all findings with indexed columns for fast queries. Agents claim findings into groups via MCP tools — no index arrays in structured output. State persists across sessions and is shared by all pipeline agents.

**Actions**: `triage_update_finding_group`, `triage_add_work_item`, `triage_add_decision`, `triage_get_workflow_args` — update status, assign work, record risk decisions, bridge into workflow execution.

### Cursor compatibility

Cursor 2.4+ reads `.claude/skills/` natively — all skills work in both Claude Code and Cursor. Both platforms support parallel sub-agents. The `/triage` skill orchestrates the pipeline with parallel agents within each phase on either platform: Claude Code uses the `triage-pipeline` workflow; Cursor uses sub-skills (`/triage-discover`, `/triage-investigate`, `/triage-deliver`) with parallel agent spawning.

## Interpreting results

When you see energy scores and risk scores in skill output:

1. **Look at the energy per hop** — which hops accelerate (risk) and which brake (defense)?
2. **Identify braking controls** — what specific security boundary or auth check is creating resistance?
3. **Check for gaps** — does the control have documented limitations?
4. **Use the bands** — under 20 is well defended (not a finding), 20-40 is moderate, over 40 deserves attention, over 60 is high priority. If all paths score under 20, the infrastructure is structurally defensive.
5. **Verify claims** — the model provides structural evidence. For exploitability decisions, verify version numbers, feature usage, and runtime configuration against your actual deployment.
