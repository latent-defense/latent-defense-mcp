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

**Graph tools** (8): `read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`

**Energy tools** (12): `energy_node_scores`, `energy_edge_scores`, `energy_momentum_path`, `energy_lowest_hop`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_compare_paths`, `energy_node_neighborhood`, `energy_entry_points`, `energy_defenses`, `energy_top_attack_paths`, `energy_chokepoints`

## Session state

Local filesystem persistence (`~/.latent-defense/triage-state/`) for cross-session user profiles and project state. State survives process restarts and works offline. Used by all investigation skills, not just triage.

### Profiles and projects

Every investigation skill loads user context and project state at session start.

**User profiles** (`triage_save_user`, `triage_load_user`): identity, role, pain points, team, verification channels, ticketing integration. Persists forever.

**Projects** (`triage_save_project`, `triage_load_project`): per-engagement state — branch, findings, verdicts, work items, decisions. Survives session boundaries.

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
