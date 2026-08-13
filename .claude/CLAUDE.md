# Latent Defense

Latent Defense maps infrastructure into a semantic graph and uses a learned energy-based model (JEPA) to discover multi-step attack paths. It scores how much structural resistance your infrastructure presents to an attacker at every step — a signal no scanner or code review tool can produce.

## How the world model works

The JEPA model encodes your entire infrastructure graph — every node, every edge, every relationship — and learns the structural patterns that make attack paths possible. You interact with it through **threat model matching**: describe an abstract attack chain, and the model tells you which parts actually exist in your infrastructure and how much resistance each step presents.

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

### Compensating controls

When the model shows braking energy on a hop, it detected a structural barrier. Use `oracle_get_node` on both endpoints to identify the specific control — a security boundary, an auth check, a network policy. The model finds defenses, not just risks.

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
| `/tutorial` | First time using the product. Interactive walkthrough of the graph, energy, risk scores, and how to read the model's signals using your own infrastructure. |
| `/my-data` | See everything in your deployment — all graphs, branches, attack paths, scans, schedules, connectors. Start here to find which graph to work with. |
| `/explore` | Explore your infrastructure graph — find entry points, crown jewels, choke points, security boundaries, and credential surfaces. |
| `/investigate` | Investigate a specific CVE, detection, alert, or finding against your graph. Enriches one finding with attack chain context and the model's structural assessment. |
| `/triage-findings` | Structural security triage. Groups scanner findings by remediation action, investigates each against the graph using energy analysis, and produces audience-specific reports. Supports the full lifecycle: onboarding → project setup → pipeline → delivery. Uses `load_graph_energies` for local SQLite-backed queries and the `triage-pipeline` workflow for scale. |
| `/triage-report` | Process an entire scanner report (Trivy, Checkov, Semgrep, Bandit). Produces a comprehensive table mapping every finding to the model's assessment with resolution status. For 50+ findings, delegates to the `triage-pipeline` workflow. |
| `/triage` | Walk the attack path triage queue interactively. |
| `/research` | Proactive attack path discovery. Explore the graph, build threat models, test hypotheses, and discover paths no scanner flagged. |
| `/review-paths` | Review existing attack paths in the triage queue. Understand risk scores in context, update statuses, escalate or dismiss. |
| `/rerun-inference` | Re-run JEPA inference on a graph after model updates, remapping, or remediation. See how the security posture changed. |
| `/diff` | Compare two graph snapshots — what was added, removed, modified between commits or branches. |
| `/map` | Map new infrastructure — repositories, cloud accounts, Kubernetes clusters, domains, CIDRs. |
| `/remediate` | Create remediation tickets for validated attack paths. |
| `/monitor` | Set up recurring scans, inference schedules, and webhook alerts. |
| `/build` | Build automations and integrations with the API. Detection ingestion, webhooks, scan scheduling, integration patterns. |
| `/siem` | Set up SIEM integration — export attack paths via polling (CEF syslog) or webhooks (HTTP push). Supports Splunk, Sentinel, Elastic, QRadar. |
| `/status` | Quick deployment health check — service health, infrastructure stats, recent activity. |
| `/health-check` | Deep deployment validation — auth, services, repos, connectors, ticketing. |
| `/setup` | Set up the MCP server in a new project. Routes to `/setup-interactive` or `/setup-headless` based on environment. |
| `/setup-interactive` | Interactive browser-based setup with device-flow OAuth. |
| `/setup-headless` | Headless setup for CI/containers — token passed via environment variable. |
| `/world-model-guide` | Reference on how the JEPA model works, how to interpret energy/risk, and how to build threat models. Context only, no actions. |

## Workflows

| Workflow | When to use |
|----------|-------------|
| `triage-pipeline` | Fan-out structural triage at scale. Seven phases: Load → Discover → Group → Sweep → Investigate → Route → Deliver. Invoked by `/triage-findings` for large finding sets. Each phase runs parallel agents operating against the shared energy graph cache. |

## Prompts

Three agentic prompts expand into structured instructions for the calling agent:

| Prompt | What it does |
|--------|-------------|
| `triage_queue_review` | Guided walkthrough of the triage queue — loads stats, filters by severity, walks each path with structural context. |
| `assess_cve` | Assesses a CVE's exposure across the graph — finds affected nodes, traces attack paths through them, produces a risk summary. |
| `chokepoint_report` | Identifies infrastructure chokepoints where many attack paths converge — ranks by path count and risk, recommends prioritized hardening. |

## Energy graph cache

`load_graph_energies(branch_id)` fetches the full graph from InfraDB and energy scores from the JEPA inference server into a local SQLite database (`~/.latent-defense/graph-cache/<branch>.db`). All graph read/search and energy analysis tools require this to be called first.

For large graphs (1000+ nodes), warm the server-side cache first: `oracle_load_branch` → `oracle_wait_for_load` → then `load_graph_energies`. The SQLite cache survives process restarts — subsequent loads are instant.

**Graph tools** (8): `read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`

**Energy tools** (12): `energy_node_scores`, `energy_edge_scores`, `energy_momentum_path`, `energy_lowest_hop`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_compare_paths`, `energy_node_neighborhood`, `energy_entry_points`, `energy_defenses`, `energy_top_attack_paths`, `energy_chokepoints`

## Triage state

Local filesystem persistence (`~/.latent-defense/triage-state/`) for cross-session triage projects and user profiles. State survives process restarts and works offline.

**User profiles**: `triage_save_user`, `triage_load_user` — identity, role, pain points, team context. Saved once, reused across all projects.

**Projects**: `triage_save_project`, `triage_load_project`, `triage_list_projects`, `triage_project_status` — each project tracks one engagement with its branch, sources, audiences, findings, work items, and decisions.

**Actions**: `triage_update_finding_group`, `triage_add_work_item`, `triage_add_decision`, `triage_get_workflow_args` — update status, assign work, record risk decisions, bridge into workflow execution.

## Interpreting results

When you see energy scores and risk scores in skill output:

1. **Look at the energy per hop** — which hops accelerate (risk) and which brake (defense)?
2. **Identify braking controls** — what specific security boundary or auth check is creating resistance?
3. **Check for gaps** — does the control have documented limitations?
4. **Use the bands** — under 20 is well defended (not a finding), 20-40 is moderate, over 40 deserves attention, over 60 is high priority. If all paths score under 20, the infrastructure is structurally defensive.
5. **Verify claims** — the model provides structural evidence. For exploitability decisions, verify version numbers, feature usage, and runtime configuration against your actual deployment.
