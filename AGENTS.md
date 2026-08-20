# Latent Defense

Latent Defense maps infrastructure into a semantic graph and uses a learned energy-based model (JEPA) to discover multi-step attack paths. It scores how much structural resistance your infrastructure presents to an attacker at every step — a signal no scanner or code review tool can produce.

## Energy & Momentum

Energy represents **structural resistance** — how much the infrastructure resists or accelerates an attacker along each edge.

- **Negative energy (accelerating)**: low resistance. The attacker has a straightforward path forward.
- **Positive energy (braking)**: a security boundary, auth check, or structural barrier creates friction.
- **Magnitude matters**: -3.0 is much less resistance than -0.5. +4.5 is a strong barrier.
- **Implicit vs explicit edges**: explicit edges (confirmed) have smaller magnitudes. Implicit edges (model-inferred) have much larger magnitudes. Never compare them on the same scale.

Energy is NOT confidence, certainty, or probability. It is a structural property of the graph.

### Risk scores (0–100)

Risk scores integrate per-hop energy along a path using the momentum model.

| Band | Meaning |
|------|---------|
| 0–20 | Strong resistance. Infrastructure actively defends this path. Not a finding. |
| 20–40 | Moderate resistance. Some controls create friction. Worth investigating. |
| 40–60 | Low resistance on significant portions. Deserves attention. |
| 60–80 | Little resistance. Most hops accelerate. High priority. |
| 80–100 | Almost no resistance. Critical priority. |

If every path scores under 20, the conclusion is "well defended" — do not treat the highest low-scoring path as a finding.

Risk scores measure structural resistance, not scanner severity. A CVSS-10 CVE on a path scoring 5/100 is less urgent than a CVSS-6 on a path scoring 55/100.

### Difficulty

Difficulty labels (trivial, easy, medium, hard, extreme) describe **attacker economics**, not skill requirements. "Easy" means an attacker (human or AI) would continue along this path. "Extreme" means pivoting elsewhere is more rational.

## Investigation method — Five Moves

Every investigation follows five moves:

1. **Ground** — find real nodes (`grep_nodes`, `find_nodes_by_type`)
2. **Position** — understand structural role (`energy_node_scores`, `energy_node_neighborhood`)
3. **Trace** — find paths (`energy_trace_to_target`, `energy_lowest_paths`)
4. **Score** — evaluate risk (`energy_momentum_path`, 0–100 bands)
5. **Verify** — check source code, config, cloud state

Energy scores tell you WHERE to look. They are the input to investigation, never the output.

## Quick start

```
1. load_graph_energies(branch_id)      # Load graph + JEPA energies into local cache
2. grep_nodes("keyword")               # Find nodes by name/description
   energy_entry_points(branch_id)      # Or discover entry points
3. energy_trace_to_target(             # Trace paths from entry to target
     branch_id, source_id, target_id)
4. energy_momentum_path(               # Score the path (0–100)
     branch_id, node_ids)
5. submit_attack_path(...)             # Submit a validated finding
```

All graph and energy tools require `load_graph_energies` to be called first. The cache persists across sessions.

## Available skills

### Shared skills (Claude Code + Cursor)

| Skill | When to use |
|-------|-------------|
| `/tutorial` | First time. Interactive walkthrough of energy, risk scores, path tracing. |
| `/my-data` | See everything in your deployment. |
| `/explore` | Browse graph — entry points, crown jewels, choke points, credentials. |
| `/investigate` | Investigate a CVE, detection, alert, or finding against your graph. |
| `/triage` | Scanner finding triage at scale. Orchestrates parallel sub-agents. |
| `/research` | Proactive attack path discovery. |
| `/review` | Walk the attack path triage queue. |
| `/diff` | Compare two graph snapshots. |
| `/map` | Map new infrastructure. |
| `/rerun-inference` | Re-run JEPA inference after changes. |
| `/build` | Integrations — webhooks, scan schedules, SIEM export, connectors. |
| `/status` | Deployment health check. `/status deep` for full validation. |

### Cursor-specific skills

| Skill | When to use |
|-------|-------------|
| `/setup` | Set up MCP server in Cursor. Configure auth and verify connection. |
| `/triage-discover` | Cluster findings into remediation groups (triage sub-phase). |
| `/triage-investigate` | Investigate one finding group (triage sub-phase). |
| `/triage-deliver` | Generate audience-specific report (triage sub-phase). |

The three triage sub-skills are used by `/triage` to orchestrate parallel agents in Cursor. They can also be invoked directly.

## MCP prompts

Eight agentic prompts expand into structured instructions:

| Prompt | What it does |
|--------|-------------|
| `triage_queue_review` | Walk the triage queue. |
| `assess_cve` | Assess CVE exposure using energy tools. |
| `chokepoint_report` | Find infrastructure chokepoints. |
| `investigate_finding` | Investigate a single finding (Five Moves). |
| `research_sweep` | Systematic attack path discovery. |
| `triage_discover` | Cluster findings into remediation groups. |
| `triage_investigate_group` | Investigate one finding group. |
| `triage_deliver` | Generate an audience-specific report. |

## Tool tiers

### Foundation

Load and cache before any analysis:

| Tool | Purpose |
|------|---------|
| `load_graph_energies` | Load graph + JEPA energies into local SQLite cache. Required first. |
| `load_branch` | Load a branch without energies (graph-only). |
| `wait_for_load` | Wait for async load to complete. |

### Read (8 tools)

Query the cached graph:

`read_node`, `read_edge`, `get_connected_edges`, `get_graph_statistics`, `grep_nodes`, `grep_edges`, `find_nodes_by_type`, `find_edges_by_type`

### Analyze (12 tools)

Energy-based structural analysis:

`energy_node_scores`, `energy_edge_scores`, `energy_momentum_path`, `energy_lowest_hop`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_compare_paths`, `energy_node_neighborhood`, `energy_entry_points`, `energy_defenses`, `energy_top_attack_paths`, `energy_chokepoints`

### Act (11 tools)

Take action on paths and findings:

`submit_attack_path`, `validate_path`, `dismiss_path`, `undismiss_path`, `update_path_status`, `override_risk_score`, `clear_risk_override`, `add_path_comment`, `edit_path_comment`, `bulk_update_paths`, `ingest_detection`

### Manage (12 tools)

Infrastructure operations:

`create_mapping_run`, `cancel_mapping_run`, `run_inference`, `create_connector`, `update_connector`, `delete_connector`, `test_connector`, `poll_connector`, `register_webhook`, `delete_webhook`, `test_webhook`, `validate_webhook_template`

### Infra (remaining)

Listing, status, and metadata tools:

`list_repositories`, `get_repository`, `list_branches`, `get_branch`, `create_branch`, `list_commits`, `diff_commits`, `get_graph`, `list_mapping_runs`, `get_mapping_run`, `list_mapping_agents`, `list_inference_runs`, `get_inference_run`, `list_scan_schedules`, `run_scan_schedule`, `create_inference_schedule`, `delete_inference_schedule`, `list_connectors`, `list_connector_types`, `get_connector`, `connector_health`, `list_webhooks`, `webhook_deliveries`, `list_attack_paths`, `get_attack_path`, `list_path_history`, `get_validation_status`, `infra_stats`, `ingest_stats`, `trigger_stats`, `list_trigger_events`, `get_trigger_event`, `search_nodes`, `get_triage_config`, `triage_stats`, `whoami`, `connection_status`

## Profile & Project

Load user profile at session start. Profiles and projects persist across sessions in `~/.latent-defense/triage-state/`.

| Tool | Purpose |
|------|---------|
| `triage_load_user` | Load user profile (identity, role, pain points, integrations). |
| `triage_save_user` | Save/update user profile. |
| `triage_load_project` | Load project state (branch, findings, verdicts, work items). |
| `triage_save_project` | Save project state. |
| `triage_list_projects` | List all projects. |
| `triage_project_status` | Get project status summary. |
| `triage_update_finding_group` | Update finding group status. |
| `triage_add_work_item` | Assign work from a finding. |
| `triage_add_decision` | Record a risk decision. |
| `triage_get_workflow_args` | Bridge into workflow execution. |

## Evidence hierarchy

When interpreting results, weight evidence in this order:

1. **Source code** — the definitive truth
2. **Configuration files** — what is configured
3. **Cloud API state** — what is deployed
4. **Semantic context** — graph node descriptions
5. **Graph structure** — relationships and topology
6. **Energy scores** — structural resistance signals

Energy is the input to investigation, never the output. Always verify energy-highlighted areas against higher-tier evidence before drawing conclusions.

## Compensating controls

When the model shows braking energy (positive) on a hop, it detected a structural barrier. Use `read_node` on both endpoints to identify the specific control. Always check the control's **limitations** — the graph often captures both what a control does AND its gaps.

## Limitations

- Cannot verify source code at the line level (use code review)
- Cannot confirm runtime behavior (graph captures static structure)
- Cannot know about controls not in the graph
- Graph completeness depends on mapping coverage
- Energy provides structural evidence, not exploitability verdicts
