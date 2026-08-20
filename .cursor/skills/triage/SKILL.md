---
name: triage
description: "Structural security triage. Process scanner findings, group by remediation action, investigate against the infrastructure graph using JEPA energy signals, and produce audience-specific reports. Orchestrates parallel sub-agents for each pipeline phase."
user-invocable: true
disable-model-invocation: false
---

# Structural Security Triage

## What this system does

Security teams drown in findings. Thousands of CVEs, hundreds of code defects, dozens of misconfigurations — each scanner reporting independently with no awareness of the infrastructure topology. This system takes findings from any source and determines what actually matters by grounding each finding in the infrastructure graph.

The core insight: most findings are noise not because they're wrong, but because they lack context. A critical CVE in a package that's unreachable from any entry point is operationally irrelevant. A medium-severity misconfiguration on a service that handles credentials for every other service is urgent. The graph and the JEPA energy model provide that context.

**The fundamental unit of triage is not "a vulnerability" but "a remediation action."** Thirty CVEs fixed by one base image rebuild are one item on the engineering backlog. Four services needing the same auth middleware are one design decision. The system discovers these structural groups, investigates each against real code and configuration, and produces audience-specific reports.

## How the pipeline works

Seven phases: **Load → Discover → Group → Sweep → Investigate → Route → Deliver**

**Load** — Loads the infrastructure graph with JEPA energy scores into a local SQLite cache. One agent, runs once. All subsequent agents query the same cache.

**Discover** — One agent reads ALL findings across all sources and identifies 8-20 high-level remediation clusters. Groups by fix action, not surface attribute: "all services missing authentication" is one cluster regardless of service name. The agent identifies patterns — it doesn't assign individual findings yet.

**Group** — Parallel agents, one per cluster, each claim specific findings by 0-based index. They read the findings, match to the cluster's description, and either terminate as a leaf (one fix covers all) or split into sub-groups. Energy tools guide split decisions:
- Entry energy spread > 2.0 across a cluster's findings → SPLIT by exposure zone (some exposed, some interior)
- `energy_trace_to_target` between two anchors returns "not reachable" → SPLIT (structurally disconnected)
- All findings anchor to similar-energy nodes → keep together

A global tracker prevents double-claims across parallel agents. The recursion terminates at leaf groups or depth limit.

**Why group before anchoring:** Most scanner findings (OS package CVEs) don't have graph nodes. `libdb5.3` isn't in the graph; the database-proxy service that contains it is. A parent agent recognizes "these are all OS package CVEs in the database-proxy image" from finding text alone — no graph needed. Energy tools then anchor the group as a whole. One intelligent anchoring per group, not thousands of mechanical anchoring attempts per CVE.

**Sweep** — One agent handles unclaimed findings. Uses cross-references from Group agents and energy proximity to assign each to an existing group or create new ones. After sweep: every finding claimed exactly once.

**Investigate** — Two-stage pipeline per group:
- Stage 1 (Explore): Energy-only. Maps structural position using `energy_node_scores`, `energy_lowest_hop`, `energy_trace_to_target`. Produces: where does this sit, what controls exist, what's reachable, what files should the verifier check?
- Stage 2 (Verify): Code/config verification. Gets the structural map, reads actual source code or configuration via the configured verification channels. Produces a verdict (confirmed / refuted / partial) with evidence cited from code, not from the graph.

The two-stage split is intentional — it prevents agents from skipping energy exploration and falling back to grep, or from citing graph topology as verification.

**Route** — For groups beyond the investigation limit, a lightweight classifier assigns: eliminable, reducible, constrained, drift_prone, or mitigated.

**Deliver** — Parallel agents, one per audience, generate reports using stored audience preferences.

## Evidence hierarchy

Verification must use a different source than screening. Strict order:

1. **Source code** — the actual implementation. Highest authority.
2. **Configuration files** — the actual kong.yml, Dockerfile, Helm values.
3. **Cloud API** — live state from AWS/Azure/GCP CLI queries.
4. **Semantic context** — the graph node's natural-language description. Used when source code isn't available.
5. **Graph structure** — which nodes connect via what edge types. Structural evidence.
6. **Energy scores** — structural exposure and resistance. Screening evidence only.

"The graph shows 0 auth edges" is NOT verification — it's the screening tool describing itself. "The kong.yml route definition has no plugin attachment" IS verification.

## Refuted findings are successes

When the model flags a structural lead and investigation confirms the controls hold, that's the system working correctly. The model identified a structurally interesting area. The investigation verified the defense. The output is a documented, defensible statement.

A system that only values confirmed vulnerabilities incentivizes the model to be conservative. A system that values refuted findings incentivizes comprehensive exploration — investigate everything structurally interesting, document both gaps and defenses.

## Principles

1. **Energy scores are input to investigation, never output.** They tell you where to look. The investigation produces a security assessment grounded in code, config, and cloud state — not energy values.

2. **The model tells you where to look, not what to conclude.** Energy signals are accurate descriptions of graph topology. They are not security assessments. A low-energy path through an auth flow is the happy path working correctly, not a vulnerability.

3. **Translation is validation.** Every energy score must become a concrete security statement. "Entry energy is 0.03" is meaningless — "this service accepts TCP connections directly from the internet with no TLS termination" is actionable. The act of translating IS the investigation.

4. **Neighborhood before paths.** Start from the user's concern, find relevant nodes, explore their neighborhood with granular tools. Wide-net enumeration misses controls one hop off the path.

5. **Never surface model internals.** No energy scores, momentum values, graph node IDs, collapse ratios, or methodology sections in user-facing output.

6. **No tickets until user sign-off.** Skills never create tickets automatically. The flow is: investigate → present findings → user reviews and approves → user creates tickets through their native ticketing integration. Reference the ticketing integration saved in the user's profile.

## Session Start

```
triage_load_user()
triage_list_projects()
```

**Profile exists:** Greet by name. List all projects with `triage_list_projects`. Show a one-line status per project (open/fixed/mitigated counts). Then **stop and ask the user** — do NOT proceed automatically:

**"You have [N] active project(s): [names]. Want to continue on one of these, start a new project for different infrastructure, or explore something specific?"**

**Profile not found but `available_users` returned:** Call `triage_load_user(name=<first_available_user>)` to load that profile instead. Then proceed as "Profile exists" above.

**No profile and no available users:** This is onboarding. Follow the onboarding sequence.

**After project selection or creation:**

```
load_graph_energies(branch_id)
```

Use `list_repositories` and `list_branches(repo_id)` to help users find their branch ID if needed. No graph → route to `/map`.

## Onboarding

Gather context in two passes — first the user, then the project. Conversational, not an interrogation.

### User profile (ask once, persists forever)

Ask: **"What's your name, your role, and what's your biggest security headache right now?"**

Then: **"Who else needs to see the results? For each person — what's their role, what do they do when they receive security information, and do they know security jargon or should I keep it plain?"**

Then: **"What ticketing integration do you have set up? For example: Linear, Jira, GitHub Issues — whatever you use in Cursor to create tickets."**

Save with `triage_save_user`: `name`, `role`, `org`, `pain_points`, `ticketing_integration`, `team` (each with name/role/needs/jargon_level).

### Project setup (per engagement)

Ask: **"What graph and findings should I work with?"** Get:
- **Branch ID** — use `list_repositories` and `list_branches(repo_id)` to find it. No graph → route to `/map`.
- Findings file paths — for each: scanner name, scanner version, scan date.

Then ask: **"What tools and access do you have that could help verify findings? For example: GitHub org for source code, cloud CLI access (AWS/Azure/GCP), kubectl contexts, IaC repos, security tools, documentation — anything an investigator would reach for."**

Capture each as a verification channel:
```json
{
  "type": "source_code | cloud_cli | kubernetes | iac | security_tool | documentation | other",
  "method": "github_api | local_path | cli | api | mcp",
  "access": { ... },
  "scope": "description of what's reachable",
  "instructions": "How agents should use this — specific commands, API patterns, auth context"
}
```

Don't assume access methods. Don't assume local files are current. Don't assume the audit target list is exhaustive — ask about the full scope.

Then: **"Is this multi-tenant or single-tenant? Managed service or self-hosted?"** and **"What do you need out of this? What decisions are you trying to make?"**

Save with `triage_save_project`: `branch_id`, `sources`, `verification_channels`, `deployment_model`, `audiences`, `user_context`.

Load the graph: `load_graph_energies(branch_id)`.

## Pipeline Orchestration

1. **Load**: Call `load_graph_energies(branch_id)`.

2. **Discover + Group + Sweep**: Invoke `/triage-discover`. Collect the group list.
   - Verify: total findings == sum of all group claimed_findings
   - Verify: unclaimed == 0

3. **Investigate**: For EACH group, spawn a sub-agent running `/triage-investigate`.
   Run all groups in parallel.
   - Barrier: collect ALL verdicts. Every group MUST have a verdict.
   - If any group returns null/error: retry that group's `/triage-investigate`.
   - Do NOT proceed until all groups have verdicts.

4. **Deliver**: For EACH audience, spawn a sub-agent running `/triage-deliver`.
   Run all audiences in parallel.
   - Each deliver agent receives ALL investigation results.

5. Save final results with `triage_save_project`.

The sub-skills (`/triage-discover`, `/triage-investigate`, `/triage-deliver`) are self-contained — each one can also be invoked independently for targeted work.

## Three Activities

### 1. Triage at scale

Before running the pipeline:

1. Call `triage_get_workflow_args` to validate and check for gaps.
2. Present any gaps with their questions. Save answers before proceeding.
3. Ask investigation depth: "Investigate all groups, or cap it?" Confirm back.
4. **Confirm settings before launch.** Present the full configuration:
   - **Branch:** branch_id and node/edge count
   - **Sources:** each findings file with scanner name
   - **Audiences:** who receives output
   - **Verification channels:** type, method, instructions for each. **Check for mismatches** — if method says `local_path` but instructions say "use GitHub API", flag it. If no channels are configured, that's a blocker.
   - **Investigation depth** and **deployment model**

   Ask: **"These are the settings I'll run with. Anything to change?"** Wait for confirmation.
5. Run using the pipeline — see Pipeline Orchestration above.

### 2. Validate a structural lead

Interactive single-finding investigation using energy tools. Start with the finding, anchor it in the graph, explore its neighborhood, and verify against real code/config.

1. Anchor the finding to a graph node using `grep_nodes` or `find_nodes_by_type`
2. Explore with `energy_node_scores`, `energy_node_neighborhood`, `energy_lowest_hop`
3. Trace paths with `energy_trace_to_target`, `energy_momentum_path`
4. Verify using the configured verification channels — read the actual implementation
5. Produce a verdict: confirmed, refuted, or partial — with evidence from code/config, not the graph

Save with `triage_update_finding_group`. Validated findings carry higher authority than raw scanner output.

### 3. Explore interactively

Free-form energy tool exploration. Use energy tools starting granular and widening:
- Start with `energy_node_scores` on a specific area of interest
- Expand with `energy_node_neighborhood` to see local context
- Trace specific paths with `energy_trace_to_target`
- Get the big picture with `energy_top_attack_paths`, `energy_chokepoints`, `energy_entry_points`

### Reframing

When the user reframes their understanding ("patch everything" → "what actually matters given our controls"), update `user_context`. The same graph supports different interpretations.

## Delivering to Audiences

For each audience ask: what they do with security info, what the report should look like, what makes it less useful. Save as `report_outline` and `not_include`.

**Reports:**
- Action table first
- Dismissed items are high-value — document the control and why it holds
- Separate remediation-ready from investigation-needed
- Blast radius with deployment model context
- Cite code/config evidence, not graph properties
- Define jargon inline when audience needs it
- Reference the user's native ticketing integration for creating work items

**Never include:** energy scores, node IDs, collapse ratios, methodology, tool comparisons, effort/timeline estimates, review dates (user sets those).

Use `triage_add_work_item` for engineering actions. `triage_add_decision` for risk acceptance.

## Resolution Categories

- **eliminable** — clear fix, no trade-off → engineering
- **reducible** — partial fix, add controls → engineering
- **constrained** — design limitation → product decision
- **drift_prone** — recurring → automation/monitoring
- **mitigated** — fix friction > risk under existing controls → accept with review date

## Energy Signal Reference

**Entry energy** — structural exposure. Lower = more reachable from external input. Not just network endpoints — K8s reconcile events, client SDK inputs, CI triggers all count.
- < 0.1: directly accessible. 0.1-0.5: entry-facing. 0.5-2.0: near-surface. 2.0-4.0: interior. > 4.0: deep interior.

**Transition energy** — per-edge resistance. Negative = accelerating (easy), positive = braking (barrier).
- Edge type patterns: `contains`/`calls` accelerate. `owns`/`member_of` brake. `has_permission`/`assumes_role` 100% accelerate. `protects`: 76% brake, 24% accelerate — an accelerating `protects` edge means the model sees the control as structurally transparent. Most reliable signal for investigation.

**Momentum** — cumulative path score integrating per-hop energy. Risk score 0-100.
- 0-20: strong structural resistance. Infrastructure is well defended. Not a finding.
- 20-40: moderate resistance. Mixed signal — investigate what's braking.
- 40-60: low resistance. Multiple accelerating hops. Deserves attention.
- 60-80: little resistance. Most hops accelerate. High priority.
- 80-100: almost no resistance across the path.

**The key rule:** Low resistance does not equal security problem. Authorized flows accelerate by design. The signal is low resistance WHERE IT SHOULD NOT BE.

**Implicit vs explicit edges:** Explicit edges (confirmed in the graph) have smaller energy magnitudes. Implicit edges (model-inferred, not confirmed) have much larger magnitudes. Never compare them on the same scale.

**Model strengths:** Structural transparency in controls, co-location anti-patterns, missing boundaries, chokepoints.

**Model blind spots:** Runtime behavior (RLS, RBAC), cryptographic backing of checks, protocol-layer auth.

## Graph Tools

- `read_node(name)`, `read_edge(name)`, `get_connected_edges(node, direction)` — read specific graph elements
- `grep_nodes(pattern, field, limit)`, `grep_edges(pattern, field, limit)` — search by substring
- `find_nodes_by_type(node_type, limit)`, `find_edges_by_type(edge_type, limit)` — search by type
- `get_graph_statistics()` — node/edge counts and type distributions

## Energy Tools

**Granular** (start here):
- `energy_node_scores(node_query)` — what is this node, what's connected
- `energy_lowest_hop(node_query)` — single least-resistance connection
- `energy_node_neighborhood(node_query, hops)` — local context including nearby controls
- `energy_edge_scores(source_query, target_query)` — specific connection energies

**Exploration** (after understanding the neighborhood):
- `energy_lowest_paths(node_query, max_hops, top_k)` — lowest-energy paths at each depth
- `energy_trace_to_target(source_query, target_query)` — least-resistance route between two points
- `energy_compare_paths(path_a, path_b)` — why one route is less defended
- `energy_momentum_path(node_names)` — momentum along a specific path

**Structural overview** (broad picture):
- `energy_top_attack_paths(limit)` — highest-momentum paths
- `energy_chokepoints(limit)` — nodes with most path flow
- `energy_entry_points(threshold, limit)` — exposed surface
- `energy_defenses(limit)` — structural resistance nodes

## State Management

- `triage_save_user` / `triage_load_user` — identity, role, pain points, ticketing integration, team
- `triage_save_project` / `triage_load_project` / `triage_list_projects` — project lifecycle
- `triage_project_status` — current state summary
- `triage_update_finding_group` — mark findings fixed/mitigated/deferred, record verdicts
- `triage_add_work_item` — create actionable items assigned to people
- `triage_add_decision` — record risk decisions with justification and review dates
- `triage_get_workflow_args` — validated args for the pipeline

## Path Submission

Use `submit_attack_path` to submit discovered paths for scoring.

**Commit state after every significant action.** Work must survive session boundaries.
