---
name: triage
description: "Structural security triage. Prioritizes scanner findings when you provide them, or the attack-path queue as root causes when you don't. Groups by remediation action, investigate against the infrastructure graph using JEPA energy signals, and produce audience-specific reports. Orchestrates parallel sub-agents for each pipeline phase."
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

**Discover** — One agent loads ALL findings into the findings store via `load_findings`, reviews the distribution with `findings_stats`, and creates 8-20 remediation groups via `create_group`. Groups by fix action, not surface attribute. The agent then claims findings for each group using `claim_findings_by_query` (with dry_run preview) and `claim_findings_range` for contiguous scanner blocks.

**Group** — Parallel agents, one per group, refine claims using the query-based claim tools. Each agent uses `query_findings` to review its findings and `claim_findings_by_query` to grab any unclaimed findings that belong. Energy tools guide split decisions:
- Entry energy spread > 2.0 across a group's findings → SPLIT by exposure zone
- `energy_trace_to_target` between two anchors returns "not reachable" → SPLIT (disconnected)
- All findings anchor to similar-energy nodes → keep together

The findings store prevents double-claims atomically — a finding belongs to exactly one group.

**Why group before anchoring:** Most scanner findings (OS package CVEs) don't have graph nodes. `libdb5.3` isn't in the graph; the database-proxy service that contains it is. A parent agent recognizes "these are all OS package CVEs in the database-proxy image" from finding text alone — no graph needed. Energy tools then anchor the group as a whole. One intelligent anchoring per group, not thousands of mechanical anchoring attempts per CVE.

**Sweep** — One agent queries unclaimed findings with `query_findings(unclaimed_only=true)` and assigns each to the closest group via `claim_findings` or creates new groups. After sweep: `findings_stats` confirms 0 unclaimed.

**Investigate** — Two-stage pipeline per group:
- Stage 1 (Explore): Energy-only. Reads group findings via `query_findings(group_id=X)`. Maps structural position using energy tools. Saves results via `save_investigation`.
- Stage 2 (Verify): Code/config verification. Reads exploration results via `get_investigation`. Verifies against source code and configuration. Saves verdict via `save_investigation` and updates group via `update_group`.

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

When no code, config or cloud access is available, what the map recorded from them (a node's description of its route config, a policy's statements) still counts, and can support any verdict, including Confirmed. Tag it (map) and note "not checked against the running system". Edge counts, topology and energies never count.

A low risk score never overrides that evidence. The model reads calls inside a cluster or network as authorized and doesn't see a missing network policy or missing service-to-service auth, so a path can score under 20 and still be Confirmed. When that happens, keep the verdict the evidence supports and say in a few words why the score is low.

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

**Profile exists:** Don't greet. Attack-path triage (no findings) doesn't need a project: announce the mode and start. For findings triage, list all projects with `triage_list_projects`. Show a one-line status per project (open/fixed/mitigated counts). Then **stop and ask the user** — do NOT proceed automatically:

**"You have [N] active project(s): [names]. Want to continue on one of these, start a new project for different infrastructure, or explore something specific?"**

**Profile not found but `available_users` returned:** Call `triage_load_user(name=<first_available_user>)` to load that profile instead. Then proceed as "Profile exists" above.

**No profile and no available users:** This is onboarding. Follow the onboarding sequence.

**After project selection or creation:**

```
load_graph_energies(branch_id)
```

Use `list_repositories` and `list_branches(repo_id)` to help users find their branch ID if needed. No graph → route to `/map`.

## Findings or attack paths? Pick the mode first

Triage always says up front what it is prioritizing, and the whole run, including every report, follows that one choice.

| What the user gave you | Mode | What gets prioritized |
|------------------------|------|-----------------------|
| One or more findings files, or findings already in the project's store | **Findings triage** | The findings, grouped by the fix that closes them. Attack paths are only evidence for a finding's verdict. |
| No findings | **Attack-path triage** | The attack-path queue for the project's graph, distilled into root causes. |

Say which mode you're in before anything else runs, in one line, for example: **"No findings were provided, so I'll prioritize the attack paths on this graph (412 open, highest score 78)."** If the user gave both findings and asked about paths, or it's unclear, ask which one they want prioritized. Don't mix them in one ranking.

### Team tag

Whichever mode you're in, every ranked group gets a tag for the team that would make the fix: [Infra], [App] or [Security]. In findings triage the tag goes on each group in `/prioritize-findings-report`; in attack-path triage it's the Team column of the ranked table.
- **[Infra]:** the fix is in cloud, IAM, network, Kubernetes, CI/CD, registry or Terraform configuration.
- **[App]:** the fix is in application code or a dependency the app pins.
- **[Security]:** the fix is a security decision or control no one team owns: a risk acceptance, a policy, a detection.

Pick one team: the one that would make the immediate fix. If another team owns the hardening, add it after a slash, e.g. [Infra/App]. The tag says who should look; we don't have ownership data, so never name a person. If the user asks for one team's view, show only that team's groups, in the same order and sections.

### Code that isn't in the graph

In both modes, when the code behind a finding or a path step isn't in the graph, follow "When the code isn't in the graph" in `/investigate`: read the code, add the node and its edges, trace through them, and tag those facts (added from code). Don't stop at "not in the graph". In the pipeline workflow, sub-agents add without committing and the pipeline commits the batch after the Investigate phase; anywhere else, ask before `commit_graph`. Only propose a mapping run when the code can't be read.

### Findings triage

Run the pipeline as described below. The ranked list is findings groups; each one's priority comes from its verdict and the reach of what it exposes.

### Attack-path triage

The goal is a short list of root causes, not one item per path: hundreds of paths usually come from a handful of configurations (one over-permissive role, one trust policy, one exposed service). This runs in the session, not through the pipeline workflow.

1. **Scope.** Call `list_attack_paths(repository_id=<repo>, status="new", summary=true)` to see the open count and top scores. Up to ~50 open paths: take them all. More: look at the spread of the top scores first.
   - **Scores spread out:** take the top band the queue actually holds (for example the top tenth, or a `min_risk_score` just under the top scores).
   - **Scores bunched** (the top hundred or so within about a point of each other): the score can't tell them apart, so don't cut by it. Take every open path, up to the first 500, and let priority come from exploitability and impact in step 5.

   Say which cut you chose, how many paths it holds and the highest score, and whether the scores were bunched. Offer all open paths as the alternative.
2. **Inventory.** Page through with `limit=50` and `offset` until `has_more` is false (larger pages overflow the response). Group paths by starting point and show the user: total paths, the starting points by count and top score, and the most common targets. If most targets appear only once, say so and don't group them into made-up categories; the grouping that matters comes from the decisive steps in step 4.
3. **Find the decisive steps.** For each starting point, `get_attack_path` its paths and read the steps that make them work (`read_node`, `read_edge`; facts often live on edges). A step is decisive when removing it breaks the path. Run starting points in parallel sub-agents, at most 5 at a time.
   - **Discard hops an attacker can't walk:** edges that only record how things are built or packaged, such as containment, an image's source repository, a repository's CI identity, or a deployment's chart or module. A path that only works through such a hop isn't a real path: drop it, and say how many you dropped and why. Don't list it as Refuted.
4. **Distill root causes.** Group the decisive steps by the configuration behind them (same role, trust policy, grant, exposed listener, shared credential, missing control). Each group is one root cause; one path can depend on two or three. Count the paths each root cause covers from the steps of the paths you paged through. `list_attack_paths(node_id=<resource>)` finds examples through a resource, but its `total` can miss paths, so don't use it as the count.
5. **Rank and report.** Rate each root cause's exploitability and impact, take priority from the table in `/report-group-deep-dive`, and present one ranked table, highest priority first. Use the same fields `/prioritize-findings-report` uses to explain each group:

   | # | Priority | Team | Root cause | Verdict | Why | Paths covered | Decisive evidence | Recommendation | Couldn't check |
   | -- | -- | -- | -- | -- | -- | -- | -- | -- | -- |
   | 1 | [CRITICAL] | [Infra] | <what to change>, so <what it stops or protects> | 🔴 Confirmed | <why this priority, in one line: who can reach it and what they get> | <n> paths from <starting point>, reaching <2–3 example targets> and <n> others | <the one fact that makes it work, tagged (map), (verified) or (per the finding)> | <what to do this week, in one line> | — |
   | 2 | [MEDIUM] 🔑 | [App] | ... | 🟡 Conditional | <why this priority if confirmed> | ... | ... | ... | <what couldn't be verified>. Grant us: <the smallest read-only check that would settle it> |
   | 3 | [MEDIUM] ❓ | [Security] | ... | 🟡 Conditional | ... | ... | ... | ... | <what couldn't be verified>. Answer: <one yes/no question> |

   - **Priority** is [CRITICAL], [HIGH], [MEDIUM] or [LOW], from the table in `/report-group-deep-dive`.
   - **Team** follows the Team tag rule above.
   - **Root cause** is one plain sentence answering "What should I change, and why?": the change first, then what it stops. No arrows or labels.
   - **Verdict:** 🔴 Confirmed, 🟡 Conditional, ⚪ Inconclusive or 🟢 Refuted. Refuted root causes go in a short list after the table, each with the control or config that blocks it.
   - **Couldn't check** is "—" for Confirmed. For Conditional and Inconclusive, tag the priority 🔑 when access was missing (end with "Grant us:" and the narrowest read-only check, never broad admin access) or ❓ when it depends on a fact only the user knows (end with "Answer:" and one question).
   - Keep cells short: under ~20 words, up to ~35 for Why and Decisive evidence.

   Then offer `/report-group-deep-dive` on any of them for the full ticket-ready write-up.

Same rules as findings triage: no tickets without sign-off, and no energies, path ids or node ids in what the user reads.

## Onboarding

Gather context in two passes — first the user, then the project. Conversational, not an interrogation.

### User profile (ask once, persists forever)

Ask: **"What's your name, your role, and what's your biggest security headache right now?"**

Then: **"Who else needs to see the results? For each person — what's their role, what do they do when they receive security information, and do they know security jargon or should I keep it plain?"**

Then: **"What ticketing integration do you have set up? For example: Linear, Jira, GitHub Issues — whatever you use to create tickets."**

Save with `triage_save_user`: `name`, `role`, `org`, `pain_points`, `ticketing_integration`, `team` (each with name/role/needs/jargon_level).

### Project setup (per engagement)

Ask: **"What graph and findings should I work with?"** Get:
- **Branch ID** — use `list_repositories` and `list_branches(repo_id)` to find it. No graph → route to `/map`.
- Findings file paths, if any — for each: scanner name, scanner version, scan date. Findings are optional: without them, triage prioritizes the attack-path queue (see "Findings or attack paths?" above).

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

Save with `triage_save_project`: `branch_id`, `sources`, `verification_channels`, `deployment_model`, `audiences`, `user_context` (an object).

Load the graph: `load_graph_energies(branch_id)`.

## Pipeline Orchestration

The pipeline is **checkpoint-driven** — every phase checks the findings store before running. Completed work is skipped automatically. This means:

- **Crash recovery**: just relaunch. The pipeline reads what's done from SQLite and picks up where it left off.
- **Rate limit**: wait for reset, relaunch with the same profile_id. Haiku agents (pennies) check each phase, only Opus agents (dollars) run for new work.
- **Resume**: `Workflow({ name: "triage-pipeline", args: { profile_id: "<project_id>" } })` — that's it. Everything else comes from the project.

Call `pipeline_status(project_id)` to see phase completion before launching.

Launch: `Workflow({ name: "triage-pipeline", args: { profile_id: "<project_id>" } })`.

The workflow handles phase orchestration, model selection per phase (Opus for discovery/investigation/delivery, Sonnet for grouping/sweep, Haiku for checkpoints/routing), and parallel agent scheduling within each phase.

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
   - **Verification channels:** type, method, instructions for each. **Check for mismatches** — if method says `local_path` but instructions say "use GitHub API", flag it. If no channels are configured, say verification will use what the map recorded from code, config and cloud state, and confirm the user is fine with that.
   - **Investigation depth** and **deployment model**

   Ask: **"These are the settings I'll run with. Anything to change?"** Wait for confirmation.
5. Launch the pipeline — see Pipeline Orchestration above.
6. When it completes, present the results and offer the follow-ups — see After the Pipeline Completes below.

**Resume after failure:** Just relaunch with the same profile_id: `Workflow({ name: "triage-pipeline", args: { profile_id: "<project_id>" } })`. The pipeline reads completed work from the findings store and only runs what's missing. No scriptPath or resumeFromRunId needed.

### 2. Validate a structural lead

Interactive single-finding investigation using energy tools. Start with the finding, anchor it in the graph, explore its neighborhood, and verify against real code/config.

1. Anchor the finding to a graph node using `grep_nodes` or `find_nodes_by_type`
2. Explore with `energy_node_scores`, `energy_node_neighborhood`, `energy_lowest_hop`
3. Trace paths with `energy_trace_to_target`, `energy_momentum_path`
4. Verify using the configured verification channels — read the actual implementation
5. Produce one of the four verdicts used everywhere: Confirmed, Conditional, Inconclusive or Refuted (defined in `/trace-blast-radius`) — with evidence from code/config, not the graph

Save with `triage_update_finding_group`. Validated findings carry higher authority than raw scanner output.

### 3. Explore interactively

Free-form energy tool exploration. Use energy tools starting granular and widening:
- Start with `energy_node_scores` on a specific area of interest
- Expand with `energy_node_neighborhood` to see local context
- Trace specific paths with `energy_trace_to_target`
- Get the big picture with `energy_top_attack_paths`, `energy_chokepoints`, `energy_entry_points`

### Reframing

When the user reframes their understanding ("patch everything" → "what actually matters given our controls"), update `user_context`. The same graph supports different interpretations.

## After the Pipeline Completes — Follow-up Options

The follow-ups are separate skills, not part of this one, so the user can come back to any of them later in the session without running triage again. Remember they exist for the rest of the session.

Once the pipeline finishes and you've shown the results, **offer these follow-ups and let the user choose. Don't run any of them automatically:**

1. **Prioritized report** → `/prioritize-findings-report`: what to fix this week, what's safe to deprioritize, and what needs their input, with each group verified against the deployed environment and compared with their scanners' severity.
2. **Deep dive on a group** → `/report-group-deep-dive`: one group's per-finding verdicts, its most critical path, the evidence, and the single fix that closes it.
3. **Every path tried** → `/trace-blast-radius-all`: every path evaluated for a group or finding, dead ends included, with the control that stopped each one.

Ask: **"Triage is done. Want the prioritized report, a deep dive on one group, or every path we tried for a group?"**

**When the user asks about a specific finding, path or root cause** (at any point in the session, not only right after triage), suggest `/trace-blast-radius`: it traces how far that one weakness reaches and ranks the paths it opens. Then offer `/trace-blast-radius-all` for the dead ends.

These skills read from the findings store (`list_groups`, `query_findings`, `get_investigation`), so their answers match what triage saved. None of them re-run the pipeline.

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
