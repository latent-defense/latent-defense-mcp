export const meta = {
  name: 'triage-pipeline',
  description: 'Structural triage: recursive grouping → energy-guided investigation → audience delivery',
  phases: [
    { title: 'Load', detail: 'Pre-load graph for energy tools' },
    { title: 'Discover', detail: 'Load findings into store, identify remediation clusters' },
    { title: 'Group', detail: 'Claim findings per group via MCP tools, energy-guided splits' },
    { title: 'Sweep', detail: 'Claim unclaimed findings via query tools' },
    { title: 'Investigate', detail: 'Two-stage: energy exploration → code verification per group' },
    { title: 'Route', detail: 'Classify remaining groups' },
    { title: 'Deliver', detail: 'Per-audience outputs' },
  ],
}

// ═══════════════════════════════════════════════════════════════
// Args — always load from project state, args override
// ═══════════════════════════════════════════════════════════════
let parsed = (typeof args === 'string') ? JSON.parse(args) : (args || {})
const profileId = parsed.profile_id || ''

if (!profileId) {
  log('✗ No profile_id provided')
  return { status: 'error', errors: ['No profile_id — pass at least {profile_id: "..."}'] }
}

// Always load from project first — args override for one-off changes
const projectData = await agent(`
Load the triage project and user profile.
ToolSearch query="select:mcp__latent-defense__triage_load_project,mcp__latent-defense__triage_load_user" max_results=2
Call triage_load_project(project_id="${profileId}").
Also call triage_load_user(name="default") or the first available user.
Return all project fields: branch_id, sources, audiences, verification_channels, user_context, deployment_model, output_dir.
`, { label: 'load-project', phase: 'Load', model: 'haiku', schema: {
  type: 'object', properties: {
    branch_id: { type: 'string' }, sources: { type: 'array' }, audiences: { type: 'array' },
    verification_channels: { type: 'array' }, user_context: { type: 'object' },
    deployment_model: { type: 'string' }, output_dir: { type: 'string' },
  },
}})

// Merge: args override project data
if (projectData) {
  const merged = { ...projectData, ...parsed, profile_id: profileId }
  parsed = merged
}

const sources = parsed.sources || []
if (parsed.findings_path && sources.length === 0) {
  sources.push({ path: parsed.findings_path, type: 'scanner', name: 'scanner', authority: 'tool' })
}
const branchId = parsed.branch_id
const verificationChannels = parsed.verification_channels || []
const uc = parsed.user_context || {}
const audiences = parsed.audiences || []
const maxInvestigate = parsed.max_investigate || 9999
const maxDepth = parsed.max_group_depth || 3
const outputDir = parsed.output_dir || 'triage-output'

const errors = []
if (sources.length === 0) errors.push('No sources')
if (!branchId) errors.push('No branch_id')
if (audiences.length === 0) errors.push('No audiences')
if (errors.length > 0) {
  for (const e of errors) log(`✗ ${e}`)
  return { status: 'error', errors }
}

log(`Profile: ${profileId}`)
log(`Sources: ${sources.map(s => s.name || s.type || s.path).join(', ')}`)
log(`Branch: ${branchId}`)
log(`Audiences: ${audiences.map(a => a.name).join(', ')}`)

// ═══════════════════════════════════════════════════════════════
// Checkpoint: read pipeline status to determine what's already done
// ═══════════════════════════════════════════════════════════════
const checkpoint = await agent(`
ToolSearch query="select:mcp__latent-defense__pipeline_status" max_results=1
Call pipeline_status(project_id="${profileId}").
Return the full result.
`, { label: 'checkpoint', phase: 'Load', model: 'haiku', schema: {
  type: 'object', properties: {
    total_findings: { type: 'integer' }, claimed: { type: 'integer' }, unclaimed: { type: 'integer' },
    groups: { type: 'integer' }, investigated: { type: 'integer' }, explored_only: { type: 'integer' },
    pending_investigate: { type: 'integer' },
    phases: { type: 'object' }, next_action: { type: 'string' },
  },
}})

const cp = checkpoint || { phases: {} }
log(`Checkpoint: ${JSON.stringify(cp.phases || {})}`)
log(`Next action: ${cp.next_action || 'start from beginning'}`)

// ═══════════════════════════════════════════════════════════════
// Verification channels → agent instructions
// ═══════════════════════════════════════════════════════════════

const VERIFY_INSTRUCTIONS = verificationChannels.length > 0
  ? verificationChannels.map(ch =>
      `### ${ch.type} (${ch.method})\n${ch.instructions || 'No specific instructions.'}\nScope: ${ch.scope || 'unspecified'}`
    ).join('\n\n')
  : 'No verification channels configured. Verify via graph semantic context only.'

// ═══════════════════════════════════════════════════════════════
// Shared constants
// ═══════════════════════════════════════════════════════════════

const ENERGY_TOOLS = `ToolSearch query="select:mcp__latent-defense__energy_node_scores,mcp__latent-defense__energy_lowest_hop,mcp__latent-defense__energy_edge_scores,mcp__latent-defense__energy_trace_to_target" max_results=5`

const GRAPH_TOOLS = `ToolSearch query="select:mcp__latent-defense__read_node,mcp__latent-defense__grep_nodes,mcp__latent-defense__find_nodes_by_type,mcp__latent-defense__get_connected_edges" max_results=5`

const FINDINGS_TOOLS = `ToolSearch query="select:mcp__latent-defense__query_findings,mcp__latent-defense__get_finding,mcp__latent-defense__findings_stats,mcp__latent-defense__claim_findings_by_query,mcp__latent-defense__claim_findings_range,mcp__latent-defense__claim_findings,mcp__latent-defense__create_group,mcp__latent-defense__update_group,mcp__latent-defense__list_groups" max_results=10`

const INVESTIGATE_TOOLS = `ToolSearch query="select:mcp__latent-defense__save_investigation,mcp__latent-defense__get_investigation,mcp__latent-defense__query_findings,mcp__latent-defense__list_groups,mcp__latent-defense__update_group" max_results=6`

const ENERGY_METHOD = `
## Energy-guided decisions

The graph is ALREADY LOADED. Do NOT call load_graph_energies.
Use energy tools to inform split/merge decisions. This is not optional.

### For split decisions:
After claiming findings, call energy_node_scores for each finding's subject
(service name, file path, resource ID). Record entry energies.
- Spread > 2.0 → SPLIT by exposure zone (exposed < 2.0 vs interior > 3.0)
- Spread <= 2.0 → keep together
- energy_trace_to_target returns "not reachable" between anchors → SPLIT (disconnected)

### For sweep merge decisions:
- energy_node_scores on the unclaimed finding's subject
- energy_trace_to_target from finding anchor to each group's anchor
- Assign to group with shortest accelerating path
- No path within 4 hops → new group

### Tool rules (large graphs):
- USE: energy_node_scores, energy_lowest_hop, energy_edge_scores, energy_trace_to_target (max_hops=4)
- AVOID: energy_node_neighborhood (too slow on large graphs)
`

const ENERGY_GUIDE = `
## How to interpret JEPA energy signals

**Entry energy** = structural exposure. < 0.1: directly accessible. 0.1-0.5: entry-facing.
0.5-2.0: near-surface. 2.0-4.0: interior. > 4.0: deep interior.

**Transition energy** = per-edge resistance. Negative = accelerating (easy). Positive = braking (barrier).

**Momentum** = cumulative path score. 0-20: well defended. 20-40: moderate. 40-60: low resistance. 60-80: concerning.

**Key rule:** Low resistance ≠ security problem. Auth happy paths accelerate by design.
The signal is low resistance WHERE IT SHOULDN'T BE.

**Edge type patterns:** contains/calls accelerate. owns/member_of/depends_on brake.
has_permission/assumes_role/validates 100% accelerate. protects: 76% brake, 24% accelerate.
An accelerating protects edge = structurally transparent control → investigate.

**High-value target types:** When tracing blast radius, these node types are what attackers
want to reach. Prioritize them in outbound exploration:
- data_store, database — where sensitive data lives
- credential, crypto_key — authentication material
- service_account, iam_role — privilege escalation
- environment_var — when it holds secrets (check context)
`

const INVESTIGATION_METHOD = `
## Investigation method

### Step 1: Energy exploration (structural map)
1. energy_node_scores — what is this node, what are its connections?
2. energy_lowest_hop — single easiest connection, follow it
3. energy_edge_scores — specific transition energies on key edges
4. energy_trace_to_target — reachability from entry points

Use graph tools for additional context: read_node for full details, grep_nodes to find related nodes.

Iterate. Each result should prompt the next question.

### Step 2: Translate energy to security statements
Every energy value must become a concrete statement:
- Entry energy → "directly accessible / behind N barriers / deep interior" — WHY?
- Transition energy → "connection has no/moderate/strong resistance" — what IS it?
- Controls → "auth check / boundary / validation at location between entry and target"
If you can't translate, explore more.

### Step 3: Verify against code, config, or live infrastructure — NOT the graph
The graph is the screening tool. Verification needs a different source.

## Verification channels available
${VERIFY_INSTRUCTIONS}

### Step 4: Resolve unknowns
Don't leave unknowns open. Flag as UNRESOLVED with specific action to resolve.

### Step 5: Blast radius
- What data/systems exposed? Single-tenant or multi-tenant?
- Deployment model: ${parsed.deployment_model || uc.deployment_model || 'unknown'}

### Step 6: Verdict
- **confirmed**: real risk, no adequate control
- **refuted**: controls hold, record what the model couldn't see (success)
- **partial**: real but lower risk than structure suggests
`

const RESOLUTION_GUIDE = `
## Resolution categories
- **eliminable**: clear fix, no trade-off → engineering
- **reducible**: partial fix, add controls → engineering
- **constrained**: design limitation → product decision
- **drift_prone**: recurring → automation/monitoring
- **mitigated**: fix friction > risk under controls → accept + review date

## Control depth chain (required for mitigated)
1. What control prevents exploitation?
2. Is the control effective?
3. What would break it?
4. Is that failure condition defended?
`

const GRAPH_CORRECTION_TOOLS = `ToolSearch query="select:mcp__latent-defense__edit_node,mcp__latent-defense__add_node,mcp__latent-defense__add_edge,mcp__latent-defense__delete_node,mcp__latent-defense__delete_edge,mcp__latent-defense__edit_edge,mcp__latent-defense__edit_subgraph,mcp__latent-defense__bulk_edit_edges" max_results=8`

const GRAPH_CORRECTION = `
## Graph corrections — required, not optional

When your verification reveals the graph is wrong — stale metadata, missing edges, inaccurate
descriptions — fix it right then. Do not document it for later. Do not flag it for remapping.
A graph that lies about infrastructure is worse than an incomplete graph.

**How:**
1. Call read_node(name) or read_edge(name) first (required before editing — the tools enforce this)
2. Verify against a source of truth (kubectl, az, aws, gh api output you already have)
3. Fix what's wrong using the appropriate tool:
   - **Stale metadata**: edit_node(name, metadata={...corrected...}, reason="verified via kubectl: ...")
     Metadata is deep-merged — nested keys you don't mention are preserved.
   - **Wrong node type**: edit_node(name, type="correct_type", reason="...")
   - **Missing node**: add_node(name, type, metadata, semantic_context, reason)
   - **Missing edge**: add_edge(name, type, source, target, reason)
   - **Wrong edge endpoint**: edit_edge(name, source=..., target=..., reason)
   - **Stale metadata keys**: edit_node(name, remove_keys=["old_key", "nested.old"], reason)
   - **Decommissioned entity**: delete_node(name, reason) or delete_edge(name, reason)
   - **Restructure a neighborhood**: edit_subgraph(remove_nodes, add_nodes, modify_nodes, ...)
   - **Fix many edges at once**: bulk_edit_edges(edge_type=..., metadata={...}, dry_run=true first)

Only correct based on grounded evidence — CLI output, source code, API responses you ran
during this investigation. Never correct based on assumptions.

Do NOT call commit_graph — corrections are committed as a batch after all investigations complete.

${GRAPH_CORRECTION_TOOLS}
`

const REPORT_METHODOLOGY = `
## Report rules
- Lead with the action table
- Separate remediation-ready from investigation-needed
- Dismissed items are high-value — document the control and why it holds
- Every finding: blast radius, evidence from code/config (not graph), no effort estimates
- No model commentary, energy scores, graph node IDs, methodology sections
- No vendor language, no tool comparisons
- Define jargon inline on first use
- Review dates come from the user, not invented
`

// ═══════════════════════════════════════════════════════════════
// Phase 1: Load graph (always runs — graph must be in cache)
// ═══════════════════════════════════════════════════════════════
phase('Load')
log('Loading graph into local cache...')
const loadResult = await agent(`
Load the infrastructure graph for energy analysis.

ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}").

This checks the local disk cache first (instant if already cached from a previous session).
Only fetches from the remote server if no cache exists.

Report the node count, edge count, and whether energies loaded (has_energies).
`, { label: 'load-graph', phase: 'Load', model: 'sonnet', schema: {
  type: 'object', properties: { n_nodes: { type: 'integer' }, n_edges: { type: 'integer' }, has_energies: { type: 'boolean' }, status: { type: 'string' } }, required: ['status'],
}})
log(`Graph: ${loadResult?.n_nodes || '?'} nodes, ${loadResult?.n_edges || '?'} edges, energies: ${loadResult?.has_energies}`)

if (!loadResult || loadResult.status === 'error' || !loadResult.n_nodes) {
  return { status: 'error', reason: 'Graph failed to load. Check authentication and branch_id.', loadResult }
}

// ═══════════════════════════════════════════════════════════════
// Phase 2: Discover — skip if groups already exist
// ═══════════════════════════════════════════════════════════════
phase('Discover')

let totalFindings = cp.total_findings || 0

if (cp.phases?.discover === 'complete') {
  log(`Discover: SKIPPING — ${cp.groups} groups already exist, ${cp.claimed}/${cp.total_findings} claimed`)
  totalFindings = cp.total_findings
} else {
  log('Loading findings into store and discovering clusters...')
  const allSourcePaths = sources.map(s => s.path)
  const discoverResult = await agent(`
You are the discovery agent. Your job:

1. Load ALL findings into the findings store.
2. Review the distribution and create remediation groups.

## Step 1: Load findings
${FINDINGS_TOOLS}

${allSourcePaths.map(p => `Call load_findings(project_id="${profileId}", path="${p}")`).join('\n')}

Then call findings_stats(project_id="${profileId}") to see the distribution.

## Step 2: Create remediation groups

${uc.data_assessment ? `User assessment: ${uc.data_assessment}` : ''}

Ask: "if I were fixing these, what batches of work would I create?"
Target 8-20 groups. Do NOT create per-finding, per-service, or per-scanner groups.

Common patterns: package CVEs per image, missing auth across services, CI/CD supply chain,
attack paths per entry point, code defects per class, Dockerfile hygiene, default credentials.

For each group, call:
  create_group(project_id="${profileId}", group_id=<short-id>, description=<remediation action>)

## Important: Do NOT claim findings

Your job is ONLY to create groups. Do NOT call claim_findings_by_query, claim_findings_range, or claim_findings.
Claiming is done by the Group agents in the next phase — they search for and claim findings
that match their group's description.

After creating groups, call findings_stats to report the distribution.
Then call list_groups to report all groups.

Return the total findings count and group count.
`, { label: 'discover', phase: 'Discover', model: 'opus', schema: {
    type: 'object', properties: {
      total_findings: { type: 'integer' },
      groups_created: { type: 'integer' },
    }, required: ['total_findings', 'groups_created'],
  }})

  if (!discoverResult) return { status: 'error', reason: 'Discover failed' }
  totalFindings = discoverResult.total_findings || 0
  log(`Discovered: ${totalFindings} findings → ${discoverResult.groups_created} groups`)
}

// ═══════════════════════════════════════════════════════════════
// Phase 3: Group — skip if all findings claimed
// ═══════════════════════════════════════════════════════════════
phase('Group')

if (cp.phases?.group === 'complete') {
  log(`Group: SKIPPING — all ${cp.claimed} findings already claimed`)
} else {
  // Read groups — only process those with 0 claims
  const groupListResult = await agent(`
You have ONE job: call the list_groups MCP tool and return the result.

Step 1: Load the tool schema.
ToolSearch query="select:mcp__latent-defense__list_groups" max_results=1

Step 2: Call the tool.
mcp__latent-defense__list_groups(project_id="${profileId}")

Step 3: Return the groups array from the result.

Do NOT write Python scripts. Do NOT use Bash. Just call the MCP tool directly.
`, { label: 'list-groups', phase: 'Group', model: 'sonnet', schema: {
    type: 'object', properties: {
      groups: { type: 'array', items: { type: 'object', properties: {
        group_id: { type: 'string' }, description: { type: 'string' }, finding_count: { type: 'integer' },
      }}},
    }, required: ['groups'],
  }})

  const groups = groupListResult?.groups || []
  // Only process groups that need claims (finding_count === 0 or undefined)
  const needsClaiming = groups.filter(g => !g.finding_count || g.finding_count === 0)
  const alreadyClaimed = groups.length - needsClaiming.length

  if (needsClaiming.length === 0 && alreadyClaimed > 0) {
    log(`Group: SKIPPING — all ${groups.length} groups already have claims`)
  } else {
    const toProcess = needsClaiming.length > 0 ? needsClaiming : groups
    log(`Claiming for ${toProcess.length} groups (${alreadyClaimed} already have claims)...`)

    await parallel(toProcess.map(group => () => agent(`
Refine group "${group.group_id}" (${group.finding_count || '?'} findings): ${group.description}

## Setup — load graph first
ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}") — returns instantly from disk cache.

## Tools
${FINDINGS_TOOLS}
${ENERGY_TOOLS}
${GRAPH_TOOLS}
${ENERGY_METHOD}

## Your task — claim findings that belong to this group

1. Search for findings matching this group's description:
   claim_findings_by_query(project_id="${profileId}", group_id="${group.group_id}", keyword=<relevant terms>, dry_run=true)
   Also try: scanner=..., severity=..., repo=..., category=...
   Review the dry_run preview carefully. If the matches look correct:
   claim_findings_by_query(project_id="${profileId}", group_id="${group.group_id}", ..., dry_run=false)

   For large contiguous scanner blocks (e.g., all Trivy findings for one image):
   claim_findings_range(project_id="${profileId}", group_id="${group.group_id}", start=..., end=..., dry_run=true)
   Review. Then: dry_run=false

   Iterate with different queries until you've captured all findings for this group.

2. Review what you claimed:
   query_findings(project_id="${profileId}", group_id="${group.group_id}", limit=20)
   Read a sample with get_finding for details. Unclaim anything that doesn't belong.

3. Energy analysis: find anchor nodes with grep_nodes, then energy_node_scores.
   If entry energy spread > 2.0, consider splitting — but splitting creates complexity,
   so only split if the findings genuinely need different remediation approaches.
   Update the group anchor: update_group(project_id="${profileId}", group_id="${group.group_id}", anchor_node=<node>)

Report what you claimed and the energy analysis.
`, { label: `refine-${group.group_id}`, phase: 'Group', model: 'sonnet' })))
  }
}

// ═══════════════════════════════════════════════════════════════
// Phase 4: Sweep — skip if all findings claimed
// ═══════════════════════════════════════════════════════════════
phase('Sweep')

// Re-check claim status after Group phase
const postGroupCheck = await agent(`
You have ONE job: call the findings_stats MCP tool and return the counts.

Step 1: Load the tool schema.
ToolSearch query="select:mcp__latent-defense__findings_stats" max_results=1

Step 2: Call the tool.
mcp__latent-defense__findings_stats(project_id="${profileId}")

Step 3: Return total, claimed, unclaimed counts from the result.

Do NOT write Python scripts. Do NOT use Bash. Just call the MCP tool directly.
`, { label: 'check-sweep', phase: 'Sweep', model: 'sonnet', schema: {
  type: 'object', properties: {
    total: { type: 'integer' }, claimed: { type: 'integer' }, unclaimed: { type: 'integer' },
  },
}})

if (postGroupCheck?.unclaimed === 0) {
  log(`Sweep: SKIPPING — all ${postGroupCheck?.claimed} findings claimed`)
} else {
  log(`Sweeping ${postGroupCheck?.unclaimed || '?'} unclaimed findings...`)
  await agent(`
Sweep: find and assign all unclaimed findings.

## Setup — load graph
ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}") — returns instantly from disk cache.

## Tools
${FINDINGS_TOOLS}
${ENERGY_TOOLS}
${GRAPH_TOOLS}
${ENERGY_METHOD}

1. Call findings_stats(project_id="${profileId}") to check how many are unclaimed.
2. If unclaimed > 0, call query_findings(project_id="${profileId}", unclaimed_only=true, limit=100)
3. For each unclaimed finding:
   - Read it with get_finding
   - Find the best matching group using keyword matching against list_groups descriptions
   - Or use grep_nodes + energy_node_scores + energy_trace_to_target to find the structurally closest group
   - Claim it: claim_findings(project_id="${profileId}", group_id=<best_match>, indices="<idx>")
4. If a finding doesn't fit any group, create a new one with create_group, then claim.
5. Repeat until findings_stats shows 0 unclaimed.

Report final stats.
`, { label: 'sweep', phase: 'Sweep', model: 'sonnet' })
}

// Hard check: do NOT proceed with unclaimed findings.
// Re-read stats to verify — the previous checks may be stale.
const preSweepVerify = await agent(`
You have ONE job: call findings_stats and return the unclaimed count.

ToolSearch query="select:mcp__latent-defense__findings_stats" max_results=1
mcp__latent-defense__findings_stats(project_id="${profileId}")

Return the unclaimed count.
Do NOT write Python scripts. Do NOT use Bash.
`, { label: 'verify-sweep', phase: 'Sweep', model: 'sonnet', schema: {
  type: 'object', properties: { unclaimed: { type: 'integer' }, total: { type: 'integer' }, claimed: { type: 'integer' } },
}})

if (preSweepVerify?.unclaimed > 0) {
  log(`⚠ ${preSweepVerify.unclaimed} findings still unclaimed after Sweep — proceeding but flagging`)
}

// ═══════════════════════════════════════════════════════════════
// Phase 5: Investigate — only pending groups
// ═══════════════════════════════════════════════════════════════
phase('Investigate')

// Get groups that still need investigation
const investigateCheck = await agent(`
You must determine which groups need investigation. Follow these steps exactly:

Step 1: Load the tool schemas.
ToolSearch query="select:mcp__latent-defense__list_groups,mcp__latent-defense__get_investigation" max_results=2

Step 2: Get all groups.
mcp__latent-defense__list_groups(project_id="${profileId}")

Step 3: For EACH group returned, check if it has an investigation.
mcp__latent-defense__get_investigation(project_id="${profileId}", group_id=<the group's ID>)

Step 4: Categorize each group:
- If get_investigation returns "No investigation found" → needs both explore and verify → add to groups_needing_explore
- If get_investigation returns explore_result but NO verdict → needs only verify → add to groups_needing_verify
- If get_investigation returns a verdict → already done

Do NOT write Python scripts. Do NOT use Bash. Call MCP tools directly.
`, { label: 'check-investigate', phase: 'Investigate', model: 'sonnet', schema: {
  type: 'object', properties: {
    groups_needing_explore: { type: 'array', items: { type: 'object', properties: {
      group_id: { type: 'string' }, description: { type: 'string' },
      finding_count: { type: 'integer' }, anchor_node: { type: 'string' },
    }}},
    groups_needing_verify: { type: 'array', items: { type: 'object', properties: {
      group_id: { type: 'string' }, description: { type: 'string' },
      finding_count: { type: 'integer' }, anchor_node: { type: 'string' },
    }}},
    already_done: { type: 'integer' },
  },
}})

const needsExplore = (investigateCheck?.groups_needing_explore || []).slice(0, maxInvestigate)
const needsVerify = investigateCheck?.groups_needing_verify || []
const alreadyInvestigated = investigateCheck?.already_done || 0

log(`Investigate: ${alreadyInvestigated} done, ${needsExplore.length} need explore+verify, ${needsVerify.length} need verify only`)

// Run explore → verify pipeline for groups that need both stages
let explored = []
if (needsExplore.length > 0) {
  explored = await pipeline(
    needsExplore,

    // Stage 1: Energy exploration
    (group) => agent(`
Explore the structural position of finding group "${group.group_id}": ${group.description}

## Setup — load graph
ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}") — returns instantly from disk cache.

${ENERGY_GUIDE}
${ENERGY_TOOLS}
${GRAPH_TOOLS}
${INVESTIGATE_TOOLS}

1. Load the group's findings: query_findings(project_id="${profileId}", group_id="${group.group_id}")
2. Find anchor nodes: grep_nodes for the affected services/resources
3. Energy analysis: energy_node_scores, energy_lowest_hop, energy_trace_to_target

${group.anchor_node ? `Start with anchor: ${group.anchor_node}` : 'Find anchor nodes via grep_nodes.'}

Explore iteratively until you can answer: where does this sit structurally,
what controls exist, what's reachable, what should the code verifier check?

Mark the group as investigating: update_group(project_id="${profileId}", group_id="${group.group_id}", status="investigating")
Save your exploration: save_investigation(project_id="${profileId}", group_id="${group.group_id}", explore_result=<JSON of your findings>)

Return: structural position, files to verify, key questions.
`, { label: `explore-${group.group_id}`, phase: 'Investigate', model: 'opus', schema: {
      type: 'object', properties: {
        id: { type: 'string' }, structural_position: { type: 'string' },
        files_to_verify: { type: 'array', items: { type: 'string' } },
        key_questions: { type: 'array', items: { type: 'string' } },
      }, required: ['id', 'structural_position', 'files_to_verify', 'key_questions'],
    }}),

    // Stage 2: Code verification
    (energyResult, group) => agent(`
Verify finding group "${group.group_id}" against code and configuration.

## Energy exploration results (from the previous stage)
${JSON.stringify(energyResult, null, 2)}

Files to verify: ${energyResult?.files_to_verify?.map(f => `\n- ${f}`).join('') || 'Use search hints.'}
Key questions: ${energyResult?.key_questions?.map(q => `\n- ${q}`).join('') || 'Determine if structural signals reflect real risk.'}

## Verification channels
${VERIFY_INSTRUCTIONS}

${RESOLUTION_GUIDE}
${uc.investigation_focus ? `User priorities: ${uc.investigation_focus}` : ''}

## Setup — load graph
ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}") — returns instantly from disk cache.

## Group context
${INVESTIGATE_TOOLS}
Load findings: query_findings(project_id="${profileId}", group_id="${group.group_id}")

${GRAPH_CORRECTION}

## Save verdict
save_investigation(project_id="${profileId}", group_id="${group.group_id}", verdict=<confirmed|refuted|partial>, evidence=<citation>)
update_group(project_id="${profileId}", group_id="${group.group_id}", resolution=<category>, action=<what to fix>, status="investigated", primary_audience=<who>)

Return verdict and action.
`, { label: `verify-${group.group_id}`, phase: 'Investigate', model: 'opus', schema: {
      type: 'object', properties: {
        id: { type: 'string' },
        resolution: { type: 'string', enum: ['eliminable', 'reducible', 'constrained', 'drift_prone', 'mitigated'] },
        verdict: { type: 'string', enum: ['confirmed', 'refuted', 'partial'] },
        action: { type: 'string' },
        primary_audience: { type: 'string' },
      }, required: ['id', 'resolution', 'verdict', 'action'],
    }})
  )
}

// Run verify-only for groups that had explore but no verdict
let verifiedFromPartial = []
if (needsVerify.length > 0) {
  log(`Running verify-only for ${needsVerify.length} groups with existing explore results...`)
  verifiedFromPartial = await parallel(needsVerify.map(group => () => agent(`
Verify finding group "${group.group_id}" against code and configuration.

## Energy exploration results
This group already has explore results saved. Load them:
${INVESTIGATE_TOOLS}
Call get_investigation(project_id="${profileId}", group_id="${group.group_id}") to get the explore_result.
Use the structural_position, files_to_verify, and key_questions from there.

## Verification channels
${VERIFY_INSTRUCTIONS}

${RESOLUTION_GUIDE}
${uc.investigation_focus ? `User priorities: ${uc.investigation_focus}` : ''}

## Setup — load graph
ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}") — returns instantly from disk cache.

## Group context
Load findings: query_findings(project_id="${profileId}", group_id="${group.group_id}")

${GRAPH_CORRECTION}

## Save verdict
save_investigation(project_id="${profileId}", group_id="${group.group_id}", verdict=<confirmed|refuted|partial>, evidence=<citation>)
update_group(project_id="${profileId}", group_id="${group.group_id}", resolution=<category>, action=<what to fix>, status="investigated", primary_audience=<who>)

Return verdict and action.
`, { label: `verify-${group.group_id}`, phase: 'Investigate', model: 'opus', schema: {
    type: 'object', properties: {
      id: { type: 'string' },
      resolution: { type: 'string', enum: ['eliminable', 'reducible', 'constrained', 'drift_prone', 'mitigated'] },
      verdict: { type: 'string', enum: ['confirmed', 'refuted', 'partial'] },
      action: { type: 'string' },
      primary_audience: { type: 'string' },
    }, required: ['id', 'resolution', 'verdict', 'action'],
  }})))
}

const allVerified = [...explored.filter(Boolean), ...verifiedFromPartial.filter(Boolean)]
log(`Verified: ${allVerified.length} (${alreadyInvestigated} previously done)`)

// Commit graph corrections accumulated during investigation
if (needsExplore.length > 0 || needsVerify.length > 0) {
  log('Committing graph corrections from investigation phase...')
  await agent(`
Commit any pending graph corrections from the investigation phase.

ToolSearch query="select:mcp__latent-defense__pending_changes,mcp__latent-defense__commit_graph" max_results=2

Call pending_changes(). If there are changes, review them briefly and call
commit_graph(message="triage investigation: graph corrections from ${profileId || 'pipeline run'}").
If no changes, report that the graph required no corrections.
`, { label: 'commit-corrections', phase: 'Investigate', model: 'sonnet' })
}

// ═══════════════════════════════════════════════════════════════
// Phase 6: Route remaining — skip if all groups are routed/investigated
// ═══════════════════════════════════════════════════════════════
phase('Route')

// Check for groups that need routing (uninvestigated groups beyond the limit)
const routeCheck = await agent(`
You have ONE job: find groups with status "open" that need routing.

Step 1: Load the tool schema.
ToolSearch query="select:mcp__latent-defense__list_groups" max_results=1

Step 2: Call the tool.
mcp__latent-defense__list_groups(project_id="${profileId}", status="open")

Step 3: Return the groups array and count.

Do NOT write Python scripts. Do NOT use Bash. Just call the MCP tool directly.
`, { label: 'check-route', phase: 'Route', model: 'sonnet', schema: {
  type: 'object', properties: {
    groups: { type: 'array', items: { type: 'object' } },
    count: { type: 'integer' },
  },
}})

const toRoute = routeCheck?.groups || []
if (toRoute.length > 0) {
  log(`Routing ${toRoute.length} remaining groups...`)
  await agent(`
Classify these uninvestigated finding groups.

${RESOLUTION_GUIDE}
${INVESTIGATE_TOOLS}

For each group, call:
  update_group(project_id="${profileId}", group_id=<id>, resolution=<category>, action=<brief>, status="routed", primary_audience=<who>)

## Groups (${toRoute.length})
${JSON.stringify(toRoute.map(g => ({ id: g.group_id, description: g.description, findings: g.finding_count })), null, 2)}
`, { label: 'bulk-route', phase: 'Route', model: 'haiku' })
} else {
  log('Route: SKIPPING — all groups investigated or routed')
}

// Save results to project
if (profileId) {
  await agent(`
Save results to project.
ToolSearch query="select:mcp__latent-defense__triage_save_project,mcp__latent-defense__pipeline_status" max_results=2

Call pipeline_status(project_id="${profileId}") to get final state.
Then call triage_save_project("${profileId}", <JSON with the pipeline_status results>).
`, { label: 'save-results', phase: 'Route', model: 'haiku' })
}

// ═══════════════════════════════════════════════════════════════
// Phase 7: Deliver — only generate missing audience outputs
// ═══════════════════════════════════════════════════════════════
phase('Deliver')
log(`Generating outputs for ${audiences.length} audience(s)...`)

const outputs = await parallel(
  audiences.map(audience => () =>
    agent(`
Generate output for **${audience.name}**.

${audience.needs ? `What they need: ${audience.needs}` : ''}
${audience.report_outline ? `Approved outline:\n${audience.report_outline}\nFollow exactly.` : ''}
${audience.not_include ? `Do NOT include: ${audience.not_include}` : ''}

${REPORT_METHODOLOGY}

## Load data from findings store
${INVESTIGATE_TOOLS}

Call findings_stats(project_id="${profileId}") for totals.
Call list_groups(project_id="${profileId}") for all groups.
For each group, call get_investigation(project_id="${profileId}", group_id=<id>) for verdict+evidence.
Filter to items relevant to this audience (match primary_audience).

Save to: ${outputDir}/${audience.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.md
`, { label: `deliver-${audience.name}`, phase: 'Deliver', model: 'opus' })
  )
)

const outputFiles = audiences.map(a => ({
  audience: a.name,
  path: `${outputDir}/${a.name.toLowerCase().replace(/[^a-z0-9]+/g, '-')}.md`,
}))

if (profileId) {
  await agent(`
Save output manifest.
ToolSearch query="select:mcp__latent-defense__triage_save_project" max_results=2
Call triage_save_project("${profileId}", ${JSON.stringify({ outputs: outputFiles })})
`, { label: 'save-outputs', phase: 'Deliver', model: 'haiku' })
}

// Build resolution distribution from the store
const finalStatus = await agent(`
${FINDINGS_TOOLS}
Call pipeline_status(project_id="${profileId}").
Return the full result.
`, { label: 'final-status', phase: 'Deliver', model: 'haiku', schema: {
  type: 'object', properties: {
    total_findings: { type: 'integer' }, groups: { type: 'integer' },
    investigated: { type: 'integer' }, phases: { type: 'object' },
  },
}})

return {
  status: 'completed',
  config: { sources: sources.map(s => s.name || s.type), audiences: audiences.map(a => a.name), branch_id: branchId },
  results: {
    total_findings: totalFindings || finalStatus?.total_findings || 0,
    groups: finalStatus?.groups || 0,
    investigated: finalStatus?.investigated || 0,
  },
  outputs: outputFiles,
  profile_id: profileId,
}
