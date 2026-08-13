export const meta = {
  name: 'triage-pipeline',
  description: 'Structural triage: recursive grouping → energy-guided investigation → audience delivery',
  phases: [
    { title: 'Load', detail: 'Pre-load graph for energy tools' },
    { title: 'Discover', detail: 'Parent agent reads all findings, identifies remediation clusters' },
    { title: 'Group', detail: 'Recursive agents claim findings, energy-guided split/merge' },
    { title: 'Sweep', detail: 'Catch unclaimed findings via structural proximity' },
    { title: 'Investigate', detail: 'Two-stage: energy exploration → code verification per group' },
    { title: 'Route', detail: 'Classify remaining groups' },
    { title: 'Deliver', detail: 'Per-audience outputs' },
  ],
}

// ═══════════════════════════════════════════════════════════════
// Args
// ═══════════════════════════════════════════════════════════════
const parsed = (typeof args === 'string') ? JSON.parse(args) : (args || {})
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
const profileId = parsed.profile_id || ''

const errors = []
if (sources.length === 0) errors.push('No sources')
if (!branchId) errors.push('No branch_id')
if (audiences.length === 0) errors.push('No audiences')
if (errors.length > 0) {
  for (const e of errors) log(`✗ ${e}`)
  return { status: 'error', errors }
}

log(`Sources: ${sources.map(s => s.name || s.type).join(', ')}`)
log(`Branch: ${branchId}`)
log(`Audiences: ${audiences.map(a => a.name).join(', ')}`)
log(`Verification channels: ${verificationChannels.length || 'none'}`)

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
A node is high-priority when it is a target type AND has many inbound writes_to,
authenticates_to, or has_permission edges AND is reachable (low entry energy).
Nodes with zero outbound edges and many sensitive inbound edges are structural sinks —
the things the infrastructure is built to protect.
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
// Schemas
// ═══════════════════════════════════════════════════════════════

const CLUSTER_SCHEMA = {
  type: 'object',
  properties: {
    clusters: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          description: { type: 'string' },
          estimated_findings: { type: 'integer' },
          hint: { type: 'string' },
          canonical_type: { type: 'string' },
          remediation_class: { type: 'string' },
        },
        required: ['id', 'description', 'estimated_findings', 'hint', 'canonical_type'],
      },
    },
    total_findings: { type: 'integer' },
    rationale: { type: 'string' },
  },
  required: ['clusters', 'total_findings'],
}

const GROUP_SCHEMA = {
  type: 'object',
  properties: {
    group_id: { type: 'string' },
    is_leaf: { type: 'boolean' },
    claimed_findings: { type: 'array', items: { type: 'integer' } },
    children: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' }, description: { type: 'string' },
          estimated_findings: { type: 'integer' }, hint: { type: 'string' },
        },
        required: ['id', 'description', 'estimated_findings', 'hint'],
      },
    },
    cross_refs: {
      type: 'array',
      items: {
        type: 'object',
        properties: { finding_idx: { type: 'integer' }, target_group: { type: 'string' }, reason: { type: 'string' } },
        required: ['finding_idx', 'reason'],
      },
    },
    energy_analysis: {
      type: 'object',
      properties: {
        anchor_nodes: { type: 'array', items: { type: 'object', properties: {
          finding_idx: { type: 'integer' }, node_id: { type: 'string' }, node_type: { type: 'string' }, entry_energy: { type: 'number' },
        }}},
        entry_energy_min: { type: 'number' }, entry_energy_max: { type: 'number' },
        entry_energy_spread: { type: 'number' },
        split_reason: { type: 'string' },
        structural_zone: { type: 'string' },
      },
    },
    annotation: {
      type: 'object',
      properties: {
        canonical_type: { type: 'string' }, remediation_class: { type: 'string' },
        affected_services: { type: 'array', items: { type: 'string' } },
        graph_search_hints: { type: 'array', items: { type: 'string' } },
        title: { type: 'string' }, severity_summary: { type: 'string' },
      },
      required: ['canonical_type', 'title'],
    },
    warnings: { type: 'array', items: { type: 'string' } },
  },
  required: ['group_id', 'is_leaf', 'claimed_findings', 'annotation'],
}

const INVESTIGATE_EXPLORE_SCHEMA = {
  type: 'object', properties: {
    id: { type: 'string' },
    structural_position: { type: 'string' },
    entry_energy: { type: 'number' },
    controls_found: { type: 'array', items: { type: 'object', properties: {
      node: { type: 'string' }, type: { type: 'string' }, braking: { type: 'boolean' }, energy: { type: 'number' },
    }}},
    paths_from_entry: { type: 'array', items: { type: 'object', properties: {
      entry: { type: 'string' }, momentum: { type: 'number' }, hops: { type: 'integer' },
    }}},
    sensitive_reachable: { type: 'array', items: { type: 'string' } },
    blast_radius_structural: { type: 'string' },
    files_to_verify: { type: 'array', items: { type: 'string' } },
    key_questions: { type: 'array', items: { type: 'string' } },
  }, required: ['id', 'structural_position', 'files_to_verify', 'key_questions'],
}

const INVESTIGATE_VERIFY_SCHEMA = {
  type: 'object', properties: {
    id: { type: 'string' },
    resolution: { type: 'string', enum: ['eliminable', 'reducible', 'constrained', 'drift_prone', 'mitigated'] },
    readiness: { type: 'string', enum: ['remediation_ready', 'investigation_needed'] },
    verdict: { type: 'string', enum: ['confirmed', 'refuted', 'partial'] },
    evidence: { type: 'string' },
    evidence_source: { type: 'string', enum: ['source_code', 'config_file', 'runtime_test', 'graph_context', 'semantic_context'] },
    unresolved: { type: 'array', items: { type: 'string' } },
    action: { type: 'string' },
    blast_radius: { type: 'string' },
    primary_audience: { type: 'string' },
    control_chain: { type: 'array', items: { type: 'object', properties: {
      question: { type: 'string' }, answer: { type: 'string' },
      status: { type: 'string', enum: ['verified', 'gap', 'unresolved'] },
    }}},
    key_insight: { type: 'string' },
  }, required: ['id', 'resolution', 'readiness', 'verdict', 'action'],
}

// ═══════════════════════════════════════════════════════════════
// Phase 1: Load graph
// ═══════════════════════════════════════════════════════════════
phase('Load')
log('Loading graph via oracle (triggers JEPA encoding with progress)...')
const loadResult = await agent(`
Load the infrastructure graph for energy analysis. This is a two-step process:

Step 1: Warm the inference cache via oracle.
ToolSearch query="select:mcp__latent-defense__oracle_load_branch,mcp__latent-defense__oracle_wait_for_load" max_results=2
Call oracle_load_branch("${branchId}").
Then call oracle_wait_for_load(timeout_secs=600, poll_interval=15) to block until encoding completes.

Step 2: Load the energy scores into the local cache.
ToolSearch query="select:mcp__latent-defense__load_graph_energies" max_results=1
Call load_graph_energies("${branchId}").
This fetches the pre-computed energy scores (instant after oracle loads).

Report the node count, edge count, and whether energies loaded (has_energies).
`, { label: 'load-graph', phase: 'Load', model: 'sonnet', schema: {
  type: 'object', properties: { n_nodes: { type: 'integer' }, n_edges: { type: 'integer' }, has_energies: { type: 'boolean' }, status: { type: 'string' } }, required: ['status'],
}})
log(`Graph: ${loadResult?.n_nodes || '?'} nodes, ${loadResult?.n_edges || '?'} edges, energies: ${loadResult?.has_energies}`)

// ═══════════════════════════════════════════════════════════════
// Phase 2: Discover clusters
// ═══════════════════════════════════════════════════════════════
phase('Discover')
log('Reading all findings...')

const allSourcePaths = sources.map(s => s.path)
const discoverResult = await agent(`
Read ALL findings and produce high-level clusters grouped by REMEDIATION ACTION.

Sources: ${allSourcePaths.map(p => `\n- ${p}`).join('')}
${uc.data_assessment ? `\nUser assessment: ${uc.data_assessment}` : ''}

Ask: "if I were fixing these, what batches of work would I create?"

Target 8-20 clusters. Do NOT create per-finding, per-service, or per-scanner clusters.

Common patterns: package CVEs per image, missing auth across services, CI/CD supply chain,
attack paths per entry point, code defects per class, Dockerfile hygiene, default credentials.
`, { label: 'discover', phase: 'Discover', model: 'opus', schema: CLUSTER_SCHEMA })

if (!discoverResult?.clusters) return { status: 'error', reason: 'Discover failed' }

log(`Discovered ${discoverResult.clusters.length} clusters from ${discoverResult.total_findings} findings`)
for (const c of discoverResult.clusters) log(`  ${c.id}: ~${c.estimated_findings} — ${c.description.slice(0, 80)}`)

// ═══════════════════════════════════════════════════════════════
// Phase 3: Recursive grouping with energy guidance
// ═══════════════════════════════════════════════════════════════
phase('Group')

const claimedGlobal = new Set()
const allGroups = []
const allCrossRefs = []

async function refineCluster(cluster, depthRemaining, parentPath) {
  const clusterId = `${parentPath}/${cluster.id}`
  const result = await agent(`
Grouping agent for: "${cluster.description}"

## Tools
${ENERGY_TOOLS}
${GRAPH_TOOLS}
${ENERGY_METHOD}

1. Read findings from: ${allSourcePaths.join(', ')}
2. Find ALL findings belonging to this cluster
3. Call energy_node_scores for each finding's subject to get entry energies
4. Based on energy spread: CLAIM (is_leaf=true) or SPLIT (is_leaf=false)

Hint: "${cluster.hint}"
Type: "${cluster.canonical_type}"
${cluster.remediation_class ? `Fix: "${cluster.remediation_class}"` : ''}
${depthRemaining <= 1 ? 'MUST terminate (is_leaf=true).' : `Depth remaining: ${depthRemaining}`}

List EXACT 0-based indices in claimed_findings. Report cross_refs for other clusters' findings.
`, { label: `group-${cluster.id}`, phase: 'Group', model: 'sonnet', schema: GROUP_SCHEMA })

  if (!result) { log(`  Warning: ${clusterId} null`); return }

  const newClaims = (result.claimed_findings || []).filter(idx => !claimedGlobal.has(idx))
  const doubles = (result.claimed_findings || []).filter(idx => claimedGlobal.has(idx))
  if (doubles.length > 0) log(`  Warning: ${clusterId} double-claimed ${doubles.length}`)
  for (const idx of newClaims) claimedGlobal.add(idx)
  if (result.cross_refs) for (const cr of result.cross_refs) allCrossRefs.push({ ...cr, source_group: clusterId })

  if (result.energy_analysis) {
    const ea = result.energy_analysis
    log(`  Energy: spread=${ea.entry_energy_spread?.toFixed(1) || '?'} zone=${ea.structural_zone || '?'}`)
  }

  if (result.is_leaf || depthRemaining <= 1) {
    allGroups.push({ ...result, group_id: clusterId, claimed_findings: newClaims, depth: maxDepth - depthRemaining })
    log(`  Leaf: ${clusterId} claimed ${newClaims.length}`)
  } else if (result.children?.length > 0) {
    log(`  Split: ${clusterId} → ${result.children.length} children`)
    if (newClaims.length > 0) {
      allGroups.push({ ...result, group_id: `${clusterId}/claimed`, is_leaf: true, claimed_findings: newClaims, children: [], depth: maxDepth - depthRemaining })
    }
    await parallel(result.children.map(child => () => refineCluster(child, depthRemaining - 1, clusterId)))
  } else {
    log(`  Warning: ${clusterId} is_leaf=false but no children, forcing leaf`)
    allGroups.push({ ...result, group_id: clusterId, is_leaf: true, claimed_findings: newClaims, depth: maxDepth - depthRemaining })
  }
}

await parallel(discoverResult.clusters.map(cluster => () => refineCluster(cluster, maxDepth, '')))
log(`Grouping: ${allGroups.length} leaf groups, ${claimedGlobal.size} claimed`)

// ═══════════════════════════════════════════════════════════════
// Phase 4: Sweep unclaimed
// ═══════════════════════════════════════════════════════════════
phase('Sweep')
const totalFindings = discoverResult.total_findings
const unclaimed = []
for (let i = 0; i < totalFindings; i++) { if (!claimedGlobal.has(i)) unclaimed.push(i) }
log(`Unclaimed: ${unclaimed.length}/${totalFindings}`)

if (unclaimed.length > 0) {
  const groupAnchors = allGroups
    .filter(g => g.energy_analysis?.anchor_nodes?.length > 0)
    .map(g => ({ group_id: g.group_id, title: g.annotation?.title, anchor: g.energy_analysis.anchor_nodes[0]?.node_id, zone: g.energy_analysis.structural_zone }))

  const sweepResult = await agent(`
Sweep: assign unclaimed findings [${unclaimed.join(', ')}]

## Tools
${ENERGY_TOOLS}
${GRAPH_TOOLS}
${ENERGY_METHOD}

Read findings from: ${allSourcePaths.join(', ')}

Existing groups:
${allGroups.map(g => `- ${g.group_id}: ${g.annotation?.title || 'untitled'} (${g.claimed_findings?.length || 0} findings)`).join('\n')}

${groupAnchors.length > 0 ? `Anchored groups:\n${groupAnchors.map(g => `- ${g.group_id}: anchor=${g.anchor}, zone=${g.zone}`).join('\n')}` : ''}

${allCrossRefs.length > 0 ? `Cross-refs:\n${allCrossRefs.slice(0, 20).map(cr => `Finding ${cr.finding_idx} → "${cr.target_group}" (${cr.reason})`).join('\n')}` : ''}
`, { label: 'sweep', phase: 'Sweep', model: 'sonnet', schema: {
    type: 'object', properties: {
      assignments: { type: 'array', items: { type: 'object', properties: { finding_idx: { type: 'integer' }, group_id: { type: 'string' }, reason: { type: 'string' } }, required: ['finding_idx', 'group_id'] } },
      new_groups: { type: 'array', items: GROUP_SCHEMA },
    }, required: ['assignments'],
  }})

  if (sweepResult) {
    for (const a of (sweepResult.assignments || [])) {
      claimedGlobal.add(a.finding_idx)
      const existing = allGroups.find(g => g.group_id === a.group_id)
      if (existing) { existing.claimed_findings = existing.claimed_findings || []; existing.claimed_findings.push(a.finding_idx) }
    }
    for (const ng of (sweepResult.new_groups || [])) {
      allGroups.push({ ...ng, depth: 0 })
      for (const idx of (ng.claimed_findings || [])) claimedGlobal.add(idx)
    }
  }
}

// Accounting check
const finalUnclaimed = []
for (let i = 0; i < totalFindings; i++) { if (!claimedGlobal.has(i)) finalUnclaimed.push(i) }
const claimCounts = {}
for (const g of allGroups) for (const idx of (g.claimed_findings || [])) claimCounts[idx] = (claimCounts[idx] || 0) + 1
const doubleClaimed = Object.entries(claimCounts).filter(([_, c]) => c > 1)
log(`After sweep: ${claimedGlobal.size}/${totalFindings} claimed, ${finalUnclaimed.length} unclaimed, ${doubleClaimed.length} double`)

// ═══════════════════════════════════════════════════════════════
// Phase 5: Investigate (two-stage pipeline)
// ═══════════════════════════════════════════════════════════════
phase('Investigate')

const toInvestigate = allGroups.slice(0, maxInvestigate)
log(`Investigating ${toInvestigate.length} groups...`)

const investigated = await pipeline(
  toInvestigate,

  // Stage 1: Energy exploration
  (group) => agent(`
Explore the structural position of this finding group using energy tools.

${ENERGY_GUIDE}
${ENERGY_TOOLS}
${GRAPH_TOOLS}

Starting point:
${group.energy_analysis?.anchor_nodes?.length > 0 ? `Anchors: ${JSON.stringify(group.energy_analysis.anchor_nodes.slice(0, 3))}` : `Search hints: ${JSON.stringify(group.annotation?.graph_search_hints?.slice(0, 5) || [])}`}

Explore iteratively until you can answer: where does this sit structurally,
what controls exist, what's reachable, what should the code verifier check?

## Group
${JSON.stringify({ id: group.group_id, title: group.annotation?.title, type: group.annotation?.canonical_type, findings: group.claimed_findings?.length, services: group.annotation?.affected_services }, null, 2)}
`, { label: `explore-${group.group_id.split('/').pop()}`, phase: 'Investigate', model: 'opus', schema: INVESTIGATE_EXPLORE_SCHEMA }),

  // Stage 2: Code verification
  (energyResult, group) => agent(`
Verify this finding group against code and configuration.

## Energy exploration results
${JSON.stringify(energyResult, null, 2)}

Files to verify: ${energyResult?.files_to_verify?.map(f => `\n- ${f}`).join('') || 'Use search hints from the group.'}
Key questions: ${energyResult?.key_questions?.map(q => `\n- ${q}`).join('') || 'Determine if structural signals reflect real risk.'}

## Verification channels
${VERIFY_INSTRUCTIONS}

${RESOLUTION_GUIDE}
${uc.investigation_focus ? `User priorities: ${uc.investigation_focus}` : ''}

## Group
${JSON.stringify({ id: group.group_id, title: group.annotation?.title, findings: group.claimed_findings?.length, services: group.annotation?.affected_services, severity: group.annotation?.severity_summary }, null, 2)}
`, { label: `verify-${group.group_id.split('/').pop()}`, phase: 'Investigate', model: 'opus', schema: INVESTIGATE_VERIFY_SCHEMA })
)

const verified = investigated.filter(Boolean)

// ═══════════════════════════════════════════════════════════════
// Phase 6: Route remaining
// ═══════════════════════════════════════════════════════════════
phase('Route')
const remaining = allGroups.slice(maxInvestigate)
let bulkRouted = []
if (remaining.length > 0) {
  log(`Bulk-routing ${remaining.length} remaining...`)
  const bulkResult = await agent(`
Classify these finding groups.

${RESOLUTION_GUIDE}

## Groups (${remaining.length})
${JSON.stringify(remaining.slice(0, 50).map(g => ({ id: g.group_id, title: g.annotation?.title, type: g.annotation?.canonical_type, findings: g.claimed_findings?.length, severity: g.annotation?.severity_summary })), null, 2)}
`, { label: 'bulk-route', phase: 'Route', model: 'haiku', schema: {
    type: 'object', properties: {
      routed: { type: 'array', items: { type: 'object', properties: {
        id: { type: 'string' }, resolution: { type: 'string', enum: ['eliminable', 'reducible', 'constrained', 'drift_prone', 'mitigated'] },
        action: { type: 'string' }, primary_audience: { type: 'string' },
      }, required: ['id', 'resolution', 'action'] }},
    }, required: ['routed'],
  }})
  bulkRouted = bulkResult?.routed || []
}

const allResolutions = [...verified, ...bulkRouted]
const resDist = {}
for (const r of allResolutions) resDist[r.resolution] = (resDist[r.resolution] || 0) + 1
log(`Resolutions: ${JSON.stringify(resDist)}`)

// Save to project
if (profileId) {
  await agent(`
Save results to project.
ToolSearch query="select:mcp__latent-defense__triage_save_project" max_results=2
Call triage_save_project("${profileId}", ${JSON.stringify({
    results: { total_findings: totalFindings, groups: allGroups.length, investigated: verified.length, resolutions: resDist },
    finding_groups: allResolutions.map(r => ({ id: r.id, resolution: r.resolution, action: r.action, evidence: r.evidence, status: 'pending', primary_audience: r.primary_audience })),
  })})
`, { label: 'save-results', phase: 'Route', model: 'haiku' })
}

// ═══════════════════════════════════════════════════════════════
// Phase 7: Deliver per audience
// ═══════════════════════════════════════════════════════════════
phase('Deliver')
log(`Generating outputs for ${audiences.length} audience(s)...`)

const byAudience = {}
for (const a of audiences) byAudience[a.name] = []
for (const r of allResolutions) {
  const target = r.primary_audience || audiences[0]?.name
  if (byAudience[target]) byAudience[target].push(r)
}

const outputs = await parallel(
  audiences.map(audience => () =>
    agent(`
Generate output for **${audience.name}**.

${audience.needs ? `What they need: ${audience.needs}` : ''}
${audience.report_outline ? `Approved outline:\n${audience.report_outline}\nFollow exactly.` : ''}
${audience.not_include ? `Do NOT include: ${audience.not_include}` : ''}

${REPORT_METHODOLOGY}

## Data
- ${totalFindings} findings → ${allGroups.length} groups
- Resolutions: ${JSON.stringify(resDist)}

## Items for this audience (${byAudience[audience.name]?.length || 0})
${JSON.stringify(byAudience[audience.name]?.slice(0, 30) || [], null, 2)}

## All investigated items
${JSON.stringify(verified.slice(0, 15), null, 2)}

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

return {
  status: 'completed',
  config: { sources: sources.map(s => s.name || s.type), audiences: audiences.map(a => a.name), branch_id: branchId },
  results: {
    total_findings: totalFindings,
    groups: allGroups.length,
    collapse_ratio: Math.round(10 * totalFindings / Math.max(1, allGroups.length)) / 10,
    investigated: verified.length,
    resolutions: resDist,
    coverage_pct: Math.round(100 * claimedGlobal.size / totalFindings),
    unclaimed: finalUnclaimed.length,
    double_claimed: doubleClaimed.length,
  },
  groups: allGroups.map(g => ({ group_id: g.group_id, title: g.annotation?.title, finding_count: g.claimed_findings?.length || 0, canonical_type: g.annotation?.canonical_type, energy: g.energy_analysis || null })),
  outputs: outputFiles,
  profile_id: profileId,
}
