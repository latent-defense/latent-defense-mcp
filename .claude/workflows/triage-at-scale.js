export const meta = {
  name: 'triage-at-scale',
  description: 'Fan out agents to triage scanner findings at scale against the world model. Each agent loads the world-model-guide for correct interpretation.',
  whenToUse: 'When the user has a large scanner report (100+ findings) and wants comprehensive triage using the world model. Invoked by /triage-report when the finding count is high.',
  phases: [
    { title: 'Parse', detail: 'Parse scanner output and cluster findings by graph node' },
    { title: 'Triage', detail: 'Fan out agents to investigate each cluster with the world model' },
    { title: 'Synthesize', detail: 'Merge results into a single prioritized triage table' },
  ],
}

const WORLD_MODEL_GUIDE_PATH = '/Users/francisbeckert/latent-defense/mcp-server/.claude/skills/world-model-guide/SKILL.md'

const TRIAGE_RESULT_SCHEMA = {
  type: 'object',
  properties: {
    cluster_name: { type: 'string' },
    findings_count: { type: 'integer' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          scanner: { type: 'string' },
          severity: { type: 'string' },
          resource: { type: 'string' },
          resolution: { type: 'string', enum: ['fix_required', 'update_recommended', 'false_positive', 'compensated', 'isolated', 'scanner_blind_spot', 'cannot_assess'] },
          reason: { type: 'string' },
          risk_score: { type: ['number', 'null'] },
          action: { type: 'string' },
        },
        required: ['id', 'scanner', 'severity', 'resolution', 'reason'],
      },
    },
    chain_tested: { type: 'string' },
    coverage_pct: { type: ['number', 'null'] },
    risk_score: { type: ['number', 'null'] },
    energy_summary: { type: 'string' },
    compensating_controls: { type: 'array', items: { type: 'string' } },
    key_insight: { type: 'string' },
  },
  required: ['cluster_name', 'findings_count', 'findings', 'chain_tested', 'key_insight'],
}

// Phase 1: Parse scanner output and build clusters
phase('Parse')

const parseResult = await agent(`
You are parsing scanner output to build finding clusters for triage.

Read the scanner summary file at: ${args.summary_path}
${args.scanner_paths ? `Full scanner JSON files are at: ${JSON.stringify(args.scanner_paths)}` : ''}

Your job:
1. Parse ALL critical and high findings from every scanner
2. For each finding, note: scanner, severity, CVE/rule ID, affected package/resource, version
3. Group findings that affect the SAME package or resource into clusters
4. Identify the graph branch to use: ${args.branch_id}

Return a JSON object with:
- total_findings: number
- clusters: array of {name, findings_count, findings: [{id, scanner, severity, resource, version}], graph_search_terms: [descriptions to search for in the graph]}
- branch_id: the branch to load

Focus on clusters with 2+ findings. Put single findings in a "singles" cluster.
`, { label: 'parse-scanner', phase: 'Parse', schema: {
  type: 'object',
  properties: {
    total_findings: { type: 'integer' },
    branch_id: { type: 'string' },
    clusters: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          name: { type: 'string' },
          findings_count: { type: 'integer' },
          findings: { type: 'array', items: { type: 'object' } },
          graph_search_terms: { type: 'array', items: { type: 'string' } },
        },
        required: ['name', 'findings_count', 'findings', 'graph_search_terms'],
      },
    },
  },
  required: ['total_findings', 'branch_id', 'clusters'],
}})

if (!parseResult || !parseResult.clusters) {
  log('Failed to parse scanner output')
  return { error: 'parse_failed' }
}

log(`Parsed ${parseResult.total_findings} findings into ${parseResult.clusters.length} clusters`)

// Phase 2: Fan out agents to investigate each cluster
phase('Triage')

const clusters = parseResult.clusters.filter(c => c.findings_count >= 2)
const singles = parseResult.clusters.filter(c => c.findings_count < 2)

log(`Investigating ${clusters.length} clusters (${singles.length} single findings set aside)`)

const clusterResults = await pipeline(
  clusters,
  (cluster) => agent(`
You are investigating a cluster of scanner findings against the infrastructure world model.

FIRST: Read the world model guide at ${WORLD_MODEL_GUIDE_PATH} — it tells you how to interpret energy scores, build threat models, and use the tools correctly. Follow it exactly.

CLUSTER: ${cluster.name}
FINDINGS (${cluster.findings_count}):
${JSON.stringify(cluster.findings, null, 2)}

GRAPH SEARCH TERMS: ${JSON.stringify(cluster.graph_search_terms)}
BRANCH: ${parseResult.branch_id}

YOUR JOB:
1. Load the graph: oracle_load_branch("${parseResult.branch_id}"), then oracle_wait_for_load()
2. Search the graph for nodes matching this cluster: use oracle_search_nodes with the search terms above
3. If found: trace edges with oracle_get_node to understand what the cluster connects to (data stores, credentials, entry points)
4. Build a threat model chain: entry → cluster node → target. Use oracle_tm_clear, oracle_tm_add_node, oracle_tm_add_edge
5. Match with the world model: oracle_tm_match(top_k=5), then oracle_tm_match_refine(top_k=5, max_iterations=3)
6. Read the energy scores and risk score
7. For CVEs: check version in the graph node description against the CVE affected range
8. Classify each finding: fix_required / false_positive / compensated / isolated / cannot_assess

CRITICAL RULES FROM THE GUIDE:
- Risk scores 0-100: under 20 = well defended (NOT a finding). Over 40 = real signal.
- You MUST run oracle_tm_match or oracle_tm_match_refine — node lookups alone are not using the model
- Braking energy = compensating control detected — find the specific control
- Never call a sub-20 risk score "critical"
- Check CVE versions and feature usage before declaring anything exploitable

Return your assessment as structured output.
`, { label: `triage:${cluster.name}`, phase: 'Triage', schema: TRIAGE_RESULT_SCHEMA })
)

// Phase 3: Synthesize results
phase('Synthesize')

const validResults = clusterResults.filter(Boolean)

// Handle singles as a batch
let singlesResult = null
if (singles.length > 0) {
  singlesResult = await agent(`
You are triaging ${singles.length} individual scanner findings that didn't cluster with other findings.

For each finding, search the graph (branch: ${parseResult.branch_id}) for the affected resource.
If found, check version and trace connections. If not found, mark as "cannot_assess".
These are low-priority since they don't converge with other findings.

FINDINGS:
${JSON.stringify(singles.flatMap(s => s.findings), null, 2)}

Read ${WORLD_MODEL_GUIDE_PATH} for interpretation guidance.
Return structured results.
`, { label: 'triage:singles', phase: 'Synthesize', schema: TRIAGE_RESULT_SCHEMA })
}

const allResults = [...validResults, singlesResult].filter(Boolean)

const synthesis = await agent(`
You are synthesizing triage results from ${allResults.length} investigation agents into a final report.

RESULTS:
${JSON.stringify(allResults, null, 2)}

TOTAL FINDINGS: ${parseResult.total_findings}

Your job:
1. Merge all cluster results into a single prioritized table
2. Sort by resolution: fix_required first, then scanner_blind_spot, update_recommended, compensated, isolated, false_positive, cannot_assess
3. Within each category, sort by risk_score descending
4. Produce summary statistics: how many in each category
5. Highlight the most important insight (e.g., "3 CVSS-10 CVEs are false positives" or "infrastructure is well defended, all paths under 20/100")

Format the output as a comprehensive triage report.
`, { label: 'synthesize', phase: 'Synthesize' })

return {
  total_findings: parseResult.total_findings,
  clusters_investigated: clusters.length,
  singles_checked: singles.length,
  results: allResults,
  synthesis: synthesis,
}
