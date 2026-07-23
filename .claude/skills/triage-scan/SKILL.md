---
name: triage-scan
description: "Cross-reference scanner findings against the infrastructure graph using the JEPA world model. Groups findings by attack surface, builds abstract kill chains as threat models, matches them against the real graph to get energy scores, and ranks what matters."
user-invocable: true
disable-model-invocation: false
---

# Triage Scan — Scanner × World Model

You have scanner output (CVEs, misconfigs, code findings) and an infrastructure graph with a learned energy model (JEPA). Your job is to use the world model to discover which scanner findings chain into real attack paths.

**Scanners find points. The world model finds paths.** A CVE in isolation has a CVSS score. In context, it might be step 2 of a 4-step chain from the internet to a production database — or it might go nowhere because the version is patched. The world model tells you which.

## How the world model works

The world model is the JEPA (Joint Embedding Predictive Architecture) energy-based model. It learned the structure of infrastructure by encoding the graph — every node, every edge, every relationship. You access it through **threat model matching**:

1. You describe an abstract attack chain as a threat model (nodes + edges)
2. The model searches the real graph for components that match your description
3. For each match, it scores the energy — how much resistance the infrastructure presents to an attacker at each hop
4. The match also shows which parts of your hypothetical chain actually exist in the graph and which don't

**Energy** represents structural resistance:
- **Negative energy (accelerating)**: the infrastructure offers low resistance — an attacker traversing this edge has a clear path forward
- **Positive energy (braking)**: the infrastructure resists — a compensating control, structural barrier, or dead end makes this hop harder
- **The magnitude matters**: -3.0 is much less resistance than -0.5. +4.0 is a strong barrier.
- **Implicit/inferred edges** have much higher energy magnitudes than explicit edges — do NOT compare them on the same scale

**You MUST use `oracle_tm_match` and `oracle_tm_match_refine` to get energy scores.** Graph node lookups (`oracle_get_node`, `oracle_search_nodes`) give you structural information but NOT the model's energy signal. Both are necessary — node lookups for evidence gathering, threat model matching for the model's assessment.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must be loaded (run `/map` first if needed)
- Scanner output files (Trivy, Checkov, Semgrep, Bandit JSON) or a summary of findings

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

### Graph exploration
| Tool | Purpose |
|------|---------|
| `oracle_graph_info()` | Node/edge counts, type distribution, available edge types |
| `oracle_search_nodes(node_description, node_type, top_k)` | Find nodes by semantic description |
| `oracle_get_node(query)` | Full node detail with neighbors and edge types |
| `oracle_list_nodes(node_type, limit)` | Browse all nodes of a type |

### World model — threat model matching
| Tool | Purpose |
|------|---------|
| `oracle_tm_clear()` | Reset the threat model (always do this before building a new one) |
| `oracle_tm_add_node(name, description, node_type)` | Add a node to your hypothetical attack chain |
| `oracle_tm_add_edge(source, target, edge_type, description)` | Add an edge describing how an attacker moves between nodes |
| `oracle_tm_show()` | View your current threat model |
| `oracle_tm_match(top_k)` | Match your chain against the real graph — returns coverage + Mermaid diagram |
| `oracle_tm_match_refine(top_k, max_iterations)` | Iterative refinement — returns per-hop energy scores, entry candidates, risk score |
| `oracle_submit_matched_path(description)` | Submit a scored path to the triage queue |

### Key constraints for threat model building
- **Node types must be valid.** Use `oracle_graph_info()` to see available types. Common ones: `http_endpoint`, `service`, `package`, `credential`, `data_store`, `s3_bucket`, `container`, `security_boundary`, `function`, `cloud_resource`
- **Edge types must be valid.** Available: `calls`, `invokes`, `data_flows_to`, `reads_from`, `writes_to`, `contains`, `depends_on`, `uses`, `accesses`, `authenticates_with`, `connected_to`, `hosts`, `imports`, `links_to`, `member_of`
- **Descriptions should be specific to what you found in the graph.** Use `oracle_search_nodes` or `oracle_get_node` first to see how real nodes are described, then write similar descriptions for your threat model nodes. The model matches by semantic similarity — vague descriptions produce poor matches.

---

## Phase 1 — Map ALL findings to the graph and cluster

Don't cherry-pick 5 findings. Map EVERY critical and high finding to the graph, then let the convergence tell you where to focus.

### 1a. Parse scanner output

Read the scanner JSON. Extract ALL critical and high findings. For Trivy, that's every CVE. For Semgrep/Bandit, every HIGH+ rule hit. Note the package name or resource for each.

### 1b. Map ALL findings to graph nodes

For each unique package/resource across all scanner findings, search the graph:

```
oracle_search_nodes("fastmcp MCP framework", node_type="package", top_k=3)
oracle_search_nodes("litellm LLM routing", node_type="package", top_k=3)
oracle_search_nodes("code execution server", node_type="service", top_k=3)
// ... continue for every affected package/resource
```

Build a complete mapping: `graph_node → [all scanner findings that affect it]`

### 1c. Cluster by convergence

Group the mapped findings by which graph nodes they converge on. The clusters with the MOST findings are your investigation targets — multiple vulnerabilities hitting the same service create compound risk.

```
CLUSTER A: mercor-rls-code-execution (6 findings)
  - CVE-2026-32871 (fastmcp SSRF, CVSS 10.0)
  - CVE-2026-49468 (litellm auth bypass, CVSS 9.8)
  - B102 (exec/eval)
  - 3 more HIGH CVEs in transitive deps

CLUSTER B: archipelago-environment-container (4 findings)
  - CKV_DOCKER_3 (root container)
  - CKV_DOCKER_2 (no healthcheck)
  - 2 Semgrep findings

CLUSTER C: isolated findings (no convergence)
  - CVE in package with no graph edges → isolated, low priority
```

### 1d. Map the graph's attack surface

```
oracle_graph_info()  // understand the full graph
oracle_list_nodes(node_type="data_store", limit=20)
oracle_list_nodes(node_type="credential", limit=20)
oracle_list_nodes(node_type="s3_bucket", limit=20)
oracle_list_nodes(node_type="security_boundary", limit=20)
oracle_list_nodes(node_type="http_endpoint", limit=20)
```

Note all high-value targets (data stores, credentials, S3) and all entry points (HTTP endpoints). You'll connect these through the clusters in Phase 2.

### 1e. Report to user

"I mapped [N] scanner findings to [M] graph nodes. The heaviest clusters are [top 3 with counts]. The graph has [X] high-value targets and [Y] entry points. Now I'll use the world model to test which clusters actually chain to targets."

---

## Phase 2 — Build abstract kill chains and match against the graph

This is the core workflow. For each interesting cluster, you:
1. Describe an abstract attack chain as a threat model
2. Match it against the real graph
3. Get energy scores from the JEPA model

### How to build a threat model from scanner findings

**The threat model is an ABSTRACT kill chain — it describes what WOULD happen if the vulnerabilities were exploitable.** The model then tells you if the chain exists in the real graph and how much resistance each hop presents.

**Example**: Scanner found exec() in a code execution service that accesses a database. The abstract chain is:

```
oracle_tm_clear()

# Step 1: Entry — how does an attacker reach this service?
oracle_tm_add_node(
  name="gateway",
  description="HTTP gateway endpoint that routes requests to backend MCP services",
  node_type="http_endpoint"
)

# Step 2: Vulnerable service — where the scanner findings cluster
oracle_tm_add_node(
  name="code-exec-service",
  description="MCP server for code execution with Python eval and database access",
  node_type="service"
)

# Step 3: Target — what the attacker reaches through the chain
oracle_tm_add_node(
  name="app-database",
  description="PostgreSQL database storing application state and business data",
  node_type="data_store"
)

# Edges — how the chain connects
oracle_tm_add_edge(
  source="gateway",
  target="code-exec-service",
  edge_type="calls",
  description="Gateway routes HTTP requests to code execution MCP server"
)
oracle_tm_add_edge(
  source="code-exec-service",
  target="app-database",
  edge_type="accesses",
  description="Code execution service connects to PostgreSQL for state persistence"
)
```

**Tips for good threat model descriptions:**
- Use `oracle_get_node` first to see how real nodes are described in the graph
- Mirror that language in your threat model node descriptions — the model matches by semantic similarity
- Be specific: "PostgreSQL database storing application state" matches better than "database"
- Include the technology stack: "FastAPI uvicorn HTTP gateway" matches better than "web server"

### Run the match

```
oracle_tm_match(top_k=5)
```

**How to read the output:**

The output is a Mermaid diagram showing:
- **Dotted arrows (-.->)** with scores: node matches. Your abstract node matched a real graph node. Higher score = better match. CHECK that the matched node has the right type — text similarity can cross types.
- **Solid arrows (-->)**: Confirmed paths between matched nodes. These are REAL graph edges with difficulty scores. **This is the strongest signal.**
- **Dashed orange arrows**: Inferred connections — the model predicts a relationship but it's not a confirmed graph edge. Treat as hypotheses.
- **Coverage line**: `nodes: N/M matched | edges: X/Y hit` — how much of your chain exists in the real graph.

**If coverage is low** (< 50% nodes matched): the chain probably doesn't exist as you described it. Try a different chain or adjust your node descriptions.

**If coverage is high** (>= 70% nodes matched): proceed to refinement.

### Refine and get energy scores

```
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

**How to read the refinement output:**

The output shows:
1. **Entry candidates** — nodes the model thinks are viable entry points, with energy and classifier scores
   - `energy: -0.77` = low resistance entry point (exposed)
   - `energy: 0.44` = some resistance (less exposed)
   - `classifier: 0.46` = model's confidence this is an entry point (higher = more likely)

2. **Per-hop energy breakdown** — for the best candidate path:
   ```
   | # | hop | energy | effect |
   | 1 | gateway → service | -0.72 | accelerate |   ← low resistance
   | 2 | service → credential | 4.61 | brake |      ← high resistance (compensating control?)
   | 3 | credential → secret | -2.72 | accelerate |  ← low resistance
   ```

3. **Estimated risk score (momentum)** — the model's integrated assessment. Higher = more concerning.

4. **Accelerate vs brake ratio** — how many hops have negative (accelerating) vs positive (braking) energy. A path where most hops accelerate has low overall resistance.

**What the energy tells you:**
- A **braking hop with high energy (e.g., +4.61)** often means the model detected a structural barrier — a security boundary, auth check, or network segmentation. Use `oracle_get_node` on both endpoints to find the specific control.
- An **accelerating hop with low energy (e.g., -2.97)** means the infrastructure has almost no resistance at this step — a direct, unprotected connection.
- An **implicit/inferred hop** (marked in the diagram) has inflated energy — don't compare its magnitude to explicit hops. It means the model thinks a connection MIGHT exist but the graph doesn't confirm it.

### Build multiple chains

Don't stop at one threat model. For each cluster, try 2-3 different chains:
- Different entry points (HTTP endpoint vs CI/CD vs dependency)
- Different targets (database vs S3 vs credentials)
- Different paths through the graph

Clear and rebuild between each:
```
oracle_tm_clear()
// ... build next chain ...
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

---

## Phase 3 — Use the model to identify false positives

**The model finds false positives too, not just real chains.** Don't switch to reading source code for false positive analysis — use the model's signal.

### Model-based false positive detection

For each cluster, the tm_match/tm_match_refine results already tell you:

**Low coverage (< 50% nodes matched)**: The chain you described doesn't exist in the graph as mapped. The model can't find the components. This is a false positive signal — the scanner flagged a package but the infrastructure doesn't have the path from that package to anything valuable.

**Mostly braking energy (positive, most hops resisting)**: The chain exists structurally but has strong resistance. Compensating controls are blocking the path. This is a compensated signal — investigate the specific controls.

**The model can't find a path from entry → CVE-affected node → target**: Even if the CVE is real, if the model can't connect it to a target, the finding is isolated. Report it as "real vulnerability, no attack chain."

### Version and feature verification (use the graph first)

Check the graph node descriptions BEFORE reading source code:
- Node descriptions often contain exact pinned versions → compare against CVE range
- Node descriptions often reveal usage patterns → "uses FastMCP as proxy gateway" tells you OpenAPI Provider isn't used
- If the graph doesn't have version/usage info, THEN read source code as a fallback

### Classify using the model's signal

- **Real chain**: model shows high coverage, mostly accelerating energy, risk score ranks near the top among all chains found → submit with `oracle_submit_matched_path()`
- **False positive via model**: model shows low coverage or can't find a path. Back up with version/feature evidence from graph node descriptions.
- **Compensated**: model shows the chain exists but braking energy on key hops → identify the controls creating resistance, report their gaps
- **Isolated**: CVE is real but model finds no chain to targets → "real vulnerability, no attack chain in current graph"
- **Well-defended**: the chain exists structurally but the risk score is very low (under 20/100) → the model sees strong resistance. **Do NOT submit low-scoring paths as findings.** Instead, report the compensating controls the model detected and note that the infrastructure is structurally defensive here. Submitting many low-score paths floods the triage queue with noise.

### When to submit vs when to report

- **Submit** paths scoring above 20/100 with mostly accelerating energy. These present real structural risk worth human triage.
- **Report but don't submit** paths where the model sees resistance. These demonstrate the value of the world model — it found the controls — but they don't need triage action.
- **If ALL paths score under 20/100**: that's a positive finding. Report: "The world model tested N chains across M clusters. All scored under 20/100 — the infrastructure has strong structural resistance. Key controls: [list the security boundaries detected]." This is more useful than submitting 8 low-priority paths.

### Risk score interpretation

**Risk scores are 0–100 (momentum model).** They integrate the per-hop energy along the path into a single number. Higher = more concerning. The bands have absolute meaning:

- **0–20**: The model sees strong resistance along this path. Most hops are braking. The infrastructure is structurally defensive here.
- **20–40**: Moderate resistance. Some hops accelerate but others brake. Mixed signal — investigate what's braking and whether those controls have gaps.
- **40–60**: Low resistance on much of the path. Multiple accelerating hops. This path deserves attention.
- **60–80**: The path has little structural resistance. Most hops accelerate. High priority to investigate.
- **80–100**: Almost no resistance. The infrastructure accelerates the attacker across nearly every hop.

**These bands are empirical observations, not fixed rules.** A 34 in a graph where every other path scores under 15 is the most concerning path in that environment. Always rank relative to other paths found in the same graph.

- Report the score, the band, AND how it ranks against other paths found.
- If the highest score across all chains is low (e.g., all < 25), that's a positive finding: "the model sees structural resistance on every path we tested."
- **NEVER map risk scores to scanner severity labels (critical/high/medium).** They measure different things — CVSS measures theoretical impact, risk score measures structural resistance in THIS specific infrastructure.

## Phase 4 — Systemic template sweep (scanner blind spots)

After analyzing the scanner findings, use the model to find what the scanners MISSED entirely.

### Load and match existing templates

```
oracle_tm_list_templates()  // see all available templates
```

For each relevant template (match the technology stack — if the repo has K8s, try K8s templates; if it has CI/CD, try supply chain templates):

```
oracle_tm_load_template(name)
oracle_tm_match(top_k=5)
// note the results — did this template match? What path did it find?
oracle_tm_clear()
```

### Correlate with scanner findings

For each path the templates found:
- Does ANY scanner finding correspond to a node in this path?
- If YES → the scanner found part of it, but the model found the chain
- If NO → **this is a scanner blind spot.** The model found a viable path that no scanner flagged.

Report blind spots separately: "The world model found [N] paths that no scanner flagged. These are structural risks — not CVEs, but architectural patterns that create attack chains."

---

## Phase 5 — Present results

### Lead with the inversions

The most valuable results are where the scanner and model disagree:
1. **Scanner critical → model false positive**: CVSS 10 CVE where the version is patched or feature unused. The model shows no viable chain.
2. **Scanner medium → model critical chain**: a buried code finding that chains to production data through the graph. The model scores it with accelerating energy.
3. **Scanner fix X → model fix Y**: the scanner suggests patching a package, but the model shows the real fix is closing a network gap in a compensating control.

### Report format

For each cluster:

```
## [CHAIN / FALSE POSITIVE / COMPENSATED / ISOLATED]

**Cluster**: [N findings on node X — list the CVEs/rules]
**Scanner priority**: [highest CVSS in cluster]

### World model assessment

Threat model: [describe the abstract chain you tested]
Match coverage: [N/M nodes matched]
Path energy: [per-hop breakdown with accelerate/brake labels]
Risk score: [momentum score if available]
Entry point: [which node, energy, classifier score]

### Verification

- [CVE-1]: version [X] vs affected range [<Y] → [patched/vulnerable]
- [CVE-1]: feature [Z] → [used/not used — evidence from graph node description]
- [Code finding]: [what it does, what it chains to]
- Compensating controls: [what exists, what gaps remain]

### Verdict

[Why this classification. What should actually be done.]
```

### Summary table

Show three sections:

**1. Scanner findings the model reclassified**
```
| Finding | Scanner severity | Model assessment | Evidence |
|---------|-----------------|-----------------|----------|
| CVE-X (pkg) | CRITICAL (10.0) | False positive | No path to targets; version patched |
| B102 (exec) | MEDIUM | Highest-risk chain | Chains to PostgreSQL; risk score [X] (rank 1/N) |
```

**2. Scanner blind spots (template sweep)**
```
| Template | Path found | Scanner coverage | Gap |
|----------|-----------|-----------------|-----|
| supply-chain-X | CI → registry → deploy | None | No scanner flagged this pattern |
```

**3. Systemic posture assessment**
- Total chains found: N (with risk score range)
- Chains with mostly accelerating energy: N (low overall resistance)
- Chains with mostly braking energy: N (good structural controls)
- High-value targets reachable from entry points: N of M
- Security boundaries detected: N (list them)

---

## Critical rules

1. **You MUST run `oracle_tm_match` or `oracle_tm_match_refine` for every cluster.** This is non-negotiable. Graph node lookups are evidence gathering. Threat model matching is using the world model. Both are required.

2. **Map ALL findings to the graph, not just 5.** The value is in convergence — 30 CVEs hitting the same service matters more than 1 CVSS-10 CVE in isolation. The clustering step is cheap; the threat model matching is where you focus.

3. **Use the model for false positives too.** If you build a chain from a CVE to a target and the model shows low coverage or high braking energy, that IS the false positive signal. Don't switch to reading source code for false positives — the model's inability to find a chain is evidence.

4. **Run the template sweep.** After analyzing scanner findings, load relevant templates and match them to find what scanners missed entirely. This is the systemic capability.

5. **Risk scores have absolute meaning.** Under 20 = well defended, not a finding. 20-40 = moderate, investigate controls. Over 40 = real signal. Over 60 = high priority. If all paths score under 20, report "infrastructure is well defended" and pivot. Don't declare a 7/100 path as "critical."

6. **Chain findings, don't isolate them.** Three medium-severity findings that chain through the same service to a database are more important than one critical CVE that goes nowhere.

7. **Verify versions and feature usage from graph node descriptions first.** Only read source code if the graph doesn't have the version or usage info you need.

8. **Report braking hops as evidence of controls.** When the model shows positive energy on a hop, find the specific control with `oracle_get_node`. Report the control AND its documented limitations.

9. **Lead with the inversion.** Start with the finding where the scanner and model disagree most dramatically.

10. **Report what the model said, separately from what you think.** "The model scored this hop at energy -2.7 (accelerating)" is the model. "This suggests low resistance" is your interpretation. Label them.
