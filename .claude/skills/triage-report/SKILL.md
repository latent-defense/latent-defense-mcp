---
name: triage-report
description: "Process a full scanner report — Trivy, Checkov, Semgrep, Bandit, or any JSON output. Maps every finding to the graph, tests chains with the world model, and produces a comprehensive triage table with resolution status for each finding."
user-invocable: true
disable-model-invocation: false
---

# Triage Report — Full Scanner Report Processing

You have a complete scanner report and an infrastructure graph. Your job is to process EVERY finding, cross-reference each against the world model, and produce a comprehensive triage table that maps scanner findings to model assessments with resolution status.

This is the heavy-duty workflow. It processes the full report, not just the top 5 findings.

## Scaling: use the workflow for large reports

For reports with 50+ findings, use the `triage-pipeline` workflow to fan out agents:

```
Workflow({
  name: "triage-pipeline",
  args: {
    branch_id: "branch_abc123",
    sources: [
      { path: "/path/to/trivy.json", type: "scanner", name: "trivy" },
      { path: "/path/to/semgrep.json", type: "scanner", name: "semgrep" }
    ],
    audiences: [{ name: "Engineering", needs: "actionable fixes" }]
  }
})
```

The workflow groups findings by remediation action, investigates each group using energy tools, and produces per-audience reports.

For smaller reports (under 50 findings), follow the manual phases below.

## Prerequisites

- The `latent-defense` MCP server must be connected
- An infrastructure graph must be loaded
- Scanner output files (JSON from Trivy, Checkov, Semgrep, Bandit, or a pre-processed summary)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

**Graph exploration**: `oracle_graph_info`, `oracle_search_nodes`, `oracle_get_node`, `oracle_list_nodes`
**World model**: `oracle_tm_clear`, `oracle_tm_add_node`, `oracle_tm_add_edge`, `oracle_tm_match`, `oracle_tm_match_refine`, `oracle_tm_list_templates`, `oracle_tm_load_template`
**Submission**: `oracle_submit_matched_path`, `oracle_submit_attack_path`

---

## Phase 1 — Ingest and map the full report

### 1a. Parse all findings

Read the scanner output. For each scanner, extract EVERY finding (not just critical/high):
- CVE ID or rule ID
- Affected package/resource + version
- Scanner severity
- Description

Count totals by scanner and severity. Report: "Loaded [N] findings: [breakdown by scanner and severity]."

### 1b. Map ALL unique packages/resources to graph nodes

For every unique package name, resource, or file path across all findings:

```
oracle_search_nodes("package or resource description", node_type="package", top_k=3)
```

Build the full map:
```
fastmcp → graph: fastmcp>=3.3.1 (package) [5 CVEs]
litellm → graph: litellm==1.83.10 (package) [3 CVEs]
Dockerfile → graph: app-container (container) [4 checks]
tools.py → graph: code-execution-service (service) [2 code findings]
authlib → NOT IN GRAPH [1 CVE]
pillow → graph: Pillow>=12.1.0 (package) [12 CVEs]
```

### 1c. Cluster by graph node

Group all findings by which graph node they map to:

```
CLUSTER: code-execution-service (8 findings)
  Trivy: CVE-2026-32871 (fastmcp), CVE-2026-49468 (litellm), CVE-2026-27962 (authlib)
  Bandit: B102 (exec), B307 (eval)
  Semgrep: sqlalchemy.text raw SQL
  Checkov: CKV_DOCKER_3 (root container)
  
CLUSTER: Pillow>=12.1.0 (12 findings)
  Trivy: 12 CVEs in image processing library

UNMAPPED: (N findings)
  Resources not found in the graph
```

### 1d. Map the attack surface

```
oracle_graph_info()
oracle_list_nodes(node_type="data_store", limit=20)
oracle_list_nodes(node_type="credential", limit=30)
oracle_list_nodes(node_type="s3_bucket", limit=20)
oracle_list_nodes(node_type="http_endpoint", limit=30)
oracle_list_nodes(node_type="security_boundary", limit=20)
```

## Phase 2 — Test chains with the world model

For each cluster with 2+ findings, build a threat model and test it.

### For each cluster:

**Step A**: Use `oracle_get_node` on the clustered node to understand its connections — entry points that reach it, targets it accesses, security boundaries that protect it.

**Step B**: Build a threat model chain: entry → cluster node → highest-value target

```
oracle_tm_clear()
oracle_tm_add_node(...)  // entry point
oracle_tm_add_node(...)  // cluster node (where findings converge)
oracle_tm_add_node(...)  // target
oracle_tm_add_edge(...)  // entry → cluster
oracle_tm_add_edge(...)  // cluster → target
oracle_tm_match(top_k=5)
```

If coverage >= 50%:
```
oracle_tm_match_refine(top_k=5, max_iterations=3)
```

**Step C**: Record the model's assessment for this cluster:
- Coverage (% nodes matched)
- Per-hop energy (accelerating/braking)
- Risk score (authoritative if available, pre-submission estimate otherwise — label which)
- Security boundaries detected and their gaps

### Also run the template sweep

```
oracle_tm_list_templates()
```

For each template relevant to this infrastructure's tech stack:
```
oracle_tm_load_template(name)
oracle_tm_match(top_k=5)
// Record: did it match? What path? Any findings in this path?
oracle_tm_clear()
```

Templates that match but have NO corresponding scanner findings = **scanner blind spots**.

## Phase 3 — Classify every finding

For each finding, assign a resolution based on the model's signal:

### Resolution categories

**FIX REQUIRED** — The finding participates in a chain the model scored with mostly accelerating energy. The version is vulnerable and the feature is used. Highest priority.

**UPDATE RECOMMENDED** — The version is vulnerable but the model shows compensating controls (braking energy). The chain exists but has resistance. The primary action is upgrading the vulnerable dependency. Use this when the finding is a version-level vulnerability (CVE) and the fix is a package upgrade.

**FALSE POSITIVE** — The model couldn't find a viable chain (low coverage), OR the version is patched, OR the vulnerable feature isn't used. No action needed.

**COMPENSATED** — The finding is real but compensating controls reduce the blast radius. The primary action is strengthening existing controls rather than patching the finding itself. Use this when the finding is architectural/configuration (not a simple version upgrade) and the fix is to close gaps in existing security boundaries.

**ISOLATED** — The finding is real at the code level but the model found no path to any high-value target. Defense-in-depth fix, not urgent.

**SCANNER BLIND SPOT** — The model found a chain that NO scanner flagged. This is net-new signal. Highest investigation priority.

**CANNOT ASSESS** — The resource isn't in the graph, or version/usage information is missing. Flag for manual review.

### Version and feature checks

For every CVE:
1. Read the graph node description for the pinned version
2. Compare against the CVE's affected version range
3. Check if the vulnerable feature/code path is mentioned in the description
4. If the version is patched → FALSE POSITIVE (regardless of CVSS)
5. If the feature isn't used → FALSE POSITIVE (regardless of CVSS)

## Phase 4 — Produce the triage table

Output a comprehensive table covering EVERY finding. Group by resolution category, sorted by model signal within each group.

```
## Triage Results: [N] findings → [breakdown by resolution]

### FIX REQUIRED ([N])

| Finding | Scanner | CVSS | Resource | Graph Node | Chain | Risk Score | Action |
|---------|---------|------|----------|------------|-------|------------|--------|
| CVE-X   | Trivy   | 9.8  | pkg@ver  | node-name  | entry → vuln → target | 45/100 | Upgrade pkg to >= X.Y |

### SCANNER BLIND SPOTS ([N])

| Chain | Template | Coverage | Risk Score | Affected Components | Action |
|-------|----------|----------|------------|-------------------|--------|
| lifecycle hook → creds | custom | 85% | 42/100 | post_deploy_hook | Restrict shell execution |

### UPDATE RECOMMENDED ([N])

| Finding | Scanner | CVSS | Resource | Compensating Control | Control Gap | Action |
|---------|---------|------|----------|---------------------|-------------|--------|

### COMPENSATED ([N])

| Finding | Scanner | Resource | Control | Gap | Action |
|---------|---------|----------|---------|-----|--------|

### FALSE POSITIVE ([N])

| Finding | Scanner | CVSS | Reason |
|---------|---------|------|--------|
| CVE-X   | Trivy   | 10.0 | Version patched (>=3.2.0, fix at 3.2.0) |
| CVE-Y   | Trivy   | 9.8  | Vulnerable feature (proxy server) not deployed |

### ISOLATED ([N])

| Finding | Scanner | Resource | Reason |
|---------|---------|----------|--------|
| CVE-X   | Trivy   | Pillow   | No path from attacker input to image processing |

### CANNOT ASSESS ([N])

| Finding | Scanner | Resource | Missing |
|---------|---------|----------|---------|
| CVE-X   | Trivy   | authlib  | Not in graph; transitive dep; usage unknown |
```

### Summary statistics

```
Total findings: [N]
  Fix required:        [N] ([%])
  Scanner blind spots: [N] ([%])
  Update recommended:  [N] ([%])
  Compensated:         [N] ([%])
  False positive:      [N] ([%])
  Isolated:            [N] ([%])
  Cannot assess:       [N] ([%])

World model chains tested: [N]
Security boundaries detected: [N]
Highest risk score: [X]/100 (path: [description])
```

## After the report

Point to related skills:
- "Want to investigate any specific finding deeper? Run `/investigate` with the CVE or finding ID."
- "Want to explore the graph around a cluster? Run `/explore`."
- "Want to submit the FIX REQUIRED paths to triage? I can do that now."
- "Want to set up continuous scanning? Run `/monitor`."

---

## Key rules

1. **Process the FULL report.** Don't stop at 5 or 10 findings. Map every unique package/resource to the graph, cluster, then focus modeling effort on the clusters.

2. **Use the world model for every cluster.** Run tm_match or tm_match_refine for each cluster with 2+ findings. The model's signal is what differentiates this from just reading the scanner output.

3. **Use the model for false positives too.** Low coverage = the chain doesn't exist. High braking energy = compensating controls. These are model-based assessments, not just version checks.

4. **Run the template sweep.** Templates can find paths no scanner flagged — these are the highest-value findings.

5. **Check versions before classifying.** A patched version = false positive regardless of CVSS score.

6. **Every finding gets a row.** The output should account for every scanner finding — nothing is silently dropped.

7. **Risk scores have absolute meaning.** Under 20 = well defended, not a finding. 20-40 = moderate, investigate controls. Over 40 = real signal, deserves attention. Over 60 = high priority. If all paths score under 20, report "infrastructure is well defended" and pivot to other investigation areas rather than treating low-score paths as findings.
