---
name: find-and-validate
description: "End-to-end security investigation — map a target, discover attack paths via JEPA, source-validate findings, adversarially review, and produce an advisory-ready report."
user-invocable: true
disable-model-invocation: false
---

# Find and Validate — Discovery-to-Advisory Pipeline

You are running an end-to-end security investigation against a target. The pipeline discovers attack paths through infrastructure graph analysis, validates them against actual source code, adversarially reviews the findings, and produces a submission-ready advisory.

## Prerequisites

- The `latent-defense` MCP server must be connected
- `gh` CLI must be authenticated (for source-code validation of public repos)
- Use ToolSearch to load MCP tool schemas before calling them

## Critical Lessons (from real investigations)

These are hard-won rules. Violating them produces overstated findings that don't survive review.

### Trust the JEPA risk scores

- **0.0 risk = the model doesn't believe this path is realistic.** Do not submit it. Use it as signal to refine your threat model or try different entry points.
- **Risk > 25 = worth investigating.** Run source-code validation.
- **Risk > 65 = strong signal.** Prioritize these paths.
- **Risk 100 / easy = the model sees genuinely low energy barriers.** These are your best candidates.
- If the JEPA scores your threat model chain at 0.0 but the validator marks it "exploitable," trust the JEPA — the validator can sometimes produce false positives due to identity conflation in complex environments.

### Distinguish service account identities

The most common overestimation error: conflating different Kubernetes service accounts that happen to exist in the same namespace. Before claiming "compromising pod X grants ClusterRole Y," verify:
1. Which SA does pod X actually run as?
2. What permissions does THAT specific SA have (not the controller's SA, not the namespace default)?
3. Is the claimed SA token actually mounted in this pod?

### Don't force chains — let the JEPA guide

Building threat models from pre-conceived attack narratives and then matching them produces low-risk-score paths that waste validation time. Instead:
1. Search the graph for what the JEPA thinks is easy to reach
2. Look for low-energy edges — these are genuine smooth traversals
3. Build threat models that follow the energy gradients, not against them

### Validate entry points honestly

Every chain needs an external entry point. If your chain starts at "argocd-server" (assuming prior compromise), the risk score will be low because you skipped the hardest part. Ask: how does an attacker actually get here from outside the perimeter?

### Patched != non-existent

A patched CVE still matters if:
- The fix is recent and unpatched deployments exist in the wild
- The chain architecture is sound (the downstream path from the patched entry point is real)
- But be honest about this in the advisory — specify affected versions

---

## Pipeline

### Phase 1: Reconnaissance

**Goal:** Understand the target and scope the investigation.

1. **Enumerate the target** — repos, org structure, security policies, VDP/bounty terms
2. **Check for existing advisories** — `gh api repos/{owner}/{repo}/security-advisories?state=published`
3. **Check CVE databases** — `gh api graphql` against the advisory database
4. **Identify CI/CD posture** — workflow files, action pinning, Dependabot config, branch protection
5. **Check VDP terms before proceeding** — responsible disclosure channels, bounty programs, scope

### Phase 2: Infrastructure Mapping

**Goal:** Build the graph.

```
trigger_scan(description, repositories=[...])  → dispatches mapper
get_mapping_run(run_id)                        → poll until complete
list_repositories()                            → find the new repo
list_branches(repo_id)                         → get branch_id
```

While the scan runs, gather GitHub-level intelligence (security policies, CI configs, CODEOWNERS, branch protection). This doesn't require the graph.

### Phase 3: JEPA-Guided Discovery

**Goal:** Find attack paths the energy model believes are genuinely traversable.

1. **Load the graph into the oracle**
   ```
   oracle_load_branch(branch_id)
   oracle_wait_for_load()
   oracle_graph_info()
   ```

2. **Ask the JEPA what it sees** — don't build threat models yet. First understand the energy landscape:
   - Search for entry points: `oracle_search_nodes("externally accessible entry point", node_type="http_endpoint")`
   - Search for high-value targets: `oracle_search_nodes("signing keys, admin credentials, cluster-admin", node_type="credential")`
   - Search for CI/CD surfaces: `oracle_search_nodes("GitHub Actions workflow with release signing keys")`
   - Use `oracle_get_node()` to inspect neighbors and find low-energy edges

3. **Build threat models that follow the energy gradient**
   - Start from nodes the JEPA identifies as entry points
   - Route through edges with low energy (E < -2.0)
   - End at high-value targets
   - `oracle_tm_match_refine(top_k=10, max_iterations=3)` — read the per-step energy scores

4. **Filter by risk score before submitting**
   - Only submit paths with risk_score > 25
   - If a path scores 0.0, refine the threat model or try different entry/target nodes
   - Do NOT submit 0.0-risk paths to validation — it wastes sandbox time

5. **Try orthogonal angles** — if your first threat models converge on one attack surface, deliberately explore different domains:
   - If K8s runtime paths score low, try CI/CD supply chain
   - If CI/CD scores low, try cross-project dependency chains
   - If direct paths score low, try multi-hop via shared credentials or shared libraries
   - Check for deployment-specific misconfigurations (anonymous access, demo apps on production clusters, hardcoded secrets)

### Phase 4: Source-Code Validation

**Goal:** Verify each claim against actual source code. This is what separates a credible finding from speculation.

For each path with risk_score > 25, spawn a validation agent:

```
Agent({
  description: "Validate [chain name]",
  prompt: "You are validating attack path [X] against [repo]. For each step, cite the exact file and content that proves or disproves it. Check: [specific things to verify]. Report CONFIRMED / PARTIALLY CONFIRMED / NOT CONFIRMED with exact file paths.",
  model: "sonnet"
})
```

**What to verify for each step:**
- Does the claimed vulnerability exist in current code? (Check for patches)
- Does the claimed credential/secret actually contain what the graph says?
- Does the claimed RBAC permission actually grant the claimed verbs on the claimed resources?
- Does the claimed service account actually run on the claimed pod?
- Does the claimed default configuration actually ship as default? (Check Helm values.yaml)
- Are there compensating controls the graph didn't capture? (Go module proxy, CI checks, branch protection)

**Common corrections to watch for:**
- ZipSlip/RCE CVEs that are patched in current releases
- Service account identity conflation (workflow pod SA != controller SA)
- "Dependency confusion" not applicable to Go modules (URL-based naming)
- httpOnly cookies preventing token theft (session-riding still works)
- Secrets in separate K8s Secret objects, not co-located as claimed
- `open-pull-requests-limit: 0` meaning security-only Dependabot updates
- Auth being "opt-in" vs "required" (check if the auth field is `+optional` in the Go struct)

### Phase 5: Adversarial Review

**Goal:** Try to break every claim before the target's security team does.

Spawn an adversarial agent with explicit instructions to refute:

```
Agent({
  description: "Adversarial review",
  prompt: "You are an adversarial reviewer. Try to REFUTE every claim in [advisory]. Check: initial requirements (what does the attacker actually need?), blast radius (is the impact overstated?), factual accuracy (verify every code citation), missing context (compensating controls not mentioned). Write a structured review.",
  model: "opus"
})
```

**Adversarial review must check:**
1. **Initial requirements** — how hard is the first step? Don't let the advisory hand-wave "attacker compromises X" when X is a major company's infrastructure.
2. **Blast radius** — does compromising workflow A actually give access to workflow B's secrets? Are they in the same job? Different workflows can't share secrets.
3. **Maintainer risk profiles** — actions maintained by GitHub/Docker/Sigstore have fundamentally different compromise profiles than individual-maintainer actions. Don't treat them the same.
4. **Compensating controls** — Go module proxy, checksum DB, CI status checks, branch protection required reviews, secret rotation. If the advisory doesn't mention them, it's incomplete.
5. **Terminology** — "dependency confusion" doesn't apply to Go. "Token theft" doesn't work with httpOnly cookies. Precision matters.

### Phase 6: Advisory Production

**Goal:** Produce a submission-ready advisory with honest severity ratings.

1. **Incorporate all adversarial corrections** — split CVSS by attack path, correct terminology, add compensating controls, add limitations section
2. **Lead with the strongest chain** — the path with the highest JEPA risk score that survived source validation
3. **Include exact remediation** — SHA-pinned action refs, version-type-filtered auto-merge configs, specific Helm values to change
4. **Cite every claim** — exact file paths and code excerpts for every factual assertion
5. **State limitations** — what you couldn't determine from public information (org-level policies, team memberships, secret rotation)

---

## Anti-Patterns to Avoid

| Anti-pattern | Why it's wrong | What to do instead |
|---|---|---|
| Submitting 0.0 risk paths to validation | Wastes sandbox time, produces false "exploitable" verdicts | Use risk score as a filter; refine threat model |
| Conflating SAs in the same namespace | Overestimates blast radius | Verify which SA runs on which pod via Helm chart |
| Forcing pre-conceived chains | Produces low-score paths that don't survive review | Let the JEPA guide discovery via energy gradients |
| Calling demo apps "intentionally vulnerable" | Overstates the finding | Verify whether the app was designed as a pentest target |
| Lumping enterprise-maintained and individual-maintained actions | Overstates attack complexity | Differentiate risk by maintainer trust level |
| Using "dependency confusion" for Go modules | Factually incorrect | Use "compromised upstream dependency" |
| Skipping adversarial review | Advisory gets torn apart by maintainers | Always adversarially verify before submission |
| Reporting architectural by-design choices as vulnerabilities | Weakens credibility | Note as "architectural concern" not "vulnerability" |
| Assuming same secret name = same secret value | The graph may infer shared-credential relationships that don't actually exist | Download public keys or artifacts to cryptographically verify sharing |

## Output

At the end of the pipeline, you should have:
1. A source-validated, adversarially reviewed advisory draft (markdown)
2. A dashboard artifact showing the investigation journey
3. Saved threat model templates for reuse
4. Tracking issues for any follow-up work (timed-out validations, etc.)
