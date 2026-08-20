---
name: triage-investigate
description: "Investigate one finding group against the infrastructure graph. Two-stage pipeline: energy exploration then mandatory code/config verification. Produces a verdict with evidence."
user-invocable: true
disable-model-invocation: false
---

# Triage Investigate

Investigate a single finding group against the infrastructure graph. This is the two-stage investigation pipeline from Phase 5 of the triage workflow. Each invocation handles ONE group.

Follow each step exactly — an agent executing this step-by-step produces the same result as the triage pipeline's investigate phase.

## CRITICAL: Two stages, both mandatory

- **Stage 1 (Energy Exploration)** maps the structural position. It is screening, not investigation.
- **Stage 2 (Code/Config Verification)** is the actual investigation. It is NOT optional.

A verdict based only on energy/graph data is INVALID. If you cannot verify, report `verification_blocked` — do NOT produce a verdict.

## Prerequisites

- `load_graph_energies(branch_id)` MUST have been called before invoking this skill. The graph is already loaded. Do NOT call `load_graph_energies` again.
- One finding group is required, with: group_id, title, canonical_type, claimed_findings, anchor_nodes, affected_services.

## Input

- One group from `/triage-discover` output:
  ```json
  {
    "group_id": "string",
    "title": "string",
    "canonical_type": "string",
    "claimed_findings": [0, 3, 7],
    "anchor_nodes": [{"finding_idx": 0, "node_id": "...", "node_type": "...", "entry_energy": 2.5}],
    "affected_services": ["service-a"]
  }
  ```
- `branch_id`: the graph branch (already loaded)
- `verification_channels` (optional): how to verify findings — source code paths, cloud CLI access, kubectl contexts, IaC repos
- `project_id` (optional): for state persistence
- `user_context` (optional): deployment model, investigation focus

If invoked independently, ask the user for the group details and verification access.

## Stage 1: Energy Exploration (structural map)

### How to interpret JEPA energy signals

**Entry energy** = structural exposure. < 0.1: directly accessible. 0.1-0.5: entry-facing. 0.5-2.0: near-surface. 2.0-4.0: interior. > 4.0: deep interior.

**Transition energy** = per-edge resistance. Negative = accelerating (easy). Positive = braking (barrier).

**Momentum** = cumulative path score. 0-20: well defended. 20-40: moderate. 40-60: low resistance. 60-80: concerning.

**Key rule:** Low resistance does NOT equal security problem. Auth happy paths accelerate by design. The signal is low resistance WHERE IT SHOULD NOT BE.

**Edge type patterns:** `contains`/`calls` accelerate. `owns`/`member_of`/`depends_on` brake. `has_permission`/`assumes_role`/`validates` 100% accelerate. `protects`: 76% brake, 24% accelerate. An accelerating `protects` edge = structurally transparent control — investigate.

**High-value target types:** When tracing blast radius, prioritize these node types:
- `data_store`, `database` — where sensitive data lives
- `credential`, `crypto_key` — authentication material
- `service_account`, `iam_role` — privilege escalation
- `environment_var` — when it holds secrets (check context)

A node is high-priority when it is a target type AND has many inbound `writes_to`, `authenticates_to`, or `has_permission` edges AND is reachable (low entry energy). Nodes with zero outbound edges and many sensitive inbound edges are structural sinks — the things the infrastructure is built to protect.

### Investigation method

Execute these steps iteratively. Each result should prompt the next question.

1. **`energy_node_scores`** — what is this node, what are its connections? Start with the group's anchor nodes or search hints.

2. **`energy_lowest_hop`** — single easiest connection, follow it. Reveals the path of least resistance from the anchor.

3. **`energy_edge_scores`** — specific transition energies on key edges. Use on edges between the anchor and controls, or between the anchor and sensitive targets.

4. **`energy_trace_to_target`** — reachability from entry points to the anchor, and from the anchor to sensitive targets (data stores, credentials, service accounts).

5. **Graph context** — use `read_node` for full node details (descriptions capture control limitations), `grep_nodes` to find related nodes, `get_connected_edges` for connections.

### Translate energy to security statements

Every energy value MUST become a concrete statement:
- Entry energy → "directly accessible / behind N barriers / deep interior" — WHY?
- Transition energy → "connection has no/moderate/strong resistance" — what IS the connection?
- Controls → "auth check / boundary / validation at [location] between entry and target"

If you cannot translate an energy value into a concrete statement, explore more.

### Stage 1 output

Produce this structured output from the exploration:

```json
{
  "id": "group-id",
  "structural_position": "Near-surface service behind API gateway, 2 hops from internet entry",
  "entry_energy": 0.35,
  "controls_found": [
    {"node": "api-gateway", "type": "network_boundary", "braking": true, "energy": 1.8},
    {"node": "auth-middleware", "type": "auth_check", "braking": true, "energy": 0.9}
  ],
  "paths_from_entry": [
    {"entry": "internet-ingress", "momentum": 35, "hops": 3}
  ],
  "sensitive_reachable": ["user-database", "credential-store"],
  "blast_radius_structural": "Reaches 2 data stores and 1 credential store via accelerating paths",
  "files_to_verify": [
    "services/api/src/middleware/auth.ts",
    "deploy/k8s/network-policies/api.yaml"
  ],
  "key_questions": [
    "Is the auth middleware actually attached to the /admin route?",
    "Does the network policy allow egress to the credential store?"
  ]
}
```

All fields are required: `id`, `structural_position`, `files_to_verify`, `key_questions`. The rest provide context for Stage 2.

## Stage 2: Code/Config Verification

This is the investigation. Energy exploration was screening.

### Verification channels

Use whatever verification channels are available:

- **source_code**: Read relevant source files, check dependency versions, feature flags, auth middleware attachment
- **cloud_cli**: Check IAM policies, security group rules, resource configurations, deployed state
- **kubernetes**: Check pod specs, network policies, RBAC bindings, service mesh config
- **iac**: Check Terraform/CloudFormation for drift
- **documentation**: Check runbooks, architecture docs

If no verification channels are configured, verify via graph semantic context only (the `description` field on nodes via `read_node`). Note the limitation.

### Verification rules

1. You MUST read at least one source file, config file, or cloud resource
2. You MUST cite the specific file, line, or API response that supports your verdict
3. If verification channels are not accessible, report `verification_blocked` — do NOT produce a verdict based only on energy

**Evidence hierarchy** (strict order — use the highest available):
1. **Source code** — the actual implementation. Highest authority.
2. **Configuration files** — the actual kong.yml, Dockerfile, Helm values.
3. **Cloud API state** — what is actually deployed right now.
4. **Semantic context** — the graph node's natural-language description.
5. **Graph structure** — which nodes connect via what edge types.
6. **Energy scores** — structural exposure and resistance. Screening evidence only.

"The graph shows 0 auth edges" is NOT verification — it is the screening tool describing itself. "The kong.yml route definition has no plugin attachment" IS verification.

### Resolve unknowns

Do not leave unknowns open. If you cannot resolve a question, flag it as UNRESOLVED with the specific action needed to resolve it.

### Blast radius

- What data/systems are exposed?
- Single-tenant or multi-tenant?
- Managed service or self-hosted?
- Is the blast radius contained or does it fan out?

### Verdict

Determine the verdict — the investigation conclusion:
- **confirmed**: real risk, no adequate control holds
- **refuted**: controls hold, the structural lead was correctly investigated and found defended (this is a success — document the defense)
- **partial**: real risk but lower than structure suggests, or risk is contextual

### Resolution categories

- **eliminable**: clear fix, no trade-off → engineering
- **reducible**: partial fix, add controls → engineering
- **constrained**: design limitation → product decision
- **drift_prone**: recurring → automation/monitoring
- **mitigated**: fix friction > risk under existing controls → accept with review date

### Control depth chain (required for mitigated)

If the resolution is `mitigated`, you MUST answer:
1. What control prevents exploitation?
2. Is the control effective?
3. What would break it?
4. Is that failure condition defended?

### Stage 2 output

Produce this structured output:

```json
{
  "id": "group-id",
  "resolution": "eliminable | reducible | constrained | drift_prone | mitigated",
  "readiness": "remediation_ready | investigation_needed",
  "verdict": "confirmed | refuted | partial",
  "evidence": "The kong.yml route definition at line 45 has no rate-limit plugin attachment...",
  "evidence_source": "source_code | config_file | runtime_test | graph_context | semantic_context",
  "unresolved": ["Could not verify if WAF rules are applied at the CDN layer"],
  "action": "Add rate-limit plugin to kong.yml route at services/api/kong.yml:45",
  "blast_radius": "Affects all API consumers. Multi-tenant — a single tenant's abuse impacts all tenants.",
  "primary_audience": "engineering | security | platform | product",
  "control_chain": [
    {"question": "What prevents exploitation?", "answer": "API gateway rate limiting", "status": "verified | gap | unresolved"}
  ],
  "key_insight": "One-sentence summary of the most important finding"
}
```

Required fields: `id`, `resolution`, `readiness`, `verdict`, `action`. The `control_chain` is required when resolution is `mitigated`.

### Save results

If a project ID was provided, save with `triage_update_finding_group(project_id, group_id, update)`.

## After completing

Report the verdict summary to the orchestrator:
- Group ID
- Verdict (confirmed/refuted/partial)
- Resolution category
- Primary audience
- One-line action

The orchestrator must collect ALL verdicts before proceeding to delivery.
