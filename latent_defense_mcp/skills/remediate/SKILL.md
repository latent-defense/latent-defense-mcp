---
name: remediate
description: "Create and track remediation tickets for validated attack paths. Manages the full lifecycle: provider setup, ticket creation, remediation analysis, and status tracking."
user-invocable: true
disable-model-invocation: false
---

# Remediate — Remediation Ticket Lifecycle

Create remediation tickets for validated attack paths, monitor remediation analysis, and track ticket status across providers.

## Prerequisites

- The `latent-defense` MCP server must be connected
- Attack paths must exist and ideally be validated (run `/triage` first)
- A ticketing provider should be configured (this skill helps set one up if not)

## Quick reference — tool names

### Ticketing

| Tool | What it does |
|------|-------------|
| `create_remediation_ticket(path_id, repository_id, branch_id, entry_node, target_node, ...)` | Create a ticket and start remediation |
| `get_ticket(ticket_id)` | Get ticket details and status |
| `get_ticket_steps(ticket_id)` | Get per-iteration remediation progress |
| `list_tickets(status, limit)` | List tickets with optional status filter |
| `ticket_stats()` | Aggregate ticket statistics |
| `update_ticket_status(ticket_id, status)` | Manually update ticket status |
| `sync_ticket(ticket_id)` | Force upstream provider status sync |
| `retry_ticket(ticket_id)` | Re-run remediation from a failed ticket |

### Provider configuration

| Tool | What it does |
|------|-------------|
| `get_ticket_provider()` | Get active provider and all configured providers |
| `configure_ticket_provider(provider, config, secret_keys, set_active)` | Register or update a provider |
| `test_ticket_provider(provider, config)` | Test provider connectivity |
| `set_active_ticket_provider(provider)` | Switch the active provider |
| `remove_ticket_provider(provider)` | Remove a configured provider |
| `get_ticket_template_variables()` | List Jinja2 template variables for custom ticket bodies |
| `preview_ticket_template(template, stage, provider)` | Dry-render a ticket template |

### Attack paths (for finding remediation candidates)

| Tool | What it does |
|------|-------------|
| `list_attack_paths(status, min_risk_score, limit, offset)` | Find paths ready for remediation |
| `get_attack_path(path_id)` | Get full path details |

## Workflow

### Step 1 — Check ticket provider

Call `get_ticket_provider()`.

If `configured` is `false`:

1. Show the user the `supported_providers` list: jira, linear, github, servicenow, pagerduty, airtable, asana, custom.

2. Ask which provider they want to configure.

3. Explain that credentials must be configured in the portal under **Settings > Credentials**. The MCP server cannot write secrets directly. Guide them:
   - **Jira**: needs `JIRA_BASE_URL`, `JIRA_PROJECT`, `JIRA_ISSUE_TYPE` in config. Credentials (`JIRA_API_TOKEN`, `JIRA_EMAIL`) via the portal.
   - **Linear**: needs `LINEAR_TEAM_ID` in config. Credential (`LINEAR_API_TOKEN`) via the portal.
   - **GitHub**: needs the repo URL in config. Credential (`GITHUB_TOKEN`) via the portal.
   - **ServiceNow**: needs `SERVICENOW_INSTANCE_URL` in config. Credentials via the portal.
   - **PagerDuty**: needs service/escalation config. Credentials via the portal.

4. Once credentials are set, call `test_ticket_provider(provider="<chosen>")` to verify.

   Returns:
   ```json
   {
     "ok": true,
     "latency_ms": 234,
     "error_class": null,
     "detail": null,
     "last4": "xK9f",
     "ready": true,
     "ready_error_class": null
   }
   ```

   If `ok` is `false`, report `error_class`:
   - `auth_failed` — credential is invalid or expired
   - `network` — cannot reach the provider endpoint
   - `not_configured` — URL or project settings are missing
   - `provider_error` — provider returned an unexpected error

   If `ok` is `true` but `ready` is `false`, report `ready_error_class`:
   - `project_not_found` — the configured project/team doesn't exist
   - `field_not_found` — a required custom field is missing

5. Provider is ready when both `ok` and `ready` are `true`.

### Step 2 — Find remediation candidates

Call `list_attack_paths(status="validated", limit=20)`. If empty, also try `list_attack_paths(status="escalated", limit=20)`.

Present each candidate:
- Path ID, entry → target
- Risk score and difficulty
- MITRE techniques
- Validation verdict (if available)

Ask the user which paths to remediate. They can select one, several, or all.

### Step 3 — Create remediation tickets

For each selected path, call `get_attack_path(path_id)` to get the full details, then call `create_remediation_ticket` with all available fields.

**Required parameters:**
- `path_id` — from the attack path
- `repository_id` — from the attack path
- `branch_id` — from the attack path
- `entry_node` — from the attack path
- `target_node` — from the attack path

**Optional parameters (include when available):**
- `steps` — JSON array of step objects from `get_attack_path`. Each step: `{"source_node": "...", "target_node": "...", "edge_type": "...", "tactic": "...", "technique": "...", "description": "..."}`
- `step_count` — number of steps
- `risk_score` — float 0-100
- `mitre_techniques` — JSON array of technique IDs e.g. `'["T1190","T1078"]'`
- `difficulty` — difficulty label from the analysis (e.g., "trivial", "easy", "medium", "hard", "extreme")
- `source` — origin tag (e.g. the `source` field from the path)
- `validation_verdict` — JSON object with the validation result if available

**Response:**
```json
{
  "ticket_id": "tkt_abc123def456",
  "path_id": "path_xyz",
  "status": "remediating",
  "provider": "jira",
  "message": "Ticket created. Remediation loop running in background."
}
```

The ticket creation is two-step:
1. **Synchronous** (this response): Creates the upstream provider ticket (Jira issue, Linear issue, etc.) with metadata-only content. The user gets a ticket URL immediately.
2. **Background**: Runs remediation analysis. When complete, updates the provider ticket with the full remediation summary and code snippets.

Save `ticket_id` from the response.

### Step 4 — Monitor remediation progress

Poll `get_ticket(ticket_id)` every 30 seconds to check the ticket status.

**Ticket status values:**
- `pending` — queued (max concurrent tickets limit reached)
- `analyzing` — examining the attack path and graph state
- `creating_ticket` — creating the upstream provider ticket
- `remediating` — remediation analysis is running
- `verifying` — verifying the proposed remediation eliminates the path
- `created` — remediation complete, upstream ticket updated with results
- `failed` — remediation loop failed

**Key fields in the ticket record:**
```json
{
  "ticket_id": "tkt_abc123",
  "path_id": "path_xyz",
  "status": "remediating",
  "provider": "jira",
  "provider_ticket_id": "SEC-1234",
  "provider_url": "https://acme.atlassian.net/browse/SEC-1234",
  "iterations": 2,
  "max_iterations": 3,
  "risk_score": 82.5,
  "entry_node": "public-api-gateway",
  "target_node": "production-database",
  "remediation_branch_id": "remediation/path_xyz",
  "failure_stage": null,
  "failure_reason": null,
  "provider_sync_status": "synced",
  "provider_status": "To Do",
  "provider_status_category": "todo"
}
```

For more detail on each iteration, call `get_ticket_steps(ticket_id)`:
```json
{
  "ticket_id": "tkt_abc123",
  "steps": [
    {
      "iteration": 1,
      "status": "completed",
      "summary": "Added network policy to block direct DB access from API gateway",
      "remaining_paths": 1,
      "delta": { "add_nodes": [...], "add_edges": [...], "remove_edges": [...] },
      "code_blocks": [
        {
          "title": "NetworkPolicy for prod-db",
          "language": "yaml",
          "description": "Restricts ingress to prod-db to only the auth-service",
          "code": "apiVersion: networking.k8s.io/v1\nkind: NetworkPolicy..."
        }
      ]
    }
  ]
}
```

Report to the user:
- Current iteration and max iterations
- Per-iteration summary and remaining paths
- Code blocks (the copy-pasteable remediation snippets)
- Whether the path was eliminated (remaining_paths == 0)

### Step 5 — Handle completion

When `status` is `created`:
- Report the final state: iterations run, whether the path was eliminated, provider URL
- Show the code blocks from the last successful iteration
- Tell the user: "The Jira/Linear issue has been updated with the full remediation summary and code snippets."

When `status` is `failed`:
- Report `failure_stage` and `failure_reason`
- Offer to retry with `retry_ticket(ticket_id)`. This creates a NEW ticket (the old one is preserved as audit trail).
  ```json
  {
    "ticket_id": "tkt_new789",
    "path_id": "path_xyz",
    "status": "remediating",
    "provider": "jira",
    "message": "Ticket created. Remediation loop running in background."
  }
  ```

### Step 6 — Track existing tickets

If the user wants to check existing tickets instead of creating new ones:

Call `list_tickets(limit=20)` and `ticket_stats()` in parallel.

`ticket_stats()` returns:
```json
{
  "total": 15,
  "patched": 8,
  "by_status": {
    "pending": 1,
    "remediating": 2,
    "created": 8,
    "failed": 4
  },
  "by_provider": { "jira": 10, "linear": 5 },
  "mean_iterations": 1.8,
  "max_iterations_hit": 2,
  "by_outcome": { "created": 8, "failed": 4 },
  "failed_by_stage": { "analyzing": 1, "remediation_loop": 2, "unknown": 1 }
}
```

For any ticket with `status: "failed"`, offer to retry. For any ticket with `provider_sync_status: "failed"`, offer to `sync_ticket(ticket_id)` to push it to the provider.

## How the remediation loop works

1. **Analyze**: Examines the attack path steps and the current graph state on the branch
2. **Propose**: Generates a graph delta (add/remove/modify nodes and edges) that would eliminate the path
3. **Commit**: The delta is committed to a remediation branch
4. **Verify**: The attack path model re-scores the graph. If the path is eliminated (difficulty rises sufficiently), success. If not, loop back to step 2 with the remaining paths.
5. **Max 3 iterations**: If the path is not eliminated after 3 iterations, the ticket is marked `created` anyway with `remaining_paths > 0` so the operator can apply what was found.

The analysis also extracts **code blocks** — copy-pasteable infrastructure-as-code snippets (Terraform, Kubernetes YAML, Helm values, etc.) that implement the proposed delta in the customer's actual codebase.

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 on `create_remediation_ticket` | API key invalid | Regenerate in portal |
| 404 on `get_ticket` | Ticket ID is wrong or ticket was purged | Re-query with `list_tickets` |
| 409 on `retry_ticket` | Ticket is not in `failed` status | Only failed tickets can be retried |
| Ticket created but `provider_sync_status: "failed"` | Provider credentials invalid when ticket was created | Fix credentials via portal, then call `sync_ticket(ticket_id)` |
| `status: "failed"`, `failure_stage: "analyzing"` | Could not analyze the path (usually missing graph data) | Check that the branch still exists and has nodes |
| `status: "failed"`, `failure_stage: "remediation_loop"` | Remediation analysis failed (model error, timeout) | Retry with `retry_ticket` |

## Important notes

- `create_remediation_ticket` manages the full two-step lifecycle. The upstream provider ticket is created immediately (Step 1), and remediation analysis runs in the background (Step 2).
- The `provider_sync_status` field tracks whether the internal ticket has been mirrored to the upstream provider. `synced` = yes, `failed` = provider was unreachable at creation time, `skipped` = no provider configured.
- Remediation results (code blocks, delta summaries) are persisted server-side. They survive service restarts.
- The ticketing service deduplicates by `path_id` — creating a second ticket for the same path returns the existing ticket.
