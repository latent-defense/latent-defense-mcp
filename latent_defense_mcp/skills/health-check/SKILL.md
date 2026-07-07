---
name: health-check
description: "Post-setup deployment check. Validates authentication, service health, infrastructure state, data sources, and ticketing."
user-invocable: true
disable-model-invocation: false
---

# Health Check — Deployment Configuration Check

Walk through a new Latent Defense deployment and verify that every component is reachable, authenticated, and ready to use.

## Prerequisites

- The `latent-defense` MCP server must be connected (check that `latent-defense` tools are available)

If the MCP server is not connected, tell the user to check their `.mcp.json` configuration and restart the session. The README in this repository has full setup instructions.

## Workflow

### Step 1 — Verify authentication and connectivity

Call `whoami()` and `connection_status()` in parallel.

`whoami()` confirms your identity and token:
- If authenticated: show email, auth method, scopes, and token expiry
- If not authenticated: guide the user to re-authenticate (see the README for setup instructions)

`connection_status()` tests reachability of every backend service:
- Report each service status (Infrastructure Graph, Mapping, Scan Trigger, Inference, Triage, Ticketing, Connectors, Validator)
- Flag any services showing errors or unreachable

If authentication fails, stop here — other checks will also fail.

### Step 2 — Review existing infrastructure

Call `list_repositories()` and `infra_stats()` in parallel.

`list_repositories()` returns a JSON array of repositories. Each has:
- `repository_id` / `id` — unique identifier
- `name` — display name
- `node_count`, `edge_count` — graph size

`infra_stats()` returns:
- `total_repositories` — count of repos
- `total_nodes`, `total_edges` — aggregate graph size
- `storage_bytes` — disk usage

If repositories exist, show a summary table: name, node count, edge count. If none exist, tell the user they need to run `/map` to scan their infrastructure.

### Step 3 — Check data source connectors

Call `list_connectors()` and `list_connector_types()` in parallel.

`list_connectors()` returns configured connectors with:
- `id`, `name`, `connector_type`
- `enabled` — whether polling is active
- `health` — one of `healthy`, `degraded`, `unhealthy`, `disabled`
- `last_poll_at`, `last_poll_status`, `last_poll_error`

`list_connector_types()` returns available connector types with:
- `type` — e.g. `aws_guardduty`, `aws_inspector`, `qualys`, `tenable`
- `description` — what the connector does

Show configured connectors and their health. If none are configured, suggest adding connectors for the customer's security tools and list the available types.

### Step 4 — Check ticketing provider

Call `get_ticket_provider()`.

Returns:
- `provider` — active provider name (e.g. `jira`, `linear`, `github`, `servicenow`)
- `configured` — boolean, whether the active provider has valid config + credentials
- `supported_providers` — list of all supported provider names
- `active_provider` — which provider is currently active
- `providers` — dict of all configured providers with their verify state
- `last_verified_at` — ISO timestamp of last successful verify, or null
- `verify_error_class` — null when healthy, or one of `auth_failed`, `network`, `not_configured`, `provider_error`

If no provider is configured (`configured: false`), offer to help set one up:

1. Ask which provider the user wants (show the `supported_providers` list)
2. Explain that credentials must be configured in the portal under **Settings > Credentials** -- the MCP server cannot store secrets
3. Once the user confirms credentials are set, call `test_ticket_provider()` to verify connectivity
4. If the test passes, the provider is ready

If a provider is configured but `verify_error_class` is not null, report the specific error:
- `auth_failed` — credentials are invalid or expired, re-enter in the portal
- `network` — cannot reach the provider endpoint, check URL configuration
- `not_configured` — provider URL or project settings are incomplete

### Step 5 — Suggest next steps

Based on what was found:

| Condition | Suggestion |
|-----------|-----------|
| No repositories | "Run `/map` to scan your infrastructure" |
| Repositories exist, no attack paths | "Run `/research` to discover attack paths" |
| Attack paths exist, none triaged | "Run `/triage` to review and validate findings" |
| No ticket provider configured | "Configure a ticketing provider in the portal, then run `/remediate`" |
| Everything configured | "You're all set. Try `/status` for a quick health check." |

To check for attack paths, call `triage_stats()` which returns:
- `total` — total path count
- `by_status` — dict of status → count (e.g. `{"new": 5, "validated": 2}`)

## Error handling

| Error | Cause | Fix |
|-------|-------|-----|
| 401 Unauthorized | API key invalid or expired | Generate a new key in **API & MCP** and update `.mcp.json` |
| 403 Forbidden | API key lacks required scopes | Check key permissions in the portal |
| Connection refused | MCP server cannot reach the deployment | Verify `LATENT_DEFENSE_URL` in `.mcp.json` points to the correct portal URL |
| 500 Internal Server Error | Backend service error | Check deployment health in the portal admin panel |
