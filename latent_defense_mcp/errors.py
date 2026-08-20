"""HTTP error handling with actionable MCP error messages."""

from __future__ import annotations

import json
import logging
import os
import re

import httpx

log = logging.getLogger("latent-defense-mcp")

_INTERNAL_URL_RE = re.compile(
    r"https?://(?:"
    r"(?:localhost|127\.0\.0\.1)(?::\d+)?|"   # localhost
    r"[\w.-]+:\d{4,5}|"                        # hostname:port (internal services)
    r"[\w-]+\.[\w-]+\.svc(?:\.cluster\.local)?" # k8s service DNS
    r")[^\s\"']*"
)


def _sanitize_error(text: str) -> str:
    """Remove internal service URLs from error messages."""
    return _INTERNAL_URL_RE.sub("[internal]", text)


class McpApiError(Exception):
    """Raised with a user-actionable error message.

    ``status`` carries the originating HTTP status code (``None`` when the
    error did not come from an HTTP response). Callers should branch on
    ``status`` — e.g. an expected 404 on a best-effort leg — rather than
    matching the message text, which changes when :func:`handle_response`
    prefers the structured error envelope over the per-status message.
    """

    def __init__(self, message: str, *, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


# ---------------------------------------------------------------------------
# Tool-to-scope mapping
#
# Maps each tool to the API key scope required to call it.
# Used to produce actionable 403 error messages.
# ---------------------------------------------------------------------------

TOOL_SCOPES: dict[str, str] = {
    # Infrastructure graph
    "list_repositories": "infra:read",
    "get_repository": "infra:read",
    "list_branches": "infra:read",
    "get_branch": "infra:read",
    "get_graph": "infra:read",
    "create_branch": "infra:write",
    "list_commits": "infra:read",
    "diff_commits": "infra:read",
    "search_nodes": "infra:read",
    "infra_stats": "infra:read",
    # Scanning
    "list_trigger_events": "map:read",
    "trigger_stats": "map:read",
    "list_scan_schedules": "map:read",
    "run_scan_schedule": "map:trigger",
    "get_trigger_event": "map:read",
    # Mapping runs
    "get_mapping_run": "map:read",
    "list_mapping_runs": "map:read",
    "create_mapping_run": "map:trigger",
    "list_mapping_agents": "map:read",
    "cancel_mapping_run": "map:trigger",
    # Inference
    "run_inference": "inference:run",
    "list_inference_runs": "inference:read",
    "get_inference_run": "inference:read",
    "ingest_detection": "inference:run",
    # Inference schedules
    "list_inference_schedules": "inference:read",
    "create_inference_schedule": "inference:configure",
    "delete_inference_schedule": "inference:configure",
    # Attack path triage
    "list_attack_paths": "triage:read",
    "get_attack_path": "triage:read",
    "update_path_status": "triage:write",
    "validate_path": "triage:write",
    "dismiss_path": "triage:write",
    "undismiss_path": "triage:write",
    "bulk_update_paths": "triage:write",
    "override_risk_score": "triage:write",
    "clear_risk_override": "triage:write",
    "add_path_comment": "triage:write",
    "edit_path_comment": "triage:write",
    "list_path_history": "triage:read",
    "submit_attack_path": "triage:write",
    "triage_stats": "triage:read",
    "get_triage_config": "triage:read",
    # Validation
    "get_validation_status": "triage:read",
    # Webhooks
    "register_webhook": "webhooks",
    "list_webhooks": "webhooks",
    "delete_webhook": "webhooks",
    "test_webhook": "webhooks",
    "webhook_deliveries": "webhooks",
    "validate_webhook_template": "webhooks",
    # Data source connectors
    "list_connectors": "connectors:read",
    "create_connector": "connectors:write",
    "get_connector": "connectors:read",
    "update_connector": "connectors:write",
    "delete_connector": "connectors:write",
    "poll_connector": "connectors:write",
    "list_connector_types": "connectors:read",
    "ingest_stats": "connectors:read",
    "test_connector": "connectors:write",
    "connector_health": "connectors:read",
    # Energy analysis + graph cache
    "load_graph_energies": "oracle",
    "load_branch": "oracle",
    "wait_for_load": "oracle",
    "read_node": "oracle",
    "read_edge": "oracle",
    "get_connected_edges": "oracle",
    "get_graph_statistics": "oracle",
    "grep_nodes": "oracle",
    "grep_edges": "oracle",
    "find_nodes_by_type": "oracle",
    "find_edges_by_type": "oracle",
    "energy_node_scores": "oracle",
    "energy_edge_scores": "oracle",
    "energy_momentum_path": "oracle",
    "energy_lowest_hop": "oracle",
    "energy_lowest_paths": "oracle",
    "energy_trace_to_target": "oracle",
    "energy_compare_paths": "oracle",
    "energy_node_neighborhood": "oracle",
    "energy_entry_points": "oracle",
    "energy_defenses": "oracle",
    "energy_top_attack_paths": "oracle",
    "energy_chokepoints": "oracle",
    # Triage state (local persistence, no scope required)
    "triage_save_user": "",
    "triage_load_user": "",
    "triage_save_project": "",
    "triage_load_project": "",
    "triage_list_projects": "",
    "triage_project_status": "",
    "triage_update_finding_group": "",
    "triage_add_work_item": "",
    "triage_add_decision": "",
    "triage_get_workflow_args": "",
    # Introspection (no scope required)
    "whoami": "",
    "connection_status": "",
}


def _parse_envelope(response: httpx.Response) -> dict | None:
    """Extract the ``error`` envelope from a response, if present."""
    try:
        body = response.json()
        env = body.get("error")
        if isinstance(env, dict) and "code" in env and "message" in env:
            return env
    except Exception:
        pass
    return None


def handle_response(
    response: httpx.Response,
    *,
    tool_name: str | None = None,
) -> None:
    """Check an HTTP response and raise McpApiError with actionable guidance.

    Prefers the structured error envelope (``{error: {code, message, hint}}``)
    when present, falling back to per-status heuristics. Every raised error
    carries the HTTP status on ``McpApiError.status`` so callers can branch on
    the code (e.g. an expected 404) without matching message text — the raise
    site (envelope vs per-status) no longer changes how a caller detects a 404.
    """
    if response.is_success:
        return
    try:
        _raise_for_response(response, tool_name=tool_name)
    except McpApiError as e:
        if e.status is None:
            e.status = response.status_code
        raise


def _raise_for_response(
    response: httpx.Response,
    *,
    tool_name: str | None = None,
) -> None:

    portal_url = os.environ.get("LATENT_DEFENSE_URL", "https://portal.latentdefense.ai")

    status = response.status_code

    envelope = _parse_envelope(response)
    if envelope and status not in (401, 403):
        parts = [_sanitize_error(envelope["message"])]
        hint = envelope.get("hint")
        if hint:
            parts.append(hint)
        if tool_name:
            parts.append(f"Tool: {tool_name}")
        raise McpApiError("\n".join(parts))

    if status == 401:
        raise McpApiError(
            "Authentication failed. Your token may have expired.\n"
            "If using device flow, re-run any tool to re-authenticate.\n"
            "If using an API key, check that LATENT_DEFENSE_API_KEY is correct."
        )

    if status == 403:
        scope = TOOL_SCOPES.get(tool_name, "unknown") if tool_name else "unknown"
        scope_line = f"Insufficient permissions: this key lacks '{scope}'."
        tool_line = f"Tool '{tool_name}' requires scope '{scope}'." if tool_name else ""
        fix_line = f"Add the scope at {portal_url}/integrations"
        parts = [scope_line]
        if tool_line:
            parts.append(tool_line)
        parts.append(fix_line)
        raise McpApiError("\n".join(parts))

    if status == 404:
        detail = ""
        try:
            body = response.json()
            detail = body.get("detail", body.get("message", ""))
            if isinstance(detail, str):
                detail = _sanitize_error(detail)
        except Exception:
            pass
        msg = "Resource not found (404)."
        if detail:
            msg += f" {detail}"
        if tool_name:
            msg += f"\nTool: {tool_name}"
        raise McpApiError(msg)

    if status == 422:
        detail = ""
        try:
            body = response.json()
            detail = _sanitize_error(json.dumps(body.get("detail", body), indent=2))
        except Exception:
            detail = _sanitize_error(response.text[:500])
        raise McpApiError(
            f"The request was rejected because one or more arguments are invalid. "
            f"See the details below:\n{detail}"
        )

    if status == 429:
        retry_after = response.headers.get("Retry-After", "a few seconds")
        raise McpApiError(
            f"Rate limit exceeded. Retry in {retry_after}.\n"
            f"Raise the limit at {portal_url}/integrations"
        )

    if status >= 500:
        body = _sanitize_error(response.text)
        if "no graph loaded" in body.lower():
            raise McpApiError("No graph is loaded. Call load_graph_energies() first.")
        raise McpApiError(
            f"Server error ({status}). The deployment may be unhealthy.\n"
            "Run connection_status() to check service health."
        )

    raise McpApiError(
        f"Request failed with status {status}.\nResponse: {_sanitize_error(response.text[:500])}"
    )
