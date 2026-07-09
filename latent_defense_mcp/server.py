"""Latent Defense MCP server — full API access via stdio transport."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

import httpx

from .auth import DeviceFlowPending
from .client import get_token_manager, make_client, _base_url as get_base_url, _verify_ssl as get_verify_ssl
from .errors import McpApiError, handle_response

log = logging.getLogger("latent-defense-mcp")

mcp = FastMCP(
    "Latent Defense",
    instructions=(
        "Infrastructure security platform. Use these tools to explore "
        "infrastructure graphs, trigger mapping scans, run attack path analysis, "
        "triage attack paths, dispatch validation, create remediation tickets, "
        "and build threat models to test attack hypotheses against real infrastructure."
    ),
)

_client: httpx.AsyncClient | None = None
_using_token_manager: bool = False
_oracle_session: str | None = None
_load_branch_id: str | None = None
_encoding_started_at: float | None = None
_graph_loaded: bool = False
_keepalive_task: object | None = None
_refresh_lock = asyncio.Lock()

VALID_NODE_TYPES = {
    "api_gateway",
    "auth_check",
    "authz_check",
    "buffer",
    "capacity_constraint",
    "cdn",
    "class",
    "cli_argument",
    "cloud_resource",
    "command_execution",
    "config_map",
    "container",
    "credential",
    "crypto_key",
    "cryptographic_op",
    "data_store",
    "database",
    "deprecated_api",
    "deserialization",
    "dynamodb_table",
    "ec2_instance",
    "ecs_service",
    "eks_cluster",
    "endpoint",
    "environment_var",
    "file",
    "file_handle",
    "file_operation",
    "file_parser",
    "firewall_rule",
    "framework",
    "function",
    "global_state",
    "grpc_method",
    "host",
    "http_endpoint",
    "iam_policy",
    "iam_role",
    "input_validation",
    "interface",
    "ipc_interface",
    "k8s_deployment",
    "k8s_ingress",
    "k8s_namespace",
    "k8s_pod",
    "k8s_rbac",
    "k8s_service",
    "kms_key",
    "lambda_function",
    "library",
    "load_balancer",
    "lock",
    "macro",
    "memory_operation",
    "message_handler",
    "module",
    "network_call",
    "network_segment",
    "package",
    "parameter",
    "process",
    "s3_bucket",
    "secrets_manager",
    "security_boundary",
    "security_group",
    "service",
    "service_account",
    "socket_listener",
    "sql_query",
    "struct",
    "subnet",
    "system_api",
    "system_call",
    "tf_data",
    "tf_module",
    "tf_resource",
    "tf_variable",
    "thread",
    "unsafe_block",
    "user_account",
    "variable",
    "vpc",
}


async def _http() -> Any:
    """Get the httpx client.

    Priority:
    1. Static API key from LATENT_DEFENSE_API_KEY env var
    2. Device-flow token via TokenManager (keychain/cache/device flow)
    """
    global _client, _using_token_manager
    if _client is not None:
        return _client

    # Try static API key first
    _client = make_client()
    if _client is not None:
        _using_token_manager = False
        return _client

    # Fall back to device-flow / cached token
    _using_token_manager = True
    tm = get_token_manager()
    token = await tm.get_token()
    _client = httpx.AsyncClient(
        base_url=get_base_url(),
        headers={"Authorization": f"Bearer {token}"},
        timeout=120,
        follow_redirects=True,
        verify=get_verify_ssl(),
    )
    return _client


async def _refresh_client() -> Any:
    """Force token refresh and rebuild the client. Called on 401."""
    async with _refresh_lock:
        global _client
        if not _using_token_manager:
            # Static API key — nothing to refresh. Re-raise the 401.
            return None
        old_client = _client
        tm = get_token_manager()
        tm.clear_access_token()
        token = await tm.get_token()
        _client = httpx.AsyncClient(
            base_url=get_base_url(),
            headers={"Authorization": f"Bearer {token}"},
            timeout=120,
            follow_redirects=True,
            verify=get_verify_ssl(),
        )
        if old_client is not None:
            await old_client.aclose()
        return _client


def _auth_pending_response(e: DeviceFlowPending) -> dict:
    return {
        "status": "authentication_required",
        "message": (
            "You need to approve this device in your browser. "
            "Open the URL below and enter the code."
        ),
        "verification_uri": e.verification_uri,
        "user_code": e.user_code,
        "expires_in_seconds": e.expires_in,
        "next_step": (
            "After approving in the browser, call any tool again — "
            "the server is polling in the background and will "
            "authenticate automatically once approved."
        ),
    }


def _parse_json_param(value: str, param_name: str) -> Any:
    """Parse a JSON string parameter, returning a friendly error dict on failure."""
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        raise McpApiError(f"Invalid JSON in '{param_name}': {e.msg} at position {e.pos}")


async def _get(path: str, *, _tool: str = "", **params) -> Any:
    try:
        r = await (await _http()).get(path, params=params)
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    try:
        if r.status_code == 401:
            client = await _refresh_client()
            if client is not None:
                r = await client.get(path, params=params)
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    handle_response(r, tool_name=_tool or None)
    return r.json() if r.content else {"status": "ok"}


async def _post(path: str, body: dict | None = None, *, _tool: str = "") -> Any:
    try:
        r = await (await _http()).post(path, json=body or {})
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    try:
        if r.status_code == 401:
            client = await _refresh_client()
            if client is not None:
                r = await client.post(path, json=body or {})
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    handle_response(r, tool_name=_tool or None)
    return r.json() if r.content else {"status": "ok"}


async def _patch(path: str, body: dict, *, _tool: str = "") -> Any:
    try:
        r = await (await _http()).patch(path, json=body)
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    try:
        if r.status_code == 401:
            client = await _refresh_client()
            if client is not None:
                r = await client.patch(path, json=body)
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    handle_response(r, tool_name=_tool or None)
    return r.json() if r.content else {"status": "ok"}


async def _delete(path: str, *, _tool: str = "") -> Any:
    try:
        r = await (await _http()).delete(path)
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    try:
        if r.status_code == 401:
            client = await _refresh_client()
            if client is not None:
                r = await client.delete(path)
    except DeviceFlowPending as e:
        return _auth_pending_response(e)
    handle_response(r, tool_name=_tool or None)
    return r.json() if r.content else {"status": "ok"}


# ---------------------------------------------------------------------------
# Introspection — identity and connectivity
# ---------------------------------------------------------------------------


@mcp.tool()
async def whoami() -> str:
    """Show current authentication identity, granted scopes, token type, and expiry.

    Use this to verify your API key or device-flow token is working and to
    see which scopes are available. If a tool returns a permissions error,
    call whoami() to see what scopes your key has.
    """
    import os
    from datetime import UTC, datetime

    from .client import get_token_manager

    try:
        client = await _http()
    except DeviceFlowPending as e:
        return json.dumps(_auth_pending_response(e))
    r = await client.get("/auth/me")

    if r.status_code == 401:
        try:
            refreshed = await _refresh_client()
            if refreshed is not None:
                r = await refreshed.get("/auth/me")
        except DeviceFlowPending as e:
            return json.dumps(_auth_pending_response(e))
        if r.status_code == 401:
            return json.dumps(
                {
                    "authenticated": False,
                    "message": (
                        "Not authenticated. "
                        "Set LATENT_DEFENSE_API_KEY in your .mcp.json, or remove it to authenticate via your browser."
                    ),
                }
            )

    if not r.is_success:
        return json.dumps(
            {
                "authenticated": False,
                "message": f"Auth check failed with status {r.status_code}.",
            }
        )

    me = r.json()

    result: dict[str, Any] = {
        "authenticated": True,
        "email": me.get("email"),
        "name": me.get("name") or me.get("email", ""),
        "auth_method": (
            "api_key" if os.environ.get("LATENT_DEFENSE_API_KEY") else "device_flow"
        ),
        "deployment_url": get_base_url(),
    }

    if me.get("scopes"):
        result["scopes"] = me["scopes"]
    if me.get("repository_ids"):
        result["repository_ids"] = me["repository_ids"]
    if me.get("key_type"):
        result["key_type"] = me["key_type"]

    # Token expiry for device-flow users (from the local TokenManager)
    if not os.environ.get("LATENT_DEFENSE_API_KEY"):
        try:
            tm = get_token_manager()
            if tm.access_token_expiry:
                result["token_expires_at"] = tm.access_token_expiry.isoformat()
                remaining = (tm.access_token_expiry - datetime.now(UTC)).total_seconds()
                result["token_expires_in_minutes"] = round(remaining / 60)
        except Exception:
            pass

    return json.dumps(result, indent=2)


@mcp.tool()
async def connection_status() -> str:
    """Check connectivity to the Latent Defense deployment and backend service health.

    Tests reachability of each backend service through the portal gateway.
    Use this when tools return server errors to identify which service is down.
    """
    try:
        client = await _http()
    except DeviceFlowPending as e:
        return json.dumps(_auth_pending_response(e))
    base_url = get_base_url()

    checks: dict[str, dict[str, Any]] = {}

    # --- Infrastructure graph ---
    try:
        r = await client.get("/api/infra/stats")
        if r.status_code == 200:
            data = r.json()
            checks["infrastructure_graph"] = {
                "status": "ok",
                "repositories": data.get("repositories", 0),
            }
        elif r.status_code == 403:
            checks["infrastructure_graph"] = {
                "status": "ok (no permission to read stats)",
                "note": "Service reachable but key lacks infra:read scope.",
            }
        else:
            checks["infrastructure_graph"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["infrastructure_graph"] = {"status": "unreachable", "error": str(exc)}

    # --- Scan trigger ---
    try:
        r = await client.get("/api/triggers/stats")
        if r.status_code == 200:
            checks["scan_trigger"] = {"status": "ok"}
        elif r.status_code == 403:
            checks["scan_trigger"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks map:read scope.",
            }
        else:
            checks["scan_trigger"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["scan_trigger"] = {"status": "unreachable", "error": str(exc)}

    # --- Mapping ---
    try:
        r = await client.get("/api/map/map/runs", params={"limit": 1})
        if r.status_code == 200:
            checks["mapping"] = {"status": "ok"}
        elif r.status_code == 403:
            checks["mapping"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks map:read scope.",
            }
        else:
            checks["mapping"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["mapping"] = {"status": "unreachable", "error": str(exc)}

    # --- Inference ---
    try:
        r = await client.get("/api/inference/runs", params={"limit": 1})
        if r.status_code == 200:
            checks["inference"] = {"status": "ok"}
        elif r.status_code == 403:
            checks["inference"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks inference:read scope.",
            }
        else:
            checks["inference"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["inference"] = {"status": "unreachable", "error": str(exc)}

    # --- Triage ---
    try:
        r = await client.get("/api/triage/stats")
        if r.status_code == 200:
            checks["triage"] = {"status": "ok"}
        elif r.status_code == 403:
            checks["triage"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks triage:read scope.",
            }
        else:
            checks["triage"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["triage"] = {"status": "unreachable", "error": str(exc)}

    # --- Ticketing ---
    try:
        r = await client.get("/api/tickets/provider")
        if r.status_code == 200:
            checks["ticketing"] = {"status": "ok"}
        elif r.status_code == 403:
            checks["ticketing"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks tickets:read scope.",
            }
        else:
            checks["ticketing"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["ticketing"] = {"status": "unreachable", "error": str(exc)}

    # --- Connectors ---
    try:
        r = await client.get("/api/ingest/connectors/health")
        if r.status_code == 200:
            checks["connectors"] = {"status": "ok"}
        elif r.status_code == 403:
            checks["connectors"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks connectors:read scope.",
            }
        else:
            checks["connectors"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["connectors"] = {"status": "unreachable", "error": str(exc)}

    # --- Validator ---
    try:
        # Check validator service reachability
        r = await client.get("/validator-api/health")
        if r.status_code == 200:
            checks["validator"] = {"status": "ok"}
        elif r.status_code == 404:
            # /health might not exist but the service is reachable
            checks["validator"] = {"status": "ok (no health endpoint)"}
        elif r.status_code == 403:
            checks["validator"] = {
                "status": "ok (no permission)",
                "note": "Service reachable but key lacks triage:read scope.",
            }
        else:
            checks["validator"] = {"status": "error", "code": r.status_code}
    except Exception as exc:
        checks["validator"] = {"status": "unreachable", "error": str(exc)}

    # Summarize
    ok_count = sum(1 for c in checks.values() if c["status"].startswith("ok"))
    total = len(checks)

    return json.dumps(
        {
            "deployment": base_url,
            "overall": (
                "healthy"
                if ok_count == total
                else f"{ok_count}/{total} services reachable"
            ),
            "services": checks,
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Infrastructure graph
# ---------------------------------------------------------------------------


def _sanitize_repo(repo: dict) -> None:
    """Strip internal graph fields and filesystem paths from a repository dict."""
    for field in ("graph_hash", "base_snapshot_id",
                  "snap_node_count", "snap_edge_count",
                  "snap_accumulated_delta"):
        repo.pop(field, None)
    # Don't show null timestamps — they add noise
    if repo.get("completed_at") is None:
        repo.pop("completed_at", None)
    # Sanitize source_metadata: strip filesystem paths
    meta = repo.get("source_metadata", {})
    if isinstance(meta, dict):
        scope = meta.get("mapping_scope", {})
        if isinstance(scope, dict):
            for source in scope.get("artifact_sources", []):
                if isinstance(source, dict):
                    source.pop("local_path", None)
                    source.pop("workspace_path", None)


@mcp.tool()
async def list_repositories() -> str:
    """List all infrastructure graph repositories."""
    result = await _get("/api/infra/repositories", _tool="list_repositories")
    if isinstance(result, dict) and "repositories" in result:
        for repo in result["repositories"]:
            if isinstance(repo, dict):
                _sanitize_repo(repo)
    elif isinstance(result, list):
        for repo in result:
            if isinstance(repo, dict):
                _sanitize_repo(repo)
    return json.dumps(result)


@mcp.tool()
async def get_repository(repo_id: str) -> str:
    """Get details for an infrastructure graph repository."""
    result = await _get(f"/api/infra/repositories/{repo_id}", _tool="get_repository")
    if isinstance(result, dict):
        _sanitize_repo(result)
    return json.dumps(result)


@mcp.tool()
async def list_branches(repo_id: str) -> str:
    """List branches in a repository."""
    return json.dumps(
        await _get(f"/api/infra/repositories/{repo_id}/branches", _tool="list_branches")
    )


@mcp.tool()
async def get_branch(branch_id: str) -> str:
    """Get branch details including head commit and graph stats."""
    return json.dumps(
        await _get(f"/api/infra/branches/{branch_id}", _tool="get_branch")
    )


@mcp.tool()
async def get_graph(branch_id: str) -> str:
    """Get the complete infrastructure graph for a branch -- all components and their connections."""
    return json.dumps(
        await _get(f"/api/infra/branches/{branch_id}/graph", _tool="get_graph")
    )


@mcp.tool()
async def list_branch_attack_paths(branch_id: str) -> str:
    """List attack paths stored on a branch before triage review. Use list_attack_paths() for the triaged queue."""
    return json.dumps(
        await _get(
            f"/api/infra/branches/{branch_id}/attack-paths",
            _tool="list_branch_attack_paths",
        )
    )


@mcp.tool()
async def create_branch(repo_id: str, label: str, source_branch_id: str = "") -> str:
    """Create a new branch in a repository.

    Args:
        repo_id: Repository ID.
        label: Branch label.
        source_branch_id: Branch to fork from. If empty, forks from the repo's default branch.
    """
    body: dict[str, Any] = {"label": label}
    if source_branch_id:
        body["source_branch_id"] = source_branch_id
    return json.dumps(
        await _post(
            f"/api/infra/repositories/{repo_id}/branches", body, _tool="create_branch"
        )
    )


@mcp.tool()
async def list_commits(branch_id: str, limit: int = 20) -> str:
    """List commits on a branch (newest first)."""
    return json.dumps(
        await _get(
            f"/api/infra/branches/{branch_id}/commits",
            _tool="list_commits",
            limit=limit,
        )
    )


@mcp.tool()
async def diff_commits(commit_a_id: str, commit_b_id: str) -> str:
    """Diff two commits — shows added/removed/modified nodes and edges."""
    return json.dumps(
        await _get(
            f"/api/infra/commits/{commit_a_id}/diff/{commit_b_id}", _tool="diff_commits"
        )
    )


@mcp.tool()
async def search_nodes(repo_id: str, query: str) -> str:
    """Search for nodes by name substring (case-insensitive).

    Matches nodes whose name contains the query text. Use short, specific
    terms that appear in node names (e.g., "postgres", "credential", "nginx")
    rather than natural language phrases.

    For semantic search by description, use oracle_search_nodes instead —
    it finds nodes by meaning, not just name matching.
    """
    return json.dumps(
        await _get(
            f"/api/infra/repositories/{repo_id}/search-nodes",
            _tool="search_nodes",
            q=query,
        )
    )


@mcp.tool()
async def infra_stats() -> str:
    """Get infrastructure graph stats (repo count, total nodes/edges, storage)."""
    result = await _get("/api/infra/stats", _tool="infra_stats")
    if isinstance(result, dict):
        for key in ("repositories", "branches_total", "branches_completed", "attack_paths"):
            if key in result:
                try:
                    result[key] = int(result[key])
                except (TypeError, ValueError):
                    result[key] = 0
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Scanning and webhook dispatch
# ---------------------------------------------------------------------------


@mcp.tool()
async def trigger_scan(
    description: str,
    credentials_profile: str = "default",
    cloud_accounts: str = "[]",
    repositories: str = "[]",
    domains: str = "[]",
) -> str:
    """Trigger a manual infrastructure mapping scan.

    Args:
        description: What to scan and why.
        credentials_profile: Credential profile to use (default: "default").
        cloud_accounts: JSON array of {"provider", "account_id", "regions"} objects.
        repositories: JSON array of repo URL strings.
        domains: JSON array of domain strings.
    """
    scope = {}
    if cloud_accounts != "[]":
        scope["cloud_accounts"] = _parse_json_param(cloud_accounts, "cloud_accounts")
    if repositories != "[]":
        scope["repositories"] = _parse_json_param(repositories, "repositories")
    if domains != "[]":
        scope["domains"] = _parse_json_param(domains, "domains")
    return json.dumps(
        await _post(
            "/api/triggers/manual",
            {
                "description": description,
                "scope": scope,
                "credentials_profile": credentials_profile,
            },
            _tool="trigger_scan",
        )
    )


@mcp.tool()
async def list_trigger_events(limit: int = 20) -> str:
    """List recent trigger events (scans, webhooks)."""
    return json.dumps(
        await _get("/api/triggers/events", _tool="list_trigger_events", limit=limit)
    )


@mcp.tool()
async def trigger_stats() -> str:
    """Get trigger service stats (active runs, rate limiting, failures)."""
    return json.dumps(await _get("/api/triggers/stats", _tool="trigger_stats"))


@mcp.tool()
async def list_scan_schedules() -> str:
    """List all scan schedules (cron-based recurring mapping runs)."""
    return json.dumps(
        await _get("/api/triggers/schedules", _tool="list_scan_schedules")
    )


@mcp.tool()
async def run_scan_schedule(schedule_id: str) -> str:
    """Manually trigger a scan schedule to run now."""
    return json.dumps(
        await _post(
            f"/api/triggers/schedules/{schedule_id}/run", _tool="run_scan_schedule"
        )
    )


@mcp.tool()
async def get_trigger_event(event_id: str) -> str:
    """Get details of a specific trigger event."""
    return json.dumps(
        await _get(f"/api/triggers/events/{event_id}", _tool="get_trigger_event")
    )


@mcp.tool()
async def get_mapping_run(run_id: str) -> str:
    """Get status and details of a mapping run."""
    result = await _get(f"/api/map/map/{run_id}", _tool="get_mapping_run")
    if isinstance(result, dict):
        # Strip internal sandbox paths from any nested metadata
        for key in ("workspace_path", "sandbox_path", "local_path"):
            result.pop(key, None)
    return json.dumps(result)


@mcp.tool()
async def list_mapping_runs(limit: int = 20) -> str:
    """List recent mapping runs with status, trigger type, and graph stats."""
    result = await _get("/api/map/map/runs", _tool="list_mapping_runs", limit=limit)
    if isinstance(result, list):
        for run in result:
            if isinstance(run, dict):
                for key in ("workspace_path", "sandbox_path", "local_path"):
                    run.pop(key, None)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Direct mapping run creation
# ---------------------------------------------------------------------------


@mcp.tool()
async def create_mapping_run(
    description: str,
    repositories: str = "[]",
    cloud_accounts: str = "[]",
    kubernetes_clusters: str = "[]",
    domains: str = "[]",
    web_endpoints: str = "[]",
    cidrs: str = "[]",
    exclude_patterns: str = "[]",
    credentials_profile: str = "default",
    model: str = "claude-sonnet-4-6",
    dry_run: bool = False,
) -> str:
    """Create a mapping run with full control over scan scope and configuration.

    Use this instead of trigger_scan when you need fine-grained scope control.

    Args:
        description: What to map and why.
        repositories: JSON array of repository URL strings.
        cloud_accounts: JSON array of {"provider", "account_id", "regions"} objects.
        kubernetes_clusters: JSON array of kubeconfig context strings.
        domains: JSON array of domain strings to probe.
        web_endpoints: JSON array of web endpoint URLs to probe.
        cidrs: JSON array of CIDR strings to probe.
        exclude_patterns: JSON array of glob patterns to exclude.
        credentials_profile: Credential profile to use (default: "default").
        model: LLM model for mapping agents (default: "claude-sonnet-4-6").
        dry_run: If true, validate the request without executing.
    """
    scope: dict[str, Any] = {}
    for key, val in [
        ("repositories", repositories),
        ("cloud_accounts", cloud_accounts),
        ("kubernetes_clusters", kubernetes_clusters),
        ("domains", domains),
        ("web_endpoints", web_endpoints),
        ("cidrs", cidrs),
        ("exclude_patterns", exclude_patterns),
    ]:
        parsed = _parse_json_param(val, key) if isinstance(val, str) else val
        if parsed:
            scope[key] = parsed

    body = {
        "trigger": {
            "type": "manual",
            "description": description,
            "scope": scope,
        },
        "credentials_profile": credentials_profile,
        "model": model,
        "dry_run": dry_run,
    }
    return json.dumps(await _post("/api/map/map", body, _tool="create_mapping_run"))


@mcp.tool()
async def list_mapping_agents(run_id: str) -> str:
    """List agents in a mapping run with per-agent status and progress."""
    return json.dumps(
        await _get(f"/api/map/map/{run_id}/agents", _tool="list_mapping_agents")
    )


@mcp.tool()
async def cancel_mapping_run(run_id: str) -> str:
    """Cancel a running mapping run."""
    return json.dumps(
        await _post(f"/api/map/map/{run_id}/cancel", _tool="cancel_mapping_run")
    )


# ---------------------------------------------------------------------------
# Inference runs and detection ingestion
# ---------------------------------------------------------------------------


@mcp.tool()
async def run_inference(branch_id: str) -> str:
    """Run attack path analysis on a branch. Analyzes the infrastructure graph to discover exploitable multi-step attack paths and forwards them to the triage queue. Check progress with get_inference_run()."""
    if not branch_id or not branch_id.strip():
        return json.dumps({
            "error": "invalid_branch_id",
            "message": "branch_id cannot be empty. Use list_branches() to find valid branch IDs.",
        })
    # Verify branch exists before creating a run
    try:
        branch = await _get(f"/api/infra/branches/{branch_id}", _tool="run_inference")
        if isinstance(branch, dict) and branch.get("status") == "authentication_required":
            return json.dumps(branch)
    except Exception:
        return json.dumps({
            "error": "branch_not_found",
            "message": (
                f"Branch '{branch_id}' not found. "
                "Use list_branches(repo_id) to see available branches."
            ),
        })
    result = await _post(
        "/api/inference/run", {"branch_id": branch_id}, _tool="run_inference"
    )
    if isinstance(result, dict):
        result.pop("task_id", None)
    return json.dumps(result)


@mcp.tool()
async def list_inference_runs(limit: int = 20) -> str:
    """List recent attack path analysis runs."""
    result = await _get("/api/inference/runs", _tool="list_inference_runs", limit=limit)
    if isinstance(result, list):
        for run in result:
            if isinstance(run, dict):
                run.pop("task_id", None)
                if run.get("detection_id") is None:
                    run.pop("detection_id", None)
    return json.dumps(result)


@mcp.tool()
async def get_inference_run(run_id: str) -> str:
    """Get status and results of an inference run."""
    result = await _get(f"/api/inference/runs/{run_id}", _tool="get_inference_run")
    if isinstance(result, dict):
        result.pop("task_id", None)
        if result.get("detection_id") is None:
            result.pop("detection_id", None)
    return json.dumps(result)


@mcp.tool()
async def ingest_detection(
    source: str,
    severity: str,
    affected_resource_type: str,
    affected_resource_id: str,
    title: str = "",
    cve: str = "",
) -> str:
    """Ingest a security detection from an external tool (scanner, SIEM, etc.).

    Args:
        source: Detection source (e.g. "vulnerability_scanner", "config_audit").
        severity: One of "critical", "high", "medium", "low", "info".
        affected_resource_type: Resource type (e.g. "ec2_instance", "pod").
        affected_resource_id: Resource identifier.
        title: Detection title.
        cve: CVE identifier if applicable.
    """
    body: dict[str, Any] = {
        "source": source,
        "severity": severity,
        "affected_resource": {
            "type": affected_resource_type,
            "identifier": affected_resource_id,
        },
    }
    if title:
        body["title"] = title
    if cve:
        body["cve"] = cve
    result = await _post("/api/detections/ingest", body, _tool="ingest_detection")
    if isinstance(result, dict):
        result.pop("task_id", None)
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Inference schedule management
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_inference_schedules() -> str:
    """List all attack path analysis schedules."""
    return json.dumps(
        await _get("/api/inference-schedules/", _tool="list_inference_schedules")
    )


@mcp.tool()
async def create_inference_schedule(
    name: str,
    cron: str,
    branch_labels: str = "[]",
    all_branches: bool = False,
) -> str:
    """Create a recurring attack path analysis schedule.

    Args:
        name: Schedule name.
        cron: Cron expression (e.g. "0 2 * * *" for 2 AM daily).
        branch_labels: JSON array of branch label strings to target. Ignored if all_branches is true.
        all_branches: Run on all branches if true.
    """
    body: dict[str, Any] = {"name": name, "cron": cron, "all_branches": all_branches}
    if branch_labels != "[]":
        body["branch_labels"] = _parse_json_param(branch_labels, "branch_labels")
    return json.dumps(
        await _post(
            "/api/inference-schedules/", body, _tool="create_inference_schedule"
        )
    )


@mcp.tool()
async def delete_inference_schedule(schedule_id: str) -> str:
    """Delete an attack path analysis schedule."""
    return json.dumps(
        await _delete(
            f"/api/inference-schedules/{schedule_id}", _tool="delete_inference_schedule"
        )
    )


# ---------------------------------------------------------------------------
# Triage — attack path lifecycle
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_attack_paths(
    status: str = "",
    min_risk_score: float = 0,
    limit: int = 20,
    offset: int = 0,
    summary: bool = True,
) -> str:
    """List attack paths, optionally filtered by status or risk score.

    Status values: new, acknowledged, validating, validated, escalated, ticketed, closed, failed, false_positive.
    Set summary=False for full details including step narratives.
    """
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    if min_risk_score > 0:
        params["min_risk_score"] = min_risk_score
    result = await _get("/api/triage/paths", _tool="list_attack_paths", **params)
    if summary and isinstance(result, dict):
        items = result.get("items", result if isinstance(result, list) else [])
        if isinstance(items, list):
            summarized = []
            for p in items:
                if not isinstance(p, dict):
                    summarized.append(p)
                    continue
                source_raw = p.get("source", "")
                source_display = {
                    "oracle": "interactive_analysis",
                    "unconstrained": "automated_scan",
                    "constrained": "targeted_scan",
                    "detection": "detection_triggered",
                }.get(source_raw, source_raw)
                summarized.append(
                    {
                        "path_id": p.get("path_id"),
                        "status": p.get("status"),
                        "risk_score": p.get("risk_score"),
                        "difficulty": p.get("difficulty"),
                        "entry_node": p.get("entry_node"),
                        "target_node": p.get("target_node"),
                        "source": source_display,
                        "n_steps": len(p.get("steps", [])),
                        "branch_id": p.get("branch_id"),
                        "created_at": p.get("created_at"),
                    }
                )
            result = {
                "items": summarized,
                "total": result.get("total", len(summarized)),
            }
    return json.dumps(result)


@mcp.tool()
async def get_attack_path(path_id: str) -> str:
    """Get full details of an attack path including steps, MITRE mappings, and risk score."""
    result = await _get(f"/api/triage/paths/{path_id}", _tool="get_attack_path")
    if isinstance(result, dict):
        # Remove internal bookkeeping fields that add noise for customers
        for field in ("validation_retry_count", "latest_revalidation",
                      "original_risk_score", "environment_profile"):
            result.pop(field, None)
    return json.dumps(result)


@mcp.tool()
async def update_path_status(path_id: str, status: str, note: str = "") -> str:
    """Update an attack path's triage status.

    Args:
        path_id: Attack path ID.
        status: Target status (acknowledged, closed, etc.).
        note: Optional note explaining the status change.
    """
    body: dict[str, Any] = {"status": status}
    if note:
        body["note"] = note
    return json.dumps(
        await _patch(
            f"/api/triage/paths/{path_id}/status", body, _tool="update_path_status"
        )
    )


@mcp.tool()
async def validate_path(path_id: str) -> str:
    """Send an attack path for automated validation. The system attempts each attack step in an isolated sandbox and independently verifies the results. Takes 5-15 minutes. Check progress with get_validation_status()."""
    return json.dumps(
        await _post(f"/api/triage/paths/{path_id}/validate", _tool="validate_path")
    )


@mcp.tool()
async def escalate_path(path_id: str) -> str:
    """Forward a validated attack path to your configured ticketing system to create a remediation ticket. Use get_ticket_provider() to check which system is configured."""
    return json.dumps(
        await _post(f"/api/triage/paths/{path_id}/escalate", _tool="escalate_path")
    )


@mcp.tool()
async def triage_stats(repository_id: str = "") -> str:
    """Get triage statistics (counts by status, severity, repository)."""
    params = {}
    if repository_id:
        params["repository_id"] = repository_id
    return json.dumps(await _get("/api/triage/stats", _tool="triage_stats", **params))


# ---------------------------------------------------------------------------
# Triage — webhook management
# ---------------------------------------------------------------------------


@mcp.tool()
async def register_webhook(
    url: str,
    events: str,
    template: str = "",
    secret: str = "",
    headers: str = "{}",
) -> str:
    """Register a triage webhook to receive notifications on attack path events.

    Args:
        url: Webhook endpoint URL.
        events: JSON array of event types (e.g. '["new_path", "status_change", "validation_complete"]').
        template: Optional Jinja2 template for the POST body. Variables: event_type, path_id, timestamp, data (full path object for new_path events).
        secret: Optional HMAC-SHA256 secret for request signing.
        headers: Optional JSON object of extra headers to send.
    """
    if not url.startswith(("https://", "http://")):
        return json.dumps({
            "error": "invalid_url",
            "message": (
                f"Invalid webhook URL: '{url}'. "
                "URLs must start with https:// (recommended) or http:// (for local development only)."
            ),
        })

    parsed_events = _parse_json_param(events, "events")

    VALID_EVENTS = {
        "new_path", "status_change", "validation_complete",
        "path_acknowledged", "path_dispatched_to_validator",
        "path_escalated_to_ticketing", "severity_change",
    }
    invalid = [e for e in parsed_events if e not in VALID_EVENTS]
    if invalid:
        return json.dumps({
            "error": "invalid_event_type",
            "message": (
                f"Unknown event type(s): {', '.join(invalid)}. "
                f"Valid events: {', '.join(sorted(VALID_EVENTS))}"
            ),
        })

    body: dict[str, Any] = {"url": url, "events": parsed_events}
    if template:
        body["template"] = template
    if secret:
        body["secret"] = secret
    if headers != "{}":
        body["headers"] = _parse_json_param(headers, "headers")
    return json.dumps(
        await _post("/api/triage/webhooks", body, _tool="register_webhook")
    )


@mcp.tool()
async def list_webhooks() -> str:
    """List all registered triage webhooks."""
    return json.dumps(await _get("/api/triage/webhooks", _tool="list_webhooks"))


@mcp.tool()
async def delete_webhook(webhook_id: str) -> str:
    """Delete a triage webhook."""
    return json.dumps(
        await _delete(f"/api/triage/webhooks/{webhook_id}", _tool="delete_webhook")
    )


# ---------------------------------------------------------------------------
# Attack path validation
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_validation_status(run_id: str) -> str:
    """Get the status of a validation run (step counts, progress)."""
    return json.dumps(
        await _get(f"/validator-api/validate/{run_id}", _tool="get_validation_status")
    )


# ---------------------------------------------------------------------------
# Ticketing — remediation tickets
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_tickets(status: str = "", limit: int = 20) -> str:
    """List remediation tickets."""
    params: dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    return json.dumps(await _get("/api/tickets", _tool="list_tickets", **params))


@mcp.tool()
async def get_ticket(ticket_id: str) -> str:
    """Get remediation ticket details."""
    return json.dumps(await _get(f"/api/tickets/{ticket_id}", _tool="get_ticket"))


@mcp.tool()
async def ticket_stats() -> str:
    """Get aggregate ticket statistics (counts by status, provider, and outcome)."""
    result = await _get("/api/tickets/stats", _tool="ticket_stats")
    if isinstance(result, dict) and result.get("total", 0) == 0:
        result["hint"] = (
            "No tickets yet. Use /remediate to create remediation tickets "
            "from validated attack paths, or configure a ticketing provider first "
            "with configure_ticket_provider()."
        )
    return json.dumps(result)


@mcp.tool()
async def create_remediation_ticket(
    path_id: str,
    repository_id: str,
    branch_id: str,
    entry_node: str,
    target_node: str,
    steps: str = "[]",
    step_count: int = 0,
    risk_score: float = 0.0,
    mitre_techniques: str = "[]",
    difficulty: str = "medium",
    source: str = "",
    validation_verdict: str = "",
) -> str:
    """Create a remediation ticket for an attack path and start two-step remediation.

    Creates the upstream ticket on the active provider immediately (~seconds), then
    runs the automated remediation analysis in the background and updates the ticket. Poll
    get_ticket_steps for per-iteration progress. Provider-agnostic: the ticket lands on
    whichever provider is currently active (see get_ticket_provider).

    Args:
        path_id: Attack path ID (from triage / validation tools).
        repository_id: Repository ID the path belongs to.
        branch_id: Branch ID.
        entry_node: Path entry node ID.
        target_node: Path target node ID.
        steps: JSON array of path-step objects (source_node/target_node/...).
        step_count: Number of steps in the path.
        risk_score: Path risk score (0.0-1.0).
        mitre_techniques: JSON array of MITRE ATT&CK technique IDs.
        difficulty: Path difficulty label from the analysis model (e.g., "trivial", "easy", "medium", "hard", "extreme").
        source: Optional origin tag for the ticket.
        validation_verdict: Optional JSON object with the validation verdict.
    """
    body: dict[str, Any] = {
        "path_id": path_id,
        "repository_id": repository_id,
        "branch_id": branch_id,
        "entry_node": entry_node,
        "target_node": target_node,
        "step_count": step_count,
        "risk_score": risk_score,
        "difficulty": difficulty,
    }
    if steps != "[]":
        body["steps"] = _parse_json_param(steps, "steps")
    if mitre_techniques != "[]":
        body["mitre_techniques"] = _parse_json_param(mitre_techniques, "mitre_techniques")
    if source:
        body["source"] = source
    if validation_verdict:
        body["validation_verdict"] = _parse_json_param(validation_verdict, "validation_verdict")
    return json.dumps(
        await _post("/api/tickets/remediate", body, _tool="create_remediation_ticket")
    )


@mcp.tool()
async def get_ticket_steps(ticket_id: str) -> str:
    """Get per-iteration remediation steps/progress for a ticket."""
    return json.dumps(
        await _get(f"/api/tickets/{ticket_id}/steps", _tool="get_ticket_steps")
    )


@mcp.tool()
async def update_ticket_status(ticket_id: str, status: str) -> str:
    """Update a ticket's status.

    Args:
        ticket_id: Ticket ID.
        status: New status. One of: pending, analyzing, remediating, verifying,
            creating_ticket, created, failed.
    """
    return json.dumps(
        await _patch(
            f"/api/tickets/{ticket_id}/status",
            {"status": status},
            _tool="update_ticket_status",
        )
    )


@mcp.tool()
async def sync_ticket(ticket_id: str) -> str:
    """Force a one-off sync of a ticket's status from its upstream provider."""
    return json.dumps(
        await _post(f"/api/tickets/{ticket_id}/sync", _tool="sync_ticket")
    )


@mcp.tool()
async def retry_ticket(ticket_id: str) -> str:
    """Re-run remediation from a failed ticket."""
    return json.dumps(
        await _post(f"/api/tickets/{ticket_id}/retry", _tool="retry_ticket")
    )


# ---------------------------------------------------------------------------
# Ticketing — provider configuration (provider-agnostic; admin via gateway)
# ---------------------------------------------------------------------------


@mcp.tool()
async def get_ticket_provider() -> str:
    """Get the active ticketing provider and all configured providers with verification state."""
    result = await _get("/api/tickets/provider", _tool="get_ticket_provider")
    if isinstance(result, dict):
        providers = result.get("providers", {})
        if isinstance(providers, dict):
            for name, prov in providers.items():
                if isinstance(prov, dict) and "config" in prov:
                    config = prov["config"]
                    if isinstance(config, dict):
                        # Only keep config fields relevant to this provider
                        prefix = name + "_"
                        relevant = {k: v for k, v in config.items()
                                    if k.startswith(prefix) or k in ("max_active_tickets",)
                                    or not any(k.startswith(p + "_") for p in
                                              ("jira", "linear", "github", "servicenow",
                                               "pagerduty", "airtable", "asana"))}
                        prov["config"] = relevant
    return json.dumps(result)


@mcp.tool()
async def configure_ticket_provider(
    provider: str,
    config: str = "{}",
    secret_keys: str = "",
    set_active: bool = True,
) -> str:
    """Register or update a ticketing provider configuration.

    One tool configures any supported provider (jira, linear, github, servicenow,
    pagerduty, airtable, asana, custom) — the REST surface is provider-agnostic.
    Secrets must be configured in the portal under Settings > Credentials; pass
    secret_keys to reference which credential key holds each secret. Do not pass
    raw secret values.

    Args:
        provider: Provider name (jira, linear, github, servicenow, pagerduty, airtable, asana, custom).
        config: JSON object with provider-specific non-secret config (base_url, project, etc.).
        secret_keys: Optional JSON object mapping credential roles to Secret keys.
        set_active: Make this the active provider after configuring (default true).
    """
    body: dict[str, Any] = {"provider": provider, "set_active": set_active}
    if config != "{}":
        body["config"] = _parse_json_param(config, "config")
    if secret_keys:
        body["secret_keys"] = _parse_json_param(secret_keys, "secret_keys")
    return json.dumps(
        await _post(
            "/api/tickets/provider/configure", body, _tool="configure_ticket_provider"
        )
    )


@mcp.tool()
async def test_ticket_provider(provider: str = "", config: str = "") -> str:
    """Test a ticketing provider's auth without making it active.

    Args:
        provider: Provider name to test. Leave empty to test the currently-configured provider.
        config: Optional JSON object with config overrides to test.
    """
    body: dict[str, Any] = {}
    if provider:
        body["provider"] = provider
    if config:
        body["config"] = _parse_json_param(config, "config")
    return json.dumps(
        await _post("/api/tickets/provider/test", body, _tool="test_ticket_provider")
    )


@mcp.tool()
async def set_active_ticket_provider(provider: str) -> str:
    """Switch the active ticketing provider to an already-configured provider."""
    return json.dumps(
        await _post(
            "/api/tickets/provider/active",
            {"provider": provider},
            _tool="set_active_ticket_provider",
        )
    )


@mcp.tool()
async def remove_ticket_provider(provider: str) -> str:
    """Remove a configured ticketing provider."""
    return json.dumps(
        await _delete(
            f"/api/tickets/provider/{provider}", _tool="remove_ticket_provider"
        )
    )


@mcp.tool()
async def get_ticket_template_variables() -> str:
    """List the variables a ticket template can reference (Jinja2 cheatsheet).

    Returns every {{ variable }} available to a TicketTemplate — dotted path,
    type, and description — plus the template `schema_version`. Fetch this before
    authoring or previewing a template with preview_ticket_template.
    """
    return json.dumps(
        await _get(
            "/api/tickets/provider/template/variables",
            _tool="get_ticket_template_variables",
        )
    )


@mcp.tool()
async def preview_ticket_template(
    template: str,
    stage: str = "final",
    provider: str = "",
) -> str:
    """Dry-render a ticket template against synthetic content — no state touched.

    Shows what a TicketTemplate will produce before it's saved on a provider.
    Returns rendered_title / rendered_description, plus fell_back + warning when a
    template fails to render (the hard-coded body is used instead), and a provider
    transform_hint (e.g. Jira flattens markdown into ADF). Does NOT modify the
    saved template on the active provider.

    Args:
        template: JSON object for the TicketTemplate. Common fields:
            description_template, title_template (Jinja2 source strings); optional
            per-stage overrides description_template_{initial,final,failure} and
            title_template_{initial,final,failure}; field_defaults (dict of scalar
            custom-field defaults). `enabled` is forced on for the preview render.
        stage: Lifecycle slice to render — "initial" (creation), "final"
            (resolution), or "failure". Defaults to "final".
        provider: Optional provider name; when set, the response includes a
            transform hint for how that provider will mutate the rendered body.
    """
    body: dict[str, Any] = {"template": _parse_json_param(template, "template"), "stage": stage}
    if provider:
        body["provider"] = provider
    return json.dumps(
        await _post(
            "/api/tickets/provider/template/preview",
            body,
            _tool="preview_ticket_template",
        )
    )


# ---------------------------------------------------------------------------
# Data source connectors
# ---------------------------------------------------------------------------


@mcp.tool()
async def list_connectors() -> str:
    """List all configured data source connectors."""
    return json.dumps(await _get("/api/ingest/connectors", _tool="list_connectors"))


@mcp.tool()
async def create_connector(
    name: str,
    connector_type: str,
    connection_config: str,
    poll_config: str = "{}",
    mapping_config: str = "{}",
) -> str:
    """Create a data source connector for automated artifact ingestion.

    Args:
        name: Connector display name.
        connector_type: Type (use list_connector_types to see available). E.g. "aws_guardduty", "aws_inspector", "qualys", "tenable".
        connection_config: JSON object with type-specific connection params (credentials, regions, etc.).
        poll_config: Optional JSON object with polling settings (interval_minutes, enabled, etc.).
        mapping_config: Optional JSON object with field mapping overrides.
    """
    body: dict[str, Any] = {
        "name": name,
        "connector_type": connector_type,
        "connection_config": _parse_json_param(connection_config, "connection_config"),
    }
    if poll_config != "{}":
        body["poll_config"] = _parse_json_param(poll_config, "poll_config")
    if mapping_config != "{}":
        body["mapping_config"] = _parse_json_param(mapping_config, "mapping_config")
    return json.dumps(
        await _post("/api/ingest/connectors", body, _tool="create_connector")
    )


@mcp.tool()
async def get_connector(connector_id: str) -> str:
    """Get connector details including status and last poll time."""
    return json.dumps(
        await _get(f"/api/ingest/connectors/{connector_id}", _tool="get_connector")
    )


@mcp.tool()
async def update_connector(
    connector_id: str,
    connection_config: str = "{}",
    poll_config: str = "{}",
    enabled: str = "",
) -> str:
    """Update a connector's configuration.

    Args:
        connector_id: Connector ID.
        connection_config: JSON object with updated connection params (merged, not replaced).
        poll_config: JSON object with updated polling settings.
        enabled: Set to "true" or "false" to enable/disable. Leave empty to keep current.
    """
    body: dict[str, Any] = {}
    if connection_config != "{}":
        body["connection_config"] = _parse_json_param(connection_config, "connection_config")
    if poll_config != "{}":
        body["poll_config"] = _parse_json_param(poll_config, "poll_config")
    if enabled:
        body["enabled"] = enabled.lower() == "true"
    return json.dumps(
        await _patch(
            f"/api/ingest/connectors/{connector_id}", body, _tool="update_connector"
        )
    )


@mcp.tool()
async def delete_connector(connector_id: str) -> str:
    """Delete a data source connector."""
    return json.dumps(
        await _delete(
            f"/api/ingest/connectors/{connector_id}", _tool="delete_connector"
        )
    )


@mcp.tool()
async def poll_connector(connector_id: str) -> str:
    """Trigger an immediate poll on a connector (fetch latest data from the source)."""
    return json.dumps(
        await _post(
            f"/api/ingest/connectors/{connector_id}/poll", _tool="poll_connector"
        )
    )


@mcp.tool()
async def list_connector_types() -> str:
    """List available connector types and their required configuration fields."""
    return json.dumps(
        await _get("/api/ingest/connectors/types", _tool="list_connector_types")
    )


@mcp.tool()
async def ingest_stats() -> str:
    """Get ingestion stats (total artifacts, connector health, last poll times)."""
    return json.dumps(await _get("/api/ingest/ingest/stats", _tool="ingest_stats"))


# ---------------------------------------------------------------------------
# Connector + webhook reliability tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def test_connector(connector_id: str) -> str:
    """Test a connector's connection without persisting artifacts. Returns record count or error details."""
    return json.dumps(
        await _post(
            f"/api/ingest/connectors/{connector_id}/test", _tool="test_connector"
        )
    )


@mcp.tool()
async def connector_health() -> str:
    """Get health summary across all connectors, sorted unhealthy-first. Shows circuit breaker state and consecutive failures."""
    return json.dumps(
        await _get("/api/ingest/connectors/health", _tool="connector_health")
    )


@mcp.tool()
async def test_webhook(webhook_id: str) -> str:
    """Send a synthetic test event to a webhook and return the delivery result with per-attempt status codes."""
    return json.dumps(
        await _post(f"/api/triage/webhooks/{webhook_id}/test", _tool="test_webhook")
    )


@mcp.tool()
async def webhook_deliveries(webhook_id: str, limit: int = 20, status: str = "") -> str:
    """Get recent delivery history for a webhook.

    Args:
        webhook_id: Webhook ID.
        limit: Max records to return (default 20).
        status: Filter by "success" or "failed". Leave empty for all.
    """
    params: dict[str, Any] = {"limit": limit}
    if status:
        params["status"] = status
    return json.dumps(
        await _get(
            f"/api/triage/webhooks/{webhook_id}/deliveries",
            _tool="webhook_deliveries",
            **params,
        )
    )


@mcp.tool()
async def validate_webhook_template(
    template: str, sample_event_type: str = "new_path"
) -> str:
    """Validate a Jinja2 webhook template against a synthetic event. Returns rendered output or parse error.

    Args:
        template: Jinja2 template string.
        sample_event_type: Event type for the sample data (default "new_path").
    """
    return json.dumps(
        await _post(
            "/api/triage/webhooks/validate-template",
            {
                "template": template,
                "sample_event_type": sample_event_type,
            },
            _tool="validate_webhook_template",
        )
    )


# ---------------------------------------------------------------------------
# Interactive analysis — threat model tools (session-managed)
# ---------------------------------------------------------------------------


async def _ensure_oracle_session() -> str:
    global _oracle_session
    if _oracle_session is None:
        result = await _post("/api/oracle/sessions", {})
        _oracle_session = result["session_id"]
        log.info("oracle session created: %s", _oracle_session)
    return _oracle_session


def _start_keepalive():
    """Start a background task that pings the oracle session every 10 min.

    The server reaps sessions after 30 min of inactivity. During long
    investigations, the user may pause to read output — this keeps the
    session alive so they don't lose their loaded graph.
    """
    import asyncio

    global _keepalive_task

    _stop_keepalive()

    async def _keepalive_loop():
        while True:
            await asyncio.sleep(600)
            session = _oracle_session
            if session is None:
                break
            try:
                client = await _http()
                await client.post(
                    f"/api/oracle/sessions/{session}/call",
                    json={"method": "graph_info", "params": {}},
                    timeout=15,
                )
            except Exception:
                pass

    _keepalive_task = asyncio.create_task(_keepalive_loop())


def _stop_keepalive():
    """Cancel the keepalive task if running."""
    global _keepalive_task
    if _keepalive_task is not None:
        _keepalive_task.cancel()
        _keepalive_task = None


async def _oracle_call(
    method: str, params: dict | None = None, *, _tool: str = ""
) -> str:
    import time

    global _oracle_session, _load_branch_id, _encoding_started_at, _graph_loaded
    sid = await _ensure_oracle_session()
    client = await _http()
    try:
        r = await client.post(
            f"/api/oracle/sessions/{sid}/call",
            json={"method": method, "params": params or {}},
            timeout=120,
        )
    except (httpx.TimeoutException, httpx.ConnectError):
        if not _graph_loaded and _encoding_started_at is not None:
            elapsed = int(time.time() - _encoding_started_at)
            return json.dumps(
                {
                    "status": "loading",
                    "elapsed_secs": elapsed,
                    "message": (
                        f"Graph is still loading ({elapsed}s elapsed). "
                        "Call oracle_load_status to check progress. "
                        "Do not call other oracle tools until loading completes."
                    ),
                }
            )
        raise
    if r.status_code == 401:
        refreshed = await _refresh_client()
        if refreshed is not None:
            r = await refreshed.post(
                f"/api/oracle/sessions/{sid}/call",
                json={"method": method, "params": params or {}},
                timeout=120,
            )

    # Oracle session recovery: 404 means the session was reaped (30-min idle timeout).
    # Reset local state and create a new session, but do NOT retry the call —
    # the loaded graph state is gone, so the caller must reload their branch.
    if r.status_code == 404:
        _oracle_session = None
        _load_branch_id = None
        _encoding_started_at = None
        _graph_loaded = False
        _stop_keepalive()
        print(
            "Oracle session expired (30-minute idle timeout). "
            "Creating a new session. You will need to reload your "
            "graph with oracle_load_branch().",
            file=sys.stderr,
        )
        await _ensure_oracle_session()
        return json.dumps(
            {
                "error": "oracle_session_expired",
                "message": (
                    "Your analysis session expired after 30 minutes of inactivity. "
                    "A new session has been created, but you need to reload your "
                    "graph by calling oracle_load_branch() before running other "
                    "oracle tools."
                ),
            }
        )

    if r.status_code == 502:
        await asyncio.sleep(3)
        try:
            client = await _http()  # Re-acquire in case of prior refresh
            r = await client.post(
                f"/api/oracle/sessions/{sid}/call",
                json={"method": method, "params": params or {}},
                timeout=120,
            )
        except (httpx.TimeoutException, httpx.ConnectError):
            pass

    handle_response(r, tool_name=_tool or None)
    result = r.json()
    return json.dumps(result.get("result", result))


async def _probe_oracle_graph_loaded(expected_branch: str | None = None) -> dict | None:
    """Check whether the graph has finished loading.

    Returns the graph_info response dict if loaded, None if not loaded, wrong graph,
    or unreachable. Bypasses _require_loaded_graph gate — makes a direct HTTP call.
    """
    global _oracle_session
    session = _oracle_session
    if session is None:
        return None
    try:
        client = await _http()
        resp = await client.post(
            f"/api/oracle/sessions/{session}/call",
            json={"method": "graph_info", "params": {}},
            timeout=30,
        )
        if resp.status_code == 404:
            _oracle_session = None
            log.info("oracle probe: session %s not found (404), cleared", session)
            return None
        if resp.status_code == 401:
            refreshed = await _refresh_client()
            if refreshed is None:
                return None
            resp = await refreshed.post(
                f"/api/oracle/sessions/{session}/call",
                json={"method": "graph_info", "params": {}},
                timeout=30,
            )
            if resp.status_code != 200:
                return None
        if resp.status_code != 200:
            return None
        data = resp.json()
        result = data.get("result", "")
        # Unwrap the tools/call content envelope if present
        if isinstance(result, dict) and "content" in result:
            content = result["content"]
            if isinstance(content, list) and content:
                text = content[0].get("text", "")
                try:
                    result = json.loads(text)
                except (json.JSONDecodeError, TypeError):
                    pass
        if isinstance(result, str):
            try:
                parsed = json.loads(result)
            except (json.JSONDecodeError, TypeError):
                return None
        else:
            parsed = result
        if parsed.get("status") == "no_graph_loaded":
            return None
        if expected_branch and parsed.get("graph_id") != expected_branch:
            return None
        return parsed
    except Exception as e:
        log.warning("oracle probe failed: %s", e)
        return None


async def _fetch_encoding_progress() -> dict | None:
    """Fetch real-time encoding progress from the inference server's encoding-status endpoint."""
    if _oracle_session is None:
        return None
    try:
        client = await _http()
        resp = await client.get(
            f"/api/oracle/sessions/{_oracle_session}/encoding-status",
            timeout=10,
        )
        if resp.status_code != 200:
            log.warning("encoding-status returned %d", resp.status_code)
            return None
        return resp.json()
    except Exception as e:
        log.warning("encoding-status fetch failed: %s", e)
        return None


async def _require_loaded_graph() -> str | None:
    """Return a JSON error string if no graph is loaded, else None.

    Probes the server to distinguish "no graph loaded" from "encoding in progress"
    so the user gets an actionable message instead of a confusing 504/timeout.
    """
    import time

    global _graph_loaded

    if _load_branch_id is None:
        return json.dumps(
            {
                "status": "no_graph_loaded",
                "message": "No graph is loaded. Call oracle_load_branch first.",
            }
        )
    if _graph_loaded:
        return None
    # Graph was requested but not yet confirmed loaded — probe the server
    probe = await _probe_oracle_graph_loaded(expected_branch=_load_branch_id)
    if probe is not None:
        _graph_loaded = True
        return None
    # Not loaded yet — give the user timing context
    if _encoding_started_at is not None:
        elapsed = int(time.time() - _encoding_started_at)
        return json.dumps(
            {
                "status": "loading",
                "elapsed_secs": elapsed,
                "message": (
                    f"Graph is still loading ({elapsed}s elapsed). "
                    "Call oracle_load_status for detailed progress. "
                    "Do not call other oracle tools until loading completes."
                ),
            }
        )
    return json.dumps(
        {
            "status": "loading",
            "message": (
                "Graph is still loading. Call oracle_load_status for detailed progress. "
                "Do not call other oracle tools until loading completes."
            ),
        }
    )


@mcp.tool()
async def oracle_load_branch(branch_id: str) -> str:
    """Load an infrastructure graph branch into the analysis session.

    Must be called before any graph exploration or threat-model matching.
    Use list_branches(repo_id) to find valid branch IDs (format: 'branch_<hex>').
    For large graphs (1000+ nodes), loading and analyzing takes 2-10 minutes. This tool returns
    immediately. Use oracle_load_status() to poll until the graph is ready.
    """
    import time

    if not branch_id or not branch_id.strip():
        return json.dumps(
            {
                "error": "invalid_branch_id",
                "message": "branch_id cannot be empty. Use list_branches() to find valid branch IDs.",
            }
        )

    global _load_branch_id, _encoding_started_at, _graph_loaded
    sid = await _ensure_oracle_session()
    _load_branch_id = branch_id
    _encoding_started_at = time.time()
    _graph_loaded = False

    # Fire-and-forget: dispatch load_branch to the server with a short timeout.
    # The server-side encoding is tied to the session, not the HTTP connection —
    # it continues regardless of whether this request completes, times out, or
    # gets killed by an intermediate proxy with a short idle timeout.
    try:
        client = await _http()
        r = await client.post(
            f"/api/oracle/sessions/{sid}/call",
            json={"method": "load_branch", "params": {"branch_id": branch_id}},
            timeout=30,
        )
        if r.is_success:
            _graph_loaded = True
            _encoding_started_at = None
            _start_keepalive()
            return json.dumps(
                {
                    "status": "loaded",
                    "branch_id": branch_id,
                    "result": r.json().get("result", r.json()),
                }
            )
    except (httpx.TimeoutException, httpx.ConnectError):
        pass
    except Exception:
        pass

    return json.dumps(
        {
            "status": "encoding_started",
            "branch_id": branch_id,
            "message": (
                "Graph loading started. Latent Defense is analyzing your infrastructure. "
                "This takes 2-5 minutes for large graphs "
                "(up to 10 minutes for 10,000+ nodes). "
                "Call oracle_wait_for_load() to block until ready, "
                "or oracle_load_status() to check progress manually."
            ),
        }
    )


async def _format_encoding_progress() -> str:
    """Poll the inference server for encoding progress and return a formatted JSON response."""
    progress = await _fetch_encoding_progress()
    if progress and progress.get("stage") is not None:
        stage_names = {
            0: "queued", 1: "fetching graph from infrastructure database",
            2: "checking cache", 3: "computing structural features",
            4: "computing node embeddings", 5: "computing edge embeddings",
            6: "running GNN encoder", 7: "building adjacency index",
            8: "complete", 9: "failed",
        }
        stage = progress.get("stage", 0)
        stage_name = stage_names.get(stage)
        if stage_name is None:
            log.warning("Unknown encoding stage %d — update stage_names dict", stage)
            stage_name = f"stage {stage}"
        pct = progress.get("progress_pct", 0)
        elapsed = progress.get("elapsed_secs", 0)
        batch_info = ""
        current_batch = progress.get("current_batch", 0)
        total_batches = progress.get("total_batches", 0)
        if total_batches > 0:
            batch_info = f" (batch {current_batch}/{total_batches})"

        if stage == 8:
            return json.dumps({"status": "loaded", "progress_pct": 100, "message": "Encoding complete."})
        if stage == 9:
            return json.dumps({"status": "failed", "error": progress.get("error"), "message": "Encoding failed."})

        return json.dumps({
            "status": "encoding",
            "stage": stage_name,
            "progress_pct": pct,
            "elapsed_secs": elapsed,
            "message": f"Encoding {pct}% complete — {stage_name}{batch_info}. "
                       f"Elapsed: {elapsed}s. Check again in 15-30 seconds.",
        })
    return json.dumps({
        "status": "encoding",
        "progress_available": False,
        "message": "Encoding in progress but progress telemetry is unavailable. Check again in 30-60 seconds.",
    })


@mcp.tool()
async def oracle_load_status() -> str:
    """Check whether the graph has finished loading after oracle_load_branch. Use oracle_wait_for_load() instead for automatic waiting."""
    import time

    global _graph_loaded, _encoding_started_at

    if _load_branch_id is None:
        return json.dumps(
            {
                "status": "no_load_in_progress",
                "message": "No load_branch call has been made. Call oracle_load_branch first.",
            }
        )

    if _graph_loaded:
        probe = await _probe_oracle_graph_loaded(expected_branch=_load_branch_id)
        if probe is not None:
            return json.dumps({"status": "loaded", "result": probe})
        # Graph was loaded but session may have been reaped — fall through to reap handling

    probe = await _probe_oracle_graph_loaded(expected_branch=_load_branch_id)
    if probe is not None:
        _graph_loaded = True
        _encoding_started_at = None
        _start_keepalive()
        return json.dumps({"status": "loaded", "result": probe})

    # Probe returned None — either still encoding, or session was reaped
    if _oracle_session is None:
        # Session was reaped by the 404 handler in _oracle_call or probe.
        # Auto-retry: create a new session and re-dispatch load_branch.
        branch = _load_branch_id
        _graph_loaded = False
        _stop_keepalive()
        _encoding_started_at = time.time()
        sid = await _ensure_oracle_session()
        try:
            client = await _http()
            await client.post(
                f"/api/oracle/sessions/{sid}/call",
                json={"method": "load_branch", "params": {"branch_id": branch}},
                timeout=30,
            )
        except Exception:
            pass
        return json.dumps(
            {
                "status": "reloading",
                "message": (
                    "Previous session expired (30-minute idle timeout). "
                    "Automatically created a new session and re-dispatched graph loading. "
                    "Check again in 30-60 seconds."
                ),
            }
        )

    # Session exists but graph not loaded yet — encoding in progress.
    # Check if encoding just completed (stage 8) so we can unblock the gate.
    progress = await _fetch_encoding_progress()
    if progress and progress.get("stage") == 8:
        probe = await _probe_oracle_graph_loaded(expected_branch=_load_branch_id)
        if probe is not None:
            _graph_loaded = True
            _encoding_started_at = None
            _start_keepalive()
            log.info("encoding complete — oracle gate unlocked for branch %s", _load_branch_id)
            return json.dumps({"status": "loaded", "message": "Graph encoding complete and loaded.", "result": probe})
    return await _format_encoding_progress()


@mcp.tool()
async def oracle_wait_for_load(timeout_secs: int = 600, poll_interval: int = 30) -> str:
    """Wait for graph loading to complete after oracle_load_branch.

    Blocks until the graph is loaded or the timeout expires. Use this instead of
    manually polling oracle_load_status in a loop.

    Returns the graph info (node/edge counts, types) on success, or an error
    if the timeout is reached or the session expires.
    """
    import asyncio
    import time

    global _graph_loaded, _encoding_started_at

    if _load_branch_id is None:
        return json.dumps(
            {
                "status": "no_load_in_progress",
                "message": "No load_branch call has been made. Call oracle_load_branch first.",
            }
        )

    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        probe = await _probe_oracle_graph_loaded(expected_branch=_load_branch_id)
        if probe is not None:
            _graph_loaded = True
            _encoding_started_at = None
            return json.dumps({"status": "loaded", "result": probe})

        if _oracle_session is None:
            branch = _load_branch_id
            _graph_loaded = False
            _stop_keepalive()
            _encoding_started_at = time.time()
            sid = await _ensure_oracle_session()
            try:
                client = await _http()
                await client.post(
                    f"/api/oracle/sessions/{sid}/call",
                    json={
                        "method": "load_branch",
                        "params": {"branch_id": branch},
                    },
                    timeout=30,
                )
            except Exception:
                pass

        remaining = int(deadline - time.time())
        elapsed = int(time.time() - _encoding_started_at) if _encoding_started_at else 0
        log.info(
            "oracle_wait_for_load: encoding %ds elapsed, %ds remaining",
            elapsed,
            remaining,
        )
        await asyncio.sleep(min(poll_interval, max(remaining, 1)))

    elapsed = int(time.time() - _encoding_started_at) if _encoding_started_at else 0
    return json.dumps(
        {
            "status": "timeout",
            "elapsed_secs": elapsed,
            "message": (
                f"Graph loading did not complete within {timeout_secs}s "
                f"({elapsed}s elapsed). Loading may still be running "
                "server-side. Try calling oracle_load_status() or "
                "oracle_wait_for_load() again."
            ),
        }
    )


@mcp.tool()
async def oracle_graph_info() -> str:
    """Get node/edge counts, type distribution, and available edge types for the loaded graph."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    raw = await _oracle_call("graph_info", _tool="oracle_graph_info")
    try:
        result = json.loads(raw)
        if isinstance(result, dict):
            # Filter unknown/internal edge types
            for key in ("edge_types", "available_edge_types", "edge_type_distribution"):
                val = result.get(key)
                if isinstance(val, list):
                    result[key] = [t for t in val if t != "<UNK>"]
                elif isinstance(val, dict):
                    result[key] = {k: v for k, v in val.items() if k != "<UNK>"}
        return json.dumps(result)
    except (json.JSONDecodeError, TypeError):
        return raw


@mcp.tool()
async def oracle_list_nodes(node_type: str = "all", limit: int = 20) -> str:
    """Browse nodes in the loaded graph, optionally filtered by type."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "list_nodes",
        {"node_type": node_type, "limit": limit},
        _tool="oracle_list_nodes",
    )


@mcp.tool()
async def oracle_get_node(query: str) -> str:
    """Look up an infrastructure component by description (e.g., 'production database' or 'API gateway'). Returns the closest match with its type, properties, and connections."""
    if not query or not query.strip():
        return json.dumps(
            {"error": "invalid_query", "message": "query cannot be empty."}
        )
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call("get_node", {"query": query}, _tool="oracle_get_node")


@mcp.tool()
async def oracle_search_nodes(
    node_description: str, node_type: str = "all", top_k: int = 10
) -> str:
    """Search for infrastructure components by description. Returns the closest matches ranked by relevance."""
    if not node_description or not node_description.strip():
        return json.dumps(
            {"error": "invalid_query", "message": "node_description cannot be empty."}
        )
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "search_nodes",
        {
            "node_description": node_description,
            "node_type": node_type,
            "top_k": top_k,
        },
        _tool="oracle_search_nodes",
    )


@mcp.tool()
async def oracle_tm_add_node(name: str, description: str, node_type: str) -> str:
    """Add a node to the threat model.

    node_type must be a valid infrastructure type (e.g. 'service', 'credential',
    'iam_role', 'http_endpoint', 's3_bucket', 'container', 'function').
    Use oracle_graph_info() to see the full list of types in the loaded graph.
    Description should be specific enough to match against real infrastructure components.
    """
    guard = await _require_loaded_graph()
    if guard:
        return guard
    if not name or not name.strip():
        return json.dumps(
            {"error": "invalid_name", "message": "Node name cannot be empty."}
        )
    if not description or not description.strip():
        return json.dumps(
            {
                "error": "invalid_description",
                "message": "Node description cannot be empty.",
            }
        )
    if node_type not in VALID_NODE_TYPES:
        return json.dumps(
            {
                "error": "invalid_node_type",
                "message": f"Invalid node_type '{node_type}'. Must be one of: {', '.join(sorted(VALID_NODE_TYPES))}",
            }
        )
    return await _oracle_call(
        "tm_add_node",
        {
            "name": name,
            "description": description,
            "node_type": node_type,
        },
        _tool="oracle_tm_add_node",
    )


@mcp.tool()
async def oracle_tm_add_edge(
    source: str, target: str, edge_type: str, description: str
) -> str:
    """Add a connection to your threat model. Describes how an attacker would move between two components."""
    if not source or not source.strip():
        return json.dumps(
            {"error": "invalid_source", "message": "Edge source cannot be empty."}
        )
    if not target or not target.strip():
        return json.dumps(
            {"error": "invalid_target", "message": "Edge target cannot be empty."}
        )
    if not description or not description.strip():
        return json.dumps(
            {
                "error": "invalid_description",
                "message": "Edge description cannot be empty.",
            }
        )
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "tm_add_edge",
        {
            "source": source,
            "target": target,
            "edge_type": edge_type,
            "description": description,
        },
        _tool="oracle_tm_add_edge",
    )


@mcp.tool()
async def oracle_tm_show() -> str:
    """View the current threat model (nodes and edges)."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call("tm_show", _tool="oracle_tm_show")


@mcp.tool()
async def oracle_tm_clear() -> str:
    """Clear the current threat model. This removes all nodes and edges and cannot be undone."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call("tm_clear", _tool="oracle_tm_clear")


@mcp.tool()
async def oracle_tm_match(top_k: int = 5) -> str:
    """Compare your threat model against real infrastructure to find matching attack paths. Returns a diagram showing which components exist in your environment, the paths between them, and how difficult each step would be for an attacker."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call("tm_match", {"top_k": top_k}, _tool="oracle_tm_match")


@mcp.tool()
async def oracle_tm_match_refine(top_k: int = 5, max_iterations: int = 3) -> str:
    """Refine the threat model match by testing multiple attack entry points and scoring each path. Returns a detailed per-step breakdown showing which paths are most feasible and where security controls were detected. Run this before submitting paths."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "tm_match_refine",
        {
            "top_k": top_k,
            "max_iterations": max_iterations,
        },
        _tool="oracle_tm_match_refine",
    )


@mcp.tool()
async def oracle_submit_attack_path(nodes: str, description: str = "") -> str:
    """Submit a discovered attack path as a chain of node descriptions (separated by ' -> '). The path is scored for feasibility and forwarded to triage.

    Args:
        nodes: Node descriptions separated by ' -> '. Example: "public API gateway -> auth service -> database credentials -> production DB"
        description: Optional description of the attack path.
    """
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "submit_attack_path",
        {
            "nodes": nodes,
            "description": description,
        },
        _tool="oracle_submit_attack_path",
    )


@mcp.tool()
async def oracle_submit_matched_path(description: str = "") -> str:
    """Submit attack paths from the current threat model's matched nodes. Requires tm_match or tm_match_refine to have been run first."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "submit_matched_path",
        {"description": description},
        _tool="oracle_submit_matched_path",
    )


@mcp.tool()
async def oracle_tm_list_templates(category: str = "") -> str:
    """List available threat model templates. Categories: identity, network, data, supply_chain, cloud_services."""
    guard = await _require_loaded_graph()
    if guard:
        return guard
    params = {}
    if category:
        params["category"] = category
    return await _oracle_call(
        "tm_list_templates", params, _tool="oracle_tm_list_templates"
    )


@mcp.tool()
async def oracle_tm_load_template(name: str) -> str:
    """Load a saved threat model template by name. WARNING: replaces the current threat model entirely.

    Call oracle_tm_show() first if you want to preserve the current model.
    Use oracle_tm_list_templates() to see available templates.
    """
    guard = await _require_loaded_graph()
    if guard:
        return guard
    return await _oracle_call(
        "tm_load_template", {"name": name}, _tool="oracle_tm_load_template"
    )


@mcp.tool()
async def oracle_tm_save(
    name: str, description: str, category: str, source_template: str = ""
) -> str:
    """Save the current threat model as a reusable template.

    Args:
        name: Template name (kebab-case, e.g. 'refined-iam-escalation-aws-prod').
        description: What this attack pattern does.
        category: One of: identity, network, data, supply_chain, cloud_services.
        source_template: Name of the seed template this was refined from, if any.
    """
    guard = await _require_loaded_graph()
    if guard:
        return guard
    params: dict[str, Any] = {
        "name": name,
        "description": description,
        "category": category,
    }
    if source_template:
        params["source_template"] = source_template
    return await _oracle_call("tm_save", params, _tool="oracle_tm_save")


@mcp.tool()
async def oracle_reset_session() -> str:
    """Destroy the current oracle session and start fresh on the next tool call."""
    global _oracle_session, _load_branch_id, _encoding_started_at, _graph_loaded
    _load_branch_id = None
    _encoding_started_at = None
    _graph_loaded = False
    if _oracle_session:
        try:
            await _delete(
                f"/api/oracle/sessions/{_oracle_session}", _tool="oracle_reset_session"
            )
        except Exception:
            pass
        _oracle_session = None
    return json.dumps({"status": "session reset"})


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
