"""Latent Defense MCP server — full API access via stdio transport."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
import uuid
from typing import Any

from mcp.server.fastmcp import FastMCP

import httpx

from .auth import DeviceFlowPending
from .client import get_token_manager, make_client, _base_url as get_base_url, _verify_ssl as get_verify_ssl
from .energy_cache import EnergyGraphCache
from .errors import McpApiError, handle_response
from .telemetry import emit_mcp_call_event, fire_and_forget

log = logging.getLogger("latent-defense-mcp")


class InstrumentedFastMCP(FastMCP):
    """FastMCP subclass that records one mcp_call_event per tool invocation."""

    async def call_tool(self, name: str, arguments: dict) -> Any:
        t0 = time.monotonic()
        success = True
        error_type: str | None = None
        try:
            return await super().call_tool(name, arguments)
        except Exception as exc:
            success = False
            error_type = type(exc).__name__
            raise
        finally:
            fire_and_forget(
                emit_mcp_call_event(
                    _http, name, (time.monotonic() - t0) * 1000, success, error_type
                )
            )


mcp = InstrumentedFastMCP(
    "Latent Defense",
    instructions=(
        "Infrastructure security platform. Use these tools to explore "
        "infrastructure graphs, trigger mapping scans, run attack path analysis, "
        "triage attack paths, dispatch validation, and investigate security "
        "findings with energy-based structural analysis."
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
_energy_cache: EnergyGraphCache | None = None

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
        if getattr(_client, "is_closed", False):
            _client = None  # Recreate below
        else:
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

    For local cache substring search use `grep_nodes`, or
    `energy_node_scores` for energy-aware search.
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

    Create and execute a mapping run with full control over scan scope and configuration.

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


def _project_path_list(
    result: Any, *, summary: bool, limit: int, offset: int
) -> Any:
    """Shared post-processing for the `/api/triage/paths` list response used by
    list_attack_paths (with optional node_id filter). When `summary` is on, projects
    each path to a compact entry (path_id/status/risk_score/nodes/...); either
    way stamps `has_more` for pagination."""
    if summary and isinstance(result, dict):
        total = result.get("total", 0)
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
                entry: dict[str, Any] = {
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
                if p.get("user_risk_score") is not None:
                    entry["user_risk_score"] = p["user_risk_score"]
                    entry["user_risk_score_reason"] = p.get("user_risk_score_reason")
                summarized.append(entry)
            result = {
                "items": summarized,
                "total": total,
                "has_more": offset + limit < total,
            }
    elif isinstance(result, dict) and "total" in result:
        result["has_more"] = offset + limit < result["total"]
    return result


@mcp.tool()
async def list_attack_paths(
    status: str = "",
    min_risk_score: float = 0,
    limit: int = 20,
    offset: int = 0,
    summary: bool = True,
    order: str = "",
    repository_id: str = "",
    mitre_technique: str = "",
    source_detection_id: str = "",
    rescored: bool = False,
    rescored_window_hours: int | None = None,
    node_id: str = "",
    branch_id: str = "",
) -> str:
    """List attack paths, optionally filtered by status, risk score, repository, MITRE technique,
    node, or branch.

    Use ``status=superseded`` to list paths eliminated by re-scoring (system-dismissed,
    not operator-dismissed). Superseded paths should not be acted on with dismiss_path.

    Pass ``node_id`` to find attack paths that flow through a specific node (chokepoint
    analysis, CVE assessment). Pass ``branch_id`` to list paths stored on a branch before
    triage review.

    Args:
        status: Filter by status. Values: new, acknowledged, validating, validated, ticketed, closed, failed, false_positive, superseded.
        min_risk_score: Only return paths with risk_score >= this value.
        limit: Maximum paths to return (1–500, default 20).
        offset: Pagination offset.
        summary: True (default) returns compact summaries; False returns full path objects with step details.
        order: Sort order — risk_score_desc (default), risk_score_asc, created_at_desc, created_at_asc.
        repository_id: Filter to a single repository.
        mitre_technique: Filter to paths that include this MITRE technique ID (e.g. "T1078").
        source_detection_id: Filter to paths produced from a specific detection finding.
        rescored: When True, narrow to paths a recent re-grade acted on (the "recently
            re-scored" queue). Default False preserves the current view.
        rescored_window_hours: How far back "recently" reaches, in hours (only meaningful
            with rescored=True). Must be > 0 and <= 8760 (1 year). Omit to use the server default (72h).
        node_id: Filter to paths that pass through this node (by node name). For
            chokepoint reasoning and CVE assessment.
        branch_id: When provided, lists paths stored on this branch (pre-triage)
            via GET /api/infra/branches/{branch_id}/attack-paths.
    """
    # Branch-scoped: use the infra endpoint directly
    if branch_id:
        result = await _get(
            f"/api/infra/branches/{branch_id}/attack-paths",
            _tool="list_attack_paths",
        )
        return json.dumps(result)

    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if status:
        params["status"] = status
    if min_risk_score > 0:
        params["min_risk_score"] = min_risk_score
    if order:
        params["order"] = order
    if repository_id:
        params["repository_id"] = repository_id
    if mitre_technique:
        params["mitre_technique"] = mitre_technique
    if source_detection_id:
        params["source_detection_id"] = source_detection_id
    if rescored:
        params["rescored"] = rescored
    if rescored_window_hours is not None:
        params["rescored_window_hours"] = rescored_window_hours
    if node_id:
        params["node_id"] = node_id
    result = await _get("/api/triage/paths", _tool="list_attack_paths", **params)
    return json.dumps(_project_path_list(result, summary=summary, limit=limit, offset=offset))


@mcp.tool()
async def get_attack_path(path_id: str) -> str:
    """Get full details of an attack path including steps, MITRE mappings, risk score,
    and reassessment history.

    The response includes ``reassessment_history`` (ordered re-grade timeline)
    and ``risk_score_model`` (which scoring model produced the risk score).
    Use ``reassessment_history[-1]`` for RE-SCORED badge logic (risk_before,
    risk_after, applied_at). Use ``get_triage_config`` for the display threshold.
    """
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
async def dismiss_path(
    path_id: str,
    reason: str,
    note: str = "",
    expires_at: str = "",
) -> str:
    """Dismiss an attack path as a false positive with a structured reason.

    Do not use on superseded paths — those were system-dismissed by re-scoring,
    not operator-dismissed. Use ``list_attack_paths(status="superseded")`` to
    view them separately.

    Args:
        path_id: Attack path ID. Must be in 'validated' or 'acknowledged' state.
        reason: Dismiss reason — one of: compensating_control, network_segmentation,
                service_decommissioned, risk_accepted, not_applicable, other.
        note: Optional free-text explanation.
        expires_at: Optional ISO-8601 datetime after which the dismissal expires and the
                    path reopens automatically (e.g. "2027-01-01T00:00:00Z").
    """
    body: dict[str, Any] = {"reason": reason}
    if note:
        body["note"] = note
    if expires_at:
        body["expires_at"] = expires_at
    return json.dumps(
        await _post(f"/api/triage/paths/{path_id}/dismiss", body, _tool="dismiss_path")
    )


@mcp.tool()
async def undismiss_path(path_id: str, reason: str, note: str = "") -> str:
    """Reopen a dismissed (false-positive) attack path back into the triage queue.

    Moves a path from 'false_positive' to 'acknowledged', which clears the
    dismissal server-side (dismiss_reason/note/expiry are reset) and restores
    the original risk score. There is no dedicated undismiss endpoint: this is
    a thin wrapper over PATCH /api/triage/paths/{id}/status. The reason and note
    are attached to the resulting status_change event so the reopen is
    attributed and auditable.

    Args:
        path_id: Attack path ID. Must be in 'false_positive' state; reopening from any
                 other state is rejected by the triage state machine (422).
        reason: Required explanation for reopening (logged on the status_change event for audit).
        note: Optional free-text detail added alongside the reason.
    """
    if not path_id.strip():
        return json.dumps({"error": "path_id is required"})
    if not reason.strip():
        return json.dumps({"error": "reason is required"})
    body: dict[str, Any] = {
        "status": "acknowledged",
        "metadata": {"reopen_reason": reason},
    }
    if note:
        body["note"] = note
    return json.dumps(
        await _patch(
            f"/api/triage/paths/{path_id}/status", body, _tool="undismiss_path"
        )
    )


@mcp.tool()
async def bulk_update_paths(
    action: str,
    status_filter: str = "",
    min_risk_score: float = 0,
    repository_id: str = "",
    reason: str = "",
    note: str = "",
    limit: int = 50,
) -> str:
    """Apply a triage action to multiple paths that match a filter in a single call.

    Args:
        action: Action to apply — acknowledge, dismiss, or close.
        status_filter: Only act on paths in this status (e.g. "validated"). Leave empty to use the
                       action-compatible defaults: acknowledge→new,failed; dismiss→acknowledged,validated;
                       close→new,acknowledged,validating,validated,ticketed,failed.
        min_risk_score: Only act on paths with risk_score >= this value.
        repository_id: Only act on paths from this repository.
        reason: Required for action=dismiss. Dismiss reason — one of: compensating_control,
                network_segmentation, service_decommissioned, risk_accepted, not_applicable, other.
        note: Optional note applied to every path.
        limit: Maximum paths to update (1–200, default 50).
    """
    if not action:
        return json.dumps({"error": "action is required"})
    if action not in {"acknowledge", "dismiss", "close"}:
        return json.dumps({"error": f"Invalid action '{action}'. Must be acknowledge, dismiss, or close."})
    if action == "dismiss" and not reason:
        return json.dumps({"error": "reason is required when action=dismiss"})
    # Pre-validate action/status_filter compatibility against the triage state machine.
    # acknowledge is only reachable from new, failed, false_positive (FORWARD_TRANSITIONS).
    # close is reachable from every non-terminal status.
    _VALID_SOURCES: dict[str, set[str]] = {
        "acknowledge": {"new", "failed", "false_positive"},
        "close": {"new", "acknowledged", "validating", "validated", "ticketed", "failed", "false_positive"},
        "dismiss": {"acknowledged", "validated"},
    }
    if status_filter and action in _VALID_SOURCES and status_filter not in _VALID_SOURCES[action]:
        valid = sorted(_VALID_SOURCES[action])
        return json.dumps({
            "error": (
                f"action='{action}' cannot be applied to paths in status='{status_filter}'. "
                f"Valid source statuses: {valid}"
            )
        })
    if limit > 200:
        limit = 200

    # When no status_filter is given, restrict to states the action can reach.
    # This prevents predictable partial failures (e.g. dismiss applied to new paths).
    _DEFAULT_STATUS: dict[str, str] = {
        "acknowledge": "new,failed",
        "dismiss": "acknowledged,validated",
        # Exclude closed/superseded (terminal) so we don't attempt closed→closed.
        "close": "new,acknowledged,validating,validated,ticketed,failed",
    }
    effective_status = status_filter or _DEFAULT_STATUS.get(action, "")

    list_params: dict[str, Any] = {"limit": limit, "offset": 0}
    if effective_status:
        list_params["status"] = effective_status
    if min_risk_score > 0:
        list_params["min_risk_score"] = min_risk_score
    if repository_id:
        list_params["repository_id"] = repository_id

    list_result = await _get("/api/triage/paths", _tool="bulk_update_paths", **list_params)
    if not isinstance(list_result, dict):
        return json.dumps({"error": "Failed to fetch paths", "detail": list_result})

    items = list_result.get("items", [])
    results = []
    for p in items:
        if not isinstance(p, dict):
            continue
        path_id = p.get("path_id")
        if not path_id:
            continue
        try:
            if action == "acknowledge":
                body: dict[str, Any] = {"status": "acknowledged"}
                if note:
                    body["note"] = note
                res = await _patch(f"/api/triage/paths/{path_id}/status", body, _tool="bulk_update_paths")
            elif action == "dismiss":
                body = {"reason": reason}
                if note:
                    body["note"] = note
                res = await _post(f"/api/triage/paths/{path_id}/dismiss", body, _tool="bulk_update_paths")
            else:  # close
                body = {"status": "closed"}
                if note:
                    body["note"] = note
                res = await _patch(f"/api/triage/paths/{path_id}/status", body, _tool="bulk_update_paths")
            results.append({"path_id": path_id, "success": True})
        except Exception as exc:
            results.append({"path_id": path_id, "success": False, "error": str(exc)})

    succeeded = sum(1 for r in results if r["success"])
    return json.dumps({
        "action": action,
        "total_matched": list_result.get("total", len(items)),
        "applied_to": len(results),
        "succeeded": succeeded,
        "failed": len(results) - succeeded,
        "results": results,
    })


@mcp.tool()
async def override_risk_score(path_id: str, risk_score: float, reason: str) -> str:
    """Override the computed risk score on an attack path.

    The model score (risk_score) is preserved; user_risk_score is used for
    display and sorting until cleared. Emits a severity_change event.

    Args:
        path_id: Attack path ID.
        risk_score: New risk score (0–100).
        reason: Required explanation for the override (logged for audit).
    """
    body: dict[str, Any] = {"risk_score": risk_score, "reason": reason}
    return json.dumps(
        await _post(f"/api/triage/paths/{path_id}/override-risk", body, _tool="override_risk_score")
    )


@mcp.tool()
async def clear_risk_override(path_id: str) -> str:
    """Remove a user risk score override; sorting reverts to the model score.

    Args:
        path_id: Attack path ID.
    """
    return json.dumps(
        await _delete(f"/api/triage/paths/{path_id}/override-risk", _tool="clear_risk_override")
    )


@mcp.tool()
async def add_path_comment(
    path_id: str,
    text: str,
    author: str = "",
    parent_comment_id: str = "",
    parent_event_id: str = "",
) -> str:
    """Add a comment to an attack path.

    Persists a new comment on the attack path. Comments are returned by
    ``list_path_history``
    (use ``include="comments"`` for comments only).

    Agent attribution (``author_kind: "agent"``) is stamped automatically —
    MCP comments are always agent-authored.

    Args:
        path_id: Attack path ID.
        text: Comment text.
        author: Optional display name. Defaults to the authenticated identity.
        parent_comment_id: Reply to another comment (one-level threading).
            Pass the target comment's ``comment_id``.
        parent_event_id: Reply to a history event (dismissal, re-grade) that
            is not itself a comment. Mutually exclusive with parent_comment_id.
    """
    from datetime import datetime, timezone

    if not path_id.strip():
        return json.dumps({"error": "path_id is required"})
    if not text.strip():
        return json.dumps({"error": "text is required"})

    comment_id = uuid.uuid4().hex
    now = datetime.now(timezone.utc).isoformat()

    data: dict[str, Any] = {
        "comment_id": comment_id,
        "path_id": path_id,
        "text": text,
        "at": now,
        "author_kind": "agent",
        "agent_name": "claude",
    }
    if author:
        data["author"] = author
    if parent_comment_id:
        data["parent_comment_id"] = parent_comment_id
    elif parent_event_id:
        data["parent_event_id"] = parent_event_id

    result = await _post(
        "/api/infra/records",
        {
            "record_type": "triage_path_comment",
            "key_id": comment_id,
            "parent_key_id": path_id,
            "data": data,
        },
        _tool="add_path_comment",
    )
    if isinstance(result, dict) and (
        result.get("status") == "authentication_required" or "error" in result
    ):
        return json.dumps(result)
    return json.dumps(data)


@mcp.tool()
async def list_path_history(path_id: str, include: str = "all") -> str:
    """Return the unified timeline for an attack path.

    Includes status changes, score changes, and comments in chronological order.
    Use this to audit what happened to a path and why.

    Comments are merged from all available sources, deduplicated, and
    returned oldest-first.

    Args:
        path_id: Attack path ID.
        include: What to include — "all" (default) returns the full timeline;
            "comments" returns only comments (filters out status/score changes).
    """
    # --- 1. Fetch the history timeline (status changes, score changes, etc.) ---
    history_result = await _get(
        f"/api/triage/paths/{path_id}/history", _tool="list_path_history"
    )
    # Normalise to a flat list of events.
    if isinstance(history_result, list):
        history_events = history_result
    elif isinstance(history_result, dict):
        history_events = history_result.get("events", history_result.get("items", []))
        if not isinstance(history_events, list):
            history_events = []
    else:
        history_events = []

    # --- 2. Fetch comment records ---
    _RECORDS_PAGE = 500
    infradb_records: list[Any] = []
    offset = 0
    while True:
        records_resp = await _get(
            "/api/infra/records",
            _tool="list_path_history",
            record_type="triage_path_comment",
            parent_key_id=path_id,
            limit=_RECORDS_PAGE,
            offset=offset,
        )
        if (
            isinstance(records_resp, dict)
            and records_resp.get("status") == "authentication_required"
        ):
            return json.dumps(records_resp)
        if not isinstance(records_resp, dict):
            break
        page = records_resp.get("records", [])
        if not isinstance(page, list):
            break
        infradb_records.extend(page)
        if not page:
            break
        total = records_resp.get("total")
        got = len(infradb_records)
        if type(total) is int:
            if got >= total:
                break
        elif len(page) < _RECORDS_PAGE:
            break
        offset += len(page)

    # --- 3. Fetch legacy triage comments (pre-move, 404-safe) ---
    legacy_comments: list[Any] = []
    try:
        legacy = await _get(
            f"/api/triage/paths/{path_id}/comments", _tool="list_path_history"
        )
        if isinstance(legacy, dict) and legacy.get("status") == "authentication_required":
            return json.dumps(legacy)
        if isinstance(legacy, list):
            legacy_comments = legacy
    except McpApiError as e:
        if e.status != 404:
            raise
        log.warning("list_path_history: no legacy triage comments for %s (404)", path_id)

    # --- 4. Merge & dedup comments from all three sources ---
    def _first_present(d: dict[str, Any], *keys: str) -> Any:
        for k in keys:
            if k in d and d[k] is not None:
                return d[k]
        return None

    merged_comments: dict[str, dict[str, Any]] = {}
    comment_order: list[str] = []

    def _add_comment(comment: dict[str, Any], source: str) -> None:
        cid = comment.get("comment_id")
        key = str(cid) if cid is not None else f"_anon_{source}_{len(comment_order)}"
        if key in merged_comments:
            return
        merged_comments[key] = {
            "event_type": "comment",
            "comment_id": cid,
            "path_id": comment.get("path_id", path_id),
            "actor": comment.get("actor"),
            "author": comment.get("author"),
            "author_kind": comment.get("author_kind"),
            "agent_name": comment.get("agent_name"),
            "text": comment.get("text"),
            "created_at": comment.get("created_at"),
            "at": comment.get("at") or comment.get("created_at"),
            "parent_comment_id": comment.get("parent_comment_id"),
            "parent_event_id": comment.get("parent_event_id"),
            "source": source,
        }
        comment_order.append(key)

    # Database records (authoritative — added first so they win dedup).
    for rec in infradb_records:
        if not isinstance(rec, dict):
            continue
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        created_at = _first_present(data, "at", "created_at")
        if created_at is None:
            created_at = rec.get("created_at")
        comment_id = _first_present(data, "comment_id")
        if comment_id is None:
            comment_id = rec.get("key_id")
        _add_comment(
            {
                "comment_id": comment_id,
                "path_id": data.get("path_id") or rec.get("parent_key_id") or path_id,
                "actor": data.get("actor"),
                "author": data.get("author"),
                "author_kind": data.get("author_kind"),
                "agent_name": data.get("agent_name"),
                "text": data.get("text"),
                "created_at": created_at,
                "at": created_at,
                "parent_comment_id": data.get("parent_comment_id"),
                "parent_event_id": data.get("parent_event_id"),
            },
            "infradb",
        )

    # Legacy triage comments.
    for c in legacy_comments:
        if isinstance(c, dict):
            ts = _first_present(c, "created_at", "at")
            _add_comment(
                {
                    "comment_id": c.get("comment_id"),
                    "path_id": c.get("path_id", path_id),
                    "actor": c.get("actor"),
                    "author": c.get("author"),
                    "author_kind": c.get("author_kind"),
                    "agent_name": c.get("agent_name"),
                    "text": c.get("text"),
                    "created_at": ts,
                    "at": ts,
                    "parent_comment_id": c.get("parent_comment_id"),
                    "parent_event_id": c.get("parent_event_id"),
                },
                "triage",
            )

    # History-endpoint comments (lowest priority — skipped if already merged from
    # infrastructure database or legacy).
    for ev in history_events:
        if isinstance(ev, dict) and ev.get("event_type") == "comment":
            ts = ev.get("at") or ev.get("created_at")
            _add_comment(
                {
                    "comment_id": ev.get("comment_id"),
                    "path_id": ev.get("path_id", path_id),
                    "actor": ev.get("actor"),
                    "author": ev.get("author"),
                    "author_kind": ev.get("author_kind"),
                    "agent_name": ev.get("agent_name"),
                    "text": ev.get("text"),
                    "created_at": ts,
                    "at": ts,
                    "parent_comment_id": ev.get("parent_comment_id"),
                    "parent_event_id": ev.get("parent_event_id"),
                },
                "history",
            )

    all_comments = list(merged_comments.values())
    all_comments.sort(
        key=lambda c: (c.get("at") is None, str(c.get("at") or ""))
    )

    # --- 5. Return based on include filter ---
    if include == "comments":
        return json.dumps(all_comments)

    # include="all": merge comments into the full history timeline, deduplicating
    # any comment events already in history_events.
    seen_comment_ids = {c.get("comment_id") for c in all_comments if c.get("comment_id")}
    non_comment_events = [
        ev for ev in history_events
        if not isinstance(ev, dict)
        or ev.get("event_type") != "comment"
    ]
    # Also drop history comment events that were already merged (to avoid dupes).
    for ev in history_events:
        if (
            isinstance(ev, dict)
            and ev.get("event_type") == "comment"
            and ev.get("comment_id") not in seen_comment_ids
        ):
            non_comment_events.append(ev)

    combined = non_comment_events + all_comments
    combined.sort(
        key=lambda e: (
            e.get("at", e.get("created_at")) is None,
            str(e.get("at", e.get("created_at")) or ""),
        )
    )
    return json.dumps(combined)


@mcp.tool()
async def edit_path_comment(path_id: str, comment_id: str, text: str) -> str:
    """Edit the text of an existing comment on an attack path.

    Appends a new revision — does not overwrite. The
    previous revision stays in the database untouched, preserving a full edit trail.
    Appends a new revision — does not overwrite.

    Authorship is enforced server-side: a write that supersedes
    another user's revision is rejected with HTTP 403.

    Args:
        path_id: Attack path ID the comment is on.
        comment_id: Logical comment id to edit (stable across edits).
        text: The new comment text.
    """
    from datetime import datetime, timezone

    if not path_id.strip():
        return json.dumps({"error": "path_id is required"})
    if not comment_id.strip():
        return json.dumps({"error": "comment_id is required"})
    if not text.strip():
        return json.dumps({"error": "text is required"})

    _RECORDS_PAGE = 500
    records: list[Any] = []
    offset = 0
    while True:
        resp = await _get(
            "/api/infra/records",
            _tool="edit_path_comment",
            record_type="triage_path_comment",
            parent_key_id=path_id,
            limit=_RECORDS_PAGE,
            offset=offset,
        )
        if isinstance(resp, dict) and resp.get("status") == "authentication_required":
            return json.dumps(resp)
        if not isinstance(resp, dict):
            break
        page = resp.get("records", [])
        if not isinstance(page, list):
            break
        records.extend(page)
        if not page:
            break
        total = resp.get("total")
        if type(total) is int:
            if len(records) >= total:
                break
        elif len(page) < _RECORDS_PAGE:
            break
        offset += len(page)

    def _fp(d: dict[str, Any], *keys: str) -> Any:
        for k in keys:
            if k in d and d[k] is not None:
                return d[k]
        return None

    def _revision_at(data: dict[str, Any]) -> str:
        for k in ("edited_at", "at"):
            if k in data and data[k] is not None:
                return str(data[k]).replace("+00:00", "Z")
        return ""

    current_key: str | None = None
    current_data: dict[str, Any] | None = None
    best_at: str | None = None
    for rec in records:
        if not isinstance(rec, dict):
            continue
        data = rec.get("data") if isinstance(rec.get("data"), dict) else {}
        rec_comment_id = _fp(data, "comment_id", "revision_id")
        if rec_comment_id is None:
            rec_comment_id = rec.get("key_id")
        if str(rec_comment_id) != str(comment_id):
            continue
        at = _revision_at(data)
        if best_at is None or at > best_at:
            best_at = at
            current_key = rec.get("key_id")
            current_data = data

    if current_data is None or current_key is None:
        return json.dumps(
            {"error": f"comment '{comment_id}' not found on path '{path_id}'"}
        )

    new_revision_id = uuid.uuid4().hex
    resolved_comment_id = _fp(current_data, "comment_id", "revision_id")
    if resolved_comment_id is None:
        resolved_comment_id = current_key
    new_data = {
        **current_data,
        "comment_id": str(resolved_comment_id),
        "path_id": current_data.get("path_id", path_id),
        "text": text,
        "revision_id": new_revision_id,
        "supersedes": current_key,
        "edited_at": datetime.now(timezone.utc).isoformat(),
    }

    result = await _post(
        "/api/infra/records",
        {
            "record_type": "triage_path_comment",
            "key_id": new_revision_id,
            "parent_key_id": path_id,
            "data": new_data,
        },
        _tool="edit_path_comment",
    )
    if isinstance(result, dict) and (
        result.get("status") == "authentication_required" or "error" in result
    ):
        return json.dumps(result)
    return json.dumps(new_data)


@mcp.tool()
async def triage_stats(repository_id: str = "", view: str = "summary") -> str:
    """Get triage statistics (counts by status, severity, repository).

    Args:
        repository_id: Filter to a single repository. Empty for all.
        view: "summary" (default) returns overall triage stats; "classification"
            returns the classification breakdown (attack path type distribution).
    """
    params: dict[str, Any] = {}
    if repository_id:
        params["repository_id"] = repository_id
    endpoint = "/api/triage/stats/classification" if view == "classification" else "/api/triage/stats"
    return json.dumps(await _get(endpoint, _tool="triage_stats", **params))


@mcp.tool()
async def get_triage_config() -> str:
    """Get triage display configuration.

    Returns the rescore display threshold and any other published config.
    Use this to apply the re-score badge display logic
    when deciding whether a risk score change is worth reporting.
    """
    return json.dumps(
        await _get("/api/triage/config", _tool="get_triage_config")
    )


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
        "severity_change",
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
    """Start a background task that pings the analysis session every 10 min.

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
    import time as _time

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
            elapsed = int(_time.time() - _encoding_started_at)
            return json.dumps(
                {
                    "status": "loading",
                    "elapsed_secs": elapsed,
                    "message": (
                        f"Graph is still loading ({elapsed}s elapsed). "
                        "Call load_graph_energies to reload."
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
        log.warning(
            "Analysis session expired (30-minute idle timeout). "
            "Creating a new session. You will need to reload your "
            "graph with load_graph_energies().",
        )
        await _ensure_oracle_session()
        return json.dumps(
            {
                "error": "session_expired",
                "message": (
                    "Your analysis session expired after 30 minutes of inactivity. "
                    "A new session has been created, but you need to reload your "
                    "graph by calling load_graph_energies() before running other "
                    "analysis tools."
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
                "message": "No graph is loaded. Call load_graph_energies first.",
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
                    "Wait for load_graph_energies to complete."
                ),
            }
        )
    return json.dumps(
        {
            "status": "loading",
            "message": (
                "The graph is still loading. Wait for load_graph_energies to complete."
            ),
        }
    )


@mcp.tool()
async def load_branch(branch_id: str) -> str:
    """Load an infrastructure graph branch and start encoding.

    Triggers the encoder to process the graph. For large graphs (1000+
    nodes), encoding takes 2-10 minutes. Call wait_for_load() to block until
    encoding completes, then load_graph_energies() to fetch the energy scores
    into the local cache.

    Quick path: load_graph_energies(branch_id) handles load_branch +
    wait_for_load + energy fetch in one call. Use the separate tools when
    you need progress visibility during encoding (e.g., in workflows).

    Args:
        branch_id: The branch to load.
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
                "load_graph_energies handles waiting automatically."
            ),
        }
    )


async def _format_encoding_progress() -> str:
    """Poll the inference server for encoding progress and return a formatted JSON response."""
    progress = await _fetch_encoding_progress()
    if progress and progress.get("stage") is not None:
        # Encoding pipeline stages — update when the inference server changes.
        stage_names = {
            0: "queued", 1: "fetching graph from infrastructure database",
            2: "checking cache", 3: "computing structural features",
            4: "computing embeddings", 5: "computing relationships",
            6: "encoding graph structure", 7: "building adjacency index",
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
async def wait_for_load(timeout_secs: int = 600, poll_interval: int = 30) -> str:
    """Wait for graph encoding to complete after load_branch().

    Blocks until the encoder finishes processing the graph, reporting
    progress at each poll interval. Returns when the graph is ready for
    energy analysis.

    Quick path: load_graph_energies(branch_id) handles load_branch +
    wait_for_load + energy fetch in one call. Use the separate tools when
    you need progress visibility during encoding (e.g., in workflows).

    Args:
        timeout_secs: Maximum wait time in seconds (default 600).
        poll_interval: Seconds between progress checks (default 30).
    """
    import asyncio
    import time

    global _graph_loaded, _encoding_started_at

    if _load_branch_id is None:
        return json.dumps(
            {
                "status": "no_load_in_progress",
                "message": "No load_branch call has been made. Call load_graph_energies first.",
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
                "server-side. Try calling load_graph_energies to retry."
            ),
        }
    )


@mcp.tool()
async def submit_attack_path(
    nodes: str, description: str = "", report: str = ""
) -> str:
    """Submit a discovered attack path as a chain of node descriptions (separated by ' -> '). The path is scored for feasibility and forwarded to triage. Include a report with your full analysis — it travels downstream to triage and the validator.

    Args:
        nodes: Node descriptions separated by ' -> '. Example: "public API gateway -> auth service -> database credentials -> production DB"
        description: Optional description of the attack path.
        report: Full attack path analysis report (markdown). Should include: executive summary, per-hop energy analysis, attack chain context, evidence citations, MITRE ATT&CK annotations, and risk assessment. This report travels downstream to triage and the validator — all reasoning must be captured here.
    """
    # If the energy cache is loaded (e.g. from disk) but the inference
    # session was never established, warm it up so _require_loaded_graph
    # and _oracle_call work.
    if not _graph_loaded and _energy_cache is not None and _energy_cache.loaded:
        branch_id = _energy_cache.branch_id
        if branch_id:
            await load_branch(branch_id)
            await wait_for_load(timeout_secs=300)

    guard = await _require_loaded_graph()
    if guard:
        return guard
    params: dict[str, str] = {
        "nodes": nodes,
        "description": description,
    }
    if report:
        params["report"] = report
    return await _oracle_call(
        "submit_attack_path",
        params,
        _tool="submit_attack_path",
    )


# ---------------------------------------------------------------------------
# Prompts — agentic triage workflows that expand into structured instructions
# the calling agent follows using the tools on this server.
# ---------------------------------------------------------------------------


@mcp.prompt(
    title="Review the triage queue",
    description=(
        "Walk the highest-risk untriaged attack paths and decide what to do with "
        "each. Uses list_attack_paths + triage_stats."
    ),
)
def triage_queue_review(
    repository_id: str = "",
    min_risk_score: float = 0,
    status: str = "new",
) -> str:
    """One-click triage queue review — the interactive triage skill as a prompt.

    Args:
        repository_id: Restrict the review to a single repository (default: all).
        min_risk_score: Only surface paths with risk_score >= this value (default: 0).
        status: Restrict the queue to a single triage status (default: "new", the
            untriaged inbox). list_attack_paths' unfiltered default returns every
            status except false_positive — including terminal paths (ticketed,
            closed, failed) that would pollute the queue and can't be actioned — so
            the queue is pinned to "new" here. Pass "" to review every status; the
            prompt still constrains the offered actions to those valid per state.
    """
    # Build the exact list_attack_paths call the agent should make. Every
    # client-supplied string is threaded through json.dumps so a value containing
    # a quote, backslash or newline can't corrupt the example call or inject text
    # into the agent's instruction stream. summary=False so per-step MITRE
    # techniques are available (the summary view collapses steps).
    call_args = ['order="risk_score_desc"', "summary=False", "limit=20"]
    if status:
        call_args.insert(0, f"status={json.dumps(status)}")
    if repository_id:
        call_args.append(f"repository_id={json.dumps(repository_id)}")
    if min_risk_score > 0:
        call_args.append(f"min_risk_score={min_risk_score}")
    list_call = f"list_attack_paths({', '.join(call_args)})"

    stats_arg = f"repository_id={json.dumps(repository_id)}" if repository_id else ""

    scope_bits = [
        f"repository {json.dumps(repository_id)}" if repository_id else "all repositories",
        f"status {json.dumps(status)}" if status else "all statuses",
    ]
    if min_risk_score > 0:
        scope_bits.append(f"risk_score >= {min_risk_score}")
    scope = ", ".join(scope_bits)

    return f"""\
You are reviewing the Latent Defense triage queue ({scope}). Work through it as an
interactive triage session.

1. Load the ranked queue. Call:
       {list_call}
   This returns attack paths ordered highest-risk first. Because `summary=False`,
   each path includes its full step list (with the MITRE technique IDs per step).
   If the response reports `has_more: true` (or `total` exceeds the number of items
   returned), tell me — there are more paths than the top 20 shown and I may want
   to page through the rest with `offset`.

2. Load the queue-level counts. Call:
       triage_stats({stats_arg})
   Use this to frame the review (how many paths are new / validating / validated /
   ticketed / closed).

3. Present the top findings as a ranked list. For each path show:
     - risk_score (and user_risk_score if a manual override is set)
     - entry_node -> target_node
     - the distinct MITRE technique IDs collected from its steps
     - validation status (the path `status` field: new, acknowledged, validating,
       validated, ticketed, closed, failed, false_positive)

4. For each path, ask me what to do and carry out the choice with the tool that is
   valid for that path's current `status`. Skip paths already in a terminal state
   (ticketed, closed, failed, false_positive) — they need no action.
     - acknowledge -> update_path_status(path_id, "acknowledged")   (from `new`)
     - validate    -> validate_path(path_id)                        (from `new` or `acknowledged`)
     - re-score    -> override_risk_score(path_id, risk_score=..., reason=...)
     - dismiss     -> dismiss_path requires the path to be `acknowledged` or
                      `validated`, so if it is still `new` call
                      update_path_status(path_id, "acknowledged") first, then
                      dismiss_path(path_id, reason=...). `reason` must be one of:
                      compensating_control, network_segmentation,
                      service_decommissioned, risk_accepted, not_applicable, other.

Start now with step 1, then summarise the queue before we walk the individual paths.
"""


@mcp.prompt(
    title="Assess CVE exposure",
    description=(
        "Investigate a CVE's exposure across the infrastructure graph. "
        "Uses energy tools (grep_nodes, energy_node_scores, energy_trace_to_target) "
        "and list_attack_paths with node_id filter."
    ),
)
def assess_cve(
    cve_id: str,
    repository_id: str = "",
    branch_id: str = "",
) -> str:
    """Assess the exposure of a specific CVE across the infrastructure.

    Args:
        cve_id: CVE identifier (e.g. "CVE-2024-1234").
        repository_id: Restrict the assessment to a single repository (default: all).
        branch_id: Branch to load for energy analysis (required for energy tools).
    """
    repo_filter = ""
    if repository_id:
        repo_filter = f", repository_id={json.dumps(repository_id)}"

    load_step = ""
    if branch_id:
        load_step = f"""
0. Load the graph with energy scores. Call:
       load_graph_energies(branch_id={json.dumps(branch_id)})
   This loads the graph and energy data into the local cache. All grep_*
   and energy_* tools require this.
"""

    return f"""\
You are assessing the exposure of {json.dumps(cve_id)} across the infrastructure.

**Energy context**: Energy scores represent structural resistance. Negative energy =
low resistance (attacker moves easily). Positive energy = friction (security barrier).
Risk score bands: 0-20 well defended, 20-40 moderate, 40-60 needs attention,
60-80 high priority, 80-100 critical.
{load_step}
1. Find affected nodes. Call:
       grep_nodes(pattern={json.dumps(cve_id)})
   Also try component-level searches (e.g., the library or service named in the CVE).
   If zero results, the CVE may not be present in the current graph — report that
   clearly and stop.

2. Understand structural position of affected nodes. Call:
       energy_node_scores(node_ids=<comma-separated affected node IDs>)
   This shows how much structural resistance surrounds each affected node.

3. For each affected node, find attack paths through it:
       list_attack_paths(node_id=<node_name>{repo_filter})
   Collect all paths. Note the risk scores and validation statuses.

4. Trace paths from affected nodes to sensitive targets. Call:
       energy_trace_to_target(source_id=<affected_node>, target_types="data_store,credential,secrets_manager")
   This shows whether an attacker can reach high-value targets from the vulnerable node.

5. Present an exposure summary:
   - **Affected nodes**: list each node with its type, location, and energy score
   - **Attack paths**: for each path through an affected node, show:
     * risk_score
     * entry_node -> target_node
     * MITRE techniques
     * validation status
   - **Structural assessment**: which nodes have low resistance (negative energy)
     and which have compensating controls (positive energy/braking)
   - **Risk assessment**: highest risk score, number of paths, whether any
     are validated/exploitable
   - **Recommendation**: whether to validate, dismiss, or escalate

Energy scores tell you WHERE to look. They are NOT conclusions. Always verify
version numbers, feature usage, and runtime configuration before declaring
exploitability.

If there are many paths (>20), summarise by risk band and highlight the top 5.
"""


@mcp.prompt(
    title="Chokepoint report",
    description=(
        "Identify infrastructure chokepoints where many attack paths converge. "
        "Uses energy_chokepoints + energy_defenses for structural analysis."
    ),
)
def chokepoint_report(
    branch_id: str = "",
    repository_id: str = "",
    min_paths: int = 3,
) -> str:
    """Identify chokepoints — nodes through which many attack paths flow.

    Args:
        branch_id: Branch to load for energy analysis (required for energy tools).
        repository_id: Restrict the report to a single repository (default: all).
        min_paths: Minimum number of paths a node must appear in to qualify as
            a chokepoint (default: 3).
    """
    repo_filter = ""
    if repository_id:
        repo_filter = f", repository_id={json.dumps(repository_id)}"

    load_step = ""
    if branch_id:
        load_step = f"""
1. Load the graph with energy scores. Call:
       load_graph_energies(branch_id={json.dumps(branch_id)})
"""

    return f"""\
You are generating a chokepoint report for the infrastructure.

**Energy context**: Energy scores represent structural resistance. Negative energy =
low resistance (attacker moves easily). Positive energy = friction (security barrier).
Risk score bands: 0-20 well defended, 20-40 moderate, 40-60 needs attention,
60-80 high priority, 80-100 critical.
{load_step}
2. Find chokepoints using the energy model. Call:
       energy_chokepoints(limit={min_paths})
   This identifies nodes where many attack paths converge based on the
   energy analysis — much faster and more accurate than manual node-frequency
   counting. Filter to nodes appearing in at least {min_paths} paths.

3. Map defense nodes. Call:
       energy_defenses()
   This identifies nodes that provide braking energy (security boundaries,
   auth checks, network segmentation) — the infrastructure's defensive controls.

4. For each chokepoint (sorted by path count descending), get attack path details:
       list_attack_paths(node_id=<node_name>{repo_filter})

5. Present the chokepoint report. For each chokepoint:
   - **Node**: name and type
   - **Path count**: how many attack paths flow through it
   - **Energy profile**: whether the node accelerates or brakes attackers
   - **Nearby defenses**: defense nodes from energy_defenses that protect this chokepoint
   - **Highest risk score**: among the paths through this node
   - **MITRE techniques**: distinct techniques across paths through this node

6. End with a prioritised remediation recommendation:
   - Which chokepoint, if hardened, would eliminate the most high-risk paths?
   - Map each chokepoint to its nearest defense nodes — which defenses already
     provide some protection, and where are the gaps?
   - Estimate the risk reduction (number of paths × average risk score).
"""


@mcp.prompt(
    title="Investigate a finding",
    description=(
        "Five-move investigation method: ground, position, trace, score, verify. "
        "Uses energy tools for structural analysis of a scanner finding."
    ),
)
def investigate_finding(
    finding_description: str,
    branch_id: str,
) -> str:
    """Investigate a scanner finding using the Five Moves method.

    Args:
        finding_description: Description of the finding (CVE, alert, detection).
        branch_id: Branch ID to load for energy analysis.
    """
    return f"""\
You are investigating a security finding using the Five Moves method.

**Finding**: {json.dumps(finding_description)}
**Branch**: {json.dumps(branch_id)}

**Energy context**: Energy scores represent structural resistance — how much the
infrastructure resists or accelerates an attacker along each edge.
- Negative energy (accelerating): low resistance, attacker moves easily
- Positive energy (braking): security barrier creates friction
- Magnitude matters: -3.0 is much less resistance than -0.5

Risk score bands (0-100, momentum model):
- 0-20: strong structural resistance — well defended, not a finding
- 20-40: moderate resistance — worth investigating controls and gaps
- 40-60: low resistance — deserves attention
- 60-80: little resistance — high priority for remediation
- 80-100: almost no resistance — critical

**IMPORTANT**: Energy scores tell you WHERE to look. They are NOT conclusions.
Verify everything against source code, configuration, and cloud state.

## The Five Moves

### Move 1 — Ground
Find the nodes related to this finding in the graph.
    load_graph_energies(branch_id={json.dumps(branch_id)})
    grep_nodes(pattern=<key terms from the finding>)

If zero results, try broader terms (library name, service name, resource type).
If still nothing, the finding may not be represented in the current graph — report
that and stop.

### Move 2 — Position
Understand the structural position of affected nodes.
    energy_node_scores(node_ids=<comma-separated affected node IDs>)
    energy_node_neighborhood(node_id=<primary affected node>)

What is the node connected to? Is it isolated or central? Does it have high
connectivity (many edges) or low? Are there security boundaries nearby?

### Move 3 — Trace
Trace paths from the affected node to sensitive targets.
    energy_trace_to_target(source_id=<affected_node>, target_types="data_store,credential,secrets_manager,database")

Can an attacker reach crown jewels from this node? What resistance do they face?
Which hops accelerate and which brake?

### Move 4 — Score
Score the full path for risk.
    energy_momentum_path(path=<node_id_1,node_id_2,...>)

Use the risk score bands above. Under 20 means the infrastructure defends this path.
Over 40 means it deserves attention.

### Move 5 — Verify
Before concluding, verify against real infrastructure:
- [ ] Check the version number — is the vulnerable version actually deployed?
- [ ] Check feature usage — is the vulnerable feature enabled/used?
- [ ] Check runtime configuration — are there mitigations not in the graph?
- [ ] Check network access — can the attacker actually reach this node?
- [ ] Check authentication — what credentials are needed?

Present your findings with:
1. Structural assessment (energy scores and what they mean)
2. Path analysis (which paths exist, risk scores)
3. Verification status (what you confirmed vs what needs manual verification)
4. Recommendation (validate, dismiss, escalate)
"""


@mcp.prompt(
    title="Research sweep",
    description=(
        "Systematic attack path discovery: entry points, structural queries, "
        "path scoring, and submission. Uses energy tools throughout."
    ),
)
def research_sweep(
    branch_id: str,
    focus_areas: str = "",
) -> str:
    """Systematic discovery of attack paths across the infrastructure.

    Args:
        branch_id: Branch ID to load for energy analysis.
        focus_areas: Comma-separated areas to focus on (e.g. "credentials,iam,ci_cd").
            Empty means sweep everything.
    """
    focus_hint = ""
    if focus_areas:
        focus_hint = f"""
Focus your investigation on these areas: {json.dumps(focus_areas)}
"""

    return f"""\
You are conducting a systematic attack path discovery sweep.

**Branch**: {json.dumps(branch_id)}
{focus_hint}
**Energy context**: Risk score bands (0-100): 0-20 well defended, 20-40 moderate,
40-60 needs attention, 60-80 high priority, 80-100 critical.

## Phase 1 — Load and Orient

    load_graph_energies(branch_id={json.dumps(branch_id)})
    energy_entry_points()

Identify the exposed surface: which nodes are reachable from outside the
infrastructure? These are your starting points.

## Phase 2 — Structural Queries by Category

Search for high-value targets and risky patterns:

**Credentials & secrets**:
    grep_nodes(pattern="credential")
    grep_nodes(pattern="secret")
    find_nodes_by_type(node_type="credential")
    find_nodes_by_type(node_type="secrets_manager")

**Data stores**:
    find_nodes_by_type(node_type="data_store")
    find_nodes_by_type(node_type="database")
    find_nodes_by_type(node_type="s3_bucket")

**CI/CD & supply chain**:
    grep_nodes(pattern="pipeline")
    grep_nodes(pattern="deploy")
    grep_nodes(pattern="ci")

**IAM & identity**:
    find_nodes_by_type(node_type="iam_role")
    find_nodes_by_type(node_type="iam_policy")
    find_nodes_by_type(node_type="service_account")

## Phase 3 — Path Discovery

For each entry point, find lowest-resistance paths to targets:
    energy_lowest_paths(source_id=<entry_point>, limit=10)

For specific source-target pairs of interest:
    energy_trace_to_target(source_id=<entry>, target_types="credential,data_store,database,secrets_manager")

## Phase 4 — Score and Evaluate

For each discovered path:
    energy_momentum_path(path=<node_id_1,node_id_2,...>)

Classify paths by risk band:
- Skip paths scoring < 20 (well defended)
- Investigate paths scoring 20-40 (check specific controls)
- Flag paths scoring > 40 (needs attention)
- Prioritise paths scoring > 60 (high priority)

## Phase 5 — Submit

For paths scoring > 20/100 that represent real risk:
    submit_attack_path(nodes="<node1> -> <node2> -> <node3>", description="...", report="...")

Include in the report: energy per hop, compensating controls found, verification
notes, and MITRE ATT&CK technique IDs where applicable.
"""


@mcp.prompt(
    title="Triage discovery",
    description=(
        "Process scanner findings: read, cluster by remediation action, refine with "
        "energy analysis. Phases 1-4 of the triage pipeline."
    ),
)
def triage_discover(
    sources: str,
    branch_id: str,
) -> str:
    """Read findings, cluster by remediation, and refine with energy analysis.

    Args:
        sources: Comma-separated list of finding source files or descriptions.
        branch_id: Branch ID to load for energy analysis.
    """
    return f"""\
You are processing scanner findings through the structural triage pipeline.

**Sources**: {json.dumps(sources)}
**Branch**: {json.dumps(branch_id)}

## Energy Method

Energy scores represent structural resistance. Use them to PRIORITIZE, not to
decide. The workflow:
1. What does the energy say? (structural signal)
2. What does the finding say? (scanner signal)
3. What does the code/config say? (ground truth)

Never skip step 3. Energy tells you where to look; the code tells you what's real.

## Resolution Categories

After investigation, each finding group resolves to one of:
- **Eliminable**: Can be fully fixed (patch, config change, code fix)
- **Reducible**: Can reduce severity (add controls, restrict access)
- **Constrained**: Accepted risk with documented justification
- **Drift-prone**: Fixed now but will recur without automation
- **Mitigated**: Compensating controls make it low-priority

## Phase 1 — Read All Findings

Read the source files and extract every finding. For each, capture:
- Finding ID / title
- Severity (from the scanner)
- Affected resource
- Description

## Phase 2 — Cluster by Remediation Action

Group findings by what batch of work would fix them:
- Same package upgrade? → one group
- Same config change? → one group
- Same IAM policy fix? → one group

Name each group by the remediation action, not by the finding title.

## Phase 3 — Energy Refinement

    load_graph_energies(branch_id={json.dumps(branch_id)})

For each group's anchor nodes:
    energy_node_scores(node_ids=<comma-separated node IDs>)
    energy_trace_to_target(source_id=<anchor_node>, target_types="credential,data_store,database")

Use energy scores to:
- Merge groups whose remediation overlaps
- Split groups where energy reveals different risk profiles
- Prioritize groups by structural exposure

## Phase 4 — Assign Unclaimed Findings

Any finding not yet in a group: find its nearest node in the graph with
grep_nodes, check energy_node_scores, and assign to the group whose
anchor node is structurally closest.

Present the final grouping as a table:
| Group | Remediation Action | Findings | Anchor Nodes | Structural Risk |
"""


@mcp.prompt(
    title="Investigate a finding group",
    description=(
        "Deep investigation of one finding group using energy analysis and "
        "verification against code/config/cloud."
    ),
)
def triage_investigate_group(
    group_description: str,
    findings: str,
    branch_id: str,
    verification_channels: str = "",
) -> str:
    """Investigate a single finding group.

    Args:
        group_description: What this group is about (the remediation action).
        findings: JSON array or comma-separated list of finding IDs/descriptions in this group.
        branch_id: Branch ID (graph must already be loaded via load_graph_energies).
        verification_channels: Comma-separated verification sources (e.g. "source_code,aws_cli,k8s").
    """
    verify_hint = ""
    if verification_channels:
        verify_hint = f"""
Verification channels available: {json.dumps(verification_channels)}
Use these to confirm or refute energy signals.
"""

    return f"""\
You are investigating a finding group for structural triage.

Prerequisites: load_graph_energies(branch_id) must have been called before using these tools.

**Group**: {json.dumps(group_description)}
**Findings**: {json.dumps(findings)}
**Branch**: {json.dumps(branch_id)}
{verify_hint}
## Energy Interpretation

Energy is structural resistance — negative means accelerating (low resistance), positive means braking (control/boundary). Magnitude matters: -3.0 is much less resistance than -0.5.

Risk score bands: 0-20 well defended, 20-40 moderate, 40-60 needs attention, 60-80 high priority, 80-100 critical.

Energy scores tell you WHERE to look. They are NOT conclusions. Verify everything against source code, configuration, and cloud state. Evidence hierarchy: source code > config files > cloud API > semantic context > graph structure > energy scores.

## Investigation Steps

### 1. Energy Analysis of Anchor Nodes
    energy_node_scores(node_ids=<anchor nodes for this group>)

What does the structural position tell us? High connectivity = more exposure.
Security boundaries nearby = compensating controls.

### 2. Structural Neighborhood
    energy_node_neighborhood(node_id=<primary anchor node>)

What surrounds this node? Are there auth checks, network boundaries, or
other controls between it and sensitive targets?

### 3. Path Tracing
    energy_trace_to_target(source_id=<anchor_node>, target_types="credential,data_store,database,secrets_manager")

Can an attacker reach crown jewels from the vulnerable nodes? What resistance
do they face? Which hops have compensating controls?

### 4. Verification

For each energy signal, verify against ground truth:
- If energy shows low resistance: check if there are controls not in the graph
- If energy shows high resistance: confirm the control is actually effective
- Check version numbers, feature flags, runtime configuration

### 5. Verdict

Produce a verdict for this group:
- **Status**: confirmed / refuted / partial
- **Resolution category**: eliminable / reducible / constrained / drift_prone / mitigated
- **Evidence**: cite specific code, config, or cloud state
- **Priority**: based on risk score band AND verification results
- **Recommended action**: specific remediation steps
"""


@mcp.prompt(
    title="Deliver triage report",
    description=(
        "Generate an audience-specific report from triage results. "
        "Action table first, evidence from code/config, no model internals."
    ),
)
def triage_deliver(
    results: str,
    audience_name: str,
    audience_needs: str = "",
    report_outline: str = "",
) -> str:
    """Generate an audience-specific triage report.

    Args:
        results: JSON string or description of triage investigation results.
        audience_name: Who this report is for (e.g. "engineering_lead", "ciso", "platform_team").
        audience_needs: What this audience cares about (e.g. "what to fix this sprint").
        report_outline: Optional custom report structure.
    """
    outline_hint = ""
    if report_outline:
        outline_hint = f"""
Follow this report outline: {json.dumps(report_outline)}
"""

    return f"""\
You are generating a triage report for a specific audience.

**Audience**: {json.dumps(audience_name)}
**Needs**: {json.dumps(audience_needs) if audience_needs else "Not specified — use defaults for this audience type."}
**Results**: {json.dumps(results)}
{outline_hint}
## Report Rules

1. **Action table first**. The report opens with what to fix, who owns it, and
   priority. Not a summary. Not context. The table.

2. **Evidence from code and config, not energy scores**. Energy scores are
   internal signals — they tell US where to look. The audience sees:
   - "This IAM role grants s3:* to the build service account" (evidence)
   - NOT "The energy score between iam-role-build and s3-prod is -2.7" (internal)

3. **No model internals**. Never mention: energy scores, JEPA, momentum model,
   structural resistance, braking/accelerating, node embeddings, or graph encoding.
   These are implementation details the audience does not need.

4. **No effort estimates**. We do not estimate engineering effort. The audience
   knows their codebase better than we do.

5. **No methodology sections**. Do not explain how the analysis was done.
   Present findings as facts with evidence citations.

## Report Structure (default)

### Action Table
| Priority | Finding | Owner | Remediation | Evidence |
|----------|---------|-------|-------------|----------|

### High-Priority Findings
For each P1/P2 finding:
- What is vulnerable and why
- What an attacker could do (concrete scenario)
- How to fix it (specific steps)
- Evidence (code path, config file, cloud resource)

### Accepted Risks
Findings classified as constrained or mitigated, with documented justification.

### Appendix
Full finding list with resolution status.

Filter everything for this audience. An engineering lead needs code paths and
remediation steps. A CISO needs business impact and risk posture. A platform
team needs infrastructure changes and ownership.
"""


# ---------------------------------------------------------------------------
# Energy graph cache — local merged graph+energy data for structural triage
# ---------------------------------------------------------------------------


_jepa_keepalive_task: object | None = None


def _get_energy_cache() -> EnergyGraphCache | None:
    """Accessor for the energy cache — passed to tool modules."""
    return _energy_cache


def _start_jepa_keepalive(branch_id: str, repository_id: str):
    """Ping the JEPA graph_metadata endpoint every 5 min to prevent cache reaping."""
    global _jepa_keepalive_task

    _stop_jepa_keepalive()

    async def _loop():
        while True:
            await asyncio.sleep(300)
            try:
                client = await _http()
                await client.post(
                    "/api/jepa/graph_metadata",
                    params={"branch_id": branch_id, "repository_id": repository_id},
                    json={},
                    timeout=15,
                )
            except Exception:
                pass

    _jepa_keepalive_task = asyncio.create_task(_loop())


def _stop_jepa_keepalive():
    global _jepa_keepalive_task
    if _jepa_keepalive_task is not None:
        _jepa_keepalive_task.cancel()
        _jepa_keepalive_task = None


@mcp.tool()
async def load_graph_energies(branch_id: str) -> str:
    """Load an infrastructure graph with energy scores into the local cache.

    This is the single entry point for all graph and energy analysis. It:
    1. Checks the local SQLite disk cache — returns immediately if fresh
    2. Triggers warm-up (encoding) on the inference server
    3. Polls until encoding completes (2-5 min for large graphs)
    4. Fetches the full graph and energy scores from the inference server
    5. Merges everything into a local SQLite cache

    All energy_*, grep_*, read_*, find_*, and get_graph_statistics tools
    require this to be called first.
    """
    global _energy_cache

    # Try reloading from existing SQLite cache on disk (survives process restart)
    cached = EnergyGraphCache.from_disk(branch_id)
    if cached is not None:
        if _energy_cache is not None:
            _energy_cache.close()
        _energy_cache = cached
        if cached.has_energies and cached.repository_id:
            _start_jepa_keepalive(branch_id, cached.repository_id)
        return json.dumps({
            "status": "loaded",
            "source": "disk_cache",
            "branch_id": branch_id,
            "n_nodes": cached._n_nodes,
            "n_edges": cached._n_edges,
            "n_node_types": cached._n_node_types,
            "n_edge_types": cached._n_edge_types,
            "n_containment_edges": cached._n_containment,
            "commit_id": cached.commit_id,
            "has_energies": cached.has_energies,
        })

    try:
        client = await _http()
    except DeviceFlowPending as e:
        return json.dumps(_auth_pending_response(e))

    # --- JEPA warm-up: trigger encoding and wait for completion ---
    # This replaces the old load_branch + wait_for_load sequence.
    # The inference session is used internally to trigger and poll encoding.
    try:
        log.info("load_graph_energies: triggering JEPA warm-up for branch %s", branch_id)
        load_result = await load_branch(branch_id)
        load_data = json.loads(load_result)

        if load_data.get("status") != "loaded":
            # Encoding started but not instant — poll until ready
            log.info("load_graph_energies: encoding in progress, waiting...")
            wait_result = await wait_for_load(timeout_secs=600, poll_interval=15)
            wait_data = json.loads(wait_result)
            if wait_data.get("status") == "timeout":
                log.warning("load_graph_energies: JEPA warm-up timed out, proceeding anyway")
            elif wait_data.get("status") == "loaded":
                log.info("load_graph_energies: JEPA encoding complete")
    except Exception as exc:
        # JEPA warm-up failure is non-fatal — we still try to fetch the graph
        # and energies. The energy fetch may fail too, but graph tools will work.
        log.warning("load_graph_energies: JEPA warm-up failed (%s), proceeding with graph fetch", exc)

    # --- Fetch graph + energies into local cache ---
    # Re-acquire the client — the JEPA warm-up above may have recreated it
    # (e.g., the original was closed and _http() built a new one).
    try:
        client = await _http()
    except DeviceFlowPending as e:
        return json.dumps(_auth_pending_response(e))

    try:
        cache = await EnergyGraphCache.build(branch_id, client)
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 401:
            refreshed = await _refresh_client()
            if refreshed is not None:
                try:
                    cache = await EnergyGraphCache.build(branch_id, refreshed)
                except Exception as retry_err:
                    return json.dumps({
                        "error": "load_failed",
                        "message": f"Failed to load graph energies after token refresh: {retry_err}",
                    })
            else:
                return json.dumps({
                    "error": "authentication_failed",
                    "message": "Token expired during graph loading and could not be refreshed.",
                })
        else:
            return json.dumps({
                "error": "load_failed",
                "message": f"HTTP {exc.response.status_code} from {exc.request.url.path}: {exc.response.text[:200]}",
            })
    except Exception as exc:
        return json.dumps({
            "error": "load_failed",
            "message": f"Failed to load graph energies: {exc}",
        })

    # Close previous cache (SQLite connection) before replacing
    if _energy_cache is not None:
        _energy_cache.close()
    _energy_cache = cache

    if cache.has_energies and cache.repository_id:
        _start_jepa_keepalive(branch_id, cache.repository_id)

    result: dict[str, Any] = {
        "status": "loaded",
        "branch_id": branch_id,
        "n_nodes": cache._n_nodes,
        "n_edges": cache._n_edges,
        "n_node_types": cache._n_node_types,
        "n_edge_types": cache._n_edge_types,
        "n_containment_edges": cache._n_containment,
        "commit_id": cache.commit_id,
        "has_energies": cache.has_energies,
    }
    if not cache.has_energies:
        result["status"] = "loaded_without_energies"
        result["energy_error"] = cache.energy_error
        result["next_step"] = (
            "Graph tools (read_node, grep_nodes, find_nodes_by_type, etc.) work. "
            "Energy tools require energy scores — retry "
            "load_graph_energies(branch_id) in a few minutes."
        )
    if cache.energies_incomplete:
        result["warning"] = (
            "Transition energy data is incomplete — the SSE stream closed "
            "before delivering results. Energy tools will work but some edges "
            "will have no energy scores."
        )
    return json.dumps(result)


# ---------------------------------------------------------------------------
# Register tool modules
# ---------------------------------------------------------------------------


from . import energy_tools, graph_tools, triage_state  # noqa: E402

graph_tools.register(mcp, _get_energy_cache)
energy_tools.register(mcp, _get_energy_cache)
triage_state.register(mcp)


def main():
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
