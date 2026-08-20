"""Best-effort MCP call telemetry — fire-and-forget mcp_call_event emission.

Records one event per tool call at the FastMCP dispatch boundary.
Failures are always suppressed so telemetry never interrupts tool callers.

Events are forwarded to the deployment's telemetry endpoint.

Identity contract
-----------------
Browser / device-flow sessions:
    /auth/me returns a JWT sub or email; resolved once and cached.

API-key sessions (LATENT_DEFENSE_API_KEY set, /auth/me returns 401):
    /auth/me does not accept API keys. A stable entity_id is derived by
    hashing the key: "apikey:<sha256[:16]>". This is distinct per key,
    non-reversible, and requires no auth-service changes.

Transient failures (network blip, device-flow pending):
    "unknown" is returned but NOT cached; the next call retries.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import Any

log = logging.getLogger("latent-defense-mcp.telemetry")

_entity_id: str | None = None
_entity_id_lock = asyncio.Lock()

# Strong references prevent the event loop from GC-ing in-flight tasks.
_bg_tasks: set[asyncio.Task] = set()


async def _resolve_entity_id(http_factory) -> str:
    """Return the user's stable subject identifier, retrying on failure."""
    global _entity_id
    # Fast path — already resolved.
    if _entity_id is not None:
        return _entity_id
    # Slow path — serialize concurrent first callers.
    async with _entity_id_lock:
        if _entity_id is not None:  # double-checked locking
            return _entity_id
        try:
            client = await http_factory()
            r = await client.get("/auth/me")
            if r.is_success:
                data = r.json()
                # Prefer sub (stable, non-PII) over email.
                resolved = data.get("sub") or data.get("email") or None
                if resolved:
                    _entity_id = resolved
                    return _entity_id
            elif r.status_code == 401:
                # /auth/me does not accept API keys (only session cookies /
                # RS256 tokens). Derive a stable per-key identity from the
                # LATENT_DEFENSE_API_KEY env var so different keys map to
                # distinct entity_ids without exposing the secret value.
                api_key = os.environ.get("LATENT_DEFENSE_API_KEY", "")
                if api_key:
                    key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
                    _entity_id = f"apikey:{key_hash}"
                else:
                    _entity_id = "unknown"
                return _entity_id
        except Exception:
            pass
    # Transient failure (network blip) — do not cache; retry on next call.
    return "unknown"


async def emit_mcp_call_event(
    http_factory,
    tool_name: str,
    duration_ms: float,
    success: bool,
    error_type: str | None,
    server_name: str = "latent-defense",
) -> None:
    """Post one mcp_call_event to the deployment's telemetry endpoint."""
    try:
        entity_id = await _resolve_entity_id(http_factory)
        payload: dict[str, Any] = {
            "tool_name": tool_name,
            "server_name": server_name,
            "duration_ms": round(duration_ms, 2),
            "success": success,
        }
        if error_type is not None:
            payload["error_type"] = error_type

        client = await http_factory()
        r = await client.post(
            "/api/telemetry/events/ingest",
            json={
                "events": [{
                    "event_type": "mcp_call_event",
                    "entity_id": entity_id,
                    "entity_type": "mcp_client",
                    "payload": payload,
                }]
            },
        )
        # Raise so non-2xx (401, 500, …) enter the suppression path below.
        r.raise_for_status()
    except Exception:
        log.debug("mcp_call_event emit failed (suppressed)", exc_info=True)


def fire_and_forget(coro) -> None:
    """Schedule *coro* as a background task with a strong reference until done."""
    try:
        loop = asyncio.get_event_loop()
        task = loop.create_task(coro)
        _bg_tasks.add(task)
        task.add_done_callback(_bg_tasks.discard)
    except Exception:
        # Close the coroutine to avoid "was never awaited" ResourceWarning.
        try:
            coro.close()
        except Exception:
            pass
        log.debug("fire_and_forget scheduling failed (suppressed)", exc_info=True)
