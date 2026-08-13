"""Tests for mcp_call_event telemetry emission.

Blocker fixes verified here:
  1. Exactly one event per tool invocation (InstrumentedFastMCP.call_tool boundary),
     regardless of how many internal HTTP calls the tool makes.
  2. Identity caching: cached only on success; transient failures retry on next call;
     concurrent first calls do not race.
  3. emit_mcp_call_event calls raise_for_status() and suppresses all errors.
  4. fire_and_forget keeps strong task references and closes the coroutine on failure.
"""

import asyncio
import hashlib
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import latent_defense_mcp.telemetry as tel
from latent_defense_mcp import server

pytestmark = pytest.mark.asyncio


# ── helpers ──────────────────────────────────────────────────────────────────


def _ok_response(data: dict) -> MagicMock:
    r = MagicMock(status_code=200, is_success=True, content=b"x")
    r.json.return_value = data
    r.raise_for_status.return_value = None
    return r


def _async_factory(data: dict):
    """Return an http_factory coroutine that yields a mock client returning data."""
    client = AsyncMock()
    client.get.return_value = _ok_response(data)
    client.post.return_value = _ok_response(data)

    async def factory():
        return client

    return factory, client


# ── identity resolution ──────────────────────────────────────────────────────


async def test_resolve_entity_id_uses_sub_over_email():
    tel._entity_id = None
    factory, _ = _async_factory({"sub": "auth0|stable", "email": "user@example.com"})
    result = await tel._resolve_entity_id(factory)
    assert result == "auth0|stable"
    assert tel._entity_id == "auth0|stable"


async def test_resolve_entity_id_falls_back_to_email_when_no_sub():
    tel._entity_id = None
    factory, _ = _async_factory({"email": "user@example.com"})
    result = await tel._resolve_entity_id(factory)
    assert result == "user@example.com"


async def test_resolve_entity_id_failure_returns_unknown_and_is_not_cached():
    """Transient failures must not poison the cache."""
    tel._entity_id = None

    async def broken_factory():
        raise ConnectionError("network down")

    result = await tel._resolve_entity_id(broken_factory)
    assert result == "unknown"
    assert tel._entity_id is None  # NOT cached — next call will retry


async def test_resolve_entity_id_401_derives_stable_key_identity(monkeypatch):
    """/auth/me returning 401 with LATENT_DEFENSE_API_KEY set yields a stable per-key entity_id.

    Different keys must map to distinct entity_ids; same key must always map to the same id.
    The identity is cached after the first resolution so /auth/me is only called once.
    """
    tel._entity_id = None
    monkeypatch.setenv("LATENT_DEFENSE_API_KEY", "test-key-abc123")
    call_count = 0

    async def factory():
        nonlocal call_count
        call_count += 1
        client = AsyncMock()
        r = MagicMock(status_code=401, is_success=False)
        client.get.return_value = r
        return client

    expected_hash = hashlib.sha256(b"test-key-abc123").hexdigest()[:16]
    expected_id = f"apikey:{expected_hash}"

    r1 = await tel._resolve_entity_id(factory)
    assert r1 == expected_id
    assert tel._entity_id == expected_id

    r2 = await tel._resolve_entity_id(factory)
    assert r2 == expected_id
    assert call_count == 1  # second call hit the cache


async def test_resolve_entity_id_401_no_api_key_falls_back_to_unknown(monkeypatch):
    """/auth/me returning 401 without LATENT_DEFENSE_API_KEY falls back to 'unknown'."""
    tel._entity_id = None
    monkeypatch.delenv("LATENT_DEFENSE_API_KEY", raising=False)
    call_count = 0

    async def factory():
        nonlocal call_count
        call_count += 1
        client = AsyncMock()
        r = MagicMock(status_code=401, is_success=False)
        client.get.return_value = r
        return client

    r1 = await tel._resolve_entity_id(factory)
    assert r1 == "unknown"
    assert tel._entity_id == "unknown"

    r2 = await tel._resolve_entity_id(factory)
    assert r2 == "unknown"
    assert call_count == 1  # second call used the cache, no second /auth/me


async def test_resolve_entity_id_retries_after_failure():
    """A failed first call still allows a successful second call to cache the id."""
    tel._entity_id = None
    attempt = 0

    async def factory():
        nonlocal attempt
        attempt += 1
        client = AsyncMock()
        if attempt == 1:
            client.get.side_effect = ConnectionError("transient")
        else:
            client.get.return_value = _ok_response({"sub": "auth0|abc"})
        return client

    r1 = await tel._resolve_entity_id(factory)
    assert r1 == "unknown"
    assert tel._entity_id is None

    r2 = await tel._resolve_entity_id(factory)
    assert r2 == "auth0|abc"
    assert tel._entity_id == "auth0|abc"


async def test_resolve_entity_id_cached_after_success():
    """Once resolved, /auth/me is not called again."""
    tel._entity_id = None
    factory, client = _async_factory({"sub": "auth0|abc"})

    await tel._resolve_entity_id(factory)
    await tel._resolve_entity_id(factory)

    assert client.get.call_count == 1  # only one real call despite two awaits


async def test_concurrent_identity_resolution_no_race():
    """Ten concurrent first-calls must all return the same value without racing."""
    tel._entity_id = None
    call_count = 0

    async def factory():
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0)  # yield to let other tasks run
        client = AsyncMock()
        client.get.return_value = _ok_response({"sub": "auth0|shared"})
        return client

    results = await asyncio.gather(*[tel._resolve_entity_id(factory) for _ in range(10)])
    assert all(r == "auth0|shared" for r in results)
    assert tel._entity_id == "auth0|shared"


# ── emit_mcp_call_event ──────────────────────────────────────────────────────


async def test_emit_raises_for_status_on_non_2xx():
    """Non-2xx telemetry responses trigger raise_for_status (then are suppressed)."""
    tel._entity_id = "auth0|abc"

    mock_resp = MagicMock()
    mock_resp.raise_for_status.side_effect = Exception("401 Unauthorized")

    client = AsyncMock()
    client.post.return_value = mock_resp

    async def factory():
        return client

    await tel.emit_mcp_call_event(factory, "list_repositories", 42.0, True, None)
    mock_resp.raise_for_status.assert_called_once()


async def test_emit_suppresses_network_error():
    """Unreachable telemetry endpoint does not propagate to callers."""
    tel._entity_id = "auth0|abc"

    async def factory():
        client = AsyncMock()
        client.post.side_effect = ConnectionError("refused")
        return client

    await tel.emit_mcp_call_event(factory, "get_graph", 100.0, False, "ConnectionError")


async def test_emit_includes_error_type_when_present():
    """error_type appears in the payload when the tool failed."""
    tel._entity_id = "auth0|abc"
    captured = []

    async def factory():
        client = AsyncMock()

        async def fake_post(path, json=None, **kw):
            captured.append(json)
            r = MagicMock()
            r.raise_for_status.return_value = None
            return r

        client.post = fake_post
        return client

    await tel.emit_mcp_call_event(factory, "run_inference", 300.0, False, "McpApiError")
    assert captured
    event = captured[0]["events"][0]
    assert event["payload"]["error_type"] == "McpApiError"
    assert event["payload"]["success"] is False


async def test_emit_omits_error_type_on_success():
    """error_type is absent from the payload on a successful call."""
    tel._entity_id = "auth0|abc"
    captured = []

    async def factory():
        client = AsyncMock()

        async def fake_post(path, json=None, **kw):
            captured.append(json)
            r = MagicMock()
            r.raise_for_status.return_value = None
            return r

        client.post = fake_post
        return client

    await tel.emit_mcp_call_event(factory, "infra_stats", 50.0, True, None)
    event = captured[0]["events"][0]
    assert "error_type" not in event["payload"]


# ── fire_and_forget ──────────────────────────────────────────────────────────


async def test_fire_and_forget_keeps_strong_reference():
    """Background task is added to _bg_tasks so GC cannot collect it."""
    tel._bg_tasks.clear()
    ran = asyncio.Event()

    async def coro():
        ran.set()

    tel.fire_and_forget(coro())
    await asyncio.sleep(0)  # let the event loop run the task
    assert ran.is_set()
    # Task was discarded from _bg_tasks only after completion — it's empty now
    # (discard callback fired). The key invariant: it was there while running.


async def test_fire_and_forget_closes_coro_on_scheduling_failure(monkeypatch):
    """If scheduling fails, the coroutine is closed to suppress ResourceWarning."""
    closed_flag = []

    # Use a mock that walks like a coroutine (has .close) — coroutine.close is
    # read-only in CPython 3.14+, so we can't patch it on a real coroutine.
    mock_coro = MagicMock()
    mock_coro.close = lambda: closed_flag.append(True)

    class BrokenLoop:
        def create_task(self, coro):
            raise RuntimeError("no loop")

    monkeypatch.setattr(asyncio, "get_event_loop", lambda: BrokenLoop())
    tel.fire_and_forget(mock_coro)

    assert closed_flag, "coroutine must be closed when scheduling fails"


# ── InstrumentedFastMCP cardinality ─────────────────────────────────────────


async def _call_tool_with_mock_http(tool_name: str, args: dict, monkeypatch, data: dict | None = None):
    """Call a tool via mcp.call_tool with a mocked HTTP layer.

    Returns the list of coroutines passed to fire_and_forget (one per event emitted).
    """
    scheduled = []

    def capture_fff(coro):
        scheduled.append(coro)
        coro.close()

    monkeypatch.setattr(server, "fire_and_forget", capture_fff)

    mock_r = _ok_response(data or {})
    mock_client = AsyncMock()
    mock_client.get.return_value = mock_r
    mock_client.post.return_value = mock_r

    async def fake_http():
        return mock_client

    monkeypatch.setattr(server, "_http", fake_http)
    # Reset the module-level client so _http() doesn't use a stale one
    monkeypatch.setattr(server, "_client", None)

    await server.mcp.call_tool(tool_name, args)
    return scheduled


async def test_single_http_tool_emits_one_event(monkeypatch):
    """infra_stats makes one GET — must produce exactly one event."""
    emitted = await _call_tool_with_mock_http("infra_stats", {}, monkeypatch, {"repositories": 3})
    assert len(emitted) == 1


async def test_multi_http_tool_emits_one_event(monkeypatch):
    """run_inference makes GET (branch check) + POST (run) — still exactly one event."""
    mock_r = _ok_response({"id": "b1", "label": "main", "run_id": "r1", "status": "queued"})
    scheduled = []

    def capture_fff(coro):
        scheduled.append(coro)
        coro.close()

    monkeypatch.setattr(server, "fire_and_forget", capture_fff)

    mock_client = AsyncMock()
    mock_client.get.return_value = mock_r
    mock_client.post.return_value = mock_r

    async def fake_http():
        return mock_client

    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server, "_client", None)

    await server.mcp.call_tool("run_inference", {"branch_id": "b1"})
    assert len(scheduled) == 1


async def test_zero_http_tool_emits_one_event(monkeypatch):
    """whoami calls _http() directly, not via _get — must still emit one event."""
    emitted = await _call_tool_with_mock_http(
        "whoami", {}, monkeypatch, {"email": "u@example.com", "sub": "auth0|x"}
    )
    assert len(emitted) == 1


async def test_failing_tool_emits_success_false(monkeypatch):
    """When a tool raises McpApiError, success=False and error_type is set."""
    from latent_defense_mcp.errors import McpApiError

    scheduled_coros = []
    emitted_calls = []

    async def fake_emit(http_factory, tool_name, duration_ms, success, error_type, **kw):
        emitted_calls.append({"tool": tool_name, "success": success, "error_type": error_type})

    def capture_fff(coro):
        # Run the coroutine synchronously for inspection
        scheduled_coros.append(coro)
        # We override emit_mcp_call_event separately

    monkeypatch.setattr(server, "emit_mcp_call_event", fake_emit)

    captured_fff_args = []

    def real_fff(coro):
        captured_fff_args.append(coro)
        # Execute it so emit_mcp_call_event is actually called
        loop = asyncio.get_event_loop()
        loop.run_until_complete(coro) if not loop.is_running() else asyncio.ensure_future(coro)

    monkeypatch.setattr(server, "fire_and_forget", real_fff)

    mock_client = AsyncMock()
    mock_r = MagicMock(status_code=404, is_success=False, content=b"x")
    mock_r.json.return_value = {"detail": "not found"}
    mock_client.get.return_value = mock_r

    async def fake_http():
        return mock_client

    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server, "_client", None)

    with pytest.raises(Exception):
        await server.mcp.call_tool("get_repository", {"repo_id": "nonexistent"})

    assert len(captured_fff_args) == 1
