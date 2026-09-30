"""Busy handling: the inference server runs one encode at a time.

Energy routes answer HTTP 503 ``{"status": "busy", ...}`` while another encode
runs, and ``GET /api/jepa/encoding-status`` reports the state of an encode.
Energy endpoints are never retried automatically.
"""

from __future__ import annotations

import json
import sqlite3

import httpx
import pytest

from latent_defense_mcp import energy_cache as ec
from latent_defense_mcp.energy_cache import EncodingBusy, EncodingInProgress, EnergyGraphCache

from test_energy_load import BRANCH, REPO, Recorder, _client, _graph_db_without_energies

pytestmark = pytest.mark.asyncio

BUSY_BODY = {
    "status": "busy",
    "same_branch": True,
    "in_flight": {"branch_id": BRANCH, "stage_name": "NodeEmbeddings", "progress_pct": 42},
}


def _busy_response() -> httpx.Response:
    return httpx.Response(503, json=BUSY_BODY, headers={"Retry-After": "30"})


def _fresh_cache(tmp_path) -> EnergyGraphCache:
    cache = EnergyGraphCache()
    cache._write_db = sqlite3.connect(str(tmp_path / "x.db"))
    EnergyGraphCache._create_tables(cache._write_db)
    return cache


class BusyOn(Recorder):
    """Recorder whose named route answers busy or 504."""

    def __init__(self, route: str, status: int = 503):
        super().__init__()
        self.route = route
        self.status = status

    def __call__(self, request):
        if request.url.path == self.route:
            self.calls.append(request)
            if self.status == 503:
                return _busy_response()
            return httpx.Response(self.status, text="gateway")
        return super().__call__(request)


@pytest.mark.parametrize("route", [
    "/api/jepa/batch_entry_energies",
    "/api/jepa/graph_metadata",
    "/api/jepa/batch_transition_energies",
])
async def test_busy_503_raises_encoding_busy_on_every_route(tmp_path, route):
    rec = BusyOn(route)
    cache = _fresh_cache(tmp_path)
    async with _client(rec) as client:
        with pytest.raises(EncodingBusy) as info:
            await cache._fetch_and_merge_energies(BRANCH, REPO, client)
    exc = info.value
    assert isinstance(exc, EncodingInProgress)
    assert exc.in_flight_branch == BRANCH
    assert exc.same_branch is True
    assert exc.progress_pct == 42
    assert exc.retry_after == 30
    assert rec.paths().count(route) == 1, "busy must not be retried"


async def test_metadata_504_raises_encoding_in_progress_not_busy(tmp_path):
    rec = BusyOn("/api/jepa/graph_metadata", status=504)
    cache = _fresh_cache(tmp_path)
    async with _client(rec) as client:
        with pytest.raises(EncodingInProgress) as info:
            await cache._fetch_and_merge_energies(BRANCH, REPO, client)
    assert not isinstance(info.value, EncodingBusy)
    assert rec.paths().count("/api/jepa/graph_metadata") == 1


async def test_plain_503_without_busy_body_is_encoding_in_progress(tmp_path):
    def handler(request):
        return httpx.Response(503, text="upstream unavailable")

    cache = _fresh_cache(tmp_path)
    async with _client(handler) as client:
        with pytest.raises(EncodingInProgress) as info:
            await cache._fetch_and_merge_energies(BRANCH, REPO, client)
    assert not isinstance(info.value, EncodingBusy)


async def test_refresh_records_busy_on_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))
    cache = EnergyGraphCache.from_disk(BRANCH)
    rec = BusyOn("/api/jepa/batch_entry_energies")
    async with _client(rec) as client:
        with pytest.raises(EncodingBusy):
            await cache.refresh_energies(client)
    assert cache.encoding_in_progress and isinstance(cache.busy, EncodingBusy)


def _wire(monkeypatch, server, *, load_results, wait_results, route_handler=None):
    """Patch load_branch / wait_for_load / _http; return call log."""
    log = {"load": 0, "wait": 0, "energy": 0, "route": []}
    loads = iter(load_results)
    waits = iter(wait_results)

    async def fake_load(branch_id):
        log["load"] += 1
        return json.dumps(next(loads))

    async def fake_wait(timeout_secs=600, poll_interval=30):
        log["wait"] += 1
        return json.dumps(next(waits))

    def handler(request):
        if request.url.path == "/api/jepa/encoding-status":
            log["route"].append(request)
            return route_handler(len(log["route"]))
        if request.url.path.startswith("/api/jepa/"):
            log["energy"] += 1
        raise AssertionError(f"unexpected {request.url.path}")

    client = _client(handler)

    async def fake_http():
        return client

    async def no_sleep(_):
        return None

    monkeypatch.setattr(server, "load_branch", fake_load)
    monkeypatch.setattr(server, "wait_for_load", fake_wait)
    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server.asyncio, "sleep", no_sleep)
    log["client"] = client
    return log


BUSY_WAIT = {
    "status": "failed", "error": "busy: another encode is running", "busy": True,
    "same_branch": True,
    "in_flight": {"branch_id": BRANCH, "progress_pct": 42, "elapsed_secs": 100},
}


async def test_same_branch_busy_waits_for_route_encode_then_reloads(monkeypatch):
    from latent_defense_mcp import server

    def route(n):
        state = {"state": "encoding", "progress_pct": 60} if n == 1 else {"state": "cached"}
        return httpx.Response(200, json=state)

    log = _wire(
        monkeypatch, server,
        load_results=[{"status": "encoding_started"}, {"status": "loaded"}],
        wait_results=[BUSY_WAIT],
        route_handler=route,
    )
    try:
        ready, progress = await server._await_encoding(BRANCH)
    finally:
        await log["client"].aclose()

    assert (ready, progress) == (True, None)
    assert log["load"] == 2, "load_branch called again after the other encode finished"
    assert len(log["route"]) == 2
    assert log["route"][0].url.params["branch_id"] == BRANCH
    assert log["energy"] == 0, "no energy routes may be called while waiting"


async def test_busy_for_other_branch_returns_immediately(monkeypatch):
    from latent_defense_mcp import server

    other = {**BUSY_WAIT, "same_branch": False,
             "in_flight": {"branch_id": "other", "progress_pct": 10}}
    log = _wire(
        monkeypatch, server,
        load_results=[{"status": "encoding_started"}],
        wait_results=[other],
        route_handler=lambda n: pytest.fail("must not poll"),
    )
    try:
        ready, progress = await server._await_encoding(BRANCH)
    finally:
        await log["client"].aclose()

    assert ready is False
    assert progress["busy"] is True and progress["same_branch"] is False
    assert progress["in_flight_branch"] == "other"
    assert log["route"] == [] and log["energy"] == 0 and log["load"] == 1


async def test_non_busy_failure_surfaces_error_not_timeout_text(tmp_path, monkeypatch):
    from latent_defense_mcp import server

    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))
    failed = {"status": "failed", "error": "OOM in encoder"}
    log = _wire(
        monkeypatch, server,
        load_results=[{"status": "encoding_started"}],
        wait_results=[failed],
        route_handler=lambda n: pytest.fail("must not poll"),
    )
    monkeypatch.setattr(server, "_start_jepa_keepalive", lambda *a, **k: None)
    monkeypatch.setattr(server.observation_tools, "load_delta_from_disk", lambda b: 0)
    monkeypatch.setattr(server, "_energy_cache", None)
    try:
        ready, progress = await server._await_encoding(BRANCH)
        assert ready is False
        assert progress["status"] == "failed" and progress["error"] == "OOM in encoder"
        assert log["route"] == []

        # Same failure through load_graph_energies.
        log["load"] = 0
        monkeypatch.setattr(server, "_await_encoding", lambda b: _ret((False, progress)))
        result = json.loads(await server.load_graph_energies(BRANCH))
    finally:
        await log["client"].aclose()
        if server._energy_cache is not None:
            server._energy_cache.close()
            server._energy_cache = None

    assert result["status"] == "loaded_without_energies"
    assert "OOM in encoder" in result["energy_error"]
    assert "after 900s" not in json.dumps(result)
    assert result["encoder"]["state"] == "failed"
    assert result["encoder"]["error"] == "OOM in encoder"


async def _ret(v):
    return v


async def test_route_status_404_falls_back_to_current_behavior(monkeypatch):
    from latent_defense_mcp import server

    log = _wire(
        monkeypatch, server,
        load_results=[{"status": "encoding_started"}],
        wait_results=[BUSY_WAIT],
        route_handler=lambda n: httpx.Response(404, text="not found"),
    )
    try:
        ready, progress = await server._await_encoding(BRANCH)
    finally:
        await log["client"].aclose()

    assert ready is False
    assert progress["status"] == "busy"
    assert len(log["route"]) == 1, "no polling against a server without the endpoint"
    assert log["load"] == 1 and log["energy"] == 0


async def test_route_status_failed_surfaces_error(monkeypatch):
    from latent_defense_mcp import server

    log = _wire(
        monkeypatch, server,
        load_results=[{"status": "encoding_started"}],
        wait_results=[BUSY_WAIT],
        route_handler=lambda n: httpx.Response(
            200, json={"state": "failed", "error": "graph fetch failed"}),
    )
    try:
        ready, progress = await server._await_encoding(BRANCH)
    finally:
        await log["client"].aclose()

    assert ready is False
    assert progress["status"] == "failed"
    assert progress["error"] == "graph fetch failed"
    assert log["load"] == 1 and log["energy"] == 0


async def test_wait_timeout_while_busy_gives_structured_encoder(tmp_path, monkeypatch):
    from latent_defense_mcp import server

    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))
    log = _wire(
        monkeypatch, server,
        load_results=[{"status": "encoding_started"}],
        wait_results=[BUSY_WAIT],
        route_handler=lambda n: httpx.Response(
            200, json={"state": "encoding", "progress_pct": 77}),
    )
    monkeypatch.setattr(server, "_ENCODE_WAIT_SECS", 0)
    monkeypatch.setattr(server, "_start_jepa_keepalive", lambda *a, **k: None)
    monkeypatch.setattr(server.observation_tools, "load_delta_from_disk", lambda b: 0)
    monkeypatch.setattr(server, "_energy_cache", None)
    try:
        result = json.loads(await server.load_graph_energies(BRANCH))
    finally:
        await log["client"].aclose()
        if server._energy_cache is not None:
            server._energy_cache.close()
            server._energy_cache = None

    assert result["status"] == "loaded_without_energies"
    enc = result["encoder"]
    assert enc["state"] == "busy"
    assert enc["in_flight_branch"] == BRANCH
    assert enc["progress_pct"] == 77
    assert enc["retry_after_secs"] == 30
    assert "busy" in result["energy_error"].lower()
    assert "after 0s" not in result["energy_error"]
    assert log["energy"] == 0


async def test_warmup_unavailable_falls_back_to_single_fetch(tmp_path, monkeypatch):
    from latent_defense_mcp import server

    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))

    async def boom(branch_id):
        raise RuntimeError("oracle down")

    monkeypatch.setattr(server, "load_branch", boom)
    assert await server._await_encoding(BRANCH) == (None, None)

    rec = Recorder()
    client = _client(rec)

    async def fake_http():
        return client

    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server, "_start_jepa_keepalive", lambda *a, **k: None)
    monkeypatch.setattr(server.observation_tools, "load_delta_from_disk", lambda b: 0)
    monkeypatch.setattr(server, "_energy_cache", None)
    try:
        result = json.loads(await server.load_graph_energies(BRANCH))
    finally:
        await client.aclose()
        if server._energy_cache is not None:
            server._energy_cache.close()
            server._energy_cache = None

    assert result["has_energies"] is True
    assert len(rec.energy_bodies()) == 1, "exactly one fallback attempt"


async def test_busy_energy_call_is_never_retried_through_load(tmp_path, monkeypatch):
    from latent_defense_mcp import server

    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))
    rec = BusyOn("/api/jepa/batch_entry_energies")
    client = _client(rec)

    async def fake_http():
        return client

    async def ready(branch_id):
        return True, None

    monkeypatch.setattr(server, "_await_encoding", ready)
    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server, "_start_jepa_keepalive", lambda *a, **k: None)
    monkeypatch.setattr(server.observation_tools, "load_delta_from_disk", lambda b: 0)
    monkeypatch.setattr(server, "_energy_cache", None)
    try:
        result = json.loads(await server.load_graph_energies(BRANCH))
    finally:
        await client.aclose()
        if server._energy_cache is not None:
            server._energy_cache.close()
            server._energy_cache = None

    assert rec.paths().count("/api/jepa/batch_entry_energies") == 1
    assert result["encoder"]["state"] == "busy"
    assert result["encoder"]["retry_after_secs"] == 30
    assert result["encoder"]["progress_pct"] == 42


async def test_wait_for_load_failed_result_includes_busy_fields(monkeypatch):
    from latent_defense_mcp import server

    async def fake_progress():
        return {
            "stage": 9, "error": "busy: encoder in use", "busy": True,
            "same_branch": False,
            "in_flight": {"branch_id": "other", "progress_pct": 5},
        }

    monkeypatch.setattr(server, "_fetch_encoding_progress", fake_progress)
    monkeypatch.setattr(server, "_load_branch_id", BRANCH)
    monkeypatch.setattr(server, "_oracle_session", "sess-9")
    monkeypatch.setattr(server, "_encoding_started_at", None)

    result = json.loads(await server.wait_for_load(timeout_secs=5, poll_interval=1))
    assert result["status"] == "failed"
    assert result["busy"] is True
    assert result["same_branch"] is False
    assert result["in_flight"]["branch_id"] == "other"


async def test_wait_for_load_plain_failure_has_no_busy_fields(monkeypatch):
    from latent_defense_mcp import server

    async def fake_progress():
        return {"stage": 9, "error": "OOM"}

    monkeypatch.setattr(server, "_fetch_encoding_progress", fake_progress)
    monkeypatch.setattr(server, "_load_branch_id", BRANCH)
    monkeypatch.setattr(server, "_oracle_session", "sess-9")
    monkeypatch.setattr(server, "_encoding_started_at", None)

    result = json.loads(await server.wait_for_load(timeout_secs=5, poll_interval=1))
    assert result["status"] == "failed" and "busy" not in result
