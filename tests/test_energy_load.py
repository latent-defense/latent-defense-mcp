"""Regression tests for energy loading behaviour.

Background: the inference server does not de-duplicate in-flight encodes. The
old client retried a timed-out ``batch_entry_energies`` with
``force_refresh=true`` and, on the next ``load_graph_energies`` call, returned
the energy-less disk cache with advice to "retry" — each retry started another
full encode on the server and none could finish. These tests pin the fixed
contract:

* a gateway timeout is surfaced as ``EncodingInProgress`` after exactly one
  request, never retried, never with ``force_refresh``;
* energies can be merged into an already-cached graph in place;
* ``build(fetch_energies=False)`` never touches the energy endpoints;
* ``load_graph_energies`` completes a cached-but-energy-less graph instead of
  handing it back stale.
"""

from __future__ import annotations

import json
import sqlite3

import httpx
import pytest

from latent_defense_mcp import energy_cache as ec
from latent_defense_mcp.energy_cache import EncodingInProgress, EnergyGraphCache

pytestmark = pytest.mark.asyncio

BRANCH = "branch_test_123"
REPO = "repo_test"
NODE_IDS = ["node-a", "node-b", "node-c", "node-d"]
EDGE_IDS = ["edge-a-b", "edge-b-c", "edge-a-d", "edge-d-c"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _graph_db_without_energies(path: str) -> None:
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    EnergyGraphCache._create_tables(conn)
    conn.executemany(
        "INSERT INTO nodes (name, type, semantic_context, metadata) VALUES (?, ?, ?, ?)",
        [(n, "service", None, "{}") for n in NODE_IDS],
    )
    conn.executemany(
        "INSERT INTO edges (name, type, source, target, semantic_context, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            ("edge-a-b", "connects_to", "node-a", "node-b", None, "{}"),
            ("edge-b-c", "authenticates", "node-b", "node-c", None, "{}"),
            ("edge-a-d", "assumes", "node-a", "node-d", None, "{}"),
            ("edge-d-c", "accesses", "node-d", "node-c", None, "{}"),
        ],
    )
    conn.commit()
    conn.close()


class Recorder:
    """MockTransport handler that records calls and serves a healthy JEPA server."""

    def __init__(self, entry_status: int = 200):
        self.calls: list[httpx.Request] = []
        self.entry_status = entry_status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(request)
        path = request.url.path
        if path == f"/api/infra/branches/{BRANCH}":
            return httpx.Response(200, json={"id": BRANCH, "repository_id": REPO})
        if path == "/api/jepa/batch_entry_energies":
            if self.entry_status == 504:
                return httpx.Response(504, text="upstream timed out")
            if self.entry_status == -1:
                raise httpx.ReadTimeout("read timed out", request=request)
            return httpx.Response(200, json={"energies": [1.0, 2.0, 3.0, 4.0]})
        if path == "/api/jepa/graph_metadata":
            return httpx.Response(200, json={
                "node_ids": NODE_IDS,
                "edge_ids": EDGE_IDS,
                "node_types": ["service"] * 4,
                "edge_types": ["e"] * 4,
            })
        if path == "/api/jepa/batch_transition_energies":
            body = "data: " + json.dumps({
                "type": "complete", "result": {"energies": [-1.0, 2.0, -0.5, -2.0]},
            }) + "\n\n"
            return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})
        raise AssertionError(f"unexpected request: {request.method} {path}")

    def paths(self) -> list[str]:
        return [c.url.path for c in self.calls]

    def energy_bodies(self) -> list[dict]:
        return [
            json.loads(c.content or b"{}")
            for c in self.calls
            if c.url.path == "/api/jepa/batch_entry_energies"
        ]


def _client(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(base_url="http://test", transport=httpx.MockTransport(handler))


# ---------------------------------------------------------------------------
# _fetch_entry_energies / _fetch_and_merge_energies
# ---------------------------------------------------------------------------

async def test_gateway_timeout_raises_encoding_in_progress_after_one_request(tmp_path):
    rec = Recorder(entry_status=504)
    cache = EnergyGraphCache()
    cache._write_db = sqlite3.connect(str(tmp_path / "x.db"))
    EnergyGraphCache._create_tables(cache._write_db)

    async with _client(rec) as client:
        with pytest.raises(EncodingInProgress):
            await cache._fetch_and_merge_energies(BRANCH, REPO, client)

    assert rec.paths() == ["/api/jepa/batch_entry_energies"], "must not retry or fall through"
    assert all(body.get("force_refresh") is not True for body in rec.energy_bodies()), (
        "client must never ask the server to force_refresh — that discards the "
        "in-flight encode and starts another"
    )


async def test_read_timeout_raises_encoding_in_progress(tmp_path):
    rec = Recorder(entry_status=-1)
    cache = EnergyGraphCache()
    cache._write_db = sqlite3.connect(str(tmp_path / "x.db"))
    EnergyGraphCache._create_tables(cache._write_db)

    async with _client(rec) as client:
        with pytest.raises(EncodingInProgress):
            await cache._fetch_and_merge_energies(BRANCH, REPO, client)
    assert len(rec.calls) == 1


async def test_non_gateway_http_error_propagates(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    cache = EnergyGraphCache()
    cache._write_db = sqlite3.connect(str(tmp_path / "x.db"))
    EnergyGraphCache._create_tables(cache._write_db)
    async with _client(handler) as client:
        with pytest.raises(httpx.HTTPStatusError):
            await cache._fetch_and_merge_energies(BRANCH, REPO, client)


# ---------------------------------------------------------------------------
# refresh_energies
# ---------------------------------------------------------------------------

async def test_refresh_energies_merges_into_cached_graph(tmp_path, monkeypatch):
    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))

    cache = EnergyGraphCache.from_disk(BRANCH)
    assert cache is not None and cache.has_energies is False
    # from_disk does not know the repository — refresh must resolve it.
    assert not cache.repository_id

    rec = Recorder()
    async with _client(rec) as client:
        assert await cache.refresh_energies(client) is True

    assert cache.has_energies is True
    assert cache.encoding_in_progress is False
    assert cache.energy_error is None
    assert cache.repository_id == REPO
    rows = dict(cache.db.execute("SELECT name, entry_energy FROM nodes").fetchall())
    assert rows == {"node-a": 1.0, "node-b": 2.0, "node-c": 3.0, "node-d": 4.0}
    edges = dict(cache.db.execute("SELECT name, transition_energy FROM edges").fetchall())
    assert edges["edge-d-c"] == -2.0
    assert cache._write_db is None, "refresh must not leave a write connection open"
    # Graph was NOT re-downloaded.
    assert f"/api/infra/branches/{BRANCH}/graph/stream" not in rec.paths()


async def test_refresh_energies_records_in_progress_and_reraises(tmp_path, monkeypatch):
    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))
    cache = EnergyGraphCache.from_disk(BRANCH)

    rec = Recorder(entry_status=504)
    async with _client(rec) as client:
        with pytest.raises(EncodingInProgress):
            await cache.refresh_energies(client)

    assert cache.has_energies is False
    assert cache.encoding_in_progress is True
    assert "still encoding" in (cache.energy_error or "")
    assert cache._write_db is None


# ---------------------------------------------------------------------------
# build(fetch_energies=False)
# ---------------------------------------------------------------------------

async def test_build_without_energy_fetch_never_calls_jepa(tmp_path, monkeypatch):
    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    rec = Recorder()
    base = rec

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/api/infra/branches/{BRANCH}/graph/stream":
            rec.calls.append(request)
            lines = [json.dumps({"kind": "commit_id", "commit_id": "c1"})] + [
                json.dumps({"kind": "node", "name": n, "type": "service"}) for n in NODE_IDS
            ]
            return httpx.Response(200, text="\n".join(lines) + "\n")
        return base(request)

    async with _client(handler) as client:
        cache = await EnergyGraphCache.build(BRANCH, client, fetch_energies=False)

    assert cache.loaded and cache._n_nodes == 4
    assert cache.has_energies is False
    assert cache.encoding_in_progress is True
    assert not any(p.startswith("/api/jepa/") for p in rec.paths())
    cache.close()


# ---------------------------------------------------------------------------
# load_graph_energies disk-cache path completes energies in place
# ---------------------------------------------------------------------------

async def test_load_graph_energies_completes_energy_less_disk_cache(tmp_path, monkeypatch):
    from latent_defense_mcp import server

    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))

    rec = Recorder()
    client = _client(rec)
    warmups: list[str] = []

    async def fake_await_encoding(branch_id: str):
        warmups.append(branch_id)
        return True, None

    async def fake_http():
        return client

    monkeypatch.setattr(server, "_await_encoding", fake_await_encoding)
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

    assert warmups == [BRANCH], "must wait for server-side encoding before fetching"
    assert result["source"] == "disk_cache"
    assert result["status"] == "loaded"
    assert result["has_energies"] is True
    assert f"/api/infra/branches/{BRANCH}/graph/stream" not in rec.paths(), "graph not re-downloaded"


async def test_load_graph_energies_reports_encoding_when_server_still_busy(tmp_path, monkeypatch):
    from latent_defense_mcp import server

    monkeypatch.setattr(ec, "_CACHE_DIR", tmp_path)
    _graph_db_without_energies(str(ec._db_path(BRANCH)))

    rec = Recorder()
    client = _client(rec)

    async def fake_await_encoding(branch_id: str):
        return False, {"status": "encoding", "progress_pct": 42}

    async def fake_http():
        return client

    monkeypatch.setattr(server, "_await_encoding", fake_await_encoding)
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

    assert result["status"] == "loaded_without_energies"
    assert result["has_energies"] is False
    assert result["encoding"]["progress_pct"] == 42
    assert "WITHOUT force_refresh" in result["next_step"]
    assert not any(p.startswith("/api/jepa/") for p in rec.paths()), (
        "must not hit energy endpoints while the server is still encoding"
    )


# ---------------------------------------------------------------------------
# load_branch must not report "loaded" when the oracle says encoding_started
# ---------------------------------------------------------------------------

async def test_load_branch_reports_encoding_started_not_loaded(monkeypatch):
    from latent_defense_mcp import server

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/oracle/sessions" and request.method == "POST":
            return httpx.Response(200, json={"session_id": "sess-1"})
        if request.url.path == "/api/oracle/sessions/sess-1/call":
            return httpx.Response(200, json={"result": {"session_id": "sess-1", "status": "encoding_started"}})
        raise AssertionError(f"unexpected {request.method} {request.url.path}")

    client = _client(handler)

    async def fake_http():
        return client

    async def fake_post(path, body):
        r = await client.post(path, json=body)
        return r.json()

    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server, "_post", fake_post)
    monkeypatch.setattr(server, "_oracle_session", None)
    monkeypatch.setattr(server, "_graph_loaded", False)
    monkeypatch.setattr(server, "_start_keepalive", lambda: None)

    try:
        result = json.loads(await server.load_branch(BRANCH))
    finally:
        await client.aclose()

    assert result["status"] == "encoding_started"
    assert server._graph_loaded is False, "must not mark the graph loaded while encoding"


async def test_load_branch_reports_loaded_on_cache_hit(monkeypatch):
    from latent_defense_mcp import server

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/oracle/sessions" and request.method == "POST":
            return httpx.Response(200, json={"session_id": "sess-2"})
        if request.url.path == "/api/oracle/sessions/sess-2/call":
            return httpx.Response(200, json={"result": {"graph_id": BRANCH, "n_nodes": 4, "n_edges": 4}})
        raise AssertionError(f"unexpected {request.method} {request.url.path}")

    client = _client(handler)

    async def fake_http():
        return client

    async def fake_post(path, body):
        r = await client.post(path, json=body)
        return r.json()

    monkeypatch.setattr(server, "_http", fake_http)
    monkeypatch.setattr(server, "_post", fake_post)
    monkeypatch.setattr(server, "_oracle_session", None)
    monkeypatch.setattr(server, "_graph_loaded", False)
    monkeypatch.setattr(server, "_start_keepalive", lambda: None)

    try:
        result = json.loads(await server.load_branch(BRANCH))
    finally:
        await client.aclose()

    assert result["status"] == "loaded"
    assert result["result"]["n_nodes"] == 4
    assert server._graph_loaded is True


# ---------------------------------------------------------------------------
# wait_for_load must not trust the session probe while the encoder is busy
# ---------------------------------------------------------------------------

async def test_wait_for_load_ignores_stale_probe_while_encoding(monkeypatch):
    from latent_defense_mcp import server

    stages = iter([4, 4, 8])  # embedding, embedding, complete
    probes: list[str] = []

    async def fake_progress():
        return {"stage": next(stages), "progress_pct": 50}

    async def fake_probe(expected_branch=None):
        probes.append(expected_branch)
        return {"graph_id": expected_branch, "n_nodes": 4}  # always "loaded" (stale)

    async def no_sleep(_):
        return None

    monkeypatch.setattr(server, "_fetch_encoding_progress", fake_progress)
    monkeypatch.setattr(server, "_probe_oracle_graph_loaded", fake_probe)
    monkeypatch.setattr(server, "_load_branch_id", BRANCH)
    monkeypatch.setattr(server, "_oracle_session", "sess-3")
    monkeypatch.setattr(server, "_graph_loaded", False)
    monkeypatch.setattr(server, "_encoding_started_at", None)
    monkeypatch.setattr(server.asyncio, "sleep", no_sleep)

    result = json.loads(await server.wait_for_load(timeout_secs=60, poll_interval=1))

    assert result["status"] == "loaded"
    assert probes == [BRANCH], "probe must only be consulted once the encoder reports complete"


async def test_wait_for_load_reports_encoder_failure(monkeypatch):
    from latent_defense_mcp import server

    async def fake_progress():
        return {"stage": 9, "error": "OOM"}

    async def fake_probe(expected_branch=None):
        raise AssertionError("probe must not be called on failure")

    monkeypatch.setattr(server, "_fetch_encoding_progress", fake_progress)
    monkeypatch.setattr(server, "_probe_oracle_graph_loaded", fake_probe)
    monkeypatch.setattr(server, "_load_branch_id", BRANCH)
    monkeypatch.setattr(server, "_oracle_session", "sess-4")
    monkeypatch.setattr(server, "_graph_loaded", False)

    result = json.loads(await server.wait_for_load(timeout_secs=60, poll_interval=1))
    assert result["status"] == "failed"
    assert result["error"] == "OOM"
