"""LD-2052: `paths_through_node(node_id)` MCP tool.

A thin `triage:read` wrapper over `GET /api/triage/paths?node_id=X`, which the
triage backend resolves server-side via the InfraDB `node_names` GIN index
(`node_names @> ARRAY[node_id]`). These tests monkeypatch the `_get` HTTP seam
so no live server is needed — they pin that node_id (and the other filters) are
forwarded, that the summary projection matches list_attack_paths, and that the
tool is registered as triage:read.
"""

import json

import pytest

from latent_defense_mcp import server
from latent_defense_mcp.errors import TOOL_SCOPES

pytestmark = pytest.mark.asyncio


def _make_path(**overrides):
    p = {
        "path_id": "p1",
        "status": "new",
        "risk_score": 82.0,
        "difficulty": "easy",
        "entry_node": "web-server",
        "target_node": "secrets-vault",
        "source": "unconstrained",
        "branch_id": "b1",
        "created_at": "2026-08-07T00:00:00Z",
        "steps": [
            {"source_node": "web-server", "target_node": "rds-primary"},
            {"source_node": "rds-primary", "target_node": "secrets-vault"},
        ],
    }
    p.update(overrides)
    return p


class TestPathsThroughNodeForwarding:
    async def test_node_id_is_forwarded(self, monkeypatch):
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["path"] = path
            seen["tool"] = _tool
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.paths_through_node(node_id="rds-primary")

        assert seen["path"] == "/api/triage/paths"
        assert seen["tool"] == "paths_through_node"
        assert seen["params"].get("node_id") == "rds-primary"

    async def test_combines_with_other_filters(self, monkeypatch):
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.paths_through_node(
            node_id="rds-primary",
            status="acknowledged",
            min_risk_score=60,
            repository_id="repo_a",
            mitre_technique="T1078",
            order="risk_score_asc",
        )

        p = seen["params"]
        assert p["node_id"] == "rds-primary"
        assert p["status"] == "acknowledged"
        assert p["min_risk_score"] == 60
        assert p["repository_id"] == "repo_a"
        assert p["mitre_technique"] == "T1078"
        assert p["order"] == "risk_score_asc"

    async def test_default_filters_absent(self, monkeypatch):
        # Only node_id + pagination are sent when nothing else is set — a zero
        # min_risk_score / empty status must not be forwarded.
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.paths_through_node(node_id="rds-primary")

        assert set(seen["params"]) == {"node_id", "limit", "offset"}


class TestPathsThroughNodeProjection:
    async def test_summary_returns_compact_entries(self, monkeypatch):
        async def fake_get(path, *, _tool="", **params):
            return {"items": [_make_path()], "total": 1}

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.paths_through_node(node_id="rds-primary"))

        assert out["total"] == 1
        assert out["has_more"] is False
        item = out["items"][0]
        assert item["path_id"] == "p1"
        assert item["risk_score"] == 82.0
        assert item["status"] == "new"
        assert item["n_steps"] == 2
        # summary collapses steps to a count
        assert "steps" not in item

    async def test_full_detail_returns_steps(self, monkeypatch):
        async def fake_get(path, *, _tool="", **params):
            return {"items": [_make_path()], "total": 1}

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(
            await server.paths_through_node(node_id="rds-primary", summary=False)
        )
        assert out["items"][0]["steps"][0]["target_node"] == "rds-primary"


class TestPathsThroughNodeScope:
    async def test_registered_as_triage_read(self):
        assert TOOL_SCOPES["paths_through_node"] == "triage:read"
