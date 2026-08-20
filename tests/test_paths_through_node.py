"""list_attack_paths(node_id=) — filter attack paths by node.

Tests that the ``node_id`` filter on ``list_attack_paths`` correctly forwards
to ``GET /api/triage/paths?node_id=X`` (resolved server-side via the infrastructure database
``node_names`` GIN index). These tests monkeypatch the ``_get`` HTTP seam so no
live server is needed — they pin that node_id (and the other filters) are
forwarded, that the summary projection works, and that the tool is registered
as triage:read.
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


class TestListAttackPathsNodeIdForwarding:
    async def test_node_id_is_forwarded(self, monkeypatch):
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["path"] = path
            seen["tool"] = _tool
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.list_attack_paths(node_id="rds-primary")

        assert seen["path"] == "/api/triage/paths"
        assert seen["tool"] == "list_attack_paths"
        assert seen["params"].get("node_id") == "rds-primary"

    async def test_combines_with_other_filters(self, monkeypatch):
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.list_attack_paths(
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
        await server.list_attack_paths(node_id="rds-primary")

        assert set(seen["params"]) == {"node_id", "limit", "offset"}


class TestListAttackPathsNodeIdProjection:
    async def test_summary_returns_compact_entries(self, monkeypatch):
        async def fake_get(path, *, _tool="", **params):
            return {"items": [_make_path()], "total": 1}

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.list_attack_paths(node_id="rds-primary"))

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
            await server.list_attack_paths(node_id="rds-primary", summary=False)
        )
        assert out["items"][0]["steps"][0]["target_node"] == "rds-primary"


class TestListAttackPathsScope:
    async def test_registered_as_triage_read(self):
        assert TOOL_SCOPES["list_attack_paths"] == "triage:read"
