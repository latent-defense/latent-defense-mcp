"""Evidence metadata surfacing through get_attack_path and list_attack_paths.

Attack-path steps and graph nodes carry structured evidence (``source_ref`` +
``evidence``) plus the per-step rationale inference emits
(``energy`` / ``edge_type`` / ``implicit`` / ``match_confidence``). The MCP tools
forward the upstream response generically — ``get_attack_path`` and
``list_attack_paths(summary=False)`` return the full path dict (only a handful of
internal bookkeeping keys are dropped).

These tests monkeypatch the ``_get`` HTTP seam so no live server is needed, and
pin that the new fields reach the returned shape. They also pin the deliberate
carve-out: ``list_attack_paths(summary=True)`` (the default) intentionally
collapses steps to a count, so step evidence is surfaced through the full-detail
tools, not the summary view.
"""

import json

import pytest

from latent_defense_mcp import server

# Every test in this module drives an async tool coroutine.
pytestmark = pytest.mark.asyncio


# Shapes mirror the shared evidence contract.
_SOURCE_REF = {
    "repo_url": "https://github.com/org/repo",
    "commit": "abc123",
    "file": "infra/vpc.tf",
    "line": 10,
    "line_end": 24,
}
_EVIDENCE = [
    {
        "source_type": "code",
        "source_ref": _SOURCE_REF,
        "description": "IAM role trust policy allows any principal to assume",
    }
]


def _make_step():
    """A path step carrying evidence + source_ref + rationale."""
    return {
        "step_index": 0,
        "technique": "assume_role",
        "description": "Assume the over-permissive role",
        # Typed rationale fields (alongside legacy metadata).
        "energy": 1.23,
        "edge_type": "assumes_role",
        "implicit": True,
        "match_confidence": 0.87,
        "source_ref": _SOURCE_REF,
        "evidence": _EVIDENCE,
        "metadata": {"implicit": True, "edge_type": "assumes_role"},
    }


def _make_path():
    return {
        "path_id": "p1",
        "status": "new",
        "risk_score": 75.0,
        "difficulty": "medium",
        "entry_node": "internet",
        "target_node": "secrets",
        "source": "unconstrained",
        "branch_id": "b1",
        "created_at": "2026-07-13T00:00:00Z",
        "source_artifacts": [
            {"type": "git", "repo_url": "https://github.com/org/repo", "commit": "abc123"}
        ],
        "steps": [_make_step()],
        # internal bookkeeping fields get_attack_path is expected to drop
        "validation_retry_count": 2,
        "environment_profile": "graph_only",
    }


class TestGetAttackPathSurfacesEvidence:
    async def test_get_attack_path_forwards_step_evidence(self, monkeypatch):
        async def fake_get(path, *, _tool="", **params):
            assert path == "/api/triage/paths/p1"
            return _make_path()

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.get_attack_path("p1"))

        assert out["path_id"] == "p1"
        assert out["source_artifacts"][0]["repo_url"] == "https://github.com/org/repo"
        step = out["steps"][0]
        assert step["source_ref"] == _SOURCE_REF
        assert step["evidence"] == _EVIDENCE
        assert step["energy"] == 1.23
        assert step["match_confidence"] == 0.87
        assert step["implicit"] is True
        # internal bookkeeping fields are still stripped (unchanged behavior)
        assert "validation_retry_count" not in out
        assert "environment_profile" not in out

    async def test_get_attack_path_legacy_path_without_evidence(self, monkeypatch):
        # Backward compatibility: a path with plain steps still works.
        async def fake_get(path, *, _tool="", **params):
            return {
                "path_id": "p0",
                "status": "new",
                "steps": [{"step_index": 0, "technique": "recon", "description": "look"}],
            }

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.get_attack_path("p0"))
        assert out["steps"][0]["technique"] == "recon"
        assert "source_ref" not in out["steps"][0]


class TestListAttackPathsSurfacesEvidence:
    async def test_full_detail_forwards_step_evidence(self, monkeypatch):
        async def fake_get(path, *, _tool="", **params):
            return {"items": [_make_path()], "total": 1}

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.list_attack_paths(summary=False))

        step = out["items"][0]["steps"][0]
        assert step["source_ref"] == _SOURCE_REF
        assert step["evidence"] == _EVIDENCE
        assert step["edge_type"] == "assumes_role"

    async def test_summary_view_collapses_steps_by_design(self, monkeypatch):
        # The summary view deliberately reduces steps to a count. Evidence is
        # surfaced via the full-detail tools (summary=False / get_attack_path).
        async def fake_get(path, *, _tool="", **params):
            return {"items": [_make_path()], "total": 1}

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.list_attack_paths(summary=True))

        item = out["items"][0]
        assert item["n_steps"] == 1
        assert "steps" not in item


# Node evidence tests deprecated — use read_node and get_connected_edges.
