"""Tests for the verify_remediation tool — P6 graph-structural cut detection."""

import json
import pytest
from unittest.mock import AsyncMock

import latent_defense_mcp.server as srv
from latent_defense_mcp.errors import TOOL_SCOPES

pytestmark = pytest.mark.asyncio

# --- Fixtures ---

_SOURCE_GRAPH = {
    "nodes": {"a": {"type": "t"}, "b": {"type": "t"}, "c": {"type": "t"}, "d": {"type": "t"}},
    "edges": [
        {"source": "a", "target": "b", "type": "e"},
        {"source": "b", "target": "c", "type": "e"},
        {"source": "c", "target": "d", "type": "e"},
    ],
}

_REMEDIATED_CUT = {
    "nodes": {"a": {"type": "t"}, "b": {"type": "t"}, "c": {"type": "t"}, "d": {"type": "t"}},
    "edges": [
        {"source": "a", "target": "b", "type": "e"},
        {"source": "c", "target": "d", "type": "e"},
    ],
}

_REMEDIATED_NO_CUT = {
    "nodes": {"a": {"type": "t"}, "b": {"type": "t"}, "c": {"type": "t"}, "d": {"type": "t"}},
    "edges": [
        {"source": "a", "target": "b", "type": "e"},
        {"source": "b", "target": "c", "type": "e"},
        {"source": "c", "target": "d", "type": "e"},
    ],
}

_COLLAPSED_GRAPH = {
    "nodes": {"a": {"type": "t"}},
    "edges": [],
}

_DICT_EDGES_GRAPH = {
    "nodes": {"a": {"type": "t"}, "b": {"type": "t"}, "c": {"type": "t"}},
    "edges": {
        "e0": {"source": "a", "target": "b", "type": "e"},
        "e1": {"source": "b", "target": "c", "type": "e"},
    },
}


def _patch_get(monkeypatch, source_graph, remediation_graph):
    """Patch _get with branch-head resolution and immutable graph snapshots."""
    graphs = {
        "src-head": source_graph,
        "rem-head": remediation_graph,
    }

    async def fake_get(path, _tool=None, **params):
        if path == "/api/infra/branches/src-branch/commits":
            assert params == {"limit": 1}
            return [{"commit_id": "src-head"}]
        if path == "/api/infra/branches/rem-branch/commits":
            assert params == {"limit": 1}
            return [{"commit_id": "rem-head"}]
        if path == "/api/infra/commits/src-head/graph":
            return graphs["src-head"]
        if path == "/api/infra/commits/rem-head/graph":
            return graphs["rem-head"]
        raise AssertionError(f"Unexpected _get call: {path}")

    monkeypatch.setattr(srv, "_get", fake_get)


# --- Tests ---

async def test_path_cut(monkeypatch):
    """Path-specific mode: edge b→c removed → verdict 'cut'."""
    _patch_get(monkeypatch, _SOURCE_GRAPH, _REMEDIATED_CUT)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "a,b,c,d"))
    assert result["verdict"] == "cut"
    assert ["b", "c"] in result["edges_cut"]
    assert len(result["edges_surviving"]) == 2


async def test_path_no_cut(monkeypatch):
    """Path-specific mode: no edges removed → verdict 'no_cut'."""
    _patch_get(monkeypatch, _SOURCE_GRAPH, _REMEDIATED_NO_CUT)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "a,b,c,d"))
    assert result["verdict"] == "no_cut"
    assert result["edges_cut"] == []


async def test_full_diff(monkeypatch):
    """No path_node_ids → full edge-set diff mode."""
    _patch_get(monkeypatch, _SOURCE_GRAPH, _REMEDIATED_CUT)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", ""))
    assert result["verdict"] == "structural_diff"
    assert len(result["edges_cut"]) == 1
    assert result["edges_cut"][0] == ["b", "c"]
    assert result["source_commit_id"] == "src-head"
    assert result["remediation_commit_id"] == "rem-head"


async def test_graph_collapse(monkeypatch):
    """Remediation graph has <50% source nodes → 'unscorable'."""
    _patch_get(monkeypatch, _SOURCE_GRAPH, _COLLAPSED_GRAPH)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "a,b,c"))
    assert result["verdict"] == "unscorable"
    assert result["node_count_source"] == 4
    assert result["node_count_remediation"] == 1


async def test_too_few_path_nodes(monkeypatch):
    """path_node_ids with only 1 node → error."""
    _patch_get(monkeypatch, _SOURCE_GRAPH, _REMEDIATED_CUT)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "a"))
    assert "error" in result


async def test_dict_keyed_edges(monkeypatch):
    """Handles the raw InfraDB dict-keyed edge shape."""
    _patch_get(monkeypatch, _DICT_EDGES_GRAPH, {
        "nodes": {"a": {"type": "t"}, "b": {"type": "t"}, "c": {"type": "t"}},
        "edges": {"e0": {"source": "a", "target": "b", "type": "e"}},
    })
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "a,b,c"))
    assert result["verdict"] == "cut"
    assert ["b", "c"] in result["edges_cut"]


async def test_nonexistent_path_edges(monkeypatch):
    """Path references edges not in source → skipped, no false cut."""
    _patch_get(monkeypatch, _SOURCE_GRAPH, _REMEDIATED_CUT)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "x,y,z"))
    assert result["verdict"] == "no_cut"
    assert result["edges_cut"] == []
    assert result["edges_surviving"] == []


async def test_branch_advancement_cannot_change_pinned_comparison(monkeypatch):
    """Commit graphs, not mutable branch-graph endpoints, define the verdict."""
    calls: list[str] = []

    async def fake_get(path, _tool=None, **params):
        calls.append(path)
        if path == "/api/infra/branches/src-branch/commits":
            return [{"commit_id": "src-before-advance"}]
        if path == "/api/infra/branches/rem-branch/commits":
            # The branch may advance after the source head was captured; the
            # prior head remains the immutable remediation snapshot for this run.
            return [{"commit_id": "rem-before-advance"}]
        if path == "/api/infra/commits/src-before-advance/graph":
            return _SOURCE_GRAPH
        if path == "/api/infra/commits/rem-before-advance/graph":
            return _REMEDIATED_CUT
        raise AssertionError(f"verify_remediation must not fetch mutable branch graph: {path}")

    monkeypatch.setattr(srv, "_get", fake_get)
    result = json.loads(await srv.verify_remediation("src-branch", "rem-branch", "a,b,c"))

    assert result["verdict"] == "cut"
    assert result["source_commit_id"] == "src-before-advance"
    assert result["remediation_commit_id"] == "rem-before-advance"
    assert all("/branches/" not in path or path.endswith("/commits") for path in calls)


async def test_tool_scopes_are_registered():
    assert TOOL_SCOPES["merge_branch"] == "infra:write"
    assert TOOL_SCOPES["verify_remediation"] == "infra:read"
