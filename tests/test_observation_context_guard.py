"""add_node / add_edge / edit_* must refuse empty semantic_context.

The encoder produces NaN energies for any element without description lines,
and the NaN spreads two hops through message passing.
"""

from __future__ import annotations

import json

import pytest

from latent_defense_mcp import observation_tools
from latent_defense_mcp.energy_cache import EnergyGraphCache

from tests.test_energy_cache import _build_fixture_cache

pytestmark = pytest.mark.asyncio


@pytest.fixture
def tools(tmp_path):
    from mcp.server.fastmcp import FastMCP

    cache: EnergyGraphCache = _build_fixture_cache(str(tmp_path))
    # Fixture cache opens read-only; writes need a writable copy path.
    mcp = FastMCP("test")
    observation_tools.register(mcp, lambda: cache)
    fns = {name: t.fn for name, t in mcp._tool_manager._tools.items()}
    yield fns
    cache.close()


async def test_add_edge_requires_semantic_context(tools):
    for bad in (None, [], [""], ["   "]):
        result = json.loads(await tools["add_edge"](
            name="edge-x", type="contains", source="node-a", target="node-b",
            semantic_context=bad, reason="test",
        ))
        assert "error" in result and "semantic_context is required" in result["error"], bad
        assert "NaN" in result["why"]


async def test_add_node_requires_semantic_context(tools):
    result = json.loads(await tools["add_node"](name="node-x", type="service", semantic_context=[]))
    assert "semantic_context is required" in result["error"]


async def test_add_edge_with_context_passes_guard(tools):
    result = json.loads(await tools["add_edge"](
        name="edge-ok", type="contains", source="node-a", target="node-b",
        semantic_context=["node-a contains node-b, verified in test"], reason="test",
    ))
    assert result.get("action") == "added", result


async def test_edit_edge_rejects_blanking_context(tools):
    # Satisfy the read-before-write gate the way read_edge does.
    observation_tools.mark_edge_read("edge-a-b")
    result = json.loads(await tools["edit_edge"](name="edge-a-b", semantic_context=[]))
    assert "semantic_context is required" in result.get("error", ""), result


async def test_edit_node_rejects_blanking_context(tools):
    observation_tools.mark_node_read("node-a")
    result = json.loads(await tools["edit_node"](name="node-a", semantic_context=[""]))
    assert "semantic_context is required" in result.get("error", ""), result
