"""Graph read and search tools backed by the SQLite EnergyGraphCache."""

from __future__ import annotations

import json
from typing import Any, Callable

from .energy_cache import EnergyGraphCache


def register(mcp: Any, get_cache: Callable[[], EnergyGraphCache | None]) -> None:
    """Register graph read/search tools on *mcp*."""

    def _gate() -> str | None:
        c = get_cache()
        if c is None or not c.loaded:
            return json.dumps({
                "error": "No graph loaded. Call load_graph_energies(branch_id) first.",
            })
        return None

    # ------------------------------------------------------------------
    # Read (4 tools)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def read_node(name: str) -> str:
        """Return the full node object by name (type, semantic context, metadata, energy scores).

        Supports exact match or substring match if exact name is not found.
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        # Try exact, then resolve via substring
        node = cache.query_node(name)
        if node is None:
            resolved = cache.resolve_node(name)
            if resolved:
                node = cache.query_node(resolved)
        if node is None:
            return json.dumps({"error": f"Node not found: {name}"})
        edges = cache.get_connected_edges(node["name"])
        node["outbound_edges"] = sum(1 for e in edges if e.get("direction") == "outbound")
        node["inbound_edges"] = sum(1 for e in edges if e.get("direction") == "inbound")
        return json.dumps(node)

    @mcp.tool()
    async def read_edge(name: str) -> str:
        """Return the full edge object by exact name (type, source, target, semantic context, metadata, energy)."""
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        row = cache.db.execute(f"SELECT {cols} FROM edges WHERE name = ?", (name,)).fetchone()
        if row is None:
            return json.dumps({"error": f"Edge not found: {name}"})
        return json.dumps(cache._edge_from_row(row))

    @mcp.tool()
    async def get_connected_edges(node_name: str, direction: str = "both") -> str:
        """Get all edges connected to a node.

        Supports exact match or substring match on the node name.

        Args:
            node_name: Node name (exact or substring).
            direction: "outbound", "inbound", or "both" (default).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        resolved = cache.resolve_node(node_name)
        if resolved is None:
            return json.dumps({"error": f"Node not found: {node_name}"})
        edges = cache.get_connected_edges(resolved, direction)
        return json.dumps({
            "node": resolved,
            "direction": direction,
            "count": len(edges),
            "edges": edges,
        })

    @mcp.tool()
    async def get_graph_statistics() -> str:
        """Get node/edge counts, type distributions, and containment edge count."""
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        return json.dumps({
            "n_nodes": cache._n_nodes,
            "n_edges": cache._n_edges,
            "n_node_types": cache._n_node_types,
            "n_edge_types": cache._n_edge_types,
            "n_containment_edges": cache._n_containment,
            "branch_id": cache.branch_id,
            "commit_id": cache.commit_id,
            "node_type_distribution": cache.node_type_distribution(),
            "edge_type_distribution": cache.edge_type_distribution(),
        })

    # ------------------------------------------------------------------
    # Search (4 tools)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def grep_nodes(pattern: str, field: str = "name", limit: int = 25) -> str:
        """Find nodes by case-insensitive substring match.

        Args:
            pattern: Substring to search for.
            field: "name", "type", "context", or "all" (default "name").
            limit: Maximum results (default 25).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        results = cache.grep_nodes(pattern, field, limit)
        return json.dumps({
            "pattern": pattern,
            "field": field,
            "count": len(results),
            "nodes": [{"name": n["name"], "type": n["type"]} for n in results],
        })

    @mcp.tool()
    async def grep_edges(pattern: str, field: str = "name", limit: int = 25) -> str:
        """Find edges by case-insensitive substring match.

        Args:
            pattern: Substring to search for.
            field: "name", "type", "context", or "all" (default "name").
            limit: Maximum results (default 25).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        results = cache.grep_edges(pattern, field, limit)
        return json.dumps({
            "pattern": pattern,
            "field": field,
            "count": len(results),
            "edges": [{"name": e["name"], "type": e["type"], "source": e["source"], "target": e["target"]}
                      for e in results],
        })

    @mcp.tool()
    async def find_nodes_by_type(node_type: str, limit: int = 50) -> str:
        """Get all nodes of a given type.

        Args:
            node_type: Exact type name (e.g. "service", "iam_role", "s3_bucket").
            limit: Maximum results (default 50).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        results, total = cache.find_nodes_by_type(node_type, limit)
        return json.dumps({
            "type": node_type,
            "count": len(results),
            "total": total,
            "nodes": [{"name": n["name"], "type": n["type"]} for n in results],
        })

    @mcp.tool()
    async def find_edges_by_type(edge_type: str, limit: int = 50) -> str:
        """Get all edges of a given type.

        Args:
            edge_type: Exact type name (e.g. "contains", "connects_to", "authenticates").
            limit: Maximum results (default 50).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        results, total = cache.find_edges_by_type(edge_type, limit)
        return json.dumps({
            "type": edge_type,
            "count": len(results),
            "total": total,
            "edges": [{"name": e["name"], "type": e["type"], "source": e["source"], "target": e["target"]}
                      for e in results],
        })
