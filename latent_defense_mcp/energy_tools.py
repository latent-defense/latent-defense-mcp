"""Energy analysis tools backed by the SQLite EnergyGraphCache.

All tools use SQL queries — no full-graph iteration in Python.
"""

from __future__ import annotations

import heapq
import json
import math
import time
from collections import Counter
from typing import Any, Callable

from .energy_cache import EnergyGraphCache


def _shorten_id(nid: str) -> str:
    """Trim node IDs for display readability."""
    parts = nid.split("-")
    filler = {"service", "module", "scope", "gh", "class", "node", "function"}
    meaningful = [p for p in parts if p not in filler]
    return "-".join(meaningful[-3:]) if meaningful else nid[-30:]


def register(mcp: Any, get_cache: Callable[[], EnergyGraphCache | None]) -> None:
    """Register energy analysis tools on *mcp*."""

    def _gate() -> str | None:
        c = get_cache()
        if c is None or not c.loaded:
            return json.dumps({
                "error": "No graph loaded. Load the graph first: "
                "load_graph_energies(branch_id).",
            })
        if not c.has_energies:
            return json.dumps({
                "error": "Graph loaded but energy scores are not available.",
                "reason": c.energy_error or "Unknown",
                "next_step": (
                    "Retry load_graph_energies(branch_id) — it handles "
                    "inference cache warm-up internally."
                ),
            })
        return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    _label_caches: dict[str, dict[str, list[str]]] = {}

    def _build_label_cache(cache: EnergyGraphCache) -> dict[str, list[str]]:
        """Build a reverse index from shortened labels to full node names."""
        bid = cache.branch_id or ""
        if bid in _label_caches:
            return _label_caches[bid]
        index: dict[str, list[str]] = {}
        rows = cache.db.execute("SELECT name FROM nodes").fetchall()
        for (name,) in rows:
            label = _shorten_id(name)
            index.setdefault(label, []).append(name)
            ll = label.lower()
            if ll != label:
                index.setdefault(ll, []).append(name)
        _label_caches[bid] = index
        return index

    class _AmbiguousLabel(Exception):
        """Raised when a short label matches multiple nodes."""
        def __init__(self, label: str, candidates: list[str]):
            self.label = label
            self.candidates = candidates
            super().__init__(
                f"Ambiguous label '{label}' matches {len(candidates)} nodes: "
                f"{candidates}. Use the full node ID instead."
            )

    def _resolve(cache: EnergyGraphCache, query: str) -> str | None:
        """Resolve a query to a node name.  Falls back to label matching.

        Raises ``_AmbiguousLabel`` when the short-label index contains
        multiple candidates for the query.
        """
        result = cache.resolve_node(query)
        if result is not None:
            return result
        label_index = _build_label_cache(cache)
        if query in label_index:
            candidates = label_index[query]
            if len(candidates) > 1:
                raise _AmbiguousLabel(query, candidates)
            return candidates[0]
        ql = query.lower()
        if ql in label_index:
            candidates = label_index[ql]
            if len(candidates) > 1:
                raise _AmbiguousLabel(ql, candidates)
            return candidates[0]
        return None

    def _node_summary(cache: EnergyGraphCache, name: str) -> dict | None:
        """Lightweight node lookup (no semantic_context/metadata)."""
        row = cache.db.execute(
            "SELECT name, type, entry_energy FROM nodes WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        return {"name": row[0], "type": row[1], "entry_energy": row[2]}

    def _ctx_snippet(cache: EnergyGraphCache, name: str, max_len: int = 150) -> str:
        row = cache.db.execute(
            "SELECT semantic_context FROM nodes WHERE name = ?", (name,)
        ).fetchone()
        if row is None or row[0] is None:
            return ""
        ctx = json.loads(row[0])
        return (ctx[0][:max_len] if isinstance(ctx, list) and ctx else "")

    # ------------------------------------------------------------------
    # Atomic (4 tools)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def energy_node_scores(node_query: str, top_k: int = 20) -> str:
        """Get energy scores for nodes matching a query (searches node IDs and semantic context).

        Returns entry energy, type, context, and connected edge energies for each match.
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        nodes = cache.grep_nodes(node_query, "all", top_k)
        if not nodes:
            # Fall back to label resolution
            try:
                resolved = _resolve(cache, node_query)
            except _AmbiguousLabel as exc:
                return json.dumps({"error": str(exc)})
            if resolved:
                node_data = cache.query_node(resolved)
                if node_data:
                    nodes = [node_data]
        results = []
        for node in nodes:
            name = node["name"]
            outbound = []
            for e in cache.get_outbound_edges(name):
                dst = _node_summary(cache, e["target"])
                outbound.append({
                    "target": _shorten_id(e["target"]),
                    "target_type": dst["type"] if dst else "unknown",
                    "edge_type": e["type"],
                    "transition_energy": round(e["transition_energy"], 3) if e["transition_energy"] is not None else None,
                    "accelerating": e["transition_energy"] < 0 if e["transition_energy"] is not None else None,
                })
            inbound = []
            for e in cache.get_inbound_edges(name):
                src = _node_summary(cache, e["source"])
                inbound.append({
                    "source": _shorten_id(e["source"]),
                    "source_type": src["type"] if src else "unknown",
                    "edge_type": e["type"],
                    "transition_energy": round(e["transition_energy"], 3) if e["transition_energy"] is not None else None,
                })
            outbound.sort(key=lambda x: x["transition_energy"] if x["transition_energy"] is not None else 999)
            inbound.sort(key=lambda x: x["transition_energy"] if x["transition_energy"] is not None else 999)
            ctx = node.get("semantic_context", [])
            ctx_str = ctx[0][:150] if isinstance(ctx, list) and ctx else ""
            results.append({
                "node_id": name,
                "label": _shorten_id(name),
                "type": node["type"],
                "entry_energy": round(node["entry_energy"], 4) if node["entry_energy"] is not None else None,
                "context": ctx_str,
                "outbound_edges": outbound[:10],
                "inbound_edges": inbound[:10],
                "total_outbound": len(outbound),
                "total_inbound": len(inbound),
                "accel_outbound": sum(1 for e in outbound if e.get("accelerating") is True),
            })
        return json.dumps({"query": node_query, "matches": len(results), "nodes": results})

    @mcp.tool()
    async def energy_edge_scores(source_query: str, target_query: str = "") -> str:
        """Get transition energy for edges between nodes matching the queries.

        If only source_query is given, returns all edges FROM matching nodes.
        If both given, returns edges between matching source and target nodes.
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        db = cache.db
        src_like = f"%{source_query}%"
        cols = "e.name, e.type, e.source, e.target, e.transition_energy"

        if target_query:
            tgt_like = f"%{target_query}%"
            rows = db.execute(
                f"SELECT {cols} FROM edges e "
                "JOIN nodes ns ON e.source = ns.name "
                "JOIN nodes nt ON e.target = nt.name "
                "WHERE (ns.name LIKE ? COLLATE NOCASE OR ns.semantic_context LIKE ? COLLATE NOCASE) "
                "AND (nt.name LIKE ? COLLATE NOCASE OR nt.semantic_context LIKE ? COLLATE NOCASE) "
                "ORDER BY e.transition_energy IS NULL, e.transition_energy LIMIT 50",
                (src_like, src_like, tgt_like, tgt_like),
            ).fetchall()
        else:
            rows = db.execute(
                f"SELECT {cols} FROM edges e "
                "JOIN nodes ns ON e.source = ns.name "
                "WHERE ns.name LIKE ? COLLATE NOCASE OR ns.semantic_context LIKE ? COLLATE NOCASE "
                "ORDER BY e.transition_energy IS NULL, e.transition_energy LIMIT 50",
                (src_like, src_like),
            ).fetchall()

        results = []
        for r in rows:
            te = r[4]
            src_node = _node_summary(cache, r[2])
            dst_node = _node_summary(cache, r[3])
            results.append({
                "source": _shorten_id(r[2]),
                "source_type": src_node["type"] if src_node else "unknown",
                "target": _shorten_id(r[3]),
                "target_type": dst_node["type"] if dst_node else "unknown",
                "edge_type": r[1],
                "transition_energy": round(te, 3) if te is not None else None,
                "accelerating": te < 0 if te is not None else None,
                "source_entry": round(src_node["entry_energy"], 3) if src_node and src_node["entry_energy"] else None,
                "target_entry": round(dst_node["entry_energy"], 3) if dst_node and dst_node["entry_energy"] else None,
            })
        return json.dumps({"query": {"source": source_query, "target": target_query}, "edges": results})

    @mcp.tool()
    async def energy_momentum_path(node_names: str) -> str:
        """Compute momentum along a specific path of node names (comma-separated or JSON array).

        Args:
            node_names: Comma-separated node names or a JSON array of node name strings.
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()

        names: list[str]
        try:
            names = json.loads(node_names)
        except (json.JSONDecodeError, TypeError):
            names = [n.strip() for n in node_names.split(",") if n.strip()]
        if len(names) < 2:
            return json.dumps({"error": "Path must have at least 2 nodes."})

        resolved = []
        for name in names:
            try:
                r = _resolve(cache, name)
            except _AmbiguousLabel as exc:
                return json.dumps({"error": str(exc)})
            if r is None:
                return json.dumps({"error": f"Node not found: {name}"})
            resolved.append(r)

        first = _node_summary(cache, resolved[0])
        if first["entry_energy"] is None:
            return json.dumps({"error": f"Node {resolved[0]} has no entry energy. Energy data may not have loaded for this node."})
        entry_e = first["entry_energy"]
        momentum = 99.0 / (1.0 + math.exp(min(entry_e, 700.0)))

        steps = [{
            "node": _shorten_id(resolved[0]),
            "node_id": resolved[0],
            "type": first["type"],
            "entry_energy": round(entry_e, 3),
            "momentum": round(momentum, 1),
        }]

        for j in range(1, len(resolved)):
            src, dst = resolved[j - 1], resolved[j]
            row = cache.db.execute(
                "SELECT type, transition_energy FROM edges WHERE source = ? AND target = ? LIMIT 1",
                (src, dst),
            ).fetchone()
            if row is None:
                return json.dumps({"error": f"No edge from {src} to {dst}"})
            et, te = row[0], row[1]
            if te is None:
                return json.dumps({"error": f"Edge from {src} to {dst} has no transition energy"})

            if te < 0:
                momentum += (99.0 - momentum) * 0.25 * min(abs(te), 4.0) / 4.0
            else:
                momentum -= momentum * 0.40 * min(te, 5.0) / 5.0
            momentum = max(0.0, min(100.0, momentum))

            dst_node = _node_summary(cache, dst)
            steps.append({
                "node": _shorten_id(dst),
                "node_id": dst,
                "type": dst_node["type"] if dst_node else "unknown",
                "entry_energy": round(dst_node["entry_energy"], 3) if dst_node and dst_node["entry_energy"] is not None else None,
                "edge_type": et,
                "transition_energy": round(te, 3),
                "accelerating": te < 0,
                "momentum": round(momentum, 1),
            })

        return json.dumps({
            "path_length": len(resolved),
            "final_momentum": round(momentum, 1),
            "steps": steps,
        })

    @mcp.tool()
    async def energy_lowest_hop(node_query: str, direction: str = "outbound") -> str:
        """Find the lowest-energy (least resistance) hop from a node.

        Args:
            node_query: Substring to match against node names/context.
            direction: "outbound" (default), "inbound", or "both".
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        try:
            target_name = _resolve(cache, node_query)
        except _AmbiguousLabel as exc:
            return json.dumps({"error": str(exc)})
        if target_name is None:
            return json.dumps({"error": f"Node not found: {node_query}"})

        hops = []
        if direction in ("outbound", "both"):
            for e in cache.get_outbound_edges(target_name):
                neighbor = _node_summary(cache, e["target"])
                hops.append({
                    "neighbor": _shorten_id(e["target"]),
                    "neighbor_id": e["target"],
                    "neighbor_type": neighbor["type"] if neighbor else "unknown",
                    "edge_type": e["type"],
                    "transition_energy": round(e["transition_energy"], 4) if e["transition_energy"] is not None else None,
                    "direction": "outbound",
                    "neighbor_entry": round(neighbor["entry_energy"], 3) if neighbor and neighbor["entry_energy"] is not None else None,
                    "neighbor_context": _ctx_snippet(cache, e["target"], 80),
                })
        if direction in ("inbound", "both"):
            for e in cache.get_inbound_edges(target_name):
                neighbor = _node_summary(cache, e["source"])
                hops.append({
                    "neighbor": _shorten_id(e["source"]),
                    "neighbor_id": e["source"],
                    "neighbor_type": neighbor["type"] if neighbor else "unknown",
                    "edge_type": e["type"],
                    "transition_energy": round(e["transition_energy"], 4) if e["transition_energy"] is not None else None,
                    "direction": "inbound",
                    "neighbor_entry": round(neighbor["entry_energy"], 3) if neighbor and neighbor["entry_energy"] is not None else None,
                    "neighbor_context": _ctx_snippet(cache, e["source"], 80),
                })

        hops.sort(key=lambda h: h["transition_energy"] if h["transition_energy"] is not None else 999)
        target_node = _node_summary(cache, target_name)
        return json.dumps({
            "center": _shorten_id(target_name),
            "center_type": target_node["type"] if target_node else "unknown",
            "center_entry": round(target_node["entry_energy"], 3) if target_node and target_node["entry_energy"] is not None else None,
            "total_hops": len(hops),
            "lowest_energy_hop": hops[0] if hops else None,
            "all_hops": hops,
        })

    # ------------------------------------------------------------------
    # Exploration (4 tools)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def energy_lowest_paths(node_query: str, max_hops: int = 6, top_k: int = 5) -> str:
        """Beam search for lowest-energy paths from a node at each depth.

        Args:
            node_query: Substring to match against node names/context.
            max_hops: Maximum path length to explore (default 6).
            top_k: Paths to keep per depth (default 5).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        try:
            target_name = _resolve(cache, node_query)
        except _AmbiguousLabel as exc:
            return json.dumps({"error": str(exc)})
        if target_name is None:
            return json.dumps({"error": f"Node not found: {node_query}"})

        target_node = _node_summary(cache, target_name)
        entry_e = target_node["entry_energy"]
        if entry_e is None:
            return json.dumps({"error": f"Node {target_name} has no entry energy."})
        init_mom = 99.0 / (1.0 + math.exp(min(entry_e, 700.0)))

        current_paths = [([target_name], 0.0, init_mom)]
        results_by_depth = {}

        for depth in range(1, max_hops + 1):
            next_paths = []
            for nodes, total_e, mom in current_paths:
                cur = nodes[-1]
                visited = set(nodes)
                for e in cache.get_outbound_edges(cur):
                    dst = e["target"]
                    if dst in visited:
                        continue
                    te = e["transition_energy"]
                    if te is None:
                        continue
                    new_total = total_e + te
                    new_mom = mom
                    if te < 0:
                        new_mom += (99.0 - new_mom) * 0.25 * min(abs(te), 4.0) / 4.0
                    else:
                        new_mom -= new_mom * 0.40 * min(te, 5.0) / 5.0
                    new_mom = max(0.0, min(100.0, new_mom))
                    next_paths.append((nodes + [dst], new_total, new_mom))

            if not next_paths:
                break
            next_paths.sort(key=lambda p: p[1])
            best = next_paths[:top_k]

            depth_results = []
            for nodes, total_e, mom in best:
                steps = []
                for i, n in enumerate(nodes):
                    ns = _node_summary(cache, n)
                    step = {
                        "node": _shorten_id(n),
                        "type": ns["type"] if ns else "unknown",
                        "entry_energy": round(ns["entry_energy"], 3) if ns and ns["entry_energy"] is not None else None,
                    }
                    if i > 0:
                        prev = nodes[i - 1]
                        er = cache.db.execute(
                            "SELECT type, transition_energy FROM edges WHERE source = ? AND target = ? LIMIT 1",
                            (prev, n),
                        ).fetchone()
                        if er:
                            step["edge_type"] = er[0]
                            step["transition_energy"] = round(er[1], 3) if er[1] is not None else None
                    steps.append(step)
                depth_results.append({
                    "total_energy": round(total_e, 3),
                    "momentum": round(mom, 1),
                    "destination": _shorten_id(nodes[-1]),
                    "destination_type": _node_summary(cache, nodes[-1])["type"] if _node_summary(cache, nodes[-1]) else "unknown",
                    "destination_context": _ctx_snippet(cache, nodes[-1], 80),
                    "steps": steps,
                })
            results_by_depth[depth] = depth_results
            current_paths = next_paths[:top_k * 3]

        return json.dumps({
            "start": _shorten_id(target_name),
            "start_type": target_node["type"],
            "start_entry": round(entry_e, 3),
            "start_momentum": round(init_mom, 1),
            "max_hops": max_hops,
            "paths_per_depth": {str(d): len(r) for d, r in results_by_depth.items()},
            "by_depth": results_by_depth,
        })

    @mcp.tool()
    async def energy_trace_to_target(source_query: str, target_query: str, max_hops: int = 8) -> str:
        """Find a low-energy path between two nodes using Dijkstra.

        Note: with accelerating (negative-energy) edges, the result may not be
        globally optimal — use energy_lowest_paths for exhaustive exploration.

        Args:
            source_query: Substring to match source node.
            target_query: Substring to match target node.
            max_hops: Maximum hops (default 8).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        try:
            src_name = _resolve(cache, source_query)
            tgt_name = _resolve(cache, target_query)
        except _AmbiguousLabel as exc:
            return json.dumps({"error": str(exc)})
        if src_name is None:
            return json.dumps({"error": f"Source not found: {source_query}"})
        if tgt_name is None:
            return json.dumps({"error": f"Target not found: {target_query}"})

        # State space keyed by (node, hops_used) to bound search with
        # negative-weight edges.  The layered structure (hops only increase)
        # guarantees no cycles in the state graph, so the search terminates
        # even with accelerating edges.
        _TIMEOUT = 30.0
        _MAX_HEAP = 100_000
        t0 = time.monotonic()

        # heap entries: (cost, hops, node)
        best: dict[tuple[str, int], float] = {(src_name, 0): 0.0}
        prev: dict[tuple[str, int], tuple[str, int]] = {}
        prev_edge_map: dict[tuple[str, int], tuple[str, float]] = {}
        heap = [(0.0, 0, src_name)]
        bounded = False

        while heap:
            if time.monotonic() - t0 > _TIMEOUT:
                bounded = True
                break
            if len(heap) > _MAX_HEAP:
                bounded = True
                break

            cost, hops, cur = heapq.heappop(heap)

            state = (cur, hops)
            if cost > best.get(state, float("inf")):
                continue  # stale entry

            # Don't expand the target — but keep searching for cheaper
            # arrivals at different hop counts.
            if cur == tgt_name:
                continue

            if hops >= max_hops:
                continue

            for e in cache.get_outbound_edges(cur):
                dst = e["target"]
                te = e["transition_energy"]
                if te is None:
                    continue
                new_cost = cost + te
                new_hops = hops + 1
                new_state = (dst, new_hops)
                if new_cost < best.get(new_state, float("inf")):
                    best[new_state] = new_cost
                    prev[new_state] = state
                    prev_edge_map[new_state] = (e["type"], te)
                    heapq.heappush(heap, (new_cost, new_hops, dst))

        # Find the cheapest state where we reached the target.
        target_states = [
            (best[s], s) for s in best if s[0] == tgt_name
        ]

        if not target_states:
            result = {
                "source": _shorten_id(src_name),
                "target": _shorten_id(tgt_name),
                "reachable": False,
                "reason": f"No path within {max_hops} hops",
            }
            if bounded:
                result["note"] = (
                    "Search was bounded (30 s timeout or 100 k heap cap). "
                    "A path may exist but was not found within budget."
                )
            return json.dumps(result)

        _, best_state = min(target_states)

        # Reconstruct path by walking the predecessor chain.
        path_nodes: list[str] = []
        path_edges: list[tuple[str, float]] = []
        st = best_state
        while st in prev:
            path_nodes.append(st[0])
            path_edges.append(prev_edge_map[st])
            st = prev[st]
        path_nodes.append(src_name)
        path_nodes.reverse()
        path_edges.reverse()

        first_node = _node_summary(cache, path_nodes[0])
        entry_e = first_node["entry_energy"] if first_node and first_node["entry_energy"] is not None else None
        if entry_e is None:
            return json.dumps({"error": f"Node {path_nodes[0]} has no entry energy."})
        mom = 99.0 / (1.0 + math.exp(min(entry_e, 700.0)))
        steps = [{
            "node": _shorten_id(path_nodes[0]),
            "node_id": path_nodes[0],
            "type": first_node["type"],
            "entry_energy": round(entry_e, 3),
            "momentum": round(mom, 1),
        }]

        for j in range(1, len(path_nodes)):
            et, te = path_edges[j - 1]
            if te < 0:
                mom += (99.0 - mom) * 0.25 * min(abs(te), 4.0) / 4.0
            else:
                mom -= mom * 0.40 * min(te, 5.0) / 5.0
            mom = max(0.0, min(100.0, mom))

            step_node = _node_summary(cache, path_nodes[j])
            steps.append({
                "node": _shorten_id(path_nodes[j]),
                "node_id": path_nodes[j],
                "type": step_node["type"] if step_node else "unknown",
                "entry_energy": round(step_node["entry_energy"], 3) if step_node and step_node["entry_energy"] is not None else None,
                "edge_type": et,
                "transition_energy": round(te, 3),
                "accelerating": te < 0,
                "momentum": round(mom, 1),
            })

        result = {
            "source": _shorten_id(src_name),
            "target": _shorten_id(tgt_name),
            "reachable": True,
            "hops": len(path_nodes) - 1,
            "total_energy": round(best[best_state], 3),
            "final_momentum": round(mom, 1),
            "steps": steps,
        }
        if bounded:
            result["note"] = (
                "Search was bounded (30 s timeout or 100 k heap cap). "
                "The path shown is the best found within budget "
                "but may not be globally optimal."
            )
        return json.dumps(result)

    @mcp.tool()
    async def energy_compare_paths(path_a: str, path_b: str) -> str:
        """Side-by-side momentum comparison of two paths.

        Args:
            path_a: Comma-separated or JSON array of node names for path A.
            path_b: Comma-separated or JSON array of node names for path B.
        """
        gate = _gate()
        if gate:
            return gate
        result_a = json.loads(await energy_momentum_path(path_a))
        result_b = json.loads(await energy_momentum_path(path_b))
        if "error" in result_a:
            return json.dumps({"error": f"Path A: {result_a['error']}"})
        if "error" in result_b:
            return json.dumps({"error": f"Path B: {result_b['error']}"})
        return json.dumps({
            "path_a": {"final_momentum": result_a["final_momentum"], "hops": result_a["path_length"] - 1, "steps": result_a["steps"]},
            "path_b": {"final_momentum": result_b["final_momentum"], "hops": result_b["path_length"] - 1, "steps": result_b["steps"]},
            "comparison": {
                "momentum_diff": round(result_a["final_momentum"] - result_b["final_momentum"], 1),
                "more_defended": "path_b" if result_a["final_momentum"] > result_b["final_momentum"] else "path_a",
            },
        })

    @mcp.tool()
    async def energy_node_neighborhood(node_query: str, hops: int = 2) -> str:
        """Explore the energy landscape around a node via BFS.

        Args:
            node_query: Substring to match against node names/context.
            hops: Radius in hops (default 2).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        try:
            target_name = _resolve(cache, node_query)
        except _AmbiguousLabel as exc:
            return json.dumps({"error": str(exc)})
        if target_name is None:
            return json.dumps({"error": f"Node not found: {node_query}"})

        visited = {target_name: 0}
        queue = [(target_name, 0)]
        neighborhood_edges = []

        while queue:
            cur, depth = queue.pop(0)
            if depth >= hops:
                continue
            for e in cache.get_connected_edges(cur):
                te = e.get("transition_energy")
                neighborhood_edges.append({
                    "from": _shorten_id(e["source"]),
                    "to": _shorten_id(e["target"]),
                    "edge_type": e["type"],
                    "transition_energy": round(te, 3) if te is not None else None,
                    "direction": e.get("direction", "outbound"),
                })
                neighbor = e["target"] if e.get("direction") == "outbound" else e["source"]
                if neighbor not in visited:
                    visited[neighbor] = depth + 1
                    queue.append((neighbor, depth + 1))

        neighborhood_nodes = []
        for nname, d in sorted(visited.items(), key=lambda x: x[1]):
            ns = _node_summary(cache, nname)
            neighborhood_nodes.append({
                "label": _shorten_id(nname),
                "node_id": nname,
                "type": ns["type"] if ns else "unknown",
                "entry_energy": round(ns["entry_energy"], 3) if ns and ns["entry_energy"] is not None else None,
                "depth": d,
                "is_center": nname == target_name,
                "context": _ctx_snippet(cache, nname, 80),
            })

        accel = [e for e in neighborhood_edges if (e.get("transition_energy") or 0) < 0]
        brake = [e for e in neighborhood_edges if (e.get("transition_energy") or 0) >= 0]
        target_node = _node_summary(cache, target_name)

        return json.dumps({
            "center": _shorten_id(target_name),
            "center_type": target_node["type"] if target_node else "unknown",
            "center_entry": round(target_node["entry_energy"], 3) if target_node and target_node["entry_energy"] is not None else None,
            "hops": hops,
            "nodes": len(neighborhood_nodes),
            "edges": len(neighborhood_edges),
            "accel_edges": len(accel),
            "brake_edges": len(brake),
            "neighborhood_nodes": neighborhood_nodes,
            "neighborhood_edges": sorted(
                neighborhood_edges,
                key=lambda e: e["transition_energy"] if e["transition_energy"] is not None else 999,
            ),
        })

    # ------------------------------------------------------------------
    # Structural (4 tools)
    # ------------------------------------------------------------------

    @mcp.tool()
    async def energy_entry_points(threshold: float = 2.0, limit: int = 30) -> str:
        """List nodes with entry energy below threshold, sorted by exposure.

        Args:
            threshold: Entry energy threshold (default 2.0).
            limit: Maximum results (default 30).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        nodes = cache.entry_points(threshold, limit)
        results = []
        for node in nodes:
            name = node["name"]
            accel_out = cache.db.execute(
                "SELECT COUNT(*) FROM edges WHERE source = ? AND transition_energy < 0",
                (name,),
            ).fetchone()[0]
            ctx = node.get("semantic_context", [])
            ctx_str = ctx[0][:150] if isinstance(ctx, list) and ctx else ""
            results.append({
                "node_id": name,
                "label": _shorten_id(name),
                "type": node["type"],
                "entry_energy": round(node["entry_energy"], 4) if node["entry_energy"] is not None else None,
                "context": ctx_str,
                "accel_outbound": accel_out,
            })
        return json.dumps({"threshold": threshold, "count": len(results), "entry_points": results})

    @mcp.tool()
    async def energy_defenses(limit: int = 30) -> str:
        """Find nodes that act as defenses — where outbound edges have braking (positive) energy.

        Returns nodes with the most braking outbound edges, ranked by total braking energy.
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()
        rows = cache.db.execute("""
            SELECT source,
                   SUM(CASE WHEN transition_energy > 0 THEN transition_energy ELSE 0 END) as total_brake,
                   SUM(CASE WHEN transition_energy > 0 THEN 1 ELSE 0 END) as brake_count,
                   SUM(CASE WHEN transition_energy < 0 THEN 1 ELSE 0 END) as accel_count
            FROM edges
            WHERE transition_energy IS NOT NULL
            GROUP BY source
            HAVING brake_count > accel_count
            ORDER BY total_brake DESC
            LIMIT ?
        """, (limit,)).fetchall()

        results = []
        for r in rows:
            ns = _node_summary(cache, r[0])
            results.append({
                "label": _shorten_id(r[0]),
                "node_id": r[0],
                "type": ns["type"] if ns else "unknown",
                "total_braking_energy": round(r[1], 2),
                "brake_edges": r[2],
                "accel_edges": r[3],
                "entry_energy": round(ns["entry_energy"], 3) if ns and ns["entry_energy"] is not None else None,
                "context": _ctx_snippet(cache, r[0], 80),
            })
        return json.dumps({"count": len(results), "defenses": results})

    @mcp.tool()
    async def energy_top_attack_paths(limit: int = 15) -> str:
        """Get the most dangerous attack paths ranked by final momentum score.

        Args:
            limit: Number of paths to return (default 15).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()

        # Start from entry points AND all sources of accelerating edges
        entry_points = set()
        for r in cache.db.execute(
            "SELECT name FROM nodes WHERE entry_energy IS NOT NULL AND entry_energy < 2.0"
        ).fetchall():
            entry_points.add(r[0])
        accel_sources = set()
        for r in cache.db.execute(
            "SELECT DISTINCT source FROM edges WHERE transition_energy IS NOT NULL AND transition_energy < 0"
        ).fetchall():
            accel_sources.add(r[0])
        # Sort for deterministic iteration — set order varies across Python
        # processes (hash seed randomization). Since global_cap truncates the
        # search, different iteration orders produce different top-N results.
        start_nodes = sorted(entry_points | accel_sources)

        max_paths = 500
        max_depth = 8          # paths > 8 hops rarely add signal
        max_stack = 10_000     # bound memory within one start node's DFS
        global_cap = max_paths * 50
        all_paths = []
        node_participation = Counter()
        for start_name in start_nodes:
            if len(all_paths) >= global_cap:
                break
            sn = _node_summary(cache, start_name)
            if sn is None or sn["entry_energy"] is None:
                continue
            start_ee = sn["entry_energy"]
            init_mom = 99.0 / (1.0 + math.exp(min(start_ee, 700.0)))
            stack = [(start_name, [start_name], [round(init_mom, 1)], {start_name})]
            while stack:
                if len(all_paths) >= global_cap:
                    break
                cur, p_nodes, p_mom, visited = stack.pop()
                next_hops = sorted(
                    [
                        (e["target"], e["transition_energy"])
                        for e in cache.get_outbound_edges(cur)
                        if e["transition_energy"] is not None and e["transition_energy"] < 0 and e["target"] not in visited
                    ],
                    key=lambda x: (x[1], x[0]),  # energy then name for determinism
                )
                if not next_hops or len(p_nodes) >= max_depth:
                    if len(p_nodes) >= 2:
                        all_paths.append({"nodes": list(p_nodes), "momentum": list(p_mom)})
                        for n in p_nodes:
                            node_participation[n] += 1
                    continue
                for dst, te in next_hops:
                    if len(stack) >= max_stack:
                        break
                    mom = p_mom[-1]
                    mom += (99.0 - mom) * 0.25 * min(abs(te), 4.0) / 4.0
                    stack.append((dst, p_nodes + [dst], p_mom + [round(mom, 1)], visited | {dst}))
                # Record prefix path
                if len(p_nodes) >= 2:
                    all_paths.append({"nodes": list(p_nodes), "momentum": list(p_mom)})
                    for n in p_nodes:
                        node_participation[n] += 1

        all_paths.sort(key=lambda p: -p["momentum"][-1])
        top = all_paths[:limit]
        finals = [p["momentum"][-1] for p in all_paths] if all_paths else [0.0]
        paths = []
        for p in top:
            node_types = []
            for n in p["nodes"]:
                ns = _node_summary(cache, n)
                node_types.append(ns["type"] if ns else "unknown")
            paths.append({
                "final_momentum": p["momentum"][-1],
                "hops": len(p["nodes"]) - 1,
                "nodes": [_shorten_id(n) for n in p["nodes"]],
                "node_ids": p["nodes"],
                "types": node_types,
                "momentum_trace": p["momentum"],
            })
        return json.dumps({
            "total_enumerated": len(all_paths),
            "showing": len(paths),
            "max_momentum": round(max(finals), 1),
            "paths": paths,
            "interpretation": "Momentum 0-20: well defended. 20-40: moderate. 40-60: low resistance. 60-80: concerning. 80+: critical.",
        })

    @mcp.tool()
    async def energy_chokepoints(limit: int = 15) -> str:
        """Find structural chokepoints — nodes that the most attack paths flow through.

        Args:
            limit: Number of chokepoints to return (default 15).
        """
        gate = _gate()
        if gate:
            return gate
        cache = get_cache()

        # Start from entry points AND all sources of accelerating edges
        entry_points = set()
        for r in cache.db.execute(
            "SELECT name FROM nodes WHERE entry_energy IS NOT NULL AND entry_energy < 2.0"
        ).fetchall():
            entry_points.add(r[0])
        accel_sources = set()
        for r in cache.db.execute(
            "SELECT DISTINCT source FROM edges WHERE transition_energy IS NOT NULL AND transition_energy < 0"
        ).fetchall():
            accel_sources.add(r[0])
        start_nodes = sorted(entry_points | accel_sources)

        participation = Counter()
        total_paths = 0
        max_depth = 8          # bound path length
        max_stack = 10_000     # bound memory within one start node's DFS
        global_cap = 25_000
        for start_name in start_nodes:
            if total_paths >= global_cap:
                break
            sn = _node_summary(cache, start_name)
            if sn is None or sn["entry_energy"] is None:
                continue
            stack = [(start_name, [start_name], {start_name})]
            while stack:
                if total_paths >= global_cap:
                    break
                cur, p_nodes, visited = stack.pop()
                next_hops = sorted(
                    [
                        (e["target"], e["transition_energy"])
                        for e in cache.get_outbound_edges(cur)
                        if e["transition_energy"] is not None and e["transition_energy"] < 0 and e["target"] not in visited
                    ],
                    key=lambda x: (x[1], x[0]),  # energy then name for determinism
                )
                if not next_hops or len(p_nodes) >= max_depth:
                    if len(p_nodes) >= 2:
                        total_paths += 1
                        for n in p_nodes:
                            participation[n] += 1
                    continue
                for dst, te in next_hops:
                    if len(stack) >= max_stack:
                        break
                    stack.append((dst, p_nodes + [dst], visited | {dst}))
                # Count prefix paths too (matches old behavior)
                if len(p_nodes) >= 2:
                    total_paths += 1
                    for n in p_nodes:
                        participation[n] += 1

        results = []
        for nname, count in participation.most_common(limit):
            ns = _node_summary(cache, nname)
            pct = round(count / max(1, total_paths) * 100, 1)
            results.append({
                "label": _shorten_id(nname),
                "node_id": nname,
                "type": ns["type"] if ns else "unknown",
                "path_count": count,
                "pct_of_paths": pct,
                "entry_energy": round(ns["entry_energy"], 3) if ns and ns["entry_energy"] is not None else None,
                "context": _ctx_snippet(cache, nname, 80),
                "interpretation": f"{'Critical chokepoint' if pct > 20 else 'Significant' if pct > 10 else 'Moderate'} — {pct}% of attack paths",
            })

        return json.dumps({
            "total_paths": total_paths,
            "chokepoints": results,
        })
