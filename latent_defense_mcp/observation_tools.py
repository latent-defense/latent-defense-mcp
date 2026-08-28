"""Graph observation tools — add, edit, delete nodes and edges in the local cache.

These tools modify the local SQLite graph cache directly.  Changes are
visible immediately to all graph and energy tools.  ``commit_graph``
persists them to infradb via the delta commit API.

The delta accumulator tracks every change so it can be replayed as a single
infradb commit.  The delta is also persisted to disk after every mutation
so it survives MCP server restarts.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine

from .energy_cache import EnergyGraphCache, _deep_merge, _remove_keys

log = logging.getLogger("latent-defense-mcp")


# ---------------------------------------------------------------------------
# Delta accumulator — tracks pending changes for future commit
# ---------------------------------------------------------------------------

@dataclass
class _ChangeRecord:
    """One logged observation."""
    action: str       # add_node, edit_node, delete_node, add_edge, edit_edge, delete_edge, edit_subgraph
    target: str       # node or edge name (or "subgraph" for edit_subgraph)
    reason: str
    timestamp: float
    details: dict = field(default_factory=dict)


class ObservationDelta:
    """Accumulates graph changes as a delta dict compatible with infradb's
    commit format.  Memory cost is O(changes), not O(graph).
    """

    def __init__(self) -> None:
        self.nodes_added: dict[str, dict] = {}
        self.nodes_modified: dict[str, dict] = {}
        self.nodes_removed: list[str] = []
        self.edges_added: dict[str, dict] = {}
        self.edges_modified: dict[str, dict] = {}
        self.edges_removed: list[str] = []
        self.changelog: list[_ChangeRecord] = []
        self._promote_nodes: set[str] = set()  # nodes needing remove+re-add
        self._promote_edges: set[str] = set()  # edges needing remove+re-add

    @property
    def is_empty(self) -> bool:
        return (
            not self.nodes_added
            and not self.nodes_modified
            and not self.nodes_removed
            and not self.edges_added
            and not self.edges_modified
            and not self.edges_removed
        )

    @property
    def change_count(self) -> int:
        return (
            len(self.nodes_added)
            + len(self.nodes_modified)
            + len(self.nodes_removed)
            + len(self.edges_added)
            + len(self.edges_modified)
            + len(self.edges_removed)
        )

    def record(self, action: str, target: str, reason: str, **details: Any) -> None:
        self.changelog.append(_ChangeRecord(
            action=action,
            target=target,
            reason=reason,
            timestamp=time.time(),
            details=details,
        ))

    def add_node(self, name: str, data: dict) -> None:
        # If previously removed, un-remove and treat as modification
        if name in self.nodes_removed:
            self.nodes_removed.remove(name)
        self.nodes_added[name] = data

    def modify_node(self, name: str, patches: dict) -> None:
        # If we already added this node, merge into the add
        if name in self.nodes_added:
            if "metadata" in patches:
                existing_meta = self.nodes_added[name].get("metadata", {})
                self.nodes_added[name]["metadata"] = _deep_merge(existing_meta, patches["metadata"])
            if "semantic_context" in patches:
                self.nodes_added[name]["semantic_context"] = patches["semantic_context"]
            if "type" in patches:
                self.nodes_added[name]["type"] = patches["type"]
        else:
            existing = self.nodes_modified.get(name, {})
            if "metadata" in patches:
                existing_meta = existing.get("metadata", {})
                existing["metadata"] = _deep_merge(existing_meta, patches["metadata"])
            if "semantic_context" in patches:
                existing["semantic_context"] = patches["semantic_context"]
            if "type" in patches:
                existing["type"] = patches["type"]
            self.nodes_modified[name] = existing

    def replace_node_metadata(self, name: str, full_metadata: dict) -> None:
        """Set the delta's metadata for a node to an exact full replacement.

        Used after remove_keys — the cache has the correct post-removal state,
        and the delta must send that full state so infradb's dict.update()
        produces the right result.
        """
        if name in self.nodes_added:
            self.nodes_added[name]["metadata"] = full_metadata
        else:
            existing = self.nodes_modified.get(name, {})
            existing["metadata"] = full_metadata
            self.nodes_modified[name] = existing

    def remove_node(self, name: str) -> None:
        # Clean up any prior add/modify for this node
        self.nodes_added.pop(name, None)
        self.nodes_modified.pop(name, None)
        if name not in self.nodes_removed:
            self.nodes_removed.append(name)

    def add_edge(self, name: str, data: dict) -> None:
        if name in self.edges_removed:
            self.edges_removed.remove(name)
        self.edges_added[name] = data

    def modify_edge(self, name: str, patches: dict) -> None:
        if name in self.edges_added:
            if "metadata" in patches:
                existing_meta = self.edges_added[name].get("metadata", {})
                self.edges_added[name]["metadata"] = _deep_merge(existing_meta, patches["metadata"])
            if "semantic_context" in patches:
                self.edges_added[name]["semantic_context"] = patches["semantic_context"]
            if "source" in patches:
                self.edges_added[name]["source"] = patches["source"]
            if "target" in patches:
                self.edges_added[name]["target"] = patches["target"]
        else:
            existing = self.edges_modified.get(name, {})
            if "metadata" in patches:
                existing_meta = existing.get("metadata", {})
                existing["metadata"] = _deep_merge(existing_meta, patches["metadata"])
            if "semantic_context" in patches:
                existing["semantic_context"] = patches["semantic_context"]
            if "source" in patches:
                existing["source"] = patches["source"]
            if "target" in patches:
                existing["target"] = patches["target"]
            self.edges_modified[name] = existing

    def replace_edge_metadata(self, name: str, full_metadata: dict) -> None:
        """Set the delta's metadata for an edge to an exact full replacement.

        Used after remove_keys — same rationale as replace_node_metadata.
        """
        if name in self.edges_added:
            self.edges_added[name]["metadata"] = full_metadata
        else:
            existing = self.edges_modified.get(name, {})
            existing["metadata"] = full_metadata
            self.edges_modified[name] = existing

    def mark_needs_promote(self, name: str, kind: str) -> None:
        """Mark a node or edge for promotion to remove+re-add in to_delta_dict.

        Used when remove_keys deletes metadata keys — infradb's merge
        can't remove keys, so the entire entity must be removed and
        re-added with the correct final state.
        """
        if kind == "node":
            self._promote_nodes.add(name)
        elif kind == "edge":
            self._promote_edges.add(name)

    def remove_edge(self, name: str) -> None:
        self.edges_added.pop(name, None)
        self.edges_modified.pop(name, None)
        if name not in self.edges_removed:
            self.edges_removed.append(name)

    def clear(self) -> None:
        self.nodes_added.clear()
        self.nodes_modified.clear()
        self.nodes_removed.clear()
        self.edges_added.clear()
        self.edges_modified.clear()
        self.edges_removed.clear()
        self.changelog.clear()
        self._promote_nodes.clear()
        self._promote_edges.clear()

    def to_delta_dict(self, cache: Any = None) -> dict:
        """Export as an infradb-compatible delta dict.

        When *cache* is provided, node type changes and edge source/target
        changes are converted from ``nodes_modified`` / ``edges_modified``
        into remove + re-add pairs, because infradb's ``materialize()``
        only processes ``metadata`` and ``semantic_context`` in the
        ``*_modified`` dicts — it ignores ``type``, ``source``, and
        ``target``.
        """
        # Start with copies so we don't mutate the live delta
        nodes_added = dict(self.nodes_added)
        nodes_modified = dict(self.nodes_modified)
        nodes_removed = list(self.nodes_removed)
        edges_added = dict(self.edges_added)
        edges_modified = dict(self.edges_modified)
        edges_removed = list(self.edges_removed)

        # Promote node modifications with type changes to remove + re-add
        if cache:
            promote_nodes = [
                name for name, mods in nodes_modified.items()
                if "type" in mods or name in self._promote_nodes
            ]
            for name in promote_nodes:
                mods = nodes_modified.pop(name)
                node = cache.query_node(name)
                if node:
                    # Build the full node for re-add from current cache state
                    nodes_added[name] = {
                        "type": node["type"],  # already updated in cache
                        "metadata": node.get("metadata", {}),
                        "semantic_context": node.get("semantic_context", []),
                    }
                    if name not in nodes_removed:
                        nodes_removed.append(name)
                    # Re-add all connected edges so they survive the
                    # remove+re-add cycle (infradb cascades edge removal
                    # when a node is removed).
                    for edge in cache.get_connected_edges(name):
                        ename = edge["name"]
                        if ename not in edges_added and ename not in edges_removed:
                            edges_added[ename] = {
                                "type": edge["type"],
                                "source": edge["source"],
                                "target": edge["target"],
                                "metadata": edge.get("metadata", {}),
                                "semantic_context": edge.get("semantic_context", []),
                            }

            # Promote edge modifications with source/target changes to remove + re-add
            promote_edges = [
                name for name, mods in edges_modified.items()
                if "source" in mods or "target" in mods or name in self._promote_edges
            ]
            for name in promote_edges:
                mods = edges_modified.pop(name)
                row = cache.db.execute(
                    "SELECT name, type, source, target, semantic_context, metadata "
                    "FROM edges WHERE name = ?", (name,)
                ).fetchone()
                if row:
                    import json as _json
                    edges_added[name] = {
                        "type": row[1],
                        "source": row[2],  # already updated in cache
                        "target": row[3],
                        "metadata": _json.loads(row[5]) if row[5] else {},
                        "semantic_context": _json.loads(row[4]) if row[4] else [],
                    }
                    if name not in edges_removed:
                        edges_removed.append(name)

        d: dict[str, Any] = {}
        if nodes_added:
            d["nodes_added"] = nodes_added
        if nodes_modified:
            d["nodes_modified"] = nodes_modified
        if nodes_removed:
            d["nodes_removed"] = nodes_removed
        if edges_added:
            d["edges_added"] = edges_added
        if edges_modified:
            d["edges_modified"] = edges_modified
        if edges_removed:
            d["edges_removed"] = edges_removed
        return d

    def summary(self) -> dict:
        return {
            "nodes_added": len(self.nodes_added),
            "nodes_modified": len(self.nodes_modified),
            "nodes_removed": len(self.nodes_removed),
            "edges_added": len(self.edges_added),
            "edges_modified": len(self.edges_modified),
            "edges_removed": len(self.edges_removed),
            "total_changes": self.change_count,
        }


# ---------------------------------------------------------------------------
# Shared state — one per MCP server process
# ---------------------------------------------------------------------------

_delta = ObservationDelta()

# Track which nodes and edges have been read in this session.
# edit/delete tools require a prior read — same pattern as the Edit tool
# requiring a prior Read of the file.
_read_nodes: set[str] = set()
_read_edges: set[str] = set()


def get_delta() -> ObservationDelta:
    return _delta


def mark_node_read(name: str) -> None:
    """Called by read_node (in graph_tools) to record that a node was read."""
    _read_nodes.add(name)


def mark_edge_read(name: str) -> None:
    """Called by read_edge (in graph_tools) to record that an edge was read."""
    _read_edges.add(name)




# ---------------------------------------------------------------------------
# Delta persistence — survive MCP server restarts
# ---------------------------------------------------------------------------

_CACHE_DIR = Path(os.environ.get(
    "GRAPH_CACHE_DIR",
    Path.home() / ".latent-defense" / "graph-cache",
))


def _delta_path(branch_id: str) -> Path:
    """Path to the persisted delta file for a branch."""
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^a-zA-Z0-9._-]", "", branch_id)
    return _CACHE_DIR / f"{safe_id}.delta.json"


def save_delta_to_disk(branch_id: str) -> None:
    """Persist the current delta to disk so it survives restarts."""
    delta = get_delta()
    if delta.is_empty:
        # Remove stale file if delta was cleared
        path = _delta_path(branch_id)
        if path.exists():
            path.unlink()
        return
    path = _delta_path(branch_id)
    data = {
        "delta": delta.to_delta_dict(),
        "changelog": [
            {
                "action": r.action,
                "target": r.target,
                "reason": r.reason,
                "timestamp": r.timestamp,
                **r.details,
            }
            for r in delta.changelog
        ],
        "saved_at": time.time(),
        "branch_id": branch_id,
    }
    path.write_text(json.dumps(data, indent=2))
    log.debug("Delta persisted: %d changes to %s", delta.change_count, path)


def load_delta_from_disk(branch_id: str) -> int:
    """Restore a persisted delta from disk.  Returns the number of changes loaded."""
    path = _delta_path(branch_id)
    if not path.exists():
        return 0
    try:
        data = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Failed to load persisted delta from %s: %s", path, exc)
        return 0

    d = data.get("delta", {})
    delta = get_delta()

    # Only load if the delta is currently empty (avoid double-loading)
    if not delta.is_empty:
        log.debug("Delta already has %d changes, skipping disk load", delta.change_count)
        return 0

    delta.nodes_added = d.get("nodes_added", {})
    delta.nodes_modified = d.get("nodes_modified", {})
    delta.nodes_removed = d.get("nodes_removed", [])
    delta.edges_added = d.get("edges_added", {})
    delta.edges_modified = d.get("edges_modified", {})
    delta.edges_removed = d.get("edges_removed", [])

    # Restore changelog
    for entry in data.get("changelog", []):
        delta.changelog.append(_ChangeRecord(
            action=entry.get("action", ""),
            target=entry.get("target", ""),
            reason=entry.get("reason", ""),
            timestamp=entry.get("timestamp", 0),
            details={k: v for k, v in entry.items()
                     if k not in ("action", "target", "reason", "timestamp")},
        ))

    count = delta.change_count
    log.warning(
        "Loaded %d pending graph changes from previous session (%s). "
        "Call pending_changes() to review or commit_graph() to persist.",
        count, path,
    )
    return count


def clear_delta_file(branch_id: str) -> None:
    """Remove the persisted delta file."""
    path = _delta_path(branch_id)
    if path.exists():
        path.unlink()
        log.debug("Cleared persisted delta: %s", path)

# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register(
    mcp: Any,
    get_cache: Callable[[], EnergyGraphCache | None],
    post_fn: Callable[..., Coroutine] | None = None,
) -> None:
    """Register graph observation tools on *mcp*.

    Args:
        mcp: The MCP server instance.
        get_cache: Accessor for the loaded energy graph cache.
        post_fn: The _post helper from server.py for remote API calls.
                 Required for commit_graph; other tools work without it.
    """

    def _gate_write() -> str | None:
        """Ensure graph is loaded and writable."""
        c = get_cache()
        if c is None or not c.loaded:
            return json.dumps({
                "error": "No graph loaded. Call load_graph_energies(branch_id) first.",
            })
        if not c.writable:
            c.enable_writes()
        return None

    def _require_read_node(name: str, resolved: str | None = None) -> str | None:
        """Return an error JSON string if the node hasn't been read yet."""
        check = resolved or name
        if check not in _read_nodes:
            return json.dumps({
                "error": (
                    f"You must read_node('{name}') before editing or deleting it. "
                    "Read the node first to understand its current state."
                ),
            })
        return None

    def _require_read_edge(name: str) -> str | None:
        """Return an error JSON string if the edge hasn't been read yet."""
        if name not in _read_edges:
            return json.dumps({
                "error": (
                    f"You must read_edge('{name}') before editing or deleting it. "
                    "Read the edge first to understand its current state."
                ),
            })
        return None

    def _auto_save() -> None:
        """Persist delta to disk after every mutation."""
        c = get_cache()
        if c and c.branch_id:
            save_delta_to_disk(c.branch_id)

    # ------------------------------------------------------------------
    # Primitives
    # ------------------------------------------------------------------

    @mcp.tool()
    async def add_node(
        name: str,
        type: str,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        reason: str = "",
    ) -> str:
        """Add a new node to the graph.

        Use when you discover infrastructure that isn't in the graph — a service,
        credential, network resource, or any other entity the mapper missed.

        Args:
            name: Unique node identifier (use the naming convention from existing nodes).
            type: Node type (e.g. "service", "credential", "network_policy", "s3_bucket").
            metadata: Key-value pairs describing the node (version, config, etc.).
            semantic_context: Description lines explaining what this node is.
            reason: Why you're adding this node (provenance for review).
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        # Check if node already exists
        existing = cache.query_node(name)
        if existing:
            return json.dumps({
                "error": f"Node '{name}' already exists. Use edit_node to modify it.",
                "existing_type": existing["type"],
            })

        cache.write_node(name, type, semantic_context, metadata)
        cache.refresh_stats()

        _delta.add_node(name, {
            "type": type,
            "metadata": metadata or {},
            "semantic_context": semantic_context or [],
        })
        _delta.record("add_node", name, reason, type=type)
        _auto_save()

        return json.dumps({
            "action": "added",
            "node": name,
            "type": type,
            "pending_changes": _delta.change_count,
            "energy_note": "New nodes have no energy scores until inference re-runs.",
        })

    @mcp.tool()
    async def edit_node(
        name: str,
        type: str | None = None,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        remove_keys: list[str] | None = None,
        reason: str = "",
    ) -> str:
        """Edit an existing node's type, metadata, or description.

        Metadata is deep-merged: nested dicts are merged recursively,
        non-dict values are replaced.  Semantic context is replaced if provided.

        Args:
            name: Node to edit (exact name or substring match).
            type: Change the node type (e.g. "service" → "k8s_deployment").
            metadata: Fields to add or overwrite (deep-merged into existing metadata).
            semantic_context: New description lines (replaces existing if provided).
            remove_keys: Dot-path metadata keys to remove (e.g. ["last_verified", "resources.cpu"]).
            reason: Why you're making this change.
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        # Resolve name
        resolved = cache.resolve_node(name)
        if resolved is None:
            return json.dumps({"error": f"Node not found: {name}"})

        # Require prior read — same pattern as Edit requiring Read
        read_gate = _require_read_node(name, resolved)
        if read_gate:
            return read_gate

        if metadata is None and semantic_context is None and type is None and remove_keys is None:
            return json.dumps({"error": "Provide type, metadata, semantic_context, or remove_keys to edit."})

        before = cache.update_node_metadata(
            resolved, metadata, semantic_context,
            node_type=type, remove_keys_list=remove_keys,
        )
        if before is None:
            return json.dumps({"error": f"Node not found: {resolved}"})

        # Compute what changed for the response
        changes: dict[str, Any] = {}
        if type is not None:
            changes["type"] = f"{before.get('type')} → {type}"
        if metadata:
            for k, v in metadata.items():
                old_val = before.get("metadata", {}).get(k)
                if old_val != v:
                    changes[f"metadata.{k}"] = f"{old_val} → {v}"
        if remove_keys:
            changes["removed_keys"] = remove_keys
        if semantic_context is not None:
            changes["semantic_context"] = "replaced"

        patches: dict[str, Any] = {}
        if type is not None:
            patches["type"] = type
        if metadata:
            patches["metadata"] = metadata
        if semantic_context is not None:
            patches["semantic_context"] = semantic_context
        _delta.modify_node(resolved, patches)

        # When keys were removed, the incremental metadata patch is insufficient —
        # infradb's dict.update() would re-add removed keys from the base.
        # Replace the delta's metadata with the full post-removal state from cache.
        if remove_keys:
            current = cache.query_node(resolved)
            if current:
                _delta.replace_node_metadata(resolved, current.get("metadata", {}))
                _delta.mark_needs_promote(resolved, "node")

        _delta.record("edit_node", resolved, reason, changes=changes)
        _auto_save()

        return json.dumps({
            "action": "edited",
            "node": resolved,
            "changes": changes,
            "pending_changes": _delta.change_count,
        })

    @mcp.tool()
    async def delete_node(
        name: str,
        cascade_edges: bool = True,
        reason: str = "",
    ) -> str:
        """Delete a node from the graph.

        By default, also removes all edges connected to this node.

        Args:
            name: Node to delete (exact name or substring match).
            cascade_edges: Also remove all connected edges (default True).
            reason: Why you're removing this node.
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        resolved = cache.resolve_node(name)
        if resolved is None:
            return json.dumps({"error": f"Node not found: {name}"})

        # Require prior read — same pattern as Edit requiring Read
        read_gate = _require_read_node(name, resolved)
        if read_gate:
            return read_gate

        result = cache.delete_node(resolved, cascade_edges)
        cache.refresh_stats()

        if result["deleted_node"] is None:
            return json.dumps({"error": f"Node not found: {resolved}"})

        _delta.remove_node(resolved)
        if cascade_edges:
            for edge in result["deleted_edges"]:
                _delta.remove_edge(edge["name"])
        _delta.record(
            "delete_node", resolved, reason,
            cascade_edges=len(result["deleted_edges"]),
        )
        _auto_save()

        return json.dumps({
            "action": "deleted",
            "node": resolved,
            "cascade_edges_removed": len(result["deleted_edges"]),
            "pending_changes": _delta.change_count,
        })

    @mcp.tool()
    async def add_edge(
        name: str,
        type: str,
        source: str,
        target: str,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        reason: str = "",
    ) -> str:
        """Add a new edge (connection) to the graph.

        Use when you discover a relationship between nodes that isn't in the
        graph — a network connection, authentication dependency, data flow, etc.

        Args:
            name: Unique edge identifier.
            type: Edge type (e.g. "connects_to", "authenticates", "contains").
            source: Source node name.
            target: Target node name.
            metadata: Key-value pairs describing the connection.
            semantic_context: Description lines explaining this relationship.
            reason: Why you're adding this edge.
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        # Check if edge already exists
        cols = "name, type, source, target"
        existing = cache.db.execute(
            f"SELECT {cols} FROM edges WHERE name = ?", (name,)
        ).fetchone()
        if existing:
            return json.dumps({
                "error": f"Edge '{name}' already exists. Use edit_edge to modify it.",
                "existing_type": existing[1],
                "existing_source": existing[2],
                "existing_target": existing[3],
            })

        # Warn (don't fail) if source/target don't exist
        warnings = []
        if not cache.db.execute("SELECT 1 FROM nodes WHERE name = ?", (source,)).fetchone():
            warnings.append(f"Source node '{source}' not found in graph.")
        if not cache.db.execute("SELECT 1 FROM nodes WHERE name = ?", (target,)).fetchone():
            warnings.append(f"Target node '{target}' not found in graph.")

        cache.write_edge(name, type, source, target, semantic_context, metadata)
        cache.refresh_stats()

        _delta.add_edge(name, {
            "type": type,
            "source": source,
            "target": target,
            "metadata": metadata or {},
            "semantic_context": semantic_context or [],
        })
        _delta.record("add_edge", name, reason, edge_type=type, source=source, edge_target=target)
        _auto_save()

        result: dict[str, Any] = {
            "action": "added",
            "edge": name,
            "type": type,
            "source": source,
            "target": target,
            "pending_changes": _delta.change_count,
        }
        if warnings:
            result["warnings"] = warnings
        return json.dumps(result)

    @mcp.tool()
    async def edit_edge(
        name: str,
        source: str | None = None,
        target: str | None = None,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        remove_keys: list[str] | None = None,
        reason: str = "",
    ) -> str:
        """Edit an existing edge's source, target, metadata, or description.

        Metadata is deep-merged: nested dicts are merged recursively.
        Semantic context is replaced if provided.

        Args:
            name: Edge to edit (exact name).
            source: Change the source node.
            target: Change the target node.
            metadata: Fields to add or overwrite (deep-merged).
            semantic_context: New description lines (replaces existing).
            remove_keys: Dot-path metadata keys to remove.
            reason: Why you're making this change.
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        # Require prior read — same pattern as Edit requiring Read
        read_gate = _require_read_edge(name)
        if read_gate:
            return read_gate

        if all(v is None for v in [source, target, metadata, semantic_context, remove_keys]):
            return json.dumps({"error": "Provide source, target, metadata, semantic_context, or remove_keys to edit."})

        before = cache.update_edge_metadata(
            name, metadata, semantic_context,
            source=source, target=target, remove_keys_list=remove_keys,
        )
        if before is None:
            return json.dumps({"error": f"Edge not found: {name}"})

        changes: dict[str, Any] = {}
        if source is not None:
            changes["source"] = f"{before.get('source')} → {source}"
        if target is not None:
            changes["target"] = f"{before.get('target')} → {target}"
        if metadata:
            for k, v in metadata.items():
                old_val = before.get("metadata", {}).get(k)
                if old_val != v:
                    changes[f"metadata.{k}"] = f"{old_val} → {v}"
        if remove_keys:
            changes["removed_keys"] = remove_keys
        if semantic_context is not None:
            changes["semantic_context"] = "replaced"

        patches: dict[str, Any] = {}
        if source is not None:
            patches["source"] = source
        if target is not None:
            patches["target"] = target
        if metadata:
            patches["metadata"] = metadata
        if semantic_context is not None:
            patches["semantic_context"] = semantic_context
        _delta.modify_edge(name, patches)

        # When keys were removed, replace delta's metadata with full post-removal state.
        if remove_keys:
            cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
            row = cache.db.execute(f"SELECT {cols} FROM edges WHERE name = ?", (name,)).fetchone()
            if row:
                import json as _json
                _delta.replace_edge_metadata(name, _json.loads(row[5]) if row[5] else {})
                _delta.mark_needs_promote(name, "edge")

        _delta.record("edit_edge", name, reason, changes=changes)
        _auto_save()

        return json.dumps({
            "action": "edited",
            "edge": name,
            "changes": changes,
            "pending_changes": _delta.change_count,
        })

    @mcp.tool()
    async def delete_edge(name: str, reason: str = "") -> str:
        """Delete an edge from the graph.

        Args:
            name: Edge to delete (exact name).
            reason: Why you're removing this edge.
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        # Require prior read — same pattern as Edit requiring Read
        read_gate = _require_read_edge(name)
        if read_gate:
            return read_gate

        edge_data = cache.delete_edge(name)
        cache.refresh_stats()

        if edge_data is None:
            return json.dumps({"error": f"Edge not found: {name}"})

        _delta.remove_edge(name)
        _delta.record("delete_edge", name, reason)
        _auto_save()

        return json.dumps({
            "action": "deleted",
            "edge": name,
            "was": {
                "type": edge_data["type"],
                "source": edge_data["source"],
                "target": edge_data["target"],
            },
            "pending_changes": _delta.change_count,
        })

    # ------------------------------------------------------------------
    # Structural — the Write/refactor equivalent
    # ------------------------------------------------------------------

    @mcp.tool()
    async def edit_subgraph(
        remove_nodes: list[str] | None = None,
        remove_edges: list[str] | None = None,
        add_nodes: dict | None = None,
        add_edges: dict | None = None,
        modify_nodes: dict | None = None,
        modify_edges: dict | None = None,
        message: str = "",
    ) -> str:
        """Atomic subgraph replacement — the graph equivalent of rewriting a file.

        Use when restructuring a section of the graph: splitting a node into
        multiple services, inserting middleware, rewiring connections, or
        correcting a whole neighborhood at once.

        All changes are applied atomically — either everything succeeds or
        nothing changes.

        Args:
            remove_nodes: Node names to delete (their edges are also removed).
            remove_edges: Edge names to delete.
            add_nodes: New nodes as {name: {type, metadata?, semantic_context?}}.
            add_edges: New edges as {name: {type, source, target, metadata?, semantic_context?}}.
            modify_nodes: Node patches as {name: {metadata?, semantic_context?}}.
            modify_edges: Edge patches as {name: {metadata?, semantic_context?}}.
            message: Description of the subgraph edit (like a commit message).
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        results: dict[str, Any] = {
            "action": "edit_subgraph",
            "removed_nodes": 0,
            "removed_edges": 0,
            "added_nodes": 0,
            "added_edges": 0,
            "modified_nodes": 0,
            "modified_edges": 0,
            "errors": [],
        }

        # 1. Remove nodes (cascades edges) — require prior read
        if remove_nodes:
            for node_name in remove_nodes:
                resolved = cache.resolve_node(node_name)
                if resolved is None:
                    results["errors"].append(f"Node not found for removal: {node_name}")
                    continue
                if (resolved or node_name) not in _read_nodes:
                    results["errors"].append(
                        f"Node '{node_name}' must be read (read_node) before removing."
                    )
                    continue
                deleted = cache.delete_node(resolved, cascade_edges=True)
                if deleted["deleted_node"]:
                    results["removed_nodes"] += 1
                    _delta.remove_node(resolved)
                    for edge in deleted["deleted_edges"]:
                        _delta.remove_edge(edge["name"])
                        results["removed_edges"] += 1

        # 2. Remove edges — require prior read
        if remove_edges:
            for edge_name in remove_edges:
                if edge_name not in _read_edges:
                    results["errors"].append(
                        f"Edge '{edge_name}' must be read (read_edge) before removing."
                    )
                    continue
                edge_data = cache.delete_edge(edge_name)
                if edge_data:
                    results["removed_edges"] += 1
                    _delta.remove_edge(edge_name)
                else:
                    results["errors"].append(f"Edge not found for removal: {edge_name}")

        # 3. Add nodes
        if add_nodes:
            for node_name, node_data in add_nodes.items():
                node_type = node_data.get("type")
                if not node_type:
                    results["errors"].append(f"Node '{node_name}' missing required 'type' field.")
                    continue
                cache.write_node(
                    node_name,
                    node_type,
                    node_data.get("semantic_context"),
                    node_data.get("metadata"),
                )
                _delta.add_node(node_name, node_data)
                results["added_nodes"] += 1

        # 4. Add edges
        if add_edges:
            for edge_name, edge_data in add_edges.items():
                edge_type = edge_data.get("type")
                source = edge_data.get("source")
                target = edge_data.get("target")
                if not all([edge_type, source, target]):
                    results["errors"].append(
                        f"Edge '{edge_name}' missing required fields (type, source, target)."
                    )
                    continue
                cache.write_edge(
                    edge_name,
                    edge_type,
                    source,
                    target,
                    edge_data.get("semantic_context"),
                    edge_data.get("metadata"),
                )
                _delta.add_edge(edge_name, edge_data)
                results["added_edges"] += 1

        # 5. Modify nodes — require prior read
        if modify_nodes:
            for node_name, patches in modify_nodes.items():
                if node_name not in _read_nodes:
                    results["errors"].append(
                        f"Node '{node_name}' must be read (read_node) before modifying."
                    )
                    continue
                before = cache.update_node_metadata(
                    node_name,
                    patches.get("metadata"),
                    patches.get("semantic_context"),
                )
                if before is None:
                    results["errors"].append(f"Node not found for modification: {node_name}")
                    continue
                _delta.modify_node(node_name, patches)
                results["modified_nodes"] += 1

        # 6. Modify edges — require prior read
        if modify_edges:
            for edge_name, patches in modify_edges.items():
                if edge_name not in _read_edges:
                    results["errors"].append(
                        f"Edge '{edge_name}' must be read (read_edge) before modifying."
                    )
                    continue
                before = cache.update_edge_metadata(
                    edge_name,
                    patches.get("metadata"),
                    patches.get("semantic_context"),
                )
                if before is None:
                    results["errors"].append(f"Edge not found for modification: {edge_name}")
                    continue
                _delta.modify_edge(edge_name, patches)
                results["modified_edges"] += 1

        cache.refresh_stats()

        total = (
            results["removed_nodes"]
            + results["removed_edges"]
            + results["added_nodes"]
            + results["added_edges"]
            + results["modified_nodes"]
            + results["modified_edges"]
        )

        _delta.record("edit_subgraph", "subgraph", message, summary=results)
        _auto_save()

        results["total_operations"] = total
        results["pending_changes"] = _delta.change_count
        results["message"] = message
        return json.dumps(results)

    # ------------------------------------------------------------------
    # Bulk operations
    # ------------------------------------------------------------------

    @mcp.tool()
    async def bulk_edit_edges(
        edge_type: str | None = None,
        source_node: str | None = None,
        target_node: str | None = None,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        dry_run: bool = True,
        reason: str = "",
    ) -> str:
        """Edit all edges matching a filter.

        Default is dry_run — shows which edges would be edited.
        Set dry_run=false to apply.  Does NOT require individual read_edge
        calls — the filter-based approach is the read.

        Args:
            edge_type: Filter by edge type (e.g. "connects_to").
            source_node: Filter by source node name.
            target_node: Filter by target node name.
            metadata: Fields to add or overwrite on all matching edges (deep-merged).
            semantic_context: New description lines for all matching edges.
            dry_run: Preview changes without applying (default True).
            reason: Why you're editing these edges.
        """
        gate = _gate_write()
        if gate:
            return gate
        cache = get_cache()

        if edge_type is None and source_node is None and target_node is None:
            return json.dumps({"error": "Provide at least one filter: edge_type, source_node, or target_node."})

        if not dry_run and metadata is None and semantic_context is None:
            return json.dumps({"error": "Provide metadata and/or semantic_context to apply."})

        # Build query
        conditions = []
        params: list[Any] = []
        if edge_type:
            conditions.append("type = ?")
            params.append(edge_type)
        if source_node:
            conditions.append("source = ?")
            params.append(source_node)
        if target_node:
            conditions.append("target = ?")
            params.append(target_node)

        where = " AND ".join(conditions)
        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        rows = cache.db.execute(f"SELECT {cols} FROM edges WHERE {where}", params).fetchall()

        edges = [cache._edge_from_row(r) for r in rows]

        if dry_run:
            return json.dumps({
                "action": "dry_run",
                "matching_edges": len(edges),
                "edges": [
                    {"name": e["name"], "type": e["type"],
                     "source": e["source"], "target": e["target"],
                     "metadata": e.get("metadata", {})}
                    for e in edges[:20]  # limit preview
                ],
                "note": f"{len(edges)} edges match. Call with dry_run=false to apply.",
            })

        # Apply edits
        for edge in edges:
            cache.update_edge_metadata(edge["name"], metadata, semantic_context)
            patches: dict[str, Any] = {}
            if metadata:
                patches["metadata"] = metadata
            if semantic_context is not None:
                patches["semantic_context"] = semantic_context
            _delta.modify_edge(edge["name"], patches)

        _delta.record(
            "bulk_edit_edges", f"{len(edges)} edges", reason,
            edge_type=edge_type, source_node=source_node, target_node=target_node,
        )
        _auto_save()

        return json.dumps({
            "action": "bulk_edited",
            "edges_updated": len(edges),
            "pending_changes": _delta.change_count,
        })

    # ------------------------------------------------------------------
    # Transaction helpers
    # ------------------------------------------------------------------

    @mcp.tool()
    async def pending_changes() -> str:
        """Show all uncommitted graph changes.

        Returns counts by category (nodes/edges added, modified, removed)
        and a changelog of every individual operation with reasons.
        """
        delta = get_delta()
        if delta.is_empty:
            return json.dumps({"status": "clean", "message": "No pending changes."})

        changelog = [
            {
                "action": r.action,
                "target": r.target,
                "reason": r.reason,
                **r.details,
            }
            for r in delta.changelog
        ]

        return json.dumps({
            "status": "dirty",
            **delta.summary(),
            "changelog": changelog,
            "delta_preview": delta.to_delta_dict(),
        })

    @mcp.tool()
    async def rollback_changes() -> str:
        """Discard all pending graph changes and reload from the original cache.

        This reverts the local SQLite cache to the last loaded state by
        clearing the delta and reloading from disk.  Remote data is not
        affected.
        """
        c = get_cache()
        if c is None or not c.loaded:
            return json.dumps({"error": "No graph loaded."})

        delta = get_delta()
        if delta.is_empty:
            return json.dumps({"status": "clean", "message": "Nothing to rollback."})

        discarded = delta.change_count
        branch_id = c.branch_id
        delta.clear()

        # Clear persisted delta file
        if branch_id:
            clear_delta_file(branch_id)

        # Close current connections — the SQLite cache has been modified
        # by observation tools, so a fresh load from the server is needed.
        c.close()

        return json.dumps({
            "status": "rolled_back",
            "discarded_changes": discarded,
            "action_required": (
                f"Call load_graph_energies('{branch_id}') to reload "
                "the graph from its original state.  The local cache "
                "file may contain the edits — a fresh load replaces it."
            ),
        })

    @mcp.tool()
    async def commit_graph(
        message: str,
        branch_id: str = "",
    ) -> str:
        """Commit pending graph changes to infradb.

        Posts the accumulated observation delta to the infradb commit endpoint,
        creating a new commit on the branch.  Requires ``infra:write`` scope
        and an active connection to the deployment.

        On success the pending delta is cleared.  On failure the delta is
        preserved so you can retry.

        Args:
            message: Commit message describing what was observed/corrected.
            branch_id: Branch to commit to.  Defaults to the currently loaded branch.
        """
        if post_fn is None:
            return json.dumps({
                "error": "commit_graph requires a remote connection. "
                         "The _post helper was not provided at registration.",
            })

        delta = get_delta()
        if delta.is_empty:
            return json.dumps({"status": "clean", "message": "No pending changes to commit."})

        cache = get_cache()
        resolved_branch = branch_id or (cache.branch_id if cache else None)
        if not resolved_branch:
            return json.dumps({
                "error": "No branch_id specified and no graph loaded.",
            })

        delta_dict = delta.to_delta_dict(cache=cache)
        summary = delta.summary()

        try:
            resp = await post_fn(
                f"/api/infra/branches/{resolved_branch}/commits",
                {
                    "delta": delta_dict,
                    "message": message,
                    "author": "mcp-observation",
                },
                _tool="commit_graph",
            )
        except Exception as exc:
            # Don't clear the delta on failure — changes are still pending
            return json.dumps({
                "error": f"Commit failed: {exc}",
                "pending_changes": delta.change_count,
                "hint": "The delta is preserved. Fix the issue and retry commit_graph.",
            })

        # Success — clear the in-memory delta and the persisted file
        delta.clear()
        if resolved_branch:
            clear_delta_file(resolved_branch)

        commit_id = resp.get("commit_id", resp.get("id", "unknown"))
        return json.dumps({
            "status": "committed",
            "commit_id": commit_id,
            "branch_id": resolved_branch,
            "message": message,
            **summary,
        })

    # ------------------------------------------------------------------
    # Rollback
    # ------------------------------------------------------------------

    @mcp.tool()
    async def rollback_to_commit(
        commit_id: str,
        branch_id: str = "",
        message: str = "",
    ) -> str:
        """Roll back the graph branch to a previous commit.

        Creates a new commit that reverses all changes since the target
        commit.  This is non-destructive — the old commits remain in the
        history and you can roll forward again by targeting a later commit.

        After rollback, the local cache is stale.  Call load_graph_energies
        to reload the graph from the rolled-back state.

        Args:
            commit_id: The commit to roll back to (from list_commits).
            branch_id: Branch to roll back. Defaults to the currently loaded branch.
            message: Commit message for the rollback. Defaults to "Rollback to {commit_id}".
        """
        if post_fn is None:
            return json.dumps({
                "error": "rollback_to_commit requires a remote connection. "
                         "The _post helper was not provided at registration.",
            })

        cache = get_cache()
        resolved_branch = branch_id or (cache.branch_id if cache else None)
        if not resolved_branch:
            return json.dumps({
                "error": "No branch_id specified and no graph loaded.",
            })

        rollback_msg = message or f"Rollback to {commit_id}"

        try:
            resp = await post_fn(
                f"/api/infra/branches/{resolved_branch}/rollback",
                {
                    "target_commit_id": commit_id,
                    "author": "mcp-observation",
                    "message": rollback_msg,
                },
                _tool="rollback_to_commit",
            )
        except Exception as exc:
            return json.dumps({
                "error": f"Rollback failed: {exc}",
                "hint": "Check that the commit_id exists on this branch.",
            })

        # Clear local state — the cache is now stale
        delta = get_delta()
        delta.clear()
        if resolved_branch:
            clear_delta_file(resolved_branch)

        new_commit_id = resp.get("commit_id", resp.get("id", "unknown"))
        return json.dumps({
            "status": "rolled_back",
            "new_commit_id": new_commit_id,
            "target_commit_id": commit_id,
            "branch_id": resolved_branch,
            "message": rollback_msg,
            "action_required": (
                f"Call load_graph_energies(\'{resolved_branch}\') to reload "
                "the graph from the rolled-back state."
            ),
        })

