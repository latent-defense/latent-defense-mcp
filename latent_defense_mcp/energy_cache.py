"""SQLite-backed graph + energy cache.

Replaces in-memory dicts with a SQLite database.  The MCP process holds a
connection, not the data — the OS page cache handles hot rows.  For a 14K-node
graph this is ~20 MB on disk vs 100+ MB in Python dicts.

The database file lives at ``~/.latent-defense/graph-cache/<branch_id>.db``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from pathlib import Path
from typing import Any

import httpx

log = logging.getLogger("latent-defense-mcp")


def _deep_merge(base: dict, updates: dict) -> dict:
    """Recursively merge *updates* into *base*.  Lists and non-dict values
    are replaced; nested dicts are merged recursively."""
    result = {**base}
    for key, val in updates.items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _remove_keys(metadata: dict, keys: list[str]) -> dict:
    """Remove dot-path keys from a metadata dict.  Returns a new dict.

    >>> _remove_keys({"a": 1, "b": {"c": 2, "d": 3}}, ["a", "b.c"])
    {'b': {'d': 3}}
    """
    result = json.loads(json.dumps(metadata))  # deep copy
    for key_path in keys:
        parts = key_path.split(".")
        obj = result
        for part in parts[:-1]:
            if isinstance(obj, dict) and part in obj:
                obj = obj[part]
            else:
                break
        else:
            if isinstance(obj, dict) and parts[-1] in obj:
                del obj[parts[-1]]
    return result


_CACHE_DIR = Path(os.environ.get(
    "GRAPH_CACHE_DIR",
    Path.home() / ".latent-defense" / "graph-cache",
))


def _db_path(branch_id: str) -> Path:
    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    safe_id = re.sub(r"[^a-zA-Z0-9._-]", "", branch_id)
    if not safe_id:
        raise ValueError("Invalid branch_id")
    return _CACHE_DIR / f"{safe_id}.db"


class EncodingInProgress(RuntimeError):
    """The inference server is still encoding this graph.

    Raised when the energy endpoints time out or return a gateway error.
    Server-side encoding is not tied to the HTTP request — it keeps running
    and populates the server's disk cache. Callers should NOT retry the
    energy endpoints while this is in flight: the inference server does not
    de-duplicate in-flight encodes, so every retry starts another full
    MiniLM + encoder pass competing for the same CPU. Wait for encoding to
    finish (oracle encoding-status), then fetch once.
    """


class EnergyGraphCache:
    """SQLite-backed graph + energy cache.

    Uses WAL mode for concurrent readers.  Each query opens a fresh connection
    from a URI-based pool so 20+ parallel tool calls don't serialize on a
    single connection or trip SQLite's thread-safety check.
    """

    def __init__(self) -> None:
        self._db_path: str | None = None
        self._write_db: sqlite3.Connection | None = None  # used only during build()
        self._read_db: sqlite3.Connection | None = None   # shared read-only connection
        self.branch_id: str | None = None
        self.repository_id: str | None = None
        self.commit_id: str | None = None
        self.loaded: bool = False
        self.has_energies: bool = False
        self.energies_incomplete: bool = False
        self.energy_error: str | None = None
        self.encoding_in_progress: bool = False
        self._n_nodes: int = 0
        self._n_edges: int = 0
        self._n_node_types: int = 0
        self._n_edge_types: int = 0
        self._n_containment: int = 0

    @property
    def db(self) -> sqlite3.Connection:
        """Return a shared read-only connection.  SQLite WAL mode supports
        concurrent readers, and check_same_thread=False allows safe access
        from any async context.  Reusing a single connection avoids leaking
        file descriptors and accumulating page-cache memory across hundreds
        of per-call connections.
        """
        if self._read_db is None:
            self._read_db = sqlite3.connect(
                f"file:{self._db_path}?mode=ro",
                uri=True,
                check_same_thread=False,
            )
            self._read_db.execute("PRAGMA query_only=ON")
        return self._read_db

    def close(self) -> None:
        if self._read_db is not None:
            self._read_db.close()
            self._read_db = None
        if self._write_db is not None:
            self._write_db.close()
            self._write_db = None

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    @staticmethod
    def _create_tables(db: sqlite3.Connection) -> None:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (
                name            TEXT PRIMARY KEY,
                type            TEXT NOT NULL,
                semantic_context TEXT,
                metadata        TEXT,
                entry_energy    REAL,
                energy_type     TEXT
            );
            CREATE TABLE IF NOT EXISTS edges (
                name            TEXT PRIMARY KEY,
                type            TEXT NOT NULL,
                source          TEXT NOT NULL,
                target          TEXT NOT NULL,
                semantic_context TEXT,
                metadata        TEXT,
                transition_energy REAL,
                energy_type     TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
            CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
            CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(type);
            CREATE INDEX IF NOT EXISTS idx_nodes_entry_energy ON nodes(entry_energy);
            CREATE INDEX IF NOT EXISTS idx_nodes_name_nocase ON nodes(name COLLATE NOCASE);
        """)

    # ------------------------------------------------------------------
    # Reload from existing database (after process restart)
    # ------------------------------------------------------------------

    @classmethod
    def from_disk(cls, branch_id: str) -> "EnergyGraphCache | None":
        """Try to reload from an existing SQLite database file."""
        db_file = _db_path(branch_id)
        if not db_file.exists():
            return None

        cache = cls()
        cache.branch_id = branch_id
        cache._db_path = str(db_file)

        # Verify it has data using a temporary connection
        try:
            conn = sqlite3.connect(str(db_file))
            n = conn.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
            e = conn.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
            conn.close()
        except sqlite3.OperationalError:
            return None

        if n == 0:
            cache.close()
            return None

        cache._n_nodes = n
        cache._n_edges = e
        conn = sqlite3.connect(str(db_file))
        cache._n_node_types = conn.execute("SELECT COUNT(DISTINCT type) FROM nodes").fetchone()[0]
        cache._n_edge_types = conn.execute("SELECT COUNT(DISTINCT type) FROM edges").fetchone()[0]
        cache._n_containment = conn.execute(
            "SELECT COUNT(*) FROM edges WHERE type = 'contains'"
        ).fetchone()[0]
        has_energy = conn.execute(
            "SELECT COUNT(*) FROM nodes WHERE entry_energy IS NOT NULL"
        ).fetchone()[0]
        conn.close()
        cache.has_energies = has_energy > 0
        if not cache.has_energies:
            cache.energy_error = "Cached graph has no energy scores."

        cache.loaded = True
        log.info(
            "Reloaded graph from disk: %d nodes, %d edges, energies=%s (file: %s)",
            n, e, cache.has_energies, db_file,
        )
        return cache

    # ------------------------------------------------------------------
    # Construction (full fetch from APIs)
    # ------------------------------------------------------------------

    @classmethod
    async def build(
        cls,
        branch_id: str,
        http_client: httpx.AsyncClient,
        fetch_energies: bool = True,
    ) -> "EnergyGraphCache":
        """Fetch the graph (and, by default, its energies) into a fresh SQLite cache.

        Pass ``fetch_energies=False`` when server-side encoding is known to be
        still running: the graph is cached so graph tools work, and energies
        can be merged later with :meth:`refresh_energies` without re-fetching
        the graph. Calling the energy endpoints mid-encode would start a
        duplicate encode on the server.
        """
        cache = cls()
        cache.branch_id = branch_id

        # 0. Look up branch to get repository_id
        branch_resp = await http_client.get(
            f"/api/infra/branches/{branch_id}",
            timeout=30,
        )
        branch_resp.raise_for_status()
        branch_data = branch_resp.json()
        cache.repository_id = branch_data.get("repository_id", "")

        # Open (or create) the SQLite database — write connection for build only
        db_file = _db_path(branch_id)
        cache._db_path = str(db_file)
        cache._write_db = sqlite3.connect(str(db_file), check_same_thread=False)
        cache._write_db.execute("PRAGMA journal_mode=WAL")
        cache._write_db.execute("PRAGMA synchronous=NORMAL")
        cls._create_tables(cache._write_db)

        # Clear any stale data from a previous load
        cache._write_db.execute("DELETE FROM nodes")
        cache._write_db.execute("DELETE FROM edges")
        cache._write_db.commit()

        # 1. Fetch graph (NDJSON stream) → SQLite
        await cache._fetch_graph(branch_id, http_client)

        # 2-4. Fetch metadata + energies from JEPA endpoints → overlay onto SQLite
        if fetch_energies:
            try:
                await cache._fetch_and_merge_energies(
                    branch_id, cache.repository_id, http_client,
                )
                cache._recompute_energy_state()
            except EncodingInProgress as exc:
                cache.encoding_in_progress = True
                cache.energy_error = str(exc)
                log.info("Energies not ready for branch %s: %s", branch_id, exc)
            except Exception as exc:
                cache.energy_error = f"Energy fetch failed: {exc}"
                log.warning("Energy fetch failed for branch %s: %s", branch_id, exc)
        else:
            cache.encoding_in_progress = True
            cache.energy_error = (
                "Encoding still in progress on the inference server; "
                "energies were not requested to avoid starting a duplicate encode."
            )

        # Compute stats from the write connection (guaranteed to see all data)
        wdb = cache._write_db
        cache._n_nodes = wdb.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        cache._n_edges = wdb.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        cache._n_node_types = wdb.execute("SELECT COUNT(DISTINCT type) FROM nodes").fetchone()[0]
        cache._n_edge_types = wdb.execute("SELECT COUNT(DISTINCT type) FROM edges").fetchone()[0]
        cache._n_containment = wdb.execute(
            "SELECT COUNT(*) FROM edges WHERE type = 'contains'"
        ).fetchone()[0]

        # Close the write connection — all further access is read-only via the db property
        cache._write_db.close()
        cache._write_db = None

        cache.loaded = True
        log.info(
            "Graph cache ready: %d nodes, %d edges, energies=%s (file: %s)",
            cache._n_nodes, cache._n_edges, cache.has_energies, db_file,
        )
        return cache

    # ------------------------------------------------------------------
    # Energy refresh for an already-cached graph
    # ------------------------------------------------------------------

    def _recompute_energy_state(self) -> None:
        """Derive has_energies / energy_error from the rows in the write connection."""
        row = self._write_db.execute(
            "SELECT COUNT(*) FROM nodes WHERE entry_energy IS NOT NULL"
        ).fetchone()
        if row[0] > 0:
            self.has_energies = True
            self.encoding_in_progress = False
            self.energy_error = None
        else:
            self.has_energies = False
            self.energy_error = (
                "Energy data returned but no names matched the graph. "
                "The inference cache may be stale — retry load_graph_energies."
            )

    async def refresh_energies(self, http_client: httpx.AsyncClient) -> bool:
        """Fetch energies for the graph already in this cache and merge them in place.

        Used when the graph was cached (from disk or a previous build) but the
        energy fetch did not complete — typically because server-side encoding
        was still running. Does not re-download the graph.

        Returns True when the cache has energies afterwards. Raises
        :class:`EncodingInProgress` if the server is still encoding.
        """
        if self._db_path is None or self.branch_id is None:
            raise RuntimeError("No graph loaded — call load_graph_energies first.")

        if not self.repository_id:
            resp = await http_client.get(
                f"/api/infra/branches/{self.branch_id}", timeout=30,
            )
            resp.raise_for_status()
            self.repository_id = resp.json().get("repository_id", "")

        owns_write = self._write_db is None
        if owns_write:
            self._write_db = sqlite3.connect(self._db_path, check_same_thread=False)
            self._write_db.execute("PRAGMA journal_mode=WAL")
            self._write_db.execute("PRAGMA synchronous=NORMAL")
        try:
            await self._fetch_and_merge_energies(
                self.branch_id, self.repository_id, http_client,
            )
            self._recompute_energy_state()
        except EncodingInProgress as exc:
            self.encoding_in_progress = True
            self.energy_error = str(exc)
            raise
        finally:
            if owns_write:
                self._write_db.close()
                self._write_db = None
            # Reopen the shared read connection lazily so it sees the merged rows.
            if self._read_db is not None:
                self._read_db.close()
                self._read_db = None
        return self.has_energies

    # ------------------------------------------------------------------
    # Step 1: Fetch graph → SQLite
    # ------------------------------------------------------------------

    async def _fetch_graph(
        self,
        branch_id: str,
        client: httpx.AsyncClient,
    ) -> None:
        db = self._write_db
        batch_nodes: list[tuple] = []
        batch_edges: list[tuple] = []

        async with client.stream(
            "GET",
            f"/api/infra/branches/{branch_id}/graph/stream",
            timeout=300,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.strip():
                    continue
                row = json.loads(line)
                if row.get("error"):
                    raise RuntimeError(f"Graph stream error: {row['error']}")
                if row.get("kind") == "commit_id":
                    self.commit_id = row.get("commit_id")
                    continue
                if row["kind"] == "node":
                    ctx = row.get("semantic_context", [])
                    batch_nodes.append((
                        row["name"],
                        row["type"],
                        json.dumps(ctx) if ctx else None,
                        json.dumps(row.get("metadata", {})),
                    ))
                elif row["kind"] == "edge":
                    ctx = row.get("semantic_context", [])
                    batch_edges.append((
                        row["name"],
                        row["type"],
                        row["source"],
                        row["target"],
                        json.dumps(ctx) if ctx else None,
                        json.dumps(row.get("metadata", {})),
                    ))

                # Flush in batches
                if len(batch_nodes) >= 1000:
                    db.executemany(
                        "INSERT OR REPLACE INTO nodes (name, type, semantic_context, metadata) "
                        "VALUES (?, ?, ?, ?)",
                        batch_nodes,
                    )
                    batch_nodes.clear()
                if len(batch_edges) >= 1000:
                    db.executemany(
                        "INSERT OR REPLACE INTO edges (name, type, source, target, semantic_context, metadata) "
                        "VALUES (?, ?, ?, ?, ?, ?)",
                        batch_edges,
                    )
                    batch_edges.clear()

        # Flush remaining
        if batch_nodes:
            db.executemany(
                "INSERT OR REPLACE INTO nodes (name, type, semantic_context, metadata) "
                "VALUES (?, ?, ?, ?)",
                batch_nodes,
            )
        if batch_edges:
            db.executemany(
                "INSERT OR REPLACE INTO edges (name, type, source, target, semantic_context, metadata) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                batch_edges,
            )
        db.commit()

        n = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        e = db.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        log.info("Fetched graph: %d nodes, %d edges (branch %s)", n, e, branch_id)

    # ------------------------------------------------------------------
    # Steps 2-4: Fetch energies → overlay onto SQLite
    # ------------------------------------------------------------------

    async def _fetch_and_merge_energies(
        self,
        branch_id: str,
        repository_id: str,
        client: httpx.AsyncClient,
    ) -> None:
        params = {"branch_id": branch_id, "repository_id": repository_id}
        db = self._write_db

        # Entry energies. On a cold server cache this call triggers encoding;
        # if the proxy times out first, EncodingInProgress propagates. We never
        # retry here — and never with force_refresh — because the server has no
        # in-flight de-duplication: each call would start another full encode.
        entry_energies = await self._fetch_entry_energies(params, client)
        if not entry_energies:
            raise RuntimeError("batch_entry_energies returned empty.")

        # Metadata
        meta_resp = await client.post(
            "/api/jepa/graph_metadata", params=params, json={}, timeout=120,
        )
        meta_resp.raise_for_status()
        meta = meta_resp.json()
        node_ids: list[str] = meta.get("node_ids", [])
        edge_ids: list[str] = meta.get("edge_ids", [])
        node_types: list[str] = meta.get("node_types", [])
        edge_types: list[str] = meta.get("edge_types", [])

        # Transition energies (SSE)
        transition_energies: list[float] = []
        async with client.stream(
            "POST", "/api/jepa/batch_transition_energies",
            params=params, json={}, timeout=600,
        ) as resp:
            resp.raise_for_status()
            async for line in resp.aiter_lines():
                if not line.startswith("data:"):
                    continue
                event = json.loads(line[5:].strip())
                if event["type"] == "complete":
                    transition_energies = event["result"]["energies"]
                elif event["type"] == "error":
                    raise RuntimeError(f"Transition energy error: {event['message']}")

        if len(edge_ids) > 0 and not transition_energies:
            self.energies_incomplete = True

        # Merge entry energies onto nodes
        node_updates = []
        for i, name in enumerate(node_ids):
            ee = entry_energies[i] if i < len(entry_energies) else None
            et = node_types[i] if i < len(node_types) else None
            if ee is not None:
                node_updates.append((ee, et, name))
        if node_updates:
            db.executemany(
                "UPDATE nodes SET entry_energy = ?, energy_type = ? WHERE name = ?",
                node_updates,
            )

        # Merge transition energies onto edges
        edge_updates = []
        for i, name in enumerate(edge_ids):
            te = transition_energies[i] if i < len(transition_energies) else None
            et = edge_types[i] if i < len(edge_types) else None
            if te is not None:
                edge_updates.append((te, et, name))
        if edge_updates:
            db.executemany(
                "UPDATE edges SET transition_energy = ?, energy_type = ? WHERE name = ?",
                edge_updates,
            )

        db.commit()
        log.info(
            "Merged energies: %d node updates, %d edge updates",
            len(node_updates),
            len(edge_updates),
        )

    async def _fetch_entry_energies(
        self,
        params: dict,
        client: httpx.AsyncClient,
    ) -> list[float]:
        """POST batch_entry_energies exactly once.

        A gateway timeout (the portal proxies /api/jepa with a 300s read
        timeout) or a client read timeout means the server is still encoding.
        That is surfaced as EncodingInProgress rather than retried.
        """
        try:
            resp = await client.post(
                "/api/jepa/batch_entry_energies",
                params=params,
                json={"force_refresh": False},
                timeout=600,
            )
            resp.raise_for_status()
            return resp.json().get("energies", [])
        except (httpx.ReadTimeout, httpx.ConnectTimeout) as exc:
            raise EncodingInProgress(
                f"batch_entry_energies timed out ({type(exc).__name__}); "
                "the inference server is still encoding this graph."
            ) from exc
        except httpx.HTTPStatusError as exc:
            if exc.response.status_code in (502, 503, 504):
                raise EncodingInProgress(
                    f"batch_entry_energies returned HTTP {exc.response.status_code}; "
                    "the inference server is still encoding this graph."
                ) from exc
            raise

    # ------------------------------------------------------------------
    # Write support (used by observation tools)
    # ------------------------------------------------------------------

    def enable_writes(self) -> None:
        """Transition the cache to read-write mode.

        Opens a WAL-mode write connection alongside the existing read-only
        connection.  WAL allows concurrent readers while writes happen.
        """
        if self._write_db is not None:
            return  # already enabled
        if self._db_path is None:
            raise RuntimeError("No graph loaded — call load_graph_energies first.")
        self._write_db = sqlite3.connect(self._db_path, check_same_thread=False)
        self._write_db.execute("PRAGMA journal_mode=WAL")
        self._write_db.execute("PRAGMA synchronous=NORMAL")
        # Close the read-only connection — reopen as read-write so it sees
        # its own writes immediately.
        if self._read_db is not None:
            self._read_db.close()
            self._read_db = None
        self._read_db = sqlite3.connect(self._db_path, check_same_thread=False)
        log.info("Graph cache: write mode enabled (WAL)")

    @property
    def writable(self) -> bool:
        return self._write_db is not None

    def write_node(
        self,
        name: str,
        node_type: str,
        semantic_context: list[str] | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Insert or replace a node in the local cache."""
        db = self._write_db
        if db is None:
            raise RuntimeError("Writes not enabled — call enable_writes() first.")
        db.execute(
            "INSERT OR REPLACE INTO nodes (name, type, semantic_context, metadata) "
            "VALUES (?, ?, ?, ?)",
            (
                name,
                node_type,
                json.dumps(semantic_context) if semantic_context else None,
                json.dumps(metadata) if metadata else "{}",
            ),
        )
        db.commit()

    def update_node_metadata(
        self,
        name: str,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        node_type: str | None = None,
        remove_keys_list: list[str] | None = None,
    ) -> dict | None:
        """Sparse-merge metadata and/or replace semantic_context on an existing node.

        Args:
            metadata: Keys to merge (deep merge — nested dicts are merged recursively).
            semantic_context: Replace if provided.
            node_type: Change the node type if provided.
            remove_keys_list: Dot-path keys to remove from metadata.

        Returns the previous state of the node, or None if not found.
        """
        db = self._write_db
        if db is None:
            raise RuntimeError("Writes not enabled — call enable_writes() first.")

        # Read current state
        row = db.execute(
            "SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
            "FROM nodes WHERE name = ?",
            (name,),
        ).fetchone()
        if row is None:
            return None

        before = self._node_from_row(row)

        # Change type if requested
        if node_type is not None:
            db.execute("UPDATE nodes SET type = ? WHERE name = ?", (node_type, name))

        # Remove keys first (before merge, so merge can re-add if needed)
        if remove_keys_list:
            current_meta = {**before.get("metadata", {})}
            current_meta = _remove_keys(current_meta, remove_keys_list)
            db.execute(
                "UPDATE nodes SET metadata = ? WHERE name = ?",
                (json.dumps(current_meta), name),
            )
            # Re-read for the merge step
            before_for_merge = {**current_meta}
        else:
            before_for_merge = {**before.get("metadata", {})}

        # Deep-merge metadata — nested dicts are merged recursively
        if metadata:
            current_meta = _deep_merge(before_for_merge, metadata)
            db.execute(
                "UPDATE nodes SET metadata = ? WHERE name = ?",
                (json.dumps(current_meta), name),
            )

        # Replace semantic_context if provided
        if semantic_context is not None:
            db.execute(
                "UPDATE nodes SET semantic_context = ? WHERE name = ?",
                (json.dumps(semantic_context), name),
            )

        db.commit()
        return before

    def write_edge(
        self,
        name: str,
        edge_type: str,
        source: str,
        target: str,
        semantic_context: list[str] | None = None,
        metadata: dict | None = None,
    ) -> None:
        """Insert or replace an edge in the local cache."""
        db = self._write_db
        if db is None:
            raise RuntimeError("Writes not enabled — call enable_writes() first.")
        db.execute(
            "INSERT OR REPLACE INTO edges "
            "(name, type, source, target, semantic_context, metadata) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                name,
                edge_type,
                source,
                target,
                json.dumps(semantic_context) if semantic_context else None,
                json.dumps(metadata) if metadata else "{}",
            ),
        )
        db.commit()

    def update_edge_metadata(
        self,
        name: str,
        metadata: dict | None = None,
        semantic_context: list[str] | None = None,
        source: str | None = None,
        target: str | None = None,
        remove_keys_list: list[str] | None = None,
    ) -> dict | None:
        """Sparse-merge metadata and/or replace semantic_context on an existing edge.

        Args:
            metadata: Keys to merge (deep merge — nested dicts are merged recursively).
            semantic_context: Replace if provided.
            source: Change the edge source node if provided.
            target: Change the edge target node if provided.
            remove_keys_list: Dot-path keys to remove from metadata.

        Returns the previous state of the edge, or None if not found.
        """
        db = self._write_db
        if db is None:
            raise RuntimeError("Writes not enabled — call enable_writes() first.")

        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        row = db.execute(f"SELECT {cols} FROM edges WHERE name = ?", (name,)).fetchone()
        if row is None:
            return None

        before = self._edge_from_row(row)

        # Change source/target if requested
        if source is not None:
            db.execute("UPDATE edges SET source = ? WHERE name = ?", (source, name))
        if target is not None:
            db.execute("UPDATE edges SET target = ? WHERE name = ?", (target, name))

        # Remove keys first
        if remove_keys_list:
            current_meta = {**before.get("metadata", {})}
            current_meta = _remove_keys(current_meta, remove_keys_list)
            db.execute(
                "UPDATE edges SET metadata = ? WHERE name = ?",
                (json.dumps(current_meta), name),
            )
            before_for_merge = {**current_meta}
        else:
            before_for_merge = {**before.get("metadata", {})}

        # Deep-merge metadata
        if metadata:
            current_meta = _deep_merge(before_for_merge, metadata)
            db.execute(
                "UPDATE edges SET metadata = ? WHERE name = ?",
                (json.dumps(current_meta), name),
            )

        if semantic_context is not None:
            db.execute(
                "UPDATE edges SET semantic_context = ? WHERE name = ?",
                (json.dumps(semantic_context), name),
            )

        db.commit()
        return before

    def delete_node(self, name: str, cascade_edges: bool = True) -> dict:
        """Delete a node from the local cache.

        Returns {deleted_node, deleted_edges} with the removed data.
        """
        db = self._write_db
        if db is None:
            raise RuntimeError("Writes not enabled — call enable_writes() first.")

        # Read the node before deleting
        row = db.execute(
            "SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
            "FROM nodes WHERE name = ?",
            (name,),
        ).fetchone()
        node_data = self._node_from_row(row) if row else None

        deleted_edges = []
        if cascade_edges:
            cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
            for erow in db.execute(
                f"SELECT {cols} FROM edges WHERE source = ? OR target = ?",
                (name, name),
            ).fetchall():
                deleted_edges.append(self._edge_from_row(erow))
            db.execute("DELETE FROM edges WHERE source = ? OR target = ?", (name, name))

        db.execute("DELETE FROM nodes WHERE name = ?", (name,))
        db.commit()

        return {"deleted_node": node_data, "deleted_edges": deleted_edges}

    def delete_edge(self, name: str) -> dict | None:
        """Delete an edge from the local cache. Returns the deleted edge data."""
        db = self._write_db
        if db is None:
            raise RuntimeError("Writes not enabled — call enable_writes() first.")

        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        row = db.execute(f"SELECT {cols} FROM edges WHERE name = ?", (name,)).fetchone()
        edge_data = self._edge_from_row(row) if row else None

        db.execute("DELETE FROM edges WHERE name = ?", (name,))
        db.commit()
        return edge_data

    def refresh_stats(self) -> None:
        """Recompute cached statistics after writes."""
        db = self._write_db or self.db
        self._n_nodes = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        self._n_edges = db.execute("SELECT COUNT(*) FROM edges").fetchone()[0]
        self._n_node_types = db.execute("SELECT COUNT(DISTINCT type) FROM nodes").fetchone()[0]
        self._n_edge_types = db.execute("SELECT COUNT(DISTINCT type) FROM edges").fetchone()[0]
        self._n_containment = db.execute(
            "SELECT COUNT(*) FROM edges WHERE type = 'contains'"
        ).fetchone()[0]

    # ------------------------------------------------------------------
    # Query helpers (used by tool modules)
    # ------------------------------------------------------------------

    def query_node(self, name: str) -> dict | None:
        row = self.db.execute(
            "SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
            "FROM nodes WHERE name = ?", (name,)
        ).fetchone()
        if row is None:
            return None
        return self._node_from_row(row)

    def grep_nodes(self, pattern: str, field: str = "name", limit: int = 25) -> list[dict]:
        like = f"%{pattern}%"
        if field == "all":
            sql = ("SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
                   "FROM nodes WHERE name LIKE ? COLLATE NOCASE "
                   "OR type LIKE ? COLLATE NOCASE "
                   "OR semantic_context LIKE ? COLLATE NOCASE LIMIT ?")
            params = (like, like, like, limit)
        elif field == "name":
            sql = ("SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
                   "FROM nodes WHERE name LIKE ? COLLATE NOCASE LIMIT ?")
            params = (like, limit)
        elif field == "type":
            sql = ("SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
                   "FROM nodes WHERE type LIKE ? COLLATE NOCASE LIMIT ?")
            params = (like, limit)
        elif field == "context":
            sql = ("SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
                   "FROM nodes WHERE semantic_context LIKE ? COLLATE NOCASE LIMIT ?")
            params = (like, limit)
        else:
            return []
        return [self._node_from_row(r) for r in self.db.execute(sql, params).fetchall()]

    def grep_edges(self, pattern: str, field: str = "name", limit: int = 25) -> list[dict]:
        like = f"%{pattern}%"
        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        if field == "all":
            sql = (f"SELECT {cols} FROM edges WHERE name LIKE ? COLLATE NOCASE "
                   "OR type LIKE ? COLLATE NOCASE "
                   "OR semantic_context LIKE ? COLLATE NOCASE LIMIT ?")
            params = (like, like, like, limit)
        elif field == "name":
            sql = f"SELECT {cols} FROM edges WHERE name LIKE ? COLLATE NOCASE LIMIT ?"
            params = (like, limit)
        elif field == "type":
            sql = f"SELECT {cols} FROM edges WHERE type LIKE ? COLLATE NOCASE LIMIT ?"
            params = (like, limit)
        elif field == "context":
            sql = f"SELECT {cols} FROM edges WHERE semantic_context LIKE ? COLLATE NOCASE LIMIT ?"
            params = (like, limit)
        else:
            return []
        return [self._edge_from_row(r) for r in self.db.execute(sql, params).fetchall()]

    def find_nodes_by_type(self, node_type: str, limit: int = 50) -> list[dict]:
        rows = self.db.execute(
            "SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
            "FROM nodes WHERE type = ? ORDER BY name LIMIT ?", (node_type, limit)
        ).fetchall()
        total = self.db.execute("SELECT COUNT(*) FROM nodes WHERE type = ?", (node_type,)).fetchone()[0]
        return [self._node_from_row(r) for r in rows], total

    def find_edges_by_type(self, edge_type: str, limit: int = 50) -> list[dict]:
        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        rows = self.db.execute(
            f"SELECT {cols} FROM edges WHERE type = ? ORDER BY name LIMIT ?", (edge_type, limit)
        ).fetchall()
        total = self.db.execute("SELECT COUNT(*) FROM edges WHERE type = ?", (edge_type,)).fetchone()[0]
        return [self._edge_from_row(r) for r in rows], total

    def get_connected_edges(self, node_name: str, direction: str = "both") -> list[dict]:
        cols = "name, type, source, target, semantic_context, metadata, transition_energy, energy_type"
        results = []
        if direction in ("outbound", "both"):
            for r in self.db.execute(f"SELECT {cols} FROM edges WHERE source = ?", (node_name,)).fetchall():
                e = self._edge_from_row(r)
                e["direction"] = "outbound"
                results.append(e)
        if direction in ("inbound", "both"):
            for r in self.db.execute(f"SELECT {cols} FROM edges WHERE target = ?", (node_name,)).fetchall():
                e = self._edge_from_row(r)
                e["direction"] = "inbound"
                results.append(e)
        return results

    def get_outbound_edges(self, node_name: str) -> list[dict]:
        cols = "name, type, source, target, transition_energy, energy_type"
        return [
            {"name": r[0], "type": r[1], "source": r[2], "target": r[3],
             "transition_energy": r[4], "energy_type": r[5]}
            for r in self.db.execute(f"SELECT {cols} FROM edges WHERE source = ?", (node_name,)).fetchall()
        ]

    def get_inbound_edges(self, node_name: str) -> list[dict]:
        cols = "name, type, source, target, transition_energy, energy_type"
        return [
            {"name": r[0], "type": r[1], "source": r[2], "target": r[3],
             "transition_energy": r[4], "energy_type": r[5]}
            for r in self.db.execute(f"SELECT {cols} FROM edges WHERE target = ?", (node_name,)).fetchall()
        ]

    def entry_points(self, threshold: float = 2.0, limit: int = 30) -> list[dict]:
        rows = self.db.execute(
            "SELECT name, type, semantic_context, metadata, entry_energy, energy_type "
            "FROM nodes WHERE entry_energy IS NOT NULL AND entry_energy <= ? "
            "ORDER BY entry_energy LIMIT ?",
            (threshold, limit),
        ).fetchall()
        return [self._node_from_row(r) for r in rows]

    def node_type_distribution(self) -> dict[str, int]:
        return {
            r[0]: r[1]
            for r in self.db.execute("SELECT type, COUNT(*) FROM nodes GROUP BY type ORDER BY type").fetchall()
        }

    def edge_type_distribution(self) -> dict[str, int]:
        return {
            r[0]: r[1]
            for r in self.db.execute("SELECT type, COUNT(*) FROM edges GROUP BY type ORDER BY type").fetchall()
        }

    def resolve_node(self, query: str) -> str | None:
        """Resolve a query to an exact node name. Tries exact match, then substring."""
        if self.db.execute("SELECT 1 FROM nodes WHERE name = ?", (query,)).fetchone():
            return query
        row = self.db.execute(
            "SELECT name FROM nodes WHERE name LIKE ? COLLATE NOCASE LIMIT 1",
            (f"%{query}%",),
        ).fetchone()
        if row:
            return row[0]
        # Try semantic context
        row = self.db.execute(
            "SELECT name FROM nodes WHERE semantic_context LIKE ? COLLATE NOCASE LIMIT 1",
            (f"%{query}%",),
        ).fetchone()
        return row[0] if row else None

    # ------------------------------------------------------------------
    # Row helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _node_from_row(row: tuple) -> dict:
        ctx = row[2]
        return {
            "name": row[0],
            "type": row[1],
            "semantic_context": json.loads(ctx) if ctx else [],
            "metadata": json.loads(row[3]) if row[3] else {},
            "entry_energy": row[4],
            "energy_type": row[5],
        }

    @staticmethod
    def _edge_from_row(row: tuple) -> dict:
        ctx = row[4] if len(row) > 4 else None
        return {
            "name": row[0],
            "type": row[1],
            "source": row[2],
            "target": row[3],
            "semantic_context": json.loads(ctx) if ctx else [],
            "metadata": json.loads(row[5]) if len(row) > 5 and row[5] else {},
            "transition_energy": row[6] if len(row) > 6 else None,
            "energy_type": row[7] if len(row) > 7 else None,
        }
