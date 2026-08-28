"""Findings store — SQLite-backed findings management for the triage pipeline.

Replaces structured-output-based claiming with MCP tool calls.  Findings,
groups, and investigation results live in a per-project SQLite database so
agents can query, claim, and update state via tool calls instead of
outputting arrays of integer indices.

The database file lives at ``~/.latent-defense/triage-state/findings-<project_id>.db``.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any

log = logging.getLogger("latent-defense-mcp")


def _state_dir() -> Path:
    return Path(
        os.environ.get(
            "TRIAGE_STATE_DIR",
            Path.home() / ".latent-defense" / "triage-state",
        )
    )


def _safe_id(name: str) -> str:
    name = name.replace("/", "").replace("\\", "").replace("..", "").replace("\0", "")
    name = re.sub(r"[^a-zA-Z0-9._-]", "-", name)
    if not name or name.strip(".") == "":
        name = "unnamed"
    return name[:200]


def _dt_now() -> str:
    return datetime.now().isoformat()


# ---------------------------------------------------------------------------
# Store class
# ---------------------------------------------------------------------------

class FindingsStore:
    """SQLite-backed findings, groups, and investigations for one project."""

    def __init__(self, project_id: str) -> None:
        self.project_id = project_id
        d = _state_dir()
        d.mkdir(parents=True, exist_ok=True)
        db_path = d / f"findings-{_safe_id(project_id)}.db"
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._create_tables()

    def _create_tables(self) -> None:
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                idx             INTEGER PRIMARY KEY,
                id              TEXT,
                title           TEXT,
                severity        TEXT,
                category        TEXT,
                scanner         TEXT,
                source_file     TEXT,
                repo            TEXT,
                resource        TEXT,
                data            TEXT,
                group_id        TEXT,
                claimed_at      TEXT
            );
            CREATE TABLE IF NOT EXISTS finding_groups (
                group_id        TEXT PRIMARY KEY,
                description     TEXT,
                resolution      TEXT,
                status          TEXT DEFAULT 'open',
                anchor_node     TEXT,
                action          TEXT,
                evidence        TEXT,
                primary_audience TEXT,
                data            TEXT
            );
            CREATE TABLE IF NOT EXISTS investigations (
                group_id        TEXT PRIMARY KEY,
                explore_result  TEXT,
                verdict         TEXT,
                evidence        TEXT,
                graph_corrections TEXT,
                investigated_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_group ON findings(group_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_findings_scanner ON findings(scanner);
            CREATE INDEX IF NOT EXISTS idx_findings_repo ON findings(repo);
            CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category);
        """)

    @property
    def db(self) -> sqlite3.Connection:
        return self._db

    def close(self) -> None:
        self._db.close()


# ---------------------------------------------------------------------------
# Module-level store cache (one per project_id)
# ---------------------------------------------------------------------------

_stores: dict[str, FindingsStore] = {}


def _get_store(project_id: str) -> FindingsStore:
    if project_id not in _stores:
        _stores[project_id] = FindingsStore(project_id)
    return _stores[project_id]


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------

def register(mcp: Any) -> None:
    """Register findings store tools on *mcp*."""

    # ------------------------------------------------------------------
    # Load
    # ------------------------------------------------------------------

    @mcp.tool()
    async def load_findings(project_id: str, path: str) -> str:
        """Load findings from a JSON array file into the queryable store.

        Parses each finding, extracts searchable fields into indexed columns,
        and keeps the full JSON in the data column.  Replaces any previously
        loaded findings for this project.

        Args:
            project_id: Project identifier (matches triage project ID).
            path: Absolute path to a JSON file containing an array of findings.
        """
        p = Path(path).expanduser()
        if not p.exists():
            return json.dumps({"error": f"File not found: {path}"})

        store = _get_store(project_id)
        db = store.db

        # Preserve existing claims before clearing — if findings are reloaded
        # (e.g., after a rescan or MCP restart), we restore the group_id mappings
        # so triage work isn't lost.
        prior_claims: dict[int, tuple[str, str]] = {}
        try:
            for row in db.execute(
                "SELECT idx, group_id, claimed_at FROM findings WHERE group_id IS NOT NULL"
            ).fetchall():
                prior_claims[row[0]] = (row[1], row[2])
        except Exception:
            pass  # table may not exist yet on first load

        # Clear existing findings only — groups and investigations are preserved
        db.execute("DELETE FROM findings")
        db.commit()

        with open(p) as f:
            findings = json.load(f)

        if not isinstance(findings, list):
            return json.dumps({"error": "Expected a JSON array of findings"})

        batch: list[tuple] = []
        scanner_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for idx, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue

            # Extract searchable fields — stringify any non-scalar values
            def _str(val: Any) -> str:
                if val is None:
                    return ""
                if isinstance(val, dict):
                    return val.get("value", val.get("name", val.get("identifier", json.dumps(val))))
                if isinstance(val, list):
                    return json.dumps(val)
                return str(val)

            fid = _str(finding.get("id", ""))
            title = _str(finding.get("title", finding.get("name", "")))
            severity = _str(finding.get("severity") or "").lower()
            category = _str(finding.get("category", finding.get("type", "")))
            scanner = _str(finding.get("scanner", finding.get("source", finding.get("_scanner", ""))))
            source_file = _str(finding.get("_source_file", finding.get("source_file", "")))
            repo = _str(finding.get("repo", finding.get("repository", finding.get("package", ""))))
            resource = _str(finding.get("resource", finding.get("affected_resource", finding.get("target", ""))))

            batch.append((
                idx, fid, title, severity, category, scanner,
                source_file, repo, resource, json.dumps(finding),
            ))

            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if len(batch) >= 1000:
                db.executemany(
                    "INSERT OR REPLACE INTO findings "
                    "(idx, id, title, severity, category, scanner, source_file, repo, resource, data) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    batch,
                )
                batch.clear()

        if batch:
            db.executemany(
                "INSERT OR REPLACE INTO findings "
                "(idx, id, title, severity, category, scanner, source_file, repo, resource, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
        db.commit()

        total = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

        # Restore prior claims — findings at the same indices get their group_id back
        restored = 0
        if prior_claims:
            for idx, (group_id, claimed_at) in prior_claims.items():
                # Only restore if the index still exists and the group still exists
                exists = db.execute("SELECT 1 FROM findings WHERE idx = ?", (idx,)).fetchone()
                group_exists = db.execute(
                    "SELECT 1 FROM finding_groups WHERE group_id = ?", (group_id,)
                ).fetchone()
                if exists and group_exists:
                    db.execute(
                        "UPDATE findings SET group_id = ?, claimed_at = ? WHERE idx = ?",
                        (group_id, claimed_at, idx),
                    )
                    restored += 1
            db.commit()

        log.info("Loaded %d findings for project %s (restored %d prior claims)", total, project_id, restored)

        # Top scanners and severities for the summary
        top_scanners = sorted(scanner_counts.items(), key=lambda x: -x[1])[:10]
        top_severities = sorted(severity_counts.items(), key=lambda x: -x[1])

        claimed_count = db.execute("SELECT COUNT(*) FROM findings WHERE group_id IS NOT NULL").fetchone()[0]

        result: dict[str, Any] = {
            "status": "loaded",
            "project_id": project_id,
            "total_findings": total,
            "by_severity": dict(top_severities),
            "by_scanner": dict(top_scanners),
        }
        if restored > 0:
            result["restored_claims"] = restored
            result["claimed"] = claimed_count
            result["unclaimed"] = total - claimed_count
        return json.dumps(result)

    @mcp.tool()
    async def append_findings(project_id: str, path: str) -> str:
        """Append new findings to an existing store without destroying claims or groups.

        New findings are assigned indices starting after the current max index.
        Existing findings, claims, groups, and investigations are untouched.
        Use this for iterative triage — add new scanner results or investigation
        findings without resetting the pipeline.

        Args:
            project_id: Project identifier (matches triage project ID).
            path: Absolute path to a JSON file containing an array of findings.
        """
        p = Path(path).expanduser()
        if not p.exists():
            return json.dumps({"error": f"File not found: {path}"})

        store = _get_store(project_id)
        db = store.db

        # Start indices after current max
        row = db.execute("SELECT MAX(idx) FROM findings").fetchone()
        start_idx = (row[0] + 1) if row[0] is not None else 0

        with open(p) as f:
            findings = json.load(f)

        if not isinstance(findings, list):
            return json.dumps({"error": "Expected a JSON array of findings"})

        batch: list[tuple] = []
        scanner_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}

        for i, finding in enumerate(findings):
            if not isinstance(finding, dict):
                continue

            idx = start_idx + i

            def _str(val: Any) -> str:
                if val is None:
                    return ""
                if isinstance(val, dict):
                    return val.get("value", val.get("name", val.get("identifier", json.dumps(val))))
                if isinstance(val, list):
                    return json.dumps(val)
                return str(val)

            fid = _str(finding.get("id", ""))
            title = _str(finding.get("title", finding.get("name", "")))
            severity = _str(finding.get("severity") or "").lower()
            category = _str(finding.get("category", finding.get("type", "")))
            scanner = _str(finding.get("scanner", finding.get("source", finding.get("_scanner", ""))))
            source_file = _str(finding.get("_source_file", finding.get("source_file", "")))
            repo = _str(finding.get("repo", finding.get("repository", finding.get("package", ""))))
            resource = _str(finding.get("resource", finding.get("affected_resource", finding.get("target", ""))))

            batch.append((
                idx, fid, title, severity, category, scanner,
                source_file, repo, resource, json.dumps(finding),
            ))

            scanner_counts[scanner] = scanner_counts.get(scanner, 0) + 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if len(batch) >= 1000:
                db.executemany(
                    "INSERT OR REPLACE INTO findings "
                    "(idx, id, title, severity, category, scanner, source_file, repo, resource, data) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    batch,
                )
                batch.clear()

        if batch:
            db.executemany(
                "INSERT OR REPLACE INTO findings "
                "(idx, id, title, severity, category, scanner, source_file, repo, resource, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                batch,
            )
        db.commit()

        appended = len(findings)
        total = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        claimed = db.execute("SELECT COUNT(*) FROM findings WHERE group_id IS NOT NULL").fetchone()[0]

        return json.dumps({
            "status": "appended",
            "project_id": project_id,
            "appended": appended,
            "start_idx": start_idx,
            "total_findings": total,
            "claimed": claimed,
            "unclaimed": total - claimed,
            "by_severity": dict(sorted(severity_counts.items(), key=lambda x: -x[1])),
            "by_scanner": dict(sorted(scanner_counts.items(), key=lambda x: -x[1])[:10]),
        })

    # ------------------------------------------------------------------
    # Query
    # ------------------------------------------------------------------

    @mcp.tool()
    async def query_findings(
        project_id: str,
        scanner: str = "",
        severity: str = "",
        category: str = "",
        repo: str = "",
        keyword: str = "",
        unclaimed_only: bool = False,
        group_id: str = "",
        limit: int = 50,
    ) -> str:
        """Search findings with filters. Returns summary rows — use get_finding for full data.

        Args:
            project_id: Project identifier.
            scanner: Filter by scanner name (substring match).
            severity: Filter by severity (exact match: critical, high, medium, low).
            category: Filter by category (substring match).
            repo: Filter by repo/package name (substring match).
            keyword: Search across title, id, and resource (substring match).
            unclaimed_only: Only return unclaimed findings (group_id IS NULL).
            group_id: Only return findings claimed by this group.
            limit: Maximum results (default 50, max 500).
        """
        store = _get_store(project_id)
        db = store.db

        conditions: list[str] = []
        params: list[Any] = []

        if scanner:
            conditions.append("scanner LIKE ? COLLATE NOCASE")
            params.append(f"%{scanner}%")
        if severity:
            conditions.append("severity = ? COLLATE NOCASE")
            params.append(severity.lower())
        if category:
            conditions.append("category LIKE ? COLLATE NOCASE")
            params.append(f"%{category}%")
        if repo:
            conditions.append("repo LIKE ? COLLATE NOCASE")
            params.append(f"%{repo}%")
        if keyword:
            conditions.append(
                "(title LIKE ? COLLATE NOCASE OR id LIKE ? COLLATE NOCASE OR resource LIKE ? COLLATE NOCASE)"
            )
            params.extend([f"%{keyword}%"] * 3)
        if unclaimed_only:
            conditions.append("group_id IS NULL")
        if group_id:
            conditions.append("group_id = ?")
            params.append(group_id)

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        limit = min(limit, 500)
        params.append(limit)

        rows = db.execute(
            f"SELECT idx, id, title, severity, scanner, repo, resource, group_id "
            f"FROM findings {where} ORDER BY idx LIMIT ?",
            params,
        ).fetchall()

        total_match = db.execute(
            f"SELECT COUNT(*) FROM findings {where}",
            params[:-1],  # no limit
        ).fetchone()[0]

        findings = [
            {
                "idx": r[0], "id": r[1], "title": r[2], "severity": r[3],
                "scanner": r[4], "repo": r[5], "resource": r[6], "group_id": r[7],
            }
            for r in rows
        ]

        return json.dumps({
            "total_matching": total_match,
            "returned": len(findings),
            "findings": findings,
        })

    @mcp.tool()
    async def get_finding(project_id: str, idx: int) -> str:
        """Read one finding in full by its index.

        Args:
            project_id: Project identifier.
            idx: Finding index (0-based, from load_findings).
        """
        store = _get_store(project_id)
        row = store.db.execute(
            "SELECT data, group_id, claimed_at FROM findings WHERE idx = ?",
            (idx,),
        ).fetchone()
        if row is None:
            return json.dumps({"error": f"Finding {idx} not found"})

        finding = json.loads(row[0])
        finding["_group_id"] = row[1]
        finding["_claimed_at"] = row[2]
        return json.dumps(finding)

    @mcp.tool()
    async def findings_stats(project_id: str) -> str:
        """Get finding counts: total, claimed, unclaimed, by scanner, severity, and group.

        Args:
            project_id: Project identifier.
        """
        store = _get_store(project_id)
        db = store.db

        total = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        if total == 0:
            return json.dumps({"error": "No findings loaded. Call load_findings first."})

        claimed = db.execute("SELECT COUNT(*) FROM findings WHERE group_id IS NOT NULL").fetchone()[0]
        unclaimed = total - claimed

        by_severity = {
            r[0]: r[1]
            for r in db.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity ORDER BY COUNT(*) DESC"
            ).fetchall()
        }

        by_scanner = {
            r[0]: r[1]
            for r in db.execute(
                "SELECT scanner, COUNT(*) FROM findings GROUP BY scanner ORDER BY COUNT(*) DESC LIMIT 15"
            ).fetchall()
        }

        by_group = {
            r[0] or "(unclaimed)": r[1]
            for r in db.execute(
                "SELECT group_id, COUNT(*) FROM findings GROUP BY group_id ORDER BY COUNT(*) DESC LIMIT 30"
            ).fetchall()
        }

        groups_total = db.execute("SELECT COUNT(*) FROM finding_groups").fetchone()[0]
        investigations_done = db.execute(
            "SELECT COUNT(*) FROM investigations WHERE verdict IS NOT NULL"
        ).fetchone()[0]

        return json.dumps({
            "project_id": project_id,
            "total": total,
            "claimed": claimed,
            "unclaimed": unclaimed,
            "claim_pct": round(100 * claimed / total, 1) if total > 0 else 0,
            "by_severity": by_severity,
            "by_scanner": by_scanner,
            "by_group": by_group,
            "groups_total": groups_total,
            "investigations_done": investigations_done,
        })

    # ------------------------------------------------------------------
    # Claim
    # ------------------------------------------------------------------

    @mcp.tool()
    async def claim_findings(project_id: str, group_id: str, indices: str) -> str:
        """Claim specific findings for a group by their indices.

        Fails if any finding is already claimed by a different group.

        Args:
            project_id: Project identifier.
            group_id: Group to claim findings for (must exist via create_group).
            indices: Comma-separated list of finding indices (e.g. "0,3,7,12").
        """
        store = _get_store(project_id)
        db = store.db

        # Parse indices
        try:
            idx_list = [int(x.strip()) for x in indices.split(",") if x.strip()]
        except ValueError:
            return json.dumps({"error": "indices must be comma-separated integers"})

        # Check group exists
        if not db.execute("SELECT 1 FROM finding_groups WHERE group_id = ?", (group_id,)).fetchone():
            return json.dumps({"error": f"Group '{group_id}' not found. Call create_group first."})

        # Check for conflicts
        conflicts = []
        for idx in idx_list:
            row = db.execute(
                "SELECT group_id FROM findings WHERE idx = ? AND group_id IS NOT NULL AND group_id != ?",
                (idx, group_id),
            ).fetchone()
            if row:
                conflicts.append({"idx": idx, "claimed_by": row[0]})

        if conflicts:
            return json.dumps({
                "error": f"{len(conflicts)} findings already claimed by other groups",
                "conflicts": conflicts[:10],
            })

        # Claim
        now = _dt_now()
        db.executemany(
            "UPDATE findings SET group_id = ?, claimed_at = ? WHERE idx = ? AND (group_id IS NULL OR group_id = ?)",
            [(group_id, now, idx, group_id) for idx in idx_list],
        )
        db.commit()

        actually_claimed = db.execute(
            "SELECT COUNT(*) FROM findings WHERE group_id = ?", (group_id,)
        ).fetchone()[0]

        return json.dumps({
            "claimed": len(idx_list),
            "group_id": group_id,
            "group_total": actually_claimed,
        })

    @mcp.tool()
    async def claim_findings_range(
        project_id: str,
        group_id: str,
        start: int,
        end: int,
        dry_run: bool = True,
    ) -> str:
        """Claim a contiguous range of findings [start, end] inclusive.

        Default is dry_run=true — shows what would be claimed without changing anything.
        Set dry_run=false to actually claim.

        Args:
            project_id: Project identifier.
            group_id: Group to claim findings for.
            start: Start index (inclusive).
            end: End index (inclusive).
            dry_run: Preview mode (default true). Set to false to actually claim.
        """
        store = _get_store(project_id)
        db = store.db

        if not db.execute("SELECT 1 FROM finding_groups WHERE group_id = ?", (group_id,)).fetchone():
            return json.dumps({"error": f"Group '{group_id}' not found. Call create_group first."})

        # Preview
        unclaimed_count = db.execute(
            "SELECT COUNT(*) FROM findings WHERE idx BETWEEN ? AND ? AND group_id IS NULL",
            (start, end),
        ).fetchone()[0]

        already_this_group = db.execute(
            "SELECT COUNT(*) FROM findings WHERE idx BETWEEN ? AND ? AND group_id = ?",
            (start, end, group_id),
        ).fetchone()[0]

        conflicts = db.execute(
            "SELECT COUNT(*) FROM findings WHERE idx BETWEEN ? AND ? AND group_id IS NOT NULL AND group_id != ?",
            (start, end, group_id),
        ).fetchone()[0]

        total_in_range = db.execute(
            "SELECT COUNT(*) FROM findings WHERE idx BETWEEN ? AND ?",
            (start, end),
        ).fetchone()[0]

        # Sample for preview
        sample = db.execute(
            "SELECT idx, id, title, severity, scanner FROM findings "
            "WHERE idx BETWEEN ? AND ? AND group_id IS NULL LIMIT 10",
            (start, end),
        ).fetchall()
        sample_list = [
            {"idx": r[0], "id": r[1], "title": r[2], "severity": r[3], "scanner": r[4]}
            for r in sample
        ]

        if dry_run:
            return json.dumps({
                "dry_run": True,
                "range": f"[{start}, {end}]",
                "total_in_range": total_in_range,
                "would_claim": unclaimed_count,
                "already_in_group": already_this_group,
                "conflicts": conflicts,
                "sample": sample_list,
                "action": "Call again with dry_run=false to claim.",
            })

        if conflicts > 0:
            return json.dumps({
                "error": f"{conflicts} findings in range already claimed by other groups",
                "hint": "Use query_findings to see which groups claimed them.",
            })

        now = _dt_now()
        db.execute(
            "UPDATE findings SET group_id = ?, claimed_at = ? "
            "WHERE idx BETWEEN ? AND ? AND group_id IS NULL",
            (group_id, now, start, end),
        )
        db.commit()

        actual = db.execute(
            "SELECT COUNT(*) FROM findings WHERE group_id = ?", (group_id,)
        ).fetchone()[0]

        return json.dumps({
            "dry_run": False,
            "claimed": unclaimed_count,
            "group_id": group_id,
            "group_total": actual,
        })

    @mcp.tool()
    async def claim_findings_by_query(
        project_id: str,
        group_id: str,
        scanner: str = "",
        severity: str = "",
        keyword: str = "",
        repo: str = "",
        category: str = "",
        dry_run: bool = True,
    ) -> str:
        """Claim all unclaimed findings matching a query.

        Default is dry_run=true — shows what would be claimed with a sample
        of the first 10 findings.  Set dry_run=false to actually claim.

        Args:
            project_id: Project identifier.
            group_id: Group to claim findings for.
            scanner: Filter by scanner (substring match).
            severity: Filter by severity (exact: critical, high, medium, low).
            keyword: Search across title, id, and resource.
            repo: Filter by repo/package name.
            category: Filter by category.
            dry_run: Preview mode (default true). Set to false to actually claim.
        """
        store = _get_store(project_id)
        db = store.db

        if not db.execute("SELECT 1 FROM finding_groups WHERE group_id = ?", (group_id,)).fetchone():
            return json.dumps({"error": f"Group '{group_id}' not found. Call create_group first."})

        # Match unclaimed OR already claimed by the same group (idempotent on resume)
        conditions = [f"(group_id IS NULL OR group_id = ?)"]
        params: list[Any] = [group_id]

        if scanner:
            conditions.append("scanner LIKE ? COLLATE NOCASE")
            params.append(f"%{scanner}%")
        if severity:
            conditions.append("severity = ? COLLATE NOCASE")
            params.append(severity.lower())
        if keyword:
            conditions.append(
                "(title LIKE ? COLLATE NOCASE OR id LIKE ? COLLATE NOCASE OR resource LIKE ? COLLATE NOCASE)"
            )
            params.extend([f"%{keyword}%"] * 3)
        if repo:
            conditions.append("repo LIKE ? COLLATE NOCASE")
            params.append(f"%{repo}%")
        if category:
            conditions.append("category LIKE ? COLLATE NOCASE")
            params.append(f"%{category}%")

        where = f"WHERE {' AND '.join(conditions)}"

        match_count = db.execute(f"SELECT COUNT(*) FROM findings {where}", params).fetchone()[0]

        # Break down: how many are unclaimed vs already ours (idempotent resume)
        # Build a WHERE for just unclaimed matches
        unclaimed_conditions = [c for c in conditions]
        unclaimed_conditions[0] = "group_id IS NULL"  # replace the OR condition
        unclaimed_where = f"WHERE {' AND '.join(unclaimed_conditions)}"
        unclaimed_params = params[1:]  # remove the group_id param from position 0
        new_claim_count = db.execute(
            f"SELECT COUNT(*) FROM findings {unclaimed_where}", unclaimed_params
        ).fetchone()[0]
        already_ours = match_count - new_claim_count

        sample = db.execute(
            f"SELECT idx, id, title, severity, scanner, repo FROM findings {where} LIMIT 10",
            params,
        ).fetchall()
        sample_list = [
            {"idx": r[0], "id": r[1], "title": r[2], "severity": r[3], "scanner": r[4], "repo": r[5]}
            for r in sample
        ]

        if dry_run:
            return json.dumps({
                "dry_run": True,
                "would_claim": new_claim_count,
                "already_in_group": already_ours,
                "total_matching": match_count,
                "group_id": group_id,
                "query": {k: v for k, v in [("scanner", scanner), ("severity", severity), ("keyword", keyword), ("repo", repo), ("category", category)] if v},
                "sample": sample_list,
                "action": (
                    "Call again with dry_run=false to claim."
                    if new_claim_count > 0
                    else (f"All {already_ours} matching findings already claimed by this group."
                          if already_ours > 0
                          else "No matching findings.")
                ),
            })

        if new_claim_count == 0 and already_ours > 0:
            # Idempotent: everything is already claimed by this group
            return json.dumps({
                "claimed": 0, "already_in_group": already_ours,
                "group_id": group_id, "group_total": already_ours,
                "message": "All matching findings already claimed by this group.",
            })
        if match_count == 0:
            return json.dumps({"claimed": 0, "group_id": group_id, "message": "No matching findings."})

        now = _dt_now()
        # Only claim unclaimed findings (don't re-stamp already-ours)
        db.execute(
            f"UPDATE findings SET group_id = ?, claimed_at = ? {unclaimed_where}",
            [group_id, now] + unclaimed_params,
        )
        db.commit()

        actual = db.execute(
            "SELECT COUNT(*) FROM findings WHERE group_id = ?", (group_id,)
        ).fetchone()[0]

        return json.dumps({
            "dry_run": False,
            "claimed": new_claim_count,
            "already_in_group": already_ours,
            "group_id": group_id,
            "group_total": actual,
        })

    @mcp.tool()
    async def unclaim_findings(project_id: str, indices: str) -> str:
        """Release findings back to unclaimed.

        Args:
            project_id: Project identifier.
            indices: Comma-separated list of finding indices to unclaim.
        """
        store = _get_store(project_id)
        db = store.db

        try:
            idx_list = [int(x.strip()) for x in indices.split(",") if x.strip()]
        except ValueError:
            return json.dumps({"error": "indices must be comma-separated integers"})

        db.executemany(
            "UPDATE findings SET group_id = NULL, claimed_at = NULL WHERE idx = ?",
            [(idx,) for idx in idx_list],
        )
        db.commit()

        return json.dumps({"unclaimed": len(idx_list)})

    # ------------------------------------------------------------------
    # Groups
    # ------------------------------------------------------------------

    @mcp.tool()
    async def create_group(
        project_id: str,
        group_id: str,
        description: str,
        anchor_node: str = "",
    ) -> str:
        """Create a finding group.  Groups represent remediation actions.

        Args:
            project_id: Project identifier.
            group_id: Unique identifier for this group (e.g. "base-image-rebuild").
            description: What this group's remediation action is.
            anchor_node: Optional graph node this group maps to.
        """
        store = _get_store(project_id)
        db = store.db

        # Idempotent: if group already exists, return success (enables safe resume).
        # On resume, Discover may re-create groups that already exist — that's fine.
        existing = db.execute(
            "SELECT description FROM finding_groups WHERE group_id = ?", (group_id,)
        ).fetchone()
        if existing:
            finding_count = db.execute(
                "SELECT COUNT(*) FROM findings WHERE group_id = ?", (group_id,)
            ).fetchone()[0]
            return json.dumps({
                "created": group_id,
                "description": existing[0],
                "already_existed": True,
                "finding_count": finding_count,
            })

        db.execute(
            "INSERT INTO finding_groups (group_id, description, anchor_node, status) "
            "VALUES (?, ?, ?, 'open')",
            (group_id, description, anchor_node or None),
        )
        db.commit()

        return json.dumps({
            "created": group_id,
            "description": description,
            "anchor_node": anchor_node or None,
        })

    @mcp.tool()
    async def update_group(
        project_id: str,
        group_id: str,
        description: str = "",
        resolution: str = "",
        status: str = "",
        anchor_node: str = "",
        action: str = "",
        evidence: str = "",
        primary_audience: str = "",
        data: str = "",
    ) -> str:
        """Update a finding group. Only provided fields are changed.

        Args:
            project_id: Project identifier.
            group_id: Group to update.
            description: Group description (what remediation action this represents).
            resolution: Resolution category (eliminable/reducible/constrained/drift_prone/mitigated).
            status: Group status (open/investigating/investigated/routed/delivered).
            anchor_node: Graph node this group maps to.
            action: Remediation action description.
            evidence: Investigation evidence.
            primary_audience: Who should act on this (engineering/security/platform/product).
            data: Extra JSON data to store on the group.
        """
        store = _get_store(project_id)
        db = store.db

        if not db.execute("SELECT 1 FROM finding_groups WHERE group_id = ?", (group_id,)).fetchone():
            return json.dumps({"error": f"Group '{group_id}' not found"})

        updates: list[str] = []
        params: list[Any] = []
        for field, val in [
            ("description", description), ("resolution", resolution), ("status", status),
            ("anchor_node", anchor_node), ("action", action), ("evidence", evidence),
            ("primary_audience", primary_audience), ("data", data),
        ]:
            if val:
                updates.append(f"{field} = ?")
                params.append(val)

        if not updates:
            return json.dumps({"error": "No fields to update"})

        params.append(group_id)
        db.execute(
            f"UPDATE finding_groups SET {', '.join(updates)} WHERE group_id = ?",
            params,
        )
        db.commit()

        return json.dumps({"updated": group_id, "fields": [u.split(" =")[0] for u in updates]})

    @mcp.tool()
    async def list_groups(project_id: str, status: str = "") -> str:
        """List all finding groups with claimed finding counts.

        Args:
            project_id: Project identifier.
            status: Optional filter by status (open/investigating/investigated/routed/delivered).
        """
        store = _get_store(project_id)
        db = store.db

        if status:
            rows = db.execute(
                "SELECT g.group_id, g.description, g.resolution, g.status, g.anchor_node, "
                "g.action, g.primary_audience, "
                "(SELECT COUNT(*) FROM findings f WHERE f.group_id = g.group_id) as finding_count "
                "FROM finding_groups g WHERE g.status = ? ORDER BY g.group_id",
                (status,),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT g.group_id, g.description, g.resolution, g.status, g.anchor_node, "
                "g.action, g.primary_audience, "
                "(SELECT COUNT(*) FROM findings f WHERE f.group_id = g.group_id) as finding_count "
                "FROM finding_groups g ORDER BY g.group_id",
            ).fetchall()

        groups = [
            {
                "group_id": r[0], "description": r[1], "resolution": r[2],
                "status": r[3], "anchor_node": r[4], "action": r[5],
                "primary_audience": r[6], "finding_count": r[7],
            }
            for r in rows
        ]

        return json.dumps({"groups": groups, "count": len(groups)})

    # ------------------------------------------------------------------
    # Investigations
    # ------------------------------------------------------------------

    @mcp.tool()
    async def save_investigation(
        project_id: str,
        group_id: str,
        explore_result: str = "",
        verdict: str = "",
        evidence: str = "",
        graph_corrections: str = "",
    ) -> str:
        """Save or update investigation results for a group.

        Call after energy exploration (with explore_result) and again after
        verification (with verdict + evidence).

        Args:
            project_id: Project identifier.
            group_id: Group being investigated.
            explore_result: JSON string of energy exploration results.
            verdict: confirmed/refuted/partial.
            evidence: Verification evidence (from code/config/cloud, not graph).
            graph_corrections: JSON array of graph corrections made during investigation.
        """
        store = _get_store(project_id)
        db = store.db

        existing = db.execute(
            "SELECT explore_result, verdict, evidence, graph_corrections "
            "FROM investigations WHERE group_id = ?",
            (group_id,),
        ).fetchone()

        if existing:
            # Merge — only update provided fields
            updates: list[str] = []
            params: list[Any] = []
            if explore_result:
                updates.append("explore_result = ?")
                params.append(explore_result)
            if verdict:
                updates.append("verdict = ?")
                params.append(verdict)
            if evidence:
                updates.append("evidence = ?")
                params.append(evidence)
            if graph_corrections:
                updates.append("graph_corrections = ?")
                params.append(graph_corrections)
            updates.append("investigated_at = ?")
            params.append(_dt_now())
            params.append(group_id)
            db.execute(
                f"UPDATE investigations SET {', '.join(updates)} WHERE group_id = ?",
                params,
            )
        else:
            db.execute(
                "INSERT INTO investigations (group_id, explore_result, verdict, evidence, graph_corrections, investigated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (group_id, explore_result or None, verdict or None, evidence or None,
                 graph_corrections or None, _dt_now()),
            )

        # Also update group status if verdict is provided
        if verdict:
            db.execute(
                "UPDATE finding_groups SET status = 'investigated' WHERE group_id = ?",
                (group_id,),
            )

        db.commit()

        return json.dumps({
            "saved": group_id,
            "has_explore": bool(explore_result or (existing and existing[0])),
            "has_verdict": bool(verdict or (existing and existing[1])),
        })

    @mcp.tool()
    async def get_investigation(project_id: str, group_id: str) -> str:
        """Read investigation results for a group.

        Args:
            project_id: Project identifier.
            group_id: Group to read investigation for.
        """
        store = _get_store(project_id)
        db = store.db

        row = db.execute(
            "SELECT explore_result, verdict, evidence, graph_corrections, investigated_at "
            "FROM investigations WHERE group_id = ?",
            (group_id,),
        ).fetchone()

        if row is None:
            return json.dumps({"error": f"No investigation found for group '{group_id}'"})

        result: dict[str, Any] = {"group_id": group_id, "investigated_at": row[4]}
        if row[0]:
            try:
                result["explore_result"] = json.loads(row[0])
            except json.JSONDecodeError:
                result["explore_result"] = row[0]
        if row[1]:
            result["verdict"] = row[1]
        if row[2]:
            result["evidence"] = row[2]
        if row[3]:
            try:
                result["graph_corrections"] = json.loads(row[3])
            except json.JSONDecodeError:
                result["graph_corrections"] = row[3]

        return json.dumps(result)

    @mcp.tool()
    async def pipeline_status(project_id: str) -> str:
        """Get triage pipeline progress — what's done, what's pending.

        Returns phase completion status derived from the findings store:
        which phases are complete, which groups need work, and what
        the next action should be.  Use this to resume after a crash,
        rate limit, or session boundary.

        Args:
            project_id: Project identifier.
        """
        store = _get_store(project_id)
        db = store.db

        total = db.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        claimed = db.execute(
            "SELECT COUNT(*) FROM findings WHERE group_id IS NOT NULL"
        ).fetchone()[0]
        groups_total = db.execute(
            "SELECT COUNT(*) FROM finding_groups"
        ).fetchone()[0]

        # Group status breakdown
        status_counts: dict[str, int] = {}
        for r in db.execute(
            "SELECT status, COUNT(*) FROM finding_groups GROUP BY status"
        ).fetchall():
            status_counts[r[0] or "open"] = r[1]

        investigated = db.execute(
            "SELECT COUNT(*) FROM investigations WHERE verdict IS NOT NULL"
        ).fetchone()[0]
        explored_only = db.execute(
            "SELECT COUNT(*) FROM investigations "
            "WHERE explore_result IS NOT NULL AND verdict IS NULL"
        ).fetchone()[0]

        # Derive phase completion
        phases: dict[str, str] = {}
        phases["load"] = "complete" if total > 0 else "pending"
        phases["discover"] = "complete" if groups_total > 0 else "pending"
        phases["group"] = (
            "complete" if total > 0 and claimed == total
            else "partial" if claimed > 0
            else "pending"
        )
        phases["sweep"] = (
            "complete" if total > 0 and claimed == total else "pending"
        )
        phases["investigate"] = (
            "complete" if investigated == groups_total and groups_total > 0
            else "partial" if investigated > 0 or explored_only > 0
            else "pending"
        )
        routed_or_done = (
            status_counts.get("routed", 0)
            + status_counts.get("investigated", 0)
            + status_counts.get("delivered", 0)
        )
        phases["route"] = (
            "complete" if routed_or_done == groups_total and groups_total > 0
            else "pending"
        )
        phases["deliver"] = (
            "complete"
            if status_counts.get("delivered", 0) == groups_total
            and groups_total > 0
            else "pending"
        )

        # Pending group details
        pending_investigate = groups_total - investigated
        open_groups = status_counts.get("open", 0)
        investigating_groups = status_counts.get("investigating", 0)

        # What's next?
        if phases["load"] == "pending":
            next_action = "Call load_findings to load the findings file"
        elif phases["discover"] == "pending":
            next_action = "Create remediation groups (run Discover phase)"
        elif phases["group"] != "complete":
            unclaimed = total - claimed
            next_action = (
                f"Claim {unclaimed} unclaimed findings into groups "
                f"(run Group/Sweep phase)"
            )
        elif phases["investigate"] != "complete":
            next_action = (
                f"Investigate {pending_investigate} remaining groups "
                f"({explored_only} have explore results awaiting verify, "
                f"{open_groups} not started)"
            )
        elif phases["route"] != "complete":
            next_action = "Route uninvestigated groups"
        elif phases["deliver"] != "complete":
            next_action = "Generate audience reports (run Deliver phase)"
        else:
            next_action = "Pipeline complete — all phases done"

        return json.dumps({
            "project_id": project_id,
            "total_findings": total,
            "claimed": claimed,
            "unclaimed": total - claimed,
            "groups": groups_total,
            "investigated": investigated,
            "explored_only": explored_only,
            "pending_investigate": pending_investigate,
            "group_status": status_counts,
            "phases": phases,
            "next_action": next_action,
        })
