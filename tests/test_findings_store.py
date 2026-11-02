"""Findings store — load_findings / append_findings / stale verdict semantics.

Covers: multi-source loads keep every file, reloads restore claims by
occurrence (ID + scanner/repo/resource, not position), append_findings skips
only occurrences already in the store, and verdicts go stale when their
group's findings change.
"""

import json

import pytest

from latent_defense_mcp import findings_store

pytestmark = pytest.mark.asyncio


class _FakeMCP:
    def __init__(self):
        self.tools = {}

    def tool(self):
        def deco(fn):
            self.tools[fn.__name__] = fn
            return fn
        return deco


@pytest.fixture
def tools(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setattr(findings_store, "_stores", {})
    mcp = _FakeMCP()
    findings_store.register(mcp)
    yield mcp.tools
    for store in findings_store._stores.values():
        store.close()


def _write(tmp_path, name, findings):
    p = tmp_path / name
    p.write_text(json.dumps(findings))
    return str(p)


def _rows(project="p"):
    db = findings_store._get_store(project).db
    return db.execute("SELECT id, group_id FROM findings ORDER BY idx").fetchall()


def _claim(finding_id, group_id, project="p"):
    db = findings_store._get_store(project).db
    db.execute(
        "INSERT OR IGNORE INTO finding_groups (group_id, description) VALUES (?, ?)",
        (group_id, "test group"),
    )
    db.execute("UPDATE findings SET group_id = ? WHERE id = ?", (group_id, finding_id))
    db.commit()


class TestLoadFindings:
    async def test_paths_loads_every_source(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}, {"id": "A2"}])
        b = _write(tmp_path, "b.json", [{"id": "B1"}])

        result = json.loads(await tools["load_findings"]("p", paths=[a, b]))

        assert result["total_findings"] == 3
        assert result["sources"] == 2
        assert [r[0] for r in _rows()] == ["A1", "A2", "B1"]

    async def test_path_and_paths_combine(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}])
        b = _write(tmp_path, "b.json", [{"id": "B1"}])

        result = json.loads(await tools["load_findings"]("p", path=a, paths=[b]))

        assert result["total_findings"] == 2

    async def test_missing_file_leaves_store_untouched(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}])
        await tools["load_findings"]("p", path=a)

        result = json.loads(
            await tools["load_findings"]("p", paths=[a, str(tmp_path / "nope.json")])
        )

        assert "error" in result
        assert [r[0] for r in _rows()] == ["A1"]

    async def test_requires_a_path(self, tools):
        assert "error" in json.loads(await tools["load_findings"]("p"))

    async def test_reload_restores_claims_by_id_not_position(self, tools, tmp_path):
        old = _write(tmp_path, "old.json", [{"id": "A1"}, {"id": "A2"}])
        await tools["load_findings"]("p", path=old)
        _claim("A2", "g-auth")

        # New export: a new finding first, so every old finding shifts position
        new = _write(tmp_path, "new.json", [{"id": "NEW"}, {"id": "A1"}, {"id": "A2"}])
        result = json.loads(await tools["load_findings"]("p", path=new))

        assert dict(_rows()) == {"NEW": None, "A1": None, "A2": "g-auth"}
        assert result["restored_claims"] == 1
        assert result["unclaimed"] == 2

    async def test_reload_keeps_groups_and_investigations(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}])
        await tools["load_findings"]("p", path=a)
        _claim("A1", "g-auth")
        db = findings_store._get_store("p").db
        db.execute("INSERT INTO investigations (group_id, verdict) VALUES ('g-auth', 'confirmed')")
        db.commit()

        await tools["load_findings"]("p", path=a)

        assert db.execute("SELECT group_id FROM finding_groups").fetchall() == [("g-auth",)]
        assert db.execute("SELECT verdict FROM investigations").fetchall() == [("confirmed",)]

    async def test_findings_without_id_restore_by_content(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"title": "x"}, {"title": "y"}])
        await tools["load_findings"]("p", path=a)
        db = findings_store._get_store("p").db
        db.execute("INSERT INTO finding_groups (group_id) VALUES ('g')")
        db.execute("UPDATE findings SET group_id = 'g' WHERE idx = 1")
        db.commit()

        await tools["load_findings"]("p", path=a)

        assert [r[1] for r in _rows()] == [None, "g"]

    async def test_claims_to_deleted_groups_are_dropped(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}])
        await tools["load_findings"]("p", path=a)
        _claim("A1", "g-gone")
        db = findings_store._get_store("p").db
        db.execute("DELETE FROM finding_groups")
        db.commit()

        await tools["load_findings"]("p", path=a)

        assert _rows() == [("A1", None)]


    async def test_same_id_on_different_resources_keeps_each_claim(self, tools, tmp_path):
        findings = [
            {"id": "CVE-123", "resource": "image-a"},
            {"id": "CVE-123", "resource": "image-b"},
        ]
        a = _write(tmp_path, "a.json", findings)
        await tools["load_findings"]("p", path=a)
        db = findings_store._get_store("p").db
        db.execute("INSERT INTO finding_groups (group_id) VALUES ('rebuild-a'), ('rebuild-b')")
        db.execute("UPDATE findings SET group_id = 'rebuild-a' WHERE resource = 'image-a'")
        db.execute("UPDATE findings SET group_id = 'rebuild-b' WHERE resource = 'image-b'")
        db.commit()

        # Reload with the order flipped
        b = _write(tmp_path, "b.json", list(reversed(findings)))
        await tools["load_findings"]("p", path=b)

        rows = db.execute("SELECT resource, group_id FROM findings ORDER BY idx").fetchall()
        assert rows == [("image-b", "rebuild-b"), ("image-a", "rebuild-a")]

    async def test_repeated_identical_occurrences_restore_in_order(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "D"}, {"id": "D"}])
        await tools["load_findings"]("p", path=a)
        db = findings_store._get_store("p").db
        db.execute("INSERT INTO finding_groups (group_id) VALUES ('g1'), ('g2')")
        db.execute("UPDATE findings SET group_id = 'g1' WHERE idx = 0")
        db.execute("UPDATE findings SET group_id = 'g2' WHERE idx = 1")
        db.commit()

        await tools["load_findings"]("p", path=a)

        assert [r[1] for r in _rows()] == ["g1", "g2"]


class TestAppendFindings:
    async def test_skips_findings_already_in_store(self, tools, tmp_path):
        old = _write(tmp_path, "old.json", [{"id": "A1"}, {"id": "A2"}])
        await tools["load_findings"]("p", path=old)
        _claim("A1", "g-auth")

        new = _write(tmp_path, "new.json", [{"id": "A1"}, {"id": "A2"}, {"id": "NEW"}])
        result = json.loads(await tools["append_findings"]("p", new))

        assert result["appended"] == 1
        assert result["skipped_existing"] == 2
        assert dict(_rows()) == {"A1": "g-auth", "A2": None, "NEW": None}

    async def test_same_id_on_a_new_resource_is_added(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "CVE-123", "resource": "image-a"}])
        await tools["load_findings"]("p", path=a)

        b = _write(tmp_path, "b.json", [{"id": "CVE-123", "resource": "image-b"}])
        result = json.loads(await tools["append_findings"]("p", b))

        assert result["appended"] == 1
        assert result["skipped_existing"] == 0

    async def test_skip_is_per_occurrence(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "D"}])
        await tools["load_findings"]("p", path=a)

        b = _write(tmp_path, "b.json", [{"id": "D"}, {"id": "D"}])
        result = json.loads(await tools["append_findings"]("p", b))

        assert result["appended"] == 1
        assert result["skipped_existing"] == 1

    async def test_skips_idless_findings_by_content(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"title": "x"}])
        await tools["load_findings"]("p", path=a)

        b = _write(tmp_path, "b.json", [{"title": "x"}, {"title": "y"}])
        result = json.loads(await tools["append_findings"]("p", b))

        assert result["appended"] == 1
        assert result["skipped_existing"] == 1

    async def test_keeps_duplicates_within_the_file(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "D"}, {"id": "D"}])

        result = json.loads(await tools["append_findings"]("p", a))

        assert result["appended"] == 2

    async def test_skip_existing_false_appends_everything(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}])
        await tools["load_findings"]("p", path=a)

        result = json.loads(await tools["append_findings"]("p", a, skip_existing=False))

        assert result["appended"] == 1
        assert result["total_findings"] == 2

    async def test_append_on_empty_store_loads(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}, {"id": "A2"}])

        result = json.loads(await tools["append_findings"]("p", a))

        assert result["start_idx"] == 0
        assert result["total_findings"] == 2


class TestStaleVerdicts:
    async def _investigated_group(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1"}, {"id": "A2"}])
        await tools["load_findings"]("p", path=a)
        _claim("A1", "g")
        _claim("A2", "g")
        await tools["save_investigation"]("p", "g", explore_result="{}", verdict="confirmed", evidence="e")

    async def test_fresh_verdict_is_not_stale(self, tools, tmp_path):
        await self._investigated_group(tools, tmp_path)

        inv = json.loads(await tools["get_investigation"]("p", "g"))
        status = json.loads(await tools["pipeline_status"]("p"))

        assert "stale" not in inv
        assert status["investigated"] == 1
        assert status["stale_verdicts"] == []
        assert status["phases"]["investigate"] == "complete"

    async def test_new_finding_in_group_makes_verdict_stale(self, tools, tmp_path):
        await self._investigated_group(tools, tmp_path)
        b = _write(tmp_path, "b.json", [{"id": "A3"}])
        await tools["append_findings"]("p", b)
        _claim("A3", "g")

        inv = json.loads(await tools["get_investigation"]("p", "g"))
        status = json.loads(await tools["pipeline_status"]("p"))

        assert inv["stale"] is True
        assert "covered 2 findings; the group now has 3" in inv["stale_reason"]
        assert status["investigated"] == 0
        assert status["stale_verdicts"] == ["g"]
        assert status["phases"]["investigate"] == "partial"

    async def test_reverify_clears_staleness(self, tools, tmp_path):
        await self._investigated_group(tools, tmp_path)
        b = _write(tmp_path, "b.json", [{"id": "A3"}])
        await tools["append_findings"]("p", b)
        _claim("A3", "g")

        await tools["save_investigation"]("p", "g", verdict="confirmed", evidence="e2")

        assert "stale" not in json.loads(await tools["get_investigation"]("p", "g"))

    async def test_reload_of_same_findings_keeps_verdict_fresh(self, tools, tmp_path):
        await self._investigated_group(tools, tmp_path)
        reordered = _write(tmp_path, "r.json", [{"id": "NEW"}, {"id": "A2"}, {"id": "A1"}])

        await tools["load_findings"]("p", path=reordered)

        assert "stale" not in json.loads(await tools["get_investigation"]("p", "g"))

    async def test_reexported_finding_with_new_content_makes_verdict_stale(self, tools, tmp_path):
        await self._investigated_group(tools, tmp_path)
        changed = _write(tmp_path, "c.json", [
            {"id": "A1", "severity": "low", "evidence": "a control blocks it"},
            {"id": "A2"},
        ])

        await tools["load_findings"]("p", path=changed)

        inv = json.loads(await tools["get_investigation"]("p", "g"))
        assert dict(_rows())["A1"] == "g"  # claim kept: same identity
        assert inv["stale"] is True
        assert "re-exported with new content" in inv["stale_reason"]

    async def test_field_order_alone_does_not_make_verdict_stale(self, tools, tmp_path):
        a = _write(tmp_path, "a.json", [{"id": "A1", "severity": "high", "title": "t"}])
        await tools["load_findings"]("p", path=a)
        _claim("A1", "g")
        await tools["save_investigation"]("p", "g", verdict="confirmed", evidence="e")

        b = _write(tmp_path, "b.json", [{"title": "t", "severity": "high", "id": "A1"}])
        await tools["load_findings"]("p", path=b)

        assert "stale" not in json.loads(await tools["get_investigation"]("p", "g"))

    async def test_store_from_before_coverage_tracking_migrates(self, tools, tmp_path, monkeypatch):
        import sqlite3

        state = tmp_path / "state"
        state.mkdir(exist_ok=True)
        old = sqlite3.connect(str(state / "findings-old.db"))
        old.executescript("""
            CREATE TABLE investigations (
                group_id TEXT PRIMARY KEY, explore_result TEXT, verdict TEXT,
                evidence TEXT, graph_corrections TEXT, investigated_at TEXT
            );
            INSERT INTO investigations (group_id, verdict) VALUES ('g', 'confirmed');
        """)
        old.commit()
        old.close()

        inv = json.loads(await tools["get_investigation"]("old", "g"))
        status = json.loads(await tools["pipeline_status"]("old"))

        assert inv["verdict"] == "confirmed"
        assert "stale" not in inv
        assert status["stale_verdicts"] == []
