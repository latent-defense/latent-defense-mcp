"""MCP triage parity — new tools and updated tools.

Tests for: add_path_comment (infrastructure database writes, threading, agent attribution),
edit_path_comment, get_triage_config, triage_stats(view="classification").

Monkeypatches the ``_get`` / ``_post`` HTTP seams (matching test_path_comments.py).
"""

import json

import pytest

from latent_defense_mcp import server

pytestmark = pytest.mark.asyncio

_INFRA_RECORDS_PATH = "/api/infra/records"


# ---------------------------------------------------------------------------
# add_path_comment — infrastructure database write, threading, agent attribution
# ---------------------------------------------------------------------------


class TestAddPathComment:
    async def test_writes_to_infradb_records(self, monkeypatch):
        """add_path_comment writes to infrastructure database records, not triage comments."""
        posted: dict = {}

        async def fake_post(path, body=None, *, _tool=""):
            posted["path"] = path
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(await server.add_path_comment("p1", "hello"))

        assert posted["path"] == _INFRA_RECORDS_PATH
        assert posted["body"]["record_type"] == "triage_path_comment"
        assert posted["body"]["parent_key_id"] == "p1"
        assert result["text"] == "hello"
        assert result["path_id"] == "p1"

    async def test_agent_attribution_automatic(self, monkeypatch):
        """Comments from MCP are automatically stamped as agent-authored."""
        posted: dict = {}

        async def fake_post(path, body=None, *, _tool=""):
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(await server.add_path_comment("p1", "note"))

        assert result["author_kind"] == "agent"
        assert result["agent_name"] == "claude"
        data = posted["body"]["data"]
        assert data["author_kind"] == "agent"
        assert data["agent_name"] == "claude"

    async def test_threading_parent_comment_id(self, monkeypatch):
        """parent_comment_id is forwarded to the infrastructure database record."""
        posted: dict = {}

        async def fake_post(path, body=None, *, _tool=""):
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(
            await server.add_path_comment("p1", "reply", parent_comment_id="c1")
        )

        assert result["parent_comment_id"] == "c1"
        assert posted["body"]["data"]["parent_comment_id"] == "c1"

    async def test_threading_parent_event_id(self, monkeypatch):
        """parent_event_id is forwarded (reply to a status/score event)."""
        posted: dict = {}

        async def fake_post(path, body=None, *, _tool=""):
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(
            await server.add_path_comment("p1", "reply to event", parent_event_id="evt1")
        )

        assert result.get("parent_event_id") == "evt1"
        assert "parent_comment_id" not in result or result["parent_comment_id"] is None

    async def test_parent_comment_wins_over_parent_event(self, monkeypatch):
        """If both parent_comment_id and parent_event_id are set, comment wins."""
        posted: dict = {}

        async def fake_post(path, body=None, *, _tool=""):
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(
            await server.add_path_comment(
                "p1", "text", parent_comment_id="c1", parent_event_id="evt1"
            )
        )

        assert result["parent_comment_id"] == "c1"
        assert "parent_event_id" not in result or result.get("parent_event_id") is None

    async def test_validates_required_fields(self, monkeypatch):
        """Empty path_id and text are rejected locally."""
        result = json.loads(await server.add_path_comment("", "text"))
        assert "error" in result

        result = json.loads(await server.add_path_comment("p1", "  "))
        assert "error" in result

    async def test_comment_has_unique_id(self, monkeypatch):
        """Each comment gets a unique comment_id."""
        ids = []

        async def fake_post(path, body=None, *, _tool=""):
            ids.append(body["data"]["comment_id"])
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        await server.add_path_comment("p1", "one")
        await server.add_path_comment("p1", "two")

        assert len(ids) == 2
        assert ids[0] != ids[1]

    async def test_author_passthrough(self, monkeypatch):
        """Explicit author is forwarded."""
        posted: dict = {}

        async def fake_post(path, body=None, *, _tool=""):
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(
            await server.add_path_comment("p1", "text", author="alice@example.com")
        )

        assert result["author"] == "alice@example.com"


# ---------------------------------------------------------------------------
# list_path_comments — author_kind and agent_name surfaced
# ---------------------------------------------------------------------------


def _infra_record(comment_id, text, at, author="alice@example.com",
                  parent_comment_id=None, author_kind=None, agent_name=None):
    data = {
        "comment_id": comment_id,
        "path_id": "p1",
        "author": author,
        "text": text,
        "at": at,
    }
    if parent_comment_id is not None:
        data["parent_comment_id"] = parent_comment_id
    if author_kind is not None:
        data["author_kind"] = author_kind
    if agent_name is not None:
        data["agent_name"] = agent_name
    return {
        "record_type": "triage_path_comment",
        "key_id": comment_id,
        "parent_key_id": "p1",
        "created_at": "1999-01-01T00:00:00Z",
        "data": data,
    }


def _route(records=None, legacy=None):
    all_records = list(records or [])

    async def fake_get(path, *, _tool="", **params):
        if path == _INFRA_RECORDS_PATH:
            limit = params.get("limit", 100)
            offset = params.get("offset", 0)
            page = all_records[offset: offset + limit]
            return {"records": page, "total": len(all_records)}
        if path.endswith("/comments"):
            return legacy or []
        raise AssertionError(f"unexpected path {path}")

    return fake_get


class TestListPathHistoryCommentsAttribution:
    async def test_surfaces_author_kind_and_agent_name(self, monkeypatch):
        """author_kind and agent_name are surfaced when filtering to comments."""
        events = [
            {
                "event_type": "comment",
                "comment_id": "c1",
                "text": "agent note",
                "at": "2026-01-01T00:00:00Z",
                "author_kind": "agent",
                "agent_name": "claude-opus-4",
            },
        ]

        async def fake_get(path, *, _tool="", **params):
            return events

        monkeypatch.setattr(server, "_get", fake_get)
        result = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(result) == 1
        assert result[0]["author_kind"] == "agent"
        assert result[0]["agent_name"] == "claude-opus-4"

    async def test_human_comments_have_null_agent_fields(self, monkeypatch):
        """Human comments have null author_kind and agent_name."""
        events = [
            {
                "event_type": "comment",
                "comment_id": "c1",
                "text": "human note",
                "at": "2026-01-01T00:00:00Z",
                "author_kind": None,
                "agent_name": None,
            },
        ]

        async def fake_get(path, *, _tool="", **params):
            return events

        monkeypatch.setattr(server, "_get", fake_get)
        result = json.loads(await server.list_path_history("p1", include="comments"))

        assert result[0]["author_kind"] is None
        assert result[0]["agent_name"] is None


# ---------------------------------------------------------------------------
# edit_path_comment
# ---------------------------------------------------------------------------


class TestEditPathComment:
    async def test_appends_new_revision(self, monkeypatch):
        """Edit creates a new record (append), not an overwrite."""
        rec = _infra_record("c1", "original", "2026-01-01T00:00:00Z")
        posted: dict = {}

        async def fake_get(path, *, _tool="", **params):
            if path == _INFRA_RECORDS_PATH:
                return {"records": [rec], "total": 1}
            raise AssertionError(f"unexpected path {path}")

        async def fake_post(path, body=None, *, _tool=""):
            posted["path"] = path
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_get", fake_get)
        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(await server.edit_path_comment("p1", "c1", "updated"))

        # Written to infrastructure database records
        assert posted["path"] == _INFRA_RECORDS_PATH
        # New key (not the original)
        assert posted["body"]["key_id"] != "c1"
        assert posted["body"]["key_id"] == result["revision_id"]
        # Supersedes the original
        assert result["supersedes"] == "c1"
        # Text updated
        assert result["text"] == "updated"
        # Logical comment_id preserved
        assert result["comment_id"] == "c1"
        # edited_at set
        assert "edited_at" in result

    async def test_not_found_returns_error(self, monkeypatch):
        """Editing a nonexistent comment returns a clean error."""
        async def fake_get(path, *, _tool="", **params):
            if path == _INFRA_RECORDS_PATH:
                return {"records": [], "total": 0}
            raise AssertionError(f"unexpected path {path}")

        monkeypatch.setattr(server, "_get", fake_get)
        result = json.loads(await server.edit_path_comment("p1", "nonexistent", "text"))
        assert "error" in result
        assert "not found" in result["error"]

    async def test_validates_required_fields(self):
        """Empty args rejected locally."""
        result = json.loads(await server.edit_path_comment("", "c1", "text"))
        assert "error" in result

        result = json.loads(await server.edit_path_comment("p1", "", "text"))
        assert "error" in result

        result = json.loads(await server.edit_path_comment("p1", "c1", "  "))
        assert "error" in result

    async def test_picks_latest_revision(self, monkeypatch):
        """When multiple revisions exist, edit supersedes the latest."""
        rec_v1 = _infra_record("c1", "v1", "2026-01-01T00:00:00Z")
        rec_v2 = {
            "record_type": "triage_path_comment",
            "key_id": "rev2",
            "parent_key_id": "p1",
            "created_at": "2026-01-02T00:00:00Z",
            "data": {
                "comment_id": "c1",
                "path_id": "p1",
                "text": "v2",
                "at": "2026-01-01T00:00:00Z",
                "edited_at": "2026-01-02T00:00:00Z",
                "revision_id": "rev2",
                "supersedes": "c1",
            },
        }
        posted: dict = {}

        async def fake_get(path, *, _tool="", **params):
            if path == _INFRA_RECORDS_PATH:
                return {"records": [rec_v2, rec_v1], "total": 2}
            raise AssertionError(f"unexpected path {path}")

        async def fake_post(path, body=None, *, _tool=""):
            posted["body"] = body
            return {"status": "ok"}

        monkeypatch.setattr(server, "_get", fake_get)
        monkeypatch.setattr(server, "_post", fake_post)
        result = json.loads(await server.edit_path_comment("p1", "c1", "v3"))

        # Supersedes rev2 (the latest), not c1 (the original)
        assert result["supersedes"] == "rev2"


# ---------------------------------------------------------------------------
# get_triage_config
# ---------------------------------------------------------------------------


class TestGetTriageConfig:
    async def test_returns_config(self, monkeypatch):
        """get_triage_config wraps GET /api/triage/config."""
        seen: dict = {}

        async def fake_get(path, *, _tool="", **params):
            seen["path"] = path
            seen["tool"] = _tool
            return {"rescore_display_threshold": 5.0}

        monkeypatch.setattr(server, "_get", fake_get)
        result = json.loads(await server.get_triage_config())

        assert seen["path"] == "/api/triage/config"
        assert result["rescore_display_threshold"] == 5.0


# ---------------------------------------------------------------------------
# get_classification_stats
# ---------------------------------------------------------------------------


class TestTriageStatsClassification:
    async def test_returns_stats(self, monkeypatch):
        """triage_stats(view='classification') wraps GET /api/triage/stats/classification."""
        seen: dict = {}

        async def fake_get(path, *, _tool="", **params):
            seen["path"] = path
            seen["params"] = params
            return {"true_positive": 10, "false_positive": 3}

        monkeypatch.setattr(server, "_get", fake_get)
        result = json.loads(await server.triage_stats(view="classification"))

        assert seen["path"] == "/api/triage/stats/classification"
        assert result["true_positive"] == 10

    async def test_forwards_repository_id(self, monkeypatch):
        """repository_id is forwarded to the API."""
        seen: dict = {}

        async def fake_get(path, *, _tool="", **params):
            seen["params"] = params
            return {}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.triage_stats(repository_id="repo-1", view="classification")

        assert seen["params"]["repository_id"] == "repo-1"

    async def test_omits_empty_repository_id(self, monkeypatch):
        """Empty repository_id is not forwarded."""
        seen: dict = {}

        async def fake_get(path, *, _tool="", **params):
            seen["params"] = params
            return {}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.triage_stats(repository_id="", view="classification")

        assert "repository_id" not in seen["params"]


# ---------------------------------------------------------------------------
# Tool registration — all new tools are discoverable
# ---------------------------------------------------------------------------


class TestToolRegistration:
    async def test_new_tools_registered(self):
        """All new/updated tools are registered on the MCP server."""
        tools = {t.name for t in await server.mcp.list_tools()}
        for name in (
            "add_path_comment",
            "edit_path_comment",
            "get_triage_config",
            "list_path_history",
            "triage_stats",
        ):
            assert name in tools, f"{name} not registered"

    async def test_new_prompts_registered(self):
        """All new prompts are registered."""
        prompts = {p.name for p in await server.mcp.list_prompts()}
        for name in ("triage_queue_review", "assess_cve", "chokepoint_report"):
            assert name in prompts, f"{name} not registered"

# cmv2 multi-repo probe
