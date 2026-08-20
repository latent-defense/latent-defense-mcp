"""Comment merge and path history read surface tests.

Scope: ``rescored`` filter invariants (``status`` is forwarded, a default call
sends no ``rescored`` param) and the full forward + cap contract in
``tests/test_rescored_filter.py``.

Comment retrieval must merge the two comment stores after the comment store migration:
new comments in the infrastructure database (``record_type=triage_path_comment``) and
legacy comments still on the triage service. A plain triage proxy would miss
every new comment. These tests monkeypatch the ``_get`` HTTP seam so no live server is
needed.
"""

import json

import pytest

from latent_defense_mcp import server
from latent_defense_mcp.errors import McpApiError

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# list_attack_paths filter forwarding
# ---------------------------------------------------------------------------
class TestListAttackPathsFilters:
    async def test_status_is_forwarded(self, monkeypatch):
        """Regression: `status` is forwarded."""
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["path"] = path
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.list_attack_paths(status="acknowledged")

        assert seen["path"] == "/api/triage/paths"
        assert seen["params"].get("status") == "acknowledged"

    async def test_rescored_never_forwarded(self, monkeypatch):
        """A normal call forwards no `rescored` param (no behavioural change vs RC)."""
        seen = {}

        async def fake_get(path, *, _tool="", **params):
            seen["params"] = params
            return {"items": [], "total": 0}

        monkeypatch.setattr(server, "_get", fake_get)
        await server.list_attack_paths()

        assert "rescored" not in seen["params"]


# ---------------------------------------------------------------------------
# Comment merge
# ---------------------------------------------------------------------------
# The comment record mirrors the comment contract:
# the `data` payload is a PathComment {comment_id, path_id, text, author,
# parent_comment_id?, parent_event_id?, at}. The canonical timestamp is `data.at` — the
# Portal derives `created_at = c.at`. The record ENVELOPE `created_at` is infrastructure database's own
# write time and is deliberately set to a WRONG value here so a test fails if the tool
# timestamps from the envelope instead of `data.at`.
_ENVELOPE_WRONG_TS = "1999-01-01T00:00:00Z"


def _infra_record(comment_id, text, at, author="alice@example.com",
                  parent_comment_id=None, parent_event_id=None):
    """An infrastructure database generic-records row (Portal PathComment payload under `data`)."""
    data = {
        "comment_id": comment_id,
        "path_id": "p1",
        "author": author,
        "text": text,
        "at": at,  # canonical timestamp (NOT `created_at`)
    }
    if parent_comment_id is not None:
        data["parent_comment_id"] = parent_comment_id
    if parent_event_id is not None:
        data["parent_event_id"] = parent_event_id
    return {
        "record_type": "triage_path_comment",
        "key_id": comment_id,
        "parent_key_id": "p1",
        "created_at": _ENVELOPE_WRONG_TS,  # envelope time — must NOT be used for ordering
        "data": data,
    }


def _legacy_comment(comment_id, text, created_at, author="bob", actor="bob@example.com"):
    """A legacy triage PathComment blob (flat, timestamp in `created_at`)."""
    return {
        "comment_id": comment_id,
        "path_id": "p1",
        "actor": actor,
        "author": author,
        "text": text,
        "created_at": created_at,
    }


# The infrastructure database read must go through the Portal's `/api/infra/` prefix (nginx rewrites it to
# infrastructure database's `/api/records`). A test that mocked `/api/records` would pass while deployment
# 404s, so the mock ONLY answers the correct path.
_INFRA_RECORDS_PATH = "/api/infra/records"


def _route(records=None, legacy=None, records_err=None, legacy_err=None,
           history_events=None):
    """Build a fake _get that dispatches by path and can raise per-source.

    The records leg honours limit/offset (slicing the full `records` list) and reports the
    full `total`, exactly like the infrastructure database endpoint — so a caller that only reads the first
    page sees `total > len(page)` and must paginate to get everything.

    ``history_events`` controls what the ``/history`` endpoint returns. When ``None``
    (the default), the history endpoint returns an empty list — this is the realistic
    behaviour (the server-side /history endpoint does NOT include infrastructure database comments).
    Pass an explicit list to override.
    """
    all_records = list(records or [])
    all_history = list(history_events) if history_events is not None else []

    async def fake_get(path, *, _tool="", **params):
        if path == _INFRA_RECORDS_PATH:
            if records_err is not None:
                raise records_err
            fake_get.records_params = params
            fake_get.records_path = path
            fake_get.records_tool = _tool
            fake_get.records_calls = getattr(fake_get, "records_calls", [])
            fake_get.records_calls.append(params)
            limit = params.get("limit", 100)
            offset = params.get("offset", 0)
            page = all_records[offset : offset + limit]
            return {"records": page, "total": len(all_records)}
        if path == "/api/records":
            # Wrong (un-prefixed) path — in deployment the Portal 404s this. Fail loudly
            # so a regression back to `/api/records` can't pass the suite.
            raise AssertionError(
                "Comment tool hit /api/records; must use /api/infra/records"
            )
        if path.endswith("/comments"):
            if legacy_err is not None:
                raise legacy_err
            fake_get.legacy_tool = _tool
            return legacy or []
        # list_path_history hits /api/triage/paths/{id}/history
        if "/history" in path:
            # Return the explicitly provided history events (realistic: the /history
            # endpoint does NOT include infrastructure database comments — the merge is client-side).
            return list(all_history)
        raise AssertionError(f"unexpected path {path}")

    return fake_get


class TestListPathHistoryCommentsFilter:
    """list_path_history merges comments from three sources: the /history endpoint,
    infrastructure database generic records (post-move), and legacy triage comments (pre-move).

    Comments written by add_path_comment go to infrastructure database records but are NOT included
    in the /history endpoint response. The merge logic restored here ensures they
    appear in the unified timeline.
    """

    async def test_infra_db_comments_appear_in_history(self, monkeypatch):
        """Comments stored in infrastructure database (via add_path_comment) must appear when
        include='comments', even though the /history endpoint doesn't include them."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[_infra_record("c1", "infra_db comment", "2026-08-02T10:00:00Z")],
                legacy=[],
                history_events=[
                    {"event_type": "status_change", "status": "acknowledged",
                     "at": "2026-08-01T10:00:00Z"},
                ],
            ),
        )
        out = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(out) == 1
        assert out[0]["comment_id"] == "c1"
        assert out[0]["text"] == "infra_db comment"

    async def test_filters_to_comments_only(self, monkeypatch):
        """include='comments' returns only comment events, merging all sources."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[_infra_record("c1", "from infra_db", "2026-08-02T10:00:00Z")],
                legacy=[_legacy_comment("c2", "from legacy", "2026-08-04T10:00:00Z")],
                history_events=[
                    {"event_type": "status_change", "status": "acknowledged",
                     "at": "2026-08-01T10:00:00Z"},
                    {"event_type": "score_change", "risk_score": 45,
                     "at": "2026-08-03T10:00:00Z"},
                ],
            ),
        )
        out = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(out) == 2
        assert [c["comment_id"] for c in out] == ["c1", "c2"]

    async def test_include_all_returns_everything(self, monkeypatch):
        """include='all' (default) returns the full history plus merged comments."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[_infra_record("c1", "a comment", "2026-08-02T10:00:00Z")],
                legacy=[],
                history_events=[
                    {"event_type": "status_change", "status": "acknowledged",
                     "at": "2026-08-01T10:00:00Z"},
                ],
            ),
        )
        out = json.loads(await server.list_path_history("p1"))

        # Should have the status_change + the merged infrastructure database comment
        assert len(out) == 2
        types = [e.get("event_type") for e in out]
        assert "status_change" in types
        assert "comment" in types

    async def test_handles_dict_response_with_events_key(self, monkeypatch):
        """Some backends return {events: [...]} instead of a bare list."""

        async def fake_get(path, *, _tool="", **params):
            if "/history" in path:
                return {
                    "events": [
                        {"event_type": "comment", "comment_id": "c1", "text": "found",
                         "at": "2026-08-01T10:00:00Z"},
                        {"event_type": "status_change", "status": "new",
                         "at": "2026-08-02T10:00:00Z"},
                    ]
                }
            if path == _INFRA_RECORDS_PATH:
                return {"records": [], "total": 0}
            if path.endswith("/comments"):
                return []
            raise AssertionError(f"unexpected path {path}")

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(out) == 1
        assert out[0]["comment_id"] == "c1"

    async def test_dedup_infra_db_wins(self, monkeypatch):
        """When the same comment_id appears in infrastructure database and history, infrastructure database wins."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[_infra_record("c1", "infra_db version", "2026-08-02T10:00:00Z")],
                legacy=[],
                history_events=[
                    {"event_type": "comment", "comment_id": "c1",
                     "text": "history version", "at": "2026-08-02T10:00:00Z"},
                ],
            ),
        )
        out = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(out) == 1
        assert out[0]["text"] == "infra_db version"
        assert out[0]["source"] == "infradb"

    async def test_timestamp_from_data_at_not_envelope(self, monkeypatch):
        """The canonical timestamp is data.at, not the record envelope's created_at."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[_infra_record("c1", "ts test", "2026-08-15T12:00:00Z")],
                legacy=[],
                history_events=[],
            ),
        )
        out = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(out) == 1
        # Must use data.at (2026-08-15), NOT envelope created_at (1999-01-01)
        assert out[0]["at"] == "2026-08-15T12:00:00Z"
        assert out[0]["created_at"] == "2026-08-15T12:00:00Z"

    async def test_legacy_404_is_safe(self, monkeypatch):
        """A 404 on the legacy comments endpoint is expected and swallowed."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[_infra_record("c1", "works", "2026-08-02T10:00:00Z")],
                legacy_err=McpApiError("not found", status=404),
                history_events=[],
            ),
        )
        out = json.loads(await server.list_path_history("p1", include="comments"))

        assert len(out) == 1
        assert out[0]["comment_id"] == "c1"

    async def test_legacy_500_reraises(self, monkeypatch):
        """A non-404 error on the legacy endpoint must not be swallowed."""
        monkeypatch.setattr(
            server, "_get",
            _route(
                records=[],
                legacy_err=McpApiError("server error", status=500),
                history_events=[],
            ),
        )
        with pytest.raises(McpApiError):
            await server.list_path_history("p1", include="comments")

