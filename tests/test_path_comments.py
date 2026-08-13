"""LD-2255 (E3): MCP triage parity — read surface.

Scope note: the E1 ``rescored`` filter that this PR previously stubbed was split out to
LD-2258/E6 (the WS-C C1a ``reassessed_at``-backed backend filter, triage #107, now merged
to triage main). E6 has since wired ``rescored`` onto ``list_attack_paths`` — the full
forward + cap contract lives in ``tests/test_rescored_filter.py``. Here we only keep the
E3-adjacent invariants: ``status`` is forwarded, and a default call sends no ``rescored``
param (no behavioural change vs RC for existing callers).

E3 — ``list_path_comments(path_id)`` must merge the two comment stores after LD-2198:
new comments in InfraDB generic records (``record_type=triage_path_comment``) and
legacy pre-move comments still on the triage service. A plain triage proxy would miss
every new comment. These tests monkeypatch the ``_get`` HTTP seam so no live server is
needed.
"""

import json

import pytest

from latent_defense_mcp import server
from latent_defense_mcp.errors import TOOL_SCOPES

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# E1 — list_attack_paths filter forwarding
# ---------------------------------------------------------------------------
class TestListAttackPathsFilters:
    async def test_status_is_forwarded(self, monkeypatch):
        """Regression: `status` is forwarded (LD-2253 audit — already present on main)."""
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
# E3 — list_path_comments merge
# ---------------------------------------------------------------------------
# The InfraDB comment record mirrors the Portal contract (portal src/api/pathComments.ts,
# PR #310): the `data` payload is a PathComment {comment_id, path_id, text, author,
# parent_comment_id?, parent_event_id?, at}. The canonical timestamp is `data.at` — the
# Portal derives `created_at = c.at`. The record ENVELOPE `created_at` is InfraDB's own
# write time and is deliberately set to a WRONG value here so a test fails if the tool
# timestamps from the envelope instead of `data.at`.
_ENVELOPE_WRONG_TS = "1999-01-01T00:00:00Z"


def _infra_record(comment_id, text, at, author="alice@x.io",
                  parent_comment_id=None, parent_event_id=None):
    """An InfraDB generic-records row (Portal PathComment payload under `data`)."""
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


def _legacy_comment(comment_id, text, created_at, author="bob", actor="bob@x.io"):
    """A legacy triage PathComment blob (flat, timestamp in `created_at`)."""
    return {
        "comment_id": comment_id,
        "path_id": "p1",
        "actor": actor,
        "author": author,
        "text": text,
        "created_at": created_at,
    }


# The InfraDB read must go through the Portal's `/api/infra/` prefix (nginx rewrites it to
# InfraDB's `/api/records`). A test that mocked `/api/records` would pass while deployment
# 404s, so the mock ONLY answers the correct path.
_INFRA_RECORDS_PATH = "/api/infra/records"


def _route(records=None, legacy=None, records_err=None, legacy_err=None):
    """Build a fake _get that dispatches by path and can raise per-source.

    The records leg honours limit/offset (slicing the full `records` list) and reports the
    full `total`, exactly like the InfraDB endpoint — so a caller that only reads the first
    page sees `total > len(page)` and must paginate to get everything.
    """
    all_records = list(records or [])

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
                "list_path_comments hit /api/records; must use /api/infra/records"
            )
        if path.endswith("/comments"):
            if legacy_err is not None:
                raise legacy_err
            fake_get.legacy_tool = _tool
            return legacy or []
        raise AssertionError(f"unexpected path {path}")

    return fake_get


class TestListPathCommentsMerge:
    async def test_merges_infradb_and_legacy(self, monkeypatch):
        fake = _route(
            records=[_infra_record("c2", "new comment", "2026-08-04T10:00:00Z")],
            legacy=[_legacy_comment("c1", "old comment", "2026-07-01T09:00:00Z")],
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert [c["comment_id"] for c in out] == ["c1", "c2"]  # oldest-first
        assert out[0]["text"] == "old comment"
        assert out[0]["source"] == "triage"
        assert out[1]["text"] == "new comment"
        assert out[1]["source"] == "infradb"

    async def test_infradb_records_query_params(self, monkeypatch):
        """The records call hits /api/infra/records with the right params (route contract)."""
        fake = _route(records=[], legacy=[])
        monkeypatch.setattr(server, "_get", fake)

        await server.list_path_comments("p1")

        # Route contract (review P1): must go through the Portal's /api/infra/ prefix,
        # NOT /api/records (which the Portal 404s). _route already asserts this, but pin
        # it explicitly so the contract is self-documenting.
        assert fake.records_path == "/api/infra/records"
        assert fake.records_params["record_type"] == "triage_path_comment"
        assert fake.records_params["parent_key_id"] == "p1"
        assert fake.records_params["limit"] == 500  # server-max page; default 100 truncates
        assert fake.records_params["offset"] == 0

    async def test_paginates_past_first_page(self, monkeypatch):
        """Regression (LD-2255 Codex blocker): a path with >500 InfraDB comments must
        return ALL of them, not just the first page. total > one page → page until done."""
        # 1201 records → 3 pages at limit=500 (500 + 500 + 201). Oldest-last order,
        # as InfraDB returns them (created_at DESC), so the sort reverses to oldest-first.
        n = 1201
        recs = [
            _infra_record(
                f"c{i:04d}",
                f"comment {i}",
                # Descending timestamps so record 0 is the NEWEST (matches DESC order);
                # oldest-first sort should then put the highest index first.
                f"2026-08-{(i % 28) + 1:02d}T{(i % 24):02d}:00:00Z",
            )
            for i in range(n)
        ]
        fake = _route(records=recs, legacy=[])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        # All records surfaced, none truncated.
        assert len(out) == n
        assert {c["comment_id"] for c in out} == {f"c{i:04d}" for i in range(n)}
        # Exactly 3 pages requested, with the right offsets.
        offsets = [c["offset"] for c in fake.records_calls]
        assert offsets == [0, 500, 1000]
        # Output is oldest-first (created_at ascending) across page boundaries.
        keys = [(c["created_at"] is None, str(c["created_at"] or "")) for c in out]
        assert keys == sorted(keys)

    async def test_paginates_exact_multiple_of_page_size(self, monkeypatch):
        """Boundary: total that is an exact multiple of the page size must not spin an
        extra empty request nor drop the last page."""
        recs = [
            _infra_record(f"c{i:04d}", f"comment {i}", f"2026-08-04T{i % 24:02d}:00:00Z")
            for i in range(1000)  # exactly 2 pages of 500
        ]
        fake = _route(records=recs, legacy=[])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert len(out) == 1000
        offsets = [c["offset"] for c in fake.records_calls]
        assert offsets == [0, 500]  # no wasted 3rd request

    async def test_pagination_terminates_if_backend_ignores_offset(self, monkeypatch):
        """Hardening: a misbehaving backend that returns a full page while ignoring
        `offset` (same rows every time) must not hang/OOM — dedup collapses the repeats
        and the loop terminates once `got >= total` or a short/empty page arrives."""
        page = [
            _infra_record(f"c{i:04d}", f"comment {i}", f"2026-08-04T{i % 24:02d}:00:00Z")
            for i in range(500)
        ]

        calls = {"n": 0}

        async def fake_get(path, *, _tool="", **params):
            if path == _INFRA_RECORDS_PATH:
                calls["n"] += 1
                # Broken backend: same 500-row page regardless of offset, total=500.
                return {"records": list(page), "total": 500}
            if path.endswith("/comments"):
                return []
            raise AssertionError(path)

        monkeypatch.setattr(server, "_get", fake_get)

        out = json.loads(await server.list_path_comments("p1"))

        # got reaches total after the first page → exactly one request, 500 unique rows.
        assert calls["n"] == 1
        assert len(out) == 500

    async def test_pagination_preserves_dedup_precedence(self, monkeypatch):
        """Dedup (InfraDB wins over legacy) must still hold when the InfraDB copy is on a
        LATER page — the merge sees the whole accumulated set, not just page one."""
        # 501 records: the duplicate id "dup" is the 501st (page 2). Legacy also has "dup".
        recs = [
            _infra_record(f"c{i:04d}", f"comment {i}", f"2026-08-04T{i % 24:02d}:00:00Z")
            for i in range(500)
        ]
        recs.append(_infra_record("dup", "authoritative", "2026-08-04T23:30:00Z"))
        fake = _route(
            records=recs,
            legacy=[_legacy_comment("dup", "stale copy", "2026-08-04T23:30:00Z")],
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert len(out) == 501  # 501 infradb, legacy "dup" collapsed
        dup = [c for c in out if c["comment_id"] == "dup"]
        assert len(dup) == 1
        assert dup[0]["text"] == "authoritative"  # InfraDB (page 2) wins
        assert dup[0]["source"] == "infradb"

    async def test_dedup_infradb_wins(self, monkeypatch):
        """Same comment_id in both stores collapses to one — InfraDB copy wins."""
        fake = _route(
            records=[_infra_record("dup", "authoritative", "2026-08-04T10:00:00Z")],
            legacy=[_legacy_comment("dup", "stale copy", "2026-08-04T10:00:00Z")],
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert len(out) == 1
        assert out[0]["text"] == "authoritative"
        assert out[0]["source"] == "infradb"

    async def test_legacy_failure_does_not_drop_new_comments(self, monkeypatch):
        """If the legacy triage read 404s (path is InfraDB-only), InfraDB (new)
        comments still surface. The 404 is detected by status, not message."""
        fake = _route(
            records=[_infra_record("c2", "new comment", "2026-08-04T10:00:00Z")],
            legacy_err=server.McpApiError("Resource not found (404).", status=404),
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert [c["comment_id"] for c in out] == ["c2"]

    async def test_legacy_404_with_envelope_message_still_swallowed(self, monkeypatch):
        """Review (claude[bot], LD-2255): a 404 whose message came from the structured
        error envelope (NOT the "Resource not found (404)" prefix) must still be treated
        as the expected InfraDB-only miss. Detection is by `status`, so the tool no longer
        aborts on an envelope-shaped 404 — the old message-prefix check would have."""
        fake = _route(
            records=[_infra_record("c2", "new comment", "2026-08-04T10:00:00Z")],
            legacy_err=server.McpApiError(
                "Attack path p1 has no comments\nTool: list_path_comments", status=404
            ),
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert [c["comment_id"] for c in out] == ["c2"]

    async def test_reads_payload_from_record_data(self, monkeypatch):
        """Comment fields come from the record's `data` blob, not the row envelope."""
        fake = _route(
            records=[_infra_record("c9", "payload text", "2026-08-04T10:00:00Z",
                                   author="carol@x.io")],
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert out[0]["author"] == "carol@x.io"
        assert out[0]["text"] == "payload text"

    async def test_falsy_comment_id_not_replaced_by_envelope_key(self, monkeypatch):
        """Review (claude[bot], LD-2255): a present-but-falsy `data.comment_id` (0 or "")
        is a real id and must be used as-is (and as the dedup key), not fall through the
        old truthiness `or` chain to the envelope `key_id`. Presence check, not truthiness."""
        rec = {
            "record_type": "triage_path_comment",
            "key_id": "envelope-key",       # envelope id — must NOT win over data's id
            "parent_key_id": "p1",
            "created_at": _ENVELOPE_WRONG_TS,
            "data": {"comment_id": 0, "path_id": "p1", "author": "a",
                     "text": "falsy id", "at": "2026-08-04T10:00:00Z"},
        }
        fake = _route(records=[rec])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert len(out) == 1
        assert out[0]["comment_id"] == 0            # honoured payload id, not "envelope-key"
        assert out[0]["text"] == "falsy id"

    async def test_timestamp_read_from_data_at_not_envelope(self, monkeypatch):
        """Review (rebeka): created_at must come from the payload's `at`, not the record
        envelope. The envelope carries a WRONG time (_ENVELOPE_WRONG_TS); ordering must
        follow `at`, so a c1(older `at`)/c2(newer `at`) pair comes back oldest-first."""
        fake = _route(records=[
            _infra_record("c2", "newer", "2026-08-04T10:00:00Z"),
            _infra_record("c1", "older", "2026-08-01T10:00:00Z"),
        ])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert [c["comment_id"] for c in out] == ["c1", "c2"]  # by data.at, not envelope
        assert out[0]["created_at"] == "2026-08-01T10:00:00Z"  # the `at`, not 1999 envelope
        assert all(c["created_at"] != _ENVELOPE_WRONG_TS for c in out)

    async def test_falsy_at_not_replaced_by_envelope(self, monkeypatch):
        """A falsy-but-valid `at` (empty string) must be honoured, not fall through to the
        record envelope's (wrong) created_at. Presence check, not truthiness."""
        rec = _infra_record("c1", "epoch-ish", "")  # empty `at` is a present value
        fake = _route(records=[rec])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert out[0]["created_at"] == ""                      # honoured `at`
        assert out[0]["created_at"] != _ENVELOPE_WRONG_TS      # NOT the 1999 envelope

    async def test_thread_anchors_preserved(self, monkeypatch):
        """Review (rebeka): parent_comment_id / parent_event_id must survive so replies
        aren't flattened into unrelated root comments."""
        fake = _route(records=[
            _infra_record("root", "root comment", "2026-08-01T10:00:00Z"),
            _infra_record("reply-c", "reply to comment", "2026-08-02T10:00:00Z",
                          parent_comment_id="root"),
            _infra_record("reply-e", "reply to event", "2026-08-03T10:00:00Z",
                          parent_event_id="evt-42"),
        ])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))
        by_id = {c["comment_id"]: c for c in out}

        assert by_id["root"]["parent_comment_id"] is None
        assert by_id["root"]["parent_event_id"] is None
        assert by_id["reply-c"]["parent_comment_id"] == "root"
        assert by_id["reply-c"]["parent_event_id"] is None
        assert by_id["reply-e"]["parent_event_id"] == "evt-42"
        assert by_id["reply-e"]["parent_comment_id"] is None
        # Anchors are always present as keys (stable shape), even on legacy/root rows.
        assert all("parent_comment_id" in c and "parent_event_id" in c for c in out)

    async def test_missing_created_at_sorts_last(self, monkeypatch):
        """A pre-LD-2010 blob without created_at is ordered deterministically (last)."""
        fake = _route(
            records=[_infra_record("c2", "dated", "2026-08-04T10:00:00Z")],
            legacy=[_legacy_comment("c0", "undated", None)],
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))

        assert [c["comment_id"] for c in out] == ["c2", "c0"]

    async def test_empty_both_stores(self, monkeypatch):
        fake = _route(records=[], legacy=[])
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))
        assert out == []

    async def test_non_404_legacy_error_propagates(self, monkeypatch):
        """A non-404 legacy failure (e.g. 403/5xx) must NOT be silently swallowed."""
        fake = _route(
            records=[_infra_record("c2", "new comment", "2026-08-04T10:00:00Z")],
            legacy_err=server.McpApiError(
                "Insufficient permissions: this key lacks 'triage:read'.", status=403
            ),
        )
        monkeypatch.setattr(server, "_get", fake)

        with pytest.raises(server.McpApiError):
            await server.list_path_comments("p1")

    async def test_auth_pending_surfaces_prompt(self, monkeypatch):
        """Device-flow pending on the InfraDB read returns the prompt, not an empty list."""
        async def fake_get(path, *, _tool="", **params):
            return {"status": "authentication_required", "user_code": "ABCD-1234"}

        monkeypatch.setattr(server, "_get", fake_get)
        out = json.loads(await server.list_path_comments("p1"))

        assert out["status"] == "authentication_required"
        assert out["user_code"] == "ABCD-1234"

    async def test_numeric_timestamp_does_not_crash_sort(self, monkeypatch):
        """Unvalidated records `data` may carry a numeric `at` — sort must not TypeError
        (str-vs-int) when mixed with ISO-string timestamps from other rows."""
        rec = _infra_record("c2", "epoch comment", 1754308800)  # numeric epoch in `at`
        fake = _route(
            records=[rec],
            legacy=[_legacy_comment("c1", "iso comment", "2026-07-01T09:00:00Z")],
        )
        monkeypatch.setattr(server, "_get", fake)

        out = json.loads(await server.list_path_comments("p1"))  # must not raise
        assert {c["comment_id"] for c in out} == {"c1", "c2"}

    async def test_tool_string_maps_to_triage_read_scope(self, monkeypatch):
        """Both underlying calls carry _tool='list_path_comments' → triage:read scope."""
        fake = _route(records=[], legacy=[])
        monkeypatch.setattr(server, "_get", fake)

        await server.list_path_comments("p1")

        assert fake.records_tool == "list_path_comments"
        assert fake.legacy_tool == "list_path_comments"
        assert TOOL_SCOPES["list_path_comments"] == "triage:read"
