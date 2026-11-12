"""Tests for bulk_update_paths: default status filters and explicit path_ids.

Verifies that each action defaults to its action-compatible source statuses
when no status_filter is supplied, preventing predictable state-machine failures.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

import httpx

import latent_defense_mcp.server as srv
from latent_defense_mcp.errors import McpApiError

pytestmark = pytest.mark.asyncio

_EMPTY_PAGE = {"items": [], "total": 0}


async def _bulk(action: str, status_filter: str = "", monkeypatch=None, **kwargs):
    """Call bulk_update_paths with a mocked _post and return the filter of each bulk request."""
    bodies = await _bulk_bodies(action, status_filter=status_filter, monkeypatch=monkeypatch, **kwargs)
    return [{"status": ",".join(b["filter"]["status"])} for b in bodies]


async def _bulk_bodies(action: str, monkeypatch, reply=None, **kwargs):
    """Call bulk_update_paths with _post mocked by `reply(body)`; return (bodies, parsed result) when
    `reply` is given, else just the bodies."""
    bodies: list[dict] = []

    async def fake_post(path, body, _tool=None):
        assert path == "/api/triage/paths/bulk"
        bodies.append(body)
        if reply is not None:
            return reply(body)
        return {"action": body["action"], "total": 0, "succeeded": 0, "failed": 0, "results": []}

    monkeypatch.setattr(srv, "_post", fake_post)
    kwargs.setdefault("reason", "risk_accepted" if action == "dismiss" else "")
    out = json.loads(await srv.bulk_update_paths(action=action, **kwargs))
    return (bodies, out) if reply is not None else bodies


def _all_ok(body):
    return {"results": [{"path_id": pid, "status": "ok", "path_status": "false_positive", "error": None}
                        for pid in body["path_ids"]]}


async def test_acknowledge_default_excludes_validated_and_false_positive(monkeypatch):
    """acknowledge with no filter defaults to new,failed — not validated or false_positive."""
    params = await _bulk("acknowledge", monkeypatch=monkeypatch)
    assert len(params) == 1
    status = params[0].get("status", "")
    statuses = set(status.split(","))
    assert "new" in statuses
    assert "failed" in statuses
    assert "validated" not in statuses
    assert "false_positive" not in statuses


async def test_dismiss_default_excludes_new_and_false_positive(monkeypatch):
    """dismiss with no filter defaults to acknowledged,validated — not new or false_positive."""
    params = await _bulk("dismiss", monkeypatch=monkeypatch)
    assert len(params) == 1
    status = params[0].get("status", "")
    statuses = set(status.split(","))
    assert "acknowledged" in statuses
    assert "validated" in statuses
    assert "new" not in statuses
    assert "false_positive" not in statuses


async def test_close_default_excludes_closed_and_superseded(monkeypatch):
    """close with no filter must not include already-closed or terminal statuses."""
    params = await _bulk("close", monkeypatch=monkeypatch)
    assert len(params) == 1
    status = params[0].get("status", "")
    statuses = set(status.split(","))
    assert "new" in statuses
    assert "acknowledged" in statuses
    assert "closed" not in statuses
    assert "superseded" not in statuses


async def test_explicit_status_filter_overrides_default(monkeypatch):
    """An explicit status_filter takes precedence over the action default."""
    params = await _bulk("acknowledge", status_filter="failed", monkeypatch=monkeypatch)
    assert params[0].get("status") == "failed"


async def test_filter_is_one_bulk_request(monkeypatch):
    bodies = await _bulk_bodies("acknowledge", monkeypatch, min_risk_score=70, repository_id="r1", limit=500, note="n")
    assert bodies == [{"action": "acknowledge", "note": "n", "limit": 200,
                       "filter": {"status": ["new", "failed"], "min_risk_score": 70, "repository_id": "r1"}}]


async def test_dismiss_always_acknowledges_first_but_filter_excludes_new(monkeypatch):
    bodies = await _bulk_bodies("dismiss", monkeypatch)
    assert bodies[0]["acknowledge_first"] is True
    assert bodies[0]["filter"]["status"] == ["acknowledged", "validated"]


async def test_only_dismiss_sends_acknowledge_first(monkeypatch):
    for action in ("acknowledge", "close"):
        bodies = await _bulk_bodies(action, monkeypatch, path_ids=["a"])
        assert "acknowledge_first" not in bodies[0]


async def test_path_ids_are_deduped_and_chunked(monkeypatch):
    ids = [f"p{i}" for i in range(1201)] + ["p0", ""]
    bodies, out = await _bulk_bodies("dismiss", monkeypatch, reply=_all_ok, path_ids=ids)
    assert [len(b["path_ids"]) for b in bodies] == [500, 500, 201]
    assert all("filter" not in b and b["reason"] == "risk_accepted" and b["acknowledge_first"] for b in bodies)
    assert (out["applied_to"], out["succeeded"], out["failed"], out["failures"]) == (1201, 1201, 0, [])
    assert out["succeeded_by_status"] == {"false_positive": 1201}


async def test_path_ids_report_failures(monkeypatch):
    def reply(body):
        return {"results": [
            {"path_id": "a", "status": "ok", "path_status": "false_positive", "error": None},
            {"path_id": "b", "status": "conflict", "path_status": None, "error": "cannot dismiss from new"},
        ]}
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=["a", "b"])
    assert (out["succeeded"], out["failed"]) == (1, 1)
    assert out["failures"] == [{"status": "conflict", "error": "cannot dismiss from new", "count": 1, "path_ids": ["b"]}]


async def test_failures_are_grouped_by_reason_largest_first(monkeypatch):
    """Errors that name the path still land in one group; the biggest group comes first."""
    def reply(body):
        return {"results": [
            *({"path_id": f"v{i}", "status": "conflict", "error": "Cannot dismiss path in 'validating' state"}
              for i in range(3)),
            *({"path_id": f"x{i}", "status": "not_found", "error": f"Path x{i} not found"} for i in range(2)),
            {"path_id": "ok1", "status": "ok", "path_status": "false_positive"},
        ]}
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=["any"])
    assert out["failures"] == [
        {"status": "conflict", "error": "Cannot dismiss path in 'validating' state", "count": 3,
         "path_ids": ["v0", "v1", "v2"]},
        {"status": "not_found", "error": "Path <path_id> not found", "count": 2, "path_ids": ["x0", "x1"]},
    ]


async def test_result_stays_small_for_thousands_of_paths(monkeypatch):
    """Per-path entries for 2,000+ paths overflowed the MCP client's tool-result limit."""
    def reply(body):
        return {"results": [
            {"path_id": pid, "status": "ok" if n % 5 else "conflict", "path_status": "false_positive",
             "error": None if n % 5 else "Cannot dismiss path in 'validating' state; must be 'validated' or 'acknowledged'"}
            for n, pid in enumerate(body["path_ids"])]}
    ids = [f"path_repo_ld_a_{i:010x}" for i in range(2123)]
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=ids)
    assert out["applied_to"] == 2123 and len(out["failures"]) == 1
    group = out["failures"][0]
    assert (group["count"], group["showing"], len(group["path_ids"])) == (425, 100, 100)
    assert "first 100 path IDs" in out["note"]
    assert len(json.dumps(out)) < 5_000  # was ~400K characters with one entry per path


async def test_every_id_failing_still_fits(monkeypatch):
    """A full retry: every path already dismissed, so all 2,123 fail the same way."""
    def reply(body):
        return {"results": [{"path_id": pid, "status": "conflict", "error": "Cannot dismiss path in "
                             "'false_positive' state; must be 'validated' or 'acknowledged'"}
                            for pid in body["path_ids"]]}
    ids = [f"path_repo_ld_a_{i:010x}" for i in range(2123)]
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=ids)
    assert (out["failed"], out["failures"][0]["count"]) == (2123, 2123)
    assert len(json.dumps(out)) < 5_000  # listing all 2,123 IDs came to ~62K characters


async def test_no_note_when_nothing_is_cut(monkeypatch):
    def reply(body):
        return {"results": [{"path_id": pid, "status": "not_found", "error": "not found"} for pid in body["path_ids"]]}
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=[f"p{i}" for i in range(100)])
    assert out["failures"][0]["count"] == 100 and "showing" not in out["failures"][0]
    assert "note" not in out


async def test_refused_request_is_one_error_not_per_path_failures(monkeypatch):
    """e.g. close by a customer: triage refuses the whole request (403); stop after it."""
    def reply(body):
        raise McpApiError("Insufficient permissions", status=403)
    bodies, out = await _bulk_bodies("close", monkeypatch, reply=reply, path_ids=[f"p{i}" for i in range(1200)])
    assert len(bodies) == 1  # stopped after the first refused chunk
    assert (out["error"], out["detail"]) == ("Bulk update failed", "Insufficient permissions")
    assert out["not_confirmed"] == 1200 and len(out["not_confirmed_path_ids"]) == 100
    assert "succeeded" not in out


@pytest.mark.parametrize("exc", [McpApiError("rate limited", status=429), httpx.ReadTimeout("timed out")])
async def test_request_failing_midway_reports_what_ran_and_what_is_not_confirmed(monkeypatch, exc):
    def reply(body):
        if body["path_ids"][0] == "p0":
            return _all_ok(body)
        raise exc
    bodies, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=[f"p{i}" for i in range(1100)])
    assert len(bodies) == 2
    assert (out["error"], out["detail"]) == ("Bulk update failed", str(exc))
    assert (out["applied_to"], out["succeeded"], out["failures"]) == (500, 500, [])
    assert out["not_confirmed"] == 600 and out["not_confirmed_path_ids"] == [f"p{i}" for i in range(500, 600)]
    assert "Re-send the same path_ids" in out["note"]


async def test_unreadable_response_stops(monkeypatch):
    def reply(body):
        if body["path_ids"][0] == "p0":
            return _all_ok(body)
        return {"status": "ok"}  # no per-path results
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply, path_ids=[f"p{i}" for i in range(1100)])
    assert out["error"] == "Bulk update did not complete"
    assert out["succeeded"] == 500 and out["not_confirmed"] == 600


async def test_filter_mode_failure_is_just_the_error(monkeypatch):
    def reply(body):
        raise httpx.ReadTimeout("timed out")
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=reply)
    assert out == {"error": "Bulk update failed", "detail": "timed out"}


async def test_dismiss_status_filter_new_is_rejected(monkeypatch):
    bodies = await _bulk_bodies("dismiss", monkeypatch, status_filter="new")
    assert bodies == []


async def test_auth_pending_is_not_counted_as_success(monkeypatch):
    _, out = await _bulk_bodies("dismiss", monkeypatch, reply=lambda b: {"status": "authentication_required"},
                                path_ids=["a"])
    assert out["error"] == "Bulk update did not complete"
    assert out["detail"]["status"] == "authentication_required"
    assert "succeeded" not in out


@pytest.mark.parametrize("action", ["acknowledge", "dismiss", "close"])
@pytest.mark.parametrize("path_ids", [[], [""], ["  ", "\t"]])
async def test_empty_path_ids_is_rejected_not_filter_mode(monkeypatch, action, path_ids):
    # "Act on nothing" must never become "act on every path matching the default filter".
    bodies, out = await _bulk_bodies(action, monkeypatch, reply=_all_ok, path_ids=path_ids)
    assert bodies == []
    assert "path_ids is empty" in out["error"]


async def test_empty_path_ids_with_filters_is_rejected(monkeypatch):
    bodies = await _bulk_bodies("dismiss", monkeypatch, path_ids=[], repository_id="r1")
    assert bodies == []


async def test_path_ids_are_stripped(monkeypatch):
    bodies, _ = await _bulk_bodies("acknowledge", monkeypatch, reply=_all_ok, path_ids=[" p1 ", "p1", "p2\n"])
    assert bodies[0]["path_ids"] == ["p1", "p2"]


async def test_path_ids_with_filters_is_rejected(monkeypatch):
    bodies = await _bulk_bodies("dismiss", monkeypatch, path_ids=["a"], repository_id="r1")
    assert bodies == []


async def test_dismiss_requires_reason(monkeypatch):
    bodies = await _bulk_bodies("dismiss", monkeypatch, path_ids=["a"], reason="")
    assert bodies == []
