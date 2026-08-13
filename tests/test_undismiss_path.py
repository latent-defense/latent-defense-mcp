"""Tests for the undismiss_path MCP tool (LD-2256, spec §E4).

undismiss_path reopens a dismissed (false_positive) attack path back into the
triage queue. There is NO dedicated /undismiss endpoint (WS-B B1/LD-2244 was
cancelled): the tool is a thin wrapper over the existing
PATCH /api/triage/paths/{id}/status, moving the path to `acknowledged`
(a valid false_positive → acknowledged FORWARD_TRANSITION that clears the
dismiss fields server-side). The reason/note are attached to the resulting
status_change event so the reopen is attributed + auditable.

Covered:
  1. Argument validation (missing path_id / reason).
  2. Correct PATCH payload: status=acknowledged + reason carried on metadata.
  3. 404 on unknown path surfaces a "not found" error.
  4. 403 maps to the triage:write scope (via TOOL_SCOPES).
  5. TOOL_SCOPES registration.
  6. _tool string == function name (telemetry/error attribution convention).
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock

import latent_defense_mcp.server as srv
from latent_defense_mcp.errors import TOOL_SCOPES, McpApiError

pytestmark = pytest.mark.asyncio


# ── helpers ──────────────────────────────────────────────────────────────────


def _response(status_code: int, data: dict | None = None) -> MagicMock:
    r = MagicMock(
        status_code=status_code,
        is_success=200 <= status_code < 300,
        content=b"x" if data is not None else b"",
    )
    r.json.return_value = data if data is not None else {}
    r.headers = {}
    r.text = json.dumps(data) if data is not None else ""
    return r


def _install_http(monkeypatch, response: MagicMock):
    """Wire srv._http to a mock httpx client and capture PATCH calls."""
    captured: list[dict] = []

    async def fake_patch(path, json=None, **kw):
        captured.append({"path": path, "body": json})
        return response

    client = AsyncMock()
    client.patch = fake_patch

    async def fake_http():
        return client

    monkeypatch.setattr(srv, "_http", fake_http)
    monkeypatch.setattr(srv, "_client", None)
    return captured


# ── argument validation ──────────────────────────────────────────────────────


async def test_missing_path_id_returns_error(monkeypatch):
    captured = _install_http(monkeypatch, _response(200, {}))
    out = json.loads(await srv.undismiss_path(path_id="", reason="reopened_after_review"))
    assert "error" in out
    assert "path_id" in out["error"]
    # No HTTP call should have been made.
    assert captured == []


async def test_missing_reason_returns_error(monkeypatch):
    captured = _install_http(monkeypatch, _response(200, {}))
    out = json.loads(await srv.undismiss_path(path_id="p-1", reason=""))
    assert "error" in out
    assert "reason" in out["error"]
    assert captured == []


async def test_whitespace_only_args_rejected(monkeypatch):
    """Whitespace-only path_id/reason must not produce a malformed PATCH or a blank audit reason."""
    captured = _install_http(monkeypatch, _response(200, {}))
    out1 = json.loads(await srv.undismiss_path(path_id="   ", reason="reopened_after_review"))
    assert "path_id" in out1.get("error", "")
    out2 = json.loads(await srv.undismiss_path(path_id="p-1", reason="   "))
    assert "reason" in out2.get("error", "")
    assert captured == []


# ── correct PATCH payload ────────────────────────────────────────────────────


async def test_patch_payload_status_acknowledged_and_reason(monkeypatch):
    path = _response(200, {"path_id": "p-1", "status": "acknowledged"})
    captured = _install_http(monkeypatch, path)

    out = json.loads(
        await srv.undismiss_path(path_id="p-1", reason="reopened_after_review")
    )
    assert out["status"] == "acknowledged"

    assert len(captured) == 1
    call = captured[0]
    assert call["path"] == "/api/triage/paths/p-1/status"
    body = call["body"]
    assert body["status"] == "acknowledged"
    # The reason must be carried through so it lands on the status_change event.
    assert body["metadata"]["reopen_reason"] == "reopened_after_review"


async def test_note_included_when_provided(monkeypatch):
    captured = _install_http(monkeypatch, _response(200, {"status": "acknowledged"}))
    await srv.undismiss_path(
        path_id="p-1", reason="risk_reassessed", note="control was removed"
    )
    body = captured[0]["body"]
    assert body["note"] == "control was removed"
    assert body["metadata"]["reopen_reason"] == "risk_reassessed"


async def test_note_omitted_when_absent(monkeypatch):
    captured = _install_http(monkeypatch, _response(200, {"status": "acknowledged"}))
    await srv.undismiss_path(path_id="p-1", reason="risk_reassessed")
    assert "note" not in captured[0]["body"]


# ── error mapping ────────────────────────────────────────────────────────────


async def test_unknown_path_raises_404(monkeypatch):
    _install_http(monkeypatch, _response(404, {"detail": "Path p-x not found"}))
    with pytest.raises(McpApiError) as exc:
        await srv.undismiss_path(path_id="p-x", reason="reopened_after_review")
    msg = str(exc.value)
    assert "not found" in msg.lower()
    assert "undismiss_path" in msg  # tool attribution


async def test_403_maps_to_triage_write_scope(monkeypatch):
    _install_http(monkeypatch, _response(403, {"detail": "forbidden"}))
    with pytest.raises(McpApiError) as exc:
        await srv.undismiss_path(path_id="p-1", reason="reopened_after_review")
    msg = str(exc.value)
    assert "triage:write" in msg
    assert "undismiss_path" in msg


# ── conventions ──────────────────────────────────────────────────────────────


async def test_registered_in_tool_scopes_as_triage_write():
    assert TOOL_SCOPES.get("undismiss_path") == "triage:write"
