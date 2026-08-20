"""Rescored filter: the `rescored` recently-re-scored filter is forwarded through
the `list_attack_paths` MCP tool to GET /api/triage/paths.

Contract for the rescored query parameter:
    rescored: bool = Query(False)
    rescored_window_hours: int = Query(72, gt=0, le=8760)

These tests monkeypatch the `_get` HTTP seam and assert on the outbound params, so no
live server is needed. Default-off must send neither param (no behavior change).
"""

import json

import pytest

from latent_defense_mcp import server

pytestmark = pytest.mark.asyncio


def _capture_get(monkeypatch):
    """Patch server._get to record the outbound path + params and return an empty list."""
    seen = {}

    async def fake_get(path, *, _tool="", **params):
        seen["path"] = path
        seen["tool"] = _tool
        seen["params"] = params
        return {"items": [], "total": 0}

    monkeypatch.setattr(server, "_get", fake_get)
    return seen


class TestRescoredForward:
    async def test_rescored_true_is_forwarded(self, monkeypatch):
        """rescored=True → outbound request carries rescored=True (to /api/triage/paths)."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(rescored=True)

        assert seen["path"] == "/api/triage/paths"
        assert seen["tool"] == "list_attack_paths"
        assert seen["params"].get("rescored") is True

    async def test_default_off_sends_neither_param(self, monkeypatch):
        """Default (no rescored args) must not send `rescored` or `rescored_window_hours`
        — the deployed view is unchanged for every existing caller."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths()

        assert "rescored" not in seen["params"]
        assert "rescored_window_hours" not in seen["params"]

    async def test_rescored_false_explicit_sends_nothing(self, monkeypatch):
        """Explicit rescored=False is the same as omitting it — no param leaks."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(rescored=False)

        assert "rescored" not in seen["params"]
        assert "rescored_window_hours" not in seen["params"]

    async def test_window_hours_passthrough(self, monkeypatch):
        """rescored_window_hours is forwarded verbatim (server default 72 when omitted)."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(rescored=True, rescored_window_hours=48)

        assert seen["params"].get("rescored") is True
        assert seen["params"].get("rescored_window_hours") == 48

    async def test_window_over_cap_is_forwarded_verbatim_not_clamped(self, monkeypatch):
        """The server owns the range guard (gt=0, le=8760 → clean 422). The MCP layer is a
        transparent passthrough: it does NOT silently clamp an over-cap value to a
        different one (which would mask the caller's intent and the 422). A window of
        9000h is forwarded as 9000, letting the server return its 422."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(rescored=True, rescored_window_hours=9000)

        assert seen["params"].get("rescored_window_hours") == 9000

    async def test_window_hours_omitted_defers_to_server_default(self, monkeypatch):
        """Omitting window_hours must NOT send it, so the server's own default (72h)
        applies — the MCP layer does not hard-code a competing default."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(rescored=True)

        assert seen["params"].get("rescored") is True
        assert "rescored_window_hours" not in seen["params"]

    async def test_window_hours_without_rescored_is_still_forwarded(self, monkeypatch):
        """A window with rescored left False is forwarded as-is; the server ignores the
        window unless rescored is set (it computes the cutoff only when rescored=True),
        so this is a harmless transparent passthrough, not an MCP-side behavior."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(rescored_window_hours=24)

        assert "rescored" not in seen["params"]
        assert seen["params"].get("rescored_window_hours") == 24

    async def test_forward_does_not_disturb_other_filters(self, monkeypatch):
        """rescored coexists with the existing filters without dropping any of them."""
        seen = _capture_get(monkeypatch)

        await server.list_attack_paths(
            status="acknowledged",
            repository_id="repo-1",
            rescored=True,
            rescored_window_hours=12,
        )

        p = seen["params"]
        assert p.get("status") == "acknowledged"
        assert p.get("repository_id") == "repo-1"
        assert p.get("rescored") is True
        assert p.get("rescored_window_hours") == 12

    async def test_scope_unchanged_triage_read(self):
        """Adding the filter requires no extra write scope — list_attack_paths stays triage:read."""
        from latent_defense_mcp.errors import TOOL_SCOPES

        assert TOOL_SCOPES["list_attack_paths"] == "triage:read"

    async def test_no_notifications_tool(self):
        """Rescored filter (window hours) was dropped — no notifications tool should exist."""
        assert not hasattr(server, "list_wave_notifications")
