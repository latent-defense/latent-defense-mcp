"""Tests for bulk_update_paths default status-filter behaviour (LD-2001).

Verifies that each action defaults to its action-compatible source statuses
when no status_filter is supplied, preventing predictable state-machine failures.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import latent_defense_mcp.server as srv

pytestmark = pytest.mark.asyncio

_EMPTY_PAGE = {"items": [], "total": 0}


async def _bulk(action: str, status_filter: str = "", monkeypatch=None, **kwargs):
    """Call bulk_update_paths with a mocked _get/_patch/_post and capture list params."""
    captured_list_params: list[dict] = []

    async def fake_get(path, _tool=None, **params):
        captured_list_params.append(dict(params))
        return _EMPTY_PAGE

    async def fake_patch(path, body, _tool=None):
        return {}

    async def fake_post(path, body, _tool=None):
        return {}

    monkeypatch.setattr(srv, "_get", fake_get)
    monkeypatch.setattr(srv, "_patch", fake_patch)
    monkeypatch.setattr(srv, "_post", fake_post)

    await srv.bulk_update_paths(
        action=action,
        status_filter=status_filter,
        reason="risk_accepted" if action == "dismiss" else "",
        **kwargs,
    )
    return captured_list_params


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
