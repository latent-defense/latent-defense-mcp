"""Tests for the ingest_detection MCP tool — raw-payload and legacy invocation modes."""

from __future__ import annotations

import json

import pytest

import latent_defense_mcp.server as srv


@pytest.fixture(autouse=True)
def _mock_post(monkeypatch):
    """Capture every _post call made by ingest_detection."""
    calls: list[tuple[str, dict]] = []

    async def fake_post(path, body, _tool=None):
        calls.append((path, body))
        return {"detection_id": "det-1", "status": "agent_dispatched", "source": body.get("source", "")}

    monkeypatch.setattr(srv, "_post", fake_post)
    return calls


@pytest.mark.asyncio
async def test_raw_payload_only(_mock_post):
    calls = _mock_post
    result = json.loads(await srv.ingest_detection(
        source="hackerone",
        raw_payload={"data": {"report": {"id": 123}}},
    ))
    assert result["status"] == "agent_dispatched"
    assert len(calls) == 1
    _, body = calls[0]
    assert body["source"] == "hackerone"
    assert body["raw_payload"] == {"data": {"report": {"id": 123}}}
    assert "affected_resource" not in body
    assert "severity" not in body


@pytest.mark.asyncio
async def test_legacy_fields(_mock_post):
    calls = _mock_post
    result = json.loads(await srv.ingest_detection(
        source="vulnerability_scanner",
        severity="high",
        affected_resource_type="ec2_instance",
        affected_resource_id="i-abc123",
        title="CVE-2026-1234",
        cve="CVE-2026-1234",
    ))
    assert result["status"] == "agent_dispatched"
    _, body = calls[0]
    assert body["severity"] == "high"
    assert body["affected_resource"] == {"type": "ec2_instance", "identifier": "i-abc123"}
    assert body["title"] == "CVE-2026-1234"
    assert body["cve"] == "CVE-2026-1234"
    assert "raw_payload" not in body


@pytest.mark.asyncio
async def test_neither_provided_returns_error(_mock_post):
    calls = _mock_post
    result = json.loads(await srv.ingest_detection(source="test"))
    assert "error" in result
    assert len(calls) == 0


@pytest.mark.asyncio
async def test_both_provided_raw_takes_precedence(_mock_post):
    """When raw_payload is provided, legacy fields are NOT forwarded — the
    server-side parser extracts everything from raw_payload, preserving
    metadata (CWE, CVSS, reporter) that a sparse legacy resource would overwrite."""
    calls = _mock_post
    result = json.loads(await srv.ingest_detection(
        source="hackerone",
        severity="critical",
        affected_resource_type="url",
        affected_resource_id="api.example.com",
        raw_payload={"data": {"report": {"id": 456}}},
    ))
    assert result["status"] == "agent_dispatched"
    _, body = calls[0]
    assert body["raw_payload"] == {"data": {"report": {"id": 456}}}
    assert "affected_resource" not in body, "legacy resource must not override parsed metadata"
    assert "severity" not in body, "legacy severity must not override parsed severity"


@pytest.mark.asyncio
async def test_empty_raw_payload_requires_legacy(_mock_post):
    calls = _mock_post
    result = json.loads(await srv.ingest_detection(source="test", raw_payload={}))
    assert "error" in result
    assert len(calls) == 0


@pytest.mark.asyncio
async def test_partial_legacy_requires_all_three(_mock_post):
    calls = _mock_post
    result = json.loads(await srv.ingest_detection(
        source="test", severity="high",
    ))
    assert "error" in result
    assert len(calls) == 0
