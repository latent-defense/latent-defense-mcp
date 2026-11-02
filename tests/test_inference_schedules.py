"""Tests for the inference schedule MCP tools (LD-3714).

inference-trigger's ScheduleCreateRequest is {name, cron, scope: {branch_labels, all_branches},
enabled} and ignores unknown fields, so a flat body silently creates a disabled schedule with an
empty scope. It keys schedules by sched_<name>, so a second create with the same name replaces the
first.
"""

from __future__ import annotations

import json

import pytest

import latent_defense_mcp.server as srv
from latent_defense_mcp.errors import McpApiError


class _Calls(list):
    """Recorded (method, path, body) calls, plus the schedules the fake list endpoint returns."""

    def __init__(self):
        super().__init__()
        self.existing: list[dict] = []


@pytest.fixture(autouse=True)
def _calls(monkeypatch):
    """Capture every _get / _post / _patch / _delete call made by the schedule tools."""
    calls = _Calls()
    existing = calls.existing

    async def fake_get(path, _tool=None, **params):
        calls.append(("GET", path, None))
        return list(existing)

    async def fake_post(path, body, _tool=None):
        calls.append(("POST", path, body))
        return {"schedule_id": f"sched_{body['name']}", **body}

    async def fake_patch(path, body, _tool=None):
        calls.append(("PATCH", path, body))
        return {"schedule_id": path.rsplit("/", 1)[-1], **body}

    async def fake_delete(path, _tool=None):
        calls.append(("DELETE", path, None))
        return {"status": "ok"}

    monkeypatch.setattr(srv, "_get", fake_get)
    monkeypatch.setattr(srv, "_post", fake_post)
    monkeypatch.setattr(srv, "_patch", fake_patch)
    monkeypatch.setattr(srv, "_delete", fake_delete)
    return calls


ACCEPTED_CRONS = ["0 3 * * *", "*/15 0-6 1,15 * mon-fri", "0 */6 * * *", "30 2 * jan-mar,dec sun",
                  "0 0 1/7 * *", "59 23 31 12 SAT", "0-30/10 * * * *"]


def _posts(calls):
    return [c for c in calls if c[0] == "POST"]


@pytest.mark.asyncio
async def test_create_sends_scope_object_and_enabled(_calls):
    result = json.loads(await srv.create_inference_schedule(
        name="main-survey", cron="0 */6 * * *", branch_labels='["main"]',
    ))
    method, path, body = _posts(_calls)[0]
    assert (method, path) == ("POST", "/api/inference-schedules/")
    assert body == {
        "name": "main-survey",
        "cron": "0 */6 * * *",
        "scope": {"branch_labels": ["main"], "all_branches": False},
        "enabled": True,
    }
    assert result["schedule_id"] == "sched_main-survey"


@pytest.mark.asyncio
async def test_create_all_branches_ignores_labels_and_starts_disabled(_calls):
    await srv.create_inference_schedule(
        name="everything", cron="0 3 * * *", branch_labels='["main"]', all_branches=True,
    )
    body = _posts(_calls)[0][2]
    assert body["scope"] == {"branch_labels": [], "all_branches": True}
    assert body["enabled"] is False


@pytest.mark.asyncio
async def test_create_all_branches_enabled_only_when_asked(_calls):
    await srv.create_inference_schedule(
        name="everything", cron="0 3 * * *", all_branches=True, enabled=True,
    )
    assert _posts(_calls)[0][2]["enabled"] is True


@pytest.mark.asyncio
async def test_create_can_start_disabled(_calls):
    await srv.create_inference_schedule(
        name="paused", cron="0 3 * * *", branch_labels='["main"]', enabled=False,
    )
    assert _posts(_calls)[0][2]["enabled"] is False


@pytest.mark.asyncio
async def test_create_rejects_empty_scope_without_calling_api(_calls):
    with pytest.raises(McpApiError, match="scope is empty"):
        await srv.create_inference_schedule(name="nothing", cron="0 3 * * *")
    assert _calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("labels", ['"main"', '[1, 2]', '{"main": true}'])
async def test_create_rejects_non_string_list_labels(_calls, labels):
    with pytest.raises(McpApiError, match="JSON array of strings"):
        await srv.create_inference_schedule(name="bad", cron="0 3 * * *", branch_labels=labels)
    assert _calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("labels", ['[""]', '["main", "  "]'])
async def test_create_rejects_blank_labels(_calls, labels):
    with pytest.raises(McpApiError, match="blank labels"):
        await srv.create_inference_schedule(name="bad", cron="0 3 * * *", branch_labels=labels)
    assert _calls == []


@pytest.mark.asyncio
async def test_create_rejects_invalid_json_labels(_calls):
    with pytest.raises(McpApiError, match="Invalid JSON"):
        await srv.create_inference_schedule(name="bad", cron="0 3 * * *", branch_labels="[main")
    assert _calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cron", [
    "0 3 * *", "0 3 * * * *", "", "0 3 * * ;rm", "every day",
    "0 0 ? * 1#2", "60 0 * * *", "0 0 * * 7",  # CronTrigger rejects these after the schedule is stored
    "0 2 * * 1", "0 2 * * */2",                # numeric weekdays: CronTrigger counts from Monday = 0
    "0 0 32 * *", "0 5-2 * * *", "*/0 * * * *", "*/60 * * * *", "0 0 * * fri-mon", "0 0 * foo *",
])
async def test_create_rejects_invalid_cron(_calls, cron):
    with pytest.raises(McpApiError, match="five-field cron"):
        await srv.create_inference_schedule(name="bad", cron=cron, branch_labels='["main"]')
    assert _calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("cron", ACCEPTED_CRONS)
async def test_create_accepts_cron_forms(_calls, cron):
    await srv.create_inference_schedule(name="ok", cron=cron, branch_labels='["main"]')
    assert _posts(_calls)[0][2]["cron"] == cron


@pytest.mark.asyncio
async def test_create_refuses_same_name_without_replace(_calls):
    _calls.existing.append({"schedule_id": "sched_main-survey", "name": "main-survey"})
    with pytest.raises(McpApiError, match="already exists"):
        await srv.create_inference_schedule(name="main-survey", cron="0 3 * * *", branch_labels='["main"]')
    assert _posts(_calls) == []


@pytest.mark.asyncio
async def test_create_replaces_same_name_when_asked(_calls):
    _calls.existing.append({"schedule_id": "sched_main-survey", "name": "main-survey"})
    await srv.create_inference_schedule(
        name="main-survey", cron="0 3 * * *", branch_labels='["main"]', replace=True,
    )
    assert [c[0] for c in _calls] == ["POST"]


@pytest.mark.asyncio
@pytest.mark.parametrize("enabled", [True, False])
async def test_set_enabled_patches_schedule(_calls, enabled):
    result = json.loads(await srv.set_inference_schedule_enabled("sched_main-survey", enabled))
    assert _calls == [("PATCH", "/api/inference-schedules/sched_main-survey", {"enabled": enabled})]
    assert result["enabled"] is enabled


@pytest.mark.asyncio
async def test_schedule_id_is_url_encoded(_calls):
    await srv.set_inference_schedule_enabled("sched_prod/main?x", True)
    await srv.delete_inference_schedule("sched_prod/main?x")
    assert [c[1] for c in _calls] == [
        "/api/inference-schedules/sched_prod%2Fmain%3Fx",
        "/api/inference-schedules/sched_prod%2Fmain%3Fx",
    ]


def _backend_trigger(cron):
    """Build the trigger the way inference-trigger's InferenceScheduler._add_job does."""
    from apscheduler.triggers.cron import CronTrigger
    minute, hour, day, month, day_of_week = cron.split()
    return CronTrigger(minute=minute, hour=hour, day=day, month=month, day_of_week=day_of_week)


@pytest.mark.parametrize("cron", ACCEPTED_CRONS)
def test_accepted_crons_build_a_backend_trigger(cron):
    assert srv._cron_problem(cron) is None
    _backend_trigger(cron)


def test_every_cron_the_tool_accepts_builds_a_backend_trigger():
    import random
    pieces = ["*", "*/1", "*/7", "*/59", "*/60", "0", "1", "5", "6", "7", "12", "23", "24", "31", "32",
              "59", "60", "1-5", "5-1", "0-59/30", "2-4/3", "1/5", "3/0", "mon", "sun", "mon-fri", "fri-mon",
              "jan", "jan-mar", "dec-jan", "xyz", "?", "1#2", "last", "L", "1,15", "mon,wed"]
    rng = random.Random(3714)
    accepted = 0
    for _ in range(20000):
        cron = " ".join(rng.choice(pieces) for _ in range(5))
        if srv._cron_problem(cron) is None:
            accepted += 1
            _backend_trigger(cron)  # raises if the scheduler would reject what the tool sent
    assert accepted > 50


@pytest.mark.asyncio
async def test_create_with_repository_ids_starts_paused_then_switches_on(_calls):
    await srv.create_inference_schedule(
        name="drata", cron="0 * * * *", branch_labels='["main"]', repository_ids='["repo_ld_1"]',
    )
    post = _posts(_calls)[0][2]
    assert post["scope"]["repository_ids"] == ["repo_ld_1"] and post["enabled"] is False
    assert _calls[-1] == ("PATCH", "/api/inference-schedules/sched_drata", {"enabled": True})


@pytest.mark.asyncio
async def test_create_with_repository_ids_stays_paused_when_asked(_calls):
    await srv.create_inference_schedule(
        name="drata", cron="0 * * * *", branch_labels='["main"]', repository_ids='["repo_ld_1"]',
        enabled=False,
    )
    assert not [c for c in _calls if c[0] == "PATCH"]


@pytest.mark.asyncio
async def test_create_removes_a_schedule_whose_server_dropped_the_repository_filter(_calls, monkeypatch):
    async def old_server_post(path, body, _tool=None):  # an inference-trigger without LD-3714
        _calls.append(("POST", path, body))
        scope = {k: v for k, v in body["scope"].items() if k != "repository_ids"}
        return {"schedule_id": f"sched_{body['name']}", **body, "scope": scope}

    monkeypatch.setattr(srv, "_post", old_server_post)
    with pytest.raises(McpApiError, match="does not support repository_ids"):
        await srv.create_inference_schedule(
            name="drata", cron="0 * * * *", branch_labels='["main"]', repository_ids='["repo_ld_1"]',
        )
    assert _calls[-1] == ("DELETE", "/api/inference-schedules/sched_drata", None)
    assert not [c for c in _calls if c[0] == "PATCH"]


@pytest.mark.asyncio
@pytest.mark.parametrize("repos", ['"repo_ld_1"', '[1]', '[" "]', "[repo"])
async def test_create_rejects_bad_repository_ids(_calls, repos):
    with pytest.raises(McpApiError):
        await srv.create_inference_schedule(
            name="bad", cron="0 * * * *", branch_labels='["main"]', repository_ids=repos,
        )
    assert _calls == []


@pytest.mark.asyncio
async def test_rejected_filtered_replace_puts_the_existing_schedule_back(_calls, monkeypatch):
    # Review of #68: replace=True had already overwritten "daily"; the cleanup deleted it.
    original = {"schedule_id": "sched_daily", "name": "daily", "cron": "0 2 * * *",
                "scope": {"branch_labels": ["main"], "all_branches": False}, "enabled": True}
    _calls.existing.append(original)

    async def old_server_post(path, body, _tool=None):
        _calls.append(("POST", path, body))
        scope = {k: v for k, v in body["scope"].items() if k != "repository_ids"}
        return {"schedule_id": f"sched_{body['name']}", **body, "scope": scope}

    monkeypatch.setattr(srv, "_post", old_server_post)
    with pytest.raises(McpApiError, match="put back as it was"):
        await srv.create_inference_schedule(
            name="daily", cron="0 3 * * *", branch_labels='["main"]', repository_ids='["repo_a"]',
            replace=True,
        )
    assert not [c for c in _calls if c[0] in ("DELETE", "PATCH")]
    assert _calls[-1] == ("POST", "/api/inference-schedules/", {
        "name": "daily", "cron": "0 2 * * *", "scope": original["scope"], "enabled": True})
