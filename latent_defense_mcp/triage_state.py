"""Triage state tools — local filesystem persistence for triage projects and user profiles.

Migrated from ``ld-local/graph-server/run.py``.  Uses flat JSON files under a
configurable state directory (``TRIAGE_STATE_DIR`` env var, default
``~/.latent-defense/triage-state``).
"""

from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any


def _dt_now() -> str:
    return datetime.now().isoformat()


def _state_dir() -> Path:
    return Path(
        os.environ.get(
            "TRIAGE_STATE_DIR",
            Path.home() / ".latent-defense" / "triage-state",
        )
    )


def register(mcp: Any) -> None:
    """Register triage state tools on *mcp*."""

    # ------------------------------------------------------------------
    # User profiles
    # ------------------------------------------------------------------

    @mcp.tool()
    async def triage_save_user(user: str) -> str:
        """Save or update the user profile for triage sessions.

        Persists across all sessions and projects — the system remembers who you are.

        Args:
            user: JSON object with user fields: name (str), role (str), org (str),
                  pain_points (str), preferences (dict), team (list), context (str).
        """
        data: dict = json.loads(user) if isinstance(user, str) else user
        state = _state_dir()
        (state / "users").mkdir(parents=True, exist_ok=True)
        user_id = data.get("name", "default").lower().replace(" ", "-")
        path = state / "users" / f"{user_id}.json"

        existing: dict = {}
        if path.exists():
            with open(path) as f:
                existing = json.load(f)

        for key, val in data.items():
            if isinstance(val, dict) and isinstance(existing.get(key), dict):
                existing[key].update(val)
            elif isinstance(val, list) and isinstance(existing.get(key), list):
                existing[key] = val
            else:
                existing[key] = val

        existing["_updated_at"] = _dt_now()
        existing.setdefault("_created_at", existing["_updated_at"])
        existing.setdefault("_session_count", 0)
        existing["_session_count"] += 1

        with open(path, "w") as f:
            json.dump(existing, f, indent=2, default=str)

        return json.dumps({
            "user_id": user_id,
            "role": existing.get("role"),
            "sessions": existing["_session_count"],
        })

    @mcp.tool()
    async def triage_load_user(name: str = "default") -> str:
        """Load a user profile. Returns everything the system knows about this user."""
        user_id = name.lower().replace(" ", "-")
        path = _state_dir() / "users" / f"{user_id}.json"
        if not path.exists():
            users_dir = _state_dir() / "users"
            if users_dir.exists():
                available = [p.stem for p in users_dir.glob("*.json")]
                if available:
                    return json.dumps({"error": f"User '{name}' not found", "available_users": available})
            return json.dumps({
                "error": "No user profile found. Use triage_save_user to create one.",
                "hint": "Tell me about yourself: name, role, org, and what's not working today.",
            })
        with open(path) as f:
            return json.dumps(json.load(f))

    # ------------------------------------------------------------------
    # Projects
    # ------------------------------------------------------------------

    @mcp.tool()
    async def triage_save_project(project_id: str, project: str) -> str:
        """Save or update a triage project.

        A project tracks one engagement: findings, audiences, results, work items, decisions.

        Args:
            project_id: Unique project identifier.
            project: JSON object with project fields (branch_id, sources, audiences,
                     user_context, finding_groups, results, work_items, decisions, history).
        """
        data: dict = json.loads(project) if isinstance(project, str) else project
        state = _state_dir()
        (state / "projects").mkdir(parents=True, exist_ok=True)
        path = state / "projects" / f"{project_id}.json"

        existing: dict = {}
        if path.exists():
            with open(path) as f:
                existing = json.load(f)

        for key, val in data.items():
            if isinstance(val, dict) and isinstance(existing.get(key), dict):
                existing[key].update(val)
            else:
                existing[key] = val

        existing["_updated_at"] = _dt_now()
        existing.setdefault("_created_at", existing["_updated_at"])
        existing.setdefault("history", [])

        with open(path, "w") as f:
            json.dump(existing, f, indent=2, default=str)

        pcs = existing.get("finding_groups", existing.get("preconditions", []))
        return json.dumps({
            "project_id": project_id,
            "branch_id": existing.get("branch_id", ""),
            "sources": len(existing.get("sources", [])),
            "audiences": len(existing.get("audiences", [])),
            "finding_groups": len(pcs),
            "work_items": len(existing.get("work_items", [])),
            "decisions": len(existing.get("decisions", [])),
            "updated_at": existing["_updated_at"],
        })

    @mcp.tool()
    async def triage_load_project(project_id: str) -> str:
        """Load a triage project with full state."""
        path = _state_dir() / "projects" / f"{project_id}.json"
        if not path.exists():
            listing = json.loads(await triage_list_projects())
            return json.dumps({"error": f"Project '{project_id}' not found", "available": listing})
        with open(path) as f:
            return json.dumps(json.load(f))

    @mcp.tool()
    async def triage_list_projects() -> str:
        """List all triage projects with summary status."""
        proj_dir = _state_dir() / "projects"
        if not proj_dir.exists():
            return json.dumps({"projects": []})
        projects: list[dict] = []
        for p in sorted(proj_dir.glob("*.json")):
            try:
                with open(p) as f:
                    data = json.load(f)
                pcs = data.get("finding_groups", data.get("preconditions", []))
                wis = data.get("work_items", [])
                projects.append({
                    "project_id": p.stem,
                    "branch_id": data.get("branch_id", ""),
                    "sources": len(data.get("sources", [])),
                    "groups_total": len(pcs),
                    "groups_open": sum(1 for pc in pcs if pc.get("status", "pending") == "pending"),
                    "groups_fixed": sum(1 for pc in pcs if pc.get("status") == "fixed"),
                    "groups_mitigated": sum(1 for pc in pcs if pc.get("status") in ("mitigated", "accepted")),
                    "work_items_total": len(wis),
                    "work_items_open": sum(1 for w in wis if w.get("status", "open") == "open"),
                    "decisions": len(data.get("decisions", [])),
                    "updated_at": data.get("_updated_at", ""),
                })
            except Exception:
                projects.append({"project_id": p.stem, "error": "corrupt"})
        return json.dumps({"projects": projects})

    @mcp.tool()
    async def triage_update_finding_group(project_id: str, group_id: str, update: str) -> str:
        """Update the status of a finding group within a project.

        Args:
            project_id: Project identifier.
            group_id: Finding group identifier.
            update: JSON object with fields to update (e.g. {"status": "fixed"}).
                    Valid statuses: pending, investigating, fixed, mitigated, accepted, deferred, wont_fix.
        """
        update_data: dict = json.loads(update) if isinstance(update, str) else update
        path = _state_dir() / "projects" / f"{project_id}.json"
        if not path.exists():
            return json.dumps({"error": f"Project '{project_id}' not found"})
        with open(path) as f:
            data = json.load(f)

        found = False
        for pc in data.get("finding_groups", data.get("preconditions", [])):
            if pc.get("id") == group_id:
                old_status = pc.get("status", "pending")
                pc.update(update_data)
                pc["_status_updated_at"] = _dt_now()
                found = True
                data.setdefault("history", []).append({
                    "timestamp": _dt_now(),
                    "action": "finding_group_updated",
                    "group_id": group_id,
                    "from_status": old_status,
                    "to_status": update_data.get("status", old_status),
                    "details": update_data,
                })
                break

        if not found:
            return json.dumps({"error": f"Finding group '{group_id}' not found"})

        data["_updated_at"] = _dt_now()
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return json.dumps({"project_id": project_id, "group_id": group_id, "updated": update_data})

    @mcp.tool()
    async def triage_add_work_item(project_id: str, work_item: str) -> str:
        """Add a work item to a project.

        Args:
            project_id: Project identifier.
            work_item: JSON object with fields: title (str), assignee (str),
                       group_ids (list), resolution (str), effort (str),
                       commands (list), context (str), status (str).
        """
        wi: dict = json.loads(work_item) if isinstance(work_item, str) else work_item
        path = _state_dir() / "projects" / f"{project_id}.json"
        if not path.exists():
            return json.dumps({"error": f"Project '{project_id}' not found"})
        with open(path) as f:
            data = json.load(f)

        wi["_created_at"] = _dt_now()
        wi.setdefault("status", "open")
        wi.setdefault("id", f"WI-{len(data.get('work_items', [])) + 1}")
        data.setdefault("work_items", []).append(wi)

        data.setdefault("history", []).append({
            "timestamp": _dt_now(),
            "action": "work_item_added",
            "work_item_id": wi["id"],
            "title": wi.get("title", ""),
            "assignee": wi.get("assignee", ""),
        })

        data["_updated_at"] = _dt_now()
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return json.dumps({"project_id": project_id, "work_item": wi})

    @mcp.tool()
    async def triage_add_decision(project_id: str, decision: str) -> str:
        """Record a risk decision on a project.

        Args:
            project_id: Project identifier.
            decision: JSON object with fields: group_ids (list),
                      decision (str: accept_risk/defer/escalate/investigate_more),
                      justification (str), control_chain (list),
                      review_date (str), decided_by (str), conditions (str).
        """
        dec: dict = json.loads(decision) if isinstance(decision, str) else decision
        path = _state_dir() / "projects" / f"{project_id}.json"
        if not path.exists():
            return json.dumps({"error": f"Project '{project_id}' not found"})
        with open(path) as f:
            data = json.load(f)

        dec["_created_at"] = _dt_now()
        dec.setdefault("id", f"DEC-{len(data.get('decisions', [])) + 1}")
        data.setdefault("decisions", []).append(dec)

        data.setdefault("history", []).append({
            "timestamp": _dt_now(),
            "action": "decision_recorded",
            "decision_id": dec["id"],
            "type": dec.get("decision", ""),
            "finding_groups": dec.get("group_ids", []),
        })

        data["_updated_at"] = _dt_now()
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)

        return json.dumps({"project_id": project_id, "decision": dec})

    @mcp.tool()
    async def triage_project_status(project_id: str) -> str:
        """Get a summary of where a project stands right now.

        Call at the start of every session to orient.
        """
        path = _state_dir() / "projects" / f"{project_id}.json"
        if not path.exists():
            return json.dumps({"error": f"Project '{project_id}' not found"})
        with open(path) as f:
            data = json.load(f)

        pcs = data.get("finding_groups", data.get("preconditions", []))
        wis = data.get("work_items", [])
        decs = data.get("decisions", [])

        pc_by_status: dict[str, list[str]] = {}
        for pc in pcs:
            s = pc.get("status", "pending")
            pc_by_status.setdefault(s, []).append(pc.get("id", "?"))

        wi_by_status: dict[str, list[dict]] = {}
        for wi in wis:
            s = wi.get("status", "open")
            wi_by_status.setdefault(s, []).append({"id": wi.get("id"), "title": wi.get("title", "")})

        upcoming_reviews: list[dict] = []
        for dec in decs:
            if dec.get("review_date"):
                upcoming_reviews.append({
                    "decision_id": dec["id"],
                    "review_date": dec["review_date"],
                    "finding_groups": dec.get("group_ids", []),
                    "decision": dec.get("decision", ""),
                })

        history = data.get("history", [])[-10:]
        unresolved_count = sum(
            1 for pc in pcs if pc.get("unresolved") and len(pc["unresolved"]) > 0
        )
        ready_count = sum(1 for pc in pcs if pc.get("readiness") == "remediation_ready")
        needs_investigation = sum(1 for pc in pcs if pc.get("readiness") == "investigation_needed")

        return json.dumps({
            "project_id": project_id,
            "updated_at": data.get("_updated_at", ""),
            "branch_id": data.get("branch_id", ""),
            "deployment_model": data.get("deployment_model", ""),
            "sources": len(data.get("sources", [])),
            "audiences": len(data.get("audiences", [])),
            "outputs": data.get("outputs", []),
            "finding_groups": {
                "total": len(pcs),
                "by_status": {s: len(ids) for s, ids in pc_by_status.items()},
                "remediation_ready": ready_count,
                "investigation_needed": needs_investigation,
                "unresolved_questions": unresolved_count,
            },
            "work_items": {
                "total": len(wis),
                "by_status": {s: len(items) for s, items in wi_by_status.items()},
                "open_items": wi_by_status.get("open", [])[:5],
                "blocked_items": wi_by_status.get("blocked", []),
            },
            "decisions": {
                "total": len(decs),
                "upcoming_reviews": sorted(upcoming_reviews, key=lambda r: r.get("review_date", ""))[:5],
            },
            "recent_history": history,
        })

    @mcp.tool()
    async def triage_get_workflow_args(project_id: str) -> str:
        """Get validated workflow args from a project.

        Bridges project state into workflow execution. Validates that all file
        paths exist and required fields are present.
        """
        path = _state_dir() / "projects" / f"{project_id}.json"
        if not path.exists():
            return json.dumps({"error": f"Project '{project_id}' not found"})
        with open(path) as f:
            data = json.load(f)

        user_context = data.get("user_context", {})
        user_name = data.get("_user", "")
        if user_name:
            user_path = _state_dir() / "users" / f"{user_name}.json"
            if user_path.exists():
                with open(user_path) as uf:
                    user_data = json.load(uf)
                if not user_context.get("pain_points") and user_data.get("pain_points"):
                    user_context["pain_points"] = user_data["pain_points"]

        channels = data.get("verification_channels", [])
        # No backwards-compat migration from legacy source_code — we don't know
        # HOW the user wants to access source code (local path vs GitHub API vs
        # other). The skill should ask explicitly during onboarding.

        args = {
            "profile_id": project_id,
            "branch_id": data.get("branch_id", ""),
            "sources": data.get("sources", []),
            "audiences": data.get("audiences", []),
            "user_context": user_context,
            "verification_channels": channels,
            "deployment_model": data.get("deployment_model", ""),
            "max_investigate": data.get("max_investigate", 9999),
            "output_dir": data.get("output_dir", "experiments/triage-output"),
        }

        errors: list[str] = []
        if not args["branch_id"]:
            errors.append("No branch_id in project. Use list_repositories / list_branches to find it.")
        if not args["sources"]:
            errors.append("No sources in project")
        else:
            for s in args["sources"]:
                sp = s.get("path", "")
                if sp and not Path(sp).exists():
                    errors.append(f"Source file not found: {sp}")
        if not args["audiences"]:
            errors.append("No audiences in project")

        if errors:
            return json.dumps({"error": "Project incomplete", "errors": errors, "args": args})

        gaps: list[dict] = []
        if not args["deployment_model"]:
            gaps.append({
                "field": "deployment_model",
                "impact": "Blast radius assessment will be generic",
                "question": "Is this multi-tenant or single-tenant? Managed service or self-hosted?",
            })
        if not args["verification_channels"]:
            gaps.append({
                "field": "verification_channels",
                "impact": (
                    "Investigation agents can only verify against graph context — "
                    "no source code, cloud CLI, or other tools to ground findings in evidence"
                ),
                "question": (
                    "What tools and access do you have that could help verify findings? "
                    "For example: GitHub org for source code, cloud CLI access (AWS/Azure/GCP), "
                    "kubectl contexts, IaC repos, security tools, documentation."
                ),
            })
        if not user_context.get("desired_outcomes"):
            gaps.append({
                "field": "user_context.desired_outcomes",
                "impact": "Reports will use generic structure",
                "question": "What do you need out of this? What decisions are you trying to make?",
            })
        for aud in args["audiences"]:
            if not aud.get("report_outline"):
                gaps.append({
                    "field": f"audiences[{aud.get('name', '?')}].report_outline",
                    "impact": f"Report for {aud.get('name', '?')} will use default structure",
                    "question": f"What should the report for {aud.get('name', '?')} look like?",
                })
        for src in args["sources"]:
            if not src.get("scanner_version") and not src.get("scan_date"):
                gaps.append({
                    "field": f"sources[{src.get('name', '?')}].scanner_metadata",
                    "impact": f"Report for {src.get('name', '?')} won't include scanner freshness info",
                    "question": f"What scanner version produced {src.get('name', '?')}, and when?",
                })

        return json.dumps({"status": "ready", "args": args, "gaps": gaps if gaps else None})
