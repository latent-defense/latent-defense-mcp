---
name: prioritize-findings-report
description: "Prioritized report from a findings export: what to fix this week, what's safe to deprioritize, and what needs the user's input, grouped by shared fix and verified against the deployed environment. Use after /triage completes, or on a new findings JSON."
user-invocable: true
disable-model-invocation: false
---

# Prioritize Findings Report

Turn a list of findings or vulnerabilities into a prioritized list of actions: which findings are actually exploitable as deployed, which are safe to deprioritize, and the evidence for each.

Follow-ups in the same session: `/report-group-deep-dive` for any group in the report.

## Before you start

- Check authentication first with `connection_status()`. If it has expired, tell the user and stop: don't load the graph or continue on cached data.
- Load the user and project (`triage_load_user`, `triage_list_projects`, `triage_load_project`) and the graph (`load_graph_energies`).
- Check `pipeline_status(project_id)`. **If `/triage` has already completed for this project and the user hasn't attached new findings, don't re-run it.** Skip to step 2 and build the report from the findings store (`list_groups`, `query_findings`, `get_investigation`).
- If the user attached a new export, start at step 0. Re-running the pipeline is checkpoint-driven, so only new work runs.
- If `get_investigation` marks a group `stale`, its findings changed after its verdict was saved (added, removed, or re-exported with new content). Explore and verify that group again from its current findings (steps 2–4) before reporting it; don't present the old verdict as covering them.

## How to work

0. Load the findings with `append_findings`, so findings, groups and investigations from earlier runs are kept and only new findings need work. Use `load_findings` only if there's no earlier store for this project.
1. Run `/triage` on the findings. Flag duplicates (same issue at the same location) and link each to one primary finding. Group the rest by shared fix.
2. For each group, find the code in the graph: search nodes by repository, file path and route (`grep_nodes`), and note the deployed service it maps to. If you can't map it, mark the group Inconclusive and say what mapping is missing.
3. For each group, run `/investigate` and follow it through the graph from the entry point (`energy_node_neighborhood`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_momentum_path`). Use `energy_defenses` to find the controls that block movement. Evaluate every candidate path, and keep the ones that fail. Save every path you evaluated, refuted ones included, in the group's `explore_result` (`save_investigation`).
4. Give each path and each group one verdict:
   - **Confirmed:** every step holds in the deployed environment
   - **Refuted:** a step fails; name the control or config that blocks it. Only refute as "not deployed" if your check covered the account, project or cluster where it would run. A missing workflow or empty state elsewhere isn't proof: mark it Inconclusive and say which scope wasn't checked.
   - **Conditional:** every step holds except one named condition you can't see
   - **Inconclusive:** not enough data to decide; say what's missing

   If the triage database returns "partial", split it into Conditional or Inconclusive. When you save the group's verdict, include each finding's own verdict in the evidence, so the per-finding counts come from what's stored. If a group from an earlier run has no per-finding verdicts stored, investigate that group to fill them in rather than inferring them.
5. Connected doesn't mean affected. Only count a relationship as impact if there's a plausible attacker mechanism and enough permissions.
6. Cite evidence for every claim (node, config, policy or file). Don't guess.
7. If you find an issue while investigating that none of the findings cover, add it as its own group marked 🆕 (newly discovered). Always re-check it against the deployed environment, even if an earlier run already found it, then give it a verdict and priority, and rank it alongside the other groups in the section its verdict belongs to. Don't list it as a remediation unless it's verified.

## Output format

Return the report in exactly this format.

Use correct singular and plural throughout (1 group, 1 finding, 2 groups).

```
## Summary
Of <N> findings, sorted into remediation groups (findings that share one
fix):
- 🔴 Confirmed: <g> groups encompassing <n> findings need action
- 🟢 Refuted or informational: <g> groups encompassing <n> findings are
  safe to deprioritize
- 🟡 Conditional or Inconclusive: <g> groups encompassing <n> findings need
  your input
- 🔁 Duplicates: <n> findings duplicate another finding
- 🆕 Newly discovered: <g> groups found outside your findings (included in
  the group counts above, not in <N>)
The finding counts add up to <N>. The group counts match the number of
groups listed in each section below, newly discovered groups included.

## Compared with your pipeline
Of <N> findings, against your scanners' severity and CVSS rating:
- ✅ Agree: <n> findings (our verdict supports it)
- ⬆️ Raised: <n> findings (worse as deployed, e.g. it crosses tenants)
- ⬇️ Lowered: <n> findings (less exploitable as deployed, e.g. a control
  blocks it)
- ⚪ Can't compare: <n> findings (inconclusive)

Biggest changes: up to 5, raised first, then the largest severity change.
The rest are in the JSON.
- ⬆️ [MEDIUM → CRITICAL] <finding ID>: <why, in one line>
- ⬇️ [CRITICAL → MEDIUM] <finding ID>: <why, in one line>
```

Title each group as one plain sentence that answers "What should I change, and why?": the change first, then what it stops. For example: "Require authentication on the internal metrics API, so workloads in the build namespace can no longer read deployment secrets through it." Don't use arrows or labels in the title.

A group takes its strongest finding's verdict, in this order: Confirmed, Conditional, Inconclusive, Refuted.

Only list a group under Fix this week if it's verified: its verdict is Confirmed, with evidence for every step of at least one path, and its priority is Low or higher. Confirmed groups with Informational priority (real, but intentional or already compensated) go under Safe to deprioritize. Anything you couldn't verify goes under Needs your input, with what's missing. This applies to newly discovered groups too.

```
## 🔴 Fix this week
Sort by priority, highest first, and start each line with the priority
in capitals: [CRITICAL], [HIGH], [MEDIUM] or [LOW].

1. [HIGH] <what to change>, so <what it stops or protects>
   Why: <why this priority, in one line>
   Findings in this group: <n> (<n> confirmed · <n> refuted ·
   <n> conditional · <n> inconclusive)
   Recommendation: <what to do this week, in one line>
2. [MEDIUM] ...

For a newly discovered group, put 🆕 after the priority, and replace the
finding counts with how you found it and why no finding covers it:
3. [HIGH] 🆕 <what to change>, so <what it stops or protects>
   Why: <why this priority, in one line>
   Found outside your findings: <how you found it>
   Recommendation: <what to do this week, in one line>

## 🟢 Safe to deprioritize
Refuted (not exploitable as deployed)
<#>. <what these findings are>: <the control or config that blocks it>

Confirmed, but no fix needed
<#>. <what these findings are>: <why, e.g. intentional, and which controls
    compensate>

## 🟡 Needs your input
Use the same group format as Fix this week. Sort by what's at stake,
highest first, and start each line with the priority the group would have
if confirmed: [CRITICAL], [HIGH], [MEDIUM] or [LOW]. After the priority,
tag what's blocking it: 🔑 if you couldn't check it because you didn't
have access, or ❓ if it depends on a fact only we know that isn't in any
system you can read. End each group with one concrete ask. For 🔑, ask for
the smallest check that would settle it: one read-only command we can run
ourselves, or the narrowest read-only scope. Never ask for broad admin
access.

<#>. [HIGH] 🔑 <what to change>, so <what it stops or protects>
    Why: <why this priority if confirmed, in one line>
    Findings in this group: <n> (<n> confirmed · <n> refuted ·
    <n> conditional · <n> inconclusive)
    Couldn't check: <what you couldn't verify, in one line>
    Grant us: <the smallest check that would settle it, e.g. "list active
    tokens with prefix ghp_ in the org", not org-admin access>, then rerun

<#>. [MEDIUM] ❓ <what to change>, so <what it stops or protects>
    Why: <why this priority if confirmed, in one line>
    Findings in this group: <n> (<n> confirmed · <n> refuted ·
    <n> conditional · <n> inconclusive)
    Couldn't check: <what you couldn't verify, in one line>
    Answer: <one question we can reply to directly, yes/no where possible>
```

Keep all the evidence and every path you evaluated, so the user can ask about any group. Save the full results as JSON keyed by the original finding ID.

## Adding new findings

When the user runs the report again with a new export, step 0 adds the new findings to the earlier ones (`append_findings`), so existing groups and investigations are kept and only the new findings are investigated. The result is one up-to-date report instead of starting over.

## After the report

Offer: "Want the deep dive on any of these groups? Name it or describe it, e.g. 'the metrics API one'." → `/report-group-deep-dive`
