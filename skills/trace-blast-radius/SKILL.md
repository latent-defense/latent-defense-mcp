---
name: trace-blast-radius
description: "Trace how far one vulnerability, finding, CVE or root cause reaches in the deployed environment: every attack path it opens, ranked, with the most critical one broken down. Use when the user asks about a specific finding, path or root cause."
user-invocable: true
disable-model-invocation: false
---

# Trace Blast Radius

Put in one vulnerability or a known root cause, and get back the attack paths it opens and its blast radius in the deployed environment.

- **Input:** one vulnerability (a pasted finding, a CVE, or a few lines on what's wrong and where) or a root cause (one line describing the underlying mistake). A finding is one place in the code where something is wrong. A root cause is the mistake behind many findings, e.g. "a shared service token scoped to the whole tenant rather than one integration" behind several route-level findings. Fixing the root cause closes all of them.
- Attaching the findings JSON is optional. If a triage project already exists for this environment, its findings store counts as the attached findings.

Follow-up in the same session: `/trace-blast-radius-all` for every path tried, dead ends included.

## Before you start

Check authentication first with `connection_status()`. If it has expired, tell the user and stop: don't load the graph or continue on cached data. Load the user and project (`triage_load_user`, `triage_list_projects`, `triage_load_project`) and the graph (`load_graph_energies`).

## How to work

1. Find where it lives in the graph: search nodes and edges for the affected code, routes and services (`grep_nodes`, `grep_edges`). If you can't map it, say what mapping is missing.
2. Run `/investigate` with this as the question. Follow it from each entry point (`energy_node_neighborhood`, `energy_lowest_paths`, `energy_trace_to_target`, `energy_momentum_path`) and evaluate every candidate path. Use `energy_defenses` to find the controls that block movement. Save every path you evaluated, refuted ones included, with `save_investigation` under a group named for this input.
3. If the user attached findings, or a triage project exists, check which findings sit on each path.
4. Give each path one verdict: Confirmed (every step holds), Refuted (a step fails; name what blocks it), Conditional (you verified every step except one named condition; if you couldn't see the deployed asset itself, such as the running image or the live cloud resource, it's Inconclusive), or Inconclusive (you couldn't trace the path; say what's missing).
5. Connected doesn't mean affected: only count a relationship as impact if there's a plausible attacker mechanism and enough permissions. Cite evidence for every step.

Only use evidence from the investigation. If something wasn't checked, say so instead of filling it in. Keep all the evidence and every path you evaluated, so the user can ask about any of them.

## Output format

Return the answer in exactly this format. Always write the verdict after its emoji: 🔴 Confirmed, 🟡 Conditional, ⚪ Inconclusive or 🟢 Refuted. Priorities are [CRITICAL], [HIGH], [MEDIUM], [LOW] or [INFO]. Keep every line short. Use correct singular and plural (1 group, 1 finding, 1 path).

```
## [HIGH] 🔴 Confirmed · <one plain sentence on what an attacker could do, e.g. "A
   webhook token can delete another integration's records with no
   audit trail">
Why this priority: <one line>
Paths evaluated: <n> (<n> confirmed · <n> refuted · <n> conditional ·
<n> inconclusive)
Findings it explains: <finding IDs, or none>

## Paths found
Sorted by priority, highest first. Up to 5; the rest are in the full list.
1. [HIGH] 🔴 Confirmed · <entry> → <impact>: <what the attacker gains,
   in one line>
2. [MEDIUM] 🟡 Conditional · ...

## Most critical path (path 1)
- 🎯 Starts with: <what the attacker controls: a user, token, workload or
  service>
- 📍 Reaches: <systems, identities or datasets>
- Can: <read | modify | delete | administer | execute code>
- Crosses: <services, environments, accounts or customer tenants, or
  "no boundaries">
- Business impact: <the sensitive data or critical operations affected>
- Gains: <what they can do that their starting access didn't allow>
- Blast radius: direct <...> · supported downstream <...> · conditional
  <...> (tag each potential or observed)
- Reachable: <yes | no | only if ...>
- 🛡️ Stopped by: <the controls that block further movement, and what extra
  access they'd need>
- Evidence: <a reference for each step>
- Related findings: <finding IDs on this path, or none>
```

## After the trace

Offer: "Want to see every path I tried, including the dead ends and the controls that stopped them?" → `/trace-blast-radius-all`
