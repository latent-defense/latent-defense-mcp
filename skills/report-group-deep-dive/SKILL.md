---
name: report-group-deep-dive
description: "Deep dive on one remediation group from a triage or prioritized findings report: per-finding verdicts, the most critical attack path, the evidence, and the one fix that closes the group. Reads from the findings store, does not re-run triage."
user-invocable: true
disable-model-invocation: false
---

# Report Group Deep Dive

The deep dive on one remediation group from `/triage` or `/prioritize-findings-report`. The user names the group by its title or describes it, e.g. "the metrics API one".

## How to work

Read this group from the findings store (`list_groups`, `query_findings` for the group, `get_investigation`) rather than from memory, so the findings, verdicts and priority match the report. **Don't re-run triage or the investigation.** If the user's description matches more than one group, ask which one.

If something has changed since the report, say what and why. If `get_investigation` marks the group `stale`, its findings changed after its verdict: say what changed (from `stale_reason`), and offer to investigate the group again before relying on the verdict. Only use evidence from the investigation. If something wasn't checked, say so instead of filling it in.

## Output format

Return it in exactly this format. Always write the verdict after its emoji: 🔴 Confirmed, 🟡 Conditional, ⚪ Inconclusive or 🟢 Refuted. Keep every line short. Use correct singular and plural (1 group, 1 finding, 1 path).

```
## [HIGH] <the group's title from the report>
Findings in this group: <n> (<n> confirmed · <n> refuted ·
<n> conditional · <n> inconclusive · <n> duplicates)

## Findings
Confirmed first. If there are more than 10, show all confirmed ones and
the first few of each other verdict, and say how many more are in the JSON.
- 🔴 <finding ID> · <source> · Confirmed: <why, in one line>
- 🟢 <finding ID> · <source> · Refuted: <what blocks it>
- 🟡 <finding ID> · <source> · Conditional: <the one condition you couldn't see>
- ⚪ <finding ID> · <source> · Inconclusive: <what data is missing>
- 🔁 <finding ID> · <source> · Duplicate of <ID>

## Most critical path
The highest-priority confirmed path in this group (or the strongest path,
if none is confirmed):
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
- 🛡️ Stopped by: <the controls that block further movement, and what extra
  access they'd need>
- ⚠️ Made worse by: <contributing risk factors, e.g. internet exposure,
  missing audit log>

## Why we believe it
- Evidence: <node, config, policy or file references>
- Not yet verified: <what's still unchecked, or "nothing">
- vs. original finding: <✅ agree | ⬆️ raised | ⬇️ lowered>
  [<their severity> → <ours>]. <why, in one line>

## The fix
- Change: <the one shared change, in one line>
- Why one fix covers all of them: <in one line>
- Scope: <services, packages, configs>
- 👤 Owner: <team, with evidence> (only if we gave you CODEOWNERS or a
  team-to-repo mapping; otherwise leave this line out)
```

## After the deep dive

- To see where one finding or root cause in this group leads beyond the group → `/trace-blast-radius`
- To go to another group → run `/report-group-deep-dive` again with that group
