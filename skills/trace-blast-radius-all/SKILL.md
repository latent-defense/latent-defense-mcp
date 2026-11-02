---
name: trace-blast-radius-all
description: "List every attack path evaluated in the last /trace-blast-radius run (or for a triage group), including dead ends and the controls that blocked them. Reads saved paths; does not re-run the investigation."
user-invocable: true
disable-model-invocation: false
---

# Every Path Tried

Every attack path evaluated, including the dead ends, so the user can see we checked rather than assumed. For each dead end, the control that stopped it, which shows which controls are doing real work.

Run this right after `/trace-blast-radius`, in the same session. After `/triage`, it can also be run for any group in the findings store.

## How to work

Read the paths you saved with `get_investigation`; **don't re-run the investigation**, so the list matches the answer the user just saw. If there is no saved investigation for this input, say so and offer `/trace-blast-radius` instead of investigating here.

## Output format

Return it in exactly this format. Always write the verdict after its emoji: 🔴 Confirmed, 🟡 Conditional, ⚪ Inconclusive or 🟢 Refuted. Keep every line short. Use correct singular and plural (1 group, 1 finding, 1 path).

```
## Paths evaluated
<n> paths: <n> confirmed · <n> refuted · <n> conditional ·
<n> inconclusive
Sets the verdict: path <#>, because <one line>
(If no path is confirmed, write instead: "Nothing confirmed; the
highest-stakes open path is <#>, because <one line>")

Confirmed first, then conditional and inconclusive, then refuted.
1. [HIGH] 🔴 Confirmed · <entry> → <steps> → <impact>
   Gains: <one line> · <direct | supported downstream | conditional> ·
   <potential | observed>
   Evidence: <references>
   Matches finding: <finding ID, or none>
2. [MEDIUM] 🟡 Conditional (or ⚪ Inconclusive) · <entry> → <steps> →
   <impact>
   Couldn't check: <the one condition or missing data>
   Matches finding: <finding ID, or none>
3. 🟢 Refuted · <entry> → <step that fails>
   🛡️ Blocked by: <the control or config, with evidence>
```
