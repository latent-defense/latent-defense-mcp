---
name: report-group-deep-dive
description: "Deep dive on one root cause (a remediation group) from /triage or a prioritized findings report, written up as one ticket-ready root cause: verdict, priority, how it's reached and what it reaches, the findings and attack paths it covers, threat model, evidence with a negative control, and the fix. Reads from the findings store, does not re-run triage."
user-invocable: true
disable-model-invocation: false
---

# Report Group Deep Dive

The deep dive on one remediation group from `/triage` or `/prioritize-findings-report`. The user names the group by its title or describes it, e.g. "the metrics API one".

## How to work

Read this group from the findings store (`list_groups`, `query_findings` for the group, `get_investigation`) rather than from memory, so the findings, verdicts and priority match the report. **Don't re-run triage or the investigation.** If the user's description matches more than one group, ask which one.

Root causes from attack-path triage aren't saved to the store. For those, work from the ranked table and the evidence gathered earlier in this conversation, and re-read the decisive nodes and edges (`read_node`, `read_edge`) for any detail you need.

If something has changed since the report, say what and why. If `get_investigation` marks the group `stale`, its findings changed after its verdict: say what changed (from `stale_reason`), and offer to investigate the group again before relying on the verdict. Only use evidence from the investigation. If something wasn't checked, say so instead of filling it in.

## Output format: one root cause

A group is one root cause: the single configuration or code defect that makes its findings and paths work. Write it up as one ticket-ready root cause in exactly this shape. The verdict, table and two diagrams are always visible; everything after them is collapsed. Someone should be able to file it as a ticket without editing.

Always write the verdict after its emoji: 🔴 Confirmed, 🟡 Conditional, ⚪ Inconclusive or 🟢 Refuted. Use correct singular and plural (1 finding, 1 path).

What the reader doesn't see: energies, momentum values, graph node ids, attack path ids, tool names, local file paths, and anything that only exists in this session. Name components the way their owners would. The 0–100 risk score and its band are the only model numbers shown.

````
## <the defect, stated plainly, e.g. "Telemetry service role can read every customer bucket">

**Verdict:** <emoji> <Confirmed | Conditional | Inconclusive | Refuted>: <one plain sentence, max ~30 words: what it is, how bad, what to do>

| Field | Value |
| -- | -- |
| Class | the kind of defect: over-permissive role, exposed service, shared credential, missing auth, vulnerable package, ... |
| Priority | Critical / High / Medium / Low, from the table below, plus "(scanner: <their severity>)" when findings came with one |
| Exploitability | High / Medium / Low, plus a few words why |
| Impact | High / Medium / Low / Unknown, plus a few words why |
| Risk score | the highest 0–100 score among this root cause's paths, with its band, or "Not scored" with the reason. If the score disagrees with the verdict (for example a missing network policy the model can't see), add why in a few words |
| Where it lives | the account, cluster, repository or config file that holds the defect |
| Product line | the product or environment it belongs to, or "Unknown" |
| Covers | <n> findings · <n> attack paths (counts by starting point and target, no ids) |
| Validation | Verified in code/config/cloud, or graph only. Say which. |
| Fix | the one change that closes it, in one line |

### How it is reached and what it reaches

**How it is reached**

<mermaid flowchart LR: the starting position → each control that matters → the defect; the gating condition on each edge; controls that hold as dashed edges labelled "blocked: ...">

**What it reaches**

<mermaid flowchart LR: the position the defect gives the attacker → the identities, data, secrets and systems it reaches; controls that hold as dashed edges labelled "blocked: ...">

<details><summary>What it accounts for</summary>

| Starting point | Paths | Findings | Reaches |
| -- | -- | -- | -- |
| <plain name> | <n> | <n> | <targets> |

Findings, confirmed first. Over 10: all confirmed ones, the first few of each other verdict, and how many more are in the store.
- 🔴 <finding ID> · <source> · Confirmed: <why, in one line>
- 🟢 <finding ID> · <source> · Refuted: <what blocks it>
- 🟡 <finding ID> · <source> · Conditional: <the condition>
- ⚪ <finding ID> · <source> · Inconclusive: <what data is missing>
- 🔁 <finding ID> · <source> · Duplicate of <ID>

Decisive steps, as the graph draws them, with what the attacker does at each:

| Step | What the attacker does |
| -- | -- |
| <"A trusts B", "service reads secret"> | <your reading> |

</details>

<details><summary>Threat model</summary>

- **Who:** the attacker this needs (outsider, any signed-in user, compromised workload, CI job, insider with a role)
- **Needs:** what they must already have or get, and how hard that is
- **Gets:** what they end up with
- **Stopped by:** controls that hold, and what extra access would get past them
- **Rating reasoning:** why exploitability and impact are rated as they are, and vs. the scanner: ✅ agree, ⬆️ raised or ⬇️ lowered, with why

</details>

<details><summary>Evidence and tests</summary>

| Fact | How we know | Result |
| -- | -- | -- |
| <decisive fact> | (map), (verified: code / config / cloud) or (per the finding) | <the relevant part> |

Negative control: a nearby role, resource or condition that should not work, shown not to work. If the investigation didn't record one, write "None recorded" instead of inventing one.

Not yet verified: what's still unchecked, or "nothing".

</details>

<details><summary>Remediation</summary>

- **Immediate:** the smallest change that breaks the decisive step, with a ready-to-apply snippet where one fits (policy JSON, Terraform, config)
- **Hardening:** what stops this class coming back
- **Shared layers:** anything else using a load balancer, security group, role or ingress the fix touches, and whether the fix breaks it
- 👤 **Owner:** team, with evidence (only if we have CODEOWNERS or a team-to-repo mapping; otherwise leave this line out)

</details>
````

Priority comes from exploitability (rows) and impact (columns). Fix cost doesn't change priority. If it isn't deployed or can't be reached, it's Low.

| Exploitability \ Impact | High | Medium | Low | Unknown |
| -- | -- | -- | -- | -- |
| High | Critical | High | Medium | High |
| Medium | High | Medium | Low | Medium |
| Low | Medium | Low | Low | Low |

Diagram rules: a control that holds is always a dashed edge (`-.->`) labelled "blocked: ...", in both diagrams; every other edge is solid. At most ~12 nodes, short quoted labels on every node and edge, no parentheses or `#` outside quotes. They render wherever the markdown is pasted. Use `<details>` sections for GitHub and the conversation; when posting to Linear use `+++ <title>` … `+++`, and to Jira use `{expand:<title>}` … `{expand}`.

Also write the full root cause, including graph node names and path ids, to `~/.latent-defense/reports/<YYYY-MM-DD>-<short-root-cause-slug>.md`, and put that path on the line after the output.

## After the deep dive

- To see where one finding or root cause in this group leads beyond the group → `/trace-blast-radius`
- To go to another group → run `/report-group-deep-dive` again with that group
