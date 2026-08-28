---
name: triage-deliver
description: "Generate an audience-specific triage report from investigation results stored in the findings store. Refuses to run until all groups have verdicts."
user-invocable: true
disable-model-invocation: false
---

# Triage Deliver

Generate an audience-specific triage report from investigation results. This is Phase 7 of the triage pipeline. Each invocation produces ONE report for ONE audience.

Follow each step exactly.

## Resume check — always run first

Call `pipeline_status(project_id)` to see the delivery state. If reports already exist for this audience in the output directory, report that and ask the user if they want to regenerate.

## Prerequisites — completeness required

ALL groups MUST have verdicts before generating a report. If any group lacks a verdict, **refuse to generate the report**:

> Cannot generate report: groups [list group IDs without verdicts] have no verdict. Run `/triage-investigate` for each before proceeding.

Do NOT generate a partial report. Every group must have a resolution and verdict.

## Input

- `project_id`: Triage project identifier (reads results from findings store)
- One audience definition: name, role, needs, jargon_level, report_outline, not_include
- `output_dir` (optional): defaults to `triage-output/`

If invoked independently, ask the user for the project ID and audience definition.

## Step 1: Load and validate results

```
findings_stats(project_id)         — total counts, claim coverage
list_groups(project_id)            — all groups with finding counts + resolutions
get_investigation(project_id, group_id)  — for each group, get verdict + evidence
```

**Completeness check:** Call `list_groups` and verify every group has a non-null resolution. If any group has status != "investigated" or "routed", stop and report which groups are missing.

Sort groups by resolution category (most actionable first):
1. `eliminable` → 2. `reducible` → 3. `constrained` → 4. `drift_prone` → 5. `mitigated`

Filter to items relevant to this audience (match on `primary_audience`). Include all items with no specific audience assignment.

## Step 2: Write the report

1. **Action table first.** Summary table of all remediation batches. Scannable in 30 seconds.
2. **Separate remediation-ready from investigation-needed.**
3. **Dismissed items are high-value.** Document the defense and evidence.
4. **Every finding: blast radius** with deployment model context.
5. **Evidence from code/config, not graph.** Cite specific files, lines, API responses.
6. **No effort estimates.** The reader estimates effort.
7. **No model internals.** No energy scores, JEPA, momentum, node IDs.
8. **No methodology sections.**
9. **Define jargon inline** matching audience jargon_level.
10. **No invented review dates.**

## Step 3: Audience customization

- If `report_outline` provided: follow it exactly
- If `not_include` provided: exclude those items
- If `needs` provided: address them directly

## Step 4: Save output

Write to: `{output_dir}/{audience-name-slug}.md`

If a project ID was provided, save the output manifest with `triage_save_project`.

## After completing

Tell the orchestrator that this audience's report is complete and where the file was saved.
