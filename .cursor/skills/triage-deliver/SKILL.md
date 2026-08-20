---
name: triage-deliver
description: "Generate an audience-specific triage report from investigation results. Refuses to run until all groups have verdicts. Phase 7 of the triage pipeline."
user-invocable: true
disable-model-invocation: false
---

# Triage Deliver

Generate an audience-specific triage report from investigation results. This is Phase 7 of the triage pipeline. Each invocation produces ONE report for ONE audience.

Follow each step exactly — an agent executing this step-by-step produces the same result as the triage pipeline's deliver phase.

## Prerequisites — completeness required

ALL groups MUST have verdicts before generating a report. If any group lacks a verdict, **refuse to generate the report**:

> Cannot generate report: groups [list group IDs without verdicts] have no verdict. Run `/triage-investigate` for each before proceeding.

Do NOT generate a partial report. Do NOT proceed with "available results." Every group must have a resolution and verdict.

## Input

- **All investigation results**: verdicts for every group (from `/triage-investigate` output or loaded from project state)
- **One audience definition**:
  ```json
  {
    "name": "engineering",
    "role": "Backend engineers",
    "needs": "What to fix, in what order, with enough context to start work",
    "jargon_level": "high",
    "report_outline": "optional — approved outline to follow exactly",
    "not_include": "optional — things to exclude"
  }
  ```
- **Full group list** with finding counts
- **Total findings count** and **resolution distribution** (how many eliminable, reducible, etc.)
- `project_id` (optional): for loading results and saving output manifest
- `output_dir` (optional): defaults to `triage-output/`

If invoked independently, ask the user for the project ID and audience definition.

## Instructions

### Step 1: Load and validate results

If a project ID is provided, call `triage_load_project(project_id)` to load investigation results.

**Completeness check:** Count groups with verdicts vs total groups. If ANY group has no verdict, stop and report which groups are missing. Do not proceed.

Sort groups by resolution category (most actionable first):
1. `eliminable` — clear fixes, no trade-offs
2. `reducible` — partial fixes, add controls
3. `constrained` — design limitations, need product decisions
4. `drift_prone` — need automation or monitoring
5. `mitigated` — adequately defended, documented acceptance

Separate groups into two buckets:
- **remediation_ready**: groups with `readiness: "remediation_ready"`
- **investigation_needed**: groups with `readiness: "investigation_needed"`

Filter groups to those relevant to this audience (match on `primary_audience` field from investigation results). Include all items that match this audience, plus any items with no specific audience assignment.

### Step 2: Write the report

Follow these rules strictly. These are exact requirements, not suggestions.

1. **Lead with the action table.** The report opens with a summary table of all remediation batches. The reader should be able to scan this table and know the full picture in 30 seconds.

2. **Separate remediation-ready from investigation-needed.** These are different sections. Remediation-ready items have clear fixes. Investigation-needed items require more analysis before action.

3. **Dismissed items are high-value.** For mitigated/refuted findings, document the compensating control and the evidence that it holds. These are valuable — they prove defenses are working. Give each one paragraph.

4. **Every finding needs blast radius.** What else is affected if this finding is exploited. Frame with deployment model context (single-tenant vs multi-tenant, managed vs self-hosted).

5. **Evidence from code/config, not graph.** Cite the specific file, line, configuration, or API response. Never cite energy scores, node IDs, momentum values, or graph terminology.

6. **No effort estimates.** The reader's team estimates effort. Do not invent story points, time estimates, or complexity ratings.

7. **No model commentary.** No energy scores, no node IDs, no momentum values, no graph terminology, no collapse ratios, no tool names, no "the JEPA model shows...", no methodology sections.

8. **No vendor language.** No tool comparisons, no product positioning, no marketing language.

9. **Define jargon inline on first use.** Match the audience's jargon level. If jargon_level is low, define every technical term. If high, skip definitions.

10. **Review dates come from the user, not invented.** Do not make up review dates, next-check dates, or reassessment timelines.

### Step 3: Handle audience customization

- If the audience has a `report_outline`: follow it exactly — it was approved by the user
- If the audience has `not_include`: exclude those items from the report
- If the audience has specific `needs`: make sure the report addresses them directly

### Step 4: Save output

Write the report to: `{output_dir}/{project_id}/{audience-name-slugified}.md`

The slug is the audience name lowercased with non-alphanumeric characters replaced by hyphens: `"Security Lead"` → `security-lead.md`

If a project ID was provided, save the output manifest with `triage_save_project`:

```json
{
  "outputs": [
    {
      "audience": "engineering",
      "path": "triage-output/project-id/engineering.md"
    }
  ]
}
```

## After completing

Tell the orchestrator that this audience's report is complete and where the file was saved. If all audiences are complete, the triage pipeline is done.
