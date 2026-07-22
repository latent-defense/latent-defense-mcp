---
name: rerun-inference
description: "Re-run JEPA inference on a graph branch to discover new attack paths. Use after model updates, remapping, or remediation to see how the security posture changed."
user-invocable: true
disable-model-invocation: false
---

# Re-run Inference

Re-run JEPA inference on a graph branch. Use this after:
- The JEPA model has been updated (new model weights deployed)
- Infrastructure has been remapped (graph has changed)
- Remediation was applied (verify paths are closed)
- You want fresh attack path analysis

## Prerequisites

- The `latent-defense` MCP server must be connected
- A graph must exist (run `/map` first, or use `/my-data` to find existing graphs)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

| Tool | Purpose |
|------|---------|
| `list_repositories()` | Find repos |
| `list_branches(repo_id)` | Find branches |
| `run_inference(branch_id)` | Start inference run |
| `get_inference_run(run_id)` | Check progress |
| `list_attack_paths(status, limit, summary)` | See results |
| `triage_stats(repository_id)` | Path counts |

---

## Workflow

### Step 1 — Select the branch

If the user specifies a repo or branch, use it. Otherwise:

"Which graph do you want to run inference on? Run `/my-data` to see all available graphs."

Or find it:
```
list_repositories()  → pick the repo
list_branches(repo_id)  → pick the branch (usually main)
```

### Step 2 — Run inference

```
run_inference(branch_id)
```

Save the returned `run_id`.

### Step 3 — Monitor progress

Poll every 30-60 seconds until status is `completed` or `failed`:

```
get_inference_run(run_id)
// repeat until status is "completed" or "failed"
```

Status progression: `pending` → `in_progress` → `completed` | `failed`

Report progress to the user. Inference typically takes 2-10 minutes depending on graph size.

### Step 4 — Review results

When complete:
```
triage_stats(repository_id)
list_attack_paths(status="new", limit=20, summary=true)
```

Report:
- How many new paths were discovered
- Risk score range of the new paths
- "The highest-risk path scores [X]/100 — [interpretation based on bands]"

### Next steps

- "Want to review the new paths?" → `/review-paths` or `/triage`
- "Want to explore the graph?" → `/explore`
- "Want to investigate a specific path?" → `/investigate`
- "Want to compare before/after?" → `/diff` to see what changed
