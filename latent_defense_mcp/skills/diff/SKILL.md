---
name: diff
description: "Compare two graph snapshots — see what changed between commits, branches, or before/after a deployment. Shows added, removed, and modified nodes and edges."
user-invocable: true
disable-model-invocation: false
---

# Diff — Graph Comparison

Compare two graph snapshots to see what changed. Use after remapping, remediation, or deployment to understand how the infrastructure graph evolved.

## Prerequisites

- The `latent-defense` MCP server must be connected
- Two commits to compare (same repo, different points in time)

## Tool reference

All tools prefixed with `mcp__latent-defense__`. Use ToolSearch to load schemas before calling.

| Tool | Purpose |
|------|---------|
| `list_repositories()` | Find repos |
| `list_branches(repo_id)` | Find branches |
| `list_commits(branch_id, limit)` | Find commits to compare |
| `diff_commits(commit_a_id, commit_b_id)` | Compare two commits |

---

## Workflow

### Step 1 — Find the commits to compare

If the user specifies commits, use those. Otherwise help them find the right ones:

```
list_repositories()
list_branches(repo_id)
list_commits(branch_id, limit=10)
```

Common comparisons:
- **Before/after a mapping run**: compare the two most recent commits
- **Before/after remediation**: compare the commit before remediation branch was created to the remediation branch head
- **Two different branches**: get the head commit of each branch

### Step 2 — Run the diff

```
diff_commits(commit_a_id, commit_b_id)
```

The diff returns:
- **Added nodes**: new infrastructure components discovered
- **Removed nodes**: components no longer present
- **Modified nodes**: components whose properties changed
- **Added edges**: new relationships
- **Removed edges**: relationships that no longer exist
- **Modified edges**: relationships whose properties changed

### Step 3 — Present the changes

#### Security-relevant changes

Highlight changes that affect the security posture:
- New `http_endpoint` nodes → new attack surface
- Removed `security_boundary` nodes → controls removed
- New `credential` nodes → new secrets introduced
- Modified `iam_role` or `k8s_rbac` nodes → permission changes
- New edges to `data_store` or `credential` nodes → new access paths

```
## Graph Changes: commit_A → commit_B

Added: [N] nodes, [M] edges
Removed: [N] nodes, [M] edges
Modified: [N] nodes, [M] edges

### Security-relevant additions
- New endpoint: [name] — potential new entry point
- New credential: [name] — new secret in the graph

### Security-relevant removals
- Removed boundary: [name] — control no longer present
```

### Next steps

- "Want to run inference on the updated graph to find new paths?" → `/rerun-inference`
- "Want to explore the current graph?" → `/explore`
- "Want to see all your graphs?" → `/my-data`
