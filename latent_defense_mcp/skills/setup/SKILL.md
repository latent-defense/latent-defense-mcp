---
name: setup
description: "Set up the Latent Defense MCP server in a project. Takes the portal endpoint URL as input and configures authentication, .mcp.json, and skills."
user-invocable: true
disable-model-invocation: false
---

# Setup — Connect to Latent Defense

Set up the Latent Defense MCP server in the current project. This skill configures `.mcp.json`, authenticates with the deployment, and installs guided workflow skills.

## Input

The user should provide their portal endpoint URL as the argument, e.g.:

```
/setup https://portal.acme-corp.latentdefense.ai
```

If no URL is provided, ask the user for their portal URL. It looks like `https://portal-<name>.latentdefense.ai` or a custom domain their admin configured.

## Step 1 — Choose setup mode

Ask the user:

> **How would you like to set up?**
>
> 1. **Automatic** — I'll configure everything for you (writes `.mcp.json`, triggers device flow authentication, installs skills, verifies the connection)
> 2. **Interactive** — Step-by-step walkthrough where you review and confirm each change before it's applied

If the user picks automatic, invoke `/setup-headless` with the portal URL.
If the user picks interactive, invoke `/setup-interactive` with the portal URL.

## Notes

- Both modes produce identical results — the same `.mcp.json`, same skills, same auth
- Automatic is faster; interactive is for users who want to understand what's being configured
- After either mode completes, suggest running `/health-check` to verify the deployment is healthy
