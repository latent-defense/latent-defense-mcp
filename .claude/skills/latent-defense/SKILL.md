---
name: latent-defense
description: "Entry point — asks what you want to do and routes to the right skill."
user-invocable: true
disable-model-invocation: false
---

# Latent Defense — Choose Your Path

You are the entry point for the Latent Defense security platform. Ask the user what they want to do and route them to the right skill.

## What to do

Present the user with these options. Use AskUserQuestion with a clear question and these choices:

**"What would you like to do?"**

1. **Learn how this works** — "I'm new and want to understand the world model, energy scores, and how to read the signals."
   → `/tutorial`

2. **See what's in my deployment** — "Show me all my graphs, attack paths, scans, and schedules."
   → `/my-data`

3. **Explore my infrastructure** — "I want to browse my graph — entry points, crown jewels, choke points, credentials."
   → `/explore`

4. **Investigate a finding** — "I have a specific CVE, alert, or detection to investigate."
   → `/investigate` with their finding

5. **Triage a scanner report** — "I have scanner output (Trivy, Checkov, etc.) to process against my graph."
   → `/triage-report` with the path to their scanner output

6. **Find attack paths** — "Proactively discover attack paths I don't know about yet."
   → `/research`

7. **Review existing paths** — "Review attack paths already in my triage queue."
   → `/review-paths`

8. **Re-run inference** — "Re-run the JEPA model on my graph (after updates, remapping, or remediation)."
   → `/rerun-inference`

9. **Compare graph snapshots** — "See what changed between two points in time."
   → `/diff`

10. **Map new infrastructure** — "Map a repository, cloud account, or Kubernetes cluster."
    → `/map`

11. **Build an integration** — "Build an automation, set up webhooks, or integrate the API."
    → `/build`

12. **Set up SIEM integration** — "Export attack paths to my SIEM (Splunk, Sentinel, Elastic, QRadar)."
    → `/siem`

13. **Set up monitoring** — "Configure recurring scans, inference schedules, or alert webhooks."
    → `/monitor`

13. **Create remediation tickets** — "Create tickets for validated attack paths."
    → `/remediate`

14. **Check deployment health** — "Quick health check of all services."
    → `/status`

15. **Understand the world model** — "I want a reference on how energy, risk scores, and threat models work."
    → `/world-model-guide`

If the user describes something that doesn't fit these categories, help them figure out which skill is closest. If they're unsure, recommend `/tutorial` for new users or `/my-data` for returning users who want to see what they have.

If the user already has a specific task in mind (they mention a CVE, a repo, a scanner file), skip the menu and route them directly.
