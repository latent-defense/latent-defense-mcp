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

5. **Triage scanner findings at scale** — "I have scanner output and want structural triage — group by remediation action, investigate against the graph, produce reports for my team."
   → `/triage-findings`

6. **Triage a scanner report** — "I have scanner output (Trivy, Checkov, etc.) to process against my graph and get a full triage table."
   → `/triage-report` with the path to their scanner output

7. **Find attack paths** — "Proactively discover attack paths I don't know about yet."
   → `/research`

8. **Review existing paths** — "Review attack paths already in my triage queue."
   → `/review-paths`

9. **Assess a CVE** — "How exposed am I to a specific CVE?"
   → Use the `assess_cve` prompt with their CVE ID

10. **Find chokepoints** — "Which nodes should I harden to eliminate the most attack paths?"
    → Use the `chokepoint_report` prompt

11. **Re-run inference** — "Re-run the JEPA model on my graph (after updates, remapping, or remediation)."
    → `/rerun-inference`

12. **Compare graph snapshots** — "See what changed between two points in time."
    → `/diff`

13. **Map new infrastructure** — "Map a repository, cloud account, or Kubernetes cluster."
    → `/map`

14. **Build an integration** — "Build an automation, set up webhooks, or integrate the API."
    → `/build`

15. **Set up SIEM integration** — "Export attack paths to my SIEM (Splunk, Sentinel, Elastic, QRadar)."
    → `/siem`

16. **Set up monitoring** — "Configure recurring scans, inference schedules, or alert webhooks."
    → `/monitor`

17. **Create remediation tickets** — "Create tickets for validated attack paths."
    → `/remediate`

18. **Check deployment health** — "Quick health check of all services."
    → `/status`

19. **Understand the world model** — "I want a reference on how energy, risk scores, and threat models work."
    → `/world-model-guide`

If the user describes something that doesn't fit these categories, help them figure out which skill is closest. If they're unsure, recommend `/tutorial` for new users or `/my-data` for returning users who want to see what they have.

If the user already has a specific task in mind (they mention a CVE, a repo, a scanner file), skip the menu and route them directly.
