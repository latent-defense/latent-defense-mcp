"""latent-defense-mcp init — scaffold skills and config into a project."""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent


def _copy_skills(dest: Path) -> list[str]:
    """Copy bundled skills into the target project's .claude/skills/ directory."""
    src = PACKAGE_DIR / "skills"
    if not src.exists():
        return []
    dest_skills = dest / ".claude" / "skills"
    copied = []
    for skill_dir in src.iterdir():
        if not skill_dir.is_dir():
            continue
        target = dest_skills / skill_dir.name
        if target.exists():
            print(f"  skip {target.relative_to(dest)} (already exists)")
            continue
        shutil.copytree(skill_dir, target)
        copied.append(skill_dir.name)
        print(f"  created {target.relative_to(dest)}")
    return copied


def _find_binary() -> str:
    """Find the latent-defense-mcp binary. Returns absolute path or bare name."""
    import shutil

    # 1. On PATH
    found = shutil.which("latent-defense-mcp")
    if found:
        return str(Path(found).resolve())

    # 2. In a .venv relative to this package
    pkg_venv = PACKAGE_DIR.parent / ".venv" / "bin" / "latent-defense-mcp"
    if pkg_venv.exists():
        return str(pkg_venv.resolve())

    # 3. Walk up from CWD looking for .venv
    cwd = Path.cwd()
    for parent in [cwd, *cwd.parents]:
        candidate = parent / ".venv" / "bin" / "latent-defense-mcp"
        if candidate.exists():
            return str(candidate.resolve())
        if parent == parent.parent:
            break

    # 4. Bare command name as last resort
    return "latent-defense-mcp"


def _write_mcp_json(dest: Path) -> bool:
    """Write a starter .mcp.json if one doesn't exist."""
    mcp_json = dest / ".mcp.json"
    if mcp_json.exists():
        existing = json.loads(mcp_json.read_text())
        if "latent-defense" in existing.get("mcpServers", {}):
            print(f"  skip .mcp.json (latent-defense already configured)")
            return False

    binary = _find_binary()
    print(f"  binary: {binary}")

    config = {
        "mcpServers": {
            "latent-defense": {
                "command": binary,
                "env": {
                    "LATENT_DEFENSE_URL": "https://portal.your-deployment.com",
                },
            }
        }
    }

    if mcp_json.exists():
        existing = json.loads(mcp_json.read_text())
        existing.setdefault("mcpServers", {})["latent-defense"] = config["mcpServers"]["latent-defense"]
        config = existing

    mcp_json.write_text(json.dumps(config, indent=2) + "\n")
    print(f"  created .mcp.json")
    return True


def main():
    dest = Path.cwd()
    if len(sys.argv) > 1 and sys.argv[1] not in ("--help", "-h"):
        dest = Path(sys.argv[1]).resolve()

    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: latent-defense-mcp-init [directory]")
        print()
        print("Scaffold Latent Defense skills and config into a project:")
        print("  - .mcp.json with latent-defense server config")
        print("  - .claude/skills/setup/              — connect to Latent Defense (start here)")
        print("  - .claude/skills/setup-headless/     — automatic setup (no prompts)")
        print("  - .claude/skills/setup-interactive/  — step-by-step guided setup")
        print("  - .claude/skills/map/                — guided mapping workflow")
        print("  - .claude/skills/research/           — interactive security research")
        print("  - .claude/skills/investigate/        — security investigation and posture queries")
        print("  - .claude/skills/health-check/       — deployment configuration check")
        print("  - .claude/skills/triage/             — attack path triage queue")
        print("  - .claude/skills/remediate/          — remediation ticket lifecycle")
        print("  - .claude/skills/monitor/            — automated scanning and alerting")
        print("  - .claude/skills/status/             — deployment health dashboard")
        print()
        print("If directory is omitted, uses the current directory.")
        sys.exit(0)

    print(f"Initializing Latent Defense in {dest}")
    print()

    wrote_mcp = _write_mcp_json(dest)
    skills = _copy_skills(dest)

    print()
    if wrote_mcp:
        print("Next steps:")
        print("  1. Edit .mcp.json — set your portal URL")
        print("  2. Restart Claude Code to pick up the MCP server")
        print("  3. The server will prompt you to authenticate on first use")
        print("  4. Type /setup to check your deployment, or /map to start mapping")
    elif skills:
        print("Skills installed. Type /setup to check your deployment.")
    else:
        print("Already initialized — nothing to do.")


if __name__ == "__main__":
    main()
