"""latent-defense-mcp login — authenticate via device flow from the CLI."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from .auth import DeviceFlowPending, TokenError, TokenManager


def main():
    if "--help" in sys.argv or "-h" in sys.argv:
        print("Usage: latent-defense-mcp-login <PORTAL_URL>")
        print()
        print("Authenticate with a Latent Defense deployment via device flow.")
        print("Opens a device code flow, waits for browser approval, and")
        print("stores the token in the OS keychain (or ~/.latent-defense/tokens.json).")
        print()
        print("Options:")
        print("  --no-verify    Disable SSL certificate verification")
        sys.exit(0)

    no_verify = "--no-verify" in sys.argv
    args = [a for a in sys.argv[1:] if not a.startswith("-")]

    if not args:
        print("Error: portal URL is required.", file=sys.stderr)
        print("Usage: latent-defense-mcp-login <PORTAL_URL>", file=sys.stderr)
        sys.exit(1)

    portal_url = args[0].rstrip("/")
    asyncio.run(_login(portal_url, verify_ssl=not no_verify))


async def _login(portal_url: str, *, verify_ssl: bool = True) -> None:
    tm = TokenManager(portal_url, verify_ssl=verify_ssl)

    print(f"Authenticating with {portal_url}...")
    print()

    try:
        # get_token will trigger device flow if no cached token
        token = await tm.get_token()
    except DeviceFlowPending as e:
        # Device flow initiated — show the prompt and wait for approval
        print(f"  Open:  {e.verification_uri}")
        print(f"  Code:  {e.user_code}")
        print(f"  Expires in {e.expires_in // 60} minutes.")
        print()
        print("  Waiting for approval...")

        # Poll until the background task completes
        while tm._poll_task and not tm._poll_task.done():
            await asyncio.sleep(1)

        if tm._poll_task:
            exc = tm._poll_task.exception()
            if exc:
                print(f"\n  Error: {exc}", file=sys.stderr)
                sys.exit(1)

        token = tm._access_token
        if not token:
            print("\n  Error: no token received after approval.", file=sys.stderr)
            sys.exit(1)

    except TokenError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    print("  Authenticated successfully.")
    print()

    # Show what was stored
    if tm._access_token_expiry:
        print(f"  Token expires: {tm._access_token_expiry.isoformat()}")

    cache_file = Path.home() / ".latent-defense" / "tokens.json"
    if cache_file.exists():
        print(f"  Cached at:     {cache_file}")

    print()
    print("  Restart Claude Code to use the authenticated connection.")


if __name__ == "__main__":
    main()
