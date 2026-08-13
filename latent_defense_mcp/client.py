"""HTTP client for the Latent Defense portal API."""

from __future__ import annotations

import logging
import os

import httpx

from .auth import TokenManager

log = logging.getLogger("latent-defense-mcp")

_token_manager: TokenManager | None = None


def _base_url() -> str:
    url = os.environ.get("LATENT_DEFENSE_URL")
    if not url:
        log.warning(
            "LATENT_DEFENSE_URL is not set. "
            "Set it in the 'env' block of .mcp.json to point to your deployment.",
        )
        return "https://portal.latentdefense.ai"
    return url


def _verify_ssl() -> bool:
    return os.environ.get("LATENT_DEFENSE_VERIFY_SSL", "true").lower() not in (
        "0",
        "false",
        "no",
    )


def make_client() -> httpx.AsyncClient | None:
    """Create an httpx client with a static API key.

    Returns None if LATENT_DEFENSE_API_KEY is not set (caller should use
    the token manager path instead).
    """
    api_key = os.environ.get("LATENT_DEFENSE_API_KEY")
    if not api_key:
        return None
    return httpx.AsyncClient(
        base_url=_base_url(),
        headers={"Authorization": f"Bearer {api_key}"},
        timeout=120,
        follow_redirects=True,
        verify=_verify_ssl(),
    )


def get_token_manager() -> TokenManager:
    """Get or create the singleton TokenManager for device-flow auth."""
    global _token_manager
    if _token_manager is None:
        _token_manager = TokenManager(_base_url(), verify_ssl=_verify_ssl())
    return _token_manager
