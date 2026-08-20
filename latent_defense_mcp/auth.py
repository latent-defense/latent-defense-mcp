"""Token lifecycle: device flow, keychain cache, refresh."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import platform
import stat
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx

log = logging.getLogger("latent-defense-mcp")

_KEYCHAIN_SERVICE = "latent-defense-mcp"
_EXPIRY_BUFFER = timedelta(minutes=5)

_TOKEN_DIR = Path.home() / ".latent-defense"
_TOKEN_FILE = _TOKEN_DIR / "tokens.json"


class TokenError(Exception):
    """Raised when authentication cannot be completed."""


class DeviceFlowPending(Exception):
    """Raised when device flow has been initiated but not yet approved.

    The MCP server should return the verification_uri and user_code to
    the caller as a tool result so the user can see them — Claude Code
    does not surface MCP server stderr.
    """

    def __init__(self, verification_uri: str, user_code: str, expires_in: int):
        self.verification_uri = verification_uri
        self.user_code = user_code
        self.expires_in = expires_in
        super().__init__(
            f"Device flow pending: open {verification_uri} and enter code {user_code}"
        )


class TokenManager:
    """Manages access + refresh tokens for one deployment URL."""

    def __init__(self, base_url: str, *, verify_ssl: bool = True) -> None:
        self.base_url = base_url
        self._verify_ssl = verify_ssl

        self._access_token: str | None = None
        self._access_token_expiry: datetime | None = None
        self._refresh_token: str | None = None

        self._poll_task: asyncio.Task | None = None
        self._pending_device_code: dict | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def get_token(self) -> str:
        """Return a valid access token. Refreshes or re-authenticates as needed.

        Call order:
        1. In-memory token still valid (>5 min remaining) -> return it
        2. Refresh token available -> POST /auth/token/refresh
        3. Keychain/file cache -> load, validate expiry, try refresh if needed
        4. Device flow -> interactive approval
        """
        # 1. In-memory token still valid
        if self._access_token and self._not_expiring_soon():
            return self._access_token

        # 2. Try refresh with in-memory refresh token
        if self._refresh_token:
            try:
                await self._refresh()
                return self._access_token  # type: ignore[return-value]
            except Exception:
                log.debug("refresh with in-memory token failed, trying cache")

        # 3. Try loading from keychain/file
        loaded = self._load_from_cache()
        if loaded:
            # Check if the loaded access token is still valid
            if self._access_token and self._not_expiring_soon():
                return self._access_token
            # Access token expired but we have a refresh token
            if self._refresh_token:
                try:
                    await self._refresh()
                    return self._access_token  # type: ignore[return-value]
                except Exception:
                    log.debug("refresh with cached token failed, starting device flow")

        # 4. Device flow
        await self._device_flow()
        return self._access_token  # type: ignore[return-value]

    def clear_access_token(self) -> None:
        """Invalidate the in-memory access token. Called on 401 to force refresh."""
        self._access_token = None
        self._access_token_expiry = None

    @property
    def access_token_expiry(self) -> datetime | None:
        return self._access_token_expiry

    # ------------------------------------------------------------------
    # Device flow (RFC 8628)
    # ------------------------------------------------------------------

    async def _device_flow(self) -> None:
        """Run the device authorization grant.

        Two-phase approach:
        1. If no device flow is in progress, initiate one and raise
           DeviceFlowPending with the code/URL. The MCP server returns
           this to the caller so the user can see it (Claude Code does
           NOT surface MCP server stderr).
        2. If a device flow is already in progress (background polling),
           check if it completed. If yes, return. If still pending,
           raise DeviceFlowPending again.
        """
        # Phase 2: Check if background poll already completed
        if self._poll_task is not None:
            if self._poll_task.done():
                exc = self._poll_task.exception()
                self._poll_task = None
                if exc is not None:
                    self._pending_device_code = None
                    raise exc
                # Success — token is set
                self._pending_device_code = None
                return
            # Still polling — re-raise pending with same code
            if self._pending_device_code:
                raise DeviceFlowPending(
                    self._pending_device_code["verification_uri"],
                    self._pending_device_code["user_code"],
                    max(0, int(self._pending_device_code["deadline"] - time.monotonic())),
                )

        # Phase 1: Initiate new device flow
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30,
            follow_redirects=True,
            verify=self._verify_ssl,
        ) as client:
            # Connectivity pre-check
            try:
                await client.get("/auth/providers")
            except (httpx.ConnectError, httpx.ConnectTimeout):
                raise TokenError(
                    f"Cannot reach {self.base_url}. "
                    "Check LATENT_DEFENSE_URL or set LATENT_DEFENSE_API_KEY "
                    "for air-gapped deployments."
                )
            except Exception:
                raise TokenError(
                    f"SSL or connection error reaching {self.base_url}. "
                    "If using a private CA, set LATENT_DEFENSE_VERIFY_SSL=false "
                    "in your .mcp.json env block, or add the CA cert to your "
                    "system trust store."
                )

            # Request device code
            resp = await client.post(
                "/auth/device",
                json={
                    "client_name": "Claude Code",
                    "client_os": platform.system(),
                },
            )
            if resp.status_code != 200:
                raise TokenError(
                    f"Failed to start device flow: {resp.status_code} {resp.text}"
                )
            data = resp.json()

        device_code: str = data["device_code"]
        user_code: str = data["user_code"]
        verification_uri: str = data["verification_uri"]
        interval: int = data["interval"]
        expires_in: int = data["expires_in"]

        # Also print to stderr for direct CLI usage
        print("", file=sys.stderr)
        print("  Authenticate with Latent Defense:", file=sys.stderr)
        print(f"  Open:  {verification_uri}", file=sys.stderr)
        print(f"  Code:  {user_code}", file=sys.stderr)
        print(f"  Expires in {expires_in // 60} minutes.", file=sys.stderr)
        print("", file=sys.stderr)

        # Save pending state and start background polling
        self._pending_device_code = {
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "interval": interval,
            "deadline": time.monotonic() + expires_in,
        }
        self._poll_task = asyncio.create_task(
            self._poll_device_approval(device_code, interval, expires_in)
        )

        # Raise immediately so the MCP tool can return the code to the user
        raise DeviceFlowPending(verification_uri, user_code, expires_in)

    async def _poll_device_approval(
        self, device_code: str, interval: int, expires_in: int
    ) -> None:
        """Background task that polls the token endpoint until approved or expired."""
        deadline = time.monotonic() + expires_in
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30,
            follow_redirects=True,
            verify=self._verify_ssl,
        ) as client:
            while time.monotonic() < deadline:
                await asyncio.sleep(interval)
                resp = await client.post(
                    "/auth/device/token",
                    json={
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                )
                if resp.status_code == 200:
                    tokens = resp.json()
                    self._access_token = tokens["access_token"]
                    self._refresh_token = tokens["refresh_token"]
                    self._access_token_expiry = datetime.now(UTC) + timedelta(
                        seconds=tokens["expires_in"]
                    )
                    self._save_to_cache()
                    print("  Authenticated successfully.", file=sys.stderr)
                    return

                if resp.status_code == 400:
                    error = resp.json().get("error", "")
                    if error == "authorization_pending":
                        continue
                    if error == "slow_down":
                        interval += 5
                        continue
                    if error == "expired_token":
                        raise TokenError(
                            "Device code expired. Call any tool to start a new flow."
                        )
                    if error == "access_denied":
                        raise TokenError(
                            "Device authorization was denied by the user."
                        )
                    raise TokenError(f"Device flow error: {error}")

                raise TokenError(
                    f"Unexpected response during device flow: {resp.status_code}"
                )

        raise TokenError(
            f"Device authorization timed out after {expires_in // 60} minutes. "
            "Call any tool to start a new flow."
        )

    # ------------------------------------------------------------------
    # Token refresh
    # ------------------------------------------------------------------

    async def _refresh(self) -> None:
        """POST /auth/token/refresh with the current refresh token.

        On success: updates _access_token, _refresh_token, _access_token_expiry,
        saves to cache. On failure: raises.
        """
        async with httpx.AsyncClient(
            base_url=self.base_url,
            timeout=30,
            follow_redirects=True,
            verify=self._verify_ssl,
        ) as client:
            resp = await client.post(
                "/auth/token/refresh",
                json={"refresh_token": self._refresh_token},
            )
            if resp.status_code != 200:
                self._refresh_token = None
                raise TokenError(f"Token refresh failed: {resp.status_code}")

            tokens = resp.json()
            self._access_token = tokens["access_token"]
            # Refresh token rotation: server returns a new refresh token each time
            self._refresh_token = tokens["refresh_token"]
            self._access_token_expiry = datetime.now(UTC) + timedelta(
                seconds=tokens["expires_in"]
            )
            self._save_to_cache()

    # ------------------------------------------------------------------
    # Keychain storage (primary) with file fallback
    # ------------------------------------------------------------------

    def _cache_key(self) -> str:
        """Unique key per deployment URL. Used as both the keyring username
        and the JSON key in the file fallback."""
        return hashlib.sha256(self.base_url.encode()).hexdigest()[:16]

    def _token_payload(self) -> str:
        """Serialize tokens to JSON for storage."""
        return json.dumps(
            {
                "access_token": self._access_token,
                "refresh_token": self._refresh_token,
                "access_token_expiry": (
                    self._access_token_expiry.isoformat()
                    if self._access_token_expiry
                    else None
                ),
                "base_url": self.base_url,
            }
        )

    def _save_to_cache(self) -> None:
        """Save tokens to OS keychain. Falls back to file on failure."""
        key = self._cache_key()
        payload = self._token_payload()
        try:
            import keyring as kr

            kr.set_password(_KEYCHAIN_SERVICE, key, payload)
            log.debug("tokens saved to keychain")
            return
        except ImportError:
            log.debug("keyring package not available, using file fallback")
        except Exception:
            # NoKeyringError, InitError, or any backend failure
            log.debug("keychain write failed, using file fallback")
            if platform.system() == "Windows":
                print(
                    "Warning: keyring backend unavailable on Windows. "
                    "Tokens will be stored in an unprotected file. "
                    "Install a keyring backend (e.g. 'pip install keyrings.alt') "
                    "for secure credential storage.",
                    file=sys.stderr,
                )
        self._save_to_file(key, payload)

    def _load_from_cache(self) -> bool:
        """Load tokens from OS keychain, falling back to file. Returns True if loaded."""
        key = self._cache_key()
        payload: str | None = None

        # Try keychain first
        try:
            import keyring as kr

            payload = kr.get_password(_KEYCHAIN_SERVICE, key)
        except ImportError:
            log.debug("keyring package not available, trying file fallback")
        except Exception:
            log.debug("keychain read failed, trying file fallback")

        # File fallback
        if payload is None:
            payload = self._load_from_file(key)

        if payload is None:
            return False

        try:
            data = json.loads(payload)
        except json.JSONDecodeError:
            log.debug("cached token payload is corrupt, ignoring")
            return False

        self._access_token = data.get("access_token")
        self._refresh_token = data.get("refresh_token")
        expiry_str = data.get("access_token_expiry")
        if expiry_str:
            try:
                self._access_token_expiry = datetime.fromisoformat(expiry_str)
            except ValueError:
                self._access_token_expiry = None
        else:
            self._access_token_expiry = None

        return self._access_token is not None or self._refresh_token is not None

    # ------------------------------------------------------------------
    # File fallback: ~/.latent-defense/tokens.json
    # ------------------------------------------------------------------
    #
    # Format: JSON dict keyed by cache_key (sha256 prefix of base_url).
    # Each value is the same JSON payload stored in the keychain.
    #
    # File permissions: 0600 (owner read/write only). Directory: 0700.
    # No encryption — the file is on the user's machine behind OS-level
    # access controls. Same security model as ~/.docker/config.json,
    # ~/.kube/config, etc.

    def _save_to_file(self, key: str, payload: str) -> None:
        try:
            _TOKEN_DIR.mkdir(parents=True, exist_ok=True)
            _TOKEN_DIR.chmod(stat.S_IRWXU)  # 0700

            # Read existing entries
            entries: dict[str, str] = {}
            if _TOKEN_FILE.exists():
                try:
                    entries = json.loads(_TOKEN_FILE.read_text())
                except (json.JSONDecodeError, OSError):
                    entries = {}

            entries[key] = payload
            content = json.dumps(entries, indent=2) + "\n"

            # Write atomically with correct permissions from the start
            import os as _os
            tmp_path = _TOKEN_FILE.with_suffix(".tmp")
            fd = _os.open(
                str(tmp_path),
                _os.O_WRONLY | _os.O_CREAT | _os.O_TRUNC,
                0o600,
            )
            try:
                with _os.fdopen(fd, "w") as f:
                    f.write(content)
            except BaseException:
                try:
                    tmp_path.unlink()
                except OSError:
                    pass
                raise
            tmp_path.rename(_TOKEN_FILE)
            log.debug("tokens saved to %s", _TOKEN_FILE)
        except OSError as exc:
            log.warning("failed to save tokens to file: %s", exc)

    def _load_from_file(self, key: str) -> str | None:
        if not _TOKEN_FILE.exists():
            return None

        # Permission check: refuse to load tokens from a world/group-readable file
        if platform.system() != "Windows":
            try:
                file_mode = _TOKEN_FILE.stat().st_mode & 0o777
                if file_mode & ~0o600:
                    print(
                        f"Warning: {_TOKEN_FILE} has permissions "
                        f"{oct(file_mode)}. Expected 0600. "
                        "Refusing to load tokens from insecure file.",
                        file=sys.stderr,
                    )
                    return None
            except OSError:
                pass  # If we can't stat, proceed cautiously

        try:
            entries = json.loads(_TOKEN_FILE.read_text())
            return entries.get(key)
        except (json.JSONDecodeError, OSError):
            return None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _not_expiring_soon(self) -> bool:
        """True if the access token has more than 5 minutes remaining."""
        if self._access_token_expiry is None:
            return False
        return datetime.now(UTC) + _EXPIRY_BUFFER < self._access_token_expiry

# cmv2 webhook e2e probe
