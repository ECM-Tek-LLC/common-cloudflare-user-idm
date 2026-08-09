"""Cached access to the Cloudflare team's JWT signing keys.

Cloudflare signs Access tokens with a key pair unique to your account and rotates it about
every six weeks, so keys have to be fetched at runtime rather than baked into config. This
cache makes that invisible:

* keys are fetched once and reused for :attr:`~CfAccessSettings.jwks_cache_ttl` seconds, so
  token verification does no network I/O on the hot path;
* a token signed with a key id we have never seen triggers an out-of-band refresh, so a
  rotation is picked up immediately rather than after the TTL expires;
* those out-of-band refreshes are rate-floored, so a flood of tokens carrying junk key ids
  cannot be turned into a request flood against Cloudflare;
* concurrent refreshes collapse into one in-flight request;
* if a refresh fails while we still hold usable keys, we keep serving with them rather than
  failing every request until Cloudflare answers again.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from typing import Any

import httpx
from jwt import PyJWK, PyJWKSet
from jwt.exceptions import PyJWKError, PyJWKSetError

from .errors import SigningKeyUnavailableError

__all__ = ["JwksCache"]

logger = logging.getLogger(__name__)


class JwksCache:
    """Fetches and caches the signing keys published at a team's ``/cdn-cgi/access/certs``."""

    def __init__(
        self,
        certs_url: str,
        *,
        ttl: int = 3600,
        min_refresh_interval: int = 300,
        timeout: float = 5.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.certs_url = certs_url
        self.ttl = ttl
        self.min_refresh_interval = min_refresh_interval
        self.timeout = timeout

        self._client = client
        self._owns_client = client is None
        self._keys: dict[str, PyJWK] = {}
        self._fetched_at = -math.inf
        self._lock = asyncio.Lock()
        self._static = False
        self.fetch_count = 0
        """Number of times the JWKS endpoint has actually been requested. Diagnostics only."""

    @classmethod
    def from_static(
        cls, jwks: dict[str, Any], certs_url: str = "https://example.invalid"
    ) -> JwksCache:
        """Build a cache backed by a fixed JWKS that is never refetched.

        Used by :mod:`cf_user_idm.testing` so a test suite can exercise the real
        verification path with a locally generated key pair and no network.
        """
        cache = cls(certs_url)
        cache._keys = cls._parse(jwks)
        cache._fetched_at = time.monotonic()
        cache._static = True
        return cache

    @property
    def age(self) -> float | None:
        """Seconds since the keys were last successfully loaded, or ``None`` if never."""
        if self._fetched_at == -math.inf:
            return None
        return time.monotonic() - self._fetched_at

    @property
    def key_ids(self) -> list[str]:
        return sorted(self._keys)

    async def get_key(self, kid: str | None) -> PyJWK:
        """Resolve the signing key for a token's ``kid``.

        Raises :class:`~cf_user_idm.errors.SigningKeyUnavailableError` if the key cannot be
        resolved -- which the caller surfaces as a 401, since an unresolvable key means we
        cannot establish who the caller is.
        """
        if not kid:
            raise SigningKeyUnavailableError(
                "The token header has no 'kid', so its signing key cannot be identified."
            )

        await self._refresh_if_older_than(self.ttl)

        key = self._keys.get(kid)
        if key is None:
            # Unknown key id: either Cloudflare just rotated, or this token is junk. Try
            # once more, but only if we have not refreshed very recently.
            await self._refresh_if_older_than(self.min_refresh_interval)
            key = self._keys.get(kid)

        if key is None:
            raise SigningKeyUnavailableError(
                f"No Cloudflare Access signing key matches key id {kid!r}."
            )
        return key

    async def _refresh_if_older_than(self, max_age: float) -> None:
        if self._static:
            return
        if self.age is not None and self.age < max_age:
            return

        async with self._lock:
            # Re-check inside the lock: whoever held it may have just refreshed for us.
            if self.age is not None and self.age < max_age:
                return
            await self._fetch()

    async def _fetch(self) -> None:
        client = self._get_client()
        try:
            response = await client.get(self.certs_url, timeout=self.timeout)
            response.raise_for_status()
            keys = self._parse(response.json())
        except (httpx.HTTPError, ValueError, PyJWKSetError, PyJWKError) as exc:
            if self._keys:
                # Stale keys still verify tokens signed before the rotation. Staying up on
                # slightly old keys beats rejecting everyone because Cloudflare blipped.
                logger.warning(
                    "Failed to refresh Cloudflare Access signing keys from %s (%s); "
                    "continuing with cached keys (age %.0fs).",
                    self.certs_url,
                    exc,
                    self.age or 0.0,
                )
                return
            logger.error(
                "Failed to load Cloudflare Access signing keys from %s: %s",
                self.certs_url,
                exc,
            )
            raise SigningKeyUnavailableError(
                "Could not load the Cloudflare Access signing keys."
            ) from exc

        self._keys = keys
        self._fetched_at = time.monotonic()
        self.fetch_count += 1
        logger.debug(
            "Loaded %d Cloudflare Access signing key(s) from %s.", len(keys), self.certs_url
        )

    @staticmethod
    def _parse(payload: dict[str, Any]) -> dict[str, PyJWK]:
        key_set = PyJWKSet.from_dict(payload)
        return {key.key_id: key for key in key_set.keys if key.key_id}

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.timeout)
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        """Release the HTTP client, if this cache created one."""
        if self._client is not None and self._owns_client:
            await self._client.aclose()
        self._client = None
