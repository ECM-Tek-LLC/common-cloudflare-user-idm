"""Optional profile enrichment via Cloudflare's get-identity endpoint.

The Access application token is deliberately thin: it proves *who* the caller is, but
carries no display name and no group membership. When an application wants those, this
fetches them from ``https://<team>.cloudflareaccess.com/cdn-cgi/access/get-identity``,
authenticated with the caller's own ``CF_Authorization`` cookie.

This is opt-in (``CF_ACCESS_FETCH_IDENTITY=true``) and best-effort by design. Identity has
already been established by the time it runs, so a failure here degrades the response
rather than rejecting the request.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from typing import Any

import httpx

from .models import AccessGroup, IdentityDetails
from .settings import CfAccessSettings

__all__ = ["IdentityClient"]

logger = logging.getLogger(__name__)

MAX_CACHE_ENTRIES = 1024
"""Cap on cached enrichment results, so a long-running process cannot grow without bound."""


class IdentityClient:
    """Fetches and caches enriched identity for a session."""

    def __init__(
        self,
        settings: CfAccessSettings,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.settings = settings
        self._client = client
        self._owns_client = client is None
        self._cache: OrderedDict[str, tuple[float, IdentityDetails]] = OrderedDict()

    async def fetch(self, token: str, cache_key: str | None) -> IdentityDetails | None:
        """Return enriched identity for ``token``, or ``None`` if it could not be fetched.

        ``cache_key`` should be the token's ``identity_nonce``, which is stable for the
        life of a session. When it is absent, the result is not cached.
        """
        cached = self._get_cached(cache_key)
        if cached is not None:
            return cached

        try:
            client = self._get_client()
            response = await client.get(
                self.settings.identity_url,
                headers={"cookie": f"CF_Authorization={token}"},
                timeout=self.settings.jwks_timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            logger.warning(
                "Cloudflare Access identity enrichment failed (%s); continuing with token "
                "claims only.",
                exc,
            )
            return None

        details = self._parse(payload)
        self._store(cache_key, details)
        return details

    @staticmethod
    def _parse(payload: dict[str, Any]) -> IdentityDetails:
        idp = payload.get("idp") or {}
        groups = [
            AccessGroup(id=group.get("id"), name=group.get("name"), email=group.get("email"))
            for group in payload.get("groups") or []
            if isinstance(group, dict)
        ]
        geo = payload.get("geo") or {}
        return IdentityDetails(
            name=payload.get("name"),
            groups=groups,
            idp_id=idp.get("id") if isinstance(idp, dict) else None,
            idp_type=idp.get("type") if isinstance(idp, dict) else None,
            geo_country=geo.get("country") if isinstance(geo, dict) else None,
            is_warp=payload.get("is_warp"),
            is_gateway=payload.get("is_gateway"),
        )

    def _get_cached(self, cache_key: str | None) -> IdentityDetails | None:
        if not cache_key:
            return None
        entry = self._cache.get(cache_key)
        if entry is None:
            return None
        expires_at, details = entry
        if expires_at <= time.monotonic():
            del self._cache[cache_key]
            return None
        self._cache.move_to_end(cache_key)
        return details

    def _store(self, cache_key: str | None, details: IdentityDetails) -> None:
        if not cache_key:
            return
        self._cache[cache_key] = (
            time.monotonic() + self.settings.identity_cache_ttl,
            details,
        )
        self._cache.move_to_end(cache_key)
        while len(self._cache) > MAX_CACHE_ENTRIES:
            self._cache.popitem(last=False)

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self.settings.jwks_timeout)
            self._owns_client = True
        return self._client

    async def aclose(self) -> None:
        if self._client is not None and self._owns_client:
            await self._client.aclose()
        self._client = None
