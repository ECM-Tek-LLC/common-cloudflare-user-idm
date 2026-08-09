"""The per-application object holding everything identification needs at request time.

Lives on ``app.state.cf_access``, created by :func:`cf_user_idm.install_cf_access`. Kept in
its own module so dependencies, the router and the installer can all reach it without
importing each other.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from starlette.requests import Request

from .errors import ConfigurationError
from .identity import IdentityClient
from .jwks import JwksCache
from .settings import CfAccessSettings
from .verifier import AccessTokenVerifier

if TYPE_CHECKING:
    from .models import Principal

__all__ = ["APP_STATE_ATTR", "CfAccessRuntime", "OnAuthenticated", "get_runtime"]

APP_STATE_ATTR = "cf_access"

OnAuthenticated = Callable[["Principal", Request], Awaitable[None] | None]
"""Hook invoked the first time a request's caller is identified.

Handy for upserting the caller into your own users table. This framework stores nothing
itself -- it has no database and no session store.
"""


@dataclass(slots=True)
class CfAccessRuntime:
    """Everything needed to identify a caller, assembled once per application."""

    settings: CfAccessSettings
    jwks: JwksCache
    verifier: AccessTokenVerifier
    identity: IdentityClient | None = None
    on_authenticated: OnAuthenticated | None = None

    @classmethod
    def build(
        cls,
        settings: CfAccessSettings,
        *,
        on_authenticated: OnAuthenticated | None = None,
        jwks: JwksCache | None = None,
    ) -> CfAccessRuntime:
        if jwks is None:
            jwks = JwksCache(
                # In dev mode there is no team domain and nothing is ever verified, so the
                # URL is a placeholder that is never fetched.
                settings.certs_url if settings.team_domain else "https://example.invalid",
                ttl=settings.jwks_cache_ttl,
                min_refresh_interval=settings.jwks_min_refresh_interval,
                timeout=settings.jwks_timeout,
            )
        return cls(
            settings=settings,
            jwks=jwks,
            verifier=AccessTokenVerifier(settings, jwks),
            identity=IdentityClient(settings) if settings.fetch_identity else None,
            on_authenticated=on_authenticated,
        )

    async def aclose(self) -> None:
        await self.jwks.aclose()
        if self.identity is not None:
            await self.identity.aclose()


def get_runtime(request: Request) -> CfAccessRuntime:
    """Fetch the runtime for the application handling ``request``."""
    runtime = getattr(request.app.state, APP_STATE_ATTR, None)
    if runtime is None:
        raise ConfigurationError(
            "Cloudflare Access identification is not installed on this application. Call "
            "install_cf_access(app) during startup before using its dependencies."
        )
    return runtime
