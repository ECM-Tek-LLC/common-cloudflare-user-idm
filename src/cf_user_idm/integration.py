"""One call to wire Cloudflare Access identification into a FastAPI application."""

from __future__ import annotations

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI

from .dev import log_dev_mode_banner
from .errors import register_exception_handler
from .jwks import JwksCache
from .router import build_router
from .runtime import APP_STATE_ATTR, CfAccessRuntime, OnAuthenticated
from .settings import CfAccessSettings

__all__ = ["install_cf_access"]

logger = logging.getLogger(__name__)


def install_cf_access(
    app: FastAPI,
    settings: CfAccessSettings | None = None,
    *,
    include_router: bool = True,
    on_authenticated: OnAuthenticated | None = None,
    jwks: JwksCache | None = None,
) -> CfAccessRuntime:
    """Install Cloudflare Access identification on ``app``.

    Call this once, at application setup::

        app = FastAPI()
        install_cf_access(app)

    It reads configuration from the environment, registers the JSON error format for
    authentication failures, mounts the ``/auth`` router, and arranges for HTTP clients to
    be closed on shutdown.

    Note that this installs *no* global enforcement: routes are protected individually by
    depending on ``CurrentUser`` (or ``CurrentPrincipal``). That keeps health checks and
    docs reachable without an allowlist to maintain, and keeps each route's requirements
    visible in its own signature.

    Args:
        app: The application to install onto.
        settings: Configuration. Read from the environment when omitted.
        include_router: Mount the built-in ``/auth`` router.
        on_authenticated: Called the first time each request's caller is identified --
            the hook for upserting the caller into your own users table. May be sync or
            async. Exceptions from it propagate and fail the request.
        jwks: Pre-built key cache. Tests pass ``JwksCache.from_static(...)`` here to
            exercise real verification without network access.

    Returns:
        The runtime, also reachable as ``app.state.cf_access``.

    Raises:
        ConfigurationError: If the configuration cannot verify tokens, or if the
            development bypass is enabled in a production-like environment.
    """
    if settings is None:
        settings = CfAccessSettings()

    runtime = CfAccessRuntime.build(settings, on_authenticated=on_authenticated, jwks=jwks)
    setattr(app.state, APP_STATE_ATTR, runtime)

    register_exception_handler(app)

    if include_router:
        app.include_router(build_router(settings))

    _wrap_lifespan(app, runtime)

    if settings.dev_mode:
        log_dev_mode_banner(settings)
    else:
        logger.info(
            "Cloudflare Access identification enabled for team %r with %d audience tag(s).",
            settings.team_domain,
            len(settings.audience),
        )

    return runtime


def _wrap_lifespan(app: FastAPI, runtime: CfAccessRuntime) -> None:
    """Close our HTTP clients on shutdown, preserving any lifespan the app already has."""
    existing = app.router.lifespan_context

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[Any]:
        # Forward whatever the wrapped lifespan yields: FastAPI lets a lifespan return a
        # mapping that becomes request state, and swallowing it here would break apps
        # that rely on it.
        async with existing(app) as state:
            try:
                yield state
            finally:
                await runtime.aclose()

    app.router.lifespan_context = lifespan
