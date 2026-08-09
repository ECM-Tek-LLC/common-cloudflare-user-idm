"""FastAPI dependencies -- the framework's main surface.

Three of them, covering the three questions a route can ask:

``CurrentUser``
    "Give me the human making this request." Rejects service tokens with 403.
``CurrentPrincipal``
    "Give me the caller, human or machine."
``OptionalUser``
    "Give me the human if there is one." Returns ``None`` for anonymous or machine callers,
    but still rejects a *forged* token -- silently downgrading a bad token to anonymous
    would hide an attack.

Usage::

    from cf_user_idm import CurrentUser

    @app.get("/profile")
    async def profile(user: CurrentUser):
        return {"id": user.id, "email": user.email}
"""

from __future__ import annotations

import inspect
import logging
from typing import Annotated

from fastapi import Depends
from starlette.requests import Request

from .dev import build_dev_user
from .errors import MissingTokenError, ServiceTokenNotPermittedError
from .extract import extract_token
from .models import AccessUser, Principal
from .runtime import get_runtime

__all__ = [
    "CurrentPrincipal",
    "CurrentUser",
    "OptionalUser",
    "get_current_principal",
    "get_current_user",
    "get_optional_user",
]

logger = logging.getLogger(__name__)

REQUEST_STATE_ATTR = "cf_principal"
"""Where the resolved caller is cached on ``request.state``.

Also makes the caller reachable from code that does not take a dependency -- logging
middleware, exception handlers, background task setup.
"""


async def _resolve(request: Request) -> Principal:
    """Identify the caller, at most once per request."""
    cached = getattr(request.state, REQUEST_STATE_ATTR, None)
    if cached is not None:
        return cached

    runtime = get_runtime(request)
    settings = runtime.settings

    if settings.dev_mode:
        principal: Principal = build_dev_user(settings)
    else:
        token = extract_token(request)
        if not token:
            raise MissingTokenError()

        principal = await runtime.verifier.verify(token)

        if principal.is_service and not settings.allow_service_tokens:
            raise ServiceTokenNotPermittedError(
                "Service tokens are not accepted by this application."
            )

        if runtime.identity is not None and isinstance(principal, AccessUser):
            details = await runtime.identity.fetch(token, principal.identity_nonce)
            if details is not None:
                principal = principal.model_copy(update={"details": details})

    setattr(request.state, REQUEST_STATE_ATTR, principal)

    if runtime.on_authenticated is not None:
        result = runtime.on_authenticated(principal, request)
        if inspect.isawaitable(result):
            await result

    return principal


async def get_current_principal(request: Request) -> Principal:
    """Identify the caller, which may be a human user or a service token."""
    return await _resolve(request)


async def get_current_user(
    principal: Annotated[Principal, Depends(get_current_principal)],
) -> AccessUser:
    """Identify the human user making this request.

    Rejects service tokens with 403 rather than returning a user object with an empty
    email, so a route written for people never quietly serves a machine.
    """
    if not isinstance(principal, AccessUser):
        raise ServiceTokenNotPermittedError()
    return principal


async def get_optional_user(request: Request) -> AccessUser | None:
    """Identify the human user if there is one, otherwise ``None``.

    Returns ``None`` when no token is present and when the caller is a service token.
    Any other failure -- bad signature, wrong audience, expired -- still raises.
    """
    try:
        principal = await _resolve(request)
    except MissingTokenError:
        return None
    return principal if isinstance(principal, AccessUser) else None


CurrentUser = Annotated[AccessUser, Depends(get_current_user)]
"""``user: CurrentUser`` -- a human user, or 401/403."""

CurrentPrincipal = Annotated[Principal, Depends(get_current_principal)]
"""``caller: CurrentPrincipal`` -- a human user or a service token, or 401."""

OptionalUser = Annotated[AccessUser | None, Depends(get_optional_user)]
"""``user: OptionalUser`` -- a human user, or ``None``."""
