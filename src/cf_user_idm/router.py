"""A small router every consuming app can mount instead of rewriting.

Mounted at ``CF_ACCESS_ROUTER_PREFIX`` (default ``/auth``) by
:func:`cf_user_idm.install_cf_access`.
"""

from __future__ import annotations

from typing import Any

import jwt
from fastapi import APIRouter, Depends
from starlette.requests import Request
from starlette.responses import RedirectResponse

from .dependencies import get_current_principal
from .errors import ConfigurationError
from .extract import ACCESS_COOKIE, ACCESS_JWT_HEADER, extract_token
from .models import Principal
from .runtime import get_runtime
from .settings import CfAccessSettings

__all__ = ["build_router"]


def build_router(settings: CfAccessSettings) -> APIRouter:
    """Build the auth router for these settings.

    The debug endpoint is only registered when explicitly enabled -- it is not gated at
    request time, it simply does not exist otherwise.
    """
    router = APIRouter(prefix=settings.router_prefix, tags=["auth"])

    @router.get("/me", response_model=None, summary="The caller identified by Cloudflare Access")
    async def me(principal: Principal = Depends(get_current_principal)) -> Principal:
        """Return the current caller.

        Handy as a browser-visible sanity check that Access is wired up, and as the
        endpoint a frontend calls on load to learn who it is talking to.
        """
        return principal

    @router.get("/logout", summary="Log out of Cloudflare Access")
    async def logout(request: Request) -> RedirectResponse:
        """Clear the local session cookie and hand off to Cloudflare's logout.

        Clearing the cookie here is not enough on its own: the session lives at
        Cloudflare's edge, so the user has to be sent there to actually end it.
        """
        runtime = get_runtime(request)
        if not runtime.settings.team_domain:
            raise ConfigurationError(
                "Cannot build a Cloudflare Access logout URL without CF_ACCESS_TEAM_DOMAIN."
            )
        response = RedirectResponse(url=runtime.settings.logout_url, status_code=302)
        response.delete_cookie(ACCESS_COOKIE)
        return response

    if settings.enable_debug_endpoint:

        @router.get("/debug", summary="Diagnose Cloudflare Access wiring")
        async def debug(request: Request) -> dict[str, Any]:
            """Report how identification is configured and what arrived on this request.

            Deliberately reports *shape*, never content: which claims exist but not their
            values, the token's key id but not the token. Enough to diagnose a 401 or a
            403 without turning the endpoint into a token leak.
            """
            runtime = get_runtime(request)
            token = extract_token(request)

            token_info: dict[str, Any] = {
                "present": token is not None,
                "source": (
                    ACCESS_JWT_HEADER
                    if request.headers.get(ACCESS_JWT_HEADER)
                    else ACCESS_COOKIE
                    if request.cookies.get(ACCESS_COOKIE)
                    else None
                ),
            }
            if token:
                try:
                    header = jwt.get_unverified_header(token)
                    unverified = jwt.decode(token, options={"verify_signature": False})
                    token_info["kid"] = header.get("kid")
                    token_info["alg"] = header.get("alg")
                    token_info["claims_present"] = sorted(unverified)
                    token_info["kind"] = "service" if unverified.get("common_name") else "user"
                except jwt.PyJWTError as exc:
                    token_info["parse_error"] = str(exc)

            return {
                "dev_mode": runtime.settings.dev_mode,
                "app_env": runtime.settings.app_env,
                "team_domain": runtime.settings.team_domain,
                "issuer": (runtime.settings.issuer if runtime.settings.team_domain else None),
                "audience_count": len(runtime.settings.audience),
                "fetch_identity": runtime.settings.fetch_identity,
                "allow_service_tokens": runtime.settings.allow_service_tokens,
                "jwks": {
                    "age_seconds": runtime.jwks.age,
                    "key_ids": runtime.jwks.key_ids,
                    "fetch_count": runtime.jwks.fetch_count,
                },
                "token": token_info,
            }

    return router
