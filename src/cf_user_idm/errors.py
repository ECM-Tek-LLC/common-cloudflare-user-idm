"""Error types for Cloudflare Access identification.

Every failure the framework can produce is one of these. They carry an HTTP status and a
stable machine-readable ``code`` so consuming apps (and their clients) can branch on the
reason without string-matching a message.

Status convention:

* **401** -- we could not establish *who* the caller is (no token, bad signature, expired).
* **403** -- the token is genuine but is not for this application (wrong audience, wrong
  issuer, or a service token hitting a human-only route).
"""

from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

__all__ = [
    "AccessAuthError",
    "AudienceMismatchError",
    "ConfigurationError",
    "InvalidTokenError",
    "IssuerMismatchError",
    "MissingTokenError",
    "ServiceTokenNotPermittedError",
    "SigningKeyUnavailableError",
    "TokenExpiredError",
    "register_exception_handler",
]


class AccessAuthError(Exception):
    """Base class for all identification failures.

    Rendered by :func:`register_exception_handler` as
    ``{"error": {"code": ..., "message": ...}}``.
    """

    status_code: int = 401
    code: str = "access_auth_error"
    message: str = "Cloudflare Access authentication failed."

    def __init__(self, message: str | None = None) -> None:
        if message is not None:
            self.message = message
        super().__init__(self.message)

    @property
    def headers(self) -> dict[str, str]:
        """Response headers to attach. 401s advertise the expected scheme."""
        if self.status_code == 401:
            return {"WWW-Authenticate": 'Bearer realm="cloudflare-access"'}
        return {}


class MissingTokenError(AccessAuthError):
    """No Access token was present on the request.

    In a correctly deployed app this should be impossible for real user traffic: Cloudflare
    Access injects the token before the request reaches the origin. Seeing this in
    production usually means the origin is reachable *without* going through Cloudflare.
    """

    status_code = 401
    code = "missing_token"
    message = "No Cloudflare Access token was present on the request."


class InvalidTokenError(AccessAuthError):
    """The token is malformed or its signature does not verify."""

    status_code = 401
    code = "invalid_token"
    message = "The Cloudflare Access token is invalid."


class TokenExpiredError(AccessAuthError):
    """The token is past its ``exp`` (beyond the configured leeway)."""

    status_code = 401
    code = "token_expired"
    message = "The Cloudflare Access token has expired."


class SigningKeyUnavailableError(AccessAuthError):
    """The key that signed this token could not be resolved from the team's JWKS."""

    status_code = 401
    code = "signing_key_unavailable"
    message = "The signing key for this token is not available."


class AudienceMismatchError(AccessAuthError):
    """A valid Access token, but issued for a different application."""

    status_code = 403
    code = "audience_mismatch"
    message = "The token was not issued for this application."


class IssuerMismatchError(AccessAuthError):
    """A valid token from a different Cloudflare One team."""

    status_code = 403
    code = "issuer_mismatch"
    message = "The token was not issued by the configured Cloudflare Access team."


class ServiceTokenNotPermittedError(AccessAuthError):
    """A service token reached a route that is for human users only."""

    status_code = 403
    code = "service_token_not_permitted"
    message = "This endpoint requires a human user; service tokens are not permitted."


class ConfigurationError(RuntimeError):
    """The framework is misconfigured.

    Raised at startup rather than per request -- a deployment that cannot verify tokens
    should fail loudly and immediately instead of serving traffic it cannot authenticate.
    """


async def _handle(_request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, AccessAuthError)  # registered only for this type
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.code, "message": exc.message}},
        headers=exc.headers,
    )


def register_exception_handler(app: FastAPI) -> None:
    """Render :class:`AccessAuthError` as a structured JSON body.

    Called for you by :func:`cf_user_idm.install_cf_access`.
    """
    app.add_exception_handler(AccessAuthError, _handle)
