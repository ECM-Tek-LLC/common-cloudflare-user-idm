"""Cloudflare Zero Trust user identification for FastAPI applications.

This package answers one question for an application sitting behind Cloudflare Access:
**who is making this request?** It verifies the Access-issued JWT and hands your code a
typed identity.

It deliberately does *not* answer "what may they do?". Cloudflare Access policy already
decided whether this caller is allowed to reach the application; roles and permissions
inside the application are the application's own business.

Quick start::

    from fastapi import FastAPI
    from cf_user_idm import CurrentUser, install_cf_access

    app = FastAPI()
    install_cf_access(app)

    @app.get("/profile")
    async def profile(user: CurrentUser):
        return {"id": user.id, "email": user.email}

See ``docs/INTEGRATION.md`` for a full integration walkthrough.
"""

from __future__ import annotations

from .dependencies import (
    CurrentPrincipal,
    CurrentUser,
    OptionalUser,
    get_current_principal,
    get_current_user,
    get_optional_user,
)
from .errors import (
    AccessAuthError,
    AudienceMismatchError,
    ConfigurationError,
    InvalidTokenError,
    IssuerMismatchError,
    MissingTokenError,
    ServiceTokenNotPermittedError,
    SigningKeyUnavailableError,
    TokenExpiredError,
)
from .extract import ACCESS_COOKIE, ACCESS_JWT_HEADER, extract_token
from .integration import install_cf_access
from .jwks import JwksCache
from .models import AccessGroup, AccessUser, IdentityDetails, Principal, ServicePrincipal
from .runtime import CfAccessRuntime, get_runtime
from .settings import CfAccessSettings
from .verifier import AccessTokenVerifier

__version__ = "0.1.0"

__all__ = [
    "ACCESS_COOKIE",
    "ACCESS_JWT_HEADER",
    "AccessAuthError",
    "AccessGroup",
    "AccessTokenVerifier",
    "AccessUser",
    "AudienceMismatchError",
    "CfAccessRuntime",
    "CfAccessSettings",
    "ConfigurationError",
    "CurrentPrincipal",
    "CurrentUser",
    "IdentityDetails",
    "InvalidTokenError",
    "IssuerMismatchError",
    "JwksCache",
    "MissingTokenError",
    "OptionalUser",
    "Principal",
    "ServicePrincipal",
    "ServiceTokenNotPermittedError",
    "SigningKeyUnavailableError",
    "TokenExpiredError",
    "__version__",
    "extract_token",
    "get_current_principal",
    "get_current_user",
    "get_optional_user",
    "get_runtime",
    "install_cf_access",
]
