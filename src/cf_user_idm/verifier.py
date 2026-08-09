"""Cryptographic verification of Cloudflare Access application tokens."""

from __future__ import annotations

import logging
from typing import Any

import jwt
from jwt import exceptions as jwt_exceptions

from .errors import (
    AudienceMismatchError,
    InvalidTokenError,
    IssuerMismatchError,
    TokenExpiredError,
)
from .jwks import JwksCache
from .models import AccessUser, Principal, ServicePrincipal
from .settings import CfAccessSettings

__all__ = ["AccessTokenVerifier"]

logger = logging.getLogger(__name__)

ALGORITHMS = ["RS256"]
"""Cloudflare signs Access tokens with RS256. Pinning the algorithm list is what stops an
attacker swapping in ``alg: none`` or an HMAC algorithm keyed on our public key."""

REQUIRED_CLAIMS = ["exp", "iat", "aud", "iss"]


class AccessTokenVerifier:
    """Turns a raw Access JWT into a :data:`~cf_user_idm.models.Principal`.

    Verification is entirely local once the signing keys are cached, so this adds no
    network round trip to a request.
    """

    def __init__(self, settings: CfAccessSettings, jwks: JwksCache) -> None:
        self.settings = settings
        self.jwks = jwks

    async def verify(self, token: str) -> Principal:
        """Verify ``token`` and return the caller it identifies.

        Raises a subclass of :class:`~cf_user_idm.errors.AccessAuthError` on any failure.
        """
        claims = await self.verify_claims(token)
        return self.to_principal(claims)

    async def verify_claims(self, token: str) -> dict[str, Any]:
        """Verify ``token`` and return its claims, without interpreting them."""
        try:
            header = jwt.get_unverified_header(token)
        except jwt_exceptions.PyJWTError as exc:
            raise InvalidTokenError("The Access token is malformed.") from exc

        signing_key = await self.jwks.get_key(header.get("kid"))

        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=signing_key.key,
                algorithms=ALGORITHMS,
                audience=self.settings.audience,
                issuer=self.settings.issuer,
                leeway=self.settings.leeway,
                options={"require": REQUIRED_CLAIMS},
            )
        except jwt_exceptions.ExpiredSignatureError as exc:
            raise TokenExpiredError() from exc
        except jwt_exceptions.InvalidAudienceError as exc:
            raise AudienceMismatchError() from exc
        except jwt_exceptions.InvalidIssuerError as exc:
            raise IssuerMismatchError() from exc
        except jwt_exceptions.MissingRequiredClaimError as exc:
            raise InvalidTokenError(
                f"The Access token is missing the required {exc.claim!r} claim."
            ) from exc
        except jwt_exceptions.PyJWTError as exc:
            # Covers bad signatures, malformed segments, immature tokens and anything else
            # PyJWT rejects. All of them mean the same thing to us: we cannot trust this.
            raise InvalidTokenError() from exc

        return claims

    @staticmethod
    def to_principal(claims: dict[str, Any]) -> Principal:
        """Classify verified claims as a human user or a machine caller.

        Service-token tokens carry ``common_name`` (the client id) and no email; user
        tokens carry ``email`` and a ``sub`` that identifies the person.
        """
        email = claims.get("email")
        common_name = claims.get("common_name")

        if common_name and not email:
            return ServicePrincipal.from_claims(claims)

        if not email or not claims.get("sub"):
            raise InvalidTokenError(
                "The Access token identifies neither a user (email and sub) nor a service "
                "token (common_name)."
            )

        return AccessUser.from_claims(claims)
