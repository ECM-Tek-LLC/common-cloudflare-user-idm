"""Test helpers for applications that use this framework.

Consuming apps need to test their protected routes, and neither "reach a real Cloudflare
tenant from CI" nor "monkeypatch the auth layer away" is acceptable. This module gives you
both realistic options:

* :class:`AccessTestKit` generates a throwaway RSA key pair, publishes a matching JWKS and
  mints signed tokens, so your tests exercise the *real* verification path -- signature,
  audience, issuer, expiry -- with no network access.
* :func:`override_principal` swaps in a fixed caller via FastAPI dependency overrides, for
  the majority of tests that care about your business logic rather than about auth.

Requires the ``testing`` extra::

    pip install "common-cloudflare-user-idm[testing]"
"""

from __future__ import annotations

import json
import time
import uuid
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from jwt.algorithms import RSAAlgorithm

from .dependencies import get_current_principal, get_optional_user
from .jwks import JwksCache
from .models import AccessUser, Principal, ServicePrincipal
from .settings import CfAccessSettings

__all__ = ["AccessTestKit", "make_service_principal", "make_user", "override_principal"]

DEFAULT_TEAM = "testteam"
DEFAULT_AUDIENCE = "test-audience-tag"
DEFAULT_KID = "test-key-1"


class AccessTestKit:
    """A self-contained stand-in for a Cloudflare Access tenant.

    Example::

        kit = AccessTestKit()
        app = FastAPI()
        install_cf_access(app, kit.settings(), jwks=kit.jwks_cache())

        token = kit.mint(email="user@example.com")
        client.get("/profile", headers=kit.headers(token))
    """

    def __init__(
        self,
        *,
        team_domain: str = DEFAULT_TEAM,
        audience: Sequence[str] = (DEFAULT_AUDIENCE,),
        kid: str = DEFAULT_KID,
    ) -> None:
        self.team_domain = team_domain
        self.audience = list(audience)
        self.kid = kid
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._foreign_key: rsa.RSAPrivateKey | None = None

    # --- Cloudflare-side surface -------------------------------------------------

    @property
    def issuer(self) -> str:
        return f"https://{self.team_domain}.cloudflareaccess.com"

    @property
    def certs_url(self) -> str:
        return f"{self.issuer}/cdn-cgi/access/certs"

    @property
    def identity_url(self) -> str:
        return f"{self.issuer}/cdn-cgi/access/get-identity"

    @property
    def jwks(self) -> dict[str, Any]:
        """The JWKS document Cloudflare would publish for this key pair."""
        key: dict[str, Any] = json.loads(RSAAlgorithm.to_jwk(self._private_key.public_key()))
        key.update({"kid": self.kid, "alg": "RS256", "use": "sig"})
        return {"keys": [key]}

    def jwks_cache(self) -> JwksCache:
        """A key cache preloaded with this kit's JWKS, which never hits the network."""
        return JwksCache.from_static(self.jwks, certs_url=self.certs_url)

    def settings(self, **overrides: Any) -> CfAccessSettings:
        """Settings pointing at this kit. Override any field via keyword."""
        values: dict[str, Any] = {
            "team_domain": self.team_domain,
            "audience": self.audience,
            "app_env": "test",
        }
        values.update(overrides)
        return CfAccessSettings(**values)

    # --- Token minting ------------------------------------------------------------

    def mint(
        self,
        *,
        sub: str | None = None,
        email: str = "user@example.com",
        audience: Sequence[str] | str | None = None,
        issuer: str | None = None,
        issued_at: int | None = None,
        expires_in: int = 3600,
        kid: str | None = None,
        common_name: str | None = None,
        custom: dict[str, Any] | None = None,
        extra_claims: dict[str, Any] | None = None,
        sign_with_foreign_key: bool = False,
    ) -> str:
        """Mint a signed token.

        Defaults produce a valid user token. Every knob exists so a test can produce
        exactly one kind of invalid token:

        * ``expires_in=-3600`` -- expired
        * ``audience="other"`` -- issued for a different application
        * ``issuer="https://other.cloudflareaccess.com"`` -- different team
        * ``kid="unknown"`` -- signed with a key the JWKS does not publish
        * ``sign_with_foreign_key=True`` -- forged signature
        """
        now = int(time.time()) if issued_at is None else issued_at
        aud = self.audience if audience is None else audience

        claims: dict[str, Any] = {
            "aud": list(aud) if isinstance(aud, (list, tuple)) else [aud],
            "iss": issuer or self.issuer,
            "iat": now,
            "nbf": now,
            "exp": now + expires_in,
            "type": "app",
        }

        if common_name is not None:
            claims["common_name"] = common_name
            claims["sub"] = ""
        else:
            claims["sub"] = sub or str(uuid.uuid5(uuid.NAMESPACE_URL, f"cf-access:{email}"))
            claims["email"] = email
            claims["identity_nonce"] = "test-nonce"
            claims["country"] = "US"
            if custom:
                claims["custom"] = custom

        if extra_claims:
            claims.update(extra_claims)

        key = self._get_foreign_key() if sign_with_foreign_key else self._private_key
        return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid or self.kid})

    def mint_service_token(self, common_name: str = "svc-client.access", **kwargs: Any) -> str:
        """Mint a token shaped like a Cloudflare Access service token."""
        return self.mint(common_name=common_name, **kwargs)

    def mint_raw(
        self,
        claims: dict[str, Any],
        *,
        kid: str | None = None,
        algorithm: str = "RS256",
        sign_with_foreign_key: bool = False,
    ) -> str:
        """Sign exactly the claims given, with no defaults filled in.

        For tests that need a deliberately malformed token -- missing required claims, or
        ``algorithm="none"`` to check the JWT downgrade attack is refused.
        """
        if algorithm == "none":
            key: Any = ""
        elif sign_with_foreign_key:
            key = self._get_foreign_key()
        else:
            key = self._private_key
        return jwt.encode(claims, key, algorithm=algorithm, headers={"kid": kid or self.kid})

    @staticmethod
    def headers(token: str) -> dict[str, str]:
        """Request headers Cloudflare would add when forwarding a request."""
        return {"Cf-Access-Jwt-Assertion": token}

    @staticmethod
    def cookies(token: str) -> dict[str, str]:
        """Cookies a browser session would carry."""
        return {"CF_Authorization": token}

    def _get_foreign_key(self) -> rsa.RSAPrivateKey:
        """A second key pair that is *not* published, for forged-signature tests."""
        if self._foreign_key is None:
            self._foreign_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        return self._foreign_key


def make_user(
    *,
    id: str = "11111111-1111-1111-1111-111111111111",
    email: str = "user@example.com",
    **overrides: Any,
) -> AccessUser:
    """Build an :class:`~cf_user_idm.models.AccessUser` for tests, no token involved."""
    return AccessUser(id=id, email=email, **overrides)


def make_service_principal(common_name: str = "svc-client.access") -> ServicePrincipal:
    """Build a :class:`~cf_user_idm.models.ServicePrincipal` for tests."""
    return ServicePrincipal(id=common_name, common_name=common_name)


@contextmanager
def override_principal(app: FastAPI, principal: Principal) -> Iterator[Principal]:
    """Force every identification dependency to return ``principal``.

    For the many tests that need *a* logged-in user but do not care how the token was
    verified::

        with override_principal(app, make_user(email="admin@example.com")):
            response = client.get("/reports")
    """
    is_user = isinstance(principal, AccessUser)
    overrides = app.dependency_overrides
    previous = {
        dependency: overrides.get(dependency)
        for dependency in (get_current_principal, get_optional_user)
    }

    # get_current_user is deliberately left alone: it chains off get_current_principal, so
    # overriding the principal keeps its real behaviour -- including rejecting a service
    # principal with 403 on a human-only route.
    overrides[get_current_principal] = lambda: principal
    overrides[get_optional_user] = lambda: principal if is_user else None

    try:
        yield principal
    finally:
        for dependency, original in previous.items():
            if original is None:
                overrides.pop(dependency, None)
            else:
                overrides[dependency] = original
