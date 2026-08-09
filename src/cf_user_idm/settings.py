"""Configuration, read from the environment with the ``CF_ACCESS_`` prefix.

The validators here are the framework's safety net: a deployment that cannot verify tokens,
or one that has the development bypass switched on in production, fails at startup instead
of quietly serving unauthenticated traffic.
"""

from __future__ import annotations

import re
from typing import Annotated, Any

from pydantic import AliasChoices, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from .errors import ConfigurationError

__all__ = ["PRODUCTION_LIKE_ENVIRONMENTS", "CfAccessSettings"]

PRODUCTION_LIKE_ENVIRONMENTS = frozenset({"prod", "production", "stage", "staging"})
"""Environment names where the development bypass must never be enabled."""

_TEAM_DOMAIN_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$", re.IGNORECASE)


class CfAccessSettings(BaseSettings):
    """Settings for Cloudflare Access identification.

    Instantiate with no arguments to read from the environment::

        settings = CfAccessSettings()

    or pass values explicitly (tests, or apps with their own config system)::

        settings = CfAccessSettings(team_domain="acme", audience=["<aud tag>"])
    """

    model_config = SettingsConfigDict(
        env_prefix="CF_ACCESS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- Cloudflare identity -------------------------------------------------------

    team_domain: str | None = None
    """Your Cloudflare One team. Accepts ``acme``, ``acme.cloudflareaccess.com``, or a full
    URL -- all normalize to ``https://acme.cloudflareaccess.com``."""

    audience: Annotated[list[str], NoDecode] = Field(default_factory=list)
    """One or more Application Audience (AUD) tags. Comma-separated in the environment.

    A list because an origin sometimes sits behind more than one Access application (for
    example a public hostname and an internal one). A token matching *any* configured AUD
    is accepted."""

    # --- Environment ---------------------------------------------------------------

    app_env: str = Field(
        default="development",
        validation_alias=AliasChoices("CF_ACCESS_APP_ENV", "APP_ENV"),
    )
    """Deployment environment name. Read from ``APP_ENV`` as well as ``CF_ACCESS_APP_ENV``.
    Used to forbid the development bypass in production-like environments."""

    # --- Development bypass --------------------------------------------------------

    dev_mode: bool = False
    """Skip token verification and inject a synthetic user. Local development only --
    startup fails if this is set while :attr:`app_env` looks production-like."""

    dev_user_email: str | None = None
    """Email for the synthetic development user. Required when :attr:`dev_mode` is on."""

    dev_user_sub: str = "00000000-0000-0000-0000-000000000000"
    """``sub`` for the synthetic development user."""

    dev_user_name: str = "Local Developer"

    # --- Verification tuning -------------------------------------------------------

    jwks_cache_ttl: int = 3600
    """Seconds to cache the team's signing keys. Cloudflare rotates roughly every 6 weeks;
    an hour keeps rotation invisible without hammering the endpoint."""

    jwks_min_refresh_interval: int = 300
    """Minimum seconds between out-of-band refreshes triggered by an unknown key id.
    Without this floor, a flood of tokens with bogus ``kid`` values would turn into a
    request flood against Cloudflare."""

    jwks_timeout: float = 5.0
    """HTTP timeout, in seconds, for JWKS and identity requests."""

    leeway: int = 60
    """Clock-skew tolerance in seconds when checking ``exp``/``iat``/``nbf``."""

    # --- Optional identity enrichment ----------------------------------------------

    fetch_identity: bool = False
    """Call ``/cdn-cgi/access/get-identity`` to add display name, groups and IdP details.

    Off by default: it adds a network call and a failure mode, and the JWT alone is enough
    to identify a user. Enrichment requires the ``CF_Authorization`` cookie, so it only
    works for browser traffic."""

    identity_cache_ttl: int = 300
    """Seconds to cache an enrichment result, keyed by the token's ``identity_nonce``."""

    # --- Principals ----------------------------------------------------------------

    allow_service_tokens: bool = True
    """Whether service-token callers may be identified at all.

    Even when true, they are only accepted on routes that explicitly ask for a
    ``Principal``; routes asking for an ``AccessUser`` always reject them."""

    # --- Router --------------------------------------------------------------------

    router_prefix: str = "/auth"
    """Mount point for the built-in router."""

    enable_debug_endpoint: bool = False
    """Expose ``{router_prefix}/debug``. Never reveals token contents, but does reveal
    configuration, so it is off by default."""

    @field_validator("audience", mode="before")
    @classmethod
    def _split_audience(cls, value: Any) -> Any:
        """Accept ``aud1,aud2`` from the environment as well as a real list."""
        if isinstance(value, str):
            return [part.strip() for part in value.split(",") if part.strip()]
        return value

    @field_validator("team_domain", mode="before")
    @classmethod
    def _normalize_team_domain(cls, value: Any) -> Any:
        """Reduce any accepted spelling of the team domain to a bare team name."""
        if not isinstance(value, str):
            return value
        team = value.strip().rstrip("/")
        if not team:
            return None
        team = re.sub(r"^https?://", "", team, flags=re.IGNORECASE)
        team = team.split("/", 1)[0]
        team = re.sub(r"\.cloudflareaccess\.com$", "", team, flags=re.IGNORECASE)
        if not _TEAM_DOMAIN_RE.match(team):
            raise ValueError(
                f"Could not parse a Cloudflare team name from {value!r}. Expected something "
                "like 'acme' or 'acme.cloudflareaccess.com'."
            )
        return team

    @field_validator("router_prefix")
    @classmethod
    def _validate_prefix(cls, value: str) -> str:
        value = value.rstrip("/")
        if value and not value.startswith("/"):
            raise ValueError("router_prefix must start with '/'")
        return value

    @model_validator(mode="after")
    def _validate_configuration(self) -> CfAccessSettings:
        if self.dev_mode:
            if self.app_env.strip().lower() in PRODUCTION_LIKE_ENVIRONMENTS:
                raise ConfigurationError(
                    "CF_ACCESS_DEV_MODE is enabled while APP_ENV is "
                    f"{self.app_env!r}. The development bypass accepts every request "
                    "without a Cloudflare Access token and must never run in a "
                    "production-like environment. Refusing to start."
                )
            if not self.dev_user_email:
                raise ConfigurationError(
                    "CF_ACCESS_DEV_MODE is enabled but CF_ACCESS_DEV_USER_EMAIL is not set. "
                    "The synthetic development user needs an email so it is obvious in logs "
                    "that the bypass is active."
                )
            return self

        missing = [
            name
            for name, value in (
                ("CF_ACCESS_TEAM_DOMAIN", self.team_domain),
                ("CF_ACCESS_AUDIENCE", self.audience),
            )
            if not value
        ]
        if missing:
            verb = "is" if len(missing) == 1 else "are"
            raise ConfigurationError(
                f"{' and '.join(missing)} {verb} not configured, so incoming Cloudflare "
                "Access tokens cannot be verified. Set it, or set CF_ACCESS_DEV_MODE=true "
                "for local development."
            )
        return self

    # --- Derived URLs ----------------------------------------------------------------

    @property
    def issuer(self) -> str:
        """The ``iss`` value Cloudflare puts in tokens for this team."""
        return f"https://{self.team_domain}.cloudflareaccess.com"

    @property
    def certs_url(self) -> str:
        """JWKS endpoint holding the team's public signing keys."""
        return f"{self.issuer}/cdn-cgi/access/certs"

    @property
    def identity_url(self) -> str:
        """Endpoint returning the enriched identity for a session."""
        return f"{self.issuer}/cdn-cgi/access/get-identity"

    @property
    def logout_url(self) -> str:
        """Cloudflare Access logout endpoint for this team."""
        return f"{self.issuer}/cdn-cgi/access/logout"
