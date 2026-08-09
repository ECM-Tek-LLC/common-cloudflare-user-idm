"""The identity types this framework hands to your application.

There are exactly two kinds of caller behind Cloudflare Access:

* :class:`AccessUser` -- a human who authenticated through your identity provider.
* :class:`ServicePrincipal` -- a machine using a Cloudflare Access service token.

Both are :data:`Principal`. Routes written for humans should depend on ``AccessUser`` and
will reject service tokens automatically; routes that serve both should depend on
``Principal``.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

__all__ = ["AccessGroup", "AccessUser", "IdentityDetails", "Principal", "ServicePrincipal"]


def _to_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), tz=UTC)


class AccessGroup(BaseModel):
    """A group from your identity provider, as reported by the get-identity endpoint.

    Only populated when identity enrichment is enabled. This framework does not use groups
    for any decision -- Cloudflare Access policy already decided the caller may be here.
    They are exposed purely as information your application may want.
    """

    id: str | None = None
    name: str | None = None
    email: str | None = None


class IdentityDetails(BaseModel):
    """Extra profile information fetched from ``/cdn-cgi/access/get-identity``.

    The Access application token deliberately carries very little: it has no display name
    and no group membership. When ``CF_ACCESS_FETCH_IDENTITY`` is enabled, this is filled
    in from Cloudflare's identity endpoint. It is best-effort -- if the call fails the
    request still succeeds with ``details`` left as ``None``.
    """

    name: str | None = None
    groups: list[AccessGroup] = Field(default_factory=list)
    idp_id: str | None = None
    idp_type: str | None = None
    geo_country: str | None = None
    is_warp: bool | None = None
    is_gateway: bool | None = None


class AccessUser(BaseModel):
    """A human user authenticated by Cloudflare Access.

    .. important::
       **Key your application's user table on** :attr:`id` **(the token's ``sub``), never
       on email.** ``sub`` is a stable Cloudflare user UUID. Email addresses change --
       people get married, companies rename domains, identity providers re-provision
       accounts -- and every one of those events would silently create a duplicate user if
       email were the key. Store email as an ordinary mutable attribute and refresh it on
       each login.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    """Cloudflare user UUID (the token's ``sub`` claim). The stable primary key."""

    email: str
    """Current email address. Mutable -- informational, not an identifier."""

    identity_nonce: str | None = None
    """Per-session nonce. Used as the enrichment cache key."""

    country: str | None = None
    """Two-letter country the user authenticated from, when Cloudflare reports it."""

    issued_at: datetime | None = None
    expires_at: datetime | None = None

    custom: dict[str, Any] = Field(default_factory=dict)
    """Custom claims your identity provider was configured to pass through."""

    details: IdentityDetails | None = None
    """Populated only when identity enrichment is enabled and the fetch succeeded."""

    is_service: Literal[False] = False

    claims: dict[str, Any] = Field(default_factory=dict, exclude=True, repr=False)
    """Raw verified JWT claims. Escape hatch for claims this model does not model.

    Excluded from serialization so responses never leak the full token payload.
    """

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> AccessUser:
        return cls(
            id=str(claims.get("sub") or ""),
            email=str(claims.get("email") or ""),
            identity_nonce=claims.get("identity_nonce"),
            country=claims.get("country"),
            issued_at=_to_datetime(claims.get("iat")),
            expires_at=_to_datetime(claims.get("exp")),
            custom=claims.get("custom") or {},
            claims=claims,
        )


class ServicePrincipal(BaseModel):
    """A machine caller using a Cloudflare Access service token.

    Service-token JWTs carry a ``common_name`` (the client ID) and have no email and no
    meaningful ``sub``, so they cannot be treated as a user. Dependencies that expect a
    human reject these with 403 rather than handing back a user object with empty fields.
    """

    model_config = ConfigDict(frozen=True)

    id: str
    """The service token's ``common_name``. Stable identifier for this machine client."""

    common_name: str
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    is_service: Literal[True] = True

    claims: dict[str, Any] = Field(default_factory=dict, exclude=True, repr=False)

    @classmethod
    def from_claims(cls, claims: dict[str, Any]) -> ServicePrincipal:
        common_name = str(claims.get("common_name") or "")
        return cls(
            id=common_name,
            common_name=common_name,
            issued_at=_to_datetime(claims.get("iat")),
            expires_at=_to_datetime(claims.get("exp")),
            claims=claims,
        )


Principal = AccessUser | ServicePrincipal
"""Any authenticated caller -- human or machine."""
