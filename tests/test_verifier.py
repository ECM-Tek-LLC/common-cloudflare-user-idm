"""Token verification: every way a token can be good, and every way it can be bad."""

from __future__ import annotations

import pytest

from cf_user_idm import (
    AccessTokenVerifier,
    AccessUser,
    AudienceMismatchError,
    InvalidTokenError,
    IssuerMismatchError,
    ServicePrincipal,
    SigningKeyUnavailableError,
    TokenExpiredError,
)
from cf_user_idm.testing import AccessTestKit


@pytest.fixture
def verifier(kit: AccessTestKit) -> AccessTokenVerifier:
    return AccessTokenVerifier(kit.settings(), kit.jwks_cache())


async def test_valid_token_yields_a_user(kit: AccessTestKit, verifier: AccessTokenVerifier) -> None:
    token = kit.mint(sub="user-123", email="ada@example.com")

    principal = await verifier.verify(token)

    assert isinstance(principal, AccessUser)
    assert principal.id == "user-123"
    assert principal.email == "ada@example.com"
    assert principal.country == "US"
    assert principal.is_service is False
    assert principal.expires_at is not None


async def test_custom_claims_are_preserved(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint(custom={"department": "platform"})

    principal = await verifier.verify(token)

    assert principal.custom == {"department": "platform"}


async def test_expired_token_is_rejected(kit: AccessTestKit, verifier: AccessTokenVerifier) -> None:
    token = kit.mint(expires_in=-3600)

    with pytest.raises(TokenExpiredError) as excinfo:
        await verifier.verify(token)

    assert excinfo.value.status_code == 401


async def test_token_within_leeway_is_still_accepted(kit: AccessTestKit) -> None:
    verifier = AccessTokenVerifier(kit.settings(leeway=120), kit.jwks_cache())
    token = kit.mint(expires_in=-30)

    principal = await verifier.verify(token)

    assert isinstance(principal, AccessUser)


async def test_token_for_another_application_is_forbidden(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint(audience="some-other-app")

    with pytest.raises(AudienceMismatchError) as excinfo:
        await verifier.verify(token)

    assert excinfo.value.status_code == 403


async def test_any_configured_audience_is_accepted(kit: AccessTestKit) -> None:
    settings = kit.settings(audience=[*kit.audience, "second-app"])
    verifier = AccessTokenVerifier(settings, kit.jwks_cache())

    principal = await verifier.verify(kit.mint(audience="second-app"))

    assert isinstance(principal, AccessUser)


async def test_token_from_another_team_is_forbidden(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint(issuer="https://someone-else.cloudflareaccess.com")

    with pytest.raises(IssuerMismatchError) as excinfo:
        await verifier.verify(token)

    assert excinfo.value.status_code == 403


async def test_forged_signature_is_rejected(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint(sign_with_foreign_key=True)

    with pytest.raises(InvalidTokenError):
        await verifier.verify(token)


async def test_unknown_signing_key_is_rejected(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint(kid="a-key-cloudflare-never-published")

    with pytest.raises(SigningKeyUnavailableError):
        await verifier.verify(token)


async def test_garbage_is_rejected(verifier: AccessTokenVerifier) -> None:
    with pytest.raises(InvalidTokenError):
        await verifier.verify("this-is-not-a-jwt")


async def test_unsigned_token_is_rejected(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    """An ``alg: none`` token must never be accepted -- the classic JWT downgrade attack."""
    unsigned = kit.mint_raw(
        {
            "aud": kit.audience,
            "iss": kit.issuer,
            "sub": "x",
            "email": "x@y.z",
            "iat": 1,
            "exp": 9999999999,
        },
        algorithm="none",
    )

    with pytest.raises(InvalidTokenError):
        await verifier.verify(unsigned)


async def test_missing_required_claim_is_rejected(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint_raw(
        {"aud": kit.audience, "iss": kit.issuer, "sub": "x", "email": "x@y.z"}  # no exp/iat
    )

    with pytest.raises(InvalidTokenError, match="required"):
        await verifier.verify(token)


async def test_service_token_yields_a_service_principal(
    kit: AccessTestKit, verifier: AccessTokenVerifier
) -> None:
    token = kit.mint_service_token(common_name="ci-runner.access")

    principal = await verifier.verify(token)

    assert isinstance(principal, ServicePrincipal)
    assert principal.id == "ci-runner.access"
    assert principal.common_name == "ci-runner.access"
    assert principal.is_service is True


async def test_token_identifying_nobody_is_rejected(kit: AccessTestKit) -> None:
    verifier = AccessTokenVerifier(kit.settings(), kit.jwks_cache())
    token = kit.mint(email="", extra_claims={"sub": "", "email": ""})

    with pytest.raises(InvalidTokenError, match="neither a user"):
        await verifier.verify(token)
