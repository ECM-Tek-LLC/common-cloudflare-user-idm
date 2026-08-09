"""Optional get-identity enrichment, including its failure modes."""

from __future__ import annotations

from collections.abc import Callable

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cf_user_idm.identity import IdentityClient
from cf_user_idm.testing import AccessTestKit

IDENTITY_URL = "https://testteam.cloudflareaccess.com/cdn-cgi/access/get-identity"

IDENTITY_PAYLOAD = {
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "groups": [
        {"id": "g1", "name": "Engineering", "email": "eng@example.com"},
        {"id": "g2", "name": "On-call"},
    ],
    "idp": {"id": "idp-1", "type": "okta"},
    "geo": {"country": "GB"},
    "is_warp": True,
    "is_gateway": False,
}


@pytest.fixture
def enriched_app(app_factory: Callable[..., FastAPI]) -> FastAPI:
    return app_factory(fetch_identity=True)


def test_enrichment_adds_the_display_name(enriched_app: FastAPI, kit: AccessTestKit) -> None:
    with respx.mock:
        respx.get(IDENTITY_URL).mock(return_value=httpx.Response(200, json=IDENTITY_PAYLOAD))
        with TestClient(enriched_app) as client:
            response = client.get("/profile", headers=kit.headers(kit.mint()))

    assert response.status_code == 200
    assert response.json()["name"] == "Ada Lovelace"


def test_enrichment_is_cached_per_session(enriched_app: FastAPI, kit: AccessTestKit) -> None:
    token = kit.mint()

    with respx.mock:
        route = respx.get(IDENTITY_URL).mock(
            return_value=httpx.Response(200, json=IDENTITY_PAYLOAD)
        )
        with TestClient(enriched_app) as client:
            for _ in range(4):
                client.get("/profile", headers=kit.headers(token))

    assert route.call_count == 1


def test_enrichment_failure_does_not_fail_the_request(
    enriched_app: FastAPI, kit: AccessTestKit
) -> None:
    """Identity is already established by this point -- degrade, do not reject."""
    with respx.mock:
        respx.get(IDENTITY_URL).mock(return_value=httpx.Response(500))
        with TestClient(enriched_app) as client:
            response = client.get("/profile", headers=kit.headers(kit.mint()))

    assert response.status_code == 200
    assert response.json()["name"] is None


def test_no_enrichment_call_when_disabled(
    app_factory: Callable[..., FastAPI], kit: AccessTestKit
) -> None:
    with respx.mock:
        route = respx.get(IDENTITY_URL).mock(
            return_value=httpx.Response(200, json=IDENTITY_PAYLOAD)
        )
        with TestClient(app_factory()) as client:
            response = client.get("/profile", headers=kit.headers(kit.mint()))

    assert response.status_code == 200
    assert route.call_count == 0


async def test_groups_and_idp_are_parsed(kit: AccessTestKit) -> None:
    client = IdentityClient(kit.settings(fetch_identity=True))

    with respx.mock:
        respx.get(IDENTITY_URL).mock(return_value=httpx.Response(200, json=IDENTITY_PAYLOAD))
        details = await client.fetch("token", "nonce-1")

    assert details is not None
    assert details.name == "Ada Lovelace"
    assert [group.name for group in details.groups] == ["Engineering", "On-call"]
    assert details.idp_type == "okta"
    assert details.geo_country == "GB"
    assert details.is_warp is True
    await client.aclose()


async def test_enrichment_sends_the_session_cookie(kit: AccessTestKit) -> None:
    """The identity endpoint authenticates with the caller's own CF_Authorization cookie."""
    client = IdentityClient(kit.settings(fetch_identity=True))

    with respx.mock:
        route = respx.get(IDENTITY_URL).mock(
            return_value=httpx.Response(200, json=IDENTITY_PAYLOAD)
        )
        await client.fetch("the-token", None)

    assert route.calls[0].request.headers["cookie"] == "CF_Authorization=the-token"
    await client.aclose()
