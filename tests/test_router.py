"""The built-in /auth router."""

from __future__ import annotations

from collections.abc import Callable

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cf_user_idm.testing import AccessTestKit


def test_me_returns_the_current_user(client: TestClient, kit: AccessTestKit) -> None:
    token = kit.mint(sub="user-1", email="ada@example.com")

    response = client.get("/auth/me", headers=kit.headers(token))

    assert response.status_code == 200
    body = response.json()
    assert body["id"] == "user-1"
    assert body["email"] == "ada@example.com"
    assert body["is_service"] is False


def test_me_never_leaks_the_raw_claims(client: TestClient, kit: AccessTestKit) -> None:
    response = client.get("/auth/me", headers=kit.headers(kit.mint()))

    assert "claims" not in response.json()


def test_me_describes_a_service_caller(client: TestClient, kit: AccessTestKit) -> None:
    response = client.get("/auth/me", headers=kit.headers(kit.mint_service_token()))

    assert response.json()["is_service"] is True
    assert response.json()["common_name"] == "svc-client.access"


def test_me_requires_a_token(client: TestClient) -> None:
    assert client.get("/auth/me").status_code == 401


def test_logout_redirects_to_cloudflare_and_clears_the_cookie(client: TestClient) -> None:
    response = client.get("/auth/logout", follow_redirects=False)

    assert response.status_code == 302
    assert (
        response.headers["location"]
        == "https://testteam.cloudflareaccess.com/cdn-cgi/access/logout"
    )
    assert "CF_Authorization=" in response.headers["set-cookie"]


def test_debug_endpoint_is_absent_by_default(client: TestClient) -> None:
    assert client.get("/auth/debug").status_code == 404


def test_debug_endpoint_reports_shape_not_secrets(
    app_factory: Callable[..., FastAPI], kit: AccessTestKit
) -> None:
    token = kit.mint(sub="user-1", email="ada@example.com")

    with TestClient(app_factory(enable_debug_endpoint=True)) as client:
        response = client.get("/auth/debug", headers=kit.headers(token))

    body = response.json()
    assert response.status_code == 200
    assert body["team_domain"] == "testteam"
    assert body["token"]["present"] is True
    assert body["token"]["kid"] == kit.kid
    assert body["token"]["kind"] == "user"
    assert "email" in body["token"]["claims_present"]

    # Shape only -- no claim values, and certainly not the token itself.
    serialized = response.text
    assert token not in serialized
    assert "ada@example.com" not in serialized


def test_debug_endpoint_works_without_a_token(
    app_factory: Callable[..., FastAPI],
) -> None:
    with TestClient(app_factory(enable_debug_endpoint=True)) as client:
        response = client.get("/auth/debug")

    assert response.status_code == 200
    assert response.json()["token"] == {"present": False, "source": None}


def test_router_prefix_is_configurable(
    app_factory: Callable[..., FastAPI], kit: AccessTestKit
) -> None:
    with TestClient(app_factory(router_prefix="/identity")) as client:
        assert client.get("/identity/me", headers=kit.headers(kit.mint())).status_code == 200
        assert client.get("/auth/me").status_code == 404
