"""End-to-end request behaviour through the FastAPI dependencies."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient
from starlette.requests import Request

from cf_user_idm import CurrentUser, install_cf_access
from cf_user_idm.models import Principal
from cf_user_idm.testing import AccessTestKit


def test_valid_token_in_the_header_identifies_the_user(
    client: TestClient, kit: AccessTestKit
) -> None:
    token = kit.mint(sub="user-abc", email="grace@example.com")

    response = client.get("/profile", headers=kit.headers(token))

    assert response.status_code == 200
    assert response.json()["id"] == "user-abc"
    assert response.json()["email"] == "grace@example.com"


def test_token_in_the_cookie_also_works(client: TestClient, kit: AccessTestKit) -> None:
    """Browser traffic that lost the header still identifies via CF_Authorization."""
    client.cookies.update(kit.cookies(kit.mint(email="grace@example.com")))

    response = client.get("/profile")

    assert response.status_code == 200
    assert response.json()["email"] == "grace@example.com"


def test_header_wins_over_cookie(client: TestClient, kit: AccessTestKit) -> None:
    """Cloudflare recommends trusting the header; the cookie may be stale or stripped."""
    client.cookies.update(kit.cookies(kit.mint(email="from-cookie@example.com")))

    response = client.get(
        "/profile", headers=kit.headers(kit.mint(email="from-header@example.com"))
    )

    assert response.json()["email"] == "from-header@example.com"


def test_missing_token_is_a_structured_401(client: TestClient) -> None:
    response = client.get("/profile")

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "missing_token",
            "message": "No Cloudflare Access token was present on the request.",
        }
    }
    assert response.headers["WWW-Authenticate"].startswith("Bearer")


def test_expired_token_is_a_structured_401(client: TestClient, kit: AccessTestKit) -> None:
    response = client.get("/profile", headers=kit.headers(kit.mint(expires_in=-3600)))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "token_expired"


def test_wrong_audience_is_a_structured_403(client: TestClient, kit: AccessTestKit) -> None:
    response = client.get("/profile", headers=kit.headers(kit.mint(audience="another-app")))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "audience_mismatch"


def test_unprotected_routes_need_no_token(client: TestClient) -> None:
    """Nothing is enforced globally, so health checks and docs stay reachable."""
    assert client.get("/public").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_service_token_is_refused_on_a_human_route(client: TestClient, kit: AccessTestKit) -> None:
    response = client.get("/profile", headers=kit.headers(kit.mint_service_token()))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "service_token_not_permitted"


def test_service_token_is_accepted_where_a_principal_is_asked_for(
    client: TestClient, kit: AccessTestKit
) -> None:
    token = kit.mint_service_token(common_name="ci-runner.access")

    response = client.get("/any-caller", headers=kit.headers(token))

    assert response.status_code == 200
    assert response.json() == {"id": "ci-runner.access", "is_service": True}


def test_service_tokens_can_be_disabled_entirely(
    app_factory: Callable[..., FastAPI], kit: AccessTestKit
) -> None:
    with TestClient(app_factory(allow_service_tokens=False)) as client:
        response = client.get("/any-caller", headers=kit.headers(kit.mint_service_token()))

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "service_token_not_permitted"


def test_optional_user_is_none_when_anonymous(client: TestClient) -> None:
    response = client.get("/maybe")

    assert response.status_code == 200
    assert response.json() == {"authenticated": False, "email": None}


def test_optional_user_is_none_for_a_service_token(client: TestClient, kit: AccessTestKit) -> None:
    response = client.get("/maybe", headers=kit.headers(kit.mint_service_token()))

    assert response.json() == {"authenticated": False, "email": None}


def test_optional_user_still_rejects_a_forged_token(client: TestClient, kit: AccessTestKit) -> None:
    """Downgrading a bad token to 'anonymous' would hide an attack in progress."""
    response = client.get("/maybe", headers=kit.headers(kit.mint(sign_with_foreign_key=True)))

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "invalid_token"


def test_dev_mode_identifies_everyone_as_the_synthetic_user(kit: AccessTestKit) -> None:
    app = FastAPI()
    install_cf_access(
        app,
        kit.settings(dev_mode=True, dev_user_email="dev@localhost", app_env="local"),
    )

    @app.get("/profile")
    async def profile(user: CurrentUser) -> dict[str, Any]:
        return {"id": user.id, "email": user.email}

    with TestClient(app) as client:
        response = client.get("/profile")

    assert response.status_code == 200
    assert response.json()["email"] == "dev@localhost"


def test_on_authenticated_hook_fires_once_per_request(kit: AccessTestKit) -> None:
    seen: list[Principal] = []

    async def record(principal: Principal, request: Request) -> None:
        seen.append(principal)

    app = FastAPI()
    install_cf_access(app, kit.settings(), jwks=kit.jwks_cache(), on_authenticated=record)

    @app.get("/twice")
    async def twice(first: CurrentUser, second: CurrentUser) -> dict[str, str]:
        return {"id": first.id, "same": str(first is second)}

    with TestClient(app) as client:
        response = client.get("/twice", headers=kit.headers(kit.mint(sub="user-xyz")))

    assert response.status_code == 200
    assert [principal.id for principal in seen] == ["user-xyz"]


def test_principal_is_reachable_from_request_state(kit: AccessTestKit) -> None:
    """So logging middleware and error handlers can name the caller."""
    app = FastAPI()
    install_cf_access(app, kit.settings(), jwks=kit.jwks_cache())

    @app.get("/state")
    async def read_state(request: Request, user: CurrentUser) -> dict[str, str]:
        return {"from_state": request.state.cf_principal.email, "from_dependency": user.email}

    with TestClient(app) as client:
        response = client.get("/state", headers=kit.headers(kit.mint(email="ada@example.com")))

    assert response.json() == {
        "from_state": "ada@example.com",
        "from_dependency": "ada@example.com",
    }


def test_dependencies_without_install_raise_a_clear_error(kit: AccessTestKit) -> None:
    app = FastAPI()

    @app.get("/profile")
    async def profile(user: CurrentUser) -> dict[str, str]:
        return {"email": user.email}

    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.get("/profile", headers=kit.headers(kit.mint()))

    assert response.status_code == 500
