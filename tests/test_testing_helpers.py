"""The helpers consuming apps will use to test their own protected routes."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI
from fastapi.testclient import TestClient

from cf_user_idm import CurrentPrincipal, CurrentUser, OptionalUser, install_cf_access
from cf_user_idm.testing import (
    AccessTestKit,
    make_service_principal,
    make_user,
    override_principal,
)


def build_app(kit: AccessTestKit) -> FastAPI:
    app = FastAPI()
    install_cf_access(app, kit.settings(), jwks=kit.jwks_cache())

    @app.get("/profile")
    async def profile(user: CurrentUser) -> dict[str, str]:
        return {"email": user.email}

    @app.get("/any-caller")
    async def any_caller(caller: CurrentPrincipal) -> dict[str, Any]:
        return {"id": caller.id, "is_service": caller.is_service}

    @app.get("/maybe")
    async def maybe(user: OptionalUser) -> dict[str, Any]:
        return {"email": user.email if user else None}

    return app


def test_override_principal_logs_a_user_in(kit: AccessTestKit) -> None:
    app = build_app(kit)
    client = TestClient(app)

    with override_principal(app, make_user(email="admin@example.com")):
        assert client.get("/profile").json() == {"email": "admin@example.com"}
        assert client.get("/maybe").json() == {"email": "admin@example.com"}


def test_override_principal_keeps_the_human_only_rule(kit: AccessTestKit) -> None:
    """Overriding identity must not quietly weaken the service-token rejection."""
    app = build_app(kit)
    client = TestClient(app)

    with override_principal(app, make_service_principal("ci.access")):
        assert client.get("/any-caller").json() == {"id": "ci.access", "is_service": True}
        assert client.get("/profile").status_code == 403
        assert client.get("/maybe").json() == {"email": None}


def test_override_principal_restores_previous_state(kit: AccessTestKit) -> None:
    app = build_app(kit)
    client = TestClient(app)

    with override_principal(app, make_user()):
        pass

    assert app.dependency_overrides == {}
    assert client.get("/profile").status_code == 401


def test_kit_tokens_verify_against_the_kit_jwks(kit: AccessTestKit) -> None:
    app = build_app(kit)
    client = TestClient(app)

    response = client.get("/profile", headers=kit.headers(kit.mint(email="real@example.com")))

    assert response.json() == {"email": "real@example.com"}


def test_kit_mints_a_stable_sub_for_a_given_email(kit: AccessTestKit) -> None:
    assert kit.mint(email="a@b.c") != kit.mint(email="d@e.f")

    app = build_app(kit)
    client = TestClient(app)
    with override_principal(app, make_user(email="x@y.z")) as principal:
        assert principal.email == "x@y.z"
    assert client.get("/profile", headers=kit.headers(kit.mint(email="a@b.c"))).status_code == 200
