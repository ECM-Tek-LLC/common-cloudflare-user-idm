"""Shared fixtures.

The key pair is generated once for the whole session -- RSA keygen is slow enough that
doing it per test is noticeable.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from cf_user_idm import CurrentPrincipal, CurrentUser, OptionalUser, install_cf_access
from cf_user_idm.testing import AccessTestKit


@pytest.fixture(scope="session")
def kit() -> AccessTestKit:
    return AccessTestKit()


def build_app(kit: AccessTestKit, **setting_overrides: Any) -> FastAPI:
    """An app with one route per dependency, wired to the kit's key pair."""
    app = FastAPI()
    install_cf_access(
        app,
        kit.settings(**setting_overrides),
        jwks=kit.jwks_cache(),
    )

    @app.get("/profile")
    async def profile(user: CurrentUser) -> dict[str, Any]:
        return {
            "id": user.id,
            "email": user.email,
            "name": user.details.name if user.details else None,
        }

    @app.get("/any-caller")
    async def any_caller(caller: CurrentPrincipal) -> dict[str, Any]:
        return {"id": caller.id, "is_service": caller.is_service}

    @app.get("/maybe")
    async def maybe(user: OptionalUser) -> dict[str, Any]:
        return {"authenticated": user is not None, "email": user.email if user else None}

    @app.get("/public")
    async def public() -> dict[str, str]:
        return {"status": "ok"}

    return app


@pytest.fixture
def app_factory(kit: AccessTestKit) -> Callable[..., FastAPI]:
    def factory(**setting_overrides: Any) -> FastAPI:
        return build_app(kit, **setting_overrides)

    return factory


@pytest.fixture
def app(app_factory: Callable[..., FastAPI]) -> FastAPI:
    return app_factory()


@pytest.fixture
def client(app: FastAPI) -> Iterator[TestClient]:
    with TestClient(app) as test_client:
        yield test_client
