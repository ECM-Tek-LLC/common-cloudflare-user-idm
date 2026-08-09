"""A complete FastAPI application using Cloudflare Access identification.

Run it locally with the development bypass::

    cp examples/basic_app/.env.example examples/basic_app/.env
    uv run uvicorn examples.basic_app.main:app --reload --env-file examples/basic_app/.env

Then::

    curl localhost:8000/auth/me
    curl localhost:8000/profile
    curl localhost:8000/reports          # 404 until the demo user creates one

Everything below is ordinary application code; the only auth-specific lines are the
``install_cf_access(app, ...)`` call and the ``CurrentUser`` / ``CurrentPrincipal`` /
``OptionalUser`` annotations on the route signatures.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI
from starlette.requests import Request

from cf_user_idm import (
    CfAccessSettings,
    CurrentPrincipal,
    CurrentUser,
    JwksCache,
    OptionalUser,
    Principal,
    install_cf_access,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("basic_app")


# --------------------------------------------------------------------------------------
# A stand-in for the application's own user store.
#
# The framework has no database. It tells you who the caller is; keeping your own record
# of them -- and any roles or permissions you attach to them -- is your application's job.
# --------------------------------------------------------------------------------------

USERS: dict[str, dict[str, Any]] = {}


async def upsert_user(principal: Principal, request: Request) -> None:
    """Record the caller in our own store the first time we see them on a request.

    Note the key: ``principal.id``. For a human that is the Cloudflare ``sub`` -- a stable
    UUID. Keying on email instead would create a second, empty account for anyone whose
    address ever changes.
    """
    record = USERS.setdefault(
        principal.id,
        {"id": principal.id, "kind": "service" if principal.is_service else "user", "visits": 0},
    )
    record["visits"] += 1
    if not principal.is_service:
        record["email"] = principal.email  # mutable attribute, refreshed on every visit


# --------------------------------------------------------------------------------------
# Application
# --------------------------------------------------------------------------------------


def create_app(
    settings: CfAccessSettings | None = None,
    *,
    jwks: JwksCache | None = None,
) -> FastAPI:
    """Build the application.

    A factory rather than a bare module-level app so tests (and
    ``examples/basic_app/local_verify.py``) can supply their own settings and signing keys.
    In a real service you would call this with no arguments and let it read the
    environment.
    """
    app = FastAPI(
        title="Cloudflare Access example app",
        description="Demonstrates cf_user_idm end to end.",
    )

    install_cf_access(app, settings, jwks=jwks, on_authenticated=upsert_user)

    @app.get("/health", tags=["public"])
    async def health() -> dict[str, str]:
        """Unauthenticated on purpose, so orchestrators can probe it.

        Nothing is enforced globally: a route is protected precisely when it asks for an
        identity in its signature.
        """
        return {"status": "ok"}

    @app.get("/profile", tags=["user"])
    async def profile(user: CurrentUser) -> dict[str, Any]:
        """A human-only route. A service token gets a 403 here."""
        return {
            "id": user.id,
            "email": user.email,
            "name": user.details.name if user.details else None,
            "session_expires_at": user.expires_at,
            "visits": USERS.get(user.id, {}).get("visits", 0),
        }

    @app.get("/ingest", tags=["machine"])
    async def ingest(caller: CurrentPrincipal) -> dict[str, Any]:
        """Open to humans *and* machines -- what a CI job would call with a service token."""
        return {"caller": caller.id, "kind": "service" if caller.is_service else "user"}

    @app.get("/landing", tags=["public"])
    async def landing(user: OptionalUser) -> dict[str, Any]:
        """Renders differently for signed-in users but never rejects an anonymous visitor.

        A forged token is still a 401 -- "optional" means optional, not unchecked.
        """
        if user is None:
            return {"greeting": "Hello, stranger."}
        return {"greeting": f"Welcome back, {user.email}."}

    @app.get("/admin/users", tags=["user"])
    async def list_users(user: CurrentUser) -> dict[str, Any]:
        """Authorization is the application's own business.

        Cloudflare Access already decided this person may reach the app at all. Whether
        they are an *admin* is a question about this application's data, so it is answered
        here -- the framework has no opinion about it.
        """
        is_admin = USERS.get(user.id, {}).get("role") == "admin"
        return {"caller": user.email, "is_admin": is_admin, "users": list(USERS.values())}

    return app


app = create_app()
