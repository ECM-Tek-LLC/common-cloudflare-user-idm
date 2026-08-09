"""The local development bypass.

Cloudflare Access only injects a token when a request actually travels through Cloudflare,
which a developer running ``uvicorn`` on their laptop is not doing. Without a bypass, every
protected route is unreachable locally and people start commenting out authentication --
which is far more dangerous than a bypass that is designed, guarded and obvious.

Two things keep this safe:

1. :class:`~cf_user_idm.settings.CfAccessSettings` refuses to construct when ``dev_mode`` is
   set in a production-like environment, so a misconfigured deploy cannot start at all.
2. Every startup with the bypass active logs an unmissable banner.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from .models import AccessUser, IdentityDetails
from .settings import CfAccessSettings

__all__ = ["build_dev_user", "log_dev_mode_banner"]

logger = logging.getLogger(__name__)


def build_dev_user(settings: CfAccessSettings) -> AccessUser:
    """Construct the synthetic user returned for every request while in dev mode."""
    now = datetime.now(tz=UTC)
    return AccessUser(
        id=settings.dev_user_sub,
        email=settings.dev_user_email or "dev@localhost",
        identity_nonce="dev-mode",
        country=None,
        issued_at=now,
        expires_at=now + timedelta(hours=24),
        custom={},
        details=IdentityDetails(name=settings.dev_user_name),
        claims={"dev_mode": True},
    )


def log_dev_mode_banner(settings: CfAccessSettings) -> None:
    """Warn, loudly and on every boot, that requests are not being authenticated."""
    logger.warning(
        "\n"
        "  ****************************************************************\n"
        "  *  CLOUDFLARE ACCESS DEVELOPMENT BYPASS IS ACTIVE              *\n"
        "  *  Requests are NOT authenticated. Every caller is treated as  *\n"
        "  *  %-60s*\n"
        "  *  APP_ENV=%-52s*\n"
        "  ****************************************************************",
        settings.dev_user_email,
        settings.app_env,
    )
