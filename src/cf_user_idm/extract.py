"""Pulling the Access token off an inbound request.

Cloudflare presents the same token two ways. The header is authoritative; the cookie is a
fallback that also happens to be what the identity endpoint needs.
"""

from __future__ import annotations

from starlette.requests import Request

__all__ = ["ACCESS_COOKIE", "ACCESS_EMAIL_HEADER", "ACCESS_JWT_HEADER", "extract_token"]

ACCESS_JWT_HEADER = "Cf-Access-Jwt-Assertion"
"""Header Cloudflare adds to every request it forwards to the origin."""

ACCESS_COOKIE = "CF_Authorization"
"""Cookie set on the application's domain for browser sessions."""

ACCESS_EMAIL_HEADER = "Cf-Access-Authenticated-User-Email"
"""Convenience header Cloudflare also sets.

Deliberately unused for identification. It is a plain unsigned string, so anything that can
reach the origin directly can set it to any address it likes. Identity comes from the
signed token or not at all.
"""


def extract_token(request: Request) -> str | None:
    """Return the Access JWT for this request, or ``None`` if there isn't one.

    Prefers the header: Cloudflare always sets it, whereas the cookie is only present for
    browser traffic and can be stripped by intermediate proxies.
    """
    token = request.headers.get(ACCESS_JWT_HEADER)
    if token:
        return token.strip()

    cookie = request.cookies.get(ACCESS_COOKIE)
    if cookie:
        return cookie.strip()

    return None
