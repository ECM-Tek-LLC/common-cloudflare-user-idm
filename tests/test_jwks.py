"""Signing-key cache behaviour: rotation, rate limiting, concurrency and outages."""

from __future__ import annotations

import asyncio

import httpx
import pytest
import respx

from cf_user_idm import SigningKeyUnavailableError
from cf_user_idm.jwks import JwksCache
from cf_user_idm.testing import AccessTestKit

CERTS_URL = "https://testteam.cloudflareaccess.com/cdn-cgi/access/certs"


@pytest.fixture
def other_kit() -> AccessTestKit:
    """A second key pair, standing in for Cloudflare's post-rotation keys."""
    return AccessTestKit(kid="rotated-key-2")


async def test_keys_are_fetched_once_and_reused(kit: AccessTestKit) -> None:
    with respx.mock:
        route = respx.get(CERTS_URL).mock(return_value=httpx.Response(200, json=kit.jwks))
        cache = JwksCache(CERTS_URL)

        for _ in range(5):
            await cache.get_key(kit.kid)

        assert route.call_count == 1
        await cache.aclose()


async def test_expired_ttl_triggers_a_refetch(kit: AccessTestKit) -> None:
    with respx.mock:
        route = respx.get(CERTS_URL).mock(return_value=httpx.Response(200, json=kit.jwks))
        cache = JwksCache(CERTS_URL, ttl=0)

        await cache.get_key(kit.kid)
        await cache.get_key(kit.kid)

        assert route.call_count == 2
        await cache.aclose()


async def test_unknown_key_id_picks_up_a_rotation(
    kit: AccessTestKit, other_kit: AccessTestKit
) -> None:
    """A token signed with a brand-new key must work immediately, not after the TTL."""
    with respx.mock:
        route = respx.get(CERTS_URL).mock(
            side_effect=[
                httpx.Response(200, json=kit.jwks),
                httpx.Response(200, json=other_kit.jwks),
            ]
        )
        cache = JwksCache(CERTS_URL, ttl=3600, min_refresh_interval=0)

        await cache.get_key(kit.kid)
        rotated = await cache.get_key(other_kit.kid)

        assert rotated is not None
        assert route.call_count == 2
        await cache.aclose()


async def test_unknown_key_ids_cannot_stampede_cloudflare(kit: AccessTestKit) -> None:
    """The rate floor is what stops junk tokens becoming a request flood upstream."""
    with respx.mock:
        route = respx.get(CERTS_URL).mock(return_value=httpx.Response(200, json=kit.jwks))
        cache = JwksCache(CERTS_URL, ttl=3600, min_refresh_interval=3600)

        await cache.get_key(kit.kid)  # one legitimate fetch
        for _ in range(20):
            with pytest.raises(SigningKeyUnavailableError):
                await cache.get_key("attacker-supplied-kid")

        assert route.call_count == 1
        await cache.aclose()


async def test_concurrent_first_requests_share_one_fetch(kit: AccessTestKit) -> None:
    with respx.mock:
        route = respx.get(CERTS_URL).mock(return_value=httpx.Response(200, json=kit.jwks))
        cache = JwksCache(CERTS_URL)

        await asyncio.gather(*(cache.get_key(kit.kid) for _ in range(10)))

        assert route.call_count == 1
        await cache.aclose()


async def test_outage_falls_back_to_cached_keys(kit: AccessTestKit) -> None:
    """Cloudflare being briefly unreachable must not lock every user out."""
    with respx.mock:
        route = respx.get(CERTS_URL).mock(
            side_effect=[
                httpx.Response(200, json=kit.jwks),
                httpx.Response(503),
            ]
        )
        cache = JwksCache(CERTS_URL, ttl=0)

        await cache.get_key(kit.kid)
        key = await cache.get_key(kit.kid)  # refresh attempt fails, stale keys still serve

        assert key is not None
        assert route.call_count == 2
        await cache.aclose()


async def test_outage_with_no_cached_keys_fails_closed(kit: AccessTestKit) -> None:
    with respx.mock:
        respx.get(CERTS_URL).mock(return_value=httpx.Response(503))
        cache = JwksCache(CERTS_URL)

        with pytest.raises(SigningKeyUnavailableError):
            await cache.get_key(kit.kid)

        await cache.aclose()


async def test_token_without_a_key_id_is_rejected() -> None:
    cache = JwksCache(CERTS_URL)

    with pytest.raises(SigningKeyUnavailableError, match="no 'kid'"):
        await cache.get_key(None)

    await cache.aclose()


async def test_static_cache_never_touches_the_network(kit: AccessTestKit) -> None:
    with respx.mock:
        route = respx.get(CERTS_URL).mock(return_value=httpx.Response(500))
        cache = JwksCache.from_static(kit.jwks, certs_url=CERTS_URL)

        assert await cache.get_key(kit.kid) is not None
        assert route.call_count == 0
        assert cache.key_ids == [kit.kid]
