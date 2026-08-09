"""Drive the example app through the *real* verification path, with no Cloudflare.

``AccessTestKit`` generates a throwaway RSA key pair and publishes a matching JWKS, so the
framework verifies signatures, audience, issuer and expiry exactly as it would in
production -- against a tenant that exists only in this process.

Run from the repository root::

    uv run python examples/basic_app/local_verify.py
"""

from __future__ import annotations

import logging
import os
import sys
import warnings
from pathlib import Path

# Run as a plain script, the repository root is not on sys.path -- only this directory is.
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

warnings.filterwarnings("ignore", module="starlette.testclient")

from fastapi.testclient import TestClient  # noqa: E402

from cf_user_idm.testing import AccessTestKit  # noqa: E402


def main() -> None:
    kit = AccessTestKit()

    # The example app reads its configuration from the environment at import time, the
    # same way it would in a container. Point it at our in-process "tenant".
    os.environ["APP_ENV"] = "local"
    os.environ["CF_ACCESS_TEAM_DOMAIN"] = kit.team_domain
    os.environ["CF_ACCESS_AUDIENCE"] = ",".join(kit.audience)
    os.environ["CF_ACCESS_ENABLE_DEBUG_ENDPOINT"] = "true"
    os.environ.pop("CF_ACCESS_DEV_MODE", None)

    from examples.basic_app.main import create_app

    logging.getLogger("httpx").setLevel(logging.WARNING)

    app = create_app(jwks=kit.jwks_cache())
    client = TestClient(app)

    cases: list[tuple[str, dict[str, str]]] = [
        ("no token at all", {}),
        ("valid user token", kit.headers(kit.mint(email="ada@example.com"))),
        ("expired token", kit.headers(kit.mint(expires_in=-3600))),
        ("token for another app", kit.headers(kit.mint(audience="some-other-app"))),
        ("token from another team", kit.headers(kit.mint(issuer="https://x.cloudflareaccess.com"))),
        ("forged signature", kit.headers(kit.mint(sign_with_foreign_key=True))),
        ("service token", kit.headers(kit.mint_service_token("ci-runner.access"))),
    ]

    print(f"\n{'case':<28} {'GET /profile':<14} {'GET /ingest':<14} detail")
    print("-" * 92)
    for label, headers in cases:
        profile = client.get("/profile", headers=headers)
        ingest = client.get("/ingest", headers=headers)
        detail = profile.json().get("error", {}).get("code") or profile.json().get("email", "")
        print(f"{label:<28} {profile.status_code:<14} {ingest.status_code:<14} {detail}")

    print(
        "\nNote the last row: a service token is refused on the human-only /profile but "
        "accepted on /ingest.\n"
    )


if __name__ == "__main__":
    main()
