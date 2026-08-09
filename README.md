# common-cloudflare-user-idm

Reusable Cloudflare Zero Trust (Access) user identification for FastAPI applications.

Every app behind Cloudflare Access has to turn the Access-issued JWT into a trustworthy
user identity. This does it once, correctly, so each new service does not re-derive
JWKS caching, audience validation and a development bypass — and re-derive their bugs.

```python
from fastapi import FastAPI
from cf_user_idm import CurrentUser, install_cf_access

app = FastAPI()
install_cf_access(app)

@app.get("/profile")
async def profile(user: CurrentUser):
    return {"id": user.id, "email": user.email}
```

```bash
CF_ACCESS_TEAM_DOMAIN=acme
CF_ACCESS_AUDIENCE=0a1b2c3d...      # the app's Application Audience (AUD) tag
```

That is the whole integration.

## Scope

**Identification, not authorization.** Cloudflare Access policy decides who may reach the
application. A valid token for our audience means the caller is allowed in. Roles,
permissions and tenancy belong in the application's own database, keyed on the user id this
library returns. There is deliberately no group or role machinery here.

## What you get

- **Verified identity.** RS256 signature, audience, issuer and expiry all checked against
  the team's published keys. No claim is trusted until the signature is.
- **Rotation handled.** Cloudflare rotates signing keys about every six weeks. Keys are
  cached for an hour, refetched the moment an unrecognized key id appears, rate-floored so
  junk tokens cannot stampede Cloudflare, and served stale rather than failing everyone if
  Cloudflare briefly blips.
- **Humans and machines as separate types.** Service tokens become a `ServicePrincipal`
  that human-only routes reject with 403, instead of a user with an empty email.
- **A development bypass that cannot reach production.** It requires an explicit flag and a
  fake email, logs a banner on every boot, and the app refuses to start if it is set while
  `APP_ENV` looks production-like.
- **Test helpers.** `AccessTestKit` is a complete stand-in for a Cloudflare tenant — its own
  key pair and JWKS — so your suite exercises the real verification path with no network.

## Install

```bash
uv add "common-cloudflare-user-idm @ git+https://github.com/ECM-Tek-LLC/common-cloudflare-user-idm@v0.1.0"
```

## Dependencies in a route

| Annotation | Yields | On a service token |
| --- | --- | --- |
| `CurrentUser` | `AccessUser` | 403 |
| `CurrentPrincipal` | `AccessUser` or `ServicePrincipal` | accepted |
| `OptionalUser` | `AccessUser` or `None` | `None` |

Nothing is enforced globally: a route is protected exactly when its signature asks for an
identity. Health checks stay reachable with no allowlist to maintain.

## The deployment requirement

**The origin must be unreachable except through Cloudflare** — a Cloudflare Tunnel, or a
proxied hostname with the origin firewalled to Cloudflare IPs. Verifying the token proves a
request came through Access; it says nothing about requests that did not. If the container
is directly reachable, an attacker skips Access entirely and none of this helps.

## Documentation

| | |
| --- | --- |
| [`docs/INTEGRATION.md`](docs/INTEGRATION.md) | Step-by-step integration into an existing FastAPI app, full env var reference, error codes, troubleshooting |
| [`docs/AI_AGENT_PROMPT.md`](docs/AI_AGENT_PROMPT.md) | Self-contained runbook to hand to an AI coding session |
| [`docs/CLOUDFLARE_SETUP.md`](docs/CLOUDFLARE_SETUP.md) | The dashboard side: applications, AUD tags, policies, service tokens, tunnels |
| [`examples/basic_app/`](examples/basic_app/) | A complete working application |

## Development

```bash
uv sync --all-extras
uv run ruff check . && uv run ruff format --check .
uv run pytest
uv run python examples/basic_app/local_verify.py   # real verification, no Cloudflare
```
