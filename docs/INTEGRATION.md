# Integration guide

**Audience: an engineer or AI coding session wiring `cf_user_idm` into an existing FastAPI
application.** Follow it top to bottom. Every code block is copy-paste ready.

---

## 0. What this does, and what it does not

**Does:** verifies the JWT that Cloudflare Access attaches to every request reaching your
origin, and gives your route handlers a typed identity — a stable user id, an email, or a
service-token name.

**Does not:** decide what that caller is allowed to do. Cloudflare Access policy already
decided they may reach this application at all. Roles, permissions, tenancy and
entitlements live in *your* application, keyed on the user id this framework gives you.

If you were about to add `require_role("admin")` to this library — don't. Build it in the
app, on top of `user.id`.

---

## 1. Prerequisites

Before the code matters, confirm the deployment shape. **The origin must not be reachable
without passing through Cloudflare.** If someone can hit your container directly, they skip
Access entirely and no amount of JWT verification helps. Use a Cloudflare Tunnel, or a
proxied hostname with the origin firewalled to Cloudflare IPs. See
[`CLOUDFLARE_SETUP.md`](CLOUDFLARE_SETUP.md).

You need two values from the Cloudflare Zero Trust dashboard:

| Value | Where | Looks like |
| --- | --- | --- |
| Team domain | Settings → Custom Pages (the `acme` in `acme.cloudflareaccess.com`) | `acme` |
| Application Audience (AUD) tag | Access → Applications → *your app* → Overview | 64 hex characters |

---

## 2. Install

Add the dependency, pinned to a tag:

```
common-cloudflare-user-idm @ git+https://github.com/ECM-Tek-LLC/common-cloudflare-user-idm@v0.1.0
```

```bash
uv add "common-cloudflare-user-idm @ git+https://github.com/ECM-Tek-LLC/common-cloudflare-user-idm@v0.1.0"
# or
pip install "common-cloudflare-user-idm[testing] @ git+https://github.com/ECM-Tek-LLC/common-cloudflare-user-idm@v0.1.0"
```

Add the `[testing]` extra to dev dependencies — you need it for step 6.

---

## 3. Configure

All configuration is environment variables prefixed `CF_ACCESS_`.

**Deployed:**

```bash
APP_ENV=production
CF_ACCESS_TEAM_DOMAIN=acme
CF_ACCESS_AUDIENCE=0a1b2c3d...   # comma-separate if behind several Access applications
```

**Local development** (no tunnel, no tokens):

```bash
APP_ENV=development
CF_ACCESS_DEV_MODE=true
CF_ACCESS_DEV_USER_EMAIL=dev@localhost
```

Full reference:

| Variable | Default | Meaning |
| --- | --- | --- |
| `CF_ACCESS_TEAM_DOMAIN` | — | Team name. Accepts `acme`, `acme.cloudflareaccess.com` or a URL. Required unless dev mode. |
| `CF_ACCESS_AUDIENCE` | — | AUD tag(s), comma-separated. Required unless dev mode. |
| `APP_ENV` | `development` | Deployment environment. Blocks dev mode when `prod`/`production`/`stage`/`staging`. |
| `CF_ACCESS_DEV_MODE` | `false` | Bypass verification, inject a synthetic user. |
| `CF_ACCESS_DEV_USER_EMAIL` | — | Required when dev mode is on. |
| `CF_ACCESS_DEV_USER_SUB` | all-zero UUID | `id` of the synthetic user. |
| `CF_ACCESS_DEV_USER_NAME` | `Local Developer` | Display name of the synthetic user. |
| `CF_ACCESS_JWKS_CACHE_TTL` | `3600` | Seconds to cache signing keys. |
| `CF_ACCESS_JWKS_MIN_REFRESH_INTERVAL` | `300` | Rate floor on rotation-triggered refetches. |
| `CF_ACCESS_JWKS_TIMEOUT` | `5.0` | HTTP timeout for Cloudflare calls. |
| `CF_ACCESS_LEEWAY` | `60` | Clock-skew tolerance, seconds. |
| `CF_ACCESS_FETCH_IDENTITY` | `false` | Fetch display name / groups / IdP from get-identity. |
| `CF_ACCESS_IDENTITY_CACHE_TTL` | `300` | Seconds to cache an enrichment result. |
| `CF_ACCESS_ALLOW_SERVICE_TOKENS` | `true` | Whether machine callers may be identified at all. |
| `CF_ACCESS_ROUTER_PREFIX` | `/auth` | Mount point for the built-in router. |
| `CF_ACCESS_ENABLE_DEBUG_ENDPOINT` | `false` | Expose `{prefix}/debug`. |

---

## 4. Wire it into the app

One call, next to where the `FastAPI` object is created:

```python
from fastapi import FastAPI
from cf_user_idm import install_cf_access

app = FastAPI()
install_cf_access(app)
```

That reads the environment, registers the JSON error format for auth failures, mounts
`/auth/me` and `/auth/logout`, and closes its HTTP clients on shutdown. It is safe to call
alongside an existing `lifespan=` — the framework wraps it rather than replacing it.

If the app already has its own settings object, pass one explicitly instead:

```python
from cf_user_idm import CfAccessSettings, install_cf_access

install_cf_access(app, CfAccessSettings(team_domain="acme", audience=["0a1b..."]))
```

To skip the built-in router: `install_cf_access(app, include_router=False)`.

---

## 5. Protect routes

There is **no global middleware**. A route is protected exactly when its signature asks for
an identity, which keeps health checks and docs reachable with no allowlist to maintain.

```python
from cf_user_idm import CurrentUser, CurrentPrincipal, OptionalUser

@app.get("/profile")
async def profile(user: CurrentUser):
    # A human. Service tokens get 403 here.
    return {"id": user.id, "email": user.email}

@app.get("/ingest")
async def ingest(caller: CurrentPrincipal):
    # A human or a machine. `caller.is_service` distinguishes them.
    return {"caller": caller.id}

@app.get("/landing")
async def landing(user: OptionalUser):
    # None when anonymous. A *forged* token is still a 401.
    return {"greeting": f"Hello, {user.email}" if user else "Hello, stranger"}
```

To protect a whole router:

```python
from fastapi import APIRouter, Depends
from cf_user_idm import get_current_user

router = APIRouter(prefix="/admin", dependencies=[Depends(get_current_user)])
```

The caller is also on `request.state.cf_principal` for logging middleware and error
handlers.

---

## 6. Store users in your own database

**Key your users table on `user.id` — the Cloudflare `sub`, a stable UUID. Never on email.**
Emails change (marriage, domain rename, IdP re-provisioning) and every one of those events
would silently create a duplicate account if email were the key. Store email as an ordinary
mutable column and refresh it on each visit.

```python
from cf_user_idm import Principal, install_cf_access
from starlette.requests import Request

async def sync_user(principal: Principal, request: Request) -> None:
    if principal.is_service:
        return
    await db.execute(
        """
        INSERT INTO users (cf_sub, email, last_seen_at)
        VALUES (:sub, :email, now())
        ON CONFLICT (cf_sub) DO UPDATE
          SET email = EXCLUDED.email, last_seen_at = now()
        """,
        {"sub": principal.id, "email": principal.email},
    )

install_cf_access(app, on_authenticated=sync_user)
```

The hook fires once per request, on first identification. It may be sync or async.
Exceptions from it propagate and fail the request, so keep it cheap and defensive.

Your roles live in your table (`users.role`, a join table, whatever you already do) and are
checked in your own dependency:

```python
async def require_admin(user: CurrentUser) -> CurrentUser:
    if not await db.is_admin(user.id):
        raise HTTPException(403, "Admin access required")
    return user
```

---

## 7. Test the protected routes

Two approaches; use both.

**Most tests** just need somebody logged in:

```python
from cf_user_idm.testing import make_user, override_principal

def test_profile(client, app):
    with override_principal(app, make_user(email="admin@example.com")):
        assert client.get("/profile").json()["email"] == "admin@example.com"
```

**Auth-specific tests** should exercise the real verification path. `AccessTestKit` is a
complete stand-in for a Cloudflare tenant — its own RSA key pair, its own JWKS, no network:

```python
import pytest
from fastapi.testclient import TestClient
from cf_user_idm import install_cf_access
from cf_user_idm.testing import AccessTestKit

@pytest.fixture(scope="session")
def kit():
    return AccessTestKit()      # session-scoped: RSA keygen is slow

@pytest.fixture
def client(kit):
    app = create_app()          # your app factory
    install_cf_access(app, kit.settings(), jwks=kit.jwks_cache())
    return TestClient(app)

def test_valid_token(client, kit):
    token = kit.mint(sub="user-1", email="ada@example.com")
    assert client.get("/profile", headers=kit.headers(token)).status_code == 200

def test_expired_token(client, kit):
    assert client.get("/profile", headers=kit.headers(kit.mint(expires_in=-3600))).status_code == 401

def test_forged_token(client, kit):
    token = kit.mint(sign_with_foreign_key=True)
    assert client.get("/profile", headers=kit.headers(token)).status_code == 401
```

`kit.mint()` knobs, one per failure mode: `expires_in=-3600` (expired),
`audience="other"` (wrong app), `issuer="https://other.cloudflareaccess.com"` (wrong team),
`kid="unknown"` (unpublished key), `sign_with_foreign_key=True` (forged).
`kit.mint_service_token()` produces a machine caller. `kit.mint_raw(claims)` signs exactly
what you pass, for malformed-token tests.

---

## 8. Verify the integration

```bash
# 1. Local, dev bypass
CF_ACCESS_DEV_MODE=true CF_ACCESS_DEV_USER_EMAIL=dev@localhost APP_ENV=development \
  uvicorn yourapp.main:app
curl localhost:8000/auth/me          # -> the synthetic user; startup logged a big banner

# 2. The prod guard actually guards
APP_ENV=production CF_ACCESS_DEV_MODE=true CF_ACCESS_DEV_USER_EMAIL=x@y.z \
  uvicorn yourapp.main:app           # -> ConfigurationError, refuses to start

# 3. Deployed, through Cloudflare
curl https://yourapp.example.com/auth/me      # -> your real identity after the Access login
```

Set `CF_ACCESS_ENABLE_DEBUG_ENDPOINT=true` and hit `/auth/debug` while wiring things up. It
reports configuration and the *shape* of the incoming token — which claims are present, the
key id — but never claim values and never the token itself.

---

## 9. Error responses

Every failure is a JSON body of the same shape, so clients can branch on `code`:

```json
{"error": {"code": "audience_mismatch", "message": "The token was not issued for this application."}}
```

| Code | Status | Meaning |
| --- | --- | --- |
| `missing_token` | 401 | No token on the request. |
| `invalid_token` | 401 | Malformed, or the signature does not verify. |
| `token_expired` | 401 | Past `exp`, beyond the leeway. |
| `signing_key_unavailable` | 401 | The token's `kid` is not in the team's JWKS. |
| `audience_mismatch` | 403 | Valid token, issued for a different application. |
| `issuer_mismatch` | 403 | Valid token, issued by a different team. |
| `service_token_not_permitted` | 403 | A machine caller hit a human-only route. |

There are no login redirects. Cloudflare authenticates at the edge before the request
reaches your origin, so by the time your code runs the user has already signed in — or the
request never arrived.

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
| --- | --- | --- |
| `missing_token` in production | The origin is reachable without going through Cloudflare — the serious one. | Put the origin behind a tunnel or firewall it to Cloudflare. |
| `missing_token` locally | No tunnel, so no token. | `CF_ACCESS_DEV_MODE=true`. |
| `audience_mismatch` | Wrong AUD tag, or the request came through a *different* Access application. | Re-copy the AUD from the app's Overview tab, or add the second tag to the comma-separated list. |
| `issuer_mismatch` | Wrong `CF_ACCESS_TEAM_DOMAIN`. | Check Settings → Custom Pages. |
| `signing_key_unavailable`, suddenly, for everyone | Cloudflare rotated keys and the origin cannot reach `cloudflareaccess.com`. | Check egress from the container. |
| `service_token_not_permitted` | A service token hit a `CurrentUser` route. | Use `CurrentPrincipal` there if machines are meant to call it. |
| App refuses to start, `ConfigurationError` | Dev mode in a prod-like `APP_ENV`, or missing team/audience. | Read the message; it names the variable. |
| `user.details` is always `None` | Enrichment off (the default), or the caller has no `CF_Authorization` cookie. | `CF_ACCESS_FETCH_IDENTITY=true`; note it only works for browser traffic. |
| A user appears twice in your database | You keyed on email. | Key on `user.id` (§6). |
| 401s right after deploying a new Access app | AUD tag changed with the new application. | Update `CF_ACCESS_AUDIENCE`. |

---

## Public API reference

```python
from cf_user_idm import (
    install_cf_access,                                    # setup
    CurrentUser, CurrentPrincipal, OptionalUser,          # dependency annotations
    get_current_user, get_current_principal, get_optional_user,   # the callables
    AccessUser, ServicePrincipal, Principal,              # identity types
    CfAccessSettings,                                     # config
    AccessAuthError,                                      # base of every auth failure
    ConfigurationError,
)
from cf_user_idm.testing import AccessTestKit, make_user, override_principal
```

`AccessUser`: `id`, `email`, `identity_nonce`, `country`, `issued_at`, `expires_at`,
`custom`, `details`, `is_service` (`False`), `claims`.
`ServicePrincipal`: `id`, `common_name`, `issued_at`, `expires_at`, `is_service` (`True`),
`claims`.
