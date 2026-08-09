# AI agent runbook

A self-contained specification for an AI coding session asked to add Cloudflare Access
identification to a FastAPI application. Paste this whole file into the session, or point
it at this path. It assumes no other context.

---

## Task

Add Cloudflare Zero Trust (Access) user identification to a FastAPI application using the
`common-cloudflare-user-idm` package (import name `cf_user_idm`).

## Scope boundary — read this before writing code

This framework answers **"who is calling?"** It does not answer **"what may they do?"**

Cloudflare Access policy already decided the caller is allowed to reach the application.
Roles, permissions, tenancy and entitlements belong in the application's own database,
keyed on the identity this framework returns.

**Do not** add group checks, role decorators, or permission logic to the auth layer, and do
not ask this library for them — it deliberately has none. If the task mentions roles, build
them in the application on top of `user.id`.

## Non-negotiable rules

1. **Key the application's user records on `user.id`** (the Cloudflare `sub`, a stable
   UUID). Never on email. Store email as a mutable column, refreshed on each visit.
2. **Never** add a code path that trusts the `Cf-Access-Authenticated-User-Email` header,
   reads claims without verification, or catches an auth error and continues as anonymous.
3. **Never** enable `CF_ACCESS_DEV_MODE` in any deployed environment or commit it to a
   production config. It bypasses verification entirely.
4. Do not weaken `CurrentUser` to accept service tokens. Use `CurrentPrincipal` on routes
   that are genuinely meant for machines.
5. Do not paste the JWT into logs, error messages, or responses.

---

## Steps

### 1. Add the dependency

```bash
uv add "common-cloudflare-user-idm @ git+https://github.com/ECM-Tek-LLC/common-cloudflare-user-idm@v0.1.0"
```

Add the `[testing]` extra as a dev dependency.

### 2. Install it on the app

Find where the `FastAPI()` object is created. Add one call immediately after:

```python
from cf_user_idm import install_cf_access

app = FastAPI()
install_cf_access(app)
```

If the app uses a factory (`def create_app() -> FastAPI`), put it inside the factory. If it
already passes `lifespan=`, leave that alone — `install_cf_access` wraps the existing
lifespan rather than replacing it.

### 3. Protect routes

There is no global middleware. Annotate the routes that need an identity:

```python
from cf_user_idm import CurrentUser, CurrentPrincipal, OptionalUser

@app.get("/profile")
async def profile(user: CurrentUser):        # human only; service tokens get 403
    return {"id": user.id, "email": user.email}

@app.get("/ingest")
async def ingest(caller: CurrentPrincipal):  # human or machine
    return {"caller": caller.id, "machine": caller.is_service}

@app.get("/landing")
async def landing(user: OptionalUser):       # None when anonymous; forged token still 401
    return {"signed_in": user is not None}
```

Whole routers: `APIRouter(dependencies=[Depends(get_current_user)])`.

Leave health checks, readiness probes and `/openapi.json` unannotated — they must stay
reachable.

### 4. Wire identity into the app's user store

Only if the app has one. Use the `on_authenticated` hook:

```python
from cf_user_idm import Principal, install_cf_access
from starlette.requests import Request

async def sync_user(principal: Principal, request: Request) -> None:
    if principal.is_service:
        return
    await upsert_user(cf_sub=principal.id, email=principal.email)

install_cf_access(app, on_authenticated=sync_user)
```

If the app's existing users table keys on email, add a `cf_sub` column, backfill it, and
make it the identity key. Say so explicitly in the summary — it is a schema change.

### 5. Configure

Add to the deployment environment:

```bash
APP_ENV=production
CF_ACCESS_TEAM_DOMAIN=<team>       # the 'acme' in acme.cloudflareaccess.com
CF_ACCESS_AUDIENCE=<aud-tag>       # 64 hex chars, comma-separate for multiple Access apps
```

Add to `.env.example` / local development docs:

```bash
APP_ENV=development
CF_ACCESS_DEV_MODE=true
CF_ACCESS_DEV_USER_EMAIL=dev@localhost
```

If you do not know the real team domain and AUD tag, **do not invent them.** Leave
placeholders, and tell the user where to get them: Zero Trust dashboard → Settings → Custom
Pages for the team domain; Access → Applications → *app* → Overview for the AUD tag.

### 6. Tests

For ordinary route tests, override the identity:

```python
from cf_user_idm.testing import make_user, override_principal

with override_principal(app, make_user(email="admin@example.com")):
    ...
```

For auth-specific tests, exercise real verification with a local key pair:

```python
import pytest
from cf_user_idm import install_cf_access
from cf_user_idm.testing import AccessTestKit

@pytest.fixture(scope="session")   # session-scoped: RSA keygen is slow
def kit():
    return AccessTestKit()

@pytest.fixture
def client(kit):
    app = create_app()
    install_cf_access(app, kit.settings(), jwks=kit.jwks_cache())
    return TestClient(app)
```

Cover at minimum: valid token → 200; no token → 401; expired (`expires_in=-3600`) → 401;
forged (`sign_with_foreign_key=True`) → 401; wrong audience (`audience="other"`) → 403;
service token (`kit.mint_service_token()`) → 403 on a `CurrentUser` route.

### 7. Verify before reporting done

```bash
# tests pass
uv run pytest

# dev bypass works locally
CF_ACCESS_DEV_MODE=true CF_ACCESS_DEV_USER_EMAIL=dev@localhost APP_ENV=development \
  uvicorn yourapp.main:app
curl localhost:8000/auth/me          # -> the synthetic user

# the production guard actually guards
APP_ENV=production CF_ACCESS_DEV_MODE=true CF_ACCESS_DEV_USER_EMAIL=x@y.z \
  uvicorn yourapp.main:app           # -> must refuse to start
```

### 8. Flag the deployment requirement

State this in the summary, every time — it is the one thing that makes the rest meaningful:

> The origin must be unreachable except through Cloudflare (a Cloudflare Tunnel, or a
> proxied hostname with the origin firewalled to Cloudflare IPs). If the container is
> directly reachable, an attacker bypasses Access entirely and JWT verification protects
> nothing.

---

## API surface

```python
from cf_user_idm import (
    install_cf_access,          # install_cf_access(app, settings=None, *, include_router=True,
                                #                   on_authenticated=None, jwks=None)
    CurrentUser,                # Annotated[AccessUser, Depends(...)]      human only
    CurrentPrincipal,           # Annotated[Principal, Depends(...)]       human or machine
    OptionalUser,               # Annotated[AccessUser | None, Depends(...)]
    get_current_user, get_current_principal, get_optional_user,
    AccessUser, ServicePrincipal, Principal,
    CfAccessSettings, AccessAuthError, ConfigurationError,
)
from cf_user_idm.testing import AccessTestKit, make_user, make_service_principal, override_principal
```

`AccessUser`: `id` (= `sub`, the primary key), `email`, `identity_nonce`, `country`,
`issued_at`, `expires_at`, `custom`, `details`, `is_service` (`False`), `claims`.

`ServicePrincipal`: `id` (= `common_name`), `common_name`, `issued_at`, `expires_at`,
`is_service` (`True`), `claims`.

Mounted by default: `GET /auth/me`, `GET /auth/logout`, and `GET /auth/debug` when
`CF_ACCESS_ENABLE_DEBUG_ENDPOINT=true`.

The caller is also available as `request.state.cf_principal`.

## Error codes

`missing_token` (401), `invalid_token` (401), `token_expired` (401),
`signing_key_unavailable` (401), `audience_mismatch` (403), `issuer_mismatch` (403),
`service_token_not_permitted` (403). Body shape:
`{"error": {"code": ..., "message": ...}}`.

## Common mistakes to avoid

| Mistake | Why it is wrong |
| --- | --- |
| Keying users on email | Email changes create duplicate accounts. Use `user.id`. |
| Adding `require_role()` to the auth layer | Roles are application data. Cloudflare already handled access. |
| Global middleware requiring auth on every path | Breaks health checks; the per-route annotation is the design. |
| Catching `AccessAuthError` and continuing anonymously | Turns a rejected token into a silent bypass. |
| Committing `CF_ACCESS_DEV_MODE=true` | Disables authentication wherever it lands. |
| Reading claims with `jwt.decode(..., verify=False)` | Unverified claims are attacker-controlled. |
| Trusting `Cf-Access-Authenticated-User-Email` | Unsigned header; forgeable by anything that reaches the origin. |

Full detail: [`INTEGRATION.md`](INTEGRATION.md) · [`CLOUDFLARE_SETUP.md`](CLOUDFLARE_SETUP.md)
