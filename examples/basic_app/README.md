# Example app

A complete FastAPI application wired up with `cf_user_idm`, showing every dependency and
the `on_authenticated` hook.

## Run it locally (development bypass)

```bash
cp examples/basic_app/.env.example examples/basic_app/.env
uv run uvicorn examples.basic_app.main:app --reload --env-file examples/basic_app/.env
```

Startup logs a large warning banner: requests are **not** authenticated, and every caller
is treated as `dev@localhost`. That is the point of the bypass, and the banner is why you
cannot forget it is on.

```bash
curl -s localhost:8000/health     | jq   # public
curl -s localhost:8000/auth/me    | jq   # the synthetic dev user
curl -s localhost:8000/profile    | jq
curl -s localhost:8000/landing    | jq
curl -s localhost:8000/auth/debug | jq   # how identification is configured
```

## Run it against real tokens, without Cloudflare

To exercise the actual verification path — signature, audience, issuer, expiry — mint a
token with the test kit and drive the app with it:

```bash
uv run python examples/basic_app/local_verify.py
```

That script builds the app with an `AccessTestKit` standing in for a Cloudflare tenant,
then shows a valid token succeeding and an expired, wrong-audience and forged token each
being refused.

## Deployed

Swap the `.env` for the production block in `.env.example` (`CF_ACCESS_TEAM_DOMAIN` and
`CF_ACCESS_AUDIENCE`, no `CF_ACCESS_DEV_MODE`), and put the origin behind a Cloudflare
Tunnel so it cannot be reached without passing through Access. See
[`docs/CLOUDFLARE_SETUP.md`](../../docs/CLOUDFLARE_SETUP.md).
