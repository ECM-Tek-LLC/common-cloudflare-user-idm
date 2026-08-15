# AGENTS.md

`common-cloudflare-user-idm` (import name `cf_user_idm`) turns the Cloudflare Access JWT into
a trustworthy identity for FastAPI applications. It is a **published library** — other repos
depend on it by pinned git tag, so a change here reaches production in apps you cannot see
from this repo.

## Adding Cloudflare Access to an application?

You are in the wrong repo. Do not copy code out of `src/`. Read
[`docs/AI_AGENT_PROMPT.md`](docs/AI_AGENT_PROMPT.md) — a self-contained runbook for exactly
that task — and install the package:

```bash
uv add "common-cloudflare-user-idm @ git+https://github.com/ECM-Tek-LLC/common-cloudflare-user-idm@v0.1.0"
```

Hand-rolling JWKS caching, audience validation and a dev bypass in each service is the
duplication this library exists to prevent.

## The scope boundary

This library answers **"who is calling?"** It does not answer **"what may they do?"**

Roles, permissions and tenancy belong in the application's database, keyed on `user.id`.
Do not add group checks, role decorators or permission machinery here — their absence is
deliberate, not an oversight.

## Non-negotiable rules for changes

- **Never** add a path that trusts the `Cf-Access-Authenticated-User-Email` header, reads
  claims before the signature is verified, or turns an auth failure into an anonymous
  request. Silently downgrading a bad token hides an attack.
- **Never** loosen `CF_ACCESS_DEV_MODE`'s guards. It bypasses verification entirely; the
  explicit flag, the fake-email requirement, the boot banner and the refusal to start in a
  production-like `APP_ENV` are all load-bearing.
- **Never** log, return, or embed a JWT in an error message.
- Key everything on `user.id` (the Cloudflare `sub`, a stable UUID) — never on email. Email
  is mutable.
- A change to verification logic MUST come with tests that exercise the failure case, not
  only the happy path. Use `AccessTestKit`, which stands in for a whole Cloudflare tenant
  with its own key pair, so tests hit the real verification path without network.
- Public API changes MUST bump the version in `pyproject.toml` and be noted in
  [`CHANGELOG.md`](CHANGELOG.md). Consumers pin by tag.

## Commands

All four must pass before you call a change done. Report the real output.

```bash
uv sync --all-extras --dev --locked
uv run ruff check . && uv run ruff format --check .
uv run mypy
uv run pytest --cov --cov-report=term-missing
```

## Repo-local overrides

These override [ECM-DEVELOPER-STANDARDS.md](https://github.com/ECM-Tek-LLC/common-ecmtek-developer-standards/blob/main/ECM-DEVELOPER-STANDARDS.md).
Each is deliberate; do not "fix" them back.

- **Python floor is 3.11, not 3.12.** The standard sets 3.12 for *applications*. This is a
  library consumed by applications, and dropping 3.11 would strand any consumer still on it
  for no benefit. CI tests 3.11, 3.12 and 3.13.
- **No Sentry integration.** The standard requires every *application* to report errors to
  Sentry. A library must not initialize error tracking — it would hijack the host
  application's configuration. Errors are raised as typed exceptions for the app to report.
- **No `/healthz` or `/readyz`.** This library ships no service of its own; health endpoints
  belong to the application that installs it.

## Related standards

- [common-ecmtek-developer-standards](https://github.com/ECM-Tek-LLC/common-ecmtek-developer-standards)
  — how code is written. Applies here except where overridden above.
- [common-ecmtek-deployment-configuration](https://github.com/ECM-Tek-LLC/common-ecmtek-deployment-configuration)
  — how apps deploy. Relevant because this library requires the origin to be unreachable
  except through Cloudflare.
