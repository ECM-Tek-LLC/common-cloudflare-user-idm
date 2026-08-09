# Changelog

## 0.1.0

Initial release.

- Cloudflare Access token verification: RS256 signature, audience, issuer and expiry, with
  the signing key resolved from the team's published JWKS.
- `JwksCache` with TTL caching, immediate refetch on an unrecognized key id, a rate floor
  on those refetches, single-flight concurrency, and stale-key fallback during an upstream
  outage.
- `AccessUser` and `ServicePrincipal` as distinct types; human-only routes reject service
  tokens with 403.
- FastAPI dependencies `CurrentUser`, `CurrentPrincipal`, `OptionalUser`.
- `install_cf_access()` one-call setup: structured JSON auth errors, the `/auth` router
  (`/me`, `/logout`, optional `/debug`), and lifespan-managed HTTP clients.
- Development bypass, guarded by a startup check that refuses production-like `APP_ENV`.
- Optional, cached identity enrichment from `/cdn-cgi/access/get-identity`.
- `on_authenticated` hook for syncing callers into an application's own user store.
- `cf_user_idm.testing`: `AccessTestKit` (local key pair, JWKS and token minting) and
  `override_principal`.
