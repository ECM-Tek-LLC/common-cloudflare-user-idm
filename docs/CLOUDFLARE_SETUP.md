# Cloudflare setup

The dashboard side of the work. Do this once per application, then hand
`CF_ACCESS_TEAM_DOMAIN` and `CF_ACCESS_AUDIENCE` to the app.

---

## The one rule that makes any of this work

**The origin must be unreachable except through Cloudflare.**

Verifying the Access JWT proves a request came through Access. It says nothing about
requests that *didn't*. If your container is reachable at a public IP, or through a load
balancer that accepts traffic from anywhere, an attacker simply connects directly, sends no
token, and the whole scheme buys you nothing.

Pick one:

- **Cloudflare Tunnel (recommended).** Run `cloudflared` next to the app; it makes an
  outbound connection to Cloudflare. The origin needs no inbound ports at all. This is the
  only option that is secure by construction rather than by configuration.
- **Proxied hostname + origin firewall.** Orange-cloud the DNS record and restrict the
  origin's firewall to [Cloudflare's IP ranges](https://www.cloudflare.com/ips/), ideally
  with mTLS (Authenticated Origin Pulls). Correct, but only as long as nobody widens that
  security group later.

---

## 1. Team domain

Zero Trust dashboard → **Settings** → **Custom Pages**. The team domain reads
`acme.cloudflareaccess.com`; the app wants `acme` (it accepts the full form too).

```bash
CF_ACCESS_TEAM_DOMAIN=acme
```

Everything the framework talks to derives from it:

| URL | Purpose |
| --- | --- |
| `https://acme.cloudflareaccess.com` | The `iss` claim in every token |
| `.../cdn-cgi/access/certs` | Public signing keys (JWKS) |
| `.../cdn-cgi/access/get-identity` | Optional profile enrichment |
| `.../cdn-cgi/access/logout` | Where `/auth/logout` redirects |

---

## 2. Create the Access application

Zero Trust dashboard → **Access** → **Applications** → **Add an application** →
**Self-hosted**.

- **Application domain** — the hostname users visit, e.g. `app.example.com`.
- **Session duration** — how long before re-authentication. This is the `exp` on the token
  your app receives.
- **Identity providers** — whichever your organization uses.

---

## 3. Copy the AUD tag

With the application created: **Access → Applications → *your app* → Overview →
Application Audience (AUD) Tag**. 64 hex characters.

```bash
CF_ACCESS_AUDIENCE=0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9
```

This is what stops a token minted for a *different* application in your own team from being
replayed against this one. Every app in the team gets its own tag; never share one.

If an origin sits behind more than one Access application — say a public hostname and an
internal one — list every tag:

```bash
CF_ACCESS_AUDIENCE=tag-for-public-app,tag-for-internal-app
```

---

## 4. Write the access policy

**Access → Applications → *your app* → Policies.** This is where authorization happens.
Everything the policy allows, the application will treat as a legitimate user — the
framework does not second-guess it.

Typical shapes:

| Policy | Rule |
| --- | --- |
| Anyone in the company | Emails ending in `@example.com` |
| A specific team | IdP group `engineering` |
| Named individuals | Email list |
| Contractors, time-boxed | Email list + expiry |

Fine-grained permissions *inside* the app (who is an admin, which tenant they belong to)
belong in the app's own database, keyed on the user id the framework provides.

---

## 5. Service tokens, for machine callers

CI jobs and other services cannot complete an interactive login. Give them a service token:

**Access → Service Auth → Service Tokens → Create Service Token.** Save the Client ID and
Client Secret; the secret is shown once.

Add a policy on the application with action **Service Auth** and a **Service Token** rule
naming that token, otherwise Access will still demand an interactive login.

Callers send two headers:

```bash
curl https://app.example.com/ingest \
  -H "CF-Access-Client-Id: <client-id>.access" \
  -H "CF-Access-Client-Secret: <client-secret>"
```

The token your app receives has a `common_name` and no email, so the framework produces a
`ServicePrincipal`. Routes annotated `CurrentUser` reject it with 403; routes annotated
`CurrentPrincipal` accept it. Set `CF_ACCESS_ALLOW_SERVICE_TOKENS=false` to refuse them
everywhere.

---

## 6. Key rotation

Cloudflare rotates the signing key roughly every six weeks. Nothing to do — the framework
caches the JWKS for an hour and refetches immediately when it sees a key id it does not
recognize. The only requirement is that the origin can make outbound HTTPS requests to
`https://<team>.cloudflareaccess.com`. If egress is locked down, allow that host, or key
rotation becomes a site-wide outage six weeks after launch.

---

## 7. Check it end to end

```bash
# From a browser, after signing in through Access:
https://app.example.com/auth/me

# The token Cloudflare attaches, seen from the origin:
CF_ACCESS_ENABLE_DEBUG_ENDPOINT=true   # then GET /auth/debug
```

If `/auth/me` returns `missing_token` in a deployed environment, the request did not come
through Cloudflare. Treat that as a deployment security finding, not an app bug: it means
the origin is directly reachable.
