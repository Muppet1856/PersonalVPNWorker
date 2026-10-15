# PersonalVPNWorker

An invite-only, passkey-based access portal you can deploy on your own domain using **Cloudflare Workers and a SQLite-backed Durable Object**. It is designed for small private groups such as families and home labs. Branding, domain, Worker name and authentication lifetimes are configurable; no personal domain is built into the application.

Despite the repository name, this project currently provides **authentication**, not a VPN tunnel. The planned Cloudflare Access integration will protect selected web applications. Network-level VPN access remains a separate service.

## Current milestone

Implemented: first-administrator bootstrap, one-time invitations, WebAuthn passkey registration and login, server-side sessions, logout, administrator invitation creation, and a minimal portal. SQLite storage initializes automatically: no D1 database, database ID, or separate migration command is needed.

Not implemented yet: Sign in with Apple, Resend email delivery, OIDC federation to Cloudflare Access, account recovery, multiple-passkey administration, rate limiting, audit trails and production hardening. This milestone is for development and evaluation; finish those controls before using it as a production identity provider.

## Quick start

Requires **Node.js 24**, npm, and a browser with WebAuthn support.

```sh
npm ci
cp .dev.vars.example .dev.vars.local
# Replace ADMIN_SETUP_SECRET in .dev.vars.local with a long random value.
npm run dev
```

Open **http://localhost:8787**. Local storage persists in `.wrangler/`, separate from production. Local development needs no Cloudflare login or database setup.

Create your first administrator invitation from a terminal, replacing the placeholders:

```sh
curl http://localhost:8787/api/setup \
  -H 'Origin: http://localhost:8787' \
  -H 'Content-Type: application/json' \
  --data '{"email":"admin@example.com","secret":"YOUR_LOCAL_SETUP_SECRET"}'
```

Paste the returned token into **Accept family invitation**, enter your display name, and create a passkey. Sign out and test signing in with that email address. The signed-in administrator can generate invitations for others; deliver those tokens privately. Invitation email delivery is a later milestone.

## Configuration

Copy the deployment template:

```sh
cp .env.deploy.example .env.deploy.local
```

Edit `.env.deploy.local` for your installation. It is ignored by Git. Alternatively, supply the same values as environment variables in your deployment/build service. Existing process environment variables take precedence over values loaded from the file.

| Setting | Purpose | Default |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | Required production HTTPS origin, such as `https://vpn.example.com` | Required for deployment |
| `WORKER_NAME` | Cloudflare Worker resource name | `family-access` |
| `SITE_NAME` | Browser title, portal heading and passkey display name | `Family Access` |
| `RP_ID` | WebAuthn relying-party hostname | Hostname from `PUBLIC_ORIGIN` |
| `FAMILY_ID` | Stable name selecting the Durable Object's database | `family-v1` |
| `SESSION_COOKIE_NAME` | Host-only session cookie name | `family_session` |
| `SESSION_TTL_SECONDS` | Lifetime for newly issued sessions; maximum 30 days | `604800` (7 days) |
| `INVITE_TTL_SECONDS` | Regular invitation lifetime; maximum 7 days | `86400` (24 hours) |
| `SETUP_INVITE_TTL_SECONDS` | First-admin invitation lifetime; maximum 24 hours | `3600` (1 hour) |
| `CHALLENGE_TTL_SECONDS` | WebAuthn challenge lifetime; maximum 10 minutes | `300` (5 minutes) |

All lifetime values must be positive whole seconds. `PUBLIC_ORIGIN` must contain no credentials, port, path beyond `/`, query or fragment. `RP_ID` must match its hostname. The custom domain is generated from that same hostname.

```sh
npm run configure
```

This validates settings and generates **`wrangler.deploy.json`**, which is ignored by Git. It copies only the listed nonsecret settings; it does not copy your entire environment or any bootstrap secret. The checked-in `wrangler.jsonc` provides generic local/CI defaults. Local runtime overrides can be placed in `.dev.vars.local`.

Changing `SITE_NAME` changes branding without invalidating passkeys. Changing the hostname/RP ID requires separate passkey enrollment. Keep the Worker identity, Durable Object class/binding and `FAMILY_ID` stable after use: changing them may select a different namespace or database. Changing the cookie name signs existing browser sessions out. Lifetime changes apply to newly created records; previously stored expiration times remain unchanged.

## Deploy on your own domain

Your domain must be managed by your Cloudflare account. Resolve any conflicting DNS record for the chosen hostname before deployment.

```sh
npx wrangler login
npm run configure
npx wrangler secret put ADMIN_SETUP_SECRET --config wrangler.deploy.json
npm run deploy
```

Set a strong bootstrap secret when prompted. `npm run deploy` regenerates the validated configuration before deploying. The declared SQLite Durable Object namespace is provisioned by Cloudflare; the object initializes its schema on first use.

Bootstrap production with the earlier `/api/setup` request, replacing both the request URL and `Origin` with your configured `PUBLIC_ORIGIN`, and using the production secret. Visit the HTTPS site to enroll the administrator's passkey. Local passkeys are scoped to `localhost` and cannot be reused on the production hostname.

Once the administrator is enrolled, delete the bootstrap secret:

```sh
npx wrangler secret delete ADMIN_SETUP_SECRET --config wrangler.deploy.json
```

Only one bootstrap invitation can be issued. If it expires before enrollment, the account owner can delete that **unused** administrator invitation through the Durable Object SQL console after confirming the `users` table is empty, then repeat bootstrap. Do not delete registered users or change `FAMILY_ID` to recover a token.

### Cloudflare Workers Builds

Connect your fork/repository and select its deployment branch. Set:

- Root directory: repository root (`/`).
- Build command: `npm ci && npm run build`.
- Deploy command: `npm run deploy`.
- Build environment variables: `PUBLIC_ORIGIN` and any optional settings from the table. `WORKER_NAME` must match the Worker connected to the build.
- Worker runtime secret: `ADMIN_SETUP_SECRET`, configured separately from build variables.

The included GitHub Actions workflow checks TypeScript, builds the Worker and runs tests. It does not deploy or need Cloudflare credentials. A connected Cloudflare Workers Builds deployment is managed separately.

## Development and validation

```sh
npm run check
npm test
npm run build
```

Tests cover WebAuthn cryptographic verification using a simulated ES256 authenticator, transaction and replay behavior, session/logout flows, disabled accounts, expired challenges, request limits and schema initialization. A Cloudflare local-runtime test exercises Worker-to-Durable-Object routing, SQLite credential storage and passkey login. Deployment configuration tests validate generated settings and reject invalid origins, identifiers and lifetimes. Test with real authenticators and your deployed HTTPS origin before rollout.

The source is organized as follows:

| Path | Responsibility |
| --- | --- |
| `src/index.ts` | Worker routing and Durable Object entry point |
| `src/auth.ts` | Passkey routes, sessions, invitation flows and portal |
| `src/config.ts` | Runtime setting defaults and lifetime bounds |
| `src/store.ts`, `src/schema.ts` | Transactional SQLite access and schema initialization |
| `scripts/configure.mjs` | Validated deployment config generation |
| `.env.deploy.example` | Portable nonsecret deployment template |
| `tests/` | Authentication, configuration and local-runtime tests |

## Security and deployment boundaries

Passkey private keys remain with authenticators. The server stores public credentials and hashes of invitation/session tokens. Registration identity and display name are bound to server-issued challenges. Challenges are consumed atomically; enrollment writes execute inside synchronous SQLite transactions. HTML branding is escaped before rendering.

The current UI uses inline scripts. Remaining hardening includes strict CSP/client bundling, throttling, enumeration resistance, expired-record cleanup, audit events, passkey/session management and a tested recovery policy.

Keep local DNS, reverse proxies, existing tunnels, VPNs and port forwarding under your own deployment's control. This application does not configure or change them. Do not place the future OIDC provider behind its own Cloudflare Access login, which would create an authentication loop.

Cloudflare's [Workers Free plan supports SQLite-backed Durable Objects](https://developers.cloudflare.com/durable-objects/platform/pricing/). Small-group usage is the intended scale; account-wide limits apply. This project does not require a paid storage backend.

Never commit `.env.deploy.local`, `.dev.vars.local`, invitation tokens, signing keys, database exports or Cloudflare API tokens. The example files contain placeholders only. Secrets belong in Worker secret storage, not public configuration. Earlier repository history may still contain previous nonsecret branding/domain settings.

## Roadmap

1. Authentication hardening, credential/session administration and recovery policy.
2. Invite-only Sign in with Apple linking and Resend delivery.
3. Reviewed OIDC Authorization Code + PKCE federation, discovery, JWKS, key rotation and Cloudflare Access integration.
4. External rollout tests and deployment-specific network changes, if desired.
