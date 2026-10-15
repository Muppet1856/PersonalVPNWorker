# PersonalVPNWorker

An invite-only, passkey-based access portal you can deploy on your own domain using **Cloudflare Workers and a SQLite-backed Durable Object**. It is designed for small private groups such as families and home labs. Branding, domain, Worker name and authentication lifetimes are configurable; no personal domain is built into the application.

Despite the repository name, this project currently provides **authentication**, not a VPN tunnel. The Cloudflare Access integration can protect selected web applications. Network-level VPN access remains a separate service.

## Current milestone

Implemented: first-administrator bootstrap, one-time invitations, WebAuthn passkey registration and login, server-side sessions, logout, administrator invitation creation and optional Resend invitation emails, a minimal portal/app launcher, OIDC Authorization Code + S256 PKCE federation, persistent RS256 signing keys, public discovery/JWKS, and optional Cloudflare Access API provisioning. SQLite storage initializes automatically: no D1 database, database ID, or separate migration command is needed.

Not implemented yet: Sign in with Apple, account recovery, multiple-passkey administration, audit trails and complete production hardening. The OIDC implementation supports one preconfigured confidential Cloudflare Access client; it is not a general-purpose, conformance-certified identity platform. This milestone is for development and evaluation; finish those controls before using it as a production identity provider.

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

Paste the returned token into **Accept family invitation**, enter your display name, and create a passkey. Sign out and test signing in with that email address. The signed-in administrator can generate invitations for others; deliver those tokens privately. When Resend is configured, the administrator can email invitation links directly.

## Connect applications through Cloudflare Access

After creating your administrator passkey, follow [Cloudflare Access setup](docs/access-setup.md). The optional GitHub deployment step can configure the identity provider, self-hosted applications and member allow policies using Cloudflare's API. It defaults to **off**. The Worker’s discovery and public-key endpoints are checked after each deployment, even before an Access client is configured.

## Invitation emails with Resend

Verify a sending domain in Resend, create a **sending-only API key restricted to that domain**, then configure:

| Setting | Location | Example |
| --- | --- | --- |
| `RESEND_API_KEY` | GitHub Actions secret or Worker secret | Your restricted API key |
| `RESEND_FROM` | GitHub Actions variable | `invites@mail.example.com` |
| `RESEND_REPLY_TO` | Optional GitHub Actions variable | A monitored reply address |

The workflow uploads a supplied API key using Wrangler's private secrets file. Existing Worker secrets are preserved when omitted from GitHub. Sender/reply-to settings can also be stored as Worker secrets when configuring directly through Cloudflare; deployment omits unspecified sender settings. Keep the sender and domain private to your installation, not in source. The domain's Resend open/click tracking should be disabled so private enrollment links are not rewritten or tracked.

Sign in as administrator and use **Create and email invitation**. The recipient opens the link, enters a display name, and creates a passkey. The token is in the URL fragment, is removed from browser history after loading, and is not consumed by opening the email or link. Enrollment still requires explicit WebAuthn registration. Links expire according to `INVITE_TTL_SECONDS` and can be redeemed once.

Sending uses one bounded retry for network errors, HTTP 429 or 5xx, with the same idempotency key and payload. Provider acceptance is not proof of inbox delivery. If delivery cannot be confirmed, the administrator gets the private link to share manually; the email may still arrive. There is no durable delivery queue or bounce webhook yet. The API requires `send_email: true` to send; without it, invitations remain manual. Sending is available only with HTTPS and valid sender/key settings.

Invitations are limited to one per address per minute and three per address per administrator per hour, including manual and failed email attempts. The SQLite schema upgrades automatically and preserves existing users, passkeys and invitation tokens. Bootstrap invitations remain manual.

## Your own app launcher

Set `LAUNCHER_ORIGIN=https://access.example.com` to serve a branded application grid on a separate custom domain. Keep `PUBLIC_ORIGIN=https://vpn.example.com` and `RP_ID=vpn.example.com` for passkey authentication. The same Worker serves both hosts; existing passkeys keep their original scope.

Tiles come from `ACCESS_APPS_JSON`. The launcher has its own Access application and verifies Cloudflare's signed assertion before displaying links. With `CONFIGURE_ACCESS=true`, deployment provisions that application and binds its audience automatically using Wrangler. Until configuration completes, the launcher returns an unavailable response. See [launcher setup](docs/access-setup.md#custom-application-launcher).

The Cloudflare team hostname remains part of authentication redirects; this launcher supplies your own landing page rather than masking those redirects.

## Configuration

Copy the deployment template:

```sh
cp .env.deploy.example .env.deploy.local
```

Edit `.env.deploy.local` for your installation. It is ignored by Git. Alternatively, supply the same values as environment variables in your deployment/build service. Existing process environment variables take precedence over values loaded from the file.

| Setting | Purpose | Default |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | Required production HTTPS origin, such as `https://vpn.example.com` | Required for deployment |
| `RESEND_FROM` | Optional bare sender email address for invitation delivery | Unset |
| `RESEND_REPLY_TO` | Optional bare address for replies | Unset |
| `LAUNCHER_ORIGIN` | Optional separate HTTPS origin for your custom, Access-protected app launcher | Unset |
| `WORKER_NAME` | Cloudflare Worker resource name | `family-access` |
| `SITE_NAME` | Browser title, portal heading and passkey display name | `Family Access` |
| `RP_ID` | WebAuthn relying-party hostname | Hostname from `PUBLIC_ORIGIN` |
| `FAMILY_ID` | Stable name selecting the Durable Object's database | `family-v1` |
| `SESSION_COOKIE_NAME` | Host-only session cookie name | `family_session` |
| `SESSION_TTL_SECONDS` | Lifetime for newly issued sessions; maximum 30 days | `604800` (7 days) |
| `INVITE_TTL_SECONDS` | Regular invitation lifetime; maximum 7 days | `86400` (24 hours) |
| `SETUP_INVITE_TTL_SECONDS` | First-admin invitation lifetime; maximum 24 hours | `3600` (1 hour) |
| `CHALLENGE_TTL_SECONDS` | WebAuthn challenge lifetime; maximum 10 minutes | `300` (5 minutes) |
| `ACCESS_TEAM_DOMAIN` | Existing Zero Trust team hostname, e.g. `example.cloudflareaccess.com` | Empty; federation disabled |
| `OIDC_CLIENT_ID` | Identifier of the trusted Cloudflare Access client | `family-access` |
| `ACCESS_APPS_JSON` | JSON array of `{ "name": "Chat", "domain": "chat.example.com" }` entries | `[]` |
| `CONFIGURE_ACCESS` | GitHub-only opt-in to Access API provisioning | Off; set variable to `true` to enable |

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

### GitHub Actions deployment (recommended)

`.github/workflows/deploy.yml` deploys on pushes to `main`, or manually through **Actions → Deploy Worker → Run workflow** on `main`. It first calls the reusable validation workflow: TypeScript checks, regression tests, generated-config dry run and HTTP authentication tests using `wrangler dev`. Deployment runs only after all checks pass, using the repository-pinned Wrangler CLI.

In your GitHub repository, open **Settings → Secrets and variables → Actions**.

Add these **repository secrets** on the **Secrets** tab:

| Secret | Value |
| --- | --- |
| `CLOUDFLARE_API_TOKEN` | API token allowed to deploy Workers in your Cloudflare account and manage the selected custom-domain zone |
| `CLOUDFLARE_ACCOUNT_ID` | The Cloudflare account ID containing the Worker and domain |
| `ADMIN_SETUP_SECRET` | A long random bootstrap secret for first-admin enrollment; optional after setup |

Create the API token using Cloudflare's **Edit Cloudflare Workers** template, scoped to your account and target zone. Ensure its permissions cover Worker deployment, Durable Object namespace/migration creation and custom-domain/route management. See [Cloudflare's GitHub Actions setup](https://developers.cloudflare.com/workers/ci-cd/external-cicd/github-actions/) and [Workers permissions](https://developers.cloudflare.com/workers/authorization/workers/). Use an API token, not your Global API key.

Add these **repository variables** on the **Variables** tab:

| Variable | Example |
| --- | --- |
| `PUBLIC_ORIGIN` | `https://vpn.example.com` (required) |
| `WORKER_NAME` | `family-access`, or your existing Worker's name |
| `SITE_NAME` | `Family Access` |

### Deploying your own fork

Fork this repository into your own GitHub account, enable Actions if GitHub prompts, then create the variables and secrets in **your fork's** settings. Forks do not inherit the original repository's Actions variables or secrets. Each owner supplies their own hostname, Cloudflare credentials and bootstrap secret, so each fork deploys independently to its owner's account.

Actions settings are scoped to repositories, organizations or deployment environments, not automatically to whichever GitHub user clicks Run workflow. If several people share one repository and need separate deployments, use separate GitHub environments with their own settings and a workflow that explicitly selects the target environment; the included workflow deploys one installation per repository.

All other settings in the configuration table can also be supplied as repository variables. The deployment workflow also accepts these settings as repository secrets if preferred; a nonempty variable takes precedence over a secret of the same name. `CLOUDFLARE_ACCOUNT_ID` accepts either location too. Keep `CLOUDFLARE_API_TOKEN` and `ADMIN_SETUP_SECRET` as secrets. Empty optional variables use the documented defaults. Repository settings are private to your installation; generic examples remain in source.

On deployment, Wrangler provisions/updates the Worker, custom domain and SQLite Durable Object binding. The optional bootstrap secret and configured `OIDC_CLIENT_SECRET` are sent using `--secrets-file` in the same deployment. It is written to a private temporary file, never printed, and removed when the deploy command finishes. Secrets absent from that file remain unchanged in Cloudflare. OIDC client setup also requires `ACCESS_TEAM_DOMAIN` and an `OIDC_CLIENT_SECRET` of at least 32 random characters; see the Access guide.

After enrollment, delete `ADMIN_SETUP_SECRET` from **both GitHub Actions secrets and the deployed Worker**. Removing it from GitHub alone does not delete the existing Cloudflare secret; leaving it in GitHub would upload it again on the next deployment.

Disable an existing Cloudflare Workers Builds integration for the same branch/Worker when switching to GitHub Actions, so only one pipeline controls deployments. Cloudflare credentials are passed only to the deployment step; pull-request and branch validation does not receive them.

### Optional: Cloudflare Workers Builds

If you prefer Cloudflare-managed builds instead of GitHub deployment, disable `deploy.yml` in GitHub Actions. Connect the repository in Cloudflare, use `npm ci && npm run build` as the build command and `npm run deploy` as the deploy command, supply the configuration values as build variables, and set `ADMIN_SETUP_SECRET` separately as a Worker runtime secret. `WORKER_NAME` must match the connected Worker.

## Development and validation

```sh
npm run check
npm test
npm run test:wrangler
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
| `src/email.ts` | Resend invitation templates, validation and bounded idempotent delivery |
| `src/launcher.ts` | Custom launcher rendering and Access JWT verification |
| `src/oidc.ts` | OIDC flow, signing keys, throttling and expired-record cleanup |
| `scripts/configure-access.mjs` | Optional, scoped Access API provisioning |
| `.env.deploy.example` | Portable nonsecret deployment template |
| `tests/` | Authentication, configuration and local-runtime tests |

## Security and deployment boundaries

Passkey private keys remain with authenticators. The server stores public credentials and hashes of invitation/session tokens. Registration identity and display name are bound to server-issued challenges. Challenges are consumed atomically; enrollment writes execute inside synchronous SQLite transactions. HTML branding is escaped before rendering.

The current UI uses inline scripts. Basic per-IP/path request throttling and expired-record cleanup are included. Remaining hardening includes strict CSP/client bundling, stronger anti-abuse and enumeration resistance, audit events, passkey/session management, a tested recovery policy, and independent OIDC conformance/security review.

Keep local DNS, reverse proxies, existing tunnels, VPNs and port forwarding under your own deployment's control. This application does not configure or change them. Do not place the future OIDC provider behind its own Cloudflare Access login, which would create an authentication loop.

Cloudflare's [Workers Free plan supports SQLite-backed Durable Objects](https://developers.cloudflare.com/durable-objects/platform/pricing/). Small-group usage is the intended scale; account-wide limits apply. This project does not require a paid storage backend.

Never commit `.env.deploy.local`, `.dev.vars.local`, invitation tokens, signing keys, database exports or Cloudflare API tokens. The example files contain placeholders only. Secrets belong in Worker secret storage, not public configuration. Earlier repository history may still contain previous nonsecret branding/domain settings.

## Roadmap

1. Independent OIDC conformance/security review and real Cloudflare Access interoperability validation.
2. Credential/session administration, audit events and recovery policy.
3. Invite-only Sign in with Apple linking and delivery webhooks/queueing.
4. Deployment-specific external rollout tests and network changes, if desired.
