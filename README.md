# Zellen Family Access

Invite-only passkey authentication for **vpn.zellen.me**, running on Cloudflare Workers with a **SQLite-backed Durable Object**. No D1 database, database ID, or separate SQL migration command is required.

This is a working authentication milestone. It does not yet provide OIDC federation to Cloudflare Access, Sign in with Apple, or Resend delivery. Keep existing access arrangements while those milestones are completed.

## Site settings

Set `SITE_NAME` in `wrangler.jsonc` → `vars` to change the browser title, portal heading, and name shown when creating a passkey. The default is `Zellen Family Access`. The `env.local.vars` value controls local development separately. The value is plain text and is escaped when rendered into HTML.

`PUBLIC_ORIGIN` is the full site URL (`https://vpn.zellen.me`); `RP_ID` is the passkey hostname (`vpn.zellen.me`). These are separate from the display name. Changing only `SITE_NAME` preserves existing passkey validity.

## Local development

Use Node.js 24 and npm.

```sh
npm ci
cp .dev.vars.example .dev.vars.local
# Set ADMIN_SETUP_SECRET in .dev.vars.local to a long random value.
npm run dev
```

Open http://localhost:8787. The local Durable Object initializes its schema automatically and persists in `.wrangler/`. No Cloudflare login is needed for local development.

Issue the first administrator invitation from your terminal (replace the example values):

```sh
curl http://localhost:8787/api/setup \
  -H 'Origin: http://localhost:8787' \
  -H 'Content-Type: application/json' \
  --data '{"email":"YOUR_EMAIL@example.com","secret":"YOUR_LOCAL_SETUP_SECRET"}'
```

Paste the returned token into **Accept family invitation**, enter your name, and enroll a passkey. Sign out and sign back in using the same email, then create invitations for family members. Tokens are displayed once for private delivery; email delivery comes later.

Local passkeys are scoped to `localhost`. Enroll separate passkeys on `vpn.zellen.me`.

## Deploy to Cloudflare

```sh
npx wrangler login
npx wrangler secret put ADMIN_SETUP_SECRET
npm run deploy
```

Set a strong bootstrap secret when prompted. The checked-in production configuration uses the `vpn.zellen.me` custom domain and a SQLite Durable Object binding. Cloudflare provisions the namespace at deployment; the object creates its schema on first use. The domain must be in your Cloudflare account, and an existing conflicting DNS record may need to be resolved in Cloudflare.

To use Cloudflare Workers Builds, connect **PersonalVPNWorker**, leave the root directory at `/`, use `npm ci && npm run build` as the build command, and `npm run deploy` as the deploy command. Set `ADMIN_SETUP_SECRET` as a Worker runtime secret, not a repository file. GitHub CI validates changes and never deploys automatically.

Bootstrap production using the same request as above, replacing both the URL and Origin with `https://vpn.zellen.me`, and supplying the production secret. Register your administrator passkey on that HTTPS origin. Then remove the bootstrap secret:

```sh
npx wrangler secret delete ADMIN_SETUP_SECRET
```

Only one bootstrap invitation can be issued. If it expires before enrollment, the account owner can delete that **unused** administrator invite in the Durable Object SQL console after confirming the `users` table is empty, then repeat bootstrap. Do not delete registered accounts or change the object name to recover a token.

Keep the binding/class and the stable object name `zellen-family-v1` unchanged: a different name selects a different database. Local and production Worker namespaces store separate data.

## Checks

```sh
npm run check
npm test
npm run build
```

Regression tests exercise actual WebAuthn cryptographic verification using a simulated ES256 authenticator, the production SQL wrapper against SQLite, one-time challenge consumption, invite redemption, setup races, expired challenges, disabled accounts, request limits, session logout, and automatic schema initialization. These are application-level tests; validate on real devices and in the Cloudflare runtime before rollout.

## Boundaries and remaining milestones

- No changes to Pi-hole, DSM, existing tunnels, UniFi Teleport, or port forwarding.
- Workers Free supports SQLite-backed Durable Objects. Normal family traffic should fit its allowances; account-wide daily limits still apply. See [Cloudflare pricing](https://developers.cloudflare.com/durable-objects/platform/pricing/).
- Public keys are stored server-side; private passkey material stays with authenticators. Invitation and session tokens are hashed before storage.
- Registration identities and names are bound to their server-issued challenge. Challenges are consumed atomically, and enrollment writes use a synchronous SQLite transaction.
- Before production identity-provider use: add throttling, enumeration resistance, expired-record cleanup, strict CSP/client bundling, audit events, credential/session administration, and tested recovery. The current UI uses inline scripts.
- Next: Sign in with Apple and Resend; then a reviewed OIDC Authorization Code + PKCE implementation, discovery, JWKS, key rotation, client registration, and Cloudflare Access integration.
- Never put this future OIDC identity provider behind its own Cloudflare Access login: that creates a redirect loop.

Never commit `.dev.vars*` secrets, `.env*`, invitation tokens, signing keys, or database exports. `.dev.vars.example` contains only a placeholder.
