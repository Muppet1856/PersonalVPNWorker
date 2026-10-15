# Connect Cloudflare Access

The Worker now implements the confidential-client OIDC authorization-code flow with mandatory S256 PKCE. Cloudflare Access redirects the browser here, the user signs in with a passkey, and the Worker returns a one-time code to Cloudflare's exact callback. Cloudflare validates the signed ID token and applies the application’s Access policy before returning the browser to the original application.

Do not put this identity portal behind an Access application that depends on the same portal. Keep its discovery, authorization, token and JWKS endpoints publicly reachable.

## GitHub settings

An existing Cloudflare Zero Trust organization and its free plan must already be initialized in your account. Find its team hostname in Cloudflare One **Settings → Team name and domain**. Use the exact hostname, e.g. `example.cloudflareaccess.com`; do not guess it from your own domain or include `https://`.

In **GitHub repository → Settings → Secrets and variables → Actions**, add:

| Type | Setting | Value |
| --- | --- | --- |
| Variable | `ACCESS_TEAM_DOMAIN` | Your existing team hostname |
| Variable | `OIDC_CLIENT_ID` | `family-access`, or another stable client ID |
| Secret | `OIDC_CLIENT_SECRET` | At least 32 random characters, e.g. output from `openssl rand -hex 32` |
| Variable | `ACCESS_APPS_JSON` | Array of the application names and exact hostnames to protect |
| Secret | `CLOUDFLARE_ACCESS_API_TOKEN` | Separate API token for Access configuration |
| Variable | `CONFIGURE_ACCESS` | `true`, only when ready to apply protection |

Example application configuration:

```json
[
  { "name": "Chat", "domain": "chat.example.com" },
  { "name": "Git", "domain": "git.example.com" }
]
```

Use existing application hostnames whose DNS/tunnels already work. Do not include the identity portal or team hostname, schemes, paths or wildcards. The same list populates the signed-in portal's app links. An empty list provisions only the identity provider, plus the launcher if configured.

The Access token needs account permissions for **Access: Organizations, Identity Providers, and Groups Write** and **Access: Apps and Policies Write**, including their corresponding read access, scoped to the target account. The normal Worker deployment token stays separate. This script does not need DNS, tunnel, billing or Worker-edit permissions on its Access token. Do not add the Access token as a Worker runtime secret.

Keep `CONFIGURE_ACCESS` unset initially if you want to inspect the plan or configure Cloudflare manually. The Worker deployment uploads the OIDC client secret, preserves your existing accounts/passkeys, and automatically upgrades the SQLite schema. Public signing keys initialize on demand and persist in the same Durable Object database.

## Review and apply

For local review, put nonsecret settings in `.env.deploy.local`, then run:

```sh
npm run access:plan
```

This prints the intended provider, callback and applications. It makes no Cloudflare API requests and omits secrets. To review in GitHub, inspect the app list and settings before enabling `CONFIGURE_ACCESS=true`.

Once enabled, run **Actions → Deploy Worker → Run workflow** on `main`. The pipeline:

1. Runs application tests and the Wrangler HTTP integration test.
2. Deploys Worker code, configuration and the OIDC secret.
3. Verifies deployed discovery and public-key endpoints.
4. Validates your existing Zero Trust team domain and checks for configuration conflicts.
5. Creates or updates only its named OIDC provider and listed applications/policies.

The provider is named `<client-id> (PersonalVPNWorker)`. Managed applications are named `<client-id>: <application-name>`. Their only allow policy accepts users authenticated through this identity provider; only active, invited accounts can obtain tokens from the Worker. Other login methods and unrelated Cloudflare applications are not changed.

The script is repeatable but not transactional across Cloudflare resources. A failure may leave earlier resources configured; fix the reported cause and rerun. New applications default to denied access until their allow policy is saved. Existing applications or policies that do not match this project's ownership convention cause the script to stop before writes; it does not adopt or overwrite them. Removing an app from the list does not delete its existing protection. Keep managed names/client IDs stable; review renames manually.

Disable Cloudflare Workers Builds if GitHub Actions is the deployment authority for this Worker. Test from outside local DNS overrides, preferably a private browser on cellular. Local DNS and reverse-proxy access remain unchanged.

## Custom application launcher

Add the repository variable `LAUNCHER_ORIGIN=https://access.example.com`. Keep `PUBLIC_ORIGIN` and `RP_ID` on your existing authentication hostname; changing them would change passkey scope. Do not add the launcher domain to `ACCESS_APPS_JSON`; that list contains the destination tiles.

With `CONFIGURE_ACCESS=true`, the deploy workflow adds the launcher custom domain, creates a separate managed Access application for it, and uploads that application's audience as the `LAUNCHER_ACCESS_AUD` Worker secret through Wrangler. The Access token handles Access resources; the deployment token handles the Worker secret. The launcher checks the RS256 signature, issuer, audience and expiry of Cloudflare's assertion and exposes no authentication API on its hostname. It shows no application list until verification succeeds.

Visit the launcher, authenticate at your existing passkey hostname, then return to your application tiles. Cloudflare's team domain may appear during authentication; it remains the callback domain and is not replaced by the launcher. Destination applications still enforce their own Access policies.

For manual setup, create a self-hosted Access application for the exact launcher hostname with the same member policy, copy its Application Audience (AUD), and run:

```sh
npx wrangler secret put LAUNCHER_ACCESS_AUD --config wrangler.deploy.json --env ""
```

Paste the audience when prompted. Custom-domain provisioning requires the deployment token's existing zone/domain permissions and no conflicting DNS record. A failed provisioning or audience-binding step leaves the launcher unavailable; fix it and rerun the workflow.

## Manual Cloudflare setup

If using the dashboard instead of API automation, leave `CONFIGURE_ACCESS` unset. Add a **Generic OpenID Connect** provider under Cloudflare One **Integrations → Identity providers**. Use:

| Field | Value relative to your `PUBLIC_ORIGIN` |
| --- | --- |
| Client ID | Your `OIDC_CLIENT_ID` |
| Client secret | The same `OIDC_CLIENT_SECRET` stored in GitHub |
| Auth URL | `/oidc/authorize` |
| Token URL | `/oidc/token` |
| Certificate/JWKS URL | `/oidc/jwks` |
| Discovery URL | `/.well-known/openid-configuration` |
| PKCE | Enabled |
| Scopes | `openid email profile` |

The only allowed callback is `https://<team>.cloudflareaccess.com/cdn-cgi/access/callback`. Hostnames match exactly; there is no wildcard callback or arbitrary return URL.

Create a self-hosted Access application for each protected hostname. Select only this OIDC login method and create an Allow policy matching that login method. Keep your existing application login if you also need application-level authentication: Access adds an outer authentication layer, not automatic login to the underlying application.

## Operational details and limits

- Authorization codes last 120 seconds and can be redeemed only once, including concurrent exchanges. ID/access tokens last five minutes. Refresh tokens, implicit grants and dynamic client registration are not supported.
- Both `client_secret_basic` and `client_secret_post` are supported. S256 PKCE, the exact registered callback, matching client credentials and active account status are checked before issuing tokens.
- Browser login continuations are bound to an HttpOnly browser cookie and expire after five minutes. `state` and `nonce` are preserved. Forced-login requests require a new passkey session.
- OIDC emails are administrator-asserted through invitations, not independently email-verified; `email_verified` is explicitly `false`. Do not build email-ownership-sensitive integrations on that claim. The automated member policy matches the trusted login method.
- Signing uses `jose` and RS256. Private JWKs stay in private Durable Object storage; JWKS publishes public keys only. The administrator can use **Rotate identity signing key** in the portal; retired public keys remain published for 24 hours. Client-secret rotation uses GitHub Secrets and a deployment; API provisioning updates the matching Cloudflare client secret in the same workflow after Worker deployment.
- Changing the client secret can briefly interrupt login until both sides are updated. Previously issued access tokens expire within five minutes; Cloudflare Access sessions have their own configured lifetime (the automation uses 24 hours). Disabling a Worker user does not instantly revoke an existing Cloudflare Access session; revoke it in Cloudflare when needed.
- Existing passkey membership and app credentials remain unchanged. No DNS, tunnel, Pi-hole, reverse-proxy or port-forward settings are changed by Access provisioning.
- This implementation has automated security regression coverage; it has not undergone independent OIDC conformance certification or a security audit. Complete real Cloudflare interoperability checks and the remaining hardening before relying on it for sensitive services.

References: [Cloudflare Generic OIDC](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/), [Identity providers API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/), [Access applications API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/), [OAuth Security BCP](https://www.rfc-editor.org/rfc/rfc9700.html).
