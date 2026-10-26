# Per-user application permissions

## Breaking rollout behavior

**New family accounts start with no app grants.** The reviewed V5 rollout preserves prior access for pre-existing active family accounts to exactly `chat.zellen.ai` and `git.zellen.io`, but only when each hostname is present in validated `APP_LINKS_JSON`. This fixed, one-time upgrade data is in `src/rollout.ts`; it is not a runtime switch. Other hostnames and inactive users receive no grants. The grants and schema marker commit atomically. Restarting, changing configuration later, or deploying again cannot replay the migration or restore a removed grant. A database already at V5 is not modified by this preservation step. An administrator should review the resulting grants before the corresponding Access policies are enabled. Administrators always retain all configured applications and cannot have their app grants edited in this console. Newly configured applications are denied to family accounts until explicitly granted.

Application permission IDs are canonical HTTPS hostnames from `APP_LINKS_JSON` (and must match `ACCESS_APPS_JSON` domains). Renaming a display label does not affect a grant; changing the hostname requires a new grant. Duplicate hostnames fail closed. One hostname represents one Access application, not individual URL paths. Deleting/re-adding the same hostname preserves stored grants: revoke grants before repurposing a hostname for a different service.

## Enforcement boundary — deployment alone is not enough

The single Cloudflare Access OIDC client does not provide a trustworthy target application to this Worker. The Worker therefore issues an authoritative `allowed_apps` array in signed ID tokens and userinfo responses; Cloudflare Access must enforce the matching per-application rule. Link filtering is not an authorization boundary.

The updated `scripts/configure-access.mjs` emits a secret-free plan by default. Its authorized `--apply` path configures the managed IdP with `claims: ["allowed_apps"]` and each non-launcher app with BOTH the existing login-method include and this required rule:

```json
{"oidc":{"claim_name":"allowed_apps","claim_value":"chat.example.com","identity_provider_id":"THE_MANAGED_IDP_ID"}}
```

Use the relevant app hostname, not a display name. The launcher remains available to active enrolled members with no app grants, so they can still reach account management. It verifies the Access JWT and reads current local account state/grants from the family's Durable Object on each request.

**Do not claim downstream restrictions are active until Access configuration has been reviewed, applied with authorization, and verified on the actual domains.** Broad alternative Allow, Bypass, service-token, or other IdP policies and origins reachable outside Access can bypass these rules. The script refuses unmanaged policies, but the operator must inspect the full deployed topology.

Cloudflare documents [multi-record custom OIDC claims](https://developers.cloudflare.com/cloudflare-one/integrations/identity-providers/generic-oidc/#custom-oidc-claims), [OIDC claim policy selectors](https://developers.cloudflare.com/api/resources/zero_trust/subresources/access/subresources/applications/), and [IdP custom-claim mapping](https://developers.cloudflare.com/api/resources/zero_trust/subresources/identity_providers/).

## Changing permissions and existing sessions

Saving grants requires passkey verification within five minutes; mailbox-only sessions cannot change grants. The target user's portal sessions, pending login challenges, OIDC codes and bearer tokens are revoked transactionally. An access-revision check blocks an in-flight token signing operation if grants change before it finishes.

This does **not** revoke already issued Cloudflare Access cookies, global Access sessions, application-local sessions, or the signed ID token already delivered to Access. Those are external state. Revoke affected Access sessions through the approved Cloudflare operator workflow, force fresh IdP authentication, and terminate application sessions if required. Until that happens, old downstream access can continue for the existing session lifetime. The UI/API explicitly warn about this limitation; no external session-revocation API is called automatically.

For the separately authorized operator action, Cloudflare documents [session management](https://developers.cloudflare.com/cloudflare-one/access-controls/access-settings/session-management/) and [revoke all Access tokens for a user](https://developers.cloudflare.com/api/resources/zero_trust/subresources/organizations/methods/revoke_users/): `POST /accounts/{account_id}/access/organizations/revoke_user` with the verified user's `email`. Do not blindly copy examples that also revoke devices or WARP sessions; those broaden the action and require separate authorization. Confirm the API result and a fresh-authentication test rather than assuming the request succeeded.

## Rollout verification (not performed by local tests)

1. Keep a working admin passkey and a second admin-capable recovery path available under the agreed policy. Verify the one-time existing-user preservation results and stage any additional reviewed family grants before enforcing new Access policies.
2. Review the generated plan and managed Access IdP/app policy bodies. Apply only after authorization; verify `allowed_apps` appears in the IdP integration's test output.
3. Use two family test accounts with different grants and an admin. In fresh browser sessions, visit Chat and Git **directly**, not just through launcher tiles. Confirm allowed apps succeed and denied apps fail.
4. Change grants, revoke external Access/application sessions, then confirm both removal and addition on direct URLs after fresh authentication. Check an existing stale session as well so propagation limits are understood.
5. Confirm disabled accounts cannot open the launcher, future apps default deny, and administrators retain access.

Automated tests exercise local permissions, signed claims, provisioning payloads, and launcher rejection; they do not prove live Cloudflare policy enforcement.
