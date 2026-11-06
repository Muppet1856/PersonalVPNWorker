# Architecture

The configured HTTPS origin routes to a Worker, which forwards requests to one `FamilyAuth` Durable Object selected by `FAMILY_ID`. Its private SQLite database holds users, public passkey credentials, invitations, challenges and hashed sessions. One object suits a small private group and keeps related writes in one transaction boundary.

The namespace is provisioned through the checked-in Wrangler `new_sqlite_classes` migration. Schema versioning runs synchronously in the object constructor inside `transactionSync`. Future upgrades must add a new schema version step; do not edit a deployed version in place. No separate D1 resource exists.

WebAuthn verification awaits cryptographic operations, so requests can interleave. Challenges are consumed with `DELETE ... RETURNING`; invitation validity is checked again when inserting a user; enrollment writes commit in a synchronous transaction. Registration's user handle matches the stored account ID. Login and session authorization both require an active account.

`PUBLIC_ORIGIN` and `RP_ID` bind authentication to the deployment's exact origin and hostname. `SITE_NAME` controls display branding independently. Local development uses `localhost` with a separate Worker namespace; local and production credentials need separate enrollment.

The public repository contains generic defaults. `scripts/configure.mjs` combines a nonsecret deployment environment with the base Wrangler configuration, validates it and writes an ignored deployment config. Secrets are stored separately. `FAMILY_ID`, Worker identity and the Durable Object class/binding must remain stable to retain the same database.

The current OIDC milestone provides one confidential client with RS256 signing, mandatory S256 PKCE, exact callbacks, browser-bound login continuation, and automatic schema version 2. See [Access setup](access-setup.md) for API provisioning and its boundaries.

The Worker sends invitations, email sign-in codes, and account-security notifications directly through Resend's HTTPS API. Resend MCP supports operator setup and inspection; it is not in the runtime email path. See [Resend setup and email flows](resend-setup.md) for sender provisioning, Mermaid diagrams, delivery limits, and opt-in family recovery.

Future milestones retain invite-only membership: Sign in with Apple linking from authenticated sessions and further hardening/conformance review of the OIDC implementation. Apple email alone must never auto-authorize membership.

The Worker runtime is a private-group identity service, not a VPN tunnel server. Separate opt-in [operator scripts](network-setup.md) provision Access policies, Cloudflare Tunnel, public DNS, and hostname-scoped WAF/cache rules. Local DNS, reverse proxies, VPN routing, and device firewalls remain under the operator's control.

See [device Access and Tunnel setup](device-access-tunnel.md) for the surrounding network architecture, Mermaid flows, WAF controls, and an operator runbook for applications behind an existing VPN/firewall.
