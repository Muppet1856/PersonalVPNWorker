# Architecture

`vpn.zellen.me` routes to a Worker, which forwards requests to one named `FamilyAuth` Durable Object, `zellen-family-v1`. Its private SQLite database holds users, public passkey credentials, invitations, challenges and hashed sessions. One object is appropriate for a small invite-only family and keeps related writes in one transaction boundary.

The namespace is provisioned through the checked-in Wrangler `new_sqlite_classes` migration. Schema versioning runs synchronously in the object constructor, inside `transactionSync`. Future schema upgrades should add a new version step; do not edit a deployed version in place. No separate D1 resource exists.

WebAuthn verification may await cryptographic operations, so requests can interleave. The implementation consumes challenges with a single `DELETE ... RETURNING`, checks invitation validity again when inserting the user, and commits enrollment writes in a synchronous storage transaction. Registration's user handle is the stored account ID. Login checks that the account remains active, and existing sessions also check active status.

Production RP ID and origin are `vpn.zellen.me` and `https://vpn.zellen.me`. Local development uses `localhost` and `http://localhost:8787`, with a separate Worker namespace. Credentials are scoped to their RP and need separate local and production enrollment.

Future milestones retain the agreed invite-only membership model: Sign in with Apple linking from authenticated sessions, Resend invitations/recovery with explicit recovery policy, then secure OIDC federation to Cloudflare Access. Apple email alone must never auto-authorize family membership.

Local Pi-hole overrides, DSM reverse proxy access and existing `cloudflared` routes remain as configured. Traditional network VPN access stays with UniFi Teleport. This Worker is a family identity service, not a VPN tunnel server.
