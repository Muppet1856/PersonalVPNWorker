# Automated Access, Tunnel, DNS, and WAF setup

Use this operator workflow to expose a selected private HTTP(S) network service to authenticated, authorized users. The user connects to its public hostname; Access verifies identity and the service grant before Tunnel forwards the request to the configured private origin and port. The Worker provides identity and grants; the CLI scripts configure the protected route and generate the connector installer. Network provisioning is opt-in and is not run by the ordinary Worker deployment workflow.

Success means an authorized user can reach the selected service, while an unauthenticated user or a user without its grant cannot reach it through the published endpoint. The origin's listening interface/firewall must also prevent unintended direct access. WAF supplements Access for HTTP traffic. General SSH/TCP/UDP exposure requires the corresponding client/protocol workflow described in the [device runbook](device-access-tunnel.md).

The [device runbook](device-access-tunnel.md) explains the traffic flow, VPN boundary, origin firewall, and acceptance tests. The commands here implement its Cloudflare-side setup. They do not require users to join the existing VPN, change the device's VPN routes/firewall, or prove the origin is reachable.

## What is automated

| Resource | Behavior |
| --- | --- |
| Access policies | Create one reusable policy per app; convert owned legacy policies in place and preserve their IDs/attachments |
| Access enforcement | Require the managed IdP and the app's `allowed_apps` claim; keep the launcher policy separate |
| Tunnel | Create/reuse a remotely managed tunnel named `PersonalVPNWorker:<client-id>:<tunnel-name>` |
| Published routes | Configure the exact service URL, verified origin TLS, and mandatory Access JWT checks with the application's current audience |
| DNS | Create/update a proxied CNAME to the tunnel; refuse existing records not owned by this workflow |
| WAF | Add a hostname-scoped rule blocking plaintext HTTP and configured sensitive paths; optionally deploy selected managed rulesets and path-specific rate limits |
| Cache | Put a hostname-scoped cache-bypass rule after existing cache rules |
| Connector | Generate a private token file, systemd unit, and Debian/Ubuntu/Raspberry Pi OS installer |

WAF uses individual rule create/update endpoints, preserving unrelated rules. Tunnel updates preserve unrelated exact-host routes and keep a final `http_status:404` catch-all. Wildcard routes, conflicting DNS, public Access overrides, overlapping Access applications, and shared/missing membership policies stop provisioning. Existing resources are identified by exact managed names, rule references, and DNS comments; arbitrary dashboard resources are not adopted.

## 1. Configure the intended application

Start with the existing `.env.deploy.local` configuration and copy the network template:

```sh
cp .network.deploy.example.json .network.deploy.local.json
```

Edit `.network.deploy.local.json`. Supply the real zone ID, exact public hostname, and service URL. The hostname must also appear in `ACCESS_APPS_JSON`. For example:

```json
{
  "tunnel_name": "home-device",
  "applications": [
    {
      "domain": "device.example.com",
      "zone_id": "YOUR_32_CHARACTER_ZONE_ID",
      "service": "http://127.0.0.1:8080",
      "waf": {
        "blocked_paths": ["/.env", "/.git"],
        "managed_ruleset_ids": [],
        "rate_limit": {
          "paths": ["/api/login"],
          "requests_per_period": 20,
          "period": 10,
          "mitigation_timeout": 10
        }
      }
    }
  ]
}
```

Those rate limits are illustrative: choose the real application paths and thresholds, and remove `rate_limit` if you do not want it. Paths match the exact path and its children; `/` explicitly matches all paths. A path that does not exist in your application provides no useful login-rate protection. Plan entitlements determine which rates, periods, and managed rulesets Cloudflare accepts. An API rejection stops the run before new routes/DNS are published; the script does not silently omit requested controls. See [rate-limiting API parameters](https://developers.cloudflare.com/waf/rate-limiting-rules/create-api/).

With `managed_ruleset_ids: []`, no new managed ruleset execution is added; existing zone protections remain. `network:inspect` lists available managed ruleset IDs/names. Add the desired IDs after checking the zone's plan and existing rules. If another rule already executes a requested ruleset, the script asks for reconciliation instead of deploying it twice. See [managed WAF deployment](https://developers.cloudflare.com/waf/managed-rules/reference/cloudflare-managed-ruleset/).

This workflow supports active **full DNS zones**, single-level subdomains, and HTTP(S) services. Loopback HTTP is allowed. Other origins require HTTPS; optional `origin_server_name`, `http_host_header`, and `ca_pool` configure origin trust/routing. `ca_pool` must point to a certificate file under `/etc` readable by the connector on the target device. Certificate installation is device-specific. TLS verification cannot be disabled through this configuration.

Use one stable tunnel name per intended connector deployment. Renaming it creates a different tunnel rather than renaming the existing one. Run different device configurations separately; set `NETWORK_CONFIG_FILE` to select a different configuration file. Omitted applications/routes/rules are retained, not automatically deleted.

## 2. Supply credentials privately

The scripts read credentials from the process environment or the ignored `.env.deploy.local`. Use a secret manager or private environment injection; never put real credentials into checked-in examples or paste them into shared command history.

| Credential | Purpose |
| --- | --- |
| `CLOUDFLARE_ACCOUNT_ID` | Account owning Access, the tunnel, and the configured zones |
| `CLOUDFLARE_ACCESS_API_TOKEN` | Existing Access provisioning token; read-only permission suffices for inspection |
| `OIDC_CLIENT_SECRET` | Required only to apply Access provisioning; must match the deployed Worker |
| `CLOUDFLARE_NETWORK_API_TOKEN` | Separate operator token for Tunnel, DNS, and security/cache rules |

Scope the network token to the target account and zones: Tunnel edit; Zone read; DNS edit; WAF edit; and Cache Rules edit. It also needs Access application/policy, identity-provider, and organization read access **unless** `CLOUDFLARE_ACCESS_API_TOKEN` is supplied separately for those reads. Use the [Tunnel API](https://developers.cloudflare.com/api/resources/zero_trust/subresources/tunnels/subresources/cloudflared/methods/create/), [WAF rules API](https://developers.cloudflare.com/waf/custom-rules/create-api/), and [Cache Rules API](https://developers.cloudflare.com/cache/how-to/cache-rules/create-api/) permission guidance when creating the scoped token. Neither operator API token is deployed to the Worker or copied to the device; the device receives only its tunnel's connector token.

## 3. Review and apply Access

```sh
npm run access:plan
npm run access:inspect
npm run access:apply
```

`plan` is offline. `inspect` makes GET requests only and reports existing IDs, audiences, and the planned migration/create/update actions. `apply` repeats the ownership checks, performs the changes, and verifies the saved policy and application attachment. See [Access setup](access-setup.md) for migration behavior and GitHub deployment integration.

For a newly added application, also deploy the updated application list through the existing Worker deployment workflow and grant the intended family users access in the administration console. Network provisioning verifies the policy configuration, not whether a particular user has been granted access. New family accounts/apps default to no grant.

## 4. Review and apply the network setup

```sh
npm run network:plan
npm run network:inspect
npm run network:apply
```

The default plan makes no network requests. Inspection checks the live account, exact Access policy, zone ownership, DNS conflicts, tunnel configuration, and security rule ownership. It does not fetch connector credentials. During apply, the sequence is:

1. Complete those checks for every configured application.
2. Install and read back all requested WAF/rate-limit/cache rules.
3. Recheck Access and its audiences.
4. Create/reuse the tunnel; configure and read back routes with JWT validation.
5. Publish and read back proxied DNS records.
6. Retrieve the connector token into a private installation bundle.

The bundle path is printed, but token values and API response bodies are not. WAF changes use individual [rule mutations](https://developers.cloudflare.com/ruleset-engine/rulesets-api/update-rule/), rather than replacing a whole zone ruleset. DNS uses the documented [tunnel CNAME target](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/routing-to-tunnel/dns/).

Cloudflare does not provide a transaction spanning these services. If a run fails, earlier successful changes can remain; correct the reported problem, inspect, and rerun. Deterministic rule references, policy names, tunnel names, and DNS comments let a retry reuse them. Run only one provisioning process at a time and avoid concurrent dashboard edits. Existing zone/account Skip or Allow rules can affect enforcement: retain the external WAF/Access acceptance tests in the device runbook.

## 5. Install the generated connector bundle

`network:apply` creates a uniquely named subdirectory inside `.cloudflared-install/` with mode `0700`. Its token is mode `0600`; this entire directory is ignored by Git. The generated systemd service uses `LoadCredential` and `--token-file` so the token is not embedded in the unit or command-line arguments. See [cloudflared token-file support](https://developers.cloudflare.com/tunnel/reference/run-parameters/).

Transfer the printed bundle directory privately to the intended Linux device using your existing SSH configuration/identity. Set the remote bundle directory to `0700` and token to `0600` if your transfer method does not preserve modes. On that device, from inside the transferred bundle, run:

```sh
sudo bash ./install.sh
```

The installer requires systemd 247+ and a Debian-based OS. It installs `cloudflared` from the official stable package repository, requires cloudflared 2025.4.0+, installs the token under `/etc/cloudflared-personalvpn/`, and enables a dedicated `cloudflared-personalvpn-<device-name>-<tunnel-suffix>.service`. The exact service name is printed; the suffix separates tunnels that share a friendly name. It refuses to replace an unmarked service. The standard `cloudflared.service` is not replaced. It does not change the host firewall, application bind address, VPN routes, or existing VPN service.

After installation, confirm the intended tunnel is healthy and perform the runbook's external allowed/denied, direct-origin, WAF, reboot, and VPN-disconnect tests. `systemctl is-active` alone does not prove that the connector can reach Cloudflare or the origin. Keep bundles only in protected storage, or remove the transferred/local copies after installation; the host retains its protected credential. Rotate the tunnel token if a bundle is exposed.

For rollback, remove this hostname's tunnel route before removing DNS or Access protection. Do not stop a shared connector to remove a single app. The scripts intentionally do not delete resources omitted from configuration; decommission them through the reviewed device-runbook procedure.
