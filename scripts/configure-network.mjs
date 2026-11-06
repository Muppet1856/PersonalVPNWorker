import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { createHash } from 'node:crypto';
import { cloudflareAPI } from './cloudflare-api.mjs';
import { networkSettings, networkRules } from './network-config.mjs';
import { assertApplicationBoundary } from './access-boundaries.mjs';
import { prepareBundleRoot, writeConnectorBundle } from './connector-bundle.mjs';

function contains(actual, expected) {
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((v, i) => contains(actual[i], v));
  if (expected && typeof expected === 'object') return actual && Object.entries(expected).every(([k, v]) => contains(actual[k], v));
  return actual === expected;
}
function checkDNS(records, app, tunnel, owner) {
  if (!records.length) return;
  const record = records[0];
  if (records.length !== 1 || record.type !== 'CNAME' || record.name !== app.domain || !tunnel
    || record.content !== `${tunnel.id}.cfargotunnel.com` || record.comment !== `${owner}:${app.domain}`) {
    throw Error(`DNS conflict for ${app.domain}; existing records will not be adopted or overwritten`);
  }
}
function mergeIngress(current, targets, team) {
  const ingress = current?.ingress ?? [], retained = [];
  const names = new Set(targets.map(t => t.app.domain)), seen = new Set();
  for (const rule of ingress) {
    if (!rule.hostname) {
      if (rule.path || rule.service !== 'http_status:404') throw Error('Tunnel has an unmanaged catch-all route');
      continue;
    }
    if (rule.hostname.includes('*')) throw Error('Tunnel has wildcard routes; review them before automated configuration');
    if (!names.has(rule.hostname)) { retained.push(rule); continue; }
    const target = targets.find(t => t.app.domain === rule.hostname);
    if (seen.has(rule.hostname) || rule.path || rule.originRequest?.access?.required !== true
      || rule.originRequest.access.teamName !== team || !isDeepStrictEqual(rule.originRequest.access.audTag, [target.access.aud])) throw Error(`Tunnel route conflict for ${rule.hostname}`);
    seen.add(rule.hostname);
  }
  return { ...current, ingress: [...retained, ...targets.map(({ app, access }) => ({ hostname: app.domain, service: app.service, originRequest: { ...app.originRequest, access: { required: true, teamName: team, audTag: [access.aud] } } })), { service: 'http_status:404' }] };
}
export async function configureNetwork(env, raw, { apply = false, inspect = false, fetcher = fetch, log = console.log, bundleRoot = '.cloudflared-install', bundleWriter = writeConnectorBundle } = {}) {
  if (apply && inspect) throw Error('Choose either --inspect or --apply');
  const settings = networkSettings(env, raw);
  const plan = { tunnel: { name: settings.tunnelName }, applications: settings.applications.map(app => ({ domain: app.domain, zone_id: app.zone_id, service: app.service, access_jwt_required: true, dns: { type: 'CNAME', proxied: true }, rules: networkRules(settings, app) })) };
  if (!apply && !inspect) { log(JSON.stringify(plan, null, 2)); return plan; }
  if (!/^[a-f0-9]{32}$/.test(env.CLOUDFLARE_ACCOUNT_ID)) throw Error('Set CLOUDFLARE_ACCOUNT_ID to the target account ID');
  const api = cloudflareAPI(env.CLOUDFLARE_NETWORK_API_TOKEN, fetcher), account = `/accounts/${env.CLOUDFLARE_ACCOUNT_ID}`;
  const accessAPI = env.CLOUDFLARE_ACCESS_API_TOKEN ? cloudflareAPI(env.CLOUDFLARE_ACCESS_API_TOKEN, fetcher) : api;
  async function verifyAccess() {
    const org = (await accessAPI.request(`${account}/access/organizations`)).result;
    if (org.auth_domain !== settings.team) throw Error('Access team does not match the account');
    const idps = await accessAPI.list(`${account}/access/identity_providers`);
    const idpMatches = idps.filter(p => p.name === `${settings.clientID} (PersonalVPNWorker)` && p.type === 'oidc' && p.config?.client_id === settings.clientID && p.config?.auth_url === env.PUBLIC_ORIGIN + '/oidc/authorize' && p.config?.token_url === env.PUBLIC_ORIGIN + '/oidc/token' && p.config?.certs_url === env.PUBLIC_ORIGIN + '/oidc/jwks' && p.config?.claims?.includes('allowed_apps'));
    if (idpMatches.length !== 1) throw Error('Configure the managed Access identity provider and allowed_apps claim first');
    const idp = idpMatches[0], apps = await accessAPI.list(`${account}/access/apps`), verified = new Map();
    for (const target of settings.applications) {
      const matches = apps.filter(a => a.domain === target.domain);
      if (matches.length !== 1) throw Error(`Configure Access for ${target.domain} before publishing its route`);
      const app = (await accessAPI.request(`${account}/access/apps/${matches[0].id}`)).result;
      assertApplicationBoundary(apps, target.domain, app);
      if (app.type !== 'self_hosted' || app.domain !== target.domain || !isDeepStrictEqual(app.allowed_idps, [idp.id]) || !/^[a-f0-9]{64}$/i.test(app.aud || '')) throw Error(`Access configuration is not ready for ${target.domain}`);
      const policies = await accessAPI.list(`${account}/access/apps/${app.id}/policies`);
      if (policies.length !== 1) throw Error(`Access policy conflict for ${target.domain}`);
      const policy = (await accessAPI.request(`${account}/access/policies/${policies[0].id}`)).result;
      if (policy.reusable !== true || policy.app_count !== 1 || policy.decision !== 'allow'
        || !isDeepStrictEqual(policy.include, [{ login_method: { id: idp.id } }])
        || !policy.require?.some(r => isDeepStrictEqual(r, { oidc: { claim_name: 'allowed_apps', claim_value: target.domain, identity_provider_id: idp.id } }))
        || policy.policy_resolution_account_id) throw Error(`Access membership policy is not enforced for ${target.domain}; run Access provisioning first`);
      verified.set(target.domain, app);
    }
    return verified;
  }
  const access = await verifyAccess();
  const tunnels = (await api.list(`${account}/cfd_tunnel`, { name: settings.tunnelName, is_deleted: 'false' })).filter(t => t.name === settings.tunnelName && !t.deleted_at);
  if (tunnels.length > 1 || (tunnels[0] && tunnels[0].config_src !== 'cloudflare')) throw Error('Tunnel ownership/configuration conflict');
  let tunnel = tunnels[0];
  const current = tunnel ? (await api.request(`${account}/cfd_tunnel/${tunnel.id}/configurations`, { allow404: true }))?.result?.config ?? {} : {};
  const zones = new Map(), phaseStates = new Map(), targets = [];
  for (const [index, app] of settings.applications.entries()) {
    if (!zones.has(app.zone_id)) {
      const zone = (await api.request(`/zones/${app.zone_id}`)).result;
      if (zone.account?.id !== env.CLOUDFLARE_ACCOUNT_ID || zone.status !== 'active' || zone.type !== 'full') throw Error('Network provisioning requires an active full DNS zone in the selected account');
      const rulesets = await api.list(`/zones/${app.zone_id}/rulesets`, {}, true);
      zones.set(app.zone_id, { zone, rulesets });
    }
    const { zone, rulesets } = zones.get(app.zone_id);
    const prefix = app.domain.endsWith('.' + zone.name) ? app.domain.slice(0, -(zone.name.length + 1)) : '';
    if (!prefix || prefix.includes('.')) throw Error(`${app.domain} must be a single-level subdomain of ${zone.name}; deeper names require separate certificate setup`);
    const records = await api.list(`/zones/${app.zone_id}/dns_records`, { name: app.domain });
    checkDNS(records, app, tunnel, settings.owner);
    const rules = networkRules(settings, app);
    for (const desired of rules) {
      const key = `${app.zone_id}:${desired.phase}`;
      if (!phaseStates.has(key)) {
        const response = await api.request(`/zones/${app.zone_id}/rulesets/phases/${desired.phase}/entrypoint`, { allow404: true });
        const state = response?.result ?? null;
        if (state && (state.kind !== 'zone' || state.phase !== desired.phase || !Array.isArray(state.rules))) throw Error('Unexpected phase entry point');
        phaseStates.set(key, state);
      }
      const state = phaseStates.get(key), matches = (state?.rules || []).filter(r => r.ref === desired.rule.ref);
      if (matches.length > 1 || (matches[0] && matches[0].description !== desired.rule.description)) throw Error(`WAF/cache rule ownership conflict for ${app.domain}`);
      if (desired.rule.action === 'execute') {
        if (!rulesets.some(r => r.id === desired.rule.action_parameters.id && r.kind === 'managed' && r.phase === desired.phase)) throw Error(`Managed ruleset is not available in the zone for ${app.domain}`);
        if ((state?.rules || []).some(r => r.ref !== desired.rule.ref && r.action === 'execute' && r.action_parameters?.id === desired.rule.action_parameters.id)) throw Error(`Requested managed ruleset is already deployed by another rule for ${app.domain}; review it before adding another execution`);
      }
    }
    const entry = plan.applications[index];
    Object.assign(entry, { access_application_id: access.get(app.domain).id, audience: access.get(app.domain).aud, dns_action: records.length ? 'update_managed_record' : 'create', available_managed_rulesets: rulesets.filter(r => r.kind === 'managed').map(r => ({ id: r.id, name: r.name })) });
    targets.push({ app, access: access.get(app.domain), rules, records });
  }
  const config = mergeIngress(current, targets, settings.team.split('.')[0]);
  Object.assign(plan.tunnel, { action: tunnel ? 'update' : 'create', ...(tunnel ? { id: tunnel.id, status: tunnel.status } : {}) });
  if (inspect) { log(JSON.stringify(plan, null, 2)); return plan; }
  if (bundleWriter === writeConnectorBundle) bundleRoot = prepareBundleRoot(bundleRoot);

  // All requested security rules must succeed before routing/DNS publication.
  for (const { app, rules } of targets) {
    for (const { phase, rule } of rules) {
      const key = `${app.zone_id}:${phase}`;
      let state = phaseStates.get(key);
      if (!state) {
        state = (await api.request(`/zones/${app.zone_id}/rulesets`, { method: 'POST', body: { name: `${settings.owner}:${phase}`, kind: 'zone', phase, rules: [rule] } })).result;
      } else {
        const existing = state.rules.find(r => r.ref === rule.ref);
        const position = phase === 'http_request_cache_settings' ? { after: '' } : { before: '' };
        state = (await api.request(`/zones/${app.zone_id}/rulesets/${state.id}/rules${existing ? '/' + existing.id : ''}`, { method: existing ? 'PATCH' : 'POST', body: { ...rule, position } })).result;
      }
      // Rule mutation responses contain the updated ruleset, not just the rule.
      const verified = (await api.request(`/zones/${app.zone_id}/rulesets/phases/${phase}/entrypoint`)).result;
      const matches = verified.rules.filter(r => r.ref === rule.ref);
      if (matches.length !== 1 || !contains(matches[0], rule)) throw Error(`Security rule verification failed for ${app.domain}`);
      if (phase === 'http_request_cache_settings' && verified.rules.at(-1).ref !== rule.ref) throw Error(`Cache bypass is not the last rule for ${app.domain}`);
      phaseStates.set(key, verified);
    }
  }
  const rechecked = await verifyAccess();
  for (const target of targets) if (rechecked.get(target.app.domain).aud !== target.access.aud) throw Error('Access audience changed during provisioning; inspect and retry');
  if (!tunnel) {
    tunnel = (await api.request(`${account}/cfd_tunnel`, { method: 'POST', body: { name: settings.tunnelName, config_src: 'cloudflare' } })).result;
    if (!tunnel?.id || tunnel.config_src !== 'cloudflare') throw Error('Cloudflare did not return the intended remotely managed tunnel');
  } else {
    const latest = (await api.request(`${account}/cfd_tunnel/${tunnel.id}/configurations`, { allow404: true }))?.result?.config ?? {};
    if (!isDeepStrictEqual(latest, current)) throw Error('Tunnel configuration changed during provisioning; inspect and retry');
  }
  await api.request(`${account}/cfd_tunnel/${tunnel.id}/configurations`, { method: 'PUT', body: { config } });
  const verifiedConfig = (await api.request(`${account}/cfd_tunnel/${tunnel.id}/configurations`)).result?.config;
  if (!contains(verifiedConfig, config)) throw Error('Tunnel configuration verification failed; DNS was not published');
  for (const { app } of targets) {
    const records = await api.list(`/zones/${app.zone_id}/dns_records`, { name: app.domain });
    checkDNS(records, app, tunnel, settings.owner);
    const body = { type: 'CNAME', name: app.domain, content: `${tunnel.id}.cfargotunnel.com`, proxied: true, ttl: 1, comment: `${settings.owner}:${app.domain}` };
    await api.request(`/zones/${app.zone_id}/dns_records${records[0] ? '/' + records[0].id : ''}`, { method: records[0] ? 'PATCH' : 'POST', body });
    const verified = await api.list(`/zones/${app.zone_id}/dns_records`, { name: app.domain });
    if (verified.length !== 1 || !contains(verified[0], body)) throw Error(`DNS verification failed for ${app.domain}`);
    log(`Verified Access-protected tunnel route, security rules, and proxied DNS for ${app.domain}.`);
  }
  const token = (await api.request(`${account}/cfd_tunnel/${tunnel.id}/token`)).result;
  // Two accounts/devices may use the same friendly name. Bind the local service
  // name to the actual tunnel so installing one cannot replace the other.
  const connectorName = settings.deviceName.slice(0, 31) + '-' + createHash('sha256').update(tunnel.id).digest('hex').slice(0, 8);
  const directory = bundleWriter(bundleRoot, connectorName, token);
  plan.tunnel.id = tunnel.id; plan.connector_bundle = directory;
  plan.connector_service = `cloudflared-personalvpn-${connectorName}.service`;
  log(`Private connector installation bundle: ${directory}`);
  log(`Connector service: ${plan.connector_service}`);
  log('Account configuration verified. Install the bundle on the intended Linux host, then test origin reachability, tunnel health, and allowed/denied access.');
  return plan;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    if (args.some(a => !['--apply', '--inspect'].includes(a))) throw Error('Supported options: --inspect or --apply');
    const raw = JSON.parse(readFileSync(process.env.NETWORK_CONFIG_FILE || '.network.deploy.local.json', 'utf8'));
    await configureNetwork(process.env, raw, { apply: args.includes('--apply'), inspect: args.includes('--inspect') });
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
