import { appendFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { accessSettings } from './access-config.mjs';
import { assertApplicationBoundary } from './access-boundaries.mjs';

const policyOptions = ['approval_groups', 'approval_required', 'connection_rules', 'isolation_required', 'mfa_config', 'purpose_justification_prompt', 'purpose_justification_required', 'session_duration'];
function memberRules(idpID, domain, isLauncher) {
  return { decision: 'allow', include: [{ login_method: { id: idpID } }], exclude: [],
    require: isLauncher ? [] : [{ oidc: { claim_name: 'allowed_apps', claim_value: domain, identity_provider_id: idpID } }] };
}
function assertManagedPolicy(policy, target, idpID, legacyName) {
  const rules = memberRules(idpID, target.app.domain, target.isLauncher);
  const legacyRequire = policy.name === legacyName && (policy.require ?? []).length === 0;
  if (!idpID || ![legacyName, target.policyName].includes(policy.name) || policy.decision !== rules.decision
    || !isDeepStrictEqual(policy.include, rules.include) || !isDeepStrictEqual(policy.exclude ?? [], rules.exclude)
    || (!legacyRequire && !isDeepStrictEqual(policy.require ?? [], rules.require)) || policy.policy_resolution_account_id) {
    throw Error(`Policy for ${target.app.domain} conflicts with managed membership rules; review it before automated configuration`);
  }
}
function assertReusable(policy, id, expectedCount, domain) {
  if (policy?.id !== id || policy.reusable !== true) throw Error(`Cloudflare did not confirm a reusable policy for ${domain}`);
  if (policy.app_count !== expectedCount) throw Error(`Policy for ${domain} is shared or has an unexpected attachment count; it will not be changed`);
}
function assertPolicySaved(policy, body, id, count, domain) {
  assertReusable(policy, id, count, domain);
  for (const [key, value] of Object.entries(body)) {
    const actual = ['exclude', 'require'].includes(key) ? policy[key] ?? [] : policy[key];
    if (!isDeepStrictEqual(actual, value)) throw Error(`Cloudflare policy verification failed for ${domain} (${key})`);
  }
}
export async function configureAccess(env, { apply = false, inspect = false, fetcher = fetch, log = console.log } = {}) {
  if (apply && inspect) throw Error('Choose either --inspect or --apply');
  if (!env.PUBLIC_ORIGIN) throw Error('Set PUBLIC_ORIGIN');
  const origin = new URL(env.PUBLIC_ORIGIN);
  if (origin.protocol !== 'https:' || origin.origin !== env.PUBLIC_ORIGIN) throw Error('PUBLIC_ORIGIN must be a canonical HTTPS origin');
  const { team, clientID, apps, launcher } = accessSettings(env);
  const targetApps = launcher ? [...apps, launcher] : apps;
  if (!team) throw Error('Set ACCESS_TEAM_DOMAIN to your existing Zero Trust team hostname');
  const managedName = `${clientID} (PersonalVPNWorker)`, legacyName = `${clientID}: Members`;
  const plan = {
    identity_provider: { name: managedName, type: 'oidc', client_id: clientID, auth_url: origin.origin + '/oidc/authorize', token_url: origin.origin + '/oidc/token', certs_url: origin.origin + '/oidc/jwks', pkce_enabled: true, claims: ['allowed_apps'] },
    callback: `https://${team}/cdn-cgi/access/callback`,
    applications: targetApps.map(app => ({ name: `${clientID}: ${app.name}`, domain: app.domain,
      policy: launcher && app.domain === launcher.domain ? 'Allow active invited members to the launcher' : `Require allowed_apps claim to contain ${app.domain}`,
      policy_name: `${clientID}: Members: ${app.domain}`, policy_type: 'reusable' })),
  };
  if (!apply && !inspect) { log(JSON.stringify(plan, null, 2)); return plan; }
  if (!env.CLOUDFLARE_ACCESS_API_TOKEN || !env.CLOUDFLARE_ACCOUNT_ID) throw Error('Set CLOUDFLARE_ACCESS_API_TOKEN and CLOUDFLARE_ACCOUNT_ID');
  if (apply && (!env.OIDC_CLIENT_SECRET || env.OIDC_CLIENT_SECRET.length < 32)) throw Error('Set OIDC_CLIENT_SECRET to at least 32 random characters');
  const root = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CLOUDFLARE_ACCOUNT_ID)}/access`;
  async function api(path, method = 'GET', body) {
    const response = await fetcher(root + path, { method, headers: { authorization: 'Bearer ' + env.CLOUDFLARE_ACCESS_API_TOKEN, 'content-type': 'application/json' }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(30000) });
    const data = await response.json();
    if (!response.ok || data.success === false) throw Error(`Cloudflare Access ${method} ${path} failed (HTTP ${response.status}; codes ${(data.errors || []).map(x => x.code).join(',')}). Check token permissions and the existing configuration.`);
    return data;
  }
  async function list(path) {
    const result = [];
    for (let page = 1; page <= 100; page++) {
      const data = await api(path + `?per_page=100&page=${page}`);
      if (!Array.isArray(data.result)) throw Error('Unexpected Cloudflare list response');
      result.push(...data.result);
      const total = data.result_info?.total_pages;
      if (total !== undefined && (!Number.isInteger(total) || total < 0)) throw Error('Unexpected Cloudflare pagination');
      if (total !== undefined ? page >= total : data.result.length < 100) return result;
    }
    throw Error('Cloudflare result pagination exceeded supported size');
  }
  // Check every target before any writes. The reusable collection also detects
  // policies left unattached by an interrupted previous deployment.
  const org = (await api('/organizations')).result;
  if (org.auth_domain !== team) throw Error('ACCESS_TEAM_DOMAIN does not match this account’s existing Zero Trust organization');
  const idps = await list('/identity_providers'), existingApps = await list('/apps'), reusablePolicies = await list('/policies');
  const matches = idps.filter(x => x.name === managedName);
  if (matches.length > 1) throw Error('Multiple managed identity providers found');
  const existingIDP = matches[0];
  if (existingIDP && (existingIDP.type !== 'oidc' || existingIDP.config?.client_id !== clientID || existingIDP.config?.auth_url !== plan.identity_provider.auth_url || existingIDP.config?.token_url !== plan.identity_provider.token_url || existingIDP.config?.certs_url !== plan.identity_provider.certs_url)) throw Error('Existing identity provider conflicts with managed configuration');
  const targets = [], selectedPolicies = new Set();
  for (const [index, app] of targetApps.entries()) {
    const entry = plan.applications[index], matches = existingApps.filter(x => x.domain === app.domain);
    if (matches.length > 1) throw Error(`Multiple Access applications already protect ${app.domain}`);
    const existing = matches[0];
    if (existing && (existing.name !== entry.name || existing.type !== 'self_hosted')) throw Error(`Existing Access application for ${app.domain} is not managed by this project; it will not be changed`);
    assertApplicationBoundary(existingApps, app.domain, existing);
    const attached = existing ? await list(`/apps/${existing.id}/policies`) : [];
    if (attached.length > 1 || attached.some(x => ![legacyName, entry.policy_name].includes(x.name))) throw Error(`Unmanaged policies exist for ${app.domain}; review them before automated configuration`);
    const named = reusablePolicies.filter(x => x.name === entry.policy_name);
    if (named.length > 1 || (attached[0] && named[0] && attached[0].id !== named[0].id)) throw Error(`Conflicting reusable policies exist for ${app.domain}`);
    let policy = attached[0] || named[0], migrate = false;
    const target = { app, entry, existing, policyName: entry.policy_name, isLauncher: app.domain === launcher?.domain, attached: attached.length > 0 };
    if (policy) {
      if (typeof policy.id !== 'string' || !policy.id || selectedPolicies.has(policy.id)) throw Error(`Invalid or shared policy for ${app.domain}`);
      selectedPolicies.add(policy.id);
      // App-policy responses may omit reusable; the full collection is authoritative.
      if (reusablePolicies.some(x => x.id === policy.id)) {
        policy = (await api(`/policies/${policy.id}`)).result;
        assertReusable(policy, attached[0]?.id || named[0].id, target.attached ? 1 : 0, app.domain);
      } else {
        if (!target.attached || policy.reusable === true || policy.name !== legacyName) throw Error(`Unrecognized policy type for ${app.domain}`);
        migrate = true;
      }
      assertManagedPolicy(policy, target, existingIDP?.id, legacyName);
    }
    Object.assign(entry, { application_action: existing ? 'update' : 'create', policy_action: migrate ? 'convert_to_reusable' : policy ? 'update_reusable' : 'create_reusable', ...(existing ? { application_id: existing.id, audience: existing.aud } : {}), ...(policy ? { policy_id: policy.id } : {}) });
    targets.push({ ...target, policy, migrate });
  }
  if (inspect) { log(JSON.stringify(plan, null, 2)); return plan; }
  const idpBody = { name: managedName, type: 'oidc', config: { client_id: clientID, client_secret: env.OIDC_CLIENT_SECRET, auth_url: plan.identity_provider.auth_url, token_url: plan.identity_provider.token_url, certs_url: plan.identity_provider.certs_url, pkce_enabled: true, claims: ['allowed_apps'], email_claim_name: 'email', scopes: ['openid', 'email', 'profile'] } };
  const idp = (await api(existingIDP ? `/identity_providers/${existingIDP.id}` : '/identity_providers', existingIDP ? 'PUT' : 'POST', idpBody)).result;
  if (!idp?.id) throw Error('Cloudflare did not return an identity provider ID');
  log('Configured managed OIDC identity provider.');
  for (const target of targets) {
    const { app, entry, existing, policyName, isLauncher, attached, migrate } = target;
    let policy = target.policy;
    if (migrate) {
      // Preserve the ID and attachment; never delete/detach to migrate.
      await api(`/apps/${existing.id}/policies/${policy.id}/make_reusable`, 'PUT');
      const converted = (await api(`/policies/${policy.id}`)).result;
      assertReusable(converted, policy.id, 1, app.domain);
      assertManagedPolicy(converted, target, idp.id, legacyName);
      policy = converted;
    }
    const preserved = Object.fromEntries(policyOptions.filter(key => policy?.[key] !== undefined).map(key => [key, policy[key]]));
    const policyBody = { name: policyName, ...memberRules(idp.id, app.domain, isLauncher), session_duration: existing?.session_duration || '24h', ...preserved };
    const savedPolicy = (await api(policy ? `/policies/${policy.id}` : '/policies', policy ? 'PUT' : 'POST', policyBody)).result;
    if (!savedPolicy?.id || (policy && savedPolicy.id !== policy.id)) throw Error('Cloudflare did not return the expected policy ID');
    assertPolicySaved((await api(`/policies/${savedPolicy.id}`)).result, policyBody, savedPolicy.id, attached ? 1 : 0, app.domain);
    const body = { name: entry.name, type: 'self_hosted', domain: app.domain, session_duration: existing?.session_duration || '24h', allowed_idps: [idp.id], auto_redirect_to_identity: true, app_launcher_visible: true,
      // Reusable references only, never inline policy definitions.
      policies: [{ id: savedPolicy.id, precedence: 1 }] };
    const saved = (await api(existing ? `/apps/${existing.id}` : '/apps', existing ? 'PUT' : 'POST', body)).result;
    if (!saved?.id || (existing && saved.id !== existing.id)) throw Error('Cloudflare did not return the expected application ID');
    const verifiedApp = (await api(`/apps/${saved.id}`)).result, verifiedAttachments = await list(`/apps/${saved.id}/policies`);
    if (verifiedApp?.id !== saved.id || verifiedApp.domain !== app.domain || verifiedApp.type !== 'self_hosted' || !isDeepStrictEqual(verifiedApp.allowed_idps, [idp.id]) || verifiedAttachments.length !== 1 || verifiedAttachments[0].id !== savedPolicy.id) throw Error(`Cloudflare application/policy attachment verification failed for ${app.domain}`);
    assertPolicySaved((await api(`/policies/${savedPolicy.id}`)).result, policyBody, savedPolicy.id, 1, app.domain);
    if (typeof verifiedApp.aud !== 'string' || !/^[a-f0-9]{64}$/i.test(verifiedApp.aud)) throw Error(`Cloudflare did not return a valid audience for ${app.domain}`);
    Object.assign(entry, { application_id: saved.id, policy_id: savedPolicy.id, audience: verifiedApp.aud });
    if (isLauncher) plan.launcher_access_aud = verifiedApp.aud;
    log(`Verified reusable Access policy for ${app.domain} (AUD: ${verifiedApp.aud}).`);
  }
  log('Access setup complete. Omitted applications and unrelated account settings were not changed.');
  return plan;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = process.argv.slice(2);
    if (args.some(arg => !['--apply', '--inspect'].includes(arg))) throw Error('Supported options: --inspect or --apply');
    const plan = await configureAccess(process.env, { apply: args.includes('--apply'), inspect: args.includes('--inspect') });
    if (plan.launcher_access_aud && process.env.GITHUB_OUTPUT) appendFileSync(process.env.GITHUB_OUTPUT, `launcher_access_aud=${plan.launcher_access_aud}\n`);
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
