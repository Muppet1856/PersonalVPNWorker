import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, statSync, chmodSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { configureNetwork } from '../scripts/configure-network.mjs';
import { networkSettings } from '../scripts/network-config.mjs';
import { prepareBundleRoot, writeConnectorBundle } from '../scripts/connector-bundle.mjs';
const accountID = 'a'.repeat(32), zoneID = 'b'.repeat(32), aud = 'c'.repeat(64), managedID = 'd'.repeat(32);
const env = { PUBLIC_ORIGIN: 'https://vpn.example.com', ACCESS_TEAM_DOMAIN: 'example.cloudflareaccess.com', CLOUDFLARE_ACCOUNT_ID: accountID, CLOUDFLARE_NETWORK_API_TOKEN: 'private-api-token', ACCESS_APPS_JSON: '[{"name":"Device","domain":"device.example.com"}]' };
const config = { tunnel_name: 'home-device', applications: [{ domain: 'device.example.com', zone_id: zoneID, service: 'http://127.0.0.1:8080', waf: { blocked_paths: ['/.env', '/.git'], managed_ruleset_ids: [managedID], rate_limit: { paths: ['/api/login'], requests_per_period: 20, period: 10, mitigation_timeout: 10 } } }] };
const clone = value => structuredClone(value);
function mock() {
  const state = { calls: [], tunnels: [], config: {}, dns: [], phases: {}, fail: null, corrupt: null,
    apps: [{ id: 'app-1', type: 'self_hosted', domain: 'device.example.com', allowed_idps: ['idp-1'], aud }],
    policy: { id: 'policy-1', reusable: true, app_count: 1, decision: 'allow', include: [{ login_method: { id: 'idp-1' } }], require: [{ oidc: { claim_name: 'allowed_apps', claim_value: 'device.example.com', identity_provider_id: 'idp-1' } }] },
  };
  const reply = (result, status = 200) => Response.json({ success: status < 400, result, errors: status >= 400 ? [{ code: 1000 }] : [], result_info: { total_pages: 1 } }, { status });
  return { state, async fetcher(url, init) {
    const parsed = new URL(url), path = parsed.pathname.replace('/client/v4', ''), method = init.method, body = init.body ? JSON.parse(init.body) : undefined;
    const call = { path, method, body }; state.calls.push(call);
    if (state.fail?.(call)) return reply(null, 403);
    let result;
    if (method === 'GET') {
      if (path.endsWith('/access/organizations')) result = { auth_domain: 'example.cloudflareaccess.com' };
      else if (path.endsWith('/access/identity_providers')) result = [{ id: 'idp-1', name: 'family-access (PersonalVPNWorker)', type: 'oidc', config: { client_id: 'family-access', auth_url: env.PUBLIC_ORIGIN + '/oidc/authorize', token_url: env.PUBLIC_ORIGIN + '/oidc/token', certs_url: env.PUBLIC_ORIGIN + '/oidc/jwks', claims: ['allowed_apps'] } }];
      else if (path.endsWith('/access/apps')) result = state.apps;
      else if (path.endsWith('/access/apps/app-1')) result = state.apps[0];
      else if (path.endsWith('/access/apps/app-1/policies')) result = [state.policy];
      else if (path.endsWith('/access/policies/policy-1')) result = state.policy;
      else if (path.endsWith('/cfd_tunnel')) result = state.tunnels;
      else if (path.endsWith('/configurations')) result = { config: state.config };
      else if (path.endsWith('/token')) result = 'private-tunnel-token';
      else if (path === `/zones/${zoneID}`) result = { name: 'example.com', account: { id: accountID }, status: 'active', type: 'full' };
      else if (path.endsWith('/dns_records')) result = state.dns.filter(r => r.name === parsed.searchParams.get('name'));
      else if (path.endsWith('/rulesets')) result = [{ id: managedID, name: 'Available managed ruleset', kind: 'managed', phase: 'http_request_firewall_managed' }];
      else if (path.endsWith('/entrypoint')) { result = state.phases[path.split('/phases/')[1].split('/')[0]]; if (!result) return reply(null, 404); }
      else throw Error('Unexpected GET ' + path);
    } else if (path.endsWith('/rulesets')) {
      result = { id: 'ruleset-' + body.phase, ...body, rules: body.rules.map((r, i) => ({ id: 'rule-' + i, ...r })) }; state.phases[body.phase] = result;
    } else if (path.includes('/rulesets/') && path.includes('/rules')) {
      const setID = path.split('/rulesets/')[1].split('/')[0], ruleset = Object.values(state.phases).find(p => p.id === setID);
      const existing = path.split('/rules/')[1];
      const { position, ...rule } = body;
      const rules = ruleset.rules.filter(r => r.id !== existing), saved = { id: existing || 'rule-' + rules.length, ...rule };
      ruleset.rules = position.after === '' ? [...rules, saved] : [saved, ...rules]; result = ruleset;
    } else if (path.endsWith('/cfd_tunnel')) {
      result = { id: 'tunnel-1', ...body, status: 'inactive' }; state.tunnels.push(result);
    } else if (path.endsWith('/configurations')) {
      state.config = clone(body.config); result = { config: state.config };
    } else if (path.includes('/dns_records')) {
      result = { id: 'dns-1', ...body }; state.dns = [result];
    } else throw Error('Unexpected mutation ' + path);
    state.corrupt?.(call); return reply(result);
  } };
}
const options = m => ({ apply: true, fetcher: m.fetcher, log: () => {}, bundleWriter: (root, name, token) => { assert.equal(token, 'private-tunnel-token'); return '/private/bundle'; } });
test('Network plan is offline, scoped, and includes no credentials', async () => {
  const logs = []; const plan = await configureNetwork(env, config, { log: s => logs.push(s), fetcher: () => { throw Error('No requests expected'); } });
  assert.equal(plan.applications[0].rules.length, 4);
  for (const { rule } of plan.applications[0].rules) assert.ok(rule.expression.startsWith('(http.host eq "device.example.com")'));
  assert.equal(logs.join('').includes(env.CLOUDFLARE_NETWORK_API_TOKEN), false);
});
test('Network config rejects unsafe origins, unknown fields, paths, and unlisted hosts', () => {
  for (const mutate of [
    c => { c.applications[0].service = 'http://192.168.1.44:8080'; },
    c => { c.applications[0].service = 'https://user:password@origin.example.com'; },
    c => { c.applications[0].service = 'ssh://localhost:22'; },
    c => { c.applications[0].noTLSVerify = true; },
    c => { c.applications[0].domain = 'vpn.example.com'; },
    c => { c.applications[0].waf.blocked_paths = ['/foo" or true']; },
    c => { c.applications[0].waf.rate_limit.paths = []; },
    c => { c.tunnel_name = 'x;touch /tmp/unsafe'; },
  ]) { const c = clone(config); mutate(c); assert.throws(() => networkSettings(env, c)); }
});
test('Inspection is read-only and reports live Access audiences', async () => {
  const m = mock(); const plan = await configureNetwork(env, config, { inspect: true, fetcher: m.fetcher, log: () => {} });
  assert.equal(plan.applications[0].audience, aud); assert.equal(plan.tunnel.action, 'create');
  assert.ok(m.state.calls.every(c => c.method === 'GET')); assert.ok(m.state.calls.every(c => !c.path.endsWith('/token')));
});
test('Apply provisions security before routing and DNS, and retries without duplicates', async () => {
  const m = mock(); const logs = []; const plan = await configureNetwork(env, config, { ...options(m), log: s => logs.push(s) });
  assert.match(plan.connector_service, /^cloudflared-personalvpn-home-device-[a-f0-9]{8}\.service$/);
  const mutations = m.state.calls.filter(c => c.method !== 'GET'), dnsAt = mutations.findIndex(c => c.path.includes('/dns_records')), tunnelAt = mutations.findIndex(c => c.path.endsWith('/configurations'));
  assert.ok(dnsAt > tunnelAt); assert.ok(mutations.slice(0, 4).every(c => c.path.includes('/rulesets')));
  assert.deepEqual(m.state.config.ingress[0].originRequest.access, { required: true, teamName: 'example', audTag: [aud] });
  assert.equal(m.state.config.ingress.at(-1).service, 'http_status:404'); assert.equal(m.state.dns[0].proxied, true);
  await configureNetwork(env, config, options(m)); assert.equal(m.state.tunnels.length, 1); assert.equal(m.state.dns.length, 1);
  assert.ok(Object.values(m.state.phases).every(p => p.rules.length === 1));
  assert.equal(logs.join('').includes('private-tunnel-token'), false); assert.equal(logs.join('').includes('private-api-token'), false);
});
test('Unrelated zone rules and tunnel routes survive updates', async () => {
  const m = mock(); await configureNetwork(env, config, options(m));
  const phase = m.state.phases.http_request_cache_settings;
  const unrelatedRule = { id: 'unrelated-rule', ref: 'unrelated', action: 'set_cache_settings', expression: 'true', action_parameters: { cache: true } };
  phase.rules.push(clone(unrelatedRule));
  const unrelatedRoute = { hostname: 'other.example.com', service: 'https://internal.example.com' };
  m.state.config.ingress.unshift(clone(unrelatedRoute));
  await configureNetwork(env, config, options(m));
  assert.deepEqual(phase.rules.find(r => r.ref === 'unrelated'), unrelatedRule);
  assert.deepEqual(m.state.config.ingress[0], unrelatedRoute); assert.equal(phase.rules.at(-1).action_parameters.cache, false);
  assert.ok(m.state.calls.every(c => !(c.method === 'PUT' && c.path.includes('/rulesets'))));
});
test('Missing grants, legacy/shared policies, public overrides and competing Access paths prevent all writes', async () => {
  for (const change of [
    s => { s.policy.require = []; }, s => { s.policy.reusable = false; }, s => { s.policy.app_count = 2; },
    s => { s.policy.include.push({ everyone: {} }); },
    s => { s.apps[0].destinations = [{ type: 'public', uri: 'device.example.com', overrides: [{ behavior: 'public', path_pattern: '/admin/*' }] }]; },
    s => { s.apps.push({ id: 'other-app', domain: 'device.example.com/admin' }); },
  ]) {
    const m = mock(); change(m.state);
    await assert.rejects(configureNetwork(env, config, options(m)), /Access|membership/);
    assert.ok(m.state.calls.every(c => c.method === 'GET'));
  }
});
test('Existing DNS and unprotected tunnel route conflicts prevent all writes', async () => {
  for (const conflict of ['dns', 'route']) {
    const m = mock();
    if (conflict === 'dns') m.state.dns = [{ name: 'device.example.com', type: 'A', content: '192.0.2.1' }];
    else { m.state.tunnels = [{ id: 'tunnel-1', name: 'PersonalVPNWorker:family-access:home-device', config_src: 'cloudflare' }]; m.state.config = { ingress: [{ hostname: 'device.example.com', service: 'http://localhost:1234' }] }; }
    await assert.rejects(configureNetwork(env, config, options(m)), /conflict/); assert.ok(m.state.calls.every(c => c.method === 'GET'));
  }
});
test('WAF failure or tunnel readback failure cannot publish DNS', async () => {
  for (const failure of ['waf', 'tunnel']) {
    const m = mock();
    if (failure === 'waf') m.state.fail = c => c.method !== 'GET' && c.path.includes('/rulesets');
    else m.state.corrupt = c => { if (c.method === 'PUT' && c.path.endsWith('/configurations')) m.state.config.ingress[0].originRequest.access.required = false; };
    await assert.rejects(configureNetwork(env, config, options(m)), /failed/);
    assert.equal(m.state.dns.length, 0); assert.ok(m.state.calls.every(c => !c.path.endsWith('/token')));
  }
});
test('DNS failure can be retried without losing the protected tunnel configuration', async () => {
  const m = mock(); m.state.fail = c => c.method === 'POST' && c.path.endsWith('/dns_records');
  await assert.rejects(configureNetwork(env, config, options(m)), /failed/); assert.equal(m.state.config.ingress[0].originRequest.access.required, true);
  m.state.fail = null; await configureNetwork(env, config, options(m)); assert.equal(m.state.tunnels.length, 1); assert.equal(m.state.dns.length, 1);
});
test('Connector bundle uses private files and systemd credentials; generated installer parses', () => {
  const root = mkdtempSync(join(tmpdir(), 'connector-test-'));
  try {
    const dir = writeConnectorBundle(root, 'home-device', 'private-test-token');
    assert.equal(statSync(dir).mode & 0o777, 0o700); assert.equal(statSync(join(dir, 'tunnel-token')).mode & 0o777, 0o600);
    const service = readFileSync(join(dir, 'cloudflared-personalvpn-home-device.service'), 'utf8');
    assert.match(service, /LoadCredential=tunnel-token:/); assert.match(service, /--token-file %d\/tunnel-token/); assert.ok(!service.includes('private-test-token'));
    const installer = readFileSync(join(dir, 'install.sh'), 'utf8'); assert.ok(!installer.includes('private-test-token'));
    const check = spawnSync('bash', ['-n', join(dir, 'install.sh')], { encoding: 'utf8' }); assert.equal(check.status, 0, check.stderr);
    chmodSync(root, 0o755); assert.throws(() => prepareBundleRoot(root), /private/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
