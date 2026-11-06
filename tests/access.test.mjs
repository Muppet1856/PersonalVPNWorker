import { test } from 'node:test';
import assert from 'node:assert/strict';
import { configureAccess } from '../scripts/configure-access.mjs';
import { accessSettings } from '../scripts/access-config.mjs';
const env = { PUBLIC_ORIGIN: 'https://vpn.example.com', ACCESS_TEAM_DOMAIN: 'example.cloudflareaccess.com', OIDC_CLIENT_SECRET: 'test-secret-with-at-least-32-characters', CLOUDFLARE_ACCOUNT_ID: 'test-account', CLOUDFLARE_ACCESS_API_TOKEN: 'test-api-token', ACCESS_APPS_JSON: JSON.stringify([{ name: 'Chat', domain: 'chat.example.com' }]) };
const quiet = { log: () => {} };
function mock() {
  const state = { idps: [], apps: [], policies: [], calls: [], fail: null, after: null };
  const response = (result, status = 200) => Response.json({ success: status < 400, result, errors: status >= 400 ? [{ code: 1000 }] : [], result_info: { total_pages: 1 } }, { status });
  const policyView = p => ({ ...p, app_count: state.apps.filter(a => a.policies?.some(x => x.id === p.id)).length });
  return { state, async fetcher(url, init) {
    const path = new URL(url).pathname.split('/access')[1], method = init.method, body = init.body ? JSON.parse(init.body) : undefined;
    const call = { path, method, body }; state.calls.push(call);
    if (state.fail?.(call)) return response(null, 500);
    let result;
    const appMatch = path.match(/^\/apps\/([^/]+)(?:\/policies(?:\/([^/]+)\/make_reusable)?)?$/);
    if (method === 'GET') {
      if (path === '/organizations') result = { auth_domain: 'example.cloudflareaccess.com' };
      else if (path === '/identity_providers') result = state.idps;
      else if (path === '/apps') result = state.apps;
      else if (path === '/policies') result = state.policies.filter(p => p.reusable).map(policyView);
      else if (path.startsWith('/policies/')) { const p = state.policies.find(p => p.id === path.slice(10) && p.reusable); if (!p) return response(null, 404); result = policyView(p); }
      else if (appMatch) { const app = state.apps.find(a => a.id === appMatch[1]); result = path.endsWith('/policies') ? app.policies.map(ref => ({ ...state.policies.find(p => p.id === ref.id), precedence: ref.precedence })) : app; }
      else throw Error('Unexpected GET ' + path);
    } else if (path.startsWith('/identity_providers')) {
      result = { id: 'idp-1', ...body }; state.idps = [result];
    } else if (path.endsWith('/make_reusable')) {
      const p = state.policies.find(p => p.id === appMatch[2]); p.reusable = true; result = [p];
    } else if (path === '/policies' || path.startsWith('/policies/')) {
      const id = method === 'POST' ? `policy-${state.policies.length + 1}` : path.slice(10);
      result = { ...body, id, reusable: true };
      state.policies = [...state.policies.filter(p => p.id !== id), result]; result = policyView(result);
    } else if (path === '/apps' || (appMatch && !path.includes('/policies'))) {
      const id = method === 'POST' ? `app-${state.apps.length + 1}` : appMatch[1];
      result = { id, aud: String(state.apps.length + 1).repeat(64).slice(0, 64), ...body };
      state.apps = [...state.apps.filter(a => a.id !== id), result];
    } else throw Error('Unexpected legacy write ' + path);
    state.after?.(call);
    return response(result);
  } };
}
async function apply(m, extra = {}) { return configureAccess({ ...env, ...extra }, { apply: true, fetcher: m.fetcher, ...quiet }); }
async function legacy(m) {
  await apply(m);
  m.state.policies[0].name = 'family-access: Members'; m.state.policies[0].reusable = false; m.state.policies[0].require = [];
  m.state.calls = [];
}
test('Access defaults to a secret-free offline plan', async () => {
  const plan = await configureAccess(env, { fetcher: () => { throw Error('unexpected request'); }, ...quiet });
  assert.equal(plan.identity_provider.pkce_enabled, true); assert.equal(JSON.stringify(plan).includes(env.OIDC_CLIENT_SECRET), false);
  assert.equal(plan.callback, 'https://example.cloudflareaccess.com/cdn-cgi/access/callback');
  assert.equal(plan.applications[0].policy_type, 'reusable');
});
test('Access rejects identity-provider loops, duplicate domains and invalid hostnames', () => {
  for (const domain of ['vpn.example.com', 'example.cloudflareaccess.com', '*.example.com', 'https://chat.example.com', 'chat.example.com/path']) assert.throws(() => accessSettings({ ...env, ACCESS_APPS_JSON: JSON.stringify([{ name: 'Invalid', domain }]) }));
  assert.throws(() => accessSettings({ ...env, ACCESS_APPS_JSON: JSON.stringify([{ name: 'A', domain: 'chat.example.com' }, { name: 'B', domain: 'chat.example.com' }]) }));
});
test('Reusable provisioning is repeatable and isolates the launcher and each app', async () => {
  const m = mock(), extra = { LAUNCHER_ORIGIN: 'https://access.example.com', ACCESS_APPS_JSON: JSON.stringify([{ name: 'Chat', domain: 'chat.example.com' }, { name: 'Git', domain: 'git.example.com' }]) };
  await apply(m, extra); const plan = await apply(m, extra);
  assert.equal(m.state.calls.filter(x => x.path === '/apps' && x.method === 'POST').length, 3);
  assert.equal(m.state.calls.filter(x => x.path === '/policies' && x.method === 'POST').length, 3);
  assert.equal(new Set(m.state.policies.map(p => p.name)).size, 3);
  for (const app of m.state.apps) {
    assert.deepEqual(app.allowed_idps, ['idp-1']);
    const policy = m.state.policies.find(p => p.id === app.policies[0].id);
    assert.equal(policy.reusable, true); assert.equal(policy.decision, 'allow');
    assert.deepEqual(policy.include, [{ login_method: { id: 'idp-1' } }]);
    assert.deepEqual(policy.require, app.domain === 'access.example.com' ? [] : [{ oidc: { claim_name: 'allowed_apps', claim_value: app.domain, identity_provider_id: 'idp-1' } }]);
  }
  assert.deepEqual(m.state.idps[0].config.claims, ['allowed_apps']); assert.match(plan.launcher_access_aud, /^[a-f0-9]{64}$/);
  assert.ok(m.state.calls.filter(x => x.method !== 'GET' && x.path.includes('/apps')).every(x => x.body.policies.every(p => Object.keys(p).sort().join(',') === 'id,precedence')));
});
test('Legacy migration preserves attachment/ID and stronger policy options', async () => {
  const m = mock(); await legacy(m); const id = m.state.policies[0].id;
  Object.assign(m.state.policies[0], { session_duration: '1h', approval_required: true, mfa_config: { allowed_authenticators: ['security_key'] } });
  m.state.after = () => assert.deepEqual(m.state.apps[0].policies, [{ id, precedence: 1 }]);
  await apply(m); await apply(m);
  assert.equal(m.state.calls.filter(c => c.path.endsWith('/make_reusable')).length, 1);
  assert.equal(m.state.policies[0].id, id); assert.equal(m.state.policies[0].session_duration, '1h');
  assert.equal(m.state.policies[0].approval_required, true); assert.deepEqual(m.state.policies[0].mfa_config, { allowed_authenticators: ['security_key'] });
  assert.equal(m.state.policies[0].require[0].oidc.claim_value, 'chat.example.com');
  assert.ok(m.state.calls.every(c => c.method !== 'DELETE'));
});
test('Inspection requires no OIDC secret and previews migration without writes', async () => {
  const m = mock(); await legacy(m); const logs = [];
  const plan = await configureAccess({ ...env, OIDC_CLIENT_SECRET: undefined }, { inspect: true, fetcher: m.fetcher, log: s => logs.push(s) });
  assert.equal(plan.applications[0].policy_action, 'convert_to_reusable'); assert.ok(m.state.calls.every(c => c.method === 'GET'));
  assert.equal(logs.join('').includes(env.CLOUDFLARE_ACCESS_API_TOKEN), false); assert.equal(logs.join('').includes(env.OIDC_CLIENT_SECRET), false);
});
test('All targets are checked before writes; unrelated apps/providers/policies are refused', async () => {
  for (const change of [
    m => { m.state.apps[0].name = 'Someone else'; },
    m => { m.state.idps[0].config.auth_url = 'https://other.example/oidc/authorize'; },
    m => { m.state.policies[0].include = [{ everyone: {} }]; },
    m => { m.state.policies[0].require.push({ ip: { ip: '192.0.2.1/32' } }); },
    m => { m.state.policies[0].decision = 'bypass'; },
    m => { m.state.apps[0].policies.push({ id: 'other' }); m.state.policies.push({ id: 'other', name: 'Manual bypass', decision: 'bypass' }); },
  ]) {
    const m = mock(); await apply(m); change(m); m.state.calls = [];
    await assert.rejects(apply(m), /managed|conflicts|Unmanaged/); assert.ok(m.state.calls.every(c => c.method === 'GET'));
  }
});
test('Shared reusable policies are never modified', async () => {
  const m = mock(); await apply(m); m.state.apps.push({ id: 'unrelated', name: 'Other', domain: 'other.example.com', policies: [{ id: m.state.policies[0].id }] }); m.state.calls = [];
  await assert.rejects(apply(m), /shared/); assert.ok(m.state.calls.every(c => c.method === 'GET'));
});
test('A failed app creation reuses the unattached policy on retry', async () => {
  const m = mock(); m.state.fail = c => c.method === 'POST' && c.path === '/apps';
  await assert.rejects(apply(m), /failed/); assert.equal(m.state.apps.length, 0); assert.equal(m.state.policies.length, 1);
  m.state.fail = null; await apply(m); assert.equal(m.state.policies.length, 1); assert.equal(m.state.apps.length, 1);
});
test('A failed migration update resumes without duplicating or detaching the policy', async () => {
  const m = mock(); await legacy(m); m.state.fail = c => c.method === 'PUT' && c.path.startsWith('/policies/');
  await assert.rejects(apply(m), /failed/); assert.equal(m.state.policies[0].reusable, true); assert.equal(m.state.apps[0].policies.length, 1);
  m.state.fail = null; await apply(m); assert.equal(m.state.policies.length, 1); assert.equal(m.state.calls.filter(c => c.path.endsWith('/make_reusable')).length, 1);
});
test('Readback catches an API that does not save the requested claim or attachment', async () => {
  for (const corrupt of ['claim', 'attachment']) {
    const m = mock(); m.state.after = c => {
      if (corrupt === 'claim' && c.path === '/policies' && c.method === 'POST') m.state.policies[0].require = [];
      if (corrupt === 'attachment' && c.path === '/apps' && c.method === 'POST') m.state.apps[0].policies = [];
    };
    await assert.rejects(apply(m), /verification failed/);
  }
});
test('Pagination discovers conflicts beyond the first page', async () => {
  const m = mock(); await apply(m); const original = m.fetcher; m.state.calls = [];
  const fetcher = async (url, init) => {
    if (new URL(url).pathname.endsWith('/policies') && !new URL(url).pathname.includes('/apps/') && init.method === 'GET') {
      const page = new URL(url).searchParams.get('page');
      return Response.json({ success: true, result: page === '1' ? Array.from({ length: 100 }, (_, i) => ({ id: 'unrelated-' + i, name: 'Unrelated', reusable: true })) : [{ ...m.state.policies[0] }, { ...m.state.policies[0], id: 'duplicate' }] });
    }
    return original(url, init);
  };
  await assert.rejects(configureAccess(env, { apply: true, fetcher, ...quiet }), /Conflicting/); assert.ok(m.state.calls.every(c => c.method === 'GET'));
});
