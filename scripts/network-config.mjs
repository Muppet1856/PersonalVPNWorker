import { createHash } from 'node:crypto';
import { accessSettings } from './access-config.mjs';
const id = /^[a-f0-9]{32}$/;
function keys(value, allowed, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).some(k => !allowed.includes(k))) throw Error(`Invalid or unknown ${label} settings`);
}
function paths(value, label) {
  if (!Array.isArray(value) || value.length > 20 || value.some(p => typeof p !== 'string' || !/^\/[A-Za-z0-9_./-]*$/.test(p) || p.includes('..') || p.includes('//'))) throw Error(`Invalid ${label} paths`);
  return [...new Set(value)];
}
export function networkSettings(env, raw) {
  const access = accessSettings(env);
  if (!env.PUBLIC_ORIGIN || !access.team) throw Error('Set PUBLIC_ORIGIN and ACCESS_TEAM_DOMAIN');
  const publicOrigin = new URL(env.PUBLIC_ORIGIN);
  if (publicOrigin.protocol !== 'https:' || publicOrigin.origin !== env.PUBLIC_ORIGIN) throw Error('PUBLIC_ORIGIN must be a canonical HTTPS origin');
  keys(raw, ['tunnel_name', 'applications'], 'network');
  if (typeof raw.tunnel_name !== 'string' || !/^[a-z0-9][a-z0-9-]{0,39}$/.test(raw.tunnel_name)) throw Error('tunnel_name must be a lowercase name, up to 40 characters');
  if (!Array.isArray(raw.applications) || raw.applications.length < 1 || raw.applications.length > 20) throw Error('Configure 1–20 network applications');
  const seen = new Set();
  const applications = raw.applications.map(app => {
    keys(app, ['domain', 'zone_id', 'service', 'origin_server_name', 'ca_pool', 'http_host_header', 'waf'], 'application');
    if (!access.apps.some(a => a.domain === app.domain) || seen.has(app.domain)) throw Error('Every network hostname must occur exactly once and be listed in ACCESS_APPS_JSON');
    seen.add(app.domain);
    if (typeof app.zone_id !== 'string' || !id.test(app.zone_id)) throw Error('zone_id must be a Cloudflare zone ID');
    const url = new URL(app.service);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash || url.pathname !== '/') throw Error('service must be an HTTP(S) origin without credentials, path, query, or fragment');
    if (url.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(url.hostname)) throw Error('Use verified HTTPS for an origin outside loopback');
    const originRequest = { noTLSVerify: false };
    for (const [key, dest] of [['origin_server_name', 'originServerName'], ['http_host_header', 'httpHostHeader']]) {
      if (app[key] !== undefined) {
        if (typeof app[key] !== 'string' || !/^[A-Za-z0-9.-]+$/.test(app[key])) throw Error(`Invalid ${key}`);
        originRequest[dest] = app[key];
      }
    }
    if (app.ca_pool !== undefined) {
      if (typeof app.ca_pool !== 'string' || !/^\/etc\/[A-Za-z0-9_./-]+$/.test(app.ca_pool) || app.ca_pool.includes('..')) throw Error('ca_pool must be an absolute certificate path under /etc');
      originRequest.caPool = app.ca_pool;
    }
    keys(app.waf, ['blocked_paths', 'managed_ruleset_ids', 'rate_limit'], 'WAF');
    const blocked = paths(app.waf.blocked_paths ?? [], 'blocked');
    const managed = app.waf.managed_ruleset_ids ?? [];
    if (!Array.isArray(managed) || managed.length > 5 || managed.some(x => typeof x !== 'string' || !id.test(x)) || new Set(managed).size !== managed.length) throw Error('Invalid managed_ruleset_ids');
    let rate;
    if (app.waf.rate_limit !== undefined) {
      rate = app.waf.rate_limit;
      keys(rate, ['paths', 'requests_per_period', 'period', 'mitigation_timeout'], 'rate limit');
      for (const key of ['requests_per_period', 'period', 'mitigation_timeout']) if (!Number.isSafeInteger(rate[key]) || rate[key] < 1 || rate[key] > 1000000) throw Error(`Invalid rate limit ${key}`);
      rate = { ...rate, paths: paths(rate.paths, 'rate limit') };
      if (!rate.paths.length) throw Error('Scope rate limiting to at least one explicit path');
    }
    return { domain: app.domain, zone_id: app.zone_id, service: url.origin, originRequest, waf: { blocked_paths: blocked, managed_ruleset_ids: managed, ...(rate ? { rate_limit: rate } : {}) } };
  });
  return { ...access, applications, tunnelName: `PersonalVPNWorker:${access.clientID}:${raw.tunnel_name}`, deviceName: raw.tunnel_name, owner: `PersonalVPNWorker:${access.clientID}` };
}
const pathExpression = list => list.map(p => p === '/' ? 'true' : `(http.request.uri.path eq ${JSON.stringify(p.replace(/\/$/, ''))} or starts_with(http.request.uri.path, ${JSON.stringify(p.replace(/\/$/, '') + '/')}))`).join(' or ');
export function networkRules(settings, app) {
  const host = `(http.host eq ${JSON.stringify(app.domain)})`;
  function rule(kind, phase, values) {
    const ref = 'pvw_' + createHash('sha256').update(`${settings.owner}:${app.domain}:${kind}`).digest('hex').slice(0, 28);
    return { phase, rule: { ref, description: `${settings.owner}:${app.domain}:${kind}`, enabled: true, ...values } };
  }
  const rules = [
    rule('origin-security', 'http_request_firewall_custom', { action: 'block', expression: `${host} and (not ssl${app.waf.blocked_paths.length ? ' or ' + pathExpression(app.waf.blocked_paths) : ''})` }),
    rule('cache-bypass', 'http_request_cache_settings', { action: 'set_cache_settings', expression: host, action_parameters: { cache: false } }),
  ];
  for (const managedID of app.waf.managed_ruleset_ids) rules.push(rule('managed-' + managedID, 'http_request_firewall_managed', { action: 'execute', expression: host, action_parameters: { id: managedID } }));
  const rate = app.waf.rate_limit;
  if (rate) rules.push(rule('rate-limit', 'http_ratelimit', { action: 'block', expression: `${host} and (${pathExpression(rate.paths)})`, ratelimit: { characteristics: ['cf.colo.id', 'ip.src'], period: rate.period, requests_per_period: rate.requests_per_period, mitigation_timeout: rate.mitigation_timeout } }));
  return rules;
}
