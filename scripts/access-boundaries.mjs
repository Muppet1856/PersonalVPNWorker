function publicURIs(app) {
  return [...new Set([app.domain, ...(app.self_hosted_domains || []), ...(app.destinations || []).filter(d => !d.type || d.type === 'public').map(d => d.uri)].filter(Boolean))];
}
export function assertApplicationBoundary(apps, domain, existing) {
  for (const app of apps) {
    if (app.id === existing?.id) continue;
    for (const uri of publicURIs(app)) {
      const host = uri.split('/')[0];
      const pattern = '^' + host.split('*').map(s => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$';
      if (new RegExp(pattern, 'i').test(domain)) throw Error(`Overlapping Access application for ${domain}; review its host/path policies`);
    }
  }
  if (existing && (publicURIs(existing).some(uri => uri !== domain)
    || (existing.destinations || []).some(d => (d.type && d.type !== 'public') || d.uri !== domain || d.overrides?.length))) {
    throw Error(`Access application for ${domain} has extra destinations or public overrides; it will not be changed`);
  }
}
