export function accessSettings(env) {
 const team=(env.ACCESS_TEAM_DOMAIN||'').trim().toLowerCase();
 if(team&&!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(team))throw Error('ACCESS_TEAM_DOMAIN must be your team hostname, e.g. example.cloudflareaccess.com');
 const clientID=env.OIDC_CLIENT_ID || 'family-access';if(!/^[A-Za-z0-9._-]{1,64}$/.test(clientID))throw Error('Invalid OIDC_CLIENT_ID');
 const raw=JSON.parse(env.ACCESS_APPS_JSON||'[]');if(!Array.isArray(raw)||raw.length>20)throw Error('ACCESS_APPS_JSON must be an array with at most 20 applications');
 const origin=new URL(env.PUBLIC_ORIGIN || 'https://vpn.example.com');const seen=new Set();
 const apps=raw.map(app=>{
  if(!app||typeof app.name!=='string'||!app.name.trim()||app.name.length>80||typeof app.domain!=='string')throw Error('Every Access application needs name and domain');
  const domain=app.domain.toLowerCase();
  if(domain.length>253||!domain.includes('.')||!domain.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)))throw Error('App domains must be exact hostnames without schemes, paths or wildcards');
  if(domain===origin.hostname||domain===team)throw Error('Never protect the identity provider or team domain with itself');
  if(seen.has(domain))throw Error('Duplicate Access application domain');seen.add(domain);
  return {name:app.name.trim(),domain};
 });
 return {team,clientID,apps};
}
