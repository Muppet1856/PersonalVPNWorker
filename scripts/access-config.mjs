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
 let launcher;
 if(env.LAUNCHER_ORIGIN){
  const url=new URL(env.LAUNCHER_ORIGIN);
  if(url.protocol!=='https:'||url.origin!==env.LAUNCHER_ORIGIN||url.username||url.password||url.port||!url.hostname.includes('.')||!url.hostname.split('.').every(part=>/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(part)))throw Error('LAUNCHER_ORIGIN must be a canonical HTTPS origin');
  if(url.hostname===origin.hostname||url.hostname===team||seen.has(url.hostname))throw Error('Launcher must have its own domain, separate from authentication and application tiles');
  launcher={name:'Application launcher',domain:url.hostname};
 }
 return {team,clientID,apps,launcher};
}
