import { readFileSync, writeFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { accessSettings } from './access-config.mjs';

export function deploymentConfig(env, base) {
  if(!env.PUBLIC_ORIGIN)throw Error('Set PUBLIC_ORIGIN in .env.deploy.local, the build environment, or GitHub repository Actions Variables/Secrets');
  const origin=new URL(env.PUBLIC_ORIGIN);
  if(origin.protocol!=='https:' || origin.username || origin.password || origin.port || origin.pathname!=='/' || origin.search || origin.hash)throw Error('PUBLIC_ORIGIN must be an HTTPS origin without path, credentials, port, query or fragment');
  const workerName=env.WORKER_NAME || 'family-access';
  if(!/^[a-z0-9][a-z0-9-]{0,62}$/.test(workerName))throw Error('WORKER_NAME must be 1–63 lowercase letters, numbers or hyphens');
  const rpID=env.RP_ID || origin.hostname;
  // Keep passkeys scoped to the exact deployment hostname.
  if(rpID!==origin.hostname)throw Error('RP_ID must match the PUBLIC_ORIGIN hostname');
  const config=structuredClone(base);delete config.env;
  config.name=workerName;config.workers_dev=false;
  config.routes=[{pattern:origin.hostname,custom_domain:true}];
  config.vars={PUBLIC_ORIGIN:origin.origin,RP_ID:rpID,SITE_NAME:env.SITE_NAME?.trim() || 'Family Access',FAMILY_ID:env.FAMILY_ID || 'family-v1',SESSION_COOKIE_NAME:env.SESSION_COOKIE_NAME || 'family_session'};
  if(!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(config.vars.SESSION_COOKIE_NAME))throw Error('Invalid SESSION_COOKIE_NAME');
  if(config.vars.FAMILY_ID.length>128)throw Error('FAMILY_ID must be at most 128 characters');
  for(const [name,fallback,max] of [['SESSION_TTL_SECONDS',604800,2592000],['INVITE_TTL_SECONDS',86400,604800],['SETUP_INVITE_TTL_SECONDS',3600,86400],['CHALLENGE_TTL_SECONDS',300,600]]) {
    const value=Number(env[name] || fallback);
    if(!Number.isSafeInteger(value)||value<1||value>max)throw Error(`${name} must be an integer from 1 to ${max}`);
    config.vars[name]=String(value);
  }
  const access=accessSettings({...env,PUBLIC_ORIGIN:origin.origin});
  config.vars.ACCESS_TEAM_DOMAIN=access.team;
  config.vars.OIDC_CLIENT_ID=access.clientID;
  config.vars.APP_LINKS_JSON=JSON.stringify(access.apps.map(app=>({name:app.name,url:'https://'+app.domain})));
  // Only explicitly listed nonsecret settings are copied, never process.env wholesale.
  return config;
}
if(process.argv[1] && import.meta.url===pathToFileURL(process.argv[1]).href) {
  try {
    const config=deploymentConfig(process.env,JSON.parse(readFileSync('wrangler.jsonc','utf8')));
    writeFileSync('wrangler.deploy.json',JSON.stringify(config,null,2)+'\n',{mode:0o600});
    console.log(`Generated deployment configuration for ${config.name} at ${config.vars.PUBLIC_ORIGIN}`);
  } catch(error) { console.error(error.message);process.exitCode=1; }
}
