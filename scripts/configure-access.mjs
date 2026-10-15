import { pathToFileURL } from 'node:url';
import { accessSettings } from './access-config.mjs';

export async function configureAccess(env,{apply=false,fetcher=fetch,log=console.log}={}) {
 if(!env.PUBLIC_ORIGIN)throw Error('Set PUBLIC_ORIGIN');
 const origin=new URL(env.PUBLIC_ORIGIN);if(origin.protocol!=='https:'||origin.origin!==env.PUBLIC_ORIGIN)throw Error('PUBLIC_ORIGIN must be a canonical HTTPS origin');
 const {team,clientID,apps}=accessSettings(env);if(!team)throw Error('Set ACCESS_TEAM_DOMAIN to your existing Zero Trust team hostname');
 const managedName=`${clientID} (PersonalVPNWorker)`;
 const plan={identity_provider:{name:managedName,type:'oidc',client_id:clientID,auth_url:origin.origin+'/oidc/authorize',token_url:origin.origin+'/oidc/token',certs_url:origin.origin+'/oidc/jwks',pkce_enabled:true},callback:`https://${team}/cdn-cgi/access/callback`,applications:apps.map(app=>({name:`${clientID}: ${app.name}`,domain:app.domain,policy:'Allow active invited members via this OIDC provider'}))};
 if(!apply){log(JSON.stringify(plan,null,2));return plan;}
 if(!env.CLOUDFLARE_ACCESS_API_TOKEN||!env.CLOUDFLARE_ACCOUNT_ID)throw Error('Set CLOUDFLARE_ACCESS_API_TOKEN and CLOUDFLARE_ACCOUNT_ID');
 if(!env.OIDC_CLIENT_SECRET||env.OIDC_CLIENT_SECRET.length<32)throw Error('Set OIDC_CLIENT_SECRET to at least 32 random characters');
 const root=`https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(env.CLOUDFLARE_ACCOUNT_ID)}/access`;
 async function api(path,method='GET',body) {
  const response=await fetcher(root+path,{method,headers:{authorization:'Bearer '+env.CLOUDFLARE_ACCESS_API_TOKEN,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{}),signal:AbortSignal.timeout(30000)});
  const data=await response.json();
  if(!response.ok||data.success===false)throw Error(`Cloudflare Access ${method} ${path} failed (HTTP ${response.status}; codes ${(data.errors||[]).map(x=>x.code).join(',')}). Check token permissions and the existing configuration.`);
  return data;
 }
 async function list(path) {
  const result=[];for(let page=1;page<=100;page++){
   const data=await api(path+`?per_page=100&page=${page}`);if(!Array.isArray(data.result))throw Error('Unexpected Cloudflare list response');result.push(...data.result);
   if(page>=(data.result_info?.total_pages||1))return result;
  }throw Error('Cloudflare result pagination exceeded supported size');
 }
 // Validate the existing organization and all ownership/collision rules before writes.
 const org=(await api('/organizations')).result;if(org.auth_domain!==team)throw Error('ACCESS_TEAM_DOMAIN does not match this account’s existing Zero Trust organization');
 const idps=await list('/identity_providers'),existingApps=await list('/apps');
 const matches=idps.filter(x=>x.name===managedName);if(matches.length>1)throw Error('Multiple managed identity providers found');
 const existingIDP=matches[0];if(existingIDP&&(existingIDP.type!=='oidc'||existingIDP.config?.client_id!==clientID||existingIDP.config?.auth_url!==plan.identity_provider.auth_url||existingIDP.config?.token_url!==plan.identity_provider.token_url||existingIDP.config?.certs_url!==plan.identity_provider.certs_url))throw Error('Existing identity provider conflicts with managed configuration');
 const targets=[];
 for(const app of apps) {
  const name=`${clientID}: ${app.name}`;
  const matches=existingApps.filter(x=>x.domain===app.domain);
  if(matches.length>1)throw Error(`Multiple Access applications already protect ${app.domain}`);
  const existing=matches[0];
  if(existing&&(existing.name!==name||existing.type!=='self_hosted'))throw Error(`Existing Access application for ${app.domain} is not managed by this project; it will not be changed`);
  const policies=existing?await list(`/apps/${existing.id}/policies`):[];
  if(policies.some(x=>x.name!==`${clientID}: Members`)||policies.length>1)throw Error(`Unmanaged policies exist for ${app.domain}; review them before automated configuration`);
  targets.push({app,name,existing,policy:policies[0]});
 }
 const idpBody={name:managedName,type:'oidc',config:{client_id:clientID,client_secret:env.OIDC_CLIENT_SECRET,auth_url:plan.identity_provider.auth_url,token_url:plan.identity_provider.token_url,certs_url:plan.identity_provider.certs_url,pkce_enabled:true,email_claim_name:'email',scopes:['openid','email','profile']}};
 const idp=(await api(existingIDP?`/identity_providers/${existingIDP.id}`:'/identity_providers',existingIDP?'PUT':'POST',idpBody)).result;
 if(!idp?.id)throw Error('Cloudflare did not return an identity provider ID');
 log('Configured managed OIDC identity provider.');
 for(const {app,name,existing,policy} of targets) {
  const body={name,type:'self_hosted',domain:app.domain,session_duration:'24h',allowed_idps:[idp.id],auto_redirect_to_identity:true,app_launcher_visible:true};
  const saved=(await api(existing?`/apps/${existing.id}`:'/apps',existing?'PUT':'POST',body)).result;
  if(!saved?.id)throw Error('Cloudflare did not return an application ID');
  await api(`/apps/${saved.id}/policies${policy?'/'+policy.id:''}`,policy?'PUT':'POST',{name:`${clientID}: Members`,decision:'allow',precedence:1,include:[{login_method:{id:idp.id}}],exclude:[],require:[]});
  log(`Configured Access protection for ${app.domain}.`);
 }
 log('Access setup complete. Omitted applications and unrelated account settings were not changed.');
 return plan;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
 try{await configureAccess(process.env,{apply:process.argv.includes('--apply')});}catch(error){console.error(error.message);process.exitCode=1;}
}
