import { test } from 'node:test';
import assert from 'node:assert/strict';
import { configureAccess } from '../scripts/configure-access.mjs';
import { accessSettings } from '../scripts/access-config.mjs';
const env={PUBLIC_ORIGIN:'https://vpn.example.com',ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:'test-secret-with-at-least-32-characters',CLOUDFLARE_ACCOUNT_ID:'test-account',CLOUDFLARE_ACCESS_API_TOKEN:'test-api-token',ACCESS_APPS_JSON:JSON.stringify([{name:'Chat',domain:'chat.example.com'}])};
test('Access defaults to a secret-free plan without making API requests',async()=>{
 const plan=await configureAccess(env,{fetcher:()=>{throw Error('unexpected request');},log:()=>{}});
 assert.equal(plan.identity_provider.pkce_enabled,true);assert.equal(JSON.stringify(plan).includes(env.OIDC_CLIENT_SECRET),false);
 assert.equal(plan.callback,'https://example.cloudflareaccess.com/cdn-cgi/access/callback');
});
test('Access rejects identity-provider loops, duplicate domains and invalid hostnames',()=>{
 for(const domain of ['vpn.example.com','example.cloudflareaccess.com','*.example.com','https://chat.example.com','chat.example.com/path'])assert.throws(()=>accessSettings({...env,ACCESS_APPS_JSON:JSON.stringify([{name:'Invalid',domain}])}));
 assert.throws(()=>accessSettings({...env,ACCESS_APPS_JSON:JSON.stringify([{name:'A',domain:'chat.example.com'},{name:'B',domain:'chat.example.com'}])}));
});
function mock(unmanaged=false) {
 const state={idps:[],apps:unmanaged?[{id:'unrelated',domain:'chat.example.com',name:'Existing app',type:'self_hosted'}]:[],policies:[],calls:[]};
 return {state,async fetcher(url,init){
  const path=new URL(url).pathname.split('/access')[1],method=init.method;
  const body=init.body?JSON.parse(init.body):undefined;state.calls.push({path,method,body});let result;
  if(method==='GET') {
   if(path==='/organizations')result={auth_domain:'example.cloudflareaccess.com'};
   else if(path==='/identity_providers')result=state.idps;
   else if(path==='/apps')result=state.apps;
   else if(path.endsWith('/policies'))result=state.policies;
   else throw Error('Unexpected path '+path);
  } else if(path.startsWith('/identity_providers')) {result={id:'idp-1',...body};state.idps=[result];}
  else if(path.includes('/policies')) {result={id:'policy-1',...body};state.policies=[result];}
  else if(path.startsWith('/apps')) {result={id:'app-1',...body};state.apps=[result];}
  else throw Error('Unexpected write '+path);
  return new Response(JSON.stringify({success:true,result,result_info:{total_pages:1}}),{status:200,headers:{'content-type':'application/json'}});
 }};
}
test('Access provisioning is idempotent and allows only the configured identity provider',async()=>{
 const m=mock();await configureAccess(env,{apply:true,fetcher:m.fetcher,log:()=>{}});await configureAccess(env,{apply:true,fetcher:m.fetcher,log:()=>{}});
 assert.equal(m.state.calls.filter(x=>x.path==='/apps'&&x.method==='POST').length,1);
 assert.deepEqual(m.state.apps[0].allowed_idps,['idp-1']);assert.equal(m.state.apps[0].auto_redirect_to_identity,true);
 assert.deepEqual(m.state.policies[0].include,[{login_method:{id:'idp-1'}}]);assert.equal(m.state.policies[0].decision,'allow');
 assert.deepEqual(m.state.idps[0].config.claims,['allowed_apps']);
 assert.deepEqual(m.state.policies[0].require,[{oidc:{claim_name:'allowed_apps',claim_value:'chat.example.com',identity_provider_id:'idp-1'}}]);
});
test('Access refuses to overwrite unrelated applications before making writes',async()=>{
 const m=mock(true);await assert.rejects(configureAccess(env,{apply:true,fetcher:m.fetcher,log:()=>{}}),/not managed/);
 assert.ok(m.state.calls.every(x=>x.method==='GET'));
});

test('Access refuses to take over a same-named provider for another issuer',async()=>{
 const m=mock();m.state.idps=[{id:'other',name:'family-access (PersonalVPNWorker)',type:'oidc',config:{client_id:'family-access',auth_url:'https://other.example/oidc/authorize'}}];
 await assert.rejects(configureAccess(env,{apply:true,fetcher:m.fetcher,log:()=>{}}),/conflicts/);assert.ok(m.state.calls.every(x=>x.method==='GET'));
});
test('launcher is protected as a separate application and returns its audience',async()=>{
 const m=mock();const fetcher=async(url,init)=>{const response=await m.fetcher(url,init);const data=await response.json();if(init.method!=='GET'&&data.result?.domain==='access.example.com')data.result.aud='a'.repeat(64);return Response.json(data);};
 const plan=await configureAccess({...env,LAUNCHER_ORIGIN:'https://access.example.com'},{apply:true,fetcher,log:()=>{}});
 assert.equal(plan.launcher_access_aud,'a'.repeat(64));assert.equal(plan.applications.length,2);
 const policies=m.state.calls.filter(x=>x.method==='POST'&&x.path.endsWith('/policies'));
 assert.equal(policies[0].body.require[0].oidc.claim_value,'chat.example.com');
 assert.deepEqual(policies[1].body.require,[]);
 const launcher=m.state.calls.find(x=>x.method==='POST'&&x.body?.domain==='access.example.com');assert.deepEqual(launcher.body.allowed_idps,['idp-1']);
});
