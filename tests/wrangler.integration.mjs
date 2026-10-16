import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import { jwtVerify, createLocalJWKSet } from 'jose';
import { authenticator } from './authenticator.mjs';

// Run through Wrangler's actual HTTP server and its configured DO binding.
// Every run uses fresh temporary persistence and test-only bootstrap credentials.
test('wrangler dev: portal, passkeys, sessions, invitations and replay rejection', {timeout:60000}, async()=>{
  const socket=createServer();socket.listen(0,'127.0.0.1');await once(socket,'listening');
  const port=socket.address().port;await new Promise(resolve=>socket.close(resolve));
  const origin=`http://localhost:${port}`;const address=`http://127.0.0.1:${port}`;
  const state=await mkdtemp(join(tmpdir(),'family-auth-ci-'));
  const child=spawn(process.execPath,['node_modules/wrangler/bin/wrangler.js','dev','--local','--env','local',
    '--ip','127.0.0.1','--port',String(port),'--inspector-port','0','--persist-to',state,
    '--show-interactive-dev-session=false','--var',`PUBLIC_ORIGIN:${origin}`,
    '--var','ACCESS_TEAM_DOMAIN:example.cloudflareaccess.com','--var','OIDC_CLIENT_SECRET:wrangler-test-secret-with-at-least-32-characters','--var','ADMIN_SETUP_SECRET:ci-bootstrap-only','--var','SITE_NAME:CI Access'],
    {stdio:['ignore','pipe','pipe'],env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false'}});
  let logs='';child.stdout.on('data',chunk=>{logs=(logs+chunk).slice(-16000);});child.stderr.on('data',chunk=>{logs=(logs+chunk).slice(-16000);});
  let spawnError;child.on('error',error=>{spawnError=error;});
  const call=(path,data,cookie,requestOrigin=origin)=>fetch(address+path,{redirect:'manual',method:data===undefined?'GET':'POST',headers:{origin:requestOrigin,'content-type':'application/json',...(cookie?{cookie}:{})},...(data===undefined?{}:{body:JSON.stringify(data)}),signal:AbortSignal.timeout(5000)});
  try {
    let ready=false;
    for(let attempt=0;attempt<90;attempt++) {
      if(spawnError)throw spawnError;
      if(child.exitCode!==null)throw Error(`Wrangler exited before readiness:\n${logs}`);
      try {if((await call('/health')).status===200){ready=true;break;}}catch{}
      await delay(500);
    }
    assert.ok(ready,`Wrangler did not become ready:\n${logs}`);
    const portal=await (await call('/')).text();assert.match(portal,/<title>CI Access<\/title>/);
    assert.ok(portal.includes('/assets/bootstrap-5.3.8.min.css'));
    const stylesheet=await call('/assets/bootstrap-5.3.8.min.css');assert.equal(stylesheet.status,200);assert.match(stylesheet.headers.get('content-type'),/text\/css/);assert.match(stylesheet.headers.get('cache-control'),/immutable/);assert.match(await stylesheet.text(),/Bootstrap\s+v5\.3\.8/);
    assert.equal((await call('/api/setup',{},undefined,'https://untrusted.example')).status,403);
    const setup=await call('/api/setup',{email:'ci@example.com',secret:'ci-bootstrap-only'});assert.equal(setup.status,200);
    const {token}=await setup.json();const options=await (await call('/api/register/options',{token,name:'CI Admin'})).json();
    assert.equal(options.options.rp.name,'CI Access');const auth=authenticator(origin);
    const registration={token,flow:options.flow,credential:auth.register(options.options.challenge)};
    const registered=await call('/api/register/verify',registration);assert.equal(registered.status,200);
    assert.equal((await call('/api/register/verify',registration)).status,403);
    const cookie=registered.headers.get('set-cookie').split(';')[0];
    assert.equal((await (await call('/api/me',undefined,cookie)).json()).user.role,'admin');
    assert.equal((await call('/api/admin/invite',{email:'member@example.com'},cookie)).status,200);
    assert.equal((await call('/api/admin/users')).status,403);
    const members=await (await call('/api/admin/users',undefined,cookie)).json();assert.equal(members.users[0].passkey_count,1);assert.equal(members.users[0].session_count,1);
    assert.equal((await call('/api/admin/users',{user_id:members.users[0].id,action:'disable'},cookie)).status,409);
    const pending=await (await call('/api/admin/invites',undefined,cookie)).json();assert.equal(pending.invitations.length,1);
    assert.equal((await call('/api/admin/invites/revoke',{invitation_id:pending.invitations[0].id},cookie)).status,200);
    assert.equal((await (await call('/api/admin/invites',undefined,cookie)).json()).invitations.length,0);
    const options2=await (await call('/api/login/options',{email:'ci@example.com'})).json();
    const assertion={flow:options2.flow,credential:auth.login(options2.options.challenge),remember_me:true};
    const login=await call('/api/login/verify',assertion);assert.equal(login.status,200);assert.match(login.headers.get('set-cookie'),/Max-Age=2592000/);assert.match(login.headers.get('set-cookie'),/Expires=/);
    assert.equal((await call('/api/login/verify',assertion)).status,403);
    // Complete the confidential-client OIDC exchange through the Wrangler HTTP server.
    const verifier='a'.repeat(43),callback='https://example.cloudflareaccess.com/cdn-cgi/access/callback';
    const authParams=new URLSearchParams({client_id:'family-access',redirect_uri:callback,response_type:'code',scope:'openid email profile',state:'wrangler-state',nonce:'wrangler-nonce',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
    const authorized=await call('/oidc/authorize?'+authParams,undefined,cookie);assert.equal(authorized.status,302);
    const code=new URL(authorized.headers.get('location')).searchParams.get('code');
    const tokenResponse=await fetch(address+'/oidc/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'family-access',client_secret:'wrangler-test-secret-with-at-least-32-characters',redirect_uri:callback,code,code_verifier:verifier})});assert.equal(tokenResponse.status,200);
    const identity=await tokenResponse.json(),jwks=await (await call('/oidc/jwks')).json();
    const verified=await jwtVerify(identity.id_token,createLocalJWKSet(jwks),{issuer:origin,audience:'family-access'});assert.equal(verified.payload.nonce,'wrangler-nonce');assert.equal(verified.payload.email,'ci@example.com');

    const signedCookie=login.headers.get('set-cookie').split(';')[0];
    assert.equal((await call('/api/logout',{},signedCookie)).status,200);
    assert.equal((await (await call('/api/me',undefined,signedCookie)).json()).user,null);
  } catch(error) {console.error(logs);throw error;}
  finally {
    if(child.exitCode===null){child.kill('SIGTERM');await Promise.race([once(child,'exit'),delay(3000)]);if(child.exitCode===null)child.kill('SIGKILL');}
    await rm(state,{recursive:true,force:true});
  }
});
