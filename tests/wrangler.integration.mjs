import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
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
    '--var','ADMIN_SETUP_SECRET:ci-bootstrap-only','--var','SITE_NAME:CI Access'],
    {stdio:['ignore','pipe','pipe'],env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false'}});
  let logs='';child.stdout.on('data',chunk=>{logs=(logs+chunk).slice(-16000);});child.stderr.on('data',chunk=>{logs=(logs+chunk).slice(-16000);});
  let spawnError;child.on('error',error=>{spawnError=error;});
  const call=(path,data,cookie,requestOrigin=origin)=>fetch(address+path,{method:data===undefined?'GET':'POST',headers:{origin:requestOrigin,'content-type':'application/json',...(cookie?{cookie}:{})},...(data===undefined?{}:{body:JSON.stringify(data)}),signal:AbortSignal.timeout(5000)});
  try {
    let ready=false;
    for(let attempt=0;attempt<90;attempt++) {
      if(spawnError)throw spawnError;
      if(child.exitCode!==null)throw Error(`Wrangler exited before readiness:\n${logs}`);
      try {if((await call('/health')).status===200){ready=true;break;}}catch{}
      await delay(500);
    }
    assert.ok(ready,`Wrangler did not become ready:\n${logs}`);
    assert.match(await (await call('/')).text(),/<title>CI Access<\/title>/);
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
    const options2=await (await call('/api/login/options',{email:'ci@example.com'})).json();
    const assertion={flow:options2.flow,credential:auth.login(options2.options.challenge)};
    const login=await call('/api/login/verify',assertion);assert.equal(login.status,200);
    assert.equal((await call('/api/login/verify',assertion)).status,403);
    const signedCookie=login.headers.get('set-cookie').split(';')[0];
    assert.equal((await call('/api/logout',{},signedCookie)).status,200);
    assert.equal((await (await call('/api/me',undefined,signedCookie)).json()).user,null);
  } catch(error) {console.error(logs);throw error;}
  finally {
    if(child.exitCode===null){child.kill('SIGTERM');await Promise.race([once(child,'exit'),delay(3000)]);if(child.exitCode===null)child.kill('SIGKILL');}
    await rm(state,{recursive:true,force:true});
  }
});
