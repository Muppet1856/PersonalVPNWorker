import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { authenticator } from './authenticator.mjs';

test('Cloudflare runtime: Worker dispatch, SQLite object, passkey enrollment and login',async()=>{
  const origin='http://localhost:8787';
  const mf=new Miniflare(convertV4MiniflareOptions({
    modules:true, scriptPath:'dist/index.js', compatibilityDate:'2026-10-01',compatibilityFlags:['nodejs_compat'],
    durableObjects:{FAMILY_AUTH:{className:'FamilyAuth',useSQLite:true}},
    bindings:{PUBLIC_ORIGIN:origin,RP_ID:'localhost',ADMIN_SETUP_SECRET:'runtime-test-only'},
  }));
  try {
    const call=(path,data,cookie)=>mf.dispatchFetch(origin+path,data?{method:'POST',headers:{origin,'content-type':'application/json',...(cookie?{cookie}:{})},body:JSON.stringify(data)}:{headers:cookie?{cookie}:{}});
    assert.equal((await call('/health')).status,200);
    const setup=await call('/api/setup',{email:'test@example.com',secret:'runtime-test-only'});assert.equal(setup.status,200);const {token}=await setup.json();
    const registration=await call('/api/register/options',{token,name:'Runtime Test'});assert.equal(registration.status,200);const o=await registration.json();
    const auth=authenticator();const registered=await call('/api/register/verify',{token,flow:o.flow,credential:auth.register(o.options.challenge)});assert.equal(registered.status,200);
    const cookie=registered.headers.get('set-cookie').split(';')[0];assert.equal((await (await call('/api/me',undefined,cookie)).json()).user.name,'Runtime Test');
    const l=await (await call('/api/login/options',{email:'test@example.com'})).json();const assertion={flow:l.flow,credential:auth.login(l.options.challenge)};
    assert.equal((await call('/api/login/verify',assertion)).status,200);assert.equal((await call('/api/login/verify',assertion)).status,403);
  } finally {await mf.dispose();}
});
