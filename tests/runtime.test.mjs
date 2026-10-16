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

test('Cloudflare runtime: real email fetch options reach the provider and email codes authenticate once',async()=>{
 const origin='https://localhost:8787';const deliveries=[];
 const mf=new Miniflare(convertV4MiniflareOptions({
  modules:true,scriptPath:'dist/index.js',compatibilityDate:'2026-10-01',compatibilityFlags:['nodejs_compat'],
  durableObjects:{FAMILY_AUTH:{className:'FamilyAuth',useSQLite:true}},
  bindings:{PUBLIC_ORIGIN:origin,RP_ID:'localhost',ADMIN_SETUP_SECRET:'runtime-test-only',RESEND_API_KEY:'test-only-key',RESEND_FROM:'signin@mail.example.com'},
  outboundService:async req=>{
   assert.equal(req.url,'https://api.resend.com/emails');assert.equal(req.method,'POST');assert.equal(req.headers.get('authorization'),'Bearer test-only-key');
   deliveries.push(await req.json());return new Response('{"id":"test-mail"}',{headers:{'content-type':'application/json'}});
  },
 }));
 const call=(path,data,cookie)=>mf.dispatchFetch(origin+path,{method:data===undefined?'GET':'POST',headers:{origin,'content-type':'application/json',...(cookie?{cookie}:{})},...(data===undefined?{}:{body:JSON.stringify(data)})});
 try{
  const {token}=await (await call('/api/setup',{email:'test@example.com',secret:'runtime-test-only'})).json();
  const o=await (await call('/api/register/options',{token,name:'Runtime Email Test'})).json();const auth=authenticator(origin);
  assert.equal((await call('/api/register/verify',{token,flow:o.flow,credential:auth.register(o.options.challenge)})).status,200);
  const requested=await call('/api/email/request',{email:'test@example.com'});assert.equal(requested.status,200);
  assert.equal(deliveries.length,1,'Email fetch must reach the mocked provider in the actual Workers runtime');
  const {flow}=await requested.json();const browser=requested.headers.get('set-cookie').split(';')[0];const code=deliveries[0].text.match(/\n\n(\d{8})\n/)[1];
  const signed=await call('/api/email/verify',{flow,code,remember_me:true},browser);assert.equal(signed.status,200);assert.match(signed.headers.get('set-cookie'),/Max-Age=2592000/);
  const session=signed.headers.get('set-cookie').split(';')[0];assert.equal((await (await call('/api/me',undefined,session)).json()).user.email,'test@example.com');
  assert.equal((await call('/api/email/verify',{flow,code},browser)).status,403);
 }finally{await mf.dispose();}
});
