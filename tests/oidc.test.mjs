import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { authenticator } from './authenticator.mjs';
const sha=value=>createHash('sha256').update(value).digest('base64url');

test('OIDC in Cloudflare runtime: codes, PKCE, tokens, browser binding and key rotation',async(t)=>{
 const origin='http://localhost:8787',callback='https://example.cloudflareaccess.com/cdn-cgi/access/callback';
 const clientID='family-access',secret='test-client-secret-at-least-32-characters';
 const mf=new Miniflare(convertV4MiniflareOptions({modules:true,scriptPath:'dist/index.js',compatibilityDate:'2026-10-01',compatibilityFlags:['nodejs_compat'],durableObjects:{FAMILY_AUTH:{className:'FamilyAuth',useSQLite:true}},bindings:{PUBLIC_ORIGIN:origin,RP_ID:'localhost',ADMIN_SETUP_SECRET:'setup-test',ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:secret}}));
 const call=(path,data,cookie,extra={})=>mf.dispatchFetch(origin+path,{redirect:'manual',method:data===undefined?'GET':'POST',headers:{origin,...(cookie?{cookie}:{}),...(data===undefined?{}:{'content-type':data instanceof URLSearchParams?'application/x-www-form-urlencoded':'application/json'}),...extra},...(data===undefined?{}:{body:data instanceof URLSearchParams?data.toString():JSON.stringify(data)})});
 try {
  const {token}=await (await call('/api/setup',{email:'admin@example.com',secret:'setup-test'})).json();
  const reg=await (await call('/api/register/options',{token,name:'OIDC Admin'})).json(),auth=authenticator();
  const registered=await call('/api/register/verify',{token,flow:reg.flow,credential:auth.register(reg.options.challenge)});assert.equal(registered.status,200);
  const cookie=registered.headers.get('set-cookie').split(';')[0];
  const verifier='a'.repeat(43);
  const authorize=(changes={},session=cookie)=>call('/oidc/authorize?'+new URLSearchParams({response_type:'code',client_id:clientID,redirect_uri:callback,scope:'openid email profile',state:'client-state',nonce:'client-nonce',code_challenge:sha(verifier),code_challenge_method:'S256',...changes}),undefined,session);
  const codeFrom=async()=>{const r=await authorize();assert.equal(r.status,302);return new URL(r.headers.get('location')).searchParams.get('code');};
  const exchange=(code,changes={},headers={})=>call('/oidc/token',new URLSearchParams({grant_type:'authorization_code',client_id:clientID,client_secret:secret,redirect_uri:callback,code,code_verifier:verifier,...changes}),undefined,headers);
  await t.test('discovery and signed ID token satisfy issuer/audience/nonce and JWKS verification',async()=>{
   const d=await (await call('/.well-known/openid-configuration')).json();assert.equal(d.issuer,origin);assert.deepEqual(d.code_challenge_methods_supported,['S256']);
   const response=await exchange(await codeFrom());assert.equal(response.status,200);const tokens=await response.json();
   const jwks=await (await call('/oidc/jwks')).json();assert.ok(jwks.keys.every(k=>!k.d));
   const {payload}=await jwtVerify(tokens.id_token,createLocalJWKSet(jwks),{issuer:origin,audience:clientID,algorithms:['RS256']});
   assert.equal(payload.email,'admin@example.com');assert.equal(payload.email_verified,false);assert.equal(payload.nonce,'client-nonce');assert.ok(payload.auth_time);assert.equal(payload.exp-payload.iat,300);
   const info=await call('/oidc/userinfo',undefined,undefined,{authorization:'Bearer '+tokens.access_token});assert.equal(info.status,200);assert.equal((await info.json()).sub,payload.sub);
  });
  await t.test('unregistered redirects, missing S256 and duplicate parameters are rejected',async()=>{
   const bad=await authorize({redirect_uri:'https://evil.example/callback'});assert.equal(bad.status,400);assert.equal(bad.headers.get('location'),null);
   const plain=await authorize({code_challenge_method:'plain'});assert.equal(new URL(plain.headers.get('location')).searchParams.get('error'),'invalid_request');
   const duplicate=await call('/oidc/authorize?client_id=family-access&client_id=other');assert.equal(duplicate.status,400);
  });
  await t.test('authorization codes are single use even when token requests race',async()=>{
   const code=await codeFrom();const r=await Promise.all([exchange(code),exchange(code)]);assert.deepEqual(r.map(x=>x.status).sort(),[200,400]);
  });
  await t.test('wrong PKCE verifier burns the code; client-auth failure does not',async()=>{
   const code=await codeFrom();assert.equal((await exchange(code,{code_verifier:'b'.repeat(43)})).status,400);assert.equal((await exchange(code)).status,400);
   const code2=await codeFrom();assert.equal((await exchange(code2,{client_secret:'wrong'})).status,401);assert.equal((await exchange(code2)).status,200);
  });
  await t.test('client_secret_basic works and mixed credentials are rejected',async()=>{
   const code=await codeFrom();const params=new URLSearchParams({grant_type:'authorization_code',redirect_uri:callback,code,code_verifier:verifier});
   const basic='Basic '+Buffer.from(clientID+':'+secret).toString('base64');const r=await call('/oidc/token',params,undefined,{authorization:basic});assert.equal(r.status,200);
   assert.equal((await exchange(await codeFrom(),{},{authorization:basic})).status,401);
  });
  await t.test('login continuation is browser-bound, one-time and preserves state',async()=>{
   const start=await authorize({},null);const id=new URL(start.headers.get('location'),origin).searchParams.get('oidc_request');assert.ok(id);
   const browser=start.headers.get('set-cookie').split(';')[0],body=new URLSearchParams({request_id:id});
   assert.equal((await call('/oidc/continue',body,cookie)).status,400);
   assert.equal((await call('/oidc/continue',body,browser+'; '+cookie,{origin:'https://evil.example'})).status,403);
   const finished=await call('/oidc/continue',body,browser+'; '+cookie);assert.equal(finished.status,200);const location=new URL((await finished.json()).redirect);assert.equal(location.origin,'https://example.cloudflareaccess.com');assert.equal(location.searchParams.get('state'),'client-state');assert.equal(location.searchParams.get('iss'),origin);
   assert.equal((await call('/oidc/continue',body,browser+'; '+cookie)).status,400);
  });
  await t.test('prompt=none does not show login; prompt=login requires a new session',async()=>{
   const none=await authorize({prompt:'none'},null);assert.equal(new URL(none.headers.get('location')).searchParams.get('error'),'login_required');
   const forced=await authorize({prompt:'login'}),browser=forced.headers.get('set-cookie').split(';')[0];const id=new URL(forced.headers.get('location'),origin).searchParams.get('oidc_request');
   const body=new URLSearchParams({request_id:id});assert.equal((await call('/oidc/continue',body,browser+'; '+cookie)).status,401);
   const opts=await (await call('/api/login/options',{email:'admin@example.com'})).json();const login=await call('/api/login/verify',{flow:opts.flow,credential:auth.login(opts.options.challenge)});assert.equal(login.status,200);
   const fresh=login.headers.get('set-cookie').split(';')[0];assert.equal((await call('/oidc/continue',body,browser+'; '+fresh)).status,200);
  });
  await t.test('signing key rotation keeps old public key and uses a new signer',async()=>{
   const before=await (await call('/oidc/jwks')).json();assert.equal((await call('/api/admin/oidc/rotate',{},undefined)).status,403);
   assert.equal((await call('/api/admin/oidc/rotate',{},cookie)).status,200);
   const after=await (await call('/oidc/jwks')).json();assert.ok(after.keys.some(x=>x.kid===before.keys[0].kid));assert.equal(after.keys.length,2);
   const tokens=await (await exchange(await codeFrom())).json();const verified=await jwtVerify(tokens.id_token,createLocalJWKSet(after),{issuer:origin,audience:clientID});assert.notEqual(verified.protectedHeader.kid,before.keys[0].kid);
  });
 } finally {await mf.dispose();}
});
