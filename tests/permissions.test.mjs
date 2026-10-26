import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { createLocalJWKSet,jwtVerify,generateKeyPair,exportJWK,SignJWT } from 'jose';
import { configuredApps,allowedAppIDs } from '../src/permissions.ts';
import { handleLauncher } from '../src/launcher.ts';
import { DatabaseSync } from 'node:sqlite';
import { authenticator } from './authenticator.mjs';
import worker from '../src/auth.ts';
import { SqlStore } from '../src/store.ts';

// Real production schema and transaction wrapper, backed by SQLite; no credential-verification mocks.
class DB extends SqlStore {
 constructor(sql=new DatabaseSync(':memory:')) {
  sql.exec('PRAGMA foreign_keys=ON');
  super({sql:{exec(query,...values){
   if(!values.length&&query.includes(';')){sql.exec(query);return {toArray:()=>[]};}
   const stmt=sql.prepare(query),args=values.map(v=>v instanceof Uint8Array?Buffer.from(v):v);
   const rows=stmt.columns().length?stmt.all(...args):(stmt.run(...args),[]);
   return {toArray:()=>rows,one:()=>{assert.equal(rows.length,1);return rows[0];}};
  }},transactionSync(fn){sql.exec('BEGIN');try{const result=fn();sql.exec('COMMIT');return result;}catch(e){sql.exec('ROLLBACK');throw e;}}});
  this.sql=sql;
 }
}
const origin='https://localhost:8787';
const tokenHash=cookie=>createHash('sha256').update(cookie.slice(cookie.indexOf('=')+1)).digest('hex');
function fixture(){
 const env={DB:new DB(),PUBLIC_ORIGIN:origin,RP_ID:'localhost',ADMIN_SETUP_SECRET:'test-only-setup'};
 return {env,call(path,data,cookie,requestOrigin=origin){return worker.fetch(new Request(origin+path,{method:data===undefined?'GET':'POST',headers:{origin:requestOrigin,'content-type':'application/json',...(cookie?{cookie}:{})},...(data===undefined?{}:{body:JSON.stringify(data)})}),env);}};
}
async function ok(response){const data=await response.json();assert.equal(response.status,200,JSON.stringify(data));return data;}
async function rejected(response){assert.ok(response.status>=400&&response.status<500,`${response.status}: ${await response.text()}`);}
async function enroll(f,email='admin@example.com',adminCookie){
 const invite=await ok(await f.call(adminCookie?'/api/admin/invite':'/api/setup',adminCookie?{email}:{email,secret:f.env.ADMIN_SETUP_SECRET},adminCookie));
 const options=await ok(await f.call('/api/register/options',{token:invite.token,name:'Account Owner'}));
 const key=authenticator(origin),response=await f.call('/api/register/verify',{token:invite.token,flow:options.flow,credential:key.register(options.options.challenge)});
 await ok(response);const cookie=response.headers.get('set-cookie').split(';')[0];
 const {user}=await ok(await f.call('/api/me',undefined,cookie));
 return {key,cookie,user,email};
}
async function login(f,account,count=1){
 const options=await ok(await f.call('/api/login/options',{email:account.email}));
 const response=await f.call('/api/login/verify',{flow:options.flow,credential:account.key.login(options.options.challenge,count)});
 await ok(response);return response.headers.get('set-cookie').split(';')[0];
}
const applications=[{name:'Chat',url:'https://chat.example.com'},{name:'Git',url:'https://git.example.com'}];
async function accounts(){const f=fixture();f.env.APP_LINKS_JSON=JSON.stringify(applications);const admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);return {...f,admin,family};}
const setApps=(f,ids,cookie=f.admin.cookie,user=f.family.user.id)=>f.call('/api/admin/users',{user_id:user,action:'set_apps',allowed_apps:ids},cookie);

test('app grants default deny families, preserve admins and reject invalid or cross-account changes',async()=>{
 const f=await accounts();
 assert.deepEqual(allowedAppIDs(f.env,f.family.user),[]);
 assert.deepEqual(allowedAppIDs(f.env,f.admin.user),['chat.example.com','git.example.com']);
 assert.deepEqual((await ok(await f.call('/api/me',undefined,f.family.cookie))).apps,[]);
 await rejected(await setApps(f,['chat.example.com'],f.family.cookie));
 for(const ids of [['not-configured.example'],['chat.example.com','chat.example.com'],'chat.example.com'])await rejected(await setApps(f,ids));
 await rejected(await setApps(f,[],f.admin.cookie,f.admin.user.id));
 await ok(await setApps(f,['chat.example.com']));
 assert.deepEqual(allowedAppIDs(f.env,f.family.user),['chat.example.com']);
 assert.equal((await ok(await f.call('/api/me',undefined,f.family.cookie))).user,null);
 const cookie=await login(f,f.family);
 assert.deepEqual((await ok(await f.call('/api/me',undefined,cookie))).apps.map(x=>x.id),['chat.example.com']);
 const list=await ok(await f.call('/api/admin/users',undefined,f.admin.cookie));
 assert.deepEqual(list.users.find(u=>u.id===f.family.user.id).allowed_apps,['chat.example.com']);
 f.env.APP_LINKS_JSON=JSON.stringify([...applications,{name:'Future',url:'https://future.example.com'}]);
 assert.deepEqual(allowedAppIDs(f.env,f.family.user),['chat.example.com']);
 assert.throws(()=>configuredApps({APP_LINKS_JSON:JSON.stringify([applications[0],applications[0]])}));
});

test('app edits require fresh live passkey authentication and revoke all portal/OIDC state',async()=>{
 const f=await accounts(),sql=f.env.DB.sql;
 sql.prepare('UPDATE sessions SET authenticated_at=1 WHERE user_id=?').run(f.admin.user.id);
 await rejected(await setApps(f,['chat.example.com']));
 sql.prepare("UPDATE sessions SET authenticated_at=?,auth_method='email' WHERE user_id=?").run(Math.floor(Date.now()/1000),f.admin.user.id);
 await rejected(await setApps(f,['chat.example.com']));
 sql.prepare("UPDATE sessions SET auth_method='passkey' WHERE user_id=?").run(f.admin.user.id);
 const before=sql.prepare('SELECT access_revision AS n FROM users WHERE id=?').get(f.family.user.id).n;
 const response=await ok(await setApps(f,[]));assert.equal(response.access_sessions_require_revocation,true);
 assert.equal(sql.prepare('SELECT access_revision AS n FROM users WHERE id=?').get(f.family.user.id).n,before+1);
 assert.equal(sql.prepare('SELECT count(*) AS n FROM sessions WHERE user_id=?').get(f.family.user.id).n,0);
 sql.prepare('DELETE FROM passkeys WHERE user_id=?').run(f.admin.user.id);
 await rejected(await setApps(f,['chat.example.com']));
});

async function oidc(f,session){
 Object.assign(f.env,{ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:'test-secret-at-least-thirty-two-characters'});
 const callback='https://example.cloudflareaccess.com/cdn-cgi/access/callback',verifier='a'.repeat(43);
 const start=await f.call('/oidc/authorize?'+new URLSearchParams({response_type:'code',client_id:'family-access',redirect_uri:callback,scope:'openid email profile',state:'test',code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'}),undefined,session);
 assert.equal(start.status,302);const code=new URL(start.headers.get('location')).searchParams.get('code');assert.ok(code);
 const exchange=()=>worker.fetch(new Request(origin+'/oidc/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'family-access',client_secret:f.env.OIDC_CLIENT_SECRET,redirect_uri:callback,code,code_verifier:verifier})}),f.env);
 return {exchange};
}

test('signed OIDC claims carry only granted apps; old codes/tokens die after permission edits',async()=>{
 const f=await accounts();await ok(await setApps(f,['chat.example.com']));
 const cookie=await login(f,f.family);const flow=await oidc(f,cookie);
 const tokens=await ok(await flow.exchange());
 const jwks=await ok(await f.call('/oidc/jwks'));
 const {payload}=await jwtVerify(tokens.id_token,createLocalJWKSet(jwks),{issuer:origin,audience:'family-access'});
 assert.deepEqual(payload.allowed_apps,['chat.example.com']);assert.equal(payload.sub,f.family.user.id);
 // This is the exact-match policy predicate, NOT a live Cloudflare direct-URL test.
 assert.equal(payload.allowed_apps.includes('chat.example.com'),true);
 assert.equal(payload.allowed_apps.includes('git.example.com'),false);
 const pending=await oidc(f,cookie);await ok(await setApps(f,[]));
 assert.equal((await pending.exchange()).status,400);
 const info=await worker.fetch(new Request(origin+'/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token}}),f.env);assert.equal(info.status,401);
 const fresh=await login(f,f.family,2),empty=await oidc(f,fresh);const emptyTokens=await ok(await empty.exchange());
 assert.deepEqual((await jwtVerify(emptyTokens.id_token,createLocalJWKSet(jwks),{issuer:origin,audience:'family-access'})).payload.allowed_apps,[]);
});

test('launcher uses current database grants, not old JWT grant data; disabled account denied',async()=>{
 const f=await accounts();Object.assign(f.env,{LAUNCHER_ORIGIN:'https://access.example.com',ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',LAUNCHER_ACCESS_AUD:'a'.repeat(64)});
 const {privateKey,publicKey}=await generateKeyPair('RS256'),jwk=await exportJWK(publicKey);jwk.kid='launcher';const keys=createLocalJWKSet({keys:[jwk]});
 const token=await new SignJWT({email:f.family.email,allowed_apps:['chat.example.com','git.example.com']}).setProtectedHeader({alg:'RS256',kid:'launcher'}).setSubject('access-subject').setIssuedAt().setIssuer('https://'+f.env.ACCESS_TEAM_DOMAIN).setAudience(f.env.LAUNCHER_ACCESS_AUD).setExpirationTime('5m').sign(privateKey);
 const request=()=>new Request(f.env.LAUNCHER_ORIGIN,{headers:{'cf-access-jwt-assertion':token}});
 let response=await handleLauncher(request(),f.env,keys);assert.equal(response.status,200);assert.ok(!(await response.text()).includes('href="https://chat.example.com'));
 await ok(await setApps(f,['chat.example.com']));
 response=await handleLauncher(request(),f.env,keys);const html=await response.text();assert.ok(html.includes('href="https://chat.example.com'));assert.ok(!html.includes('href="https://git.example.com'));
 f.env.DB.sql.prepare('UPDATE users SET active=0 WHERE id=?').run(f.family.user.id);
 assert.equal((await handleLauncher(request(),f.env,keys)).status,403);
});

test('OIDC revocation during asynchronous ID-token signing fails closed',async()=>{
 const f=await accounts();const flow=await oidc(f,f.family.cookie);
 // Initialize the signing key so the hook observes ID-token signing, not generation.
 await ok(await f.call('/oidc/jwks'));
 const original=crypto.subtle.sign;
 crypto.subtle.sign=async function(...args){const result=await original.apply(this,args);f.env.DB.sql.prepare('UPDATE users SET access_revision=access_revision+1 WHERE id=?').run(f.family.user.id);return result;};
 try{assert.equal((await flow.exchange()).status,400);}finally{crypto.subtle.sign=original;}
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM oidc_tokens').get().n,0);
});

test('OIDC revocation after the session read cannot issue a new authorization code',async()=>{
 const f=await accounts();Object.assign(f.env,{ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:'test-secret-at-least-thirty-two-characters'});
 const original=crypto.subtle.digest,token=f.family.cookie.split('=')[1];let reads=0;
 crypto.subtle.digest=async function(...args){const result=await original.apply(this,args);if(new TextDecoder().decode(args[1])===token&&++reads===2)f.env.DB.sql.prepare('UPDATE users SET access_revision=access_revision+1 WHERE id=?').run(f.family.user.id);return result;};
 try{
  const response=await f.call('/oidc/authorize?'+new URLSearchParams({response_type:'code',client_id:'family-access',redirect_uri:'https://example.cloudflareaccess.com/cdn-cgi/access/callback',scope:'openid',state:'test',code_challenge:'a'.repeat(43),code_challenge_method:'S256'}),undefined,f.family.cookie);
  assert.equal(response.status,302);assert.equal(new URL(response.headers.get('location')).searchParams.get('error'),'access_denied');
 }finally{crypto.subtle.digest=original;}
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM oidc_codes').get().n,0);
});
