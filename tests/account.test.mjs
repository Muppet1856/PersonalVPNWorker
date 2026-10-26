import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
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
async function reauth(f,account,count=1,cookie=account.cookie){
 const options=await ok(await f.call('/api/account/reauth/options',{},cookie));
 await ok(await f.call('/api/account/reauth/verify',{flow:options.flow,credential:account.key.login(options.options.challenge,count)},cookie));
}
async function add(f,account,name='Backup key'){
 const options=await ok(await f.call('/api/account/passkeys/options',{name},account.cookie));
 const key=authenticator(origin);
 await ok(await f.call('/api/account/passkeys/verify',{flow:options.flow,credential:key.register(options.options.challenge)},account.cookie));
 return {key,options};
}

test('account passkeys preserve identity, names and the original credential',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 const {key,options}=await add(f,account,'Spare phone');
 assert.equal(Buffer.from(options.options.user.id,'base64url').toString(),account.user.id);
 assert.ok(options.options.excludeCredentials.some(k=>k.id===account.key.id));
 const list=await ok(await f.call('/api/account',undefined,account.cookie));
 assert.equal(list.passkeys.length,2);assert.equal(list.passkeys.find(k=>k.id===key.id).name,'Spare phone');
 assert.equal(list.email_recovery_enabled,false);
 await ok(await f.call('/api/account/passkeys/rename',{id:key.id,name:'Travel key'},account.cookie));
 assert.equal((await ok(await f.call('/api/account',undefined,account.cookie))).passkeys.find(k=>k.id===key.id).name,'Travel key');
 const backupCookie=await login(f,{...account,key});
 assert.deepEqual((await ok(await f.call('/api/me',undefined,backupCookie))).user.id,account.user.id);
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM users').get().n,1);
});

test('account routes require session and correct origin; never disclose another account keys',async()=>{
 const f=fixture(),admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);
 await rejected(await f.call('/api/account'));
 await rejected(await f.call('/api/account/reauth/options',{},admin.cookie,'https://evil.example'));
 await reauth(f,admin);await reauth(f,family);
 const list=await ok(await f.call('/api/account',undefined,family.cookie));
 assert.equal(list.passkeys.length,1);assert.equal(list.passkeys[0].id,family.key.id);
 await rejected(await f.call('/api/account/passkeys/rename',{id:admin.key.id,name:'Taken'},family.cookie));
 await rejected(await f.call('/api/account/passkeys/remove',{id:admin.key.id},family.cookie));
 assert.equal(f.env.DB.sql.prepare('SELECT user_id FROM passkeys WHERE id=?').get(admin.key.id).user_id,admin.user.id);
});

test('account enrollment challenge is one-use, account- and session-bound',async()=>{
 const f=fixture(),admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);
 await reauth(f,admin);await reauth(f,family);
 const options=await ok(await f.call('/api/account/passkeys/options',{name:'Bound key'},admin.cookie));
 const key=authenticator(origin),data={flow:options.flow,credential:key.register(options.options.challenge)};
 await rejected(await f.call('/api/account/passkeys/verify',data,family.cookie));
 const secondCookie=await login(f,admin,2);
 await rejected(await f.call('/api/account/passkeys/verify',data,secondCookie));
 const responses=await Promise.all([f.call('/api/account/passkeys/verify',data,admin.cookie),f.call('/api/account/passkeys/verify',data,admin.cookie)]);
 assert.equal(responses.filter(r=>r.status===200).length,1);
 assert.ok(responses.filter(r=>r.status!==200).every(r=>r.status>=400&&r.status<500));
 await rejected(await f.call('/api/account/passkeys/verify',data,admin.cookie));
});

test('fresh authentication assertion is bound to session and cannot replay or accept another user key',async()=>{
 const f=fixture(),admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);
 const options=await ok(await f.call('/api/account/reauth/options',{},admin.cookie));
 const data={flow:options.flow,credential:admin.key.login(options.options.challenge)};
 await rejected(await f.call('/api/account/reauth/verify',data,family.cookie));
 await ok(await f.call('/api/account/reauth/verify',data,admin.cookie));
 await rejected(await f.call('/api/account/reauth/verify',data,admin.cookie));
 const wrong=await ok(await f.call('/api/account/reauth/options',{},admin.cookie));
 await rejected(await f.call('/api/account/reauth/verify',{flow:wrong.flow,credential:family.key.login(wrong.options.challenge)},admin.cookie));
});

test('concurrent removals preserve at least one credential and removed keys cannot login',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);const {key}=await add(f,account);
 const options=await ok(await f.call('/api/login/options',{email:account.email}));
 const responses=await Promise.all([f.call('/api/account/passkeys/remove',{id:key.id},account.cookie),f.call('/api/account/passkeys/remove',{id:account.key.id},account.cookie)]);
 assert.equal(responses.filter(r=>r.status===200).length,1);
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM passkeys').get().n,1);
 const remaining=f.env.DB.sql.prepare('SELECT id FROM passkeys').get().id;
 const removed=remaining===key.id?account.key:key;
 await rejected(await f.call('/api/login/verify',{flow:options.flow,credential:removed.login(options.options.challenge,3)}));
});

test('administrators cannot enable mailbox recovery and stale or legacy sessions cannot change credentials',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 await rejected(await f.call('/api/account/recovery',{enabled:true},account.cookie));
 const columns=f.env.DB.sql.prepare('PRAGMA table_info(sessions)').all().map(c=>c.name);
 assert.ok(columns.includes('auth_method'));
 f.env.DB.sql.prepare("UPDATE sessions SET auth_method='email' WHERE token_hash=?").run(tokenHash(account.cookie));
 for(const [path,data] of [['passkeys/options',{name:'Forbidden'}],['passkeys/rename',{id:account.key.id,name:'Forbidden'}],['passkeys/remove',{id:account.key.id}],['recovery',{enabled:true}]])await rejected(await f.call('/api/account/'+path,data,account.cookie));
});

test('expired account challenges and stale freshness fail closed, including in-flight add',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 const options=await ok(await f.call('/api/account/passkeys/options',{name:'Expired'},account.cookie));
 f.env.DB.sql.prepare('UPDATE account_challenges SET expires_at=0 WHERE id=?').run(options.flow);
 await rejected(await f.call('/api/account/passkeys/verify',{flow:options.flow,credential:authenticator(origin).register(options.options.challenge)},account.cookie));
 const next=await ok(await f.call('/api/account/passkeys/options',{name:'Stale'},account.cookie));
 f.env.DB.sql.prepare('UPDATE sessions SET authenticated_at=? WHERE token_hash=?').run(Math.floor(Date.now()/1000)-301,tokenHash(account.cookie));
 await rejected(await f.call('/api/account/passkeys/verify',{flow:next.flow,credential:authenticator(origin).register(next.options.challenge)},account.cookie));
 await rejected(await f.call('/api/account/passkeys/rename',{id:account.key.id,name:'Stale'},account.cookie));
 const re=await ok(await f.call('/api/account/reauth/options',{},account.cookie));
 f.env.DB.sql.prepare('UPDATE account_challenges SET expires_at=0 WHERE id=?').run(re.flow);
 await rejected(await f.call('/api/account/reauth/verify',{flow:re.flow,credential:account.key.login(re.options.challenge,2)},account.cookie));
 f.env.DB.sql.prepare("UPDATE sessions SET auth_method='unknown',authenticated_at=0 WHERE token_hash=?").run(tokenHash(account.cookie));
 await rejected(await f.call('/api/account/passkeys/options',{name:'Legacy'},account.cookie));
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM passkeys').get().n,1);
});

test('revoking a session or disabling an account invalidates pending credential additions',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 let options=await ok(await f.call('/api/account/passkeys/options',{name:'Pending'},account.cookie));
 await ok(await f.call('/api/logout',{},account.cookie));
 await rejected(await f.call('/api/account/passkeys/verify',{flow:options.flow,credential:authenticator(origin).register(options.options.challenge)},account.cookie));
 account.cookie=await login(f,account,2);
 options=await ok(await f.call('/api/account/passkeys/options',{name:'Disabled'},account.cookie));
 f.env.DB.sql.prepare('UPDATE users SET active=0 WHERE id=?').run(account.user.id);
 await rejected(await f.call('/api/account/passkeys/verify',{flow:options.flow,credential:authenticator(origin).register(options.options.challenge)},account.cookie));
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM passkeys').get().n,1);
});

test('passkey names reject empty or excessive values and are server-bound to enrollment options',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 for(const name of ['', ' '.repeat(3), 'x'.repeat(201),{},null]){
  await rejected(await f.call('/api/account/passkeys/options',{name},account.cookie));
  await rejected(await f.call('/api/account/passkeys/rename',{id:account.key.id,name},account.cookie));
 }
 const options=await ok(await f.call('/api/account/passkeys/options',{name:'Intended name'},account.cookie));
 const key=authenticator(origin);
 await ok(await f.call('/api/account/passkeys/verify',{flow:options.flow,name:'Changed untrusted name',credential:key.register(options.options.challenge)},account.cookie));
 assert.equal(f.env.DB.sql.prepare('SELECT name FROM passkeys WHERE id=?').get(key.id).name,'Intended name');
});

async function emailLogin(f,email,deliveries){
 const request=await f.call('/api/email/request',{email});const data=await ok(request);
 const browserCookie=request.headers.get('set-cookie').split(';')[0];
 const message=deliveries.findLast(mail=>mail.to.includes(email)&&/\b\d{8}\b/.test(mail.text));assert.ok(message,'Code email must be sent');
 const code=message.text.match(/\b\d{8}\b/)[0];
 const response=await f.call('/api/email/verify',{flow:data.flow,code},browserCookie);await ok(response);
 return response.headers.get('set-cookie').split(';')[0];
}

test('family recovery is explicit opt-in, preserves identity, revokes other portal sessions, and sends notices',async()=>{
 const f=fixture(),admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);
 Object.assign(f.env,{RESEND_API_KEY:'test-not-a-real-key',RESEND_FROM:'sender@example.com'});
 const originalFetch=globalThis.fetch,deliveries=[];
 globalThis.fetch=async(url,init)=>{assert.equal(String(url),'https://api.resend.com/emails');deliveries.push(JSON.parse(init.body));return new Response('{"id":"test-message"}',{status:200});};
 try{
  const emailCookie=await emailLogin(f,family.email,deliveries);
  await rejected(await f.call('/api/account/passkeys/options',{name:'Not opted in'},emailCookie));
  await reauth(f,family);
  await ok(await f.call('/api/account/recovery',{enabled:true},family.cookie));
  assert.equal((await ok(await f.call('/api/account',undefined,family.cookie))).email_recovery_enabled,true);
  const before=deliveries.length;
  const options=await ok(await f.call('/api/account/passkeys/options',{name:'Recovered phone'},emailCookie));
  const key=authenticator(origin);
  await ok(await f.call('/api/account/passkeys/verify',{flow:options.flow,credential:key.register(options.options.challenge)},emailCookie));
  assert.ok(deliveries.length>before,'Recovery must send a notification to the original mailbox');
  assert.equal((await ok(await f.call('/api/me',undefined,family.cookie))).user,null,'Previous portal sessions revoked');
  assert.equal((await ok(await f.call('/api/me',undefined,emailCookie))).user.id,family.user.id);
  await rejected(await f.call('/api/account/passkeys/remove',{id:family.key.id},emailCookie));
  const recovered={...family,key,cookie:emailCookie};await reauth(f,recovered);
  await ok(await f.call('/api/account/passkeys/remove',{id:family.key.id},emailCookie));
  const signed=await login(f,recovered,2);
  const user=(await ok(await f.call('/api/me',undefined,signed))).user;
  assert.equal(user.id,family.user.id);assert.equal(user.email,family.email);assert.equal(user.role,'family');
  assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM users').get().n,2);
 }finally{globalThis.fetch=originalFetch;}
});

test('admin email fallback still signs in but cannot recover administrator credentials',async()=>{
 const f=fixture(),admin=await enroll(f);Object.assign(f.env,{RESEND_API_KEY:'test-not-a-real-key',RESEND_FROM:'sender@example.com'});
 const originalFetch=globalThis.fetch,deliveries=[];
 globalThis.fetch=async(url,init)=>{deliveries.push(JSON.parse(init.body));return new Response('{"id":"test-message"}',{status:200});};
 try{
  const cookie=await emailLogin(f,admin.email,deliveries);
  assert.equal((await ok(await f.call('/api/me',undefined,cookie))).user.id,admin.user.id);
  // Even a corrupt/legacy opt-in flag must not override the role safeguard.
  f.env.DB.sql.prepare('UPDATE users SET email_recovery_enabled=1 WHERE id=?').run(admin.user.id);
  await rejected(await f.call('/api/account/passkeys/options',{name:'Mailbox takeover'},cookie));
  await rejected(await f.call('/api/account/recovery',{enabled:true},cookie));
 }finally{globalThis.fetch=originalFetch;}
});

test('account challenge purposes cannot be substituted',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 const registration=await ok(await f.call('/api/account/passkeys/options',{name:'Purpose-bound'},account.cookie));
 await rejected(await f.call('/api/account/reauth/verify',{flow:registration.flow,credential:account.key.login(registration.options.challenge,2)},account.cookie));
 const authentication=await ok(await f.call('/api/account/reauth/options',{},account.cookie));
 await rejected(await f.call('/api/account/passkeys/verify',{flow:authentication.flow,credential:authenticator(origin).register(authentication.options.challenge)},account.cookie));
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM passkeys').get().n,1);
});

test('reauthentication rechecks revocation after asynchronous signature verification',async()=>{
 const f=fixture(),account=await enroll(f);
 const options=await ok(await f.call('/api/account/reauth/options',{},account.cookie));
 const original=crypto.subtle.verify;let reached=false;
 crypto.subtle.verify=async function(...args){
  const valid=await original.apply(this,args);reached=true;
  f.env.DB.sql.prepare('DELETE FROM sessions WHERE token_hash=?').run(tokenHash(account.cookie));return valid;
 };
 try{
  await rejected(await f.call('/api/account/reauth/verify',{flow:options.flow,credential:account.key.login(options.options.challenge)},account.cookie));
  assert.equal(reached,true,'Exercise revocation at the cryptographic await boundary');
  assert.equal((await ok(await f.call('/api/me',undefined,account.cookie))).user,null);
 }finally{crypto.subtle.verify=original;}
});

test('notification delivery failure is reported honestly without undoing the committed credential change',async()=>{
 const f=fixture(),account=await enroll(f);await reauth(f,account);
 Object.assign(f.env,{RESEND_API_KEY:'test-not-a-real-key',RESEND_FROM:'sender@example.com'});
 const originalFetch=globalThis.fetch;
 globalThis.fetch=async()=>new Response('denied',{status:403});
 try{
  const result=await ok(await f.call('/api/account/passkeys/rename',{id:account.key.id,name:'Renamed despite provider failure'},account.cookie));
  assert.equal(result.notification,'failed');
  assert.equal(f.env.DB.sql.prepare('SELECT name FROM passkeys WHERE id=?').get(account.key.id).name,'Renamed despite provider failure');
  const event=f.env.DB.sql.prepare("SELECT notification FROM security_events WHERE event='Passkey renamed'").get();
  assert.equal(event.notification,'failed');
 }finally{globalThis.fetch=originalFetch;}
});

test('reauthentication cannot revive a disabled account or a credential revoked during verification',async()=>{
 for(const revoke of ['account','key']){
  const f=fixture(),account=await enroll(f);
  const options=await ok(await f.call('/api/account/reauth/options',{},account.cookie));
  const original=crypto.subtle.verify;let reached=false;
  crypto.subtle.verify=async function(...args){
   const valid=await original.apply(this,args);reached=true;
   if(revoke==='account')f.env.DB.sql.prepare('UPDATE users SET active=0 WHERE id=?').run(account.user.id);
   else f.env.DB.sql.prepare('DELETE FROM passkeys WHERE id=?').run(account.key.id);
   return valid;
  };
  try{
   await rejected(await f.call('/api/account/reauth/verify',{flow:options.flow,credential:account.key.login(options.options.challenge)},account.cookie));
   assert.equal(reached,true);
  }finally{crypto.subtle.verify=original;}
 }
});

test('admin writes require fresh passkeys even when ordinary email sign-in and admin reads remain available',async()=>{
 const f=fixture(),admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);
 Object.assign(f.env,{ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:'secret-at-least-32-characters-for-test'});
 const requests=[
  ['/api/admin/invite',{email:'next@example.com'}],
  ['/api/admin/users',{user_id:family.user.id,action:'disable'}],
  ['/api/admin/users',{user_id:family.user.id,action:'revoke_sessions'}],
  ['/api/admin/invites/revoke',{invitation_id:'a'.repeat(64)}],
  ['/api/admin/oidc/rotate',{}],
 ];
 for(const method of ['email','unknown','stale']){
  f.env.DB.sql.prepare('UPDATE sessions SET auth_method=?,authenticated_at=? WHERE token_hash=?').run(method==='stale'?'passkey':method,Math.floor(Date.now()/1000)-(method==='stale'?301:0),tokenHash(admin.cookie));
  assert.equal((await ok(await f.call('/api/me',undefined,admin.cookie))).user.id,admin.user.id);
  await ok(await f.call('/api/admin/users',undefined,admin.cookie));
  for(const [path,data] of requests)assert.equal((await f.call(path,data,admin.cookie)).status,403,`${method} must not authorize ${path}`);
 }
 assert.equal(f.env.DB.sql.prepare('SELECT active FROM users WHERE id=?').get(family.user.id).active,1);
 await reauth(f,admin);
 await ok(await f.call('/api/admin/invite',{email:'next@example.com'},admin.cookie));
});

test('admin authorization is rechecked after a streamed request body ages the proof',async()=>{
 for(const [path,data] of [['/api/admin/users',{action:'disable'}],['/api/admin/invite',{email:'streamed@example.com'}]]){
  const f=fixture(),admin=await enroll(f),family=await enroll(f,'family@example.com',admin.cookie);
  let read=false;
  const stream=new ReadableStream({pull(controller){
   read=true;f.env.DB.sql.prepare('UPDATE sessions SET authenticated_at=? WHERE token_hash=?').run(Math.floor(Date.now()/1000)-301,tokenHash(admin.cookie));
   controller.enqueue(new TextEncoder().encode(JSON.stringify({...data,user_id:family.user.id})));controller.close();
  }},{highWaterMark:0});
  const response=await worker.fetch(new Request(origin+path,{method:'POST',headers:{origin,'content-type':'application/json',cookie:admin.cookie},body:stream,duplex:'half'}),f.env);
  assert.equal(read,true,'Test must reach the body-reading async boundary');assert.equal(response.status,403);
  assert.equal(f.env.DB.sql.prepare('SELECT active FROM users WHERE id=?').get(family.user.id).active,1);
 }
});
