import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { authenticator } from './authenticator.mjs';
import authWorker from '../src/auth.ts';
import { SqlStore } from '../src/store.ts';

// Execute production SqlStore/schema with SQLite and Durable Object-shaped storage.
class DB extends SqlStore {
  constructor(sql = new DatabaseSync(':memory:')) {
    sql.exec('PRAGMA foreign_keys=ON');
    const storage = {
      sql: {exec(query,...values) {
        if (!values.length && query.includes(';')) {sql.exec(query);return {toArray:()=>[]};}
        const statement=sql.prepare(query);
        const args=values.map(v=>v instanceof Uint8Array?Buffer.from(v):v);
        const rows=statement.columns().length ? statement.all(...args) : (statement.run(...args), []);
        return {toArray:()=>rows, one:()=>{assert.equal(rows.length,1);return rows[0];}};
      }},
      transactionSync(callback) {
        sql.exec('BEGIN');try {const result=callback();sql.exec('COMMIT');return result;}
        catch(e) {sql.exec('ROLLBACK');throw e;}
      },
    };
    super(storage);this.sql=sql;
  }
}
const worker=authWorker;
const origin = 'http://localhost:8787';
function fixture() {
  const env = { DB:new DB(), PUBLIC_ORIGIN:origin, RP_ID:'localhost', ADMIN_SETUP_SECRET:'test-only-bootstrap-secret' };
  return { env, async call(path, data, cookie, customOrigin=origin) {
    return worker.fetch(new Request(origin+path, { method:data===undefined?'GET':'POST', headers:{origin:customOrigin,'content-type':'application/json', ...(cookie?{cookie}:{})}, ...(data===undefined?{}:{body:JSON.stringify(data)}) }), env);
  }};
}
async function enroll(f) {
  const setup=await f.call('/api/setup',{email:'jeff@example.com',secret:f.env.ADMIN_SETUP_SECRET});assert.equal(setup.status,200);
  const {token}=await setup.json();const options=await (await f.call('/api/register/options',{token,name:'Jeff'})).json();
  const auth=authenticator();const data={token,flow:options.flow,name:'Untrusted changed name',credential:auth.register(options.options.challenge)};
  const response=await f.call('/api/register/verify',data);assert.equal(response.status,200);
  return {auth, data, options, cookie:response.headers.get('set-cookie').split(';')[0]};
}

test('passkey enrollment, sign-in, invite and logout round trip',async()=>{
  const f=fixture();const {auth,cookie,options}=await enroll(f);
  const user=(await (await f.call('/api/me',undefined,cookie)).json()).user;
  assert.equal(user.name,'Jeff');assert.equal(user.role,'admin');
  assert.equal(Buffer.from(options.options.user.id,'base64url').toString(),user.id);
  const invite=await f.call('/api/admin/invite',{email:'family@example.com'},cookie);assert.equal(invite.status,200);
  const login=await (await f.call('/api/login/options',{email:'jeff@example.com'})).json();
  const signed=await f.call('/api/login/verify',{flow:login.flow,credential:auth.login(login.options.challenge)});assert.equal(signed.status,200);
  const session=signed.headers.get('set-cookie').split(';')[0];assert.match(signed.headers.get('set-cookie'),/HttpOnly/);
  await f.call('/api/logout',{},session);assert.equal((await (await f.call('/api/me',undefined,session)).json()).user,null);
});
test('registration challenge and invitation cannot be replayed',async()=>{
  const f=fixture();const {data}=await enroll(f);assert.equal((await f.call('/api/register/verify',data)).status,403);
});
test('login assertion challenge is one time, including concurrent submissions',async()=>{
  const f=fixture();const {auth}=await enroll(f);const login=await (await f.call('/api/login/options',{email:'jeff@example.com'})).json();
  const data={flow:login.flow,credential:auth.login(login.options.challenge)};
  const responses=await Promise.all([f.call('/api/login/verify',data),f.call('/api/login/verify',data)]);
  assert.deepEqual(responses.map(x=>x.status).sort(),[200,403]);
});
test('only one bootstrap invitation can be outstanding',async()=>{
  const f=fixture();const request={email:'jeff@example.com',secret:f.env.ADMIN_SETUP_SECRET};
  const responses=await Promise.all([f.call('/api/setup',request),f.call('/api/setup',request)]);
  assert.deepEqual(responses.map(x=>x.status).sort(),[200,409]);
});
test('wrong origins and unauthorized invitations are rejected',async()=>{
  const f=fixture();assert.equal((await f.call('/api/setup',{},undefined,'https://evil.example')).status,403);
  assert.equal((await f.call('/api/admin/invite',{email:'family@example.com'})).status,403);
  assert.equal((await f.call('/api/setup',{email:'bad',secret:f.env.ADMIN_SETUP_SECRET})).status,400);
});
test('expired registration challenges do not enroll accounts',async()=>{
  const f=fixture();const {token}=await (await f.call('/api/setup',{email:'jeff@example.com',secret:f.env.ADMIN_SETUP_SECRET})).json();
  const o=await (await f.call('/api/register/options',{token,name:'Jeff'})).json();f.env.DB.sql.exec('UPDATE challenges SET expires_at=0');
  assert.equal((await f.call('/api/register/verify',{token,flow:o.flow,credential:authenticator().register(o.options.challenge)})).status,403);
  assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM users').get().n,0);
});
test('disabled accounts cannot finish an in-flight login or use sessions',async()=>{
  const f=fixture();const {auth,cookie}=await enroll(f);const o=await (await f.call('/api/login/options',{email:'jeff@example.com'})).json();
  f.env.DB.sql.exec('UPDATE users SET active=0');assert.equal((await f.call('/api/login/verify',{flow:o.flow,credential:auth.login(o.options.challenge)})).status,403);
  assert.equal((await (await f.call('/api/me',undefined,cookie)).json()).user,null);
});
test('actual streamed request size is limited and invalid JSON is rejected',async()=>{
  const f=fixture();for(const [body,status] of [['x'.repeat(65537),413],['{',400],['null',400]]) {
    const r=await worker.fetch(new Request(origin+'/api/setup',{method:'POST',headers:{origin,'content-type':'application/json'},body}),f.env);assert.equal(r.status,status);
  }
});

test('schema initialization preserves existing accounts on object restart',async()=>{const f=fixture();await enroll(f);new DB(f.env.DB.sql);assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM users').get().n,1);});

test('OIDC migration preserves the previous passkey schema and existing users',async()=>{
 const {schemaV1}=await import('../src/schema.ts');const sql=new DatabaseSync(':memory:');
 sql.exec(schemaV1);sql.exec("CREATE TABLE schema_version(version INTEGER PRIMARY KEY);INSERT INTO schema_version VALUES(1);INSERT INTO users(id,email,name,role,created_at) VALUES('existing','existing@example.com','Existing','admin',1)");
 sql.prepare('INSERT INTO passkeys(id,user_id,public_key,counter,device_type,created_at) VALUES(?,?,?,?,?,?)').run('key','existing',Buffer.from([1,2,3]),4,'singleDevice',1);
 new DB(sql);assert.equal(sql.prepare('SELECT counter FROM passkeys WHERE id=?').get('key').counter,4);assert.equal(sql.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,3);
 assert.ok(sql.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='oidc_keys'").get());
});
test('OIDC expired codes and disabled accounts cannot obtain identity tokens',async()=>{
 const {createHash}=await import('node:crypto');const hash=x=>createHash('sha256').update(x).digest('base64url');
 const f=fixture();await enroll(f);Object.assign(f.env,{ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:'secret-at-least-32-characters-for-test'});
 const user=f.env.DB.sql.prepare('SELECT id FROM users').get();const callback='https://example.cloudflareaccess.com/cdn-cgi/access/callback';const verifier='a'.repeat(43);
 const insert=(token,expires)=>f.env.DB.sql.prepare('INSERT INTO oidc_codes(token_hash,user_id,client_id,redirect_uri,scope,challenge,auth_time,expires_at) VALUES(?,?,?,?,?,?,?,?)').run(hash(token),user.id,'family-access',callback,'openid',hash(verifier),1,expires);
 const exchange=code=>worker.fetch(new Request(origin+'/oidc/token',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({grant_type:'authorization_code',client_id:'family-access',client_secret:f.env.OIDC_CLIENT_SECRET,redirect_uri:callback,code_verifier:verifier,code})}),f.env);
 insert('expired',1);assert.equal((await exchange('expired')).status,400);
 insert('disabled',Math.floor(Date.now()/1000)+100);f.env.DB.sql.exec('UPDATE users SET active=0');assert.equal((await exchange('disabled')).status,400);
});

test('invitations expose private links, enforce concurrent cooldown and preserve one-time enrollment',async()=>{
 const f=fixture();const {cookie}=await enroll(f);
 const replies=await Promise.all([f.call('/api/admin/invite',{email:'family@example.com'},cookie),f.call('/api/admin/invite',{email:'family@example.com'},cookie)]);
 assert.deepEqual(replies.map(r=>r.status).sort(),[200,429]);const result=await replies.find(r=>r.status===200).json();
 assert.equal(result.delivery,'manual');const url=new URL(result.invitation_url);assert.equal(new URLSearchParams(url.hash.slice(1)).get('invite'),result.token);
 const o=await (await f.call('/api/register/options',{token:result.token,name:'Family'})).json();assert.ok(o.options.challenge);
 // Keep three attempts inside an hour, moving each beyond the per-minute cooldown.
 for(let n=0;n<2;n++){f.env.DB.sql.exec("UPDATE invites SET created_at=created_at-61 WHERE role='family'");assert.equal((await f.call('/api/admin/invite',{email:'family@example.com'},cookie)).status,200);}
 f.env.DB.sql.exec("UPDATE invites SET created_at=created_at-61 WHERE role='family'");assert.equal((await f.call('/api/admin/invite',{email:'family@example.com'},cookie)).status,429);
});
test('administrator email invitation sends only after authorization and keeps fallback on provider rejection',async(t)=>{
 const f=fixture();const {cookie}=await enroll(f);Object.assign(f.env,{RESEND_FROM:'invites@mail.example.com',RESEND_API_KEY:'fake-key'});
 // A matching HTTPS origin is required before outbound delivery is enabled.
 assert.equal((await f.call('/api/admin/invite',{email:'family@example.com',send_email:true},cookie)).status,503);
 const httpsOrigin='https://vpn.example.com';f.env.PUBLIC_ORIGIN=httpsOrigin;
 const call=(email,cookieValue)=>worker.fetch(new Request(httpsOrigin+'/api/admin/invite',{method:'POST',headers:{origin:httpsOrigin,'content-type':'application/json',...(cookieValue?{cookie:cookieValue}:{})},body:JSON.stringify({email,send_email:true})}),f.env);
 let sends=0;const original=globalThis.fetch;t.after(()=>{globalThis.fetch=original;});globalThis.fetch=async()=>{sends++;return new Response('',{status:sends===1?200:403});};
 assert.equal((await call('family@example.com')).status,403);assert.equal(sends,0);
 const accepted=await (await call('family@example.com',cookie)).json();assert.equal(accepted.delivery,'accepted');assert.equal(sends,1);
 const failed=await (await call('other@example.com',cookie)).json();assert.equal(failed.delivery,'failed');assert.ok(failed.invitation_url);assert.ok(failed.token);assert.equal(sends,2);
});
test('portal consumes invitation fragments without an automatic enrollment request',async()=>{
 const f=fixture();const html=await (await f.call('/')).text();assert.match(html,/location.hash.slice\(1\)/);assert.match(html,/history.replaceState/);assert.match(html,/Create and email invitation/);
 const script=html.match(/<script>([\s\S]*)<\/script>/)[1];new Function(script);
});
test('email schema migration preserves existing v2 invitations and passkey accounts',async()=>{
 const {schemaV1,schemaV2}=await import('../src/schema.ts');const sql=new DatabaseSync(':memory:');sql.exec(schemaV1);sql.exec(schemaV2);sql.exec('CREATE TABLE schema_version(version INTEGER PRIMARY KEY);INSERT INTO schema_version VALUES(2)');
 sql.prepare('INSERT INTO invites(token_hash,email,role,expires_at,created_by) VALUES(?,?,?,?,?)').run('existing-hash','family@example.com','family',2000000000,'existing-admin');
 new DB(sql);const invite=sql.prepare('SELECT * FROM invites').get();assert.equal(invite.token_hash,'existing-hash');assert.equal(invite.expires_at,2000000000);assert.equal(invite.created_at,0);assert.equal(sql.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,3);
});

test('user management is administrator-only and rejects cross-origin mutations',async()=>{
 const f=fixture();const {cookie}=await enroll(f);
 for(const path of ['/api/admin/users','/api/admin/invites'])assert.equal((await f.call(path)).status,403);
 assert.equal((await f.call('/api/admin/users',{user_id:'missing',action:'disable'},cookie,'https://evil.example')).status,403);
 const users=await (await f.call('/api/admin/users',undefined,cookie)).json();assert.equal(users.users.length,1);assert.equal(users.users[0].passkey_count,1);assert.equal(users.users[0].session_count,1);assert.equal(users.users[0].role,'admin');
 assert.equal(JSON.stringify(users).includes('public_key'),false);assert.equal(JSON.stringify(users).includes('token_hash'),false);
 assert.equal((await f.call('/api/admin/users',{user_id:users.users[0].id,action:'disable'},cookie)).status,409);
 assert.equal((await f.call('/api/me',undefined,cookie)).status,200);
});
async function enrollFamily(f,adminCookie){
 const invite=await (await f.call('/api/admin/invite',{email:'family@example.com'},adminCookie)).json();const o=await (await f.call('/api/register/options',{token:invite.token,name:'Family <member>'})).json();const auth=authenticator();const registered=await f.call('/api/register/verify',{token:invite.token,flow:o.flow,credential:auth.register(o.options.challenge)});assert.equal(registered.status,200);const cookie=registered.headers.get('set-cookie').split(';')[0];
 return {auth,cookie,user:(await (await f.call('/api/me',undefined,cookie)).json()).user};
}
test('disable clears family sessions and OIDC credentials; enabling preserves passkeys and requires fresh login',async()=>{
 const f=fixture();const admin=await enroll(f);const family=await enrollFamily(f,admin.cookie);
 assert.equal((await f.call('/api/admin/users',undefined,family.cookie)).status,403);
 assert.equal((await f.call('/api/admin/users',{user_id:admin.data.credential.id,action:'disable'},family.cookie)).status,403);
 f.env.DB.sql.prepare('INSERT INTO oidc_tokens(token_hash,user_id,scope,expires_at) VALUES(?,?,?,?)').run('test-access-token',family.user.id,'openid',2000000000);
 const disable=await f.call('/api/admin/users',{user_id:family.user.id,action:'disable'},admin.cookie);assert.equal(disable.status,200);
 assert.equal((await (await f.call('/api/me',undefined,family.cookie)).json()).user,null);assert.equal((await f.call('/api/login/options',{email:family.user.email})).status,403);
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM oidc_tokens WHERE user_id=?').get(family.user.id).n,0);
 assert.equal((await f.call('/api/admin/users',{user_id:family.user.id,action:'enable'},admin.cookie)).status,200);
 assert.equal((await (await f.call('/api/me',undefined,family.cookie)).json()).user,null);
 const options=await (await f.call('/api/login/options',{email:family.user.email})).json();assert.equal((await f.call('/api/login/verify',{flow:options.flow,credential:family.auth.login(options.options.challenge)})).status,200);
 const list=await (await f.call('/api/admin/users',undefined,admin.cookie)).json();assert.equal(list.users.find(u=>u.id===family.user.id).passkey_count,1);
});
test('sign out everywhere invalidates sessions without removing the account or its passkey',async()=>{
 const f=fixture();const admin=await enroll(f);const family=await enrollFamily(f,admin.cookie);
 assert.equal((await f.call('/api/admin/users',{user_id:family.user.id,action:'revoke_sessions'},admin.cookie)).status,200);
 assert.equal((await (await f.call('/api/me',undefined,family.cookie)).json()).user,null);
 assert.equal((await f.call('/api/login/options',{email:family.user.email})).status,200);
 assert.equal((await f.call('/api/admin/users',{user_id:'missing',action:'revoke_sessions'},admin.cookie)).status,404);
 assert.equal((await f.call('/api/admin/users',{user_id:family.user.id,action:'promote'},admin.cookie)).status,400);
});
test('revoking a pending invitation blocks in-flight enrollment and does not touch enrolled users',async()=>{
 const f=fixture();const admin=await enroll(f);const invitation=await (await f.call('/api/admin/invite',{email:'pending@example.com'},admin.cookie)).json();
 const pending=await (await f.call('/api/admin/invites',undefined,admin.cookie)).json();assert.equal(pending.invitations.length,1);assert.equal(JSON.stringify(pending).includes(invitation.token),false);const id=pending.invitations[0].id;
 const options=await (await f.call('/api/register/options',{token:invitation.token,name:'Pending'})).json();
 assert.equal((await f.call('/api/admin/invites/revoke',{invitation_id:id})).status,403);
 assert.equal((await f.call('/api/admin/invites/revoke',{invitation_id:id},admin.cookie)).status,200);
 assert.equal((await f.call('/api/register/verify',{token:invitation.token,flow:options.flow,credential:authenticator().register(options.options.challenge)})).status,403);
 assert.equal((await (await f.call('/api/admin/invites',undefined,admin.cookie)).json()).invitations.length,0);
 assert.equal((await f.call('/api/admin/invites/revoke',{invitation_id:id},admin.cookie)).status,409);
 assert.equal(f.env.DB.sql.prepare('SELECT count(*) AS n FROM users').get().n,1);
});
