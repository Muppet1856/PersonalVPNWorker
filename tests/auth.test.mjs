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
 new DB(sql);assert.equal(sql.prepare('SELECT counter FROM passkeys WHERE id=?').get('key').counter,4);assert.equal(sql.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,4);
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
 new DB(sql);const invite=sql.prepare('SELECT * FROM invites').get();assert.equal(invite.token_hash,'existing-hash');assert.equal(invite.expires_at,2000000000);assert.equal(invite.created_at,0);assert.equal(sql.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,4);
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

test('remembered sign-in persists for 30 days across object restart and logout revokes it',async()=>{
 const f=fixture();const {auth}=await enroll(f);const options=await (await f.call('/api/login/options',{email:'jeff@example.com'})).json();
 const response=await f.call('/api/login/verify',{flow:options.flow,credential:auth.login(options.options.challenge),remember_me:true});assert.equal(response.status,200);
 const header=response.headers.get('set-cookie');assert.match(header,/Max-Age=2592000/);assert.match(header,/Expires=/);assert.match(header,/HttpOnly; SameSite=Lax/);
 const expires=new Date(header.match(/Expires=([^;]+)/)[1]).getTime();assert.ok(Math.abs(expires-Date.now()-2592000000)<3000);
 const latest=f.env.DB.sql.prepare('SELECT MAX(expires_at-created_at) AS ttl FROM sessions').get();assert.equal(latest.ttl,2592000);
 const cookie=header.split(';')[0];f.env.DB=new DB(f.env.DB.sql);assert.ok((await (await f.call('/api/me',undefined,cookie)).json()).user);
 await f.call('/api/logout',{},cookie);assert.equal((await (await f.call('/api/me',undefined,cookie)).json()).user,null);
});
test('unremembered sign-in uses a browser-session cookie and invalid preferences do not consume a challenge',async()=>{
 const f=fixture();const {auth}=await enroll(f);const options=await (await f.call('/api/login/options',{email:'jeff@example.com'})).json();const credential=auth.login(options.options.challenge);
 assert.equal((await f.call('/api/login/verify',{flow:options.flow,credential,remember_me:'yes'})).status,400);
 const response=await f.call('/api/login/verify',{flow:options.flow,credential,remember_me:false});assert.equal(response.status,200);
 const header=response.headers.get('set-cookie');assert.ok(!header.includes('Max-Age='));assert.ok(!header.includes('Expires='));assert.match(header,/HttpOnly/);
});
test('enrollment honors the remembered-session lifetime configuration',async()=>{
 const f=fixture();f.env.REMEMBER_ME_TTL_SECONDS='3600';const invite=await (await f.call('/api/setup',{email:'new@example.com',secret:f.env.ADMIN_SETUP_SECRET})).json();const options=await (await f.call('/api/register/options',{token:invite.token,name:'New user'})).json();
 const response=await f.call('/api/register/verify',{token:invite.token,flow:options.flow,credential:authenticator().register(options.options.challenge),remember_me:true});assert.equal(response.status,200);assert.match(response.headers.get('set-cookie'),/Max-Age=3600/);
});

test('direct portal visits launch separate tabs while app sign-in keeps re-authentication visible',async()=>{
 const f=fixture();const page=await (await f.call('/')).text();const refreshSource=page.match(/async function refresh\(\)\{[^\n]*\}/)[0];
 for(const continuing of [false,true]){
  const nodes=new Map();const node=()=>({hidden:false,dataset:{},children:[],classList:{toggle(){}},replaceChildren(){this.children=[]},append(...children){this.children.push(...children)},setAttribute(){}});
  const get=id=>{if(!nodes.has(id))nodes.set(id,node());return nodes.get(id);};let dashboard;
  const document={body:{classList:{toggle(name,value){dashboard=value;}}},createElement:()=>node()};
  const fetcher=async()=>({json:async()=>({user:{name:'Member',email:'member@example.com',role:'family'},apps:[{name:'Chat',url:'https://chat.example.com',icon:'chat'}],oidc_ready:true,email_ready:false})});
  const refresh=new Function('$','fetch','continuingLogin','document','refreshAdmin','appIcons',`let emailReady=false;return (${refreshSource});`)(get,fetcher,continuing,document,()=>{throw Error('Unexpected administrator request');},{grid:'<svg></svg>'});
  await refresh();assert.equal(dashboard,!continuing);assert.equal(get('signin').hidden,!continuing);
  const link=get('appLinks').children[0];assert.equal(link.target,continuing?'_self':'_blank');assert.equal(link.rel,'noopener noreferrer');
 }
 const finishSource=page.match(/async function finishOIDC\(\)\{[^\n]*\}/)[0];let returned;
 const finish=new Function('location','fetch',`return (${finishSource});`)({search:'?oidc_request=flow',assign:url=>{returned=url;}},async(url,init)=>{assert.equal(url,'/oidc/continue');assert.equal(init.method,'POST');return {ok:true,json:async()=>({redirect:'https://example.cloudflareaccess.com/cdn-cgi/access/callback?code=code'})};});
 await finish();assert.equal(returned,'https://example.cloudflareaccess.com/cdn-cgi/access/callback?code=code');
});

test('logout revokes the portal session and supplies only the configured Access team logout destination',async()=>{
 const f=fixture();const {cookie}=await enroll(f);f.env.ACCESS_TEAM_DOMAIN='example.cloudflareaccess.com';
 const rejected=await f.call('/api/logout',{},cookie,'https://untrusted.example');assert.equal(rejected.status,403);
 assert.ok((await (await f.call('/api/me',undefined,cookie)).json()).user);
 const response=await f.call('/api/logout',{logout_url:'https://untrusted.example'},cookie);
 assert.equal(response.status,200);assert.equal((await response.json()).logout_url,'https://example.cloudflareaccess.com/cdn-cgi/access/logout');
 assert.match(response.headers.get('set-cookie'),/family_session=;.*Max-Age=0/);
 assert.equal((await (await f.call('/api/me',undefined,cookie)).json()).user,null);
 // Repeat logout can finish Access sign-out even after the portal cookie is gone.
 assert.equal((await (await f.call('/api/logout',{})).json()).logout_url,'https://example.cloudflareaccess.com/cdn-cgi/access/logout');
 for(const team of [undefined,'example.cloudflareaccess.com.evil.test','example.cloudflareaccess.com/path','https://example.cloudflareaccess.com']){
  f.env.ACCESS_TEAM_DOMAIN=team;assert.equal((await (await f.call('/api/logout',{})).json()).logout_url,null);
 }
});

test('portal logout navigates the same browser to Access only after successful local logout',async()=>{
 const f=fixture();const page=await (await f.call('/')).text();const source=page.match(/async function logout\(\)\{[^\n]*\}/)[0];
 for(const mode of ['access','local','failure']){
  const events=[];const logout=new Function('api','location','say','refresh',`return (${source});`)(async(path,data)=>{
   events.push('local');assert.equal(path,'/api/logout');assert.deepEqual(data,{});if(mode==='failure')throw Error('Request failed');
   return {logout_url:mode==='access'?'https://example.cloudflareaccess.com/cdn-cgi/access/logout':null};
  },{assign:url=>events.push(url)},message=>events.push(message),async()=>events.push('refresh'));
  await logout();
  assert.deepEqual(events,mode==='access'?['local','Signing out of protected applications…','https://example.cloudflareaccess.com/cdn-cgi/access/logout']:mode==='local'?['local','Signed out','refresh']:['local','Error: Request failed']);
 }
});

async function emailFixture(run){
 const f=fixture();const enrolled=await enroll(f);Object.assign(f.env,{PUBLIC_ORIGIN:'https://vpn.example.com',RESEND_API_KEY:'test-only-key',RESEND_FROM:'signin@mail.example.com'});
 const call=(path,data,cookie,requestOrigin=f.env.PUBLIC_ORIGIN)=>f.call(path,data,cookie,requestOrigin);
 const sent=[];const oldFetch=globalThis.fetch;globalThis.fetch=async(url,init)=>{assert.equal(url,'https://api.resend.com/emails');sent.push(JSON.parse(init.body));return new Response('',{status:200});};
 const request=async(email='jeff@example.com')=>{const response=await call('/api/email/request',{email});assert.equal(response.status,200);const body=await response.json();const cookie=response.headers.get('set-cookie').split(';')[0];return {flow:body.flow,cookie,code:sent.at(-1)?.text.match(/\n\n(\d{8})\n/)[1],body,response};};
 try{await run({f,call,sent,request,enrolled});}finally{globalThis.fetch=oldFetch;}
}
test('email codes create remembered sessions, survive object restart, and cannot be replayed or raced',async()=>emailFixture(async({f,call,sent,request})=>{
 const x=await request('JEFF@example.com');assert.equal(sent.length,1);assert.equal(sent[0].to[0],'jeff@example.com');assert.match(x.code,/^\d{8}$/);assert.match(x.response.headers.get('set-cookie'),/HttpOnly; SameSite=Lax; Max-Age=600; Secure/);
 const stored=JSON.stringify(f.env.DB.sql.prepare('SELECT * FROM email_logins').all());assert.ok(!stored.includes(x.code));assert.ok(!stored.includes(x.flow));
 f.env.DB=new DB(f.env.DB.sql);
 const input={flow:x.flow,code:x.code,remember_me:true};const replies=await Promise.all([call('/api/email/verify',input,x.cookie),call('/api/email/verify',input,x.cookie)]);assert.deepEqual(replies.map(r=>r.status).sort(),[200,403]);
 const signed=replies.find(r=>r.status===200);assert.match(signed.headers.get('set-cookie'),/Max-Age=2592000/);const session=signed.headers.get('set-cookie').split(';')[0];
 assert.equal((await (await call('/api/me',undefined,session)).json()).user.email,'jeff@example.com');assert.equal(f.env.DB.sql.prepare('SELECT COUNT(*) AS n FROM email_logins').get().n,0);
 assert.equal((await call('/api/email/verify',input,x.cookie)).status,403);
 await call('/api/logout',{},session);assert.equal((await (await call('/api/me',undefined,session)).json()).user,null);
}));
test('email codes require the requesting browser, same origin, valid preferences and at most five guesses',async()=>emailFixture(async({call,request})=>{
 const x=await request();const input={flow:x.flow,code:x.code,remember_me:false};
 assert.equal((await call('/api/email/verify',input)).status,403);
 assert.equal((await call('/api/email/verify',input,'family_session_email=wrong')).status,403);
 assert.equal((await call('/api/email/verify',input,x.cookie,'https://evil.example')).status,403);
 assert.equal((await call('/api/email/verify',{...input,remember_me:'true'},x.cookie)).status,400);
 const wrong=x.code==='00000000'?'11111111':'00000000';for(let n=0;n<4;n++)assert.equal((await call('/api/email/verify',{...input,code:wrong},x.cookie)).status,403);
 const success=await call('/api/email/verify',input,x.cookie);assert.equal(success.status,200);assert.doesNotMatch(success.headers.get('set-cookie'),/Max-Age|Expires/);
}));
test('five wrong email guesses permanently burn the challenge; requesting a code has persistent limits',async()=>emailFixture(async({f,call,request,sent})=>{
 const x=await request();const wrong=x.code==='00000000'?'11111111':'00000000';
 const attempts=await Promise.all(Array.from({length:8},()=>call('/api/email/verify',{flow:x.flow,code:wrong},x.cookie)));assert.ok(attempts.every(r=>r.status===403));
 assert.equal((await call('/api/email/verify',{flow:x.flow,code:x.code},x.cookie)).status,403);
 assert.equal((await call('/api/email/request',{email:'jeff@example.com'})).status,429);assert.equal(sent.length,1);
 f.env.DB=new DB(f.env.DB.sql);assert.equal((await call('/api/email/request',{email:'jeff@example.com'})).status,429);
 for(let n=0;n<2;n++){f.env.DB.sql.exec("UPDATE rate_limits SET reset_at=0 WHERE key LIKE 'email-send-minute:%'");await request();}
 f.env.DB.sql.exec("UPDATE rate_limits SET reset_at=0 WHERE key LIKE 'email-send-minute:%'");assert.equal((await call('/api/email/request',{email:'jeff@example.com'})).status,429);assert.equal(sent.length,3);
}));
test('email codes expire and a newer code replaces the old challenge',async()=>emailFixture(async({f,call,request})=>{
 const old=await request();f.env.DB.sql.exec("UPDATE rate_limits SET reset_at=0 WHERE key LIKE 'email-send-minute:%'");const fresh=await request();
 assert.equal((await call('/api/email/verify',{flow:old.flow,code:old.code},old.cookie)).status,403);
 f.env.DB.sql.exec('UPDATE email_logins SET expires_at=1');assert.equal((await call('/api/email/verify',{flow:fresh.flow,code:fresh.code},fresh.cookie)).status,403);
}));
test('unknown, unenrolled and disabled addresses receive generic responses without mail or usable challenges',async()=>emailFixture(async({f,call,sent,request})=>{
 const known=await request();const unknown=await request('unknown@example.com');assert.equal(unknown.body.message,known.body.message);assert.equal(unknown.flow.length,known.flow.length);assert.equal(sent.length,1);
 assert.equal((await call('/api/email/verify',{flow:unknown.flow,code:known.code},unknown.cookie)).status,403);
 f.env.DB.sql.exec('UPDATE users SET active=0');const disabled=await request('JEFF2@example.com');assert.equal(disabled.body.message,known.body.message);
 assert.equal((await call('/api/email/verify',{flow:known.flow,code:known.code},known.cookie)).status,403);
 f.env.DB.sql.exec("DELETE FROM rate_limits WHERE key LIKE 'email-send%'");await request();assert.equal(sent.length,1);
 assert.equal((await call('/api/email/request',{email:'a\r\nb@example.com'})).status,400);
 f.env.RESEND_API_KEY='';assert.equal((await call('/api/email/request',{email:'jeff@example.com'})).status,503);
}));
test('failed mail delivery never leaves a usable email code',async()=>emailFixture(async({f,call})=>{
 let code;globalThis.fetch=async(url,init)=>{code=JSON.parse(init.body).text.match(/\n\n(\d{8})\n/)[1];return new Response('',{status:403});};
 const response=await call('/api/email/request',{email:'jeff@example.com'});const {flow}=await response.json();assert.equal(response.status,200);assert.equal(f.env.DB.sql.prepare('SELECT COUNT(*) AS n FROM email_logins').get().n,0);
 assert.equal((await call('/api/email/verify',{flow,code},response.headers.get('set-cookie').split(';')[0])).status,403);
}));
test('administrator revocation removes pending email codes before the user can sign in',async()=>emailFixture(async({f,call,request,enrolled})=>{
 const x=await request();const id=f.env.DB.sql.prepare('SELECT id FROM users').get().id;
 assert.equal((await call('/api/admin/users',{user_id:id,action:'revoke_sessions'},enrolled.cookie)).status,200);
 assert.equal((await call('/api/email/verify',{flow:x.flow,code:x.code},x.cookie)).status,403);
}));
test('email authentication completes the existing browser-bound OIDC continuation',async()=>emailFixture(async({f,call,request})=>{
 const {createHash}=await import('node:crypto');Object.assign(f.env,{ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',OIDC_CLIENT_SECRET:'secret-at-least-32-characters-for-test'});
 const callback='https://example.cloudflareaccess.com/cdn-cgi/access/callback';const params=new URLSearchParams({response_type:'code',client_id:'family-access',redirect_uri:callback,scope:'openid email',state:'email-test-state',nonce:'nonce',prompt:'login',code_challenge:createHash('sha256').update('a'.repeat(43)).digest('base64url'),code_challenge_method:'S256'});
 const started=await call('/oidc/authorize?'+params);assert.equal(started.status,302);const requestID=new URL(started.headers.get('location'),origin).searchParams.get('oidc_request');const browser=started.headers.get('set-cookie').split(';')[0];
 const x=await request();const signed=await call('/api/email/verify',{flow:x.flow,code:x.code},x.cookie);assert.equal(signed.status,200);
 const continued=await worker.fetch(new Request(origin+'/oidc/continue',{method:'POST',headers:{origin:f.env.PUBLIC_ORIGIN,'content-type':'application/x-www-form-urlencoded',cookie:browser+'; '+signed.headers.get('set-cookie').split(';')[0]},body:new URLSearchParams({request_id:requestID})}),f.env);
 assert.equal(continued.status,200);const redirect=new URL((await continued.json()).redirect);assert.equal(redirect.origin+redirect.pathname,callback);assert.equal(redirect.searchParams.get('state'),'email-test-state');assert.ok(redirect.searchParams.get('code'));
}));

test('portal logout invalidates the requesting browser email challenge',async()=>emailFixture(async({call,request})=>{
 const x=await request();assert.equal((await call('/api/logout',{},x.cookie)).status,200);
 assert.equal((await call('/api/email/verify',{flow:x.flow,code:x.code},x.cookie)).status,403);
}));
test('email code UI verifies inside the current window and continues OIDC after authentication',async()=>{
 const f=fixture();const page=await (await f.call('/')).text();assert.match(page,/autocomplete="one-time-code"/);assert.match(page,/id="sendCode"/);
 const source=page.match(/\$\('verifyCode'\)\.onclick=(async\(\)=>\{[^\n]*\});/)[1];const events=[];
 const nodes={emailCode:{value:'01234567',reportValidity:()=>true},verifyCode:{disabled:false},rememberMe:{checked:true},codeEntry:{hidden:false}};
 const handler=new Function('$','api','say','refresh','finishOIDC',`let emailFlow='flow';return (${source});`)(id=>nodes[id],async(path,data)=>{events.push('verify');assert.equal(path,'/api/email/verify');assert.deepEqual(data,{flow:'flow',code:'01234567',remember_me:true});},()=>{},async()=>events.push('refresh'),async()=>events.push('continue'));
 await handler();assert.deepEqual(events,['verify','refresh','continue']);assert.equal(nodes.emailCode.value,'');assert.equal(nodes.codeEntry.hidden,true);assert.equal(nodes.verifyCode.disabled,false);
});
