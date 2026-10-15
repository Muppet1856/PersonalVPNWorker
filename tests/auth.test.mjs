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
