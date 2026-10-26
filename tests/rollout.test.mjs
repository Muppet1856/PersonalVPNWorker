import {test} from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {SqlStore} from '../src/store.ts';
import {schemaV1,schemaV2,schemaV3,schemaV4} from '../src/schema.ts';
import {legacyRolloutGrants} from '../src/rollout.ts';
function storage(sql){return {sql:{exec(query,...args){if(!args.length&&query.includes(';')){sql.exec(query);return {toArray:()=>[]}}const stmt=sql.prepare(query);const rows=stmt.columns().length?stmt.all(...args):(stmt.run(...args),[]);return {toArray:()=>rows,one:()=>rows[0]}}},transactionSync(fn){sql.exec('BEGIN');try{const result=fn();sql.exec('COMMIT');return result}catch(e){sql.exec('ROLLBACK');throw e}}}}
function prior(){const sql=new DatabaseSync(':memory:');sql.exec(schemaV1+schemaV2+schemaV3+schemaV4+"CREATE TABLE schema_version(version INTEGER PRIMARY KEY);INSERT INTO schema_version VALUES(4)");for(const [id,role,active]of [['existing','family',1],['inactive','family',0],['admin','admin',1]])sql.prepare('INSERT INTO users(id,email,name,role,active,created_at) VALUES(?,?,?,?,?,0)').run(id,id+'@example.com',id,role,active);return sql}
const apps={APP_LINKS_JSON:JSON.stringify([{name:'Chat',url:'https://chat.zellen.ai'},{name:'Git',url:'https://git.zellen.io'},{name:'Future',url:'https://future.example.com'}])};
test('reviewed preservation only selects exact approved configured hosts',()=>{
 assert.deepEqual(legacyRolloutGrants(apps),['chat.zellen.ai','git.zellen.io']);assert.deepEqual(legacyRolloutGrants({APP_LINKS_JSON:'[{"name":"Other","url":"https://other.example.com"}]'}),[]);assert.deepEqual(legacyRolloutGrants({}),[]);
 assert.throws(()=>legacyRolloutGrants({APP_LINKS_JSON:'[{"name":"Bad","url":"http://chat.zellen.ai"}]'}));
});
test('upgrade snapshots active existing families once; no admin/inactive/future grants or restart regrant',()=>{
 const sql=prior(),state=storage(sql);new SqlStore(state,legacyRolloutGrants(apps));
 assert.deepEqual(sql.prepare('SELECT user_id,app_id FROM user_app_permissions ORDER BY app_id').all().map(x=>({...x})),[{user_id:'existing',app_id:'chat.zellen.ai'},{user_id:'existing',app_id:'git.zellen.io'}]);
 sql.exec("DELETE FROM user_app_permissions WHERE app_id='git.zellen.io';INSERT INTO users(id,email,name,role,created_at) VALUES('new','new@example.com','New','family',0);UPDATE users SET active=1 WHERE id='inactive'");new SqlStore(state,legacyRolloutGrants(apps));
 assert.deepEqual(sql.prepare('SELECT user_id,app_id FROM user_app_permissions').all().map(x=>({...x})),[{user_id:'existing',app_id:'chat.zellen.ai'}]);assert.equal(sql.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,5);
});
test('preservation and version marker roll back together on failure',()=>{
 const sql=prior(),state=storage(sql);assert.throws(()=>new SqlStore(state,['chat.zellen.ai','chat.zellen.ai']));assert.equal(sql.prepare('SELECT MAX(version) AS v FROM schema_version').get().v,4);assert.equal(sql.prepare("SELECT COUNT(*) AS n FROM sqlite_master WHERE name='user_app_permissions'").get().n,0);new SqlStore(state,legacyRolloutGrants(apps));assert.equal(sql.prepare('SELECT COUNT(*) AS n FROM user_app_permissions').get().n,2);
});
