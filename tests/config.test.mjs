import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { deploymentConfig } from '../scripts/configure.mjs';
import { settings } from '../src/config.ts';
const base=JSON.parse(readFileSync('wrangler.jsonc','utf8'));
test('deployment config derives domain and only copies allowlisted settings',()=>{
 const config=deploymentConfig({PUBLIC_ORIGIN:'https://vpn.example.com',SITE_NAME:'Example Access',ADMIN_SETUP_SECRET:'must-not-be-copied'},base);
 assert.equal(config.vars.RP_ID,'vpn.example.com');assert.equal(config.vars.SITE_NAME,'Example Access');
 assert.deepEqual(config.routes,[{pattern:'vpn.example.com',custom_domain:true}]);assert.equal(config.env,undefined);
 assert.equal(JSON.stringify(config).includes('must-not-be-copied'),false);assert.equal(config.workers_dev,false);
 assert.equal(base.vars.RP_ID,'localhost');
});
test('deployment config rejects unsafe origins and invalid settings',()=>{
 for(const origin of ['http://vpn.example.com','https://user@vpn.example.com','https://vpn.example.com/path','https://vpn.example.com:8787','https://vpn.example.com?x=1'])assert.throws(()=>deploymentConfig({PUBLIC_ORIGIN:origin},base));
 assert.throws(()=>deploymentConfig({},base));
 for(const extra of [{RP_ID:'other.example.com'},{WORKER_NAME:'invalid name'},{SESSION_COOKIE_NAME:'session; Path=/'},{SESSION_TTL_SECONDS:'0'},{CHALLENGE_TTL_SECONDS:'601'}])assert.throws(()=>deploymentConfig({PUBLIC_ORIGIN:'https://vpn.example.com',...extra},base));
});
test('runtime settings apply custom lifetimes and reject invalid overrides',()=>{
 const config=settings({SITE_NAME:'Example Access',SESSION_TTL_SECONDS:'3600',INVITE_TTL_SECONDS:'7200',SESSION_COOKIE_NAME:'example_session'});
 assert.equal(config.sessionTTL,3600);assert.equal(config.inviteTTL,7200);assert.equal(config.cookieName,'example_session');assert.equal(config.siteName,'Example Access');
 assert.throws(()=>settings({SESSION_TTL_SECONDS:'NaN'}));assert.throws(()=>settings({SESSION_COOKIE_NAME:'bad;cookie'}));
});
