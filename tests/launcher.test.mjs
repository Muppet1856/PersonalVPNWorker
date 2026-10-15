import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,createLocalJWKSet,SignJWT} from 'jose';
import {verifyLauncherAssertion,launcherPage,handleLauncher} from '../src/launcher.ts';
import worker from '../src/index.ts';
import {deploymentConfig} from '../scripts/configure.mjs';
import {readFileSync} from 'node:fs';
const env={PUBLIC_ORIGIN:'https://vpn.example.com',LAUNCHER_ORIGIN:'https://access.example.com',ACCESS_TEAM_DOMAIN:'example.cloudflareaccess.com',LAUNCHER_ACCESS_AUD:'a'.repeat(64),SITE_NAME:'Family <Access>',APP_LINKS_JSON:'[{"name":"Chat <app>","url":"https://chat.example.com"}]'};
test('launcher validates signature, issuer, audience and expiry',async()=>{
 const {privateKey,publicKey}=await generateKeyPair('RS256');const jwk=await exportJWK(publicKey);jwk.kid='test';const keys=createLocalJWKSet({keys:[jwk]});
 async function token(override={}){return new SignJWT({email:'member@example.com',...override}).setProtectedHeader({alg:'RS256',kid:'test'}).setSubject('member').setIssuedAt().setIssuer('https://'+env.ACCESS_TEAM_DOMAIN).setAudience(env.LAUNCHER_ACCESS_AUD).setExpirationTime('5m').sign(privateKey);}
 const valid=await token();assert.equal(await verifyLauncherAssertion(valid,env,keys),'member@example.com');
 await assert.rejects(verifyLauncherAssertion(valid,{...env,LAUNCHER_ACCESS_AUD:'wrong'},keys));
 await assert.rejects(verifyLauncherAssertion(valid,{...env,ACCESS_TEAM_DOMAIN:'other.cloudflareaccess.com'},keys));
 const expired=await new SignJWT({email:'member@example.com'}).setProtectedHeader({alg:'RS256',kid:'test'}).setSubject('member').setIssuedAt().setIssuer('https://'+env.ACCESS_TEAM_DOMAIN).setAudience(env.LAUNCHER_ACCESS_AUD).setExpirationTime(1).sign(privateKey);
 await assert.rejects(verifyLauncherAssertion(expired,env,keys));
 await assert.rejects(verifyLauncherAssertion(valid.slice(0,-10)+'xxxxxxxxxx',env,keys));
});
test('launcher escapes content and fails closed without Access configuration or assertion',async()=>{
 const html=launcherPage(env,'<member@example.com>');assert.ok(html.includes('Chat &lt;app&gt;'));assert.ok(html.includes('&lt;member@example.com&gt;'));assert.ok(!html.includes('<member@'));
 assert.equal((await handleLauncher(new Request(env.LAUNCHER_ORIGIN),{...env,LAUNCHER_ACCESS_AUD:''})).status,503);
 assert.equal((await handleLauncher(new Request(env.LAUNCHER_ORIGIN),env)).status,401);
 assert.equal((await handleLauncher(new Request(env.LAUNCHER_ORIGIN,{headers:{'cf-access-jwt-assertion':'invalid'}}),env)).status,403);
 assert.equal((await worker.fetch(new Request(env.LAUNCHER_ORIGIN+'/api/me'),env)).status,404);
});
test('launcher adds its own custom domain while preserving passkey origin and scope',()=>{
 const base=JSON.parse(readFileSync('wrangler.jsonc','utf8'));
 const config=deploymentConfig(env,base);assert.equal(config.vars.PUBLIC_ORIGIN,env.PUBLIC_ORIGIN);assert.equal(config.vars.RP_ID,'vpn.example.com');
 assert.deepEqual(config.routes.map(x=>x.pattern),['vpn.example.com','access.example.com']);
 for(const origin of [env.PUBLIC_ORIGIN,'https://example.cloudflareaccess.com','https://access.example.com/path','http://access.example.com'])assert.throws(()=>deploymentConfig({...env,LAUNCHER_ORIGIN:origin},base));
});
