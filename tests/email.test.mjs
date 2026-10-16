import {test} from 'node:test';
import assert from 'node:assert/strict';
import {invitationEmail,sendInvitation,emailConfigured,invitationLink,validateEmailSettings} from '../src/email.ts';
import {deploymentConfig} from '../scripts/configure.mjs';
import {readFileSync} from 'node:fs';
const env={PUBLIC_ORIGIN:'https://vpn.example.com',SITE_NAME:'Family <Access>',RESEND_FROM:'invites@mail.example.com',RESEND_REPLY_TO:'help@example.com',RESEND_API_KEY:'test-only-key'};
test('email template escapes content and uses a private fragment enrollment link',()=>{
 const mail=invitationEmail(env,'member@example.com','test-token',2000000000);
 assert.equal(mail.to[0],'member@example.com');assert.equal(mail.reply_to,'help@example.com');assert.match(mail.html,/Family &lt;Access&gt;/);
 assert.match(mail.text,/https:\/\/vpn.example.com\/#invite=test-token/);assert.ok(!mail.html.includes('Family <Access>'));
 const url=new URL(invitationLink(env.PUBLIC_ORIGIN,'private&token'));assert.equal(url.search,'');assert.equal(new URLSearchParams(url.hash.slice(1)).get('invite'),'private&token');
});
test('email retries transient failures using an identical payload and idempotency key',async()=>{
 const calls=[];const result=await sendInvitation(env,'member@example.com','private-token',2000000000,'hash-only',async(url,init)=>{calls.push({url,init});return new Response('',{status:calls.length===1?503:200});});
 assert.equal(result,'accepted');assert.equal(calls.length,2);assert.equal(calls[0].init.body,calls[1].init.body);assert.equal(calls[0].init.headers['idempotency-key'],calls[1].init.headers['idempotency-key']);assert.equal(calls[0].init.headers['idempotency-key'].includes('private-token'),false);assert.equal(calls[0].init.redirect,'error');
});
test('email permanent failures do not retry, and missing configuration sends nothing',async()=>{
 let calls=0;const fetcher=async()=>{calls++;return new Response('',{status:403});};
 assert.equal(await sendInvitation(env,'member@example.com','token',2000000000,'hash',fetcher),'failed');assert.equal(calls,1);
 assert.equal(await sendInvitation({...env,RESEND_API_KEY:''},'member@example.com','token',2000000000,'hash',fetcher),'failed');assert.equal(calls,1);
 assert.equal(emailConfigured({...env,PUBLIC_ORIGIN:'http://localhost:8787'}),false);
 assert.throws(()=>validateEmailSettings({...env,RESEND_FROM:'bad\r\nBcc: victim@example.com'}));
});
test('deployment allows only valid sender settings and never copies the Resend key',()=>{
 const config=deploymentConfig(env,JSON.parse(readFileSync('wrangler.jsonc','utf8')));assert.equal(config.vars.RESEND_FROM,env.RESEND_FROM);assert.equal(config.vars.RESEND_REPLY_TO,env.RESEND_REPLY_TO);assert.equal(JSON.stringify(config).includes(env.RESEND_API_KEY),false);
 assert.throws(()=>deploymentConfig({...env,RESEND_FROM:'bad\r\nBcc: victim@example.com'},{}));
});

test('sign-in emails contain a copyable code and no magic link or code in the subject',async()=>{
 const {signInCodeEmail,sendSignInCode}=await import('../src/email.ts');const mail=signInCodeEmail(env,'member@example.com','01234567');
 assert.match(mail.text,/01234567/);assert.match(mail.text,/same window/);assert.match(mail.html,/Family &lt;Access&gt;/);assert.ok(!mail.subject.includes('01234567'));assert.ok(!mail.html.includes('<a '));
 const calls=[];assert.equal(await sendSignInCode(env,'member@example.com','01234567','test-hash',async(url,init)=>{calls.push(init);return new Response('',{status:calls.length===1?500:200});}),'accepted');
 assert.equal(calls.length,2);assert.equal(calls[0].body,calls[1].body);assert.equal(calls[0].headers['idempotency-key'],'signin-test-hash');assert.equal(calls[1].headers['idempotency-key'],'signin-test-hash');
});
