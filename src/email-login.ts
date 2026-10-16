import type {AuthEnv} from './auth.ts';
import {settings} from './config.ts';
import {emailConfigured,sendSignInCode} from './email.ts';
const now=()=>Math.floor(Date.now()/1000);
const random=()=>crypto.randomUUID()+crypto.randomUUID();
const hash=async(value:string)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
const json=(data:unknown,status=200,headers:HeadersInit={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}});
const bindingName=(env:AuthEnv)=>settings(env).cookieName+'_email';
const cookie=(req:Request,name:string)=>req.headers.get('cookie')?.split(';').map(v=>v.trim()).find(v=>v.startsWith(name+'='))?.slice(name.length+1)||'';
function numericCode(){let value:number;do{value=crypto.getRandomValues(new Uint32Array(1))[0];}while(value>=4200000000);return String(value%100000000).padStart(8,'0');}
// Persist rate reservations before any provider I/O. Expired windows reset even across object restarts.
function allow(env:AuthEnv,key:string,limit:number,seconds:number){const row=env.DB.prepare(`INSERT INTO rate_limits(key,count,reset_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=CASE WHEN reset_at<=? THEN 1 ELSE count+1 END,reset_at=CASE WHEN reset_at<=? THEN excluded.reset_at ELSE reset_at END RETURNING count`).bind(key,now()+seconds,now(),now()).first<{count:number}>();return !!row&&row.count<=limit;}
export async function requestEmailCode(req:Request,env:AuthEnv,data:Record<string,unknown>):Promise<Response>{
 if(!emailConfigured(env)){console.warn(JSON.stringify({event:'email_login_request',outcome:'not_configured'}));return json({error:'Email sign-in is not configured'},503);}
 const email=typeof data.email==='string'?data.email.trim().toLowerCase():'';
 if(email.length>254||! /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return json({error:'Enter a valid email address'},400);
 // Version the hourly bucket once so attempts lost to the unsupported redirect mode do not lock users out after the fix.
 const emailHash=await hash(email),ipHash=await hash(req.headers.get('cf-connecting-ip')||'local');
 if(!allow(env,'email-send-minute:'+emailHash,1,60)||!allow(env,'email-send-hour-v2:'+emailHash,3,3600)||!allow(env,'email-send-ip:'+ipHash,20,3600)||!allow(env,'email-send-day',90,86400)){console.info(JSON.stringify({event:'email_login_request',outcome:'rate_limited'}));return json({error:'Please wait before requesting another code'},429,{'retry-after':'60'});}
 const flow=random(),browser=random(),code=numericCode();
 const [id,browserHash,codeHash]=await Promise.all([hash(flow),hash(browser),hash(flow+':'+code)]);
 // Only an already enrolled active user can receive a usable code. Unknown addresses get the same public response.
 const user=env.DB.prepare('SELECT id FROM users WHERE email=? AND active=1').bind(email).first<{id:string}>();
 if(user){
  env.DB.batch([
   env.DB.prepare('DELETE FROM email_logins WHERE user_id=?').bind(user.id),
   env.DB.prepare('INSERT INTO email_logins(id,user_id,browser_hash,code_hash,attempts,expires_at) SELECT ?,id,?,?,0,? FROM users WHERE id=? AND active=1').bind(id,browserHash,codeHash,now()+600,user.id)
  ]);
  const sent=await sendSignInCode(env,email,code,id);
  console.info(JSON.stringify({event:'email_login_request',outcome:sent==='accepted'?'send_accepted':'send_failed'}));
  if(sent!=='accepted')env.DB.prepare('DELETE FROM email_logins WHERE id=?').bind(id).run();
 }else console.info(JSON.stringify({event:'email_login_request',outcome:'account_unavailable'}));
 return json({ok:true,flow,message:'If this address has an active account, a code will arrive shortly. Enter it here within 10 minutes.'},200,{'set-cookie':`${bindingName(env)}=${browser}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600; Secure;`});
}
export async function verifyEmailCode(req:Request,env:AuthEnv,data:Record<string,unknown>,ttl:number):Promise<string|null>{
 if(!emailConfigured(env)||typeof data.flow!=='string'||data.flow.length>128||typeof data.code!=='string'||!/^\d{8}$/.test(data.code))return null;
 const browser=cookie(req,bindingName(env));if(!browser||browser.length>128)return null;
 const token=random();const [id,browserHash,codeHash,tokenHash]=await Promise.all([hash(data.flow),hash(browser),hash(data.flow+':'+data.code),hash(token)]);
 // All three operations are synchronous in one SQLite transaction: guesses cannot race or codes be replayed.
 const result=env.DB.batch([
  env.DB.prepare('UPDATE email_logins SET attempts=attempts+1 WHERE id=? AND browser_hash=? AND attempts<5 AND expires_at>?').bind(id,browserHash,now()),
  env.DB.prepare(`INSERT INTO sessions(token_hash,user_id,expires_at,created_at) SELECT ?,u.id,?,? FROM email_logins e JOIN users u ON u.id=e.user_id WHERE e.id=? AND e.browser_hash=? AND e.code_hash=? AND e.attempts<=5 AND e.expires_at>? AND u.active=1`).bind(tokenHash,now()+ttl,now(),id,browserHash,codeHash,now()),
  env.DB.prepare('DELETE FROM email_logins WHERE id=? AND browser_hash=? AND (code_hash=? OR attempts>=5)').bind(id,browserHash,codeHash)
 ]);
 return result[1].meta.changes===1?token:null;
}
