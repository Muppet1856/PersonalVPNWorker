import { generateAuthenticationOptions, generateRegistrationOptions, verifyAuthenticationResponse, verifyRegistrationResponse } from '@simplewebauthn/server';
import type { AuthEnv } from './auth.ts';
import { settings } from './config.ts';
import { emailConfigured, sendSecurityNotification } from './email.ts';

const now=()=>Math.floor(Date.now()/1000);
const json=(data:unknown,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const error=(message:string,status=403)=>json({error:message},status);
const digest=async(value:string)=>Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))),b=>b.toString(16).padStart(2,'0')).join('');
type Account={id:string;email:string;name:string;role:string;email_recovery_enabled:number;auth_method:string;authenticated_at:number;credential_id:string|null};
type Key={id:string;public_key:ArrayBuffer;counter:number;transports:string};
type Challenge={challenge:string;name:string|null;expires_at:number};
// Every authorization read is live. No security decision survives an async crypto/provider boundary.
function account(env:AuthEnv,sessionHash:string):Account|null {
 return env.DB.prepare(`SELECT u.id,u.email,u.name,u.role,u.email_recovery_enabled,s.auth_method,s.authenticated_at,s.credential_id
 FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(sessionHash,now()).first<Account>();
}
function freshPasskey(env:AuthEnv,user:Account):boolean {
 return user.auth_method==='passkey'&&user.authenticated_at>now()-300&&user.authenticated_at<=now()&&!!env.DB.prepare('SELECT id FROM passkeys WHERE id=? AND user_id=?').bind(user.credential_id,user.id).first();
}
function freshRecovery(env:AuthEnv,user:Account):boolean {
 return user.role==='family'&&user.email_recovery_enabled===1&&emailConfigured(env)&&user.auth_method==='email'&&user.authenticated_at>now()-300&&user.authenticated_at<=now();
}
function validName(value:unknown):value is string {return typeof value==='string'&&value.trim().length>0&&value.trim().length<=80&&!/[\u0000-\u001f\u007f]/.test(value);}
function event(env:AuthEnv,userId:string,action:string):string {
 const id=crypto.randomUUID();env.DB.prepare('INSERT INTO security_events(id,user_id,event,created_at) VALUES(?,?,?,?)').bind(id,userId,action,now()).run();return id;
}
async function notify(env:AuthEnv,user:Account,id:string,action:string):Promise<Response> {
 const notification=emailConfigured(env)?await sendSecurityNotification(env,user.email,action,id):'unconfigured';
 env.DB.prepare('UPDATE security_events SET notification=? WHERE id=?').bind(notification,id).run();
 return json({ok:true,notification});
}
export async function handleAccount(req:Request,env:AuthEnv,data:Record<string,unknown>={}):Promise<Response> {
 const raw=req.headers.get('cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(settings(env).cookieName+'='))?.slice(settings(env).cookieName.length+1);
 if(!raw||raw.length>256)return error('Sign in to manage your account');
 const sessionHash=await digest(raw),user=account(env,sessionHash);
 if(!user)return error('Sign in to manage your account');
 const path=new URL(req.url).pathname;
 env.DB.prepare('DELETE FROM account_challenges WHERE expires_at<=?').bind(now()).run();
 if(req.method==='GET'&&path==='/api/account'){
  const manage=freshPasskey(env,user);
  return json({role:user.role,passkeys:env.DB.prepare('SELECT id,name,created_at,last_used_at FROM passkeys WHERE user_id=? ORDER BY created_at,id').bind(user.id).all().results,email_recovery_enabled:user.email_recovery_enabled===1,email_recovery_available:user.role==='family'&&emailConfigured(env),can_manage:manage,can_add:manage||freshRecovery(env,user),auth_method:user.auth_method,reauth_required:!manage});
 }
 if(req.method!=='POST')return error('Not found',404);
 if(req.headers.get('origin')!==env.PUBLIC_ORIGIN)return error('Invalid origin');
 if(path==='/api/account/reauth/options'){
  const keys=env.DB.prepare('SELECT id,transports FROM passkeys WHERE user_id=?').bind(user.id).all<{id:string;transports:string}>().results;
  if(!keys.length)return error('No passkey is available');
  const options=await generateAuthenticationOptions({rpID:env.RP_ID,userVerification:'required',allowCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
  if(!account(env,sessionHash))return error('Session expired');
  const flow=crypto.randomUUID();
  env.DB.transaction(()=>{
   env.DB.prepare("DELETE FROM account_challenges WHERE session_hash=? AND kind='reauth'").bind(sessionHash).run();
   env.DB.prepare("INSERT INTO account_challenges(id,user_id,session_hash,kind,challenge,expires_at) VALUES(?,?,?,'reauth',?,?)").bind(flow,user.id,sessionHash,options.challenge,now()+300).run();
  });
  return json({flow,options});
 }
 if(path==='/api/account/reauth/verify'){
  if(typeof data.flow!=='string'||!data.credential||typeof data.credential!=='object')return error('Invalid assertion',400);
  const ch=env.DB.prepare("DELETE FROM account_challenges WHERE id=? AND user_id=? AND session_hash=? AND kind='reauth' AND expires_at>? RETURNING challenge,expires_at").bind(data.flow,user.id,sessionHash,now()).first<Challenge>();
  if(!ch)return error('Challenge expired');
  const credential=data.credential as Parameters<typeof verifyAuthenticationResponse>[0]['response'];
  const key=env.DB.prepare('SELECT id,public_key,counter,transports FROM passkeys WHERE id=? AND user_id=?').bind(credential.id,user.id).first<Key>();
  if(!key)return error('Credential unavailable');
  let verified;try{verified=await verifyAuthenticationResponse({response:credential,expectedChallenge:ch.challenge,expectedOrigin:env.PUBLIC_ORIGIN,expectedRPID:env.RP_ID,requireUserVerification:true,credential:{id:key.id,publicKey:new Uint8Array(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});}catch{return error('Passkey verification failed');}
  if(!verified.verified)return error('Passkey verification failed');
  const changed=env.DB.transaction(()=>{
   const current=account(env,sessionHash);if(!current||current.id!==user.id||ch.expires_at<=now())return false;
   const updated=env.DB.prepare('UPDATE passkeys SET counter=?,last_used_at=? WHERE id=? AND user_id=? AND counter=?').bind(verified.authenticationInfo.newCounter,now(),key.id,user.id,key.counter).run();
   if(updated.meta.changes!==1)return false;
   env.DB.prepare("UPDATE sessions SET auth_method='passkey',authenticated_at=?,credential_id=? WHERE token_hash=?").bind(now(),key.id,sessionHash).run();return true;
  });
  return changed?json({ok:true}):error('Session or credential changed; sign in again');
 }
 if(path==='/api/account/passkeys/options'){
  if(!validName(data.name))return error('Use a passkey name of 1–80 characters',400);
  if(!freshPasskey(env,user)&&!freshRecovery(env,user))return error('Verify a passkey again, or use enabled email recovery');
  const keys=env.DB.prepare('SELECT id,transports FROM passkeys WHERE user_id=?').bind(user.id).all<{id:string;transports:string}>().results;
  if(keys.length>=20)return error('Maximum 20 passkeys; remove an unused one first',409);
  const options=await generateRegistrationOptions({rpName:settings(env).siteName,rpID:env.RP_ID,userName:user.email,userDisplayName:user.name,userID:new TextEncoder().encode(user.id),attestationType:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'},excludeCredentials:keys.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});
  const current=account(env,sessionHash);if(!current||(!freshPasskey(env,current)&&!freshRecovery(env,current)))return error('Verify your identity again');
  const flow=crypto.randomUUID();
  env.DB.transaction(()=>{
   env.DB.prepare("DELETE FROM account_challenges WHERE session_hash=? AND kind='add'").bind(sessionHash).run();
   env.DB.prepare("INSERT INTO account_challenges(id,user_id,session_hash,kind,challenge,name,expires_at) VALUES(?,?,?,'add',?,?,?)").bind(flow,user.id,sessionHash,options.challenge,(data.name as string).trim(),now()+300).run();
  });
  return json({flow,options});
 }
 if(path==='/api/account/passkeys/verify'){
  if(!freshPasskey(env,user)&&!freshRecovery(env,user))return error('Verify your identity again');
  if(typeof data.flow!=='string'||!data.credential||typeof data.credential!=='object')return error('Invalid registration',400);
  const ch=env.DB.prepare("DELETE FROM account_challenges WHERE id=? AND user_id=? AND session_hash=? AND kind='add' AND expires_at>? RETURNING challenge,name,expires_at").bind(data.flow,user.id,sessionHash,now()).first<Challenge>();
  if(!ch)return error('Challenge expired');
  let verified;try{verified=await verifyRegistrationResponse({response:data.credential as Parameters<typeof verifyRegistrationResponse>[0]['response'],expectedChallenge:ch.challenge,expectedOrigin:env.PUBLIC_ORIGIN,expectedRPID:env.RP_ID,requireUserVerification:true});}catch{return error('Passkey verification failed');}
  if(!verified.verified||!verified.registrationInfo)return error('Passkey verification failed');
  const info=verified.registrationInfo,key=info.credential;
  const result=env.DB.transaction(()=>{
   const current=account(env,sessionHash);if(!current||current.id!==user.id||ch.expires_at<=now()||(!freshPasskey(env,current)&&!freshRecovery(env,current)))return null;
   const count=env.DB.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE user_id=?').bind(user.id).first<{n:number}>();if(count!.n>=20)return null;
   if(env.DB.prepare('SELECT id FROM passkeys WHERE id=?').bind(key.id).first())return null;
   env.DB.prepare('INSERT INTO passkeys(id,user_id,public_key,counter,transports,device_type,backed_up,created_at,name) VALUES(?,?,?,?,?,?,?,?,?)').bind(key.id,user.id,key.publicKey,key.counter,JSON.stringify(key.transports||[]),info.credentialDeviceType,info.credentialBackedUp?1:0,now(),ch.name||'Passkey').run();
   const recovery=!freshPasskey(env,current),action=recovery?'Passkey added using email recovery':'Passkey added';
   if(recovery){
    env.DB.prepare('UPDATE users SET access_revision=access_revision+1 WHERE id=?').bind(user.id).run();
    env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').bind(user.id,sessionHash).run();
    for(const table of ['oidc_codes','oidc_tokens','challenges','email_logins','account_challenges'])env.DB.prepare(`DELETE FROM ${table} WHERE user_id=?`).bind(user.id).run();
   }
   return {id:event(env,user.id,action),action};
  });
  if(!result)return error('Session or credentials changed; verify again',409);
  return notify(env,user,result.id,result.action);
 }
 if(!freshPasskey(env,user))return error('Verify a passkey within the last five minutes to make this change');
 if(path==='/api/account/passkeys/rename'){
  if(typeof data.id!=='string'||!validName(data.name))return error('Invalid passkey or name',400);
  const result=env.DB.transaction(()=>{
   const changed=env.DB.prepare('UPDATE passkeys SET name=? WHERE id=? AND user_id=?').bind((data.name as string).trim(),data.id as string,user.id).run();
   return changed.meta.changes===1?event(env,user.id,'Passkey renamed'):null;
  });
  return result?notify(env,user,result,'Passkey renamed'):error('Passkey not found',404);
 }
 if(path==='/api/account/passkeys/remove'){
  if(typeof data.id!=='string')return error('Invalid passkey',400);
  // Count and delete happen inside the same synchronous transaction: two removals cannot erase the last key.
  const result=env.DB.transaction(()=>{
   if(!env.DB.prepare('SELECT id FROM passkeys WHERE id=? AND user_id=?').bind(data.id as string,user.id).first())return {status:404};
   const count=env.DB.prepare('SELECT COUNT(*) AS n FROM passkeys WHERE user_id=?').bind(user.id).first<{n:number}>();
   if(count!.n<=1)return {status:409};
   env.DB.prepare('DELETE FROM passkeys WHERE id=? AND user_id=?').bind(data.id as string,user.id).run();
   env.DB.prepare('UPDATE users SET access_revision=access_revision+1 WHERE id=?').bind(user.id).run();
   env.DB.prepare('DELETE FROM sessions WHERE user_id=? AND credential_id=?').bind(user.id,data.id as string).run();
   // Outstanding codes and bearer tokens may have originated from the removed key.
   for(const table of ['oidc_codes','oidc_tokens','challenges','account_challenges'])env.DB.prepare(`DELETE FROM ${table} WHERE user_id=?`).bind(user.id).run();
   return {id:event(env,user.id,'Passkey removed')};
  });
  return result.id?notify(env,user,result.id,'Passkey removed'):error(result.status===404?'Passkey not found':'Add a replacement before removing your last passkey',result.status);
 }
 if(path==='/api/account/recovery'){
  if(typeof data.enabled!=='boolean')return error('enabled must be a boolean',400);
  if(user.role!=='family')return error('Administrator recovery requires an existing passkey; email-only recovery is not permitted');
  if(data.enabled&&!emailConfigured(env))return error('Configure email delivery before enabling recovery',409);
  const action=data.enabled?'Email recovery enabled':'Email recovery disabled';
  const id=env.DB.transaction(()=>{
   env.DB.prepare('UPDATE users SET email_recovery_enabled=? WHERE id=?').bind(data.enabled?1:0,user.id).run();
   env.DB.prepare("DELETE FROM account_challenges WHERE user_id=? AND kind='add'").bind(user.id).run();
   return event(env,user.id,action);
  });
  return notify(env,user,id,action);
 }
 return error('Not found',404);
}
