import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import { SqlStore } from './store.ts';
import { settings, type Settings } from './config.ts';

export type AuthEnv = Settings & { DB: SqlStore; PUBLIC_ORIGIN: string; RP_ID: string; ADMIN_SETUP_SECRET?: string };
type User = { id:string; email:string; name:string; role:string; active:number };
type Challenge = { id:string; user_id:string; challenge:string; expires_at:number; registration_user_id?:string; display_name?:string };
type KeyRow = { id:string; user_id:string; public_key:ArrayBuffer; counter:number; transports:string };
const now = () => Math.floor(Date.now()/1000);
const rand = () => crypto.randomUUID();
const encoder = new TextEncoder();
async function digest(value:string) { return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))].map(v=>v.toString(16).padStart(2,'0')).join(''); }
function json(data:unknown,status=200,headers:HeadersInit={}) { return new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store',...headers}}); }
const failure=(msg:string,status=400)=>json({error:msg},status);
function cookie(req:Request,name:string):string|undefined { return req.headers.get('cookie')?.split(';').map(s=>s.trim()).find(s=>s.startsWith(name+'='))?.slice(name.length+1); }
const secure=(env:AuthEnv)=>new URL(env.PUBLIC_ORIGIN).protocol==='https:'?' Secure;':'';
const sessionCookie=(token:string,env:AuthEnv)=>`${settings(env).cookieName}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${settings(env).sessionTTL};${secure(env)}`;
async function session(req:Request,env:AuthEnv):Promise<User|null>{
 const token=cookie(req,settings(env).cookieName); if(!token)return null;
 return (await env.DB.prepare(`SELECT u.id,u.email,u.name,u.role,u.active FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(await digest(token),now()).first<User>())??null;
}
async function body(req:Request):Promise<any>{
 if(!req.headers.get('content-type')?.toLowerCase().startsWith('application/json'))throw new InputError('Expected JSON',415);
 const reader=req.body?.getReader();if(!reader)throw new InputError('Missing JSON body',400);
 const chunks:Uint8Array[]=[];let length=0;
 while(true){const {done,value}=await reader.read();if(done)break;length+=value.byteLength;if(length>65536){await reader.cancel();throw new InputError('Body too large',413);}chunks.push(value);}
 const bytes=new Uint8Array(length);let offset=0;for(const chunk of chunks){bytes.set(chunk,offset);offset+=chunk.byteLength;}
 try{const result=JSON.parse(new TextDecoder().decode(bytes));if(!result||typeof result!=='object'||Array.isArray(result))throw Error();return result;}catch{throw new InputError('Invalid JSON object',400);}
}
class InputError extends Error {constructor(message:string,readonly status:number){super(message);}}

function requireOrigin(req:Request,env:AuthEnv):boolean {const origin=req.headers.get('origin');return origin===env.PUBLIC_ORIGIN;}
function html(content:string){return new Response(content,{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','content-security-policy':"default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",'x-content-type-options':'nosniff','referrer-policy':'no-referrer'}});}
async function issueSession(userId:string,env:AuthEnv){const token=rand()+rand();await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)').bind(await digest(token),userId,now()+settings(env).sessionTTL,now()).run();return token;}
const siteName=(env:AuthEnv)=>settings(env).siteName;
const escapeHtml=(text:string)=>text.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const page=(name:string)=>`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(name)}</title><style>body{font:16px system-ui;background:#101827;color:#e8f1fb;max-width:670px;margin:3rem auto;padding:0 1rem}article{background:#202c3d;border-radius:14px;padding:22px;margin-bottom:18px}input,button{padding:12px;border-radius:8px;margin:6px 4px 6px 0;font:inherit}input{width:min(95%,370px)}button{cursor:pointer;background:#58c0a7;border:0}small{color:#a9b5c7}pre{white-space:pre-wrap}</style><h1>🔐 ${escapeHtml(name)}</h1><p>Family passkey authentication · Milestone 1</p><article id="me">Checking session...</article><article><h3>Sign in</h3><input id="email" type="email" placeholder="Email address" autocomplete="username webauthn"><button id="login">Sign in with passkey</button></article><article><h3>Accept family invitation</h3><input id="invite" placeholder="Invitation token"><input id="displayName" placeholder="Display name"><button id="register">Create account with passkey</button><small>Invitations are issued by the administrator. One passkey is enrolled during registration.</small></article><article id="admin" hidden><h3>Invite family member</h3><input id="newEmail" type="email" placeholder="Email address"><button id="createInvite">Create invitation</button><small>Copy the token privately to your family member. Automated email delivery is a later milestone.</small></article><article><button id="logout">Sign out</button><pre id="message" role="status"></pre></article><script>
const $=id=>document.getElementById(id);const say=x=>$('message').textContent=typeof x==='string'?x:JSON.stringify(x,null,2);
const b64=bytes=>{let s='';for(const x of new Uint8Array(bytes))s+=String.fromCharCode(x);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')};
const bytes=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
async function api(url,data){const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.error||'Request failed');return j}
async function refresh(){const r=await fetch('/api/me');const m=await r.json();$('me').textContent=m.user?'Signed in: '+m.user.name+' ('+m.user.email+')':'Not signed in';$('admin').hidden=!m.user||m.user.role!=='admin';}
function attestationJSON(c){return {id:c.id,rawId:b64(c.rawId),type:c.type,response:{clientDataJSON:b64(c.response.clientDataJSON),attestationObject:b64(c.response.attestationObject),transports:c.response.getTransports?.()||[]},clientExtensionResults:c.getClientExtensionResults()}}
function assertionJSON(c){return {id:c.id,rawId:b64(c.rawId),type:c.type,response:{clientDataJSON:b64(c.response.clientDataJSON),authenticatorData:b64(c.response.authenticatorData),signature:b64(c.response.signature),userHandle:c.response.userHandle?b64(c.response.userHandle):undefined},clientExtensionResults:c.getClientExtensionResults()}}
$('register').onclick=async()=>{try{const t=$('invite').value.trim(),n=$('displayName').value.trim();const x=await api('/api/register/options',{token:t,name:n});x.options.challenge=bytes(x.options.challenge);x.options.user.id=bytes(x.options.user.id);x.options.excludeCredentials=(x.options.excludeCredentials||[]).map(c=>({...c,id:bytes(c.id)}));const c=await navigator.credentials.create({publicKey:x.options});await api('/api/register/verify',{flow:x.flow,token:t,name:n,credential:attestationJSON(c)});say('Account created successfully');await refresh()}catch(e){say(String(e))}};
$('login').onclick=async()=>{try{const x=await api('/api/login/options',{email:$('email').value.trim()});x.options.challenge=bytes(x.options.challenge);x.options.allowCredentials=(x.options.allowCredentials||[]).map(c=>({...c,id:bytes(c.id)}));const c=await navigator.credentials.get({publicKey:x.options});await api('/api/login/verify',{flow:x.flow,credential:assertionJSON(c)});say('Signed in');await refresh()}catch(e){say(String(e))}};
$('createInvite').onclick=async()=>{try{const r=await api('/api/admin/invite',{email:$('newEmail').value.trim()});say('Invitation token (shown once): '+r.token)}catch(e){say(String(e))}};
$('logout').onclick=async()=>{try{await api('/api/logout',{});say('Signed out');await refresh()}catch(e){say(String(e))}};refresh();
</script></html>`;

export default {async fetch(req:Request,env:AuthEnv):Promise<Response>{
 try{
 const path=new URL(req.url).pathname;
 if(req.method==='GET'&&path==='/')return html(page(siteName(env)));
 if(req.method==='GET'&&path==='/health')return json({status:'ok'});
 if(req.method==='GET'&&path==='/api/me'){const u=await session(req,env);return json({user:u});}
 if(req.method!=='POST')return failure('Not found',404);
 if(!requireOrigin(req,env))return failure('Invalid origin',403);
 const data=await body(req);
 if(path==='/api/setup'){
  if(!env.ADMIN_SETUP_SECRET || typeof data.secret!=='string'||data.secret.length!==env.ADMIN_SETUP_SECRET.length)return failure('Unavailable',403);
  const a=encoder.encode(data.secret),b=encoder.encode(env.ADMIN_SETUP_SECRET);let diff=0;for(let i=0;i<a.length;i++)diff|=a[i]^b[i];if(diff)return failure('Unavailable',403);
  const existing=await env.DB.prepare('SELECT id FROM users LIMIT 1').first();if(existing)return failure('Already initialized',409);
  const email=String(data.email||'').trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return failure('Invalid email');
  const token=rand()+rand();const created=await env.DB.prepare("INSERT INTO invites(token_hash,email,role,expires_at,created_by) VALUES(?,?,?,?,?) ON CONFLICT DO NOTHING").bind(await digest(token),email,'admin',now()+settings(env).setupInviteTTL,null).run();if(created.meta.changes!==1)return failure('Setup invitation already issued; see bootstrap recovery instructions',409);return json({token,expires_in_seconds:settings(env).setupInviteTTL});
 }
 if(path==='/api/register/options'){
  const token=String(data.token||'');const inv=await env.DB.prepare('SELECT email,role FROM invites WHERE token_hash=? AND used_at IS NULL AND expires_at>?').bind(await digest(token),now()).first<{email:string;role:string}>();if(!inv)return failure('Invitation invalid or expired',403);
  const name=String(data.name||'').trim();if(name.length<2||name.length>100)return failure('Invalid display name');
  if(await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(inv.email).first())return failure('Account already exists',409);
  const id=rand();const options=await generateRegistrationOptions({rpName:siteName(env),rpID:env.RP_ID,userName:inv.email,userDisplayName:name,userID:encoder.encode(id),attestationType:'none',authenticatorSelection:{residentKey:'preferred',userVerification:'required'},excludeCredentials:[]});
  const flow=rand();await env.DB.prepare('INSERT INTO challenges(id,user_id,kind,challenge,expires_at,registration_user_id,display_name) VALUES(?,?,?,?,?,?,?)').bind(flow,await digest(token),'register',options.challenge,now()+settings(env).challengeTTL,id,name).run();return json({flow,options});
 }
 if(path==='/api/register/verify'){
  const token=String(data.token||'');const hash=await digest(token);
  const inv=await env.DB.prepare('SELECT email,role FROM invites WHERE token_hash=? AND used_at IS NULL AND expires_at>?').bind(hash,now()).first<{email:string;role:string}>();if(!inv)return failure('Invitation invalid or expired',403);
  const ch=await env.DB.prepare('DELETE FROM challenges WHERE id=? AND user_id=? AND kind=? AND expires_at>? RETURNING *').bind(data.flow,hash,'register',now()).first<Challenge>();if(!ch)return failure('Challenge expired',403);
  const verified=await verifyRegistrationResponse({response:data.credential,expectedChallenge:ch.challenge,expectedOrigin:env.PUBLIC_ORIGIN,expectedRPID:env.RP_ID,requireUserVerification:true});
  if(!verified.verified||!verified.registrationInfo)return failure('Passkey verification failed',403);
  const c=verified.registrationInfo.credential;const userId=ch.registration_user_id;if(!userId||!ch.display_name)return failure('Challenge invalid',403);
  // SQLite batches are transactional. Only an unexpired, unused invitation can insert
  // a user; the passkey and invitation update depend on that exact user ID.
  const result=await env.DB.batch([
    env.DB.prepare('INSERT INTO users(id,email,name,role,created_at) SELECT ?,email,?,role,? FROM invites WHERE token_hash=? AND used_at IS NULL AND expires_at>?').bind(userId,ch.display_name,now(),hash,now()),
    env.DB.prepare('INSERT INTO passkeys(id,user_id,public_key,counter,transports,device_type,backed_up,created_at) SELECT ?,id,?,?,?,?,?,? FROM users WHERE id=?').bind(c.id,c.publicKey,c.counter,JSON.stringify(c.transports||[]),verified.registrationInfo.credentialDeviceType,verified.registrationInfo.credentialBackedUp?1:0,now(),userId),
    env.DB.prepare('UPDATE invites SET used_at=? WHERE token_hash=? AND used_at IS NULL AND EXISTS(SELECT 1 FROM users WHERE id=?)').bind(now(),hash,userId)
  ]);
  if(result.some(x=>!x.success||x.meta.changes!==1))return failure('Registration failed',409);
  const s=await issueSession(userId,env);return json({ok:true},200,{'set-cookie':sessionCookie(s,env)});
 }
 if(path==='/api/login/options'){
  const email=String(data.email||'').trim().toLowerCase();const u=await env.DB.prepare('SELECT id FROM users WHERE email=? AND active=1').bind(email).first<{id:string}>();if(!u)return failure('Account or passkey unavailable',403);
  const keys=await env.DB.prepare('SELECT id,transports FROM passkeys WHERE user_id=?').bind(u.id).all<{id:string;transports:string}>();if(!keys.results.length)return failure('Account or passkey unavailable',403);
  const options=await generateAuthenticationOptions({rpID:env.RP_ID,userVerification:'required',allowCredentials:keys.results.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});const flow=rand();await env.DB.prepare('INSERT INTO challenges(id,user_id,kind,challenge,expires_at) VALUES(?,?,?,?,?)').bind(flow,u.id,'login',options.challenge,now()+settings(env).challengeTTL).run();return json({flow,options});
 }
 if(path==='/api/login/verify'){
  const ch=await env.DB.prepare('DELETE FROM challenges WHERE id=? AND kind=? AND expires_at>? RETURNING *').bind(data.flow,'login',now()).first<Challenge>();if(!ch)return failure('Challenge expired',403);
  const k=await env.DB.prepare('SELECT p.* FROM passkeys p JOIN users u ON u.id=p.user_id WHERE p.id=? AND p.user_id=? AND u.active=1').bind(data.credential?.id,ch.user_id).first<KeyRow>();if(!k)return failure('Credential unavailable',403);
  const verified=await verifyAuthenticationResponse({response:data.credential,expectedChallenge:ch.challenge,expectedOrigin:env.PUBLIC_ORIGIN,expectedRPID:env.RP_ID,requireUserVerification:true,credential:{id:k.id,publicKey:new Uint8Array(k.public_key),counter:k.counter,transports:JSON.parse(k.transports)}});
  if(!verified.verified)return failure('Authentication failed',403);
  const updated=await env.DB.prepare('UPDATE passkeys SET counter=?,last_used_at=? WHERE id=? AND counter=? RETURNING id').bind(verified.authenticationInfo.newCounter,now(),k.id,k.counter).first();
  if(!updated)return failure('Please sign in again',409);
  const s=await issueSession(ch.user_id,env);return json({ok:true},200,{'set-cookie':sessionCookie(s,env)});
 }
 if(path==='/api/admin/invite'){
  const u=await session(req,env);if(!u||u.role!=='admin')return failure('Forbidden',403);
  const email=String(data.email||'').trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return failure('Invalid email');
  if(await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first())return failure('Already registered',409);
  const token=rand()+rand();await env.DB.prepare('INSERT INTO invites(token_hash,email,role,expires_at,created_by) VALUES(?,?,?,?,?)').bind(await digest(token),email,'family',now()+settings(env).inviteTTL,u.id).run();return json({token,expires_in_seconds:settings(env).inviteTTL});
 }
 if(path==='/api/logout'){
  const token=cookie(req,settings(env).cookieName);if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();return json({ok:true},200,{'set-cookie':`${settings(env).cookieName}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0;${secure(env)}`});
 }
 return failure('Not found',404);
 }catch(e){if(e instanceof InputError)return failure(e.message,e.status);console.error('Request failed');return failure('Request could not be completed',500);}
}} satisfies ExportedHandler<AuthEnv>;
