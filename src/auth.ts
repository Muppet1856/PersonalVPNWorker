import { uiAsset } from './ui-assets.ts';
import {
  generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse,
} from '@simplewebauthn/server';

import { emailConfigured, invitationLink, sendInvitation, type EmailEnv } from './email.ts';
import { portalShell } from './portal.ts';
import { APP_ICONS, appIconKey } from './icons.ts';
import { manageUsers } from './admin.ts';
import { SqlStore } from './store.ts';
import { settings, type Settings } from './config.ts';
import { handleOIDC, throttle, cleanup, oidcConfigured } from './oidc.ts';

export type AuthEnv = Settings & EmailEnv & { DB: SqlStore; PUBLIC_ORIGIN: string; RP_ID: string; ADMIN_SETUP_SECRET?: string; ACCESS_TEAM_DOMAIN?: string; OIDC_CLIENT_ID?: string; OIDC_CLIENT_SECRET?: string; APP_LINKS_JSON?: string; LAUNCHER_ORIGIN?: string; LAUNCHER_ACCESS_AUD?: string };
export type User = { id:string; email:string; name:string; role:string; active:number; auth_time:number };
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
function sessionPolicy(data:Record<string,unknown>,env:AuthEnv){
 if(data.remember_me!==undefined&&typeof data.remember_me!=='boolean')throw new InputError('remember_me must be a boolean',400);
 return {ttl:data.remember_me===true?settings(env).rememberTTL:settings(env).sessionTTL,persistent:data.remember_me!==false};
}
function sessionCookie(token:string,env:AuthEnv,policy:{ttl:number;persistent:boolean}){
 const expiry=policy.persistent?` Max-Age=${policy.ttl}; Expires=${new Date((now()+policy.ttl)*1000).toUTCString()};`:'';
 return `${settings(env).cookieName}=${token}; HttpOnly; SameSite=Lax; Path=/;${expiry}${secure(env)}`;
}
async function session(req:Request,env:AuthEnv):Promise<User|null>{
 const token=cookie(req,settings(env).cookieName); if(!token)return null;
 return (await env.DB.prepare(`SELECT u.id,u.email,u.name,u.role,u.active,s.created_at AS auth_time FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token_hash=? AND s.expires_at>? AND u.active=1`).bind(await digest(token),now()).first<User>())??null;
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
async function issueSession(userId:string,env:AuthEnv,ttl=settings(env).sessionTTL){const token=rand()+rand();const inserted=await env.DB.prepare('INSERT INTO sessions(token_hash,user_id,expires_at,created_at) SELECT ?,id,?,? FROM users WHERE id=? AND active=1').bind(await digest(token),now()+ttl,now(),userId).run();if(inserted.meta.changes!==1)throw new InputError('Account unavailable',403);return token;}
const siteName=(env:AuthEnv)=>settings(env).siteName;
const page=(name:string)=>portalShell(name)+`<script>
const appIcons=${JSON.stringify(APP_ICONS)};
let emailReady=false;
const continuingLogin=new URLSearchParams(location.search).has('oidc_request');
const $=id=>document.getElementById(id);const say=x=>{const text=typeof x==='string'?x:JSON.stringify(x,null,2);$('message').textContent=text;const failed=text.startsWith('Error:');$('message').classList.toggle('alert-danger',failed);$('message').classList.toggle('alert-success',!failed);};
const b64=bytes=>{let s='';for(const x of new Uint8Array(bytes))s+=String.fromCharCode(x);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')};
const bytes=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
async function api(url,data){const r=await fetch(url,{method:'POST',headers:{'content-type':'application/json'},credentials:'same-origin',body:JSON.stringify(data)});const j=await r.json();if(!r.ok)throw Error(j.error||'Request failed');return j}
async function finishOIDC(){const id=new URLSearchParams(location.search).get('oidc_request');if(!id)return;const r=await fetch('/oidc/continue',{method:'POST',headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({request_id:id})});const result=await r.json();if(!r.ok)throw Error(result.error||'Could not continue login');location.assign(result.redirect);}
$('oidcNotice').hidden=!continuingLogin;
async function refresh(){const r=await fetch('/api/me');const m=await r.json();const showDashboard=!!m.user&&!continuingLogin;emailReady=!!m.email_ready;$('createInvite').textContent=emailReady?'Create and email invitation':'Create invitation link';$('inviteHelp').textContent=emailReady?'An invitation email will be sent to this address.':'Share invitation links privately with the person you are inviting.';document.body.classList.toggle('logged-in',showDashboard);$('logout').hidden=!m.user;if(continuingLogin)$('oidcNotice').textContent=m.user?'Confirm your passkey to continue to your application.':'Sign in with your passkey to continue to your application.';$('me').textContent=m.user?'Signed in: '+m.user.name+' ('+m.user.email+')':'Not signed in';$('admin').hidden=!showDashboard||m.user.role!=='admin';$('management').hidden=$('admin').hidden;$('adminColumn').hidden=$('admin').hidden;$('appsColumn').className=$('admin').hidden?'col-12':'col-lg-8';$('signin').hidden=showDashboard;$('enroll').hidden=!!m.user;if($('admin').hidden){$('usersList').replaceChildren();$('invitesList').replaceChildren();}$('connections').hidden=!showDashboard;$('appLinks').replaceChildren();for(const app of m.apps||[]){const a=document.createElement('a');const url=new URL(app.url);if(url.protocol!=='https:')continue;a.href=url.href;a.target=continuingLogin?'_self':'_blank';a.rel='noopener noreferrer';a.className='app-tile';const icon=document.createElement('span');icon.className='app-icon';icon.dataset.icon=app.icon;icon.innerHTML=Object.hasOwn(appIcons,app.icon)?appIcons[app.icon]:appIcons.grid;const copy=document.createElement('span');const title=document.createElement('span');title.className='app-title';title.textContent=app.name;const host=document.createElement('span');host.className='app-host';host.textContent=url.hostname;copy.append(title,host);const arrow=document.createElement('span');arrow.className='app-arrow';arrow.textContent='↗';arrow.setAttribute('aria-hidden','true');a.append(icon,copy,arrow);$('appLinks').append(a);}if(m.user&&!(m.apps||[]).length)$('appLinks').textContent=m.oidc_ready?'Open a protected application to sign in through Cloudflare Access.':'Cloudflare Access connection is not configured yet.';if(!$('management').hidden)await refreshAdmin();}


function memberText(parent,tag,text){const node=document.createElement(tag);node.textContent=text;parent.append(node);return node;}
function memberButton(parent,label,action,danger=false){const button=document.createElement('button');button.type='button';button.textContent=label;button.className=danger?'btn btn-sm btn-outline-danger':'btn btn-sm btn-outline-secondary';button.onclick=async()=>{button.disabled=true;try{await action();await refresh()}catch(e){say(String(e));button.disabled=false}};parent.append(button);}
async function readAdmin(path){const r=await fetch(path,{credentials:'same-origin'});const data=await r.json();if(!r.ok)throw Error(data.error||'Could not load administration data');return data;}
async function refreshAdmin(){
 const [members,pending]=await Promise.all([readAdmin('/api/admin/users'),readAdmin('/api/admin/invites')]);
 $('usersList').replaceChildren();$('invitesList').replaceChildren();
 for(const user of members.users){const row=document.createElement('section');row.className='member';memberText(row,'strong',user.name);memberText(row,'p',user.email);memberText(row,'small',(user.role==='admin'?'Administrator':'Family member')+' · '+(user.active?'Active':'Disabled')+' · '+user.passkey_count+' passkey(s) · '+user.session_count+' portal session(s)');memberText(row,'small',user.last_sign_in?'Last sign-in: '+new Date(user.last_sign_in*1000).toLocaleString():'No passkey sign-in recorded');
 if(user.role!=='admin')memberButton(row,user.active?'Disable account':'Enable account',async()=>{if(user.active&&!confirm('Disable '+user.email+' and sign out their portal sessions?'))return;await api('/api/admin/users',{user_id:user.id,action:user.active?'disable':'enable'});say(user.active?'Account disabled.':'Account enabled.');},!!user.active);
 memberButton(row,'Sign out everywhere',async()=>{if(!confirm('Sign out all portal sessions for '+user.email+'? Cloudflare Access sessions are managed separately.'))return;await api('/api/admin/users',{user_id:user.id,action:'revoke_sessions'});say('Portal sessions revoked.');});$('usersList').append(row);}
 for(const invitation of pending.invitations){const row=document.createElement('section');row.className='member';memberText(row,'strong',invitation.email);memberText(row,'small','Expires: '+new Date(invitation.expires_at*1000).toLocaleString());if(invitation.role!=='admin')memberButton(row,'Revoke invitation',async()=>{if(!confirm('Revoke the unused invitation for '+invitation.email+'?'))return;await api('/api/admin/invites/revoke',{invitation_id:invitation.id});say('Invitation revoked.');},true);$('invitesList').append(row);}
 if(!pending.invitations.length)memberText($('invitesList'),'small','No pending invitations.');
 if(members.limited)memberText($('usersList'),'small','Showing the first 200 users.');if(pending.limited)memberText($('invitesList'),'small','Showing the first 200 invitations.');
}
$('refreshUsers').onclick=async()=>{try{await refreshAdmin();say('User list refreshed.')}catch(e){say(String(e))}};

function attestationJSON(c){return {id:c.id,rawId:b64(c.rawId),type:c.type,response:{clientDataJSON:b64(c.response.clientDataJSON),attestationObject:b64(c.response.attestationObject),transports:c.response.getTransports?.()||[]},clientExtensionResults:c.getClientExtensionResults()}}
function assertionJSON(c){return {id:c.id,rawId:b64(c.rawId),type:c.type,response:{clientDataJSON:b64(c.response.clientDataJSON),authenticatorData:b64(c.response.authenticatorData),signature:b64(c.response.signature),userHandle:c.response.userHandle?b64(c.response.userHandle):undefined},clientExtensionResults:c.getClientExtensionResults()}}
$('register').onclick=async()=>{try{const t=$('invite').value.trim(),n=$('displayName').value.trim();const x=await api('/api/register/options',{token:t,name:n});x.options.challenge=bytes(x.options.challenge);x.options.user.id=bytes(x.options.user.id);x.options.excludeCredentials=(x.options.excludeCredentials||[]).map(c=>({...c,id:bytes(c.id)}));const c=await navigator.credentials.create({publicKey:x.options});await api('/api/register/verify',{flow:x.flow,token:t,name:n,credential:attestationJSON(c),remember_me:$('rememberEnrollment').checked});say('Account created successfully');await refresh();await finishOIDC()}catch(e){say(String(e))}};
$('email').addEventListener('keydown',event=>{if(event.key==='Enter')$('login').click()});
$('login').onclick=async()=>{if(!$('email').reportValidity())return;const button=$('login');button.disabled=true;try{const x=await api('/api/login/options',{email:$('email').value.trim()});x.options.challenge=bytes(x.options.challenge);x.options.allowCredentials=(x.options.allowCredentials||[]).map(c=>({...c,id:bytes(c.id)}));const c=await navigator.credentials.get({publicKey:x.options});await api('/api/login/verify',{flow:x.flow,credential:assertionJSON(c),remember_me:$('rememberMe').checked});say('Signed in');await refresh();await finishOIDC()}catch(e){say(String(e))}finally{button.disabled=false}};
$('createInvite').onclick=async()=>{if(!$('newEmail').reportValidity())return;const button=$('createInvite');button.disabled=true;try{const r=await api('/api/admin/invite',{email:$('newEmail').value.trim(),send_email:emailReady});say((r.delivery==='accepted'?'Invitation email accepted for delivery.':r.delivery==='failed'?'Email could not be confirmed. Share this private link instead; an email may still arrive.':'Invitation created. Share this private link:')+'\\n'+r.invitation_url);await refreshAdmin()}catch(e){say(String(e))}finally{button.disabled=false}};
$('rotateKey').onclick=async()=>{try{const r=await api('/api/admin/oidc/rotate',{});say('Signing key rotated. Existing public keys remain available for 24 hours. New key: '+r.kid)}catch(e){say(String(e))}};
const invitation=new URLSearchParams(location.hash.slice(1)).get('invite');if(invitation){$('enroll').open=true;$('invite').value=invitation;history.replaceState(null,'',location.pathname+location.search);$('displayName').focus();}
$('logout').onclick=async()=>{try{await api('/api/logout',{});say('Signed out');await refresh()}catch(e){say(String(e))}};refresh().catch(e=>say(String(e)));
</script></body></html>`;

export default {async fetch(req:Request,env:AuthEnv):Promise<Response>{
 try{
 const asset=uiAsset(req);if(asset)return asset;
 const path=new URL(req.url).pathname;
 if((req.method==='POST'||path==='/oidc/authorize')&&!throttle(req,env))return json({error:'Too many requests; try again shortly'},429,{'retry-after':'60'});
 cleanup(env);
 if(path.startsWith('/oidc/')||path==='/.well-known/openid-configuration'||path==='/api/admin/oidc/rotate')return await handleOIDC(req,env,()=>session(req,env));
 if(req.method==='GET'&&path==='/')return html(page(siteName(env)));
 if(req.method==='GET'&&path==='/health')return json({status:'ok'});
 if(req.method==='GET'&&path==='/api/me'){const u=await session(req,env);return json({user:u,apps:u?JSON.parse(env.APP_LINKS_JSON||'[]').map((app:{name:string;url:string;icon?:string})=>({...app,icon:appIconKey(app.name,app.url,app.icon)})):[],oidc_ready:oidcConfigured(env),email_ready:!!u&&u.role==='admin'&&emailConfigured(env)});}
 if(req.method==='GET'&&(path==='/api/admin/users'||path==='/api/admin/invites'))return manageUsers(req,env,await session(req,env));
 if(req.method!=='POST')return failure('Not found',404);
 if(!requireOrigin(req,env))return failure('Invalid origin',403);
 const data=await body(req);
 if(path==='/api/admin/users'||path==='/api/admin/invites/revoke')return manageUsers(req,env,await session(req,env),data);
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
  const policy=sessionPolicy(data,env);
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
  const s=await issueSession(userId,env,policy.ttl);return json({ok:true},200,{'set-cookie':sessionCookie(s,env,policy)});
 }
 if(path==='/api/login/options'){
  const email=String(data.email||'').trim().toLowerCase();const u=await env.DB.prepare('SELECT id FROM users WHERE email=? AND active=1').bind(email).first<{id:string}>();if(!u)return failure('Account or passkey unavailable',403);
  const keys=await env.DB.prepare('SELECT id,transports FROM passkeys WHERE user_id=?').bind(u.id).all<{id:string;transports:string}>();if(!keys.results.length)return failure('Account or passkey unavailable',403);
  const options=await generateAuthenticationOptions({rpID:env.RP_ID,userVerification:'required',allowCredentials:keys.results.map(k=>({id:k.id,transports:JSON.parse(k.transports)}))});const flow=rand();await env.DB.prepare('INSERT INTO challenges(id,user_id,kind,challenge,expires_at) VALUES(?,?,?,?,?)').bind(flow,u.id,'login',options.challenge,now()+settings(env).challengeTTL).run();return json({flow,options});
 }
 if(path==='/api/login/verify'){
  const policy=sessionPolicy(data,env);
  const ch=await env.DB.prepare('DELETE FROM challenges WHERE id=? AND kind=? AND expires_at>? RETURNING *').bind(data.flow,'login',now()).first<Challenge>();if(!ch)return failure('Challenge expired',403);
  const k=await env.DB.prepare('SELECT p.* FROM passkeys p JOIN users u ON u.id=p.user_id WHERE p.id=? AND p.user_id=? AND u.active=1').bind(data.credential?.id,ch.user_id).first<KeyRow>();if(!k)return failure('Credential unavailable',403);
  const verified=await verifyAuthenticationResponse({response:data.credential,expectedChallenge:ch.challenge,expectedOrigin:env.PUBLIC_ORIGIN,expectedRPID:env.RP_ID,requireUserVerification:true,credential:{id:k.id,publicKey:new Uint8Array(k.public_key),counter:k.counter,transports:JSON.parse(k.transports)}});
  if(!verified.verified)return failure('Authentication failed',403);
  const updated=await env.DB.prepare('UPDATE passkeys SET counter=?,last_used_at=? WHERE id=? AND counter=? RETURNING id').bind(verified.authenticationInfo.newCounter,now(),k.id,k.counter).first();
  if(!updated)return failure('Please sign in again',409);
  const s=await issueSession(ch.user_id,env,policy.ttl);return json({ok:true},200,{'set-cookie':sessionCookie(s,env,policy)});
 }
 if(path==='/api/admin/invite'){
  const u=await session(req,env);if(!u||u.role!=='admin')return failure('Forbidden',403);
  const email=String(data.email||'').trim().toLowerCase();if(!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email))return failure('Invalid email');
  if(await env.DB.prepare('SELECT id FROM users WHERE email=?').bind(email).first())return failure('Already registered',409);
  if(data.send_email!==undefined&&typeof data.send_email!=='boolean')return failure('send_email must be a boolean');
  if(data.send_email&&!emailConfigured(env))return failure('Invitation email is not configured',503);
  // Count before the insert, then reserve the attempt before awaiting the provider.
  // Concurrent requests resume in this object before any external send completes.
  const recent=await env.DB.prepare('SELECT COUNT(*) AS n,MAX(created_at) AS latest FROM invites WHERE email=? AND created_by=? AND created_at>?').bind(email,u.id,now()-3600).first<{n:number;latest:number|null}>();
  if(recent&&(recent.n>=3||(recent.latest!==null&&recent.latest>now()-60)))return json({error:'Wait at least 60 seconds between invitations; maximum three per address per hour'},429,{'retry-after':'60'});
  const token=rand()+rand(),hash=await digest(token),ttl=settings(env).inviteTTL,expires=now()+ttl;
  // Recheck the reservation atomically because async hashing/session reads can interleave.
  const reserved=await env.DB.prepare('INSERT INTO invites(token_hash,email,role,expires_at,created_by,created_at) SELECT ?,?,?,?,?,? WHERE (SELECT COUNT(*) FROM invites WHERE email=? AND created_by=? AND created_at>?)<3 AND NOT EXISTS(SELECT 1 FROM invites WHERE email=? AND created_by=? AND created_at>?)').bind(hash,email,'family',expires,u.id,now(),email,u.id,now()-3600,email,u.id,now()-60).run();
  if(reserved.meta.changes!==1)return json({error:'Please wait before inviting this address again'},429,{'retry-after':'60'});
  const delivery=data.send_email?await sendInvitation(env,email,token,expires,hash):'manual';
  return json({token,invitation_url:invitationLink(env.PUBLIC_ORIGIN,token),expires_in_seconds:ttl,delivery});
 }
 if(path==='/api/logout'){
  const token=cookie(req,settings(env).cookieName);if(token)await env.DB.prepare('DELETE FROM sessions WHERE token_hash=?').bind(await digest(token)).run();return json({ok:true},200,{'set-cookie':`${settings(env).cookieName}=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0;${secure(env)}`});
 }
 return failure('Not found',404);
 }catch(e){if(e instanceof InputError)return failure(e.message,e.status);console.error('Request failed');return failure('Request could not be completed',500);}
}} satisfies ExportedHandler<AuthEnv>;
