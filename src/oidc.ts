import { SignJWT, generateKeyPair, exportJWK, importJWK, calculateJwkThumbprint, type JWK } from 'jose';
import type { AuthEnv, User } from './auth.ts';
import { settings } from './config.ts';
import { allowedAppIDs } from './permissions.ts';

const now=()=>Math.floor(Date.now()/1000);
const encoder=new TextEncoder();
const random=()=>{const bytes=crypto.getRandomValues(new Uint8Array(32));return btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');};
const b64=(bytes:Uint8Array)=>btoa(String.fromCharCode(...bytes)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const sha=async(value:string)=>b64(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value))));
const cookie=(req:Request,name:string)=>req.headers.get('cookie')?.split(';').map(x=>x.trim()).find(x=>x.startsWith(name+'='))?.slice(name.length+1) || '';
const flowCookieName='family_oidc_flow';
const flowCookie=(token:string,env:AuthEnv)=>`${flowCookieName}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600;${env.PUBLIC_ORIGIN.startsWith('https:')?' Secure;':''}`;
const json=(data:unknown,status=200,headers:HeadersInit={})=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer',...headers}});
const error=(name:string,status=400)=>json({error:name},status);
const redirect=(url:string,headers:HeadersInit={})=>new Response(null,{status:302,headers:{location:url,'cache-control':'no-store','referrer-policy':'no-referrer',...headers}});
function configured(env:AuthEnv) {
 const team=env.ACCESS_TEAM_DOMAIN;
 if(!team || !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(team) || !env.OIDC_CLIENT_SECRET || env.OIDC_CLIENT_SECRET.length<32)return null;
 return {id:env.OIDC_CLIENT_ID || 'family-access',secret:env.OIDC_CLIENT_SECRET,redirect:`https://${team}/cdn-cgi/access/callback`};
}
export const oidcConfigured=(env:AuthEnv)=>!!configured(env);
const issuer=(env:AuthEnv)=>env.PUBLIC_ORIGIN;
function claims(env:AuthEnv,user:User,scope:string) {
 const result:Record<string,unknown>={sub:user.id,allowed_apps:allowedAppIDs(env,user)};
 const scopes=scope.split(' ');
 if(scopes.includes('email')){result.email=user.email;result.email_verified=false;}
 if(scopes.includes('profile'))result.name=user.name;
 return result;
}
type KeyRow={kid:string;private_jwk:string;public_jwk:string};
async function newKey() {
 const pair=await generateKeyPair('RS256',{extractable:true,modulusLength:2048});
 const privateJwk=await exportJWK(pair.privateKey),publicJwk=await exportJWK(pair.publicKey);
 const kid=await calculateJwkThumbprint(publicJwk);
 return {kid,privateJwk,publicJwk:{...publicJwk,kid,alg:'RS256',use:'sig'}};
}
const keyPromises=new WeakMap<AuthEnv['DB'],Promise<KeyRow>>();
async function signingKey(env:AuthEnv):Promise<KeyRow> {
 const current=env.DB.prepare('SELECT * FROM oidc_keys WHERE active=1').first<KeyRow>();if(current)return current;
 let pending=keyPromises.get(env.DB);
 if(!pending){pending=(async()=>{
   const key=await newKey();
   env.DB.prepare('INSERT INTO oidc_keys(kid,private_jwk,public_jwk,active,created_at) SELECT ?,?,?,1,? WHERE NOT EXISTS(SELECT 1 FROM oidc_keys WHERE active=1)').bind(key.kid,JSON.stringify(key.privateJwk),JSON.stringify(key.publicJwk),now()).run();
   return env.DB.prepare('SELECT * FROM oidc_keys WHERE active=1').first<KeyRow>()!;
 })();keyPromises.set(env.DB,pending);}
 try{return await pending;}finally{keyPromises.delete(env.DB);}
}
export function throttle(req:Request,env:AuthEnv):boolean {
 const path=new URL(req.url).pathname;
 const ip=req.headers.get('cf-connecting-ip') || 'local';
 // The key stays local to the object; expired buckets are removed on each call.
 env.DB.prepare('DELETE FROM rate_limits WHERE reset_at<=?').bind(now()).run();
 const key=path+':'+ip.slice(0,64);
 const row=env.DB.prepare('INSERT INTO rate_limits(key,count,reset_at) VALUES(?,1,?) ON CONFLICT(key) DO UPDATE SET count=count+1 RETURNING count').bind(key,now()+60).first<{count:number}>();
 return (row?.count || 0)<=60;
}
export function cleanup(env:AuthEnv) {
 // At most once per minute per object, with persisted coordination across restarts.
 const row=env.DB.prepare("INSERT INTO rate_limits(key,count,reset_at) VALUES('cleanup',1,?) ON CONFLICT(key) DO UPDATE SET reset_at=excluded.reset_at WHERE rate_limits.reset_at<=? RETURNING key").bind(now()+60,now()).first();
 if(!row)return;
 for(const table of ['oidc_requests','oidc_codes','oidc_tokens','sessions','challenges','email_logins'])env.DB.prepare(`DELETE FROM ${table} WHERE expires_at<=?`).bind(now()).run();
 env.DB.prepare('DELETE FROM invites WHERE expires_at<=? AND role<>? AND created_at<=?').bind(now(),'admin',now()-3600).run();
 env.DB.prepare('DELETE FROM oidc_keys WHERE active=0 AND retired_at<?').bind(now()-86400).run();
}
type Authorization={client_id:string;redirect_uri:string;scope:string;state:string;nonce:string|null;challenge:string;max_age:number|null;require_reauth:number;previous_session_hash:string|null};
async function issueCode(env:AuthEnv,user:User,request:Authorization) {
 const code=random();
 const inserted=env.DB.prepare('INSERT INTO oidc_codes(token_hash,user_id,client_id,redirect_uri,scope,nonce,challenge,auth_time,expires_at) SELECT ?,id,?,?,?,?,?,?,? FROM users WHERE id=? AND active=1 AND access_revision=?').bind(await sha(code),request.client_id,request.redirect_uri,request.scope,request.nonce,request.challenge,user.auth_time,now()+120,user.id,user.access_revision).run();
 if(inserted.meta.changes!==1)return null;
 const target=new URL(request.redirect_uri);target.searchParams.set('code',code);target.searchParams.set('state',request.state);target.searchParams.set('iss',issuer(env));return target.toString();
}
async function readParams(req:Request):Promise<URLSearchParams|null> {
 if(!req.headers.get('content-type')?.toLowerCase().startsWith('application/x-www-form-urlencoded'))return null;
 const reader=req.body?.getReader();if(!reader)return null;
 const chunks:Uint8Array[]=[];let size=0;
 while(true){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>16384){await reader.cancel();return null;}chunks.push(value);}
 const bytes=new Uint8Array(size);let offset=0;for(const c of chunks){bytes.set(c,offset);offset+=c.length;}
 return new URLSearchParams(new TextDecoder().decode(bytes));
}
function unique(params:URLSearchParams) {const seen=new Set<string>();let valid=true;params.forEach((_,key)=>{if(seen.has(key))valid=false;seen.add(key);});return valid;}
async function sameSecret(a:string,b:string) {const x=await sha(a),y=await sha(b);let diff=0;for(let i=0;i<x.length;i++)diff|=x.charCodeAt(i)^y.charCodeAt(i);return diff===0;}

export async function handleOIDC(req:Request,env:AuthEnv,getUser:()=>User|null):Promise<Response> {
 const url=new URL(req.url),path=url.pathname;
 const client=configured(env);
 if(req.method==='GET'&&path==='/.well-known/openid-configuration')return json({
  issuer:issuer(env),authorization_endpoint:issuer(env)+'/oidc/authorize',token_endpoint:issuer(env)+'/oidc/token',
  userinfo_endpoint:issuer(env)+'/oidc/userinfo',jwks_uri:issuer(env)+'/oidc/jwks',
  response_types_supported:['code'],response_modes_supported:['query'],grant_types_supported:['authorization_code'],
  subject_types_supported:['public'],id_token_signing_alg_values_supported:['RS256'],
  token_endpoint_auth_methods_supported:['client_secret_basic','client_secret_post'],code_challenge_methods_supported:['S256'],
  scopes_supported:['openid','email','profile'],claims_supported:['sub','iss','aud','exp','iat','auth_time','nonce','email','email_verified','name','allowed_apps'],
  authorization_response_iss_parameter_supported:true,
 });
 if(req.method==='GET'&&path==='/oidc/jwks'){
  await signingKey(env);const keys=env.DB.prepare('SELECT public_jwk FROM oidc_keys WHERE active=1 OR retired_at>?').bind(now()-86400).all<{public_jwk:string}>().results.map(x=>JSON.parse(x.public_jwk));
  return json({keys},200,{'cache-control':'public, max-age=300'});
 }
 if(req.method==='POST'&&path==='/api/admin/oidc/rotate') {
  if(req.headers.get('origin')!==env.PUBLIC_ORIGIN)return error('invalid_origin',403);
  const user=await getUser();if(!user||user.role!=='admin')return error('access_denied',403);
  const key=await newKey();
  const current=getUser();if(!current||current.role!=='admin'||current.auth_method!=='passkey'||current.auth_time<=now()-300||current.auth_time>now())return error('access_denied',403);
  env.DB.batch([
   env.DB.prepare('UPDATE oidc_keys SET active=0,retired_at=? WHERE active=1').bind(now()),
   env.DB.prepare('INSERT INTO oidc_keys(kid,private_jwk,public_jwk,active,created_at) VALUES(?,?,?,1,?)').bind(key.kid,JSON.stringify(key.privateJwk),JSON.stringify(key.publicJwk),now()),
  ]);return json({ok:true,kid:key.kid});
 }
 if(!client)return error('oidc_not_configured',503);
 if(req.method==='GET'&&path==='/oidc/authorize') {
  const p=url.searchParams;if(p.has('request')||p.has('request_uri'))return error('request_not_supported');if(!unique(p)||url.search.length>8192)return error('invalid_request');
  if(p.get('client_id')!==client.id||p.get('redirect_uri')!==client.redirect)return error('invalid_client');
  const failure=(name:string)=>{const u=new URL(client.redirect);u.searchParams.set('error',name);if(p.get('state'))u.searchParams.set('state',p.get('state')!);u.searchParams.set('iss',issuer(env));return redirect(u.toString());};
  if(p.get('response_type')!=='code')return failure('unsupported_response_type');
  if(p.has('response_mode')&&p.get('response_mode')!=='query')return failure('invalid_request');
  const scopes=(p.get('scope')||'').split(' ').filter(Boolean);
  if(!scopes.includes('openid')||scopes.some(s=>!['openid','email','profile'].includes(s)))return failure('invalid_scope');
  const state=p.get('state')||'',nonce=p.get('nonce');
  if(!state||state.length>2048||(nonce!==null&&(!nonce||nonce.length>512)))return failure('invalid_request');
  const challenge=p.get('code_challenge')||'';
  if(p.get('code_challenge_method')!=='S256'||!/[A-Za-z0-9_-]{43}/.test(challenge)||challenge.length!==43)return failure('invalid_request');
  const prompt=p.get('prompt');if(prompt&&!['none','login'].includes(prompt))return failure('invalid_request');
  const maxAge=p.has('max_age')?Number(p.get('max_age')):null;if(maxAge!==null&&(!Number.isSafeInteger(maxAge)||maxAge<0||maxAge>2592000))return failure('invalid_request');
  const user=await getUser();const reauth=prompt==='login'||maxAge===0||!!(user&&maxAge!==null&&now()-user.auth_time>maxAge);
  const request:Authorization={client_id:client.id,redirect_uri:client.redirect,scope:[...new Set(scopes)].join(' '),state,nonce,challenge,max_age:maxAge,require_reauth:reauth?1:0,previous_session_hash:await sha(cookie(req,settings(env).cookieName))};
  if(user&&!reauth){const target=await issueCode(env,user,request);return target?redirect(target):failure('access_denied');}
  if(prompt==='none')return failure('login_required');
  const id=random(),browser=random();env.DB.prepare('INSERT INTO oidc_requests(id,browser_hash,client_id,redirect_uri,scope,state,nonce,challenge,previous_session_hash,require_reauth,max_age,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,await sha(browser),request.client_id,request.redirect_uri,request.scope,state,nonce,challenge,request.previous_session_hash,request.require_reauth,maxAge,now(),now()+600).run();
  return redirect('/?oidc_request='+encodeURIComponent(id),{'set-cookie':flowCookie(browser,env)});
 }
 if(req.method==='POST'&&path==='/oidc/continue') {
  if(req.headers.get('origin')!==env.PUBLIC_ORIGIN)return error('invalid_origin',403);
  // The continuation accepts a small request ID only; all redirect data stays server-side.
  if(Number(req.headers.get('content-length')||0)>2048)return error('invalid_request');
  const data=await readParams(req);if(!data||!unique(data))return error('invalid_request');
  const user=await getUser();if(!user)return error('login_required',401);
  const pending=env.DB.prepare('SELECT * FROM oidc_requests WHERE id=? AND browser_hash=? AND expires_at>?').bind(data.get('request_id')||'',await sha(cookie(req,flowCookieName)),now()).first<Authorization>();
  if(!pending||pending.client_id!==client.id||pending.redirect_uri!==client.redirect)return error('invalid_request');
  if(pending.require_reauth&&pending.previous_session_hash===await sha(cookie(req,settings(env).cookieName)))return error('login_required',401);
  if(pending.max_age!==null&&pending.max_age>0&&now()-user.auth_time>pending.max_age)return error('login_required',401);
  const consumed=env.DB.prepare('DELETE FROM oidc_requests WHERE id=? AND browser_hash=? AND expires_at>? RETURNING id').bind(data.get('request_id'),await sha(cookie(req,flowCookieName)),now()).first();if(!consumed)return error('invalid_request');
  const target=await issueCode(env,user,pending);if(!target)return error('access_denied',403);
  return json({redirect:target},200,{'set-cookie':flowCookie('',env).replace('Max-Age=600','Max-Age=0')});
 }
 if(req.method==='POST'&&path==='/oidc/token') {
  const p=await readParams(req);if(!p||!unique(p))return error('invalid_request');
  let id=p.get('client_id')||'',secret=p.get('client_secret')||'';
  const auth=req.headers.get('authorization');
  if(auth){
   if(!auth.startsWith('Basic ')||p.has('client_secret'))return error('invalid_client',401);
   try{const value=atob(auth.slice(6)),split=value.indexOf(':');if(split<0)throw Error();const basicID=decodeURIComponent(value.slice(0,split).replace(/\+/g,' '));if(id&&id!==basicID)throw Error();id=basicID;secret=decodeURIComponent(value.slice(split+1).replace(/\+/g,' '));}catch{return error('invalid_client',401);}
  }
  if(id!==client.id||!await sameSecret(secret,client.secret))return json({error:'invalid_client'},401,{'www-authenticate':'Basic realm="OIDC"'});
  if(p.get('grant_type')!=='authorization_code')return error('unsupported_grant_type');
  const verifier=p.get('code_verifier')||'';if(!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier)||p.get('redirect_uri')!==client.redirect)return error('invalid_grant');
  const verifierHash=await sha(verifier);
  const code=env.DB.prepare('DELETE FROM oidc_codes WHERE token_hash=? AND client_id=? AND redirect_uri=? AND expires_at>? RETURNING *').bind(await sha(p.get('code')||''),id,client.redirect,now()).first<{user_id:string;scope:string;nonce:string|null;challenge:string;auth_time:number}>();
  if(!code||verifierHash!==code.challenge)return error('invalid_grant');
  const user=env.DB.prepare('SELECT * FROM users WHERE id=? AND active=1').bind(code.user_id).first<User&{access_revision:number}>();if(!user)return error('invalid_grant');
  const key=await signingKey(env),access=random();
  const claim=claims(env,user,code.scope);if(code.nonce)claim.nonce=code.nonce;claim.auth_time=code.auth_time;
  const accessHash=await sha(access);claim.at_hash=b64(Uint8Array.from(atob(accessHash.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)).slice(0,16));
  const jwt=await new SignJWT(claim).setProtectedHeader({alg:'RS256',kid:key.kid,typ:'JWT'}).setIssuer(issuer(env)).setAudience(id).setIssuedAt().setExpirationTime(now()+300).sign(await importJWK(JSON.parse(key.private_jwk) as JWK,'RS256'));
  // JWT signing yields; permission changes or disable/revoke may have happened meanwhile.
  // Recheck the revision and active state immediately before committing/returning.
  const inserted=env.DB.prepare('INSERT INTO oidc_tokens(token_hash,user_id,scope,expires_at) SELECT ?,id,?,? FROM users WHERE id=? AND active=1 AND access_revision=?').bind(accessHash,code.scope,now()+300,user.id,user.access_revision).run();
  if(inserted.meta.changes!==1)return error('invalid_grant');
  return json({access_token:access,token_type:'Bearer',expires_in:300,id_token:jwt,scope:code.scope});
 }
 if(req.method==='GET'&&path==='/oidc/userinfo') {
  const auth=req.headers.get('authorization')||'';if(!auth.startsWith('Bearer '))return error('invalid_token',401);
  const row=env.DB.prepare('SELECT u.*,t.scope FROM oidc_tokens t JOIN users u ON u.id=t.user_id WHERE t.token_hash=? AND t.expires_at>? AND u.active=1').bind(await sha(auth.slice(7)),now()).first<User&{scope:string}>();
  if(!row)return json({error:'invalid_token'},401,{'www-authenticate':'Bearer error="invalid_token"'});
  return json(claims(env,row,row.scope));
 }
 return error('not_found',404);
}
