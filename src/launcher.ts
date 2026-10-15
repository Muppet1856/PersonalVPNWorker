import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';

type LauncherEnv={PUBLIC_ORIGIN:string;SITE_NAME?:string;LAUNCHER_ORIGIN?:string;LAUNCHER_ACCESS_AUD?:string;ACCESS_TEAM_DOMAIN?:string;APP_LINKS_JSON?:string};
const escape=(text:string)=>text.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const headers={'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"};
// Cache only public verification keys, never users, tokens or request data.
const keySets=new Map<string,ReturnType<typeof createRemoteJWKSet>>();
export async function verifyLauncherAssertion(token:string,env:LauncherEnv,resolver?:JWTVerifyGetKey) {
 if(!env.ACCESS_TEAM_DOMAIN||!env.LAUNCHER_ACCESS_AUD)throw Error('Launcher Access settings missing');
 if(!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.cloudflareaccess\.com$/.test(env.ACCESS_TEAM_DOMAIN))throw Error('Invalid Access team domain');
 const issuer='https://'+env.ACCESS_TEAM_DOMAIN;
 let keys=resolver || keySets.get(issuer);
 if(!keys){const remote=createRemoteJWKSet(new URL(issuer+'/cdn-cgi/access/certs'));keySets.set(issuer,remote);keys=remote;}
 const verified=await jwtVerify(token,keys,{issuer,audience:env.LAUNCHER_ACCESS_AUD,algorithms:['RS256'],requiredClaims:['sub','exp','iat','email']});
 if(typeof verified.payload.email!=='string')throw Error('Missing identity');
 return verified.payload.email;
}
export function launcherPage(env:LauncherEnv,email:string) {
 const name=escape(env.SITE_NAME?.trim()||'Family Access');
 const apps:unknown=JSON.parse(env.APP_LINKS_JSON||'[]');
 const tiles=Array.isArray(apps)?apps.flatMap(app=>{
  if(!app||typeof app.name!=='string'||typeof app.url!=='string')return [];
  const url=new URL(app.url);if(url.protocol!=='https:'||url.origin===env.LAUNCHER_ORIGIN)return [];
  const initial=escape(app.name.trim().charAt(0).toUpperCase()||'A');
  return [`<a class="tile" href="${escape(url.href)}"><span class="app-icon" aria-hidden="true">${initial}</span><span class="app-copy"><strong>${escape(app.name)}</strong><span>${escape(url.hostname)}</span></span><span class="arrow" aria-hidden="true">↗</span></a>`];
 }).join(''):'';
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="dark"><title>${name} · Applications</title><style>
:root{font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#edf4f7;background:#0d151f;font-synthesis:none}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at 85% 0%,#1a3b44 0,transparent 46%),#0d151f}a{color:inherit}.shell{max-width:1080px;margin:auto;padding:36px 28px 64px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:20px;padding-bottom:28px;border-bottom:1px solid #ffffff18}.brand{display:flex;align-items:center;gap:12px;font-size:15px;font-weight:650;letter-spacing:.01em}.mark{width:36px;height:36px;display:grid;place-items:center;background:#8ce4ca;color:#123a33;border-radius:11px}.account{color:#b5c5d1;text-decoration:none;font-size:14px}.account:hover{color:white}.intro{margin:70px 0 34px}.eyebrow{color:#8ce4ca;letter-spacing:.17em;text-transform:uppercase;font-size:11px;font-weight:700}h1{font-size:clamp(34px,5vw,52px);font-weight:600;letter-spacing:-.045em;margin:12px 0}.intro p{color:#a8bac9;font-size:17px;line-height:1.6;margin:0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,310px),1fr));gap:16px}.tile{display:flex;align-items:center;gap:18px;min-height:126px;padding:24px;border:1px solid #314451;background:#142430b3;border-radius:18px;text-decoration:none;transition:background .15s,border-color .15s,transform .15s}.tile:hover{background:#1b3543;border-color:#8ce4ca;transform:translateY(-2px)}a:focus-visible{outline:3px solid #8ce4ca;outline-offset:5px}.app-icon{display:grid;place-items:center;flex-shrink:0;width:48px;height:48px;border-radius:14px;background:#263e4c;color:#a9e8dc;font-weight:650;font-size:21px}.app-copy{display:flex;flex-direction:column;gap:7px;min-width:0}.app-copy strong{font-size:19px;font-weight:600}.app-copy>span{font-size:13px;color:#9eb5c4;overflow-wrap:anywhere}.arrow{color:#8ce4ca;margin-left:auto;font-size:22px}.empty{color:#a8bac9;padding:28px;border:1px dashed #3a5262;border-radius:18px}.footer{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;margin-top:38px;padding-top:22px;border-top:1px solid #ffffff18;color:#8ea4b5;font-size:12px}.identity{overflow-wrap:anywhere}@media(max-width:560px){.shell{padding:24px 20px}.intro{margin-top:48px}.topbar{align-items:flex-start}.brand{max-width:65%}.tile{padding:21px;min-height:112px}}
</style></head><body><main class="shell"><header class="topbar"><div class="brand"><span class="mark" aria-hidden="true">⌘</span>${name}</div><a class="account" href="${escape(env.PUBLIC_ORIGIN)}">Manage account ↗</a></header><section class="intro"><div class="eyebrow">Private workspace</div><h1>Your applications.</h1><p>Choose an application to open.</p></section><nav class="grid" aria-label="Applications">${tiles||'<div class="empty">No applications have been added yet.</div>'}</nav><footer class="footer"><span class="identity">Signed in as ${escape(email)}</span><span>Protected by passkey sign-in</span></footer></main></body></html>`;
}
export async function handleLauncher(req:Request,env:LauncherEnv):Promise<Response> {
 if(new URL(req.url).pathname!=='/'||!['GET','HEAD'].includes(req.method))return new Response('Not found',{status:404,headers:{'cache-control':'no-store'}});
 if(!env.ACCESS_TEAM_DOMAIN||!env.LAUNCHER_ACCESS_AUD)return new Response('The application launcher is awaiting its Cloudflare Access configuration.',{status:503,headers:{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}});
 const token=req.headers.get('cf-access-jwt-assertion');if(!token)return new Response('Sign in through Cloudflare Access to open this launcher.',{status:401,headers:{'cache-control':'no-store'}});
 try{const email=await verifyLauncherAssertion(token,env);return new Response(req.method==='HEAD'?null:launcherPage(env,email),{headers});}
 catch{return new Response('Access could not be verified. Sign in again.',{status:403,headers:{'cache-control':'no-store'}});}
}
