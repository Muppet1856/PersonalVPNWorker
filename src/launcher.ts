import { BOOTSTRAP_PATH } from './ui-assets.ts';
import { APP_ICONS, appIconKey } from './icons.ts';
import { createRemoteJWKSet, jwtVerify, type JWTVerifyGetKey } from 'jose';

type LauncherEnv={PUBLIC_ORIGIN:string;SITE_NAME?:string;LAUNCHER_ORIGIN?:string;LAUNCHER_ACCESS_AUD?:string;ACCESS_TEAM_DOMAIN?:string;APP_LINKS_JSON?:string};
const escape=(text:string)=>text.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
const headers={'content-type':'text/html; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','referrer-policy':'no-referrer','content-security-policy':"default-src 'none'; style-src 'self' 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"};
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
  const icon=appIconKey(app.name,app.url,app.icon);
  return [`<div class="col-md-6 col-lg-4"><a class="card app-tile h-100 text-decoration-none" href="${escape(url.href)}" target="_blank" rel="noopener noreferrer"><div class="card-body d-flex align-items-center gap-3 p-4"><span class="app-icon" data-icon="${icon}">${APP_ICONS[icon]}</span><span class="app-copy"><strong>${escape(app.name)}</strong><span>${escape(url.hostname)}</span></span><span class="ms-auto text-secondary" aria-hidden="true">↗</span></div></a></div>`];
 }).join(''):'';
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>${name} · Applications</title><link rel="stylesheet" href="${BOOTSTRAP_PATH}"><style>
:root{--bs-body-font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--bs-body-bg:#f5f7f4;--bs-body-color:#2a4031;--bs-border-color:#e0e7d8}body{min-height:100vh;background:radial-gradient(ellipse at 5% 0%,#e6eddd 0,transparent 45%),var(--bs-body-bg)}.container{max-width:1140px}.brand{font-size:1rem;font-weight:650;letter-spacing:-.025em}.mark{display:grid;place-items:center;width:40px;height:40px;background:#225f48;color:#f0f5df;border-radius:13px;flex-shrink:0}svg{width:22px;height:22px}.intro{padding-top:72px;padding-bottom:36px}.eyebrow{font-size:.65rem;font-weight:750;letter-spacing:.17em;text-transform:uppercase;color:#788956}.eyebrow:before{content:'';display:inline-block;width:6px;height:6px;border-radius:50%;background:#859e53;margin-right:8px;vertical-align:middle}h1{font-size:clamp(2.5rem,5vw,3.7rem);font-weight:600;letter-spacing:-.05em;line-height:1.1}.lead{font-size:1rem;color:#819074}.card{border-radius:16px;border-color:#e0e7d8;background:#fff;box-shadow:0 12px 30px #29482e06}.app-tile{color:inherit;transition:border-color .15s,background .15s}.app-tile:hover{border-color:#93ab78;background:#fbfdf7}.app-icon{display:grid;place-items:center;width:48px;height:48px;border-radius:13px;flex-shrink:0;background:#edf2e3;color:#708a4a}.app-icon[data-icon=git]{background:#f8e9dc;color:#ac6b38}.app-icon svg{width:25px;height:25px}.app-copy{min-width:0}.app-copy strong{display:block;font-size:1rem;font-weight:650}.app-copy>span{display:block;margin-top:6px;font-size:.72rem;color:#96a184;overflow-wrap:anywhere}.btn{font-size:.75rem;font-weight:600;border-radius:9px;min-height:42px;--bs-btn-color:#6c7d5c;--bs-btn-border-color:#d5dfc8;--bs-btn-hover-bg:#e9f0df;--bs-btn-hover-color:#3d5c30;--bs-btn-hover-border-color:#b5c79f}.footer{color:#96a184;font-size:.72rem;margin-top:48px}a:focus-visible{outline:3px solid #93a064;outline-offset:4px}@media(max-width:600px){.brand{font-size:.85rem;max-width:62%}.mark{width:34px;height:34px;border-radius:11px}.intro{padding-top:42px}.footer{margin-top:32px}}@media(prefers-reduced-motion:reduce){*{transition:none!important}}
</style></head><body><header class="container px-4"><nav class="navbar py-4 d-flex justify-content-between gap-3" aria-label="Account"><div class="brand d-flex align-items-center gap-3"><span class="mark">${APP_ICONS.shield}</span>${name}</div><a class="btn btn-outline-secondary d-flex align-items-center" href="${escape(env.PUBLIC_ORIGIN)}">Manage account ↗</a></nav></header><main class="container px-4 pb-4"><section class="intro"><div class="eyebrow mb-4">Private workspace</div><h1 class="mb-3">Your applications.</h1><p class="lead mb-0">A familiar place for everything you need.</p></section><nav class="row g-3" aria-label="Applications">${tiles||'<div class="col-12"><div class="card"><div class="card-body p-4 text-secondary">No applications have been added yet.</div></div></div>'}</nav><footer class="footer d-flex flex-wrap justify-content-between gap-3 border-top pt-4"><span class="text-break">Signed in as ${escape(email)}</span><span>Protected by passkey sign-in</span></footer></main></body></html>`;
}
export async function handleLauncher(req:Request,env:LauncherEnv):Promise<Response> {
 if(new URL(req.url).pathname!=='/'||!['GET','HEAD'].includes(req.method))return new Response('Not found',{status:404,headers:{'cache-control':'no-store'}});
 if(!env.ACCESS_TEAM_DOMAIN||!env.LAUNCHER_ACCESS_AUD)return new Response('The application launcher is awaiting its Cloudflare Access configuration.',{status:503,headers:{'content-type':'text/plain; charset=utf-8','cache-control':'no-store'}});
 const token=req.headers.get('cf-access-jwt-assertion');if(!token)return new Response('Sign in through Cloudflare Access to open this launcher.',{status:401,headers:{'cache-control':'no-store'}});
 try{const email=await verifyLauncherAssertion(token,env);return new Response(req.method==='HEAD'?null:launcherPage(env,email),{headers});}
 catch{return new Response('Access could not be verified. Sign in again.',{status:403,headers:{'cache-control':'no-store'}});}
}
