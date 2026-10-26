import type { AuthEnv, User } from './auth.ts';

export type Application = {id:string;name:string;url:string;icon?:string};
// Canonical hostnames are stable permission IDs, shared with ACCESS_APPS_JSON domains.
// Fail closed on ambiguous configuration; URL paths are not separate Access apps.
export function configuredApps(env:{APP_LINKS_JSON?:string}):Application[] {
 const raw:unknown=JSON.parse(env.APP_LINKS_JSON||'[]');
 if(!Array.isArray(raw)||raw.length>20)throw Error('Invalid application configuration');
 const seen=new Set<string>();
 return raw.map((app:unknown)=>{
  if(!app||typeof app!=='object'||!('name' in app)||typeof app.name!=='string'||!('url' in app)||typeof app.url!=='string')throw Error('Invalid application configuration');
  const url=new URL(app.url);
  if(url.protocol!=='https:'||url.username||url.password||url.port||seen.has(url.hostname))throw Error('Invalid or duplicate application hostname');
  seen.add(url.hostname);
  return {id:url.hostname,name:app.name,url:url.href,...('icon' in app&&typeof app.icon==='string'?{icon:app.icon}:{})};
 });
}
export function permittedApps(env:Pick<AuthEnv,'DB'|'APP_LINKS_JSON'>,user:Pick<User,'id'|'role'|'active'>):Application[] {
 if(!user.active)return [];
 const apps=configuredApps(env);
 if(user.role==='admin')return apps;
 const grants=new Set(env.DB.prepare('SELECT app_id FROM user_app_permissions WHERE user_id=?').bind(user.id).all<{app_id:string}>().results.map(row=>row.app_id));
 return apps.filter(app=>grants.has(app.id));
}
export const allowedAppIDs=(env:Pick<AuthEnv,'DB'|'APP_LINKS_JSON'>,user:Pick<User,'id'|'role'|'active'>)=>permittedApps(env,user).map(app=>app.id);
