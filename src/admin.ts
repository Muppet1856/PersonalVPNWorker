import type {AuthEnv,User} from './auth.ts';
import {configuredApps,allowedAppIDs} from './permissions.ts';
const json=(value:unknown,status=200)=>new Response(JSON.stringify(value),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store'}});
const error=(message:string,status=400)=>json({error:message},status);
// The caller supplies a freshly verified session; every entry point also checks its role.
export function manageUsers(req:Request,env:AuthEnv,actor:User|null,data?:Record<string,unknown>):Response {
 if(!actor||actor.role!=='admin')return error('Forbidden',403);
 const path=new URL(req.url).pathname,now=Math.floor(Date.now()/1000);
 if(req.method==='GET'&&path==='/api/admin/users'){
  const rows=env.DB.prepare(`SELECT u.id,u.email,u.name,u.role,u.active,u.created_at,
   (SELECT COUNT(*) FROM passkeys p WHERE p.user_id=u.id) AS passkey_count,
   (SELECT MAX(last_used_at) FROM passkeys p WHERE p.user_id=u.id) AS last_sign_in,
   (SELECT COUNT(*) FROM sessions s WHERE s.user_id=u.id AND s.expires_at>?) AS session_count
   FROM users u ORDER BY u.role='admin' DESC,u.name COLLATE NOCASE,u.id LIMIT 201`).bind(now).all<Pick<User,'id'|'role'|'active'>&Record<string,unknown>>();
  return json({users:rows.results.slice(0,200).map(row=>({...row,allowed_apps:allowedAppIDs(env,row)})),apps:configuredApps(env),limited:rows.results.length>200});
 }
 if(req.method==='GET'&&path==='/api/admin/invites'){
  const rows=env.DB.prepare('SELECT token_hash AS id,email,role,expires_at,created_at FROM invites WHERE used_at IS NULL AND expires_at>? ORDER BY expires_at DESC,token_hash LIMIT 201').bind(now).all();
  return json({invitations:rows.results.slice(0,200),limited:rows.results.length>200});
 }
 if(req.method!=='POST')return error('Not found',404);
 if(req.headers.get('origin')!==env.PUBLIC_ORIGIN)return error('Invalid origin',403);
 if(path==='/api/admin/users'){
  if(!data||typeof data.user_id!=='string'||data.user_id.length>128)return error('Invalid user');
  const target=env.DB.prepare('SELECT id,role FROM users WHERE id=?').bind(data.user_id).first<{id:string;role:string}>();
  if(!target)return error('User not found',404);
  if(data.action==='set_apps'){
   if(actor.auth_method!=='passkey'||actor.auth_time<now-300)return error('Verify a passkey again before changing app permissions',403);
   if(target.role==='admin')return error('Administrator app access is protected',409);
   const apps=configuredApps(env),ids=new Set(apps.map(app=>app.id));
   if(!Array.isArray(data.allowed_apps)||data.allowed_apps.length>20||data.allowed_apps.some(id=>typeof id!=='string'||!ids.has(id))||new Set(data.allowed_apps).size!==data.allowed_apps.length)return error('Invalid app permissions');
   env.DB.batch([
    env.DB.prepare('DELETE FROM user_app_permissions WHERE user_id=?').bind(target.id),
    ...data.allowed_apps.map(id=>env.DB.prepare('INSERT INTO user_app_permissions(user_id,app_id) VALUES(?,?)').bind(target.id,id as string)),
    env.DB.prepare('UPDATE users SET access_revision=access_revision+1 WHERE id=?').bind(target.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM oidc_codes WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM oidc_tokens WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM challenges WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM email_logins WHERE user_id=?').bind(target.id)
   ]);
   return json({ok:true,access_sessions_require_revocation:true});
  }else if(data.action==='disable'){
   if(target.role==='admin')return error('Administrator accounts cannot be disabled in this console',409);
   env.DB.batch([
    env.DB.prepare("UPDATE users SET active=0,access_revision=access_revision+1 WHERE id=? AND role<>'admin'").bind(target.id),
    env.DB.prepare("DELETE FROM sessions WHERE user_id=? AND EXISTS(SELECT 1 FROM users WHERE id=? AND active=0)").bind(target.id,target.id),
    env.DB.prepare('DELETE FROM oidc_codes WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM oidc_tokens WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM challenges WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM email_logins WHERE user_id=?').bind(target.id)
   ]);
  }else if(data.action==='enable'){
   env.DB.prepare('UPDATE users SET active=1 WHERE id=?').bind(target.id).run();
  }else if(data.action==='revoke_sessions'){
   env.DB.batch([
    env.DB.prepare('UPDATE users SET access_revision=access_revision+1 WHERE id=?').bind(target.id),
    env.DB.prepare('DELETE FROM sessions WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM oidc_codes WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM oidc_tokens WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM challenges WHERE user_id=?').bind(target.id),
    env.DB.prepare('DELETE FROM email_logins WHERE user_id=?').bind(target.id)
   ]);
  }else return error('Invalid action');
  return json({ok:true});
 }
 if(path==='/api/admin/invites/revoke'){
  if(!data||typeof data.invitation_id!=='string'||!/^[a-f0-9]{64}$/.test(data.invitation_id))return error('Invalid invitation');
  // Revoking a used invitation cannot remove an enrolled account.
  const changed=env.DB.prepare("DELETE FROM invites WHERE token_hash=? AND used_at IS NULL AND role<>'admin'").bind(data.invitation_id).run();
  if(changed.meta.changes!==1)return error('Invitation unavailable or protected',409);
  return json({ok:true});
 }
 return error('Not found',404);
}
