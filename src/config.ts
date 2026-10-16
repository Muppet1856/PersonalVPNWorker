export type Settings = {
  SITE_NAME?: string;
  FAMILY_ID?: string;
  SESSION_COOKIE_NAME?: string;
  SESSION_TTL_SECONDS?: string;
  REMEMBER_ME_TTL_SECONDS?: string;
  INVITE_TTL_SECONDS?: string;
  SETUP_INVITE_TTL_SECONDS?: string;
  CHALLENGE_TTL_SECONDS?: string;
};
export function seconds(value:string|undefined, fallback:number, max:number):number {
  if(value===undefined || value==='')return fallback;
  const n=Number(value);
  if(!Number.isSafeInteger(n)||n<1||n>max)throw new Error('Invalid lifetime configuration');
  return n;
}
export function settings(env:Settings) {
  const cookieName=env.SESSION_COOKIE_NAME || 'family_session';
  if(!/^[A-Za-z][A-Za-z0-9_]{0,63}$/.test(cookieName))throw new Error('Invalid session cookie name');
  return {
    siteName:env.SITE_NAME?.trim() || 'Family Access',
    cookieName,
    sessionTTL:seconds(env.SESSION_TTL_SECONDS,604800,2592000),
    rememberTTL:seconds(env.REMEMBER_ME_TTL_SECONDS,2592000,2592000),
    inviteTTL:seconds(env.INVITE_TTL_SECONDS,86400,604800),
    setupInviteTTL:seconds(env.SETUP_INVITE_TTL_SECONDS,3600,86400),
    challengeTTL:seconds(env.CHALLENGE_TTL_SECONDS,300,600),
  };
}
