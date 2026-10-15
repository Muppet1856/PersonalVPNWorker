export type EmailEnv={PUBLIC_ORIGIN:string;SITE_NAME?:string;RESEND_API_KEY?:string;RESEND_FROM?:string;RESEND_REPLY_TO?:string};
const mailbox=/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}$/;
export function validateEmailSettings(env:EmailEnv){
 if(env.RESEND_FROM&&!mailbox.test(env.RESEND_FROM))throw Error('RESEND_FROM must be a bare email address');
 if(env.RESEND_REPLY_TO&&!mailbox.test(env.RESEND_REPLY_TO))throw Error('RESEND_REPLY_TO must be a bare email address');
}
export function emailConfigured(env:EmailEnv){try{validateEmailSettings(env);return !!(env.RESEND_API_KEY&&env.RESEND_FROM&&new URL(env.PUBLIC_ORIGIN).protocol==='https:');}catch{return false;}}
const escape=(value:string)=>value.replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]!));
export function invitationLink(origin:string,token:string){const url=new URL('/',origin);url.hash=new URLSearchParams({invite:token}).toString();return url.href;}
export function invitationEmail(env:EmailEnv,email:string,token:string,expires:number){
 const brand=(env.SITE_NAME?.trim()||'Family Access').replace(/[\r\n]/g,' ').slice(0,100);
 const link=invitationLink(env.PUBLIC_ORIGIN,token),expiry=new Date(expires*1000).toISOString().replace('T',' ').replace('.000Z',' UTC');
 return {from:`${brand.replace(/[<>"\\]/g,'')} <${env.RESEND_FROM}>`,to:[email],subject:`Your invitation to ${brand}`,...(env.RESEND_REPLY_TO?{reply_to:env.RESEND_REPLY_TO}:{}),
 text:`You have been invited to ${brand}.\n\nOpen this private link, enter your display name, and create a passkey:\n${link}\n\nThis single-use invitation expires ${expiry}. Do not forward it. If you were not expecting this invitation, you can ignore this email.`,
 html:`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Your invitation</title></head><body style="margin:0;background:#f3f6f8;font-family:Arial,sans-serif;color:#162535"><div style="max-width:560px;margin:32px auto;padding:32px;background:#fff;border-radius:16px"><p style="font-size:16px">${escape(brand)}</p><h1 style="font-size:26px">You’re invited.</h1><p style="font-size:16px;line-height:1.6">Open your invitation, enter your display name, and create a passkey to access your account.</p><p style="margin:28px 0"><a href="${escape(link)}" style="display:inline-block;padding:16px 24px;border-radius:8px;background:#176d5d;color:#fff;text-decoration:none;font-size:16px">Accept invitation</a></p><p style="font-size:16px;line-height:1.6">This single-use invitation expires ${expiry}. Keep it private.</p><p style="font-size:14px;color:#536373">If the button does not work, copy this link:</p><p style="font-size:14px;overflow-wrap:anywhere"><a href="${escape(link)}">${escape(link)}</a></p><p style="font-size:14px;color:#536373">If you were not expecting this invitation, you can ignore this email.</p></div></body></html>`};
}
// A bounded retry uses the same key and payload, so ambiguous network errors do not duplicate mail.
export async function sendInvitation(env:EmailEnv,email:string,token:string,expires:number,idempotencyKey:string,fetcher:typeof fetch=fetch):Promise<'accepted'|'failed'>{
 if(!emailConfigured(env)||!mailbox.test(email))return 'failed';
 const body=JSON.stringify(invitationEmail(env,email,token,expires));
 for(let attempt=0;attempt<2;attempt++){
  let retry=true;
  try{const response=await fetcher('https://api.resend.com/emails',{method:'POST',redirect:'error',headers:{authorization:'Bearer '+env.RESEND_API_KEY,'content-type':'application/json','idempotency-key':'invitation-'+idempotencyKey},body,signal:AbortSignal.timeout(10000)});
   const accepted=response.ok;retry=response.status===429||response.status>=500;
   await response.body?.cancel();if(accepted)return 'accepted';
  }catch{/* Do not log provider responses, credentials, recipients or invitation links. */}
  if(!retry||attempt===1)return 'failed';
  await new Promise(resolve=>setTimeout(resolve,1000));
 }
 return 'failed';
}
