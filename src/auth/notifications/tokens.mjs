import {b64,unb64,utf8,hash,one,fail} from '../core.mjs';
const label=ctx=>`${ctx.issuer??ctx.origin}${ctx.basePath??''}:security-report:v1`;
async function key(ctx) {
 if(typeof ctx.secret!=='string'||ctx.secret.length<32)fail('notification_signing_unavailable',503);
 return crypto.subtle.importKey('raw',utf8.encode(ctx.secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
export async function reportToken(ctx,nonce,expiresAt) {
 const body=`${nonce}.${expiresAt}`,signature=await crypto.subtle.sign('HMAC',await key(ctx),utf8.encode(`${label(ctx)}:${body}`));
 return `${body}.${b64(signature)}`;
}
export async function verifiedNotification(ctx,token) {
 if(typeof token!=='string'||token.length>300)fail('notification_report_unavailable',410);
 const parts=token.split('.');if(parts.length!==3||!/^\d{13}$/.test(parts[1]))fail('notification_report_unavailable',410);
 const [nonce,expiry,signature]=parts,expiresAt=Number(expiry);
 let valid=false;try{valid=await crypto.subtle.verify('HMAC',await key(ctx),unb64(signature),utf8.encode(`${label(ctx)}:${nonce}.${expiry}`));}catch{}
 if(!valid||expiresAt<=ctx.now())fail('notification_report_unavailable',410);
 const row=await one(ctx,'SELECT * FROM auth_security_notifications WHERE token_hash=? AND expires_at=? AND expires_at>? AND reported_at IS NULL',await hash(nonce),expiresAt,ctx.now());
 if(!row||!row.person_id)fail('notification_report_unavailable',410);
 return row;
}
