import {one} from './core.mjs';

const messages={
 approve:'Passkey recovery was approved by another administrator. Review your account if you did not request it.',
 cancel:'Passkey recovery was cancelled. Your existing factors remain enrolled.',
 complete:'Passkey recovery completed. Earlier factors and sessions ended; enroll replacement hardware.',
 emergency:'Local emergency recovery was used. Earlier factors and sessions ended; enroll replacement hardware.',
};

// Insert in the same transaction as the successful state change, before old
// sessions end. A refused or losing operation cannot create a notification.
export function recoveryNotice(ctx,p,personId,recoveryId,action,gate) {
 return p(`INSERT INTO auth_notices(id,session_id,recovery_id,message,created_at)
  SELECT lower(hex(randomblob(24))),n.id,?,?,? FROM auth_sessions n JOIN oa_operators person ON person.id=n.person_id
  WHERE person.id=? AND person.status='active' AND person.version=n.person_version
  AND n.revoked_at IS NULL AND n.expires_at>? AND ${gate.clause}`,
  recoveryId,messages[action],ctx.now(),personId,ctx.now(),...gate.args);
}

export async function recoveryEmail(ctx,personId,action) {
 if(!ctx.mail)return;
 // Resolve the affected person's current verified mailbox at dispatch. The
 // caller cannot supply an address or an authentication-bearing link.
 const person=await one(ctx,"SELECT p.email FROM oa_operators p JOIN auth_emails e ON e.person_id=p.id WHERE p.id=? AND p.status='active'",personId);
 if(!person)return;
 await ctx.mail({to:person.email,subject:action==='emergency'?'Auth emergency recovery used':'Auth passkey recovery update',text:`${messages[action]} Open ${(ctx.issuer??ctx.origin)}/app/account to inspect the outcome.`,html:`<p>${messages[action]}</p><p>Sign in to Auth to inspect the outcome.</p>`});
}
