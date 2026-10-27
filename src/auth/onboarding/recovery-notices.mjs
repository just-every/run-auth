import {personalRecoveryContact} from './dispatch.mjs';
import {audit} from '../core.mjs';

// Recovery notices carry no sign-in link, completion token or other credential.
export async function personalRecoveryNotice(ctx,personId) {
 const contact=await personalRecoveryContact(ctx,personId);
 if(!contact||!ctx.mail)return;
 try {
  await ctx.mail({personId,personalRecovery:{personId},to:contact.personal_email,
   subject:'Auth account recovery notice',text:'An account recovery was requested or updated. Contact your employer if you did not request it. Sign in at your usual Auth address to review the outcome.',
   html:'<p>An account recovery was requested or updated. Contact your employer if you did not request it. Sign in at your usual Auth address to review the outcome.</p>'});
  await audit(ctx,null,'onboarding_personal_recovery_notice_dispatched',personId);
 }catch{await audit(ctx,null,'onboarding_personal_recovery_notice_failed',personId);}
}
