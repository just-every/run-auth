import {all,one,fail} from '../core.mjs';
import {refreshReceiptStatus} from './remote.mjs';

const deletion=kind=>['scim-delete','partner-delete'].includes(kind);
function selected(data,partners,{required=false}={}) {
 const destinations=data?.destinations===undefined?[]:data.destinations;
 if(!Array.isArray(destinations)||destinations.some(p=>typeof p!=='string'||!p||!partners.has(p)))fail('invalid_erasure_destinations');
 const unique=[...new Set(destinations)];
 if(required&&!unique.length)fail('erasure_destinations_required');
 return unique;
}
// A legacy broad boolean carries no authority: only exact destination choices
// from the current preview can authorize downstream data deletion.
export function deletionConsent(plan,data) {
 const destinations=selected(data,new Set(plan.remote.filter(task=>deletion(task.kind)).map(task=>task.partner)));
 if(destinations.length&&data.confirmRemoteDeletion!==true)fail('remote_erasure_confirmation_required');
 return destinations;
}
async function receiptTasks(ctx,receiptId) {
 if(typeof receiptId!=='string'||!receiptId||!await one(ctx,'SELECT id FROM auth_erasure_receipts WHERE id=?',receiptId))fail('erasure_receipt_not_found',404);
 return all(ctx,'SELECT * FROM auth_erasure_remote WHERE receipt_id=?',receiptId);
}
// The caller supplies the owner/hardware/fresh-email authority gate. These
// commands are intentionally usable against either a live or retained store.
export async function consentRemote(ctx,receiptId,data,authorize) {
 const tasks=await receiptTasks(ctx,receiptId),destinations=selected(data,new Set(tasks.filter(task=>deletion(task.kind)).map(task=>task.partner)));
 if(destinations.length&&data.confirmRemoteDeletion!==true)fail('remote_erasure_confirmation_required');
 for(const partner of destinations)if(!tasks.some(task=>task.partner===partner&&deletion(task.kind)&&!task.abandoned_at&&task.state!=='verified'))fail('remote_erasure_unavailable',409);
 if(destinations.length)await authorize(guard=>destinations.map(partner=>ctx.db.prepare(`UPDATE auth_erasure_remote SET consented_at=COALESCE(consented_at,?),updated_at=? WHERE receipt_id=? AND partner=? AND kind IN ('scim-delete','partner-delete') AND abandoned_at IS NULL AND state!='verified' AND EXISTS(SELECT 1 FROM auth_erasure_receipts WHERE id=?) AND ${guard.clause}`).bind(ctx.now(),ctx.now(),receiptId,partner,receiptId,...guard.args)));
 return {destinations,status:await refreshReceiptStatus(ctx,receiptId)};
}
export async function abandonRemote(ctx,receiptId,data,authorize) {
 if(data?.confirmation!=='ABANDON')fail('remote_abandon_confirmation_required');
 const tasks=await receiptTasks(ctx,receiptId),destinations=selected(data,new Set(tasks.filter(task=>task.state!=='verified'&&!task.abandoned_at).map(task=>task.partner)),{required:true});
 await authorize(guard=>destinations.map(partner=>ctx.db.prepare(`UPDATE auth_erasure_remote SET sealed_work=NULL,abandoned_at=?,state='blocked',last_error='remote_erasure_abandoned',updated_at=? WHERE receipt_id=? AND partner=? AND state!='verified' AND abandoned_at IS NULL AND EXISTS(SELECT 1 FROM auth_erasure_receipts WHERE id=?) AND ${guard.clause}`).bind(ctx.now(),ctx.now(),receiptId,partner,receiptId,...guard.args)));
 return {destinations,status:await refreshReceiptStatus(ctx,receiptId)};
}
