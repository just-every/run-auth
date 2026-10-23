import {one,random,hash,requireSession,fail,json} from '../core.mjs';
import {personSessionGuard} from '../agents/delegation/common.mjs';
import {unseal} from '../keys.mjs';

export const UNLINKED_RECEIPT='Auth erased your installation identity. Memberships you did not link are held separately by those employers; Auth did not see or erase them. Ask each employer to erase them.';
const rootOnly=ctx=>{if(ctx.organizationId!=='root')fail('installation_identity_required',403);};
const exact=(data,keys)=>{if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(key=>!keys.includes(key))||keys.some(key=>!Object.hasOwn(data,key)))fail('invalid_receipt_request');};
const namespace=id=>{if(!/^[a-f0-9]{32}$/.test(id))fail('receipt_unavailable',404);return 'org_'+id+'_';};
async function lookup(ctx,key) {
 if(typeof key!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(key))fail('receipt_unavailable',404);
 const digest=await hash(key);
 await ctx.db.prepare("UPDATE auth_erasure_person_receipts SET expired_at=expires_at,person_id=NULL,notices='[]' WHERE token_hash=? AND expires_at<=? AND expired_at IS NULL").bind(digest,ctx.now()).run();
 return await one(ctx,'SELECT * FROM auth_erasure_person_receipts WHERE token_hash=? AND expires_at>? AND revoked_at IS NULL AND expired_at IS NULL',digest,ctx.now())||fail('receipt_unavailable',404);
}
export async function receiptAction(ctx,request,path,data) {
 rootOnly(ctx);
 if(path.endsWith('/receipt-revoke')) {
  exact(data,['receiptKey','confirm']);if(data.confirm!==true)fail('explicit_receipt_revocation_required',403);
  // Possession can surrender only this receipt key, including after sign-in ends.
  const row=await lookup(ctx,data.receiptKey);
  await ctx.db.prepare("UPDATE auth_erasure_person_receipts SET revoked_at=?,person_id=NULL,notices='[]' WHERE token_hash=? AND revoked_at IS NULL").bind(ctx.now(),row.token_hash).run();
  return json({revoked:true});
 }
 exact(data,['confirm']);if(data.confirm!==true)fail('explicit_receipt_consent_required',403);
 const s=await requireSession(ctx,request);if(!JSON.parse(s.amr).includes('hwk'))fail('independent_passkey_required',403);
 const token=random()+random(),guard=personSessionGuard(ctx,s),expires=new Date(ctx.now());expires.setUTCMonth(expires.getUTCMonth()+13);
 const result=await ctx.db.prepare(`INSERT INTO auth_erasure_person_receipts(token_hash,person_id,created_at,expires_at,notices) SELECT ?,?,?,?,'[]' WHERE ${guard.clause}`).bind(await hash(token),s.person_id,ctx.now(),expires.getTime(),...guard.args).run();
 if(!result.meta.changes)fail('receipt_key_refused',403);
 return json({receiptKey:token,expiresAt:expires.getTime(),instruction:'Shown once. Save privately. Post only in a request body to read your receipt or revoke this key. Never put it in a URL or log.'},201);
}
export async function personReceipt(ctx,request,data) {
 rootOnly(ctx);exact(data,['receiptKey']);
 const row=await lookup(ctx,data.receiptKey);
 if(!row.erased_at)return json({state:'awaiting-installation-erasure',notices:[]});
 const notices=await unseal(ctx,'personal-erasure-receipt:'+row.token_hash,row.notices),visible=[];
 for(const entry of notices) {
  const org=await one(ctx,'SELECT status FROM auth_organizations WHERE id=?',entry.organizationId);
  const notice=org?.status==='active'?await ctx.db.prepare(`SELECT handle,erasure_reference,state,hold_id FROM ${namespace(entry.organizationId)}auth_identity_release_notices WHERE id=?`).bind(entry.noticeId).first():null;
  const activeHold=notice?.state==='held'&&await ctx.db.prepare(`SELECT id FROM ${namespace(entry.organizationId)}auth_erasure_holds WHERE id=? AND released_at IS NULL`).bind(notice.hold_id).first();
  // Resolve pre-rider payloads only while their original notice still exists.
  const handle=entry.handle??notice?.handle,erasureReference=entry.erasureReference??notice?.erasure_reference;
  if(!handle||!erasureReference)fail('receipt_unavailable',404);
  visible.push({handle,erasureReference,state:org?.status==='erased'?'employer-erased':notice?.state==='held'&&!activeHold?'pending':notice?.state??'unknown'});
 }
 return json({state:'installation-erased',notices:visible,message:UNLINKED_RECEIPT});
}
