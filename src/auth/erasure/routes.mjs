import {initializePortability} from './portability.mjs';
import {all,one,run,random,requireSession,fail,json} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {ensureSigningKey} from '../keys.mjs';
import {planErasure,publicPlan} from './plan.mjs';
import {commitErasure} from './execute.mjs';
import {publicRemote,executeRemote} from './remote.mjs';
import {signedJournal} from './export.mjs';
import {organizationOf} from './journal.mjs';

const ACTIONS=['/erasure/preview','/erasure/confirm','/erasure/hold','/erasure/policy','/erasure/retry'];
export const ERASURE_READS=['/api/auth/erasure/receipts','/api/auth/erasure/journal'];
export const isErasureAction=path=>ACTIONS.includes(path);
async function owner(ctx,request,write=false) {
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('owner_required',403);
 if(write)requireLocalEmail(ctx,s);return s;
}
async function guarded(ctx,s,sql,args) {
 const guard=authority(ctx,s,['owner']);
 const result=await run(ctx,sql+' AND '+guard.clause,...args,...guard.args);
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('erasure_conflict',409);}
 return result;
}
const validKind=kind=>{if(!['person','app','organization','installation'].includes(kind))fail('invalid_erasure_kind');return kind;};
const targetOf=(ctx,data)=>String(data.target||data.personId||data.appId||(['organization','installation'].includes(data.kind)?organizationOf(ctx):''));
export async function erasureModel(ctx,request) {
 await owner(ctx,request);
 const [policy,holds,receipts,remote]=await Promise.all([
  one(ctx,'SELECT * FROM auth_erasure_policy WHERE singleton=1'),
  all(ctx,'SELECT id,kind,target,reason,created_at,released_at FROM auth_erasure_holds ORDER BY created_at DESC'),
  all(ctx,'SELECT id,reference,kind,actor_ref,created_at,stores,limitations,decisions,status FROM auth_erasure_receipts ORDER BY created_at DESC'),
  all(ctx,'SELECT * FROM auth_erasure_remote ORDER BY created_at DESC'),
 ]);
 return {policy:policy?{configured:Boolean(policy.configured),...JSON.parse(policy.policy)}:{configured:false},holds,
  receipts:receipts.map(r=>({id:r.id,reference:r.reference,kind:r.kind,actor:r.actor_ref,createdAt:r.created_at,stores:JSON.parse(r.stores),limitations:JSON.parse(r.limitations),decisions:JSON.parse(r.decisions),local:'complete',status:r.status,remote:remote.filter(d=>d.receipt_id===r.id).map(publicRemote)}))};
}
export async function erasureRead(ctx,request,path=new URL(request.url).pathname) {
 await owner(ctx,request);
 if(path==='/api/auth/erasure/receipts')return json(await erasureModel(ctx,request));
 if(path==='/api/auth/erasure/journal') {
  // The final journal survives a namespace reset even though signing keys do not.
  const saved=await one(ctx,'SELECT journal FROM auth_erasure_receipts ORDER BY created_at DESC,rowid DESC LIMIT 1');
  return json(saved?JSON.parse(saved.journal):await signedJournal(ctx));
 }
 fail('not_found',404);
}
export async function erasureAction(ctx,request,path,data) {
 if(!isErasureAction(path))fail('not_found',404);
 const s=await owner(ctx,request,true);
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_erasure_request');
 if(path==='/erasure/policy') {
  if(data.confirm!==true||data.automaticDeletion!==false||data.honorLegalHolds!==true)fail('explicit_erasure_policy_required');
  const policy={mode:'explicit-owner-confirmation',automaticDeletion:false,heldData:'refuse-erasure',audit:'anonymized',remote:'separate-until-verified'};
  await guarded(ctx,s,'UPDATE auth_erasure_policy SET configured=1,policy=?,updated_by=?,updated_at=? WHERE singleton=1',[JSON.stringify(policy),s.person_id,ctx.now()]);
  await ensureSigningKey(ctx);
  await initializePortability(ctx);
  return json({configured:true,...policy});
 }
 if(path==='/erasure/hold') {
  if(data.release===true) {
   if(typeof data.id!=='string')fail('invalid_hold');
   await guarded(ctx,s,'UPDATE auth_erasure_holds SET released_by=?,released_at=? WHERE id=? AND released_at IS NULL',[s.person_id,ctx.now(),data.id]);
   return json({released:true});
  }
  const kind=validKind(data.kind),target=targetOf(ctx,data),reason=String(data.reason||'').trim();
  if(!target||target.length>512||!reason||reason.length>500)fail('invalid_hold');
  if(kind==='organization'&&target!==organizationOf(ctx))fail('wrong_erasure_organization',403);
  const id=random();
  const guard=authority(ctx,s,['owner']);
  const saved=await run(ctx,`INSERT INTO auth_erasure_holds(id,kind,target,reason,created_by,created_at) SELECT ?,?,?,?,?,? WHERE ${guard.clause}`,id,kind,target,reason,s.person_id,ctx.now(),...guard.args);
  if(!saved.meta.changes){await requireAuthority(ctx,s,guard);fail('erasure_conflict',409);}
  return json({id,kind,target,reason},201);
 }
 if(path==='/erasure/preview') {
  const kind=validKind(data.kind),target=targetOf(ctx,data),plan=await planErasure(ctx,kind,target),id=random(),now=ctx.now(),guard=authority(ctx,s,['owner']);
  const saved=await run(ctx,`INSERT INTO auth_erasure_previews(id,actor_id,kind,target,digest,created_at,expires_at) SELECT ?,?,?,?,?,?,? WHERE ${guard.clause}`,id,s.person_id,kind,target,plan.fingerprint,now,now+600000,...guard.args);
  if(!saved.meta.changes){await requireAuthority(ctx,s,guard);fail('erasure_conflict',409);}
  return json({id,expiresAt:now+600000,...publicPlan(plan)});
 }
 if(path==='/erasure/retry') {
  if(data.confirmRemoteDeletion!==true||typeof data.receiptId!=='string')fail('remote_erasure_confirmation_required');
  await guarded(ctx,s,'UPDATE auth_erasure_receipts SET status=status WHERE id=?',[data.receiptId]);
  await executeRemote(ctx,data.receiptId);return json(await erasureModel(ctx,request));
 }
 const preview=await one(ctx,'SELECT * FROM auth_erasure_previews WHERE id=?',String(data.previewId||data.id||''));
 if(!preview||preview.actor_id!==s.person_id||preview.expires_at<=ctx.now())fail('erasure_preview_expired',409);
 const plan=await planErasure(ctx,preview.kind,preview.target);
 if(plan.fingerprint!==preview.digest)fail('erasure_preview_changed',409);
 if(data.confirmation!==plan.confirmation)fail('erasure_confirmation_required');
 if(data.confirmRemoteDeletion!==true)fail('remote_erasure_confirmation_required');
 return json(await commitErasure(ctx,s,plan,preview.id));
}
