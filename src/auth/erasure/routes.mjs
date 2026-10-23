import {releasePerson} from './pair-erasure.mjs';
import {resetConsentAction} from './reset-consent.mjs';
import {initializePortability} from './portability.mjs';
import {all,one,run,random,requireSession,fail,json} from '../core.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {ensureSigningKey} from '../keys.mjs';
import {planErasure,publicPlan} from './plan.mjs';
import {commitErasure} from './execute.mjs';
import {executeRemote} from './remote.mjs';
import {deletionConsent,consentRemote,abandonRemote} from './consent.mjs';
import {selectErasureContext,ownerWrite,assertOwnerProof} from './authorization.mjs';
import {signedJournal} from './export.mjs';
import {receiptContext,savedJournal,journalIntegrity} from './integrity.mjs';
import {organizationOf} from './journal.mjs';
import {receiptModel,retainedReceipts,retryRetained} from './retained.mjs';

const ACTIONS=['/erasure/reset-preview','/erasure/reset-consent','/erasure/preview','/erasure/confirm','/erasure/hold','/erasure/policy','/erasure/retry','/erasure/abandon'];
export const ERASURE_READS=['/api/auth/erasure/receipts','/api/auth/erasure/journal','/api/auth/erasure/integrity'];
export const isErasureAction=path=>ACTIONS.includes(path);
async function owner(ctx,request,write=false) {
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('owner_required',403);
 if(write)requireLocalEmail(ctx,s);return s;
}
async function guarded(ctx,s,sql,args) {
 return (await ownerWrite(ctx,s,g=>[ctx.db.prepare(sql+' AND '+g.clause).bind(...args,...g.args)]))[0];
}
const validKind=kind=>{if(!['person','app','organization','installation'].includes(kind))fail('invalid_erasure_kind');return kind;};
const targetOf=(ctx,data)=>String(data.target||data.personId||data.appId||(['organization','installation'].includes(data.kind)?organizationOf(ctx):''));
export async function erasureModel(ctx,request) {
 const s=await owner(ctx,request);
 const [policy,holds,receipts,retained]=await Promise.all([
  one(ctx,'SELECT * FROM auth_erasure_policy WHERE singleton=1'),
  all(ctx,'SELECT id,kind,target,reason,created_at,released_at FROM auth_erasure_holds ORDER BY created_at DESC'),
  receiptModel(ctx),retainedReceipts(ctx,s),
 ]);
 return {resetOrganizations:ctx.organizationId==='root'?await all(ctx,"SELECT id,name FROM auth_organizations WHERE status='active' ORDER BY created_at"):null,policy:policy?{configured:Boolean(policy.configured),...JSON.parse(policy.policy)}:{configured:false},holds,
  receipts:[...receipts,...retained]};
}
export async function erasureRead(ctx,request,path=new URL(request.url).pathname) {
 const s=await owner(ctx,request);
 if(path==='/api/auth/erasure/receipts')return json(await erasureModel(ctx,request));
 const query=new URL(request.url).searchParams;
 ctx=await receiptContext(ctx,query.get('receiptId'),s);
 if(path==='/api/auth/erasure/journal'||path==='/api/auth/erasure/integrity') {
  const saved=await savedJournal(ctx,query.get('receiptId'));
  return json(path.endsWith('/integrity')?await journalIntegrity(ctx,saved):saved??await signedJournal(ctx));
 }
 fail('not_found',404);
}
export async function erasureAction(ctx,request,path,data) {
 if(!isErasureAction(path))fail('not_found',404);
 const s=await owner(ctx,request,true);
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_erasure_request');
 if(path==='/erasure/reset-preview'||path==='/erasure/reset-consent')return resetConsentAction(ctx,s,path,data);
 ctx=await selectErasureContext(ctx,s,path,data);
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
  await ownerWrite(ctx,s,g=>[ctx.db.prepare(`INSERT INTO auth_erasure_holds(id,kind,target,reason,created_by,created_at) SELECT ?,?,?,?,?,? WHERE ${g.clause}`).bind(id,kind,target,reason,s.person_id,ctx.now(),...g.args)]);
  return json({id,kind,target,reason},201);
 }
 if(path==='/erasure/preview') {
  const kind=validKind(data.kind),target=data.releaseNoticeId?await releasePerson(ctx,request,data.releaseNoticeId):targetOf(ctx,data),plan=await planErasure(ctx,kind,target),id=random(),now=ctx.now();
  await ownerWrite(ctx,s,g=>[ctx.db.prepare(`INSERT INTO auth_erasure_previews(id,actor_id,kind,target,digest,created_at,expires_at) SELECT ?,?,?,?,?,?,? WHERE ${g.clause}`).bind(id,s.person_id,kind,target,plan.fingerprint,now,now+600000,...g.args)]);
  return json({id,organizationId:ctx.organizationId,expiresAt:now+600000,...publicPlan(plan)});
 }
 if(path==='/erasure/retry'||path==='/erasure/abandon') {
  if(typeof data.receiptId!=='string')fail('invalid_erasure_receipt');
  const abandon=path==='/erasure/abandon';
  if(data.retained===true){await retryRetained(ctx,s,data,abandon);return json(await erasureModel(ctx,request));}
  await guarded(ctx,s,'UPDATE auth_erasure_receipts SET status=status WHERE id=?',[data.receiptId]);
  if(abandon)await abandonRemote(ctx,data.receiptId,data,build=>ownerWrite(ctx,s,build));
  else {await consentRemote(ctx,data.receiptId,data,build=>ownerWrite(ctx,s,build));await executeRemote(ctx,data.receiptId,{assertAuthority:()=>assertOwnerProof(ctx,s)});}
  await run(ctx,"INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES(?,?,?,?)",s.person_id,abandon?'erasure_remote_abandoned':'erasure_remote_retry',data.receiptId,ctx.now());
  return json(await erasureModel(ctx,request));
 }
 const preview=await one(ctx,'SELECT * FROM auth_erasure_previews WHERE id=?',String(data.previewId||data.id||''));
 if(!preview||preview.actor_id!==s.person_id||preview.expires_at<=ctx.now())fail('erasure_preview_expired',409);
 const plan=await planErasure(ctx,preview.kind,preview.target);
 if(plan.fingerprint!==preview.digest)fail('erasure_preview_changed',409);
 if(data.confirmation!==plan.confirmation)fail('erasure_confirmation_required');
 if(plan.installationReset&&(data.destinations?.length||data.confirmRemoteDeletion===true))fail('organization_consent_required',403);
 return json(await commitErasure(ctx,s,plan,preview.id,plan.installationReset?(plan.resetConsent?.destinations??[]):deletionConsent(plan,data)));
}
