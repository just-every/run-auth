import {all,one,hash} from '../core.mjs';
import {roleState} from '../roles/state.mjs';

// The stored snapshot is never refreshed in place. Current observations are a
// separate drift report, not a rewrite of what a reviewer was asked to certify.
export async function accessSnapshot(ctx,s) {
 const state=await roleState(ctx,s),now=ctx.now(),items=[];
 const [lastUses,connectors,denials]=await Promise.all([
  all(ctx,'SELECT person_id,MAX(last_used_at) AS last_used_at FROM auth_passkeys GROUP BY person_id'),
  all(ctx,'SELECT app_id,last_success_at,last_reconciled_at FROM auth_scim_connectors'),
  all(ctx,'SELECT app_id,person_id FROM auth_app_denials'),
 ]);
 for(const a of state.dir.assignments) {
  const ids=a.principal_type==='person'?[a.principal_id]:[...state.memberships].filter(([,groups])=>groups.has(a.principal_id)).map(([id])=>id);
  for(const id of ids) {
   const p=state.dir.people.get(id);if(!p||p.status!=='active'||denials.some(d=>d.app_id===a.app_id&&d.person_id===id))continue;
   const fields=state.dir.values(p),connector=connectors.find(c=>c.app_id===a.app_id),last=lastUses.find(u=>u.person_id===id)?.last_used_at??null;
   const snapshot={identity:{id,email:p.email,name:p.name,kind:fields.kind,status:p.status},groups:[...(state.memberships.get(id)??[])].sort(),assignment:{appId:a.app_id,app:a.app,principalType:a.principal_type,principalId:a.principal_id,role:a.role},source:{kind:a.principal_type==='group'?'group':'direct',directory:[...state.dir.sourceIds].filter(([key])=>key.endsWith(':'+id)).map(([key,value])=>({source:key.split(':')[0],id:value}))},lastObservedUse:last,freshness:{observedAt:now,providerObservedAt:connector?.last_reconciled_at??connector?.last_success_at??null,usage:'unknown: passkey use is not app usage'}};
   items.push({subject_id:id,app_id:a.app_id,principal_type:a.principal_type,principal_id:a.principal_id,role:a.role,snapshot});
  }
 }
 return items.sort((a,b)=>keyOf(a).localeCompare(keyOf(b)));
}
export const keyOf=i=>[i.subject_id,i.app_id,i.principal_type,i.principal_id].join(':');
export function comparable(snapshot) {const {freshness,...rest}=snapshot;return rest;}
export const fingerprint=snapshot=>hash(JSON.stringify(comparable(snapshot)));
export async function itemDrift(ctx,item) {
 const snapshot=JSON.parse(item.snapshot),a=snapshot.assignment;
 const current=await one(ctx,'SELECT role FROM auth_app_assignments WHERE app_id=? AND principal_type=? AND principal_id=?',item.app_id,item.principal_type,item.principal_id);
 const p=await one(ctx,'SELECT status,version FROM oa_operators WHERE id=?',item.subject_id);
 const membership=item.principal_type==='person'||Boolean(await one(ctx,'SELECT 1 FROM auth_group_members WHERE group_id=? AND person_id=?',item.principal_id,item.subject_id));
 const denied=await one(ctx,'SELECT 1 FROM auth_app_denials WHERE app_id=? AND person_id=?',item.app_id,item.subject_id);
 return !current||current.role!==a.role||p?.status!=='active'||!membership||Boolean(denied);
}
