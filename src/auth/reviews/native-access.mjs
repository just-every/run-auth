import {all,one,fail,random} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {planChange} from '../roles/plans.mjs';
import {requireHardware} from '../roles/policy.mjs';
import {ALL_RESOURCES,BUILTINS,LEGACY_RANK} from '../roles/permissions.mjs';
import {requireLocalEmail} from '../local-email.mjs';
import {fencePerson} from '../links/logout.mjs';
import {personChanged} from '../provisioning/obligations.mjs';
import {emit,personSubject} from '../events/store.mjs';

export const isNativeItem=item=>['administrator_grant','installation_role'].includes(item.principal_type);
const stored=item=>typeof item.snapshot==='string'?JSON.parse(item.snapshot):item.snapshot;
const roleDefinition=role=>({id:role.id,name:role.name,rank:role.rank,revision:role.revision,builtin:role.builtin,permissions:[...role.permissions]});
function sourceOf(person,grant=null) {
 const role=grant?.role??{id:person.role,name:person.role==='owner'?'Owner':'Administrator',rank:LEGACY_RANK[person.role],revision:1,builtin:true,permissions:BUILTINS[0].permissions};
 return {kind:grant?'administrator_grant':'installation_role',personVersion:person.version,installationRole:person.role,role:roleDefinition(role),resources:grant?.resources??ALL_RESOURCES,
  ...(grant?{grant:{id:grant.id,personId:grant.person_id,roleId:grant.role_id,roleRevision:grant.role_revision,grantedBy:grant.granted_by,sponsorGrantId:grant.sponsor_grant_id,createdAt:grant.created_at,revokedAt:grant.revoked_at}}:{})};
}

// These rows identify Auth's real administration resource. They do not create
// an app, a grant or an alternative permission evaluator.
export async function nativeSnapshot(ctx,state,now=ctx.now()) {
 const appId=(ctx.issuer??ctx.origin).replace(/\/$/,'')+'/api/auth/roles';
 const uses=await all(ctx,'SELECT person_id,MAX(last_used_at) AS last_used_at FROM auth_passkeys GROUP BY person_id');
 const items=[];
 const add=(person,grant)=>{
  const source=sourceOf(person,grant),principalType=source.kind,principalId=grant?.id??person.id,role=source.role.id;
  const snapshot={identity:{id:person.id,email:person.email,name:person.name,kind:state.dir.values(person).kind,status:person.status},groups:[...(state.memberships.get(person.id)??[])].sort(),assignment:{appId,app:'Auth administration',principalType,principalId,role,grantRole:role},source,lastObservedUse:uses.find(u=>u.person_id===person.id)?.last_used_at??null,freshness:{observedAt:now,providerObservedAt:null,usage:'unknown: passkey use is not administration usage'}};
  items.push({subject_id:person.id,app_id:appId,principal_type:principalType,principal_id:principalId,role,snapshot});
 };
 for(const person of state.dir.people.values())if(person.status==='active'&&['owner','admin'].includes(person.role))add(person,null);
 for(const grant of state.activeGrants)add(state.dir.people.get(grant.person_id),grant);
 return items.sort((a,b)=>[a.subject_id,a.principal_type,a.principal_id].join(':').localeCompare([b.subject_id,b.principal_type,b.principal_id].join(':')));
}

export async function nativeItemDrift(ctx,item) {
 const person=await one(ctx,'SELECT id,status FROM oa_operators WHERE id=?',item.subject_id);
 if(person?.status!=='active')return true;
 const state=await roleState(ctx,{person_id:person.id}),current=state.dir.people.get(person.id);
 const grant=item.principal_type==='administrator_grant'?state.activeGrants.find(g=>g.id===item.principal_id&&g.person_id===person.id):null;
 if(item.principal_type==='administrator_grant'&&!grant||item.principal_type==='installation_role'&&!['owner','admin'].includes(current.role))return true;
 return JSON.stringify(sourceOf(current,grant))!==JSON.stringify(stored(item).source);
}

export async function nativeTarget(ctx,s,item,operation) {
 if(item.reviewer_id!==s.person_id)fail('reviewer_required',403);
 if(item.subject_id===s.person_id)fail('self_approval_refused',403);
 if(operation==='reduce')fail('native_role_reduction_not_available',409);
 if(!['certify','revoke'].includes(operation))fail('review_decision_not_available');
 if(await nativeItemDrift(ctx,item))fail('review_access_changed',409);
 const native=stored(item).source;
 if(operation==='revoke') {
  requireHardware(s);requireLocalEmail(ctx,s);
  const state=await roleState(ctx,s),person=state.dir.people.get(item.subject_id);
  if(person.role==='owner'||native.role.id==='owner')fail('owner_revocation_refused',403);
  if(item.principal_type==='administrator_grant')planChange(state,s,{kind:'revoke',grantId:item.principal_id});
  else {
   if(state.person.role!=='owner')fail('owner_required',403);
   if(state.rankOf(person.id)>=state.rank)fail('lower_rank_required',403);
  }
 }
 return {native,administratorGate:operation==='revoke'};
}

export function nativeStatements(ctx,s,item,operation,won,p) {
 if(operation!=='revoke')return [];
 const now=ctx.now(),source=stored(item).source,id=random(),detail=JSON.stringify({reviewId:item.review_id,itemId:item.id,decisionOperationId:won.args[0],source});
 return [
  p(`INSERT INTO auth_role_operations(id,actor_id,session_id,permission,subject_id,detail,created_at) SELECT ?,?,?,'reviews.revoke',?,?,? WHERE ${won.clause}`,id,s.person_id,s.id,item.subject_id,detail,now,...won.args),
  item.principal_type==='administrator_grant'
   ?p(`UPDATE auth_role_grants SET revoked_at=?,revoked_by=? WHERE id=? AND revoked_at IS NULL AND ${won.clause}`,now,s.person_id,item.principal_id,...won.args)
   :p(`UPDATE oa_operators SET role='member',version=version+1 WHERE id=? AND role='admin' AND version=? AND ${won.clause}`,item.subject_id,source.personVersion,...won.args),
  p(`UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND revoked_at IS NULL AND ${won.clause}`,now,item.subject_id,...won.args),
  p(`INSERT INTO auth_role_events(operation_id,actor_id,session_id,event,subject_id,detail,created_at) SELECT ?,?,?,'reviews.revoke',?,?,? WHERE ${won.clause}`,id,s.person_id,s.id,item.subject_id,detail,now,...won.args),
 ];
}

export async function nativeAfter(ctx,item,operation) {
 if(operation==='revoke'&&item.principal_type==='installation_role') {
  await fencePerson(ctx,item.subject_id);
  await emit(ctx,'person.role_changed',await personSubject(ctx,item.subject_id),{role:'member'});
  await personChanged(ctx,item.subject_id,'person_role_changed');
 }
}

export async function nativeRemediation(ctx,item) {
 if(!item.decision)return {state:'awaiting_decision',complete:false};
 if(item.decision==='certify')return {state:'certified',complete:true};
 if(item.decision!=='revoke')return {state:'native_role_reduction_not_available',complete:false};
 const current=item.principal_type==='administrator_grant'
  ?await one(ctx,'SELECT revoked_at FROM auth_role_grants WHERE id=?',item.principal_id)
  :await one(ctx,'SELECT role FROM oa_operators WHERE id=?',item.subject_id);
 const complete=item.principal_type==='administrator_grant'?Boolean(current&&current.revoked_at!==null):Boolean(current&&!['owner','admin'].includes(current.role));
 return {state:complete?'native_access_revoked':'local_access_still_present',complete,detail:'Auth administration is local; dependent grants retain no authority without their live sponsor.'};
}
