import {deliverGenericLogouts} from '../../oidc-apps/session.mjs';
import {prepareLeaver} from '../../lifecycle/plan.mjs';
import {reconcileLeavers} from '../../lifecycle/history.mjs';
import {deliverLogouts} from '../../links/logout.mjs';
import {dispatch} from '../../provisioning/obligations.mjs';
// Doing a plan: every statement of a person's edit commits together, each under
// the administrator's live authority, then the effects follow (sign-out fence,
// events, provisioning, group provisioning) once the change has committed.
import {random,fail,auditDetail} from '../../core.mjs';
import {requireAuthority} from '../../local-email.mjs';
import {commitAccountWrite} from '../../ranks.mjs';
import {setStatement,clearStatement} from './fields.mjs';
import {addRuleMember,dropRuleMember} from './groups.mjs';
import {planEdit} from './plan.mjs';
import {fencePerson} from '../../links/logout.mjs';
import {personChanged,groupChanged} from '../../provisioning/obligations.mjs';
import {emit,personSubject} from '../../events/store.mjs';

const EVENTS={suspend:'person.suspended',terminate:'person.terminated',restore:'person.restored',rehire:'person.restored'};
const REASONS={suspend:'person_suspended',terminate:'person_terminated',restore:'person_restored',rehire:'person_restored'};

function stateStatements(ctx,g,id,change,at) {
 const claim=`id=? AND role!='owner'`;
 if(change.kind==='suspend')return [ctx.db.prepare(`UPDATE oa_operators SET status='inactive' WHERE ${claim} AND status='active' AND ${g.clause}`).bind(id,...g.args)];
 if(change.kind==='terminate')return [
  ctx.db.prepare(`INSERT INTO auth_people(person_id,terminated_at) SELECT ?,? WHERE ${g.clause} AND EXISTS(SELECT 1 FROM oa_operators WHERE ${claim} AND status IN ('active','inactive')) ON CONFLICT(person_id) DO UPDATE SET terminated_at=excluded.terminated_at`).bind(id,at,...g.args,id),
  ctx.db.prepare(`UPDATE oa_operators SET status='inactive' WHERE ${claim} AND status IN ('active','inactive') AND ${g.clause}`).bind(id,...g.args),
 ];
 return [ctx.db.prepare(`UPDATE oa_operators SET status='active' WHERE id=? AND status='inactive' AND ${g.clause}`).bind(id,...g.args)];
}

// The statements of one planned entry; `stateAt` is the index of the status change, whose row count proves it applied.
function entryStatements(ctx,g,actorId,dir,e,at=ctx.now()) {
 const statements=[];let stateAt=-1;
 for(const w of e.writes)statements.push(w.value===null?clearStatement(ctx,g,e.personId,w.field,w.source):setStatement(ctx,g,e.personId,w.field,w.source,w.value,actorId));
 if(e.nameChange)statements.push(ctx.db.prepare(`UPDATE oa_operators SET display_name=? WHERE id=? AND ${g.clause}`).bind(e.nameChange.to,e.personId,...g.args));
 if(e.emailChange)statements.push(
  ctx.db.prepare(`DELETE FROM auth_emails WHERE person_id=? AND ${g.clause}`).bind(e.personId,...g.args),
  ctx.db.prepare(`UPDATE oa_operators SET email=?,version=version+1 WHERE id=? AND ${g.clause}`).bind(e.emailChange.to,e.personId,...g.args));
 if(e.bind&&!dir.sourceIds.has(`${e.bind.source}:${e.personId}`))statements.push(ctx.db.prepare(`INSERT INTO auth_person_sources(source,source_id,person_id,bound_by,bound_at) SELECT ?,?,?,?,? WHERE ${g.clause}`).bind(e.bind.source,e.bind.sourceId,e.personId,actorId,ctx.now(),...g.args));
 if(e.state){const s=stateStatements(ctx,g,e.personId,e.state,at);stateAt=statements.length+s.length-1;statements.push(...s);}
 for(const gr of e.groups.added)statements.push(addRuleMember(ctx,g,gr.id,e.personId,actorId));
 for(const gr of e.groups.removed)statements.push(dropRuleMember(ctx,g,gr.id,e.personId));
 return {statements,stateAt};
}
const touched=e=>e.writes.length||e.state||e.emailChange||e.nameChange||e.bind||e.groups.added.length||e.groups.removed.length;

// Effects that follow a committed change. Identity fences go out for anything that ends sessions.
async function afterwards(ctx,actorId,e,bulk,leaver) {
 const id=e.personId,subject=await personSubject(ctx,id);
 if(e.state){
  if(!leaver&&(e.state.kind==='suspend'||e.state.kind==='terminate'))await fencePerson(ctx,id);
  await emit(ctx,EVENTS[e.state.kind],subject,{});if(!leaver)await personChanged(ctx,id,REASONS[e.state.kind]);
 }
 if(e.emailChange&&!leaver){await fencePerson(ctx,id);await personChanged(ctx,id,'person_email_changed');}
 else if(e.nameChange&&!e.state)await personChanged(ctx,id,'person_name_changed');
 if(e.writes.length||e.nameChange||e.emailChange)await emit(ctx,'person.updated',subject,{fields:[...new Set([...e.writes.map(w=>w.field),...(e.nameChange?['name']:[]),...(e.emailChange?['email']:[])])],source:e.source});
 for(const [list,type,reason] of [[e.groups.added,'group.member_added','group_member_added'],[e.groups.removed,'group.member_removed','group_member_removed']])
  for(const gr of list){await emit(ctx,type,subject,{group:gr.id,via:'rule'});if(!leaver)await groupChanged(ctx,gr.id,[id],reason);}
 if(leaver){const work=(async()=>{await deliverLogouts(ctx);await deliverGenericLogouts(ctx);await dispatch(ctx);await reconcileLeavers(ctx);})();if(ctx.waitUntil)ctx.waitUntil(work);else await work;}
 await auditDetail(ctx,actorId,e.state?`person_${e.state.kind==='terminate'?'terminated':e.state.kind==='suspend'?'suspended':e.state.kind==='rehire'?'rehired':'restored'}`:'directory_person_updated',id,{source:e.source,bulk,changes:e.changes,state:e.state,email:e.emailChange,groups:{added:e.groups.added.map(g=>g.name),removed:e.groups.removed.map(g=>g.name)},apps:e.apps});
}

export function applyPlan(ctx,s,guard,dir,planned,options) {
 return applyAuthorizedPlan(ctx,{actorId:s.person_id,assertAuthority:()=>requireAuthority(ctx,s,guard)},guard,dir,planned,options);
}
export async function applyAuthorizedPlan(ctx,actor,guard,dir,planned,{bulk=false}={}) {
 const results=[];
 for(const e of planned.entries) {
  if(!touched(e)){results.push({personId:e.personId,changed:false});continue;}
  const leaver=prepareLeaver(ctx,e,planned.digest,actor.actorId,dir.people.get(e.personId).version);
  const build=g=>{const held=leaver?{clause:`(${g.clause}) AND (${leaver.held.clause})`,args:[...g.args,...leaver.held.args]}:g;return [...(leaver?.statements(g)??[]),...entryStatements(ctx,held,actor.actorId,dir,e,leaver?.at).statements,...(actor.receiptStatements?.(held,e.personId)??[])];};
  const prefix=leaver?.statements(guard).length??0;
  const stateAt=entryStatements(ctx,guard,actor.actorId,dir,e).stateAt+prefix,statements=build(guard);
  let done;
  try {
   const accountEdit=(e.writes.length||e.state||e.emailChange||e.nameChange)&&!(e.source==='self'&&e.personId===actor.actorId);
   done=accountEdit?await commitAccountWrite(ctx,actor,e.personId,guard,build):await (actor.commit??(statements=>ctx.db.batch(statements)))(statements);
  }
  catch(error) {
   await actor.assertAuthority();
   if(/UNIQUE|constraint/i.test(String(error?.message)))fail(e.emailChange?'email_in_use':'source_id_in_use',409);
   throw error;
  }
  await actor.assertAuthority();
  if(stateAt>=0&&!done[stateAt].meta.changes)fail('person_changed',409);
  await afterwards(ctx,actor.actorId,e,bulk,leaver);
  results.push({personId:e.personId,changed:true,...(leaver?{planId:leaver.id}:{})});
 }
 return results;
}

// A new person: Base's invited member row, the values the administrator gave, and the groups their values put them in.
export function onboardPerson(ctx,s,guard,dir,data,notify) {
 return onboardAuthorizedPerson(ctx,{actorId:s.person_id,assertAuthority:()=>requireAuthority(ctx,s,guard)},guard,dir,data,notify);
}
export async function onboardAuthorizedPerson(ctx,actor,guard,dir,data,notify) {
 const address=String(data.email??'');
 const probe={id:random(),email:address.trim().toLowerCase(),name:String(data.name||address).replace(/\s+/g,' ').trim().slice(0,160),role:'member',status:'invited',state:'invited',fields:new Map()};
 const taken=dir.byEmail.get(probe.email);
 if(taken)return {refused:[taken.state==='terminated'||taken.state==='suspended'?'rehire_review_required':'person_exists'],personId:taken.id};
 dir.people.set(probe.id,probe);dir.byEmail.set(probe.email,probe);
 const set={...data.set};if(data.kind!==undefined)set.kind=data.kind;
 delete set.name;
 const e=await planEdit(ctx,dir,{personId:probe.id,source:data.source??'manual',set,email:probe.email,bind:data.sourceId?{source:data.source,sourceId:String(data.sourceId).trim().slice(0,128)}:null},actor.actorId);
 if(!probe.email||!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(probe.email)||(!ctx.local&&/\.(localhost|test|invalid)$/.test(probe.email)))e.refusals.push('invalid_email');
 if(data.sourceId&&!['hr','directory'].includes(data.source))e.refusals.push('invalid_source');
 if(e.refusals.length)return {refused:e.refusals,plan:e};
 const {statements}=entryStatements(ctx,guard,actor.actorId,dir,{...e,emailChange:null});
 const insert=ctx.db.prepare(`INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE ${guard.clause} AND NOT EXISTS(SELECT 1 FROM oa_operators WHERE email=?)`).bind(probe.id,probe.email,probe.name,ctx.now(),...guard.args,probe.email);
 try {await (actor.commit??(statements=>ctx.db.batch(statements)))([insert,...statements,...(actor.receiptStatements?.(guard,probe.id)??[])]);}
 catch(error) {await actor.assertAuthority();if(/UNIQUE|constraint/i.test(String(error?.message)))fail(data.sourceId?'source_id_in_use':'person_exists',409);throw error;}
 await actor.assertAuthority();
 await auditDetail(ctx,actor.actorId,'person_onboarded',probe.id,{email:probe.email,source:e.source,fields:e.writes.map(w=>w.field),groups:e.groups.added.map(g=>g.name)});
 await emit(ctx,'person.invited',{type:'person',id:probe.id,email:probe.email},{name:probe.name,source:e.source});
 for(const gr of e.groups.added){await emit(ctx,'group.member_added',{type:'person',id:probe.id,email:probe.email},{group:gr.id,via:'rule'});await groupChanged(ctx,gr.id,[probe.id],'group_member_added');}
 if(data.invite!==false)await notify(ctx,probe.email);
 return {personId:probe.id,plan:e};
}
