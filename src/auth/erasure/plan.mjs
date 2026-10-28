import {privatePairStore} from './pair-erasure.mjs';
import {followupReferences,followupErasure} from '../obligations/erasure.mjs';
import {fail,hash,random} from '../core.mjs';
import {snapshot,erasureTable} from './schema.mjs';
import {anonymous,contains,isEvidence,referenceColumns} from './scrub.mjs';
import {sourceOf,organizationOf} from './journal.mjs';
import {resetConsent} from './reset-policy.mjs';

const rowId=(table,index)=>table+':'+index;
const serialized=new Set(['record','detail','data','subject','params','effect','target_state','reason','outcome','undo_report','metadata','message','payload','resources','program','plan','verification','policy','snapshot','purpose']);
const staging=new Set(['rer_portability_jobs','rer_portability_parts','rer_portability_segments','rer_portability_owned']);
const values=(stores,name)=>stores.get(name)?.rows||[];
const text=v=>typeof v==='string'&&v.length>0;
export async function planErasure(ctx,kind,target,reference='erased:'+random()) {
 if(!['person','app','organization','installation'].includes(kind))fail('invalid_erasure_kind');
 if(typeof target!=='string'||!target||target.length>512)fail('invalid_erasure_target');
 if(kind==='organization'&&ctx.organizationId!=='root'&&!ctx.installationAuthority&&!ctx.organizationOwnerConsent)fail('installation_owner_required',403);
 if(kind==='organization'&&target!==organizationOf(ctx))fail('wrong_erasure_organization',403);
 if(kind==='installation'&&(!ctx.local||ctx.organizationId&&ctx.organizationId!=='root'))fail('local_installation_reset_required',403);
 const reset=['organization','installation'].includes(kind),stores=await snapshot(ctx);
 const otherOrganizations=values(stores,'auth_organizations').some(org=>org.id!=='root');
 if(kind==='installation'&&otherOrganizations)fail('installation_reset_requires_cli',409);
 if(kind==='organization'&&(!ctx.organizationId||ctx.organizationId==='root')&&otherOrganizations)fail('root_organization_reset_requires_installation',409);
 const people=values(stores,'oa_operators'),person=people.find(p=>p.id===target);
 const app=values(stores,'auth_apps').find(a=>a.id===target)||values(stores,'auth_clients').find(a=>a.id===target);
 if(kind==='person'&&!person)fail('person_not_found',404);
 if(kind==='app'&&!app)fail('app_not_found',404);
 if(person?.role==='owner'&&person.status==='active'&&people.filter(p=>p.role==='owner'&&p.status==='active').length<=1)fail('last_owner_requires_reset_or_transfer',409);
 const identifiers=new Set(reset?people.flatMap(p=>[p.id,p.email]):[target]),historicalAddresses=new Set();
 const names=new Set(reset?people.map(p=>p.display_name).filter(text):[]);
 if(person){identifiers.add(person.email);names.add(person.display_name);}
 if(app){for(const v of [app.client_id,app.sector_id,app.origin])if(text(v))identifiers.add(v);names.add(app.name);}
 // Historical addresses must be recovered from records explicitly bound to
 // this person, never from a shared actor or an unrelated audit detail.
 if(person) {
  for(const row of values(stores,'auth_events')) {
   let subject,data;try{subject=JSON.parse(row.subject);data=JSON.parse(row.data);}catch{continue;}
   if(subject?.type==='person'&&subject.id===target) {
    if(text(subject.email))historicalAddresses.add(subject.email);
    if(row.type==='person.invited'&&text(data?.name))names.add(data.name);
   }
  }
  const changes=new Set(values(stores,'auth_activity').filter(row=>row.subject_id===target&&row.event==='directory_person_updated').map(row=>row.id));
  for(const row of values(stores,'auth_activity_details'))if(changes.has(row.activity_id)) {
   let detail;try{detail=JSON.parse(row.detail);}catch{continue;}
   for(const address of [detail?.email?.from,detail?.email?.to])if(text(address))historicalAddresses.add(address);
  }
 }

 for(const name of ['auth_person_sources','auth_former_subjects','oa_external_identities'])for(const row of values(stores,name))if(reset||row.person_id===target||row.operator_id===target)for(const field of ['source_id','subject'])if(text(row[field]))identifiers.add(row[field]);
 // Session/factor/grant identifiers can occur in copies without the person's ID.
 for(const name of ['auth_sessions','oa_sessions','auth_passkeys','auth_agent_keys','auth_admin_service_apps'])for(const row of values(stores,name))if(reset||row.person_id===target||row.operator_id===target||row.owner_id===target)for(const field of ['id','client_id'])if(text(row[field]))identifiers.add(row[field]);
 for(const row of values(stores,'auth_delegated_agents'))if(reset||row.registered_by===target||identifiers.has(row.client_id)){identifiers.add(row.id);identifiers.add(row.client_id);}
 for(const row of [...values(stores,'auth_delegated_tasks'),...values(stores,'auth_external_tasks')])if(reset||contains(row,identifiers))identifiers.add(row.id);
 if(kind==='app')for(const row of values(stores,'auth_oidc_clients'))if(row.app_id===target)identifiers.add(row.client_id);
 for(const name of ['auth_refresh_families','auth_refresh_consents'])for(const row of values(stores,name))if(reset||contains(row,identifiers))identifiers.add(row.id);
 followupReferences(stores,identifiers,reset);
 const holds=values(stores,'auth_erasure_holds').filter(h=>!h.released_at&&(reset||h.kind==='installation'||h.kind==='organization'&&h.target===organizationOf(ctx)||h.kind===kind&&identifiers.has(h.target)));
 const policy=values(stores,'auth_erasure_policy')[0];
 // Old addresses can have a new holder. They redact retained evidence only;
 // they must never select another person's account or credentials for deletion.
 const evidenceIdentifiers=new Set([...identifiers,...historicalAddresses]);
 const removed=new Set(),updates=new Map(),decisions=[];
 // Role/state/type labels are values, never person identifiers. In particular,
 // erasing a creator whose id is 'owner' must not select every owner role.
 const canMatch=(name,row)=>contains(Object.fromEntries(Object.entries(row).filter(([column])=>!['role','state','status','kind','event','type'].includes(column))),identifiers);
 const steward=people.find(p=>p.id!==target&&p.role==='owner'&&p.status==='active')?.id;
 for(const table of stores.values())for(const [index,row] of table.rows.entries()) {
  const key=rowId(table.name,index),name=table.name;
  if(erasureTable(name)||['rer_portability_state','rer_portability_journal','rer_portability_epochs'].includes(name))continue;
  // Immutable task effects are authority, not editable provenance. Preserve
  // their anonymous decision before removing the exact grant and its bindings.
  if(['auth_delegated_tasks','auth_external_tasks'].includes(name)&&(reset||identifiers.has(row.id)||contains(row,identifiers))) {
   removed.add(key);decisions.push({kind:name==='auth_external_tasks'?'delegated_external_task':'delegated_assignment',status:row.state,createdAt:row.created_at,decidedAt:row.completed_at??row.revoked_at??row.approved_at??row.consented_at,reference});continue;
  }
  const followup=followupErasure(table,row,{stores,identifiers,reset,reference});
  if(followup) {if(followup.remove)removed.add(key);else updates.set(key,followup.update);continue;}
  // A leaver capture belongs to its subject. Erasing an approver must redact
  // their provenance without deleting another person's retained execution.
  if(name==='auth_lifecycle_plans'&&kind==='person'&&row.person_id!==target) {
   const changed={};
   for(const column of ['actor_id','custodian_id'])if(identifiers.has(row[column]))changed[column]=reference;
   if(contains(row.plan,evidenceIdentifiers))changed.plan=JSON.stringify(anonymous(JSON.parse(row.plan),new Set([...evidenceIdentifiers,...names].filter(text)),reference));
   if(Object.keys(changed).length)updates.set(key,changed);
   continue;
  }
  const relatedActivity=name==='auth_activity_details'&&values(stores,'auth_activity').some(a=>a.id===row.activity_id&&(canMatch('auth_activity',a)||contains(a.subject_id,historicalAddresses)));
  const matched=relatedActivity||canMatch(name,row)||isEvidence(name)&&contains(row.subject_id,historicalAddresses),discardMap=name==='auth_grant_maps',discardStage=staging.has(name);
  if(isEvidence(name)) {
   if(reset||matched) {
    const changed={};
    for(const [column,value] of Object.entries(row)) {
     if(referenceColumns.has(column)&&text(value)&&(reset||contains(value,evidenceIdentifiers)))changed[column]=reference;
     else if(serialized.has(column)&&text(value))changed[column]=column==='subject'&&value.startsWith('{')?JSON.stringify({type:'erased',id:reference}):column==='detail'||column==='data'||['params','effect','target_state','outcome'].includes(column)?JSON.stringify({erasure:reference}):anonymous(value,new Set([...evidenceIdentifiers,...names].filter(text)),reference);
     else if((column==='target'||column==='value')&&text(value)&&(reset||contains(value,evidenceIdentifiers)))changed[column]=reference;
    }
    // An erased key's proposal cannot retain its foreign-key dependency. Keep
    // its decision, event time and kind in the receipt before removing it.
    if(name==='auth_agent_proposals'&&(reset||identifiers.has(row.key_id))){removed.add(key);decisions.push({kind:row.kind,status:row.status,createdAt:row.created_at,decidedAt:row.decided_at,reference});}
    else if(Object.keys(changed).length)updates.set(key,changed);
   }
   continue;
  }
  if(reset||discardMap||discardStage){removed.add(key);continue;}
  const direct=Object.entries(row).some(([column,value])=>text(value)&&identifiers.has(value)&&(
   ['person_id','operator_id','session_id','owner_id','owner_person_id','key_id','client_id','app_id','subject_id','sector_id','email','source_id','family_id','refresh_consent_id'].includes(column)||column==='id'&&['oa_operators','auth_apps','auth_clients'].includes(name)));
  if(direct||matched&&Object.keys(row).some(c=>serialized.has(c)||['email','source_id','subject','bucket'].includes(c))){removed.add(key);continue;}
  const changed={};
  for(const [column,value] of Object.entries(row))if(referenceColumns.has(column)&&text(value)&&identifiers.has(value)) {
   const fk=table.foreignKeys.find(f=>f.from===column&&f.table==='oa_operators');
   changed[column]=fk?(table.columns.find(c=>c.name===column)?.notnull?steward:null):reference;
   if(fk&&!changed[column]&&table.columns.find(c=>c.name===column)?.notnull)fail('erasure_custody_transfer_required',409);
  }
  if(Object.keys(changed).length)updates.set(key,changed);
 }
 // Close actual foreign-key dependencies, including tables added after this
 // edition. Nullable provenance references can be anonymized without deleting
 // another person's authentication state.
 let added=true;
 while(added){added=false;for(const table of stores.values())for(const [index,row] of table.rows.entries()) {
  const key=rowId(table.name,index);if(removed.has(key)||erasureTable(table.name))continue;
  for(const fk of table.foreignKeys) {
   // An explicit anonymization already removes this dependency.
   if(row[fk.from]===null||Object.hasOwn(updates.get(key)??{},fk.from))continue;
   const parent=stores.get(fk.table);if(!parent)continue;
   const dependency=parent.rows.some((r,i)=>r[fk.to]===row[fk.from]&&removed.has(rowId(parent.name,i)));
   if(!dependency)continue;
   const changed=updates.get(key)||{},column=table.columns.find(c=>c.name===fk.from);
   if(referenceColumns.has(fk.from)&&!reset) {
    changed[fk.from]=column?.notnull?steward:null;
    if(column?.notnull&&!steward)fail('erasure_custody_transfer_required',409);
    updates.set(key,changed);
   }else {removed.add(key);updates.delete(key);added=true;
    if(isEvidence(table.name)||['auth_delegated_tasks','auth_external_tasks'].includes(table.name))decisions.push({kind:['auth_delegated_tasks','auth_external_tasks'].includes(table.name)?'delegated_assignment':row.kind||row.event||row.type,status:row.status??row.state,createdAt:row.created_at||row.occurred_at,decidedAt:row.decided_at??row.completed_at??row.revoked_at??row.approved_at??row.consented_at,reference});
   }
  }
 }}
 const remote=[];
 for(const account of values(stores,'auth_scim_accounts'))if(reset||kind==='person'&&identifiers.has(account.subject_id)||kind==='app'&&account.app_id===target) {
  if(account.state==='deleted')continue;
  const connector=values(stores,'auth_scim_connectors').find(c=>c.app_id===account.app_id);
  remote.push({kind:'scim-delete',appLabel:values(stores,'auth_apps').find(a=>a.id===account.app_id)?.name||'SCIM app',partner:connector?new URL(connector.base_url).origin:'connector unavailable',work:connector?{connector,remoteId:account.remote_id,resource:account.subject_type==='group'?'Groups':'Users'}:null});
 }
 // Linked-app fences are authority revocation; independently held app data is
 // a named partner deletion task rather than a claimed remote deletion.
 for(const client of values(stores,'auth_clients'))if(reset||kind==='app'&&client.id===target||kind==='person'&&values(stores,'auth_grants').some(g=>g.client_id===client.id&&g.person_id===target)) {
  remote.push({kind:'partner-delete',appLabel:client.name||'Linked app',partner:client.origin,work:null});
 }
 for(const company of values(stores,'auth_apps')) {
  const groups=new Set(values(stores,'auth_group_members').filter(m=>m.person_id===target).map(m=>m.group_id));
  const assigned=values(stores,'auth_app_assignments').some(a=>a.app_id===company.id&&(a.principal_type==='person'&&a.principal_id===target||a.principal_type==='group'&&groups.has(a.principal_id)));
  const held=values(stores,'auth_scim_accounts').some(a=>a.app_id===company.id&&a.subject_id===target);
  if(reset||kind==='app'&&company.id===target||kind==='person'&&(assigned||held)) {
   let partner='app:'+company.id;
   let acs=[];try{acs=JSON.parse(company.acs);}catch{}
   let redirect=[];try{redirect=JSON.parse(values(stores,'auth_oidc_clients').find(client=>client.app_id===company.id)?.redirect_uris||'[]');}catch{}
   try{partner=new URL(company.launch_url||acs[0]?.url||redirect[0]).origin;}catch{}
   remote.push({kind:'partner-delete',appLabel:company.name||'Company app',partner,work:null});
  }
 }
 // Delivered event/hook copies are independently held processor data. A
 // local erase cannot silently treat their deletion as a verified outcome.
 const events=new Set(values(stores,'auth_events').filter(row=>reset||contains(row,identifiers)).map(row=>row.id));
 const subscriptions=new Set(values(stores,'auth_event_deliveries').filter(row=>reset||events.has(row.event_id)).map(row=>row.subscription_id));
 for(const subscription of values(stores,'auth_event_subscriptions'))if(reset||subscriptions.has(subscription.id))remote.push({kind:'partner-delete',partner:new URL(subscription.url).origin,work:null});
 for(const hook of values(stores,'auth_hooks'))if(reset||values(stores,'auth_activity_details').some(row=>contains(row,identifiers)&&String(row.detail).includes(hook.id)))remote.push({kind:'partner-delete',partner:new URL(hook.url).origin,work:null});
 const counts=[];
 for(const table of stores.values()) {
  const deleted=table.rows.filter((_,i)=>removed.has(rowId(table.name,i))).length,anonymized=table.rows.filter((_,i)=>updates.has(rowId(table.name,i))&&!removed.has(rowId(table.name,i))).length;
  counts.push({store:table.name,examined:table.rows.length,deleted,anonymized,status:'complete'});
 }
 const consent=ctx.installationAuthority?await resetConsent(ctx,{remote}):null;
 const fingerprint=await hash(JSON.stringify([[...stores].map(([name,t])=>[name,t.rows]),...(ctx.installationAuthority?[consent]:[])]));
 return {kind,target,reference,reset,installationReset:Boolean(ctx.installationAuthority),resetConsent:consent,stores,removed,updates,identifiers,names,holds,policy,counts,remote,decisions,fingerprint,
  confirmation:reset?`RESET ${sourceOf(ctx)}`:'ERASE',source:sourceOf(ctx),organization:organizationOf(ctx)};
}
export const keyOf=rowId;
export const publicPlan=plan=>({kind:plan.kind,target:plan.target,confirmation:plan.confirmation,stores:plan.counts.filter(row=>!privatePairStore(row.store)),
 remote:plan.remote.map(r=>({kind:r.kind,...(plan.installationReset?{app:r.appLabel||'Connected app',deletionPreauthorized:Boolean(plan.resetConsent?.destinations.includes(r.partner))}:{partner:r.partner}),state:r.work?'awaiting-confirmation':'partner-action-required'})),
 holds:plan.holds.map(h=>({id:h.id,kind:h.kind,...(plan.installationReset?{}:{reason:h.reason})})),policyConfigured:Boolean(plan.policy?.configured),
 limits:['Mailbox/provider owners must delete already delivered messages; Auth cannot recall them.','Installation owners must delete exported archive/backup copies or supply the later erasure journal on restore.','External audit receiver owners must delete delivered event copies; Auth cannot verify that independent storage.','Ask every named partner to delete its independently held copies and confirm completion.','Save the receipt and signed erasure journal before local reset; an old archive cannot discover a later journal.']});
