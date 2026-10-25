import {verifiedDomain} from '../domains/ownership.mjs';
// What a preparer key may propose. Each kind names its target, reads the
// target's current state, refuses what cannot apply, describes who and which
// apps the change affects, and gives the statements that run it. The approval's
// claim carries `same` (the exact state the proposal was filed against) and any
// `requires` condition, so the claim succeeds only when the effect applies, and
// every effect statement runs only under that claim.
import {email,one,all,fail,hash} from '../core.mjs';
import {configuredProvider} from '../domain-policy.mjs';
import {fencePerson} from '../links/logout.mjs';
import {personChanged} from '../provisioning/obligations.mjs';
import {emit,personSubject} from '../events/store.mjs';
import {DIAGNOSTIC_KINDS} from './diagnostic-kind.mjs';
import {APP_KINDS} from './app-kinds.mjs';

const domainOf=value=>{const domain=String(value||'').trim().toLowerCase();if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||domain.length>253)fail('invalid_domain');return domain;};
const ADMINISTRATORS="status='active' AND role IN ('owner','admin')";

// People: the state is the row's identity, role, status and version; Base bumps
// the version on every status or role change, so any change since filing shows.
async function personTarget(ctx,data) {
 const value=String(data.target||'').trim();
 const p=await one(ctx,'SELECT id FROM oa_operators WHERE id=? OR email=?',value,email(value)||'')||fail('person_not_found',404);
 return {target:p.id,params:{}};
}
const personState=async(ctx,target)=>await one(ctx,'SELECT id,email,display_name AS name,role,status,version FROM oa_operators WHERE id=?',target)||null;
const samePerson=state=>({sql:'EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND email=? AND role=? AND status=? AND version=?)',args:[state.id,state.email,state.role,state.status,state.version]});
async function personEffect(ctx,state,after) {
 if(!state)return {person:null,after};
 const [sessions,apps,passkey]=await Promise.all([
  one(ctx,'SELECT count(*) AS n FROM auth_sessions WHERE person_id=? AND revoked_at IS NULL AND expires_at>? AND person_version=?',state.id,ctx.now(),state.version),
  all(ctx,'SELECT c.name,c.origin FROM auth_grants g JOIN auth_clients c ON c.id=g.client_id WHERE g.person_id=? ORDER BY c.name',state.id),
  one(ctx,'SELECT 1 AS present FROM auth_passkeys WHERE person_id=? LIMIT 1',state.id),
 ]);
 return {person:{email:state.email,name:state.name,role:state.role,status:state.status},after,activeSessions:sessions.n,apps,passkey:Boolean(passkey)};
}

async function domainTarget(ctx,data,needsProvider) {
 const domain=domainOf(data.target);
 if(!needsProvider)return {target:domain,params:{}};
 const providerId=String(data.providerId||'');if(!configuredProvider(ctx,providerId))fail('unknown_provider');
 return {target:domain,params:{providerId}};
}
const domainState=async(ctx,target)=>({domain:target,provider_id:(await one(ctx,'SELECT provider_id FROM oa_domain_rules WHERE domain=?',target))?.provider_id??null});
const sameRule=state=>({sql:'(SELECT provider_id FROM oa_domain_rules WHERE domain=?) IS ?',args:[state.domain,state.provider_id]});
const providerLabel=(ctx,id)=>{const p=id&&configuredProvider(ctx,id);return id?{id,label:p?(p.label||p.preset):id}:null;};
async function domainEffect(ctx,state,providerId) {
 const people=await all(ctx,"SELECT email,status FROM oa_operators WHERE role!='owner' AND status!='inactive' AND email LIKE ? ORDER BY email",'%@'+state.domain);
 return {domain:state.domain,provider:providerLabel(ctx,state.provider_id),after:providerLabel(ctx,providerId),people};
}

export const KINDS={
 suspend_person:{
  target:personTarget,state:personState,same:samePerson,
  check:state=>!state?'person_not_found':state.role==='owner'?'owner_suspension_requires_transfer':state.status!=='active'?'person_not_active':null,
  effect:(ctx,state)=>personEffect(ctx,state,'suspended'),
  // Never the approver themself, so the key's own accountable owner needs a
  // second administrator, and never the last active administrator.
  approver:(state,approverId)=>state.id===approverId?'second_administrator_required':null,
  requires:state=>({sql:`EXISTS(SELECT 1 FROM oa_operators WHERE ${ADMINISTRATORS} AND id!=?)`,args:[state.id]}),
  run:(ctx,state,claim)=>[
   ctx.db.prepare(`UPDATE oa_operators SET status='inactive' WHERE id=? AND role!='owner' AND ${claim.sql}`).bind(state.id,...claim.args),
   ctx.db.prepare(`UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND revoked_at IS NULL AND ${claim.sql}`).bind(ctx.now(),state.id,...claim.args),
  ],
  after:async(ctx,state)=>{await fencePerson(ctx,state.id);await emit(ctx,'person.suspended',await personSubject(ctx,state.id),{});await personChanged(ctx,state.id,'person_suspended');}},
 restore_person:{
  target:personTarget,state:personState,same:samePerson,
  check:async(state,ctx)=>!state?'person_not_found':state.status!=='inactive'?'person_not_suspended':await one(ctx,'SELECT 1 FROM oa_invitation_cancellations WHERE operator_id=?',state.id)?'invitation_was_removed':null,
  effect:(ctx,state)=>personEffect(ctx,state,'active'),
  run:(ctx,state,claim)=>[ctx.db.prepare(`UPDATE oa_operators SET status='active' WHERE id=? AND status='inactive' AND ${claim.sql}`).bind(state.id,...claim.args)],
  after:async(ctx,state)=>{await emit(ctx,'person.restored',await personSubject(ctx,state.id),{});await personChanged(ctx,state.id,'person_restored');}},
 remove_invitation:{
  target:personTarget,state:personState,same:samePerson,
  check:state=>!state?'person_not_found':state.status!=='invited'?'not_an_invitation':null,
  effect:(ctx,state)=>personEffect(ctx,state,'invitation removed'),
  // Base records invited -> inactive as a cancelled invitation.
  run:(ctx,state,claim)=>[ctx.db.prepare(`UPDATE oa_operators SET status='inactive' WHERE id=? AND status='invited' AND ${claim.sql}`).bind(state.id,...claim.args)]},
 invite_person:{
  async target(ctx,data) {
   const address=email(data.target);if(!address||(!ctx.local&&/\.(localhost|test|invalid)$/.test(address)))fail('invalid_email');
   return {target:address,params:{name:String(data.name||address).replace(/\s+/g,' ').trim().slice(0,160)}};
  },
  state:async(ctx,target)=>({email:target,exists:Boolean(await one(ctx,'SELECT 1 FROM oa_operators WHERE email=?',target))}),
  same:state=>({sql:`${state.exists?'':'NOT '}EXISTS(SELECT 1 FROM oa_operators WHERE email=?)`,args:[state.email]}),
  check:state=>state.exists?'person_exists':null,
  effect:async(ctx,state,params)=>({person:{email:state.email,name:params.name,role:'member',status:null},after:'invited',invitationEmail:true}),
  run:(ctx,state,claim,params,id)=>[ctx.db.prepare(`INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE ${claim.sql}`).bind(id,state.email,params.name,ctx.now(),...claim.args)],
  mail:true},
 add_domain_rule:{
  target:(ctx,data)=>domainTarget(ctx,data,true),state:domainState,same:sameRule,
  check:async(state,ctx,params)=>!configuredProvider(ctx,params.providerId)?'unknown_provider':!await verifiedDomain(ctx,state.domain)?'domain_not_verified':state.provider_id===params.providerId?'rule_unchanged':null,
  effect:(ctx,state,params)=>domainEffect(ctx,state,params.providerId),
  run:(ctx,state,claim,params,id,approverId)=>[ctx.db.prepare(`INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) SELECT ?,?,?,? WHERE ${claim.sql} ON CONFLICT(domain) DO UPDATE SET provider_id=excluded.provider_id,created_by=excluded.created_by,created_at=excluded.created_at`).bind(state.domain,params.providerId,approverId,ctx.now(),...claim.args)]},
 remove_domain_rule:{
  target:(ctx,data)=>domainTarget(ctx,data,false),state:domainState,same:sameRule,
  check:state=>state.provider_id?null:'rule_not_found',
  effect:(ctx,state)=>domainEffect(ctx,state,null),
  run:(ctx,state,claim)=>[ctx.db.prepare(`DELETE FROM oa_domain_rules WHERE domain=? AND ${claim.sql}`).bind(state.domain,...claim.args)]},
};
Object.assign(KINDS,APP_KINDS,DIAGNOSTIC_KINDS);
export const UNAVAILABLE={};

export const digest=state=>hash(JSON.stringify(state));
// Plain words for what moved between filing and now.
export function changes(before,now) {
 if(!now)return ['the person no longer exists'];
 const moved=Object.keys({...before,...now}).filter(k=>k!=='version'&&JSON.stringify(before[k])!==JSON.stringify(now[k])).map(k=>`${k}: ${before[k]??'none'} → ${now[k]??'none'}`);
 return moved.length?moved:before.version!==now.version?['status or role changed and changed back since filing']:[];
}
