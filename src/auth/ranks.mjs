// Administrator rank is a fence on administration of an account. It never
// grants a permission, widens a resource set or applies to ordinary viewing.
import {fail,one,random} from './core.mjs';

export const LEGACY_RANK=Object.freeze({owner:100,admin:90,member:0});
export const BUILTIN_RANKS=Object.freeze({
 owner:100,
 'identity-administrator':80,
 'security-policy-administrator':80,
 'app-administrator':50,
 'help-desk':20,
 auditor:10,
 'group-owner':0,
 manager:0,
 'app-owner':0,
 employee:0,
});
const ACCOUNT_PERMISSIONS=new Set([
 'people.profile.edit','people.suspend','people.restore','people.factors.reset',
 'people.export','recovery.approve','cases.open','cases.verify','roles.grant',
 'people.sessions.end','sessions.revoke',
]);
export const accountPermission=permission=>ACCOUNT_PERMISSIONS.has(permission);
export const lowerAccountRank=(state,personId)=>personId!==state.person.id&&state.rankOf(personId)<state.rank;
const humanId=principal=>principal.ownerId??principal.person_id??principal.actorId;

export async function requireAccountRank(ctx,principal,personId,guard) {
 const {roleState}=await import('./roles/state.mjs');
 const state=await roleState(ctx,{person_id:humanId(principal)});
 if(!state.dir.people.has(personId))fail('person_not_found',404);
 if(!lowerAccountRank(state,personId))fail('lower_rank_required',403);
 return {...guard,clause:`(${guard.clause}) AND EXISTS(SELECT 1 FROM auth_role_epoch WHERE id=1 AND epoch=?)`,args:[...guard.args,state.epoch]};
}

// Native directory commands may change the authority epoch in several SQL
// statements. Claim the live rank decision first, then run the whole existing
// batch under that marker, including when the actor is a machine's human owner.
export async function commitAccountWrite(ctx,actor,personId,guard,build) {
 const live=await requireAccountRank(ctx,actor,personId,guard),id=random();
 const won={clause:`(${guard.clause}) AND EXISTS(SELECT 1 FROM auth_role_operations WHERE id=?)`,args:[...guard.args,id]};
 const statements=build(won);
 const results=await (actor.commit??(batch=>ctx.db.batch(batch)))([
  ctx.db.prepare(`INSERT INTO auth_role_operations(id,actor_id,session_id,permission,subject_id,detail,created_at) SELECT ?,?,?,'account.rank',?,?,? WHERE ${live.clause}`)
   .bind(id,actor.actorId??humanId(actor),actor.id??actor.sessionId??humanId(actor),personId,JSON.stringify({account:personId,custodian:humanId(actor)}),ctx.now(),...live.args),
  ...statements,
 ]);
 if(!results[0].meta.changes) {
  await actor.assertAuthority();
  if(!await one(ctx,`SELECT 1 WHERE ${live.clause}`,...live.args))fail('account_authority_changed',409);
  fail('account_changed',409);
 }
 return results.slice(1);
}
