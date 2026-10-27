import {one,fail,requireSession,sessionById} from '../core.mjs';
import {requireRolePermission,assertGuard} from '../roles/policy.mjs';

export async function connectionAuthority(ctx,s,c,personId=null) {
 const guard=await requireRolePermission(ctx,s,'automations.manage',{groupId:c.group_id,...(personId?{personId}:{}),write:true});
 if(c.revoked_at||c.granted_to!==s.person_id)fail('automation_connection_grant_required',403);
 if(personId&&!guard.state.memberships.get(personId)?.has(c.group_id))fail('automation_person_outside_grant',403);
 return {...guard,clause:`${guard.clause} AND EXISTS(SELECT 1 FROM auth_automation_connections WHERE id=? AND version=? AND revoked_at IS NULL AND granted_to=?)`,args:[...guard.args,c.id,c.version,s.person_id]};
}
export async function loadAutomation(ctx,id) {
 const a=await one(ctx,'SELECT * FROM auth_automations WHERE id=?',id)||fail('automation_not_found',404);
 const c=await one(ctx,'SELECT * FROM auth_automation_connections WHERE id=?',id)||fail('automation_not_found',404);
 return {a,c,config:JSON.parse(a.config)};
}
export async function executionAuthority(ctx,r,request) {
 const {a,c,config}=await loadAutomation(ctx,r.automation_id);
 if(a.version!==r.automation_version||c.version!==r.connection_version||!r.approved_by)fail('automation_approval_changed',409);
 const s=request?await requireSession(ctx,request):await sessionById(ctx,new Request(ctx.origin),r.session_id);
 if(!s||s.id!==r.session_id||s.person_id!==r.approved_by)fail('automation_approval_expired',403);
 const guard=await connectionAuthority(ctx,s,c,r.person_id);
 const person=guard.state.dir.people.get(r.person_id);
 if(guard.state.epoch!==r.epoch||person?.version!==r.person_version||person?.status!=='active')fail('automation_authority_changed',409);
 const live={...guard,clause:`${guard.clause} AND EXISTS(SELECT 1 FROM auth_automations WHERE id=? AND version=?) AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND version=? AND status='active') AND EXISTS(SELECT 1 FROM auth_automation_runs WHERE id=? AND approved_by=? AND session_id=? AND epoch=? AND state IN ('approved','running') AND (state='approved' OR lease_until>?))`,args:[...guard.args,a.id,a.version,r.person_id,r.person_version,r.id,r.approved_by,r.session_id,r.epoch,ctx.now()]};
 await assertGuard(ctx,live);
 return {a,c,config,s,guard:live};
}
