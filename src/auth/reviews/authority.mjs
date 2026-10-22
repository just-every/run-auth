import {requireSession,fail} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {requireHardware,permitted,assertPermission,roleGuard} from '../roles/policy.mjs';
import {requireLocalEmail} from '../local-email.mjs';

export const reviewAllowed=(state,permission,item)=>permitted(state,permission,{personId:item.subject_id,appId:item.app_id,write:permission!=='reviews.view'});
export const canManageReviews=state=>state.entries.some(e=>e.role.permissions.includes('reviews.manage'));
export const canViewReviews=state=>state.entries.some(e=>e.role.permissions.some(p=>['reviews.view','reviews.manage','reviews.export'].includes(p)));
export async function reviewActor(ctx,request,{permission='reviews.manage',write=true}={}) {
 const s=await requireSession(ctx,request);requireHardware(s);if(write)requireLocalEmail(ctx,s);
 const state=await roleState(ctx,s);assertPermission(state,permission,{write});
 return {s,state,guard:roleGuard(ctx,s,state)};
}
export function requireReviewScope(state,permission,items) {
 if(!items.every(item=>reviewAllowed(state,permission,item)))fail('review_resource_outside_scope',403);
}
export const visibleReviewItem=(state,item)=>reviewAllowed(state,'reviews.view',item)||reviewAllowed(state,'reviews.manage',item)||reviewAllowed(state,'reviews.export',item);
