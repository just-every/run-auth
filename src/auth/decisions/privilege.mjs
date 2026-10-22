import {one,all} from '../core.mjs';

// An exact role override wins over the app classification. Unclassified apps
// and every unclassified role in them remain privileged. A group's own mark
// can only strengthen the authority required by its assigned app roles.
export async function privilegedApp(ctx,appId,role) {
 const mark=role!=null?await one(ctx,'SELECT privileged FROM auth_privileged_app_roles WHERE app_id=? AND role=?',appId,role):null;
 if(mark)return mark.privileged!==0;
 return (await one(ctx,"SELECT privileged FROM auth_privileged_resources WHERE kind='app' AND target_id=?",appId))?.privileged!==0;
}
export async function privilegedGroup(ctx,id) {
 if(await one(ctx,"SELECT 1 FROM auth_privileged_resources WHERE kind='group' AND target_id=? AND privileged=1",id))return true;
 for(const a of await all(ctx,"SELECT app_id,role FROM auth_app_assignments WHERE principal_type='group' AND principal_id=?",id))if(await privilegedApp(ctx,a.app_id,a.role))return true;
 return false;
}
