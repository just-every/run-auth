import {one,fail} from '../core.mjs';
import {assignment} from '../workforce/directory.mjs';
// App-defined role attributes and conventional role claims cannot reintroduce
// an authority that a live review cap removed, even through a mapping or hook.
export async function capRoleClaims(ctx,appId,personId,attributes,claims) {
 if(!await one(ctx,'SELECT 1 FROM auth_app_reductions WHERE app_id=? AND person_id=?',appId,personId))return claims;
 const current=await assignment(ctx,appId,personId);if(!current)fail('review_access_changed',403);
 const result={...claims},names=new Set(attributes.filter(a=>a.source==='role').map(a=>a.name));
 for(const name of ['role','roles'])if(Object.hasOwn(result,name))names.add(name);
 for(const name of names)result[name]=name==='roles'||Array.isArray(result[name])?[current.role]:current.role;
 return result;
}
