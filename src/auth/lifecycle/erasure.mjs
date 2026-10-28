import {anonymous,contains} from '../erasure/scrub.mjs';

// A plan belongs to its subject. An approving administrator's erasure removes
// their provenance without deleting the subject's retained plan or work links.
export function leaverErasure(table,row,{kind,target,identifiers,names,reference}) {
 if(table.name!=='auth_lifecycle_plans'||kind!=='person'||row.person_id===target)return null;
 const update={};
 for(const column of ['actor_id','custodian_id'])if(identifiers.has(row[column]))update[column]=reference;
 const privateValues=new Set([...identifiers,...names].filter(value=>typeof value==='string'&&value));
 if(contains(row.plan,privateValues))update.plan=JSON.stringify(anonymous(JSON.parse(row.plan),privateValues,reference));
 return {update};
}
