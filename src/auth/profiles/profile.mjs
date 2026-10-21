// An employee's own profile: the fields they may see, the ones they may edit,
// and who holds the rest. A value a source or an administrator holds is
// protected: the employee cannot overwrite it, and is told who holds it.
import {json,fail} from '../core.mjs';
import {loadDirectory} from '../workforce/people/load.mjs';
import {planEdits} from '../workforce/people/plan.mjs';
import {applyPlan} from '../workforce/people/apply.mjs';
import {owner} from '../workforce/people/fields.mjs';

// The session's own authority for a write that is not administration: live, same version, same methods.
export function sessionGuard(ctx,s) {
 return {clause:`EXISTS(SELECT 1 FROM auth_sessions a JOIN oa_operators ap ON ap.id=a.person_id WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=ap.version AND ap.status='active' AND a.revoked_at IS NULL AND a.expires_at>?)`,args:[s.id,s.person_id,s.amr,ctx.now()]};
}
const HOLDERS={manual:'field_set_by_administrator',hr:'field_owned_by_source',directory:'field_owned_by_source'};

export async function profileView(ctx,s) {
 const dir=await loadDirectory(ctx),person=dir.people.get(s.person_id),values=dir.values(person);
 const fields=[...dir.defs.values()].filter(spec=>spec.visibility==='employee').map(spec=>{
  const holder=owner(person.fields,spec.key),editable=spec.employeeEditable&&!holder;
  return {key:spec.key,label:spec.label,type:spec.type,choices:spec.choices??null,value:spec.key==='name'?person.name:values[spec.key]??null,editable,
   ...(editable?{}:{protectedBy:holder??'not_editable'})};
 });
 return {person:{id:person.id,email:person.email,name:person.name},fields};
}

export async function updateProfile(ctx,s,data) {
 const dir=await loadDirectory(ctx),person=dir.people.get(s.person_id),set={};
 if(!data.fields||typeof data.fields!=='object'||!Object.keys(data.fields).length)fail('invalid_fields');
 for(const [key,raw] of Object.entries(data.fields)) {
  const spec=dir.defs.get(key);
  if(!spec||spec.visibility!=='employee')fail('unknown_field',404);
  if(!spec.employeeEditable)fail('field_protected',403);
  const holder=owner(person.fields,key);
  if(holder)fail(HOLDERS[holder],403);
  set[key]=raw===null||raw===''?null:raw;
 }
 const plan=await planEdits(ctx,dir,[{personId:person.id,source:'self',set}],s.person_id,{self:true});
 if(!plan.ok)return json({error:'edit_refused',refusals:plan.entries[0].refusals},409);
 await applyPlan(ctx,s,sessionGuard(ctx,s),dir,plan);
 return json({ok:true,profile:await profileView(ctx,s)});
}
