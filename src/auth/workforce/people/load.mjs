// One read of the whole directory: people with their values by source, the
// groups and who is in them, and what each group and person is assigned.
// A workforce is thousands of people, so planning reads it once and works in memory.
import {all} from '../../core.mjs';
import {definitions,valuesByPerson,effective} from './fields.mjs';

export const stateOf=person=>person.status==='invited'?'invited':person.status==='active'?'active':person.terminatedAt?'terminated':'suspended';

export async function loadDirectory(ctx) {
 const [defs,rows,fieldMap,groupRows,memberRows,exclusionRows,ownerRows,assignmentRows,sourceRows,cancelled]=await Promise.all([
  definitions(ctx),
  all(ctx,'SELECT p.id,p.email,p.display_name AS name,p.role,p.status,p.version,p.created_at,d.terminated_at FROM oa_operators p LEFT JOIN auth_people d ON d.person_id=p.id ORDER BY p.email'),
  valuesByPerson(ctx),
  all(ctx,'SELECT id,name,rule FROM auth_groups ORDER BY name'),
  all(ctx,'SELECT group_id,person_id,source,added_by,added_at FROM auth_group_members'),
  all(ctx,'SELECT group_id,person_id,reason,set_by,set_at FROM auth_group_exclusions'),
  all(ctx,'SELECT group_id,person_id FROM auth_group_owners'),
  all(ctx,'SELECT a.app_id,a.principal_type,a.principal_id,a.role,p.name AS app FROM auth_app_assignments a JOIN auth_apps p ON p.id=a.app_id AND p.disabled_at IS NULL'),
  all(ctx,'SELECT source,source_id,person_id FROM auth_person_sources'),
  all(ctx,'SELECT operator_id FROM oa_invitation_cancellations'),
 ]);
 const people=new Map(),byEmail=new Map();
 for(const r of rows) {
  const person={id:r.id,email:r.email,name:r.name,role:r.role,status:r.status,version:r.version,createdAt:r.created_at,terminatedAt:r.terminated_at,fields:fieldMap.get(r.id)??new Map()};
  person.state=stateOf(person);people.set(r.id,person);byEmail.set(r.email,person);
 }
 const groups=groupRows.map(g=>({id:g.id,name:g.name,rule:g.rule?JSON.parse(g.rule):null}));
 const members=new Map(groups.map(g=>[g.id,new Map()]));
 for(const m of memberRows)members.get(m.group_id)?.set(m.person_id,m);
 const exclusions=new Map(exclusionRows.map(e=>[e.group_id+':'+e.person_id,e]));
 const sources=new Map(sourceRows.map(s=>[s.source+':'+s.source_id,s.person_id])),sourceIds=new Map(sourceRows.map(s=>[s.source+':'+s.person_id,s.source_id]));
 const dir={defs,people,byEmail,groups,ruleGroups:groups.filter(g=>g.rule),members,exclusions,owners:ownerRows,assignments:assignmentRows,sources,sourceIds,cancelled:new Set(cancelled.map(c=>c.operator_id)),
  values:person=>effective(person.fields,defs)};
 return dir;
}

// The apps a person reaches through these groups: a direct assignment's role wins over a group's.
export function appsFor(dir,personId,groupIds) {
 const apps=new Map();
 for(const a of dir.assignments) {
  if(a.principal_type==='person'&&a.principal_id===personId)apps.set(a.app_id,{appId:a.app_id,app:a.app,role:a.role,via:'direct'});
 }
 for(const a of dir.assignments)if(a.principal_type==='group'&&groupIds.has(a.principal_id)&&!apps.has(a.app_id))apps.set(a.app_id,{appId:a.app_id,app:a.app,role:a.role,via:'group'});
 return apps;
}
export const groupIdsOf=(dir,personId)=>new Set(dir.groups.filter(g=>dir.members.get(g.id)?.has(personId)).map(g=>g.id));
