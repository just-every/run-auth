import {one} from '../core.mjs';
import {organization} from './authority.mjs';
import {matchesResource} from './config.mjs';

// One SQLite snapshot supplies every changing fact used by a decision. Direct
// assignments win over groups, as in workforce/directory and SCIM provisioning.
export async function decisionSnapshot(ctx,apiId,personId,guard={clause:'1',args:[]}) {
 return one(ctx,`SELECT snap.*,EXISTS(SELECT 1 FROM auth_app_denials d WHERE d.app_id=snap.app_id AND d.person_id=snap.person_id) AS review_denied,
 (SELECT json_object('role',cap.role,'revision',cap.order_revision,'currentRevision',cur.revision,'currentLevel',cur.level,'capLevel',lim.level) FROM auth_app_reductions cap LEFT JOIN auth_app_role_order cur ON cur.app_id=cap.app_id AND cur.role=snap.assigned_role LEFT JOIN auth_app_role_order lim ON lim.app_id=cap.app_id AND lim.role=cap.role WHERE cap.app_id=snap.app_id AND cap.person_id=snap.person_id) AS review_cap
 FROM (SELECT api.*,p.id AS person_id,p.version AS person_version,p.status AS person_status,
 app.disabled_at AS app_disabled,
 (SELECT role FROM (
  SELECT a.role,0 AS rank FROM auth_app_assignments a WHERE a.app_id=api.app_id AND a.principal_type='person' AND a.principal_id=p.id
  UNION ALL SELECT a.role,1 AS rank FROM auth_app_assignments a JOIN auth_group_members m ON m.group_id=a.principal_id JOIN auth_groups g ON g.id=m.group_id WHERE a.app_id=api.app_id AND a.principal_type='group' AND m.person_id=p.id
 ) ORDER BY rank LIMIT 1) AS assigned_role,
 (SELECT json_group_array(json_object('field',f.field,'source',f.source,'value',f.value)) FROM auth_person_fields f WHERE f.person_id=p.id) AS fields
 FROM auth_resource_apis api JOIN auth_apps app ON app.id=api.app_id JOIN oa_operators p ON p.id=? WHERE api.id=? AND ${guard.clause}) snap`,personId,apiId,...guard.args);
}
const priority=['manual','hr','directory','self'];
export function effectiveFields(snapshot) {
 const fields=Object.assign(Object.create(null),{kind:'employee'});
 const rows=JSON.parse(snapshot.fields).sort((a,b)=>priority.indexOf(b.source)-priority.indexOf(a.source));
 for(const r of rows)Object.defineProperty(fields,r.field,{value:r.value,enumerable:true,configurable:true});
 return fields;
}
export function evaluate(ctx,snapshot,data,principal=null) {
 const denied=reason=>({allowed:false,reason,apiId:data.apiId,organizationId:organization(ctx)});
 if(!snapshot||snapshot.person_status!=='active'||snapshot.app_disabled!==null)return denied('inactive_context');
 if(data.audience!==undefined&&data.audience!==snapshot.audience)return denied('wrong_audience');
 const resource=typeof data.resource==='string'?{id:data.resource}:data.resource;
 if(!resource||typeof resource.id!=='string'||resource.organizationId!==undefined&&resource.organizationId!==organization(ctx))return denied('wrong_resource_context');
 if(snapshot.review_denied)return denied('review_access_revoked');
 let assignedRole=snapshot.assigned_role;
 if(snapshot.review_cap){const cap=JSON.parse(snapshot.review_cap);if(cap.revision!==cap.currentRevision||cap.currentLevel===null||cap.capLevel===null)return denied('review_role_order_changed');if(cap.currentLevel>cap.capLevel)assignedRole=cap.role;}
 const policy=JSON.parse(snapshot.policy),target=policy.resources.find(r=>r.id===resource.id);
 if(!target)return denied('unknown_resource');
 if(typeof data.action!=='string'||!policy.scopes.includes(data.action))return denied('unknown_action');
 const rule=policy.roles.find(r=>r.role===assignedRole);
 if(!rule||!rule.scopes.includes(data.action))return denied('role_denied');
 if(!rule.resources.some(pattern=>matchesResource(pattern,target.id)))return denied('resource_denied');
 if(principal&&(!principal.scopes.includes(data.action)||!principal.resources.some(pattern=>matchesResource(pattern,target.id))))return denied('service_scope_denied');
 const fields=effectiveFields(snapshot);
 if(Object.entries(rule.attributes).some(([key,value])=>!Object.hasOwn(fields,key)||fields[key]!==value))return denied('attribute_denied');
 for(const [field,relation] of Object.entries(rule.relations)) {
  const expected=relation==='$person'?snapshot.person_id:fields[relation.slice('$attribute:'.length)];
  if(expected===undefined||!Object.hasOwn(target.attributes,field)||target.attributes[field]!==expected)return denied('relation_denied');
 }
 return {allowed:true,apiId:snapshot.id,action:data.action,resource:target.id,organizationId:organization(ctx),principal:principal?{kind:principal.kind,id:principal.id,ownerId:snapshot.person_id}:{kind:'person',id:snapshot.person_id},role:rule.role,revision:snapshot.revision};
}
