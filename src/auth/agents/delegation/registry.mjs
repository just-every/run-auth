import {DAY,random,run,json,auditDetail,fail} from '../../core.mjs';
import {publicKeys} from '../../grants/public-keys.mjs';
import {CLIENT_PREFIX,SCOPE,id,text,exact,ownerSession,ownerGuard,browserData,both} from './common.mjs';
import {agentRow,employerGuard,held} from './state.mjs';

const ids=(value,code)=>{
 if(!Array.isArray(value)||!value.length||value.length>100)fail(code);
 return [...new Set(value.map(v=>id(v,code)))];
};
export async function registerAgent(ctx,request,data) {
 data=await browserData(ctx,request,data);
 exact(data,['name','purpose','jwks','appIds','personIds','expiresAt']);
 const s=await ownerSession(ctx,request),keys=await publicKeys(data.jwks);
 const name=text(data.name,80,'invalid_agent_name'),purpose=text(data.purpose,500,'invalid_agent_purpose');
 const apps=ids(data.appIds,'invalid_agent_apps'),people=ids(data.personIds,'invalid_agent_people');
 if(!Number.isSafeInteger(data.expiresAt)||data.expiresAt<=ctx.now()||data.expiresAt>ctx.now()+365*DAY)fail('invalid_agent_expiry');
 const agentId=random(),serviceId=random(),clientId=CLIENT_PREFIX+agentId,now=ctx.now();
 const resources={apps,people,groups:[]};
 const guard=both(ownerGuard(ctx,s),employerGuard(ctx));
 // Agent registration and its dedicated machine authorization are one guarded
 // transaction. No secret is minted, returned, copied or accepted.
 const results=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_admin_service_apps(id,client_id,name,purpose,owner_id,jwks,scopes,resources,created_by,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`).bind(serviceId,clientId,name,purpose,s.person_id,JSON.stringify(keys),JSON.stringify([SCOPE]),JSON.stringify(resources),s.person_id,now,data.expiresAt,...guard.args),
  ctx.db.prepare(`INSERT INTO auth_delegated_agents(id,client_id,service_app_id,name,registered_by,registered_owner_version,created_at,expires_at) SELECT ?,?,?,?,?,?,?,? WHERE ${guard.clause} AND EXISTS(SELECT 1 FROM auth_admin_service_apps WHERE id=?)`).bind(agentId,clientId,serviceId,name,s.person_id,s.person_version,now,data.expiresAt,...guard.args,serviceId),
 ]);
 if(!results[1].meta.changes){await held(ctx,guard);fail('agent_registration_refused',409);}
 await auditDetail(ctx,s.person_id,'delegated_agent_registered',agentId,{clientId,serviceAppId:serviceId,scopes:[SCOPE],resources,expiresAt:data.expiresAt});
 return json({id:agentId,clientId,name,scopes:[SCOPE],resources,expiresAt:data.expiresAt,independentApprovalRequired:true},201);
}
export async function suspendAgent(ctx,request,data) {
 data=await browserData(ctx,request,data);exact(data,['clientId']);
 const s=await ownerSession(ctx,request),agent=await agentRow(ctx,id(data.clientId))||fail('agent_not_found',404);
 const guard=both(ownerGuard(ctx,s),employerGuard(ctx));
 const result=await run(ctx,`UPDATE auth_delegated_agents SET state='suspended',revision=revision+1 WHERE id=? AND revision=? AND state='active' AND ${guard.clause}`,agent.id,agent.revision,...guard.args);
 if(!result.meta.changes){await held(ctx,guard);fail('agent_unavailable',409);}
 await auditDetail(ctx,s.person_id,'delegated_agent_suspended',agent.id,{clientId:agent.client_id});
 return json({ok:true});
}
