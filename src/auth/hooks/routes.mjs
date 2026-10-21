import {all,one,run,random,json,fail,requireSession,auditDetail} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {seal} from '../keys.mjs';
import {POINTS,registrationFields} from './policy.mjs';
import {checkedDestination,withinTimeout} from './network.mjs';
import {newSecret} from './signing.mjs';

export const isHookAction=path=>['/hooks/register','/hooks/disable'].includes(path);
const identifier=value=>typeof value==='string'&&value.length>0&&value.length<=320?value:null;
export async function hookAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_hook_config');
 delete data.csrf;
 if(path==='/hooks/disable') {
  const guard=authority(ctx,s,['owner','admin']);
  const result=await run(ctx,`UPDATE auth_hooks SET disabled_at=? WHERE id=? AND disabled_at IS NULL AND ${guard.clause}`,ctx.now(),identifier(data.id),...guard.args);
  if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('hook_not_found',404);}
  await auditDetail(ctx,s.person_id,'hook_disabled',data.id,{});return json({ok:true});
 }
 if(path!=='/hooks/register')fail('not_found',404);
 if(Object.keys(data).some(k=>!['point','url','appId','clientId','allowedFields','timeoutMs','failClosed'].includes(k))||!POINTS.includes(data.point))fail('invalid_hook_config');
 if(data.point==='password_import')fail('hook_point_unavailable',409);
 const point=data.point,appId=identifier(data.appId),clientId=identifier(data.clientId);
 if(data.appId!=null&&!appId||data.clientId!=null&&!clientId)fail('invalid_hook_scope');
 if(point==='token'?Boolean(appId)===Boolean(clientId):point==='saml'?!appId||Boolean(clientId):Boolean(appId||clientId))fail('invalid_hook_scope');
 if(appId&&!await one(ctx,'SELECT id FROM auth_apps WHERE id=? AND protocol=? AND disabled_at IS NULL',appId,point==='token'?'oidc':'saml'))fail('hook_app_not_found',404);
 if(clientId&&!await one(ctx,'SELECT id FROM auth_clients WHERE id=? AND disabled_at IS NULL',clientId))fail('hook_client_not_found',404);
 const timeoutMs=data.timeoutMs??3000,failClosed=data.failClosed??true,fields=registrationFields(point,data.allowedFields);
 if(!Number.isInteger(timeoutMs)||timeoutMs<100||timeoutMs>10000||typeof failClosed!=='boolean')fail('invalid_hook_config');
 let url;
 try {url=await withinTimeout(3000,signal=>checkedDestination(ctx,data.url,signal));}
 catch(error){if(error.hookTimeout)fail('hook_timeout',503);throw error;}
 const id=random(),secret=newSecret(),sealed=await seal(ctx,'hooks:'+id,secret);
 // Recompute the guard after DNS and encryption so freshness is checked at
 // the write time. At most four active hooks per scope bounds total latency.
 const guard=authority(ctx,s,['owner','admin']);
 const result=await run(ctx,`INSERT INTO auth_hooks(id,point,url,app_id,client_id,allowed_fields,timeout_ms,fail_closed,sealed_secret,created_by,created_at) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause} AND (SELECT count(*) FROM auth_hooks WHERE point=? AND app_id IS ? AND client_id IS ? AND disabled_at IS NULL)<4`,id,point,url,appId,clientId,JSON.stringify(fields),timeoutMs,Number(failClosed),sealed,s.person_id,ctx.now(),...guard.args,point,appId,clientId);
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('hook_limit_reached',409);}
 await auditDetail(ctx,s.person_id,'hook_registered',id,{point,appId,clientId,allowedFields:fields,timeoutMs,failClosed});
 return json({id,secret,point,appId,clientId,allowedFields:fields,timeoutMs,failClosed,message:`Signing secret, shown once: ${secret}`},201);
}

export async function hookModel(ctx) {
 const rows=await all(ctx,'SELECT id,point,url,app_id,client_id,allowed_fields,timeout_ms,fail_closed,created_at,disabled_at FROM auth_hooks ORDER BY created_at,id');
 return {points:POINTS.filter(p=>p!=='password_import'),hooks:rows.map(row=>({id:row.id,point:row.point,url:row.url,appId:row.app_id,clientId:row.client_id,allowedFields:JSON.parse(row.allowed_fields),timeoutMs:row.timeout_ms,failClosed:Boolean(row.fail_closed),createdAt:row.created_at,status:row.disabled_at?'stopped':'active'}))};
}
