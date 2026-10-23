import {all,auditDetail,fail,json,one,requireSession,run} from '../core.mjs';
import {configuration,configurationView} from '../grants/configuration.mjs';
import {authority,requireAuthority,requireLocalEmail} from '../local-email.mjs';
import {requireHardware} from '../roles/policy.mjs';
import {requireAccountRank} from '../ranks.mjs';
import {genericClient} from '../oidc-apps/clients.mjs';
import {consentView,decideConsent} from './consent.mjs';
import {endFamily} from './lifecycle.mjs';
import {liveFamily} from './authority.mjs';

export const isRefreshAction=path=>['/refresh/consent','/refresh/revoke','/refresh/profile'].includes(path);
const view=f=>({id:f.id,personId:f.person_id,personEmail:f.person_email,appName:f.app_name,clientId:f.client_id,deviceName:f.device_name,scopes:JSON.parse(f.scopes),audience:f.audience,createdAt:f.created_at,lastUsedAt:f.last_used_at,idleExpiresAt:f.idle_expires_at,absoluteExpiresAt:f.absolute_expires_at,revokedAt:f.revoked_at,reason:f.reason,status:f.live?'active':f.revoked_at?'revoked':'ended'});
export async function refreshInventory(ctx,request,s=null) {
 s??=await requireSession(ctx,request);
 const admin=new URL(request.url).searchParams.get('refreshAdmin')==='1';
 let apiIds=null;
 if(admin) {
  const apis=await all(ctx,'SELECT id,app_id AS appId FROM auth_resource_apis');
  apiIds=new Set((await configurationView(ctx,request,{apis,services:[]})).apis.map(a=>a.id));
 }
 const rows=await all(ctx,`SELECT f.*,p.email AS person_email,a.name AS app_name,api.audience FROM auth_refresh_families f JOIN oa_operators p ON p.id=f.person_id JOIN auth_oidc_clients c ON c.client_id=f.client_id JOIN auth_apps a ON a.id=c.app_id JOIN auth_resource_apis api ON api.id=f.api_id ${admin?'':'WHERE f.person_id=?'} ORDER BY f.created_at DESC LIMIT 200`,...(admin?[]:[s.person_id]));
 const grants=[];
 for(const f of rows)if(!apiIds||apiIds.has(f.api_id))grants.push(view({...f,live:await liveFamily(ctx,f)}));
 const canManage=['owner','admin'].includes(s.role)&&JSON.parse(s.amr).includes('hwk');
 const clients=canManage?await all(ctx,'SELECT c.client_id AS clientId,a.name FROM auth_oidc_clients c JOIN auth_apps a ON a.id=c.app_id WHERE a.disabled_at IS NULL ORDER BY a.name'):[];
 const apis=canManage?await all(ctx,'SELECT id,app_id AS appId,name,audience FROM auth_resource_apis'):[];
 const profiles=canManage?await all(ctx,'SELECT p.client_id AS clientId,a.name,p.enabled,p.idle_ms AS idleMs,p.absolute_ms AS absoluteMs FROM auth_refresh_profiles p JOIN auth_oidc_clients c ON c.client_id=p.client_id JOIN auth_apps a ON a.id=c.app_id'):[];
 const id=new URL(request.url).searchParams.get('refreshConsent');
 return {grants,admin,canManage,clients,apis,profiles,consent:id?await consentView(ctx,s,id):null};
}
export async function refreshAction(ctx,request,path,data) {
 if(path==='/refresh/consent')return decideConsent(ctx,request,data);
 const s=await requireSession(ctx,request);
 if(path==='/refresh/revoke') {
  const f=await one(ctx,'SELECT * FROM auth_refresh_families WHERE id=?',String(data.id||''));
  if(!f)fail('grant_not_found',404);
  if(f.person_id!==s.person_id) {
   requireHardware(s);requireLocalEmail(ctx,s);
   const client=await genericClient(ctx,f.client_id);if(!client)fail('grant_not_found',404);
   const {guard}=await configuration(ctx,request,'/register',{appId:client.app_id});
   const rank=await requireAccountRank(ctx,s,f.person_id,guard);
   const changed=await run(ctx,`UPDATE auth_refresh_families SET revoked_at=?,reason='administrator_revoked' WHERE id=? AND revoked_at IS NULL AND ${rank.clause}`,ctx.now(),f.id,...rank.args);
   if(!changed.meta.changes)await requireAuthority(ctx,s,rank);
  }else {
   const changed=await run(ctx,`UPDATE auth_refresh_families SET revoked_at=?,reason='employee_revoked' WHERE id=? AND person_id=? AND revoked_at IS NULL AND EXISTS(SELECT 1 FROM auth_sessions live JOIN oa_operators p ON p.id=live.person_id WHERE live.id=? AND live.person_id=? AND live.person_version=p.version AND p.status='active' AND live.revoked_at IS NULL AND live.expires_at>?)`,ctx.now(),f.id,s.person_id,s.id,s.person_id,ctx.now());
   if(!changed.meta.changes&&f.revoked_at===null)fail('session_authority_changed',403);
  }
  await endFamily(ctx,f.id,f.person_id===s.person_id?'employee_revoked':'administrator_revoked',s.person_id);
  await auditDetail(ctx,s.person_id,'refresh_grant_revoked',f.id,{clientId:f.client_id,personId:f.person_id});
  return json({ok:true});
 }
 if(path!=='/refresh/profile')fail('not_found',404);
 const client=await genericClient(ctx,String(data.clientId||''));if(!client)fail('client_not_found',404);
 const {guard}=await configuration(ctx,request,'/register',{appId:client.app_id});
 const prior=await one(ctx,'SELECT * FROM auth_refresh_profiles WHERE client_id=?',client.client_id);
 if(data.enabled===false||data.enabled==='false') {
  if(!prior)fail('profile_not_found',404);
  const r=await run(ctx,`UPDATE auth_refresh_profiles SET enabled=0,revision=revision+1 WHERE client_id=? AND ${guard.clause}`,client.client_id,...guard.args);
  if(!r.meta.changes)await requireAuthority(ctx,s,guard);
 }else {
  const api=await one(ctx,'SELECT * FROM auth_resource_apis WHERE id=? AND app_id=?',String(data.apiId||''),client.app_id);
  const scopes=Array.isArray(data.scopes)?data.scopes:String(data.scopes||'').trim().split(/\s+/);
  const idle=Number(data.idleHours)*3600000,absolute=Number(data.absoluteHours)*3600000;
  if(!api||!scopes.length||scopes.some(scope=>!JSON.parse(api.policy).scopes.includes(scope)||['openid','offline_access','email','profile','groups','claim'].includes(scope))||!Number.isSafeInteger(idle)||!Number.isSafeInteger(absolute)||idle<1000||absolute<idle||absolute>Number.MAX_SAFE_INTEGER-ctx.now())fail('invalid_refresh_profile');
  const r=await run(ctx,`INSERT INTO auth_refresh_profiles(client_id,api_id,scopes,idle_ms,absolute_ms,created_by,created_at) SELECT ?,?,?,?,?,?,? WHERE ${guard.clause} ON CONFLICT(client_id) DO UPDATE SET api_id=excluded.api_id,scopes=excluded.scopes,idle_ms=excluded.idle_ms,absolute_ms=excluded.absolute_ms,enabled=1,revision=revision+1`,client.client_id,api.id,JSON.stringify([...new Set(scopes)]),idle,absolute,s.person_id,ctx.now(),...guard.args);
  if(!r.meta.changes)await requireAuthority(ctx,s,guard);
 }
 // Republishing cannot revive a grant issued under an earlier profile.
 const old=await all(ctx,'SELECT id FROM auth_refresh_families WHERE client_id=? AND revoked_at IS NULL',client.client_id);
 for(const f of old)await endFamily(ctx,f.id,'profile_changed',s.person_id);
 await auditDetail(ctx,s.person_id,'refresh_profile_published',client.client_id,{enabled:data.enabled!==false});
 return json({ok:true});
}
