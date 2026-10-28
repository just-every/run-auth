// Interactive SAML configuration review. Preview is a sealed, expiring value:
// it writes nothing and contains only the reviewed nonsecret configuration.
import {one,all,random,json,fail,requireSession,hash} from '../core.mjs';
import {seal,unseal} from '../keys.mjs';
import {appOf,appSettings,settingsColumns,SETTINGS_SQL,spMetadata} from '../saml/apps.mjs';
import {requireRolePermission,assertGuard} from '../roles/policy.mjs';
import {commit} from '../roles/commit.mjs';

export const REVISION_ACTIONS=['/catalog/preview','/catalog/approve','/catalog/history'];
export const isRevisionAction=path=>REVISION_ACTIONS.includes(path);
const fields=['name','metadata','nameIdFormat','nameIdSource','sign','digest','sha1Exception','encryption','wantRequestsSigned','idpInitiated','relayState','attributes','launchUrl'];
export function configurationOf(app) {
 return {name:app.name,metadata:spMetadata(app),nameIdFormat:app.name_id_format,nameIdSource:app.name_id_source,sign:app.sign,digest:app.digest,sha1Exception:Boolean(app.sha1_exception),encryption:app.encryption,wantRequestsSigned:Boolean(app.want_requests_signed),idpInitiated:Boolean(app.idp_initiated),relayState:app.relay_state,attributes:app.attributes,launchUrl:app.launch_url};
}
const label=ctx=>'catalog-review:'+JSON.stringify([ctx.origin,ctx.organizationId??'root']);
const app=async(ctx,id)=>appOf(await one(ctx,"SELECT * FROM auth_apps WHERE id=? AND protocol='saml' AND disabled_at IS NULL",id))??fail('app_not_found',404);
export async function revisionHistory(ctx,appId) {
 return (await all(ctx,'SELECT version,configuration,created_by,created_at,rolled_back_from FROM auth_app_revisions WHERE app_id=? ORDER BY version DESC',appId)).map(({configuration,...row})=>({...row,configuration:JSON.parse(configuration)}));
}
export async function revisionAction(ctx,request,path,data) {
 return revisionCommand(ctx,await requireSession(ctx,request),path,data);
}
export async function revisionCommand(ctx,s,path,data) {
 const appId=String(data.appId??''),guard=await requireRolePermission(ctx,s,'apps.edit',{appId,write:true});
 const current=await app(ctx,appId),before=configurationOf(current);
 if(path==='/catalog/history') {
  const revisions=await revisionHistory(ctx,appId);await assertGuard(ctx,guard);
  return json({appId,version:current.version,configuration:before,revisions});
 }
 if(path==='/catalog/preview') {
  if(Number(data.version)!==current.version)fail('app_changed',409);
  let input,rollback=null;
  if(data.targetVersion!==undefined) {
   rollback=Number(data.targetVersion);
   const row=await one(ctx,'SELECT configuration FROM auth_app_revisions WHERE app_id=? AND version=?',appId,rollback)??fail('revision_not_found',404);
   input=JSON.parse(row.configuration);
  } else {
   const changes=data.settings??data;
   input={...before,...Object.fromEntries(fields.filter(key=>Object.hasOwn(changes,key)).map(key=>[key,changes[key]]))};
  }
  // Validate both preview and commit through the ordinary SAML validator.
  const settings=appSettings(ctx,input),proposed=configurationOf(appOf({name:settings.name,entity_id:settings.entityId,acs:JSON.stringify(settings.acs),slo:settings.slo?JSON.stringify(settings.slo):null,sp_certificates:JSON.stringify(settings.signingCertificates),encryption_certificate:settings.encryptionCertificate,name_id_format:settings.nameIdFormat,name_id_source:settings.nameIdSource,sign:settings.sign,digest:settings.digest,sha1_exception:settings.sha1Exception,encryption:settings.encryption,want_requests_signed:settings.wantRequestsSigned,idp_initiated:settings.idpInitiated,relay_state:settings.relayState,attributes:JSON.stringify(settings.attributes),launch_url:settings.launchUrl}));
  if(await one(ctx,'SELECT 1 FROM auth_apps WHERE entity_id=? AND id!=?',settings.entityId,appId))fail('entity_id_in_use',409);
  await assertGuard(ctx,guard);
  const review={id:random(),appId,version:current.version,actor:s.person_id,session:s.id,expiresAt:ctx.now()+10*60000,before:await hash(JSON.stringify(before)),proposed,rollback};
  return json({preview:await seal(ctx,label(ctx),review),version:current.version,before,proposed,rollback,notes:settings.notes,expiresAt:review.expiresAt});
 }
 if(path!=='/catalog/approve')fail('not_found',404);
 if(data.confirm!==true)fail('configuration_approval_required');
 let review;try{review=await unseal(ctx,label(ctx),String(data.preview??''));}catch{fail('invalid_configuration_preview',409);}
 if(review.appId!==appId||review.actor!==s.person_id||review.session!==s.id||review.expiresAt<=ctx.now()||review.version!==current.version||review.before!==await hash(JSON.stringify(before)))fail('configuration_preview_changed',409);
 if(review.rollback!==null) {
  const target=await one(ctx,'SELECT configuration FROM auth_app_revisions WHERE app_id=? AND version=?',appId,review.rollback);
  if(!target||target.configuration!==JSON.stringify(review.proposed))fail('configuration_preview_changed',409);
 }
 const settings=appSettings(ctx,review.proposed);
 if(await one(ctx,'SELECT 1 FROM auth_apps WHERE entity_id=? AND id!=?',settings.entityId,appId))fail('entity_id_in_use',409);
 const next=current.version+1,now=ctx.now(),serialized=JSON.stringify(review.proposed);
 const exact={clause:`${guard.clause} AND EXISTS(SELECT 1 FROM auth_apps WHERE id=? AND version=? AND disabled_at IS NULL) AND NOT EXISTS(SELECT 1 FROM auth_app_revisions WHERE preview_id=?)`,args:[...guard.args,appId,current.version,review.id]};
 // The authority and version decision, baseline, app write, revision and audit
 // share one transaction. Only settings columns change; access and credentials
 // are never read into a revision or restored by rollback.
 await commit(ctx,s,exact,'catalog.configuration.approved',appId,{version:next,from:current.version,rollback:review.rollback},(g,q)=>[
  q(`INSERT INTO auth_app_revisions(app_id,version,configuration,created_by,created_at) SELECT ?,?,?,?,? WHERE ${g.clause} ON CONFLICT(app_id,version) DO NOTHING`,appId,current.version,JSON.stringify(before),s.person_id,now,...g.args),
  q(`UPDATE auth_apps SET ${SETTINGS_SQL.split(',').map(c=>`${c}=?`).join(',')},version=?,updated_at=? WHERE id=? AND ${g.clause}`,...settingsColumns(settings),next,now,appId,...g.args),
  q(`INSERT INTO auth_app_revisions(app_id,version,configuration,created_by,created_at,rolled_back_from,preview_id) SELECT ?,?,?,?,?,?,? WHERE ${g.clause}`,appId,next,serialized,s.person_id,now,review.rollback,review.id,...g.args),
 ]);
 return json({appId,version:next,rollback:review.rollback});
}
