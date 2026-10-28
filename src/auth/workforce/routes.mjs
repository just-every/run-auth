// Administration of company apps: groups, SAML apps and their assignments,
// Auth's SAML signing certificates, SCIM provisioning and the catalog. Every
// write is an administration write: passkey administrator, this session's
// fresh local email proof, rechecked with its authority in the committing
// statement (signing certificates: the owner).
import {random,one,all,run,json,fail,requireSession,auditDetail,session} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {seal} from '../keys.mjs';
import {appSettings,settingsColumns,SETTINGS_SQL,appOf,spMetadata,FORMATS,parseAttributes,endpoint} from '../saml/apps.mjs';
import {clientSettings,overlapOf,METHODS} from '../oidc-apps/clients.mjs';
import {hash} from '../core.mjs';
import {stageSamlKey,activateSamlKey,retireSamlKey,publishedKeys,ensureSamlKey} from '../saml/signing.mjs';
import {idpEntity} from '../saml/assertion.mjs';
import {scimBase,connectorOf,testConnection} from '../provisioning/scim.mjs';
import {queue,queueApp,groupChanged,reconcile,preview,dispatch,ESCALATE_AFTER} from '../provisioning/obligations.mjs';
import {isRevisionAction,revisionAction,revisionHistory,configurationOf} from '../catalog/revisions.mjs';
import {recipe,catalog} from '../catalog/recipes.mjs';
import {launcher,launcherPreference,launcherOpen} from '../launcher/index.mjs';
import {emit} from '../events/store.mjs';
import {loadDirectory} from './people/load.mjs';
import {matches} from './people/groups.mjs';

const OWNER_ACTIONS=['/saml-keys/stage','/saml-keys/activate','/saml-keys/retire'];
const ADMIN_ACTIONS=['/bookmarks/create','/bookmarks/remove','/oidc-apps/create','/oidc-apps/rotate-secret','/groups/create','/groups/delete','/groups/add','/groups/remove','/company-apps/create','/company-apps/update','/company-apps/remove','/company-apps/assign','/company-apps/unassign','/provisioning/connect','/provisioning/rotate','/provisioning/disconnect','/provisioning/test','/provisioning/preview','/provisioning/sync','/provisioning/retry','/provisioning/adopt','/catalog/add'];
export const isWorkforceAction=path=>isRevisionAction(path)||path==='/launcher/favorite'||OWNER_ACTIONS.includes(path)||ADMIN_ACTIONS.includes(path);
const text=(value,max,code)=>{const v=String(value??'').trim();if(!v||v.length>max)fail(code);return v;};

export async function workforceAction(ctx,request,path,data) {
 if(isRevisionAction(path))return revisionAction(ctx,request,path,data);
 if(path==='/launcher/favorite')return launcherPreference(ctx,request,data);
 const s=await requireSession(ctx,request,true),owner=OWNER_ACTIONS.includes(path);
 if(owner&&s.role!=='owner')fail('owner_required',403);
 requireLocalEmail(ctx,s);
 const guard=authority(ctx,s,owner?['owner']:['owner','admin']);
 return workforceCommand(ctx,{kind:owner?'human-owner':'human',actorId:s.person_id,guard,assertAuthority:()=>requireAuthority(ctx,s,authority(ctx,s,owner?['owner']:['owner','admin']))},path,data);
}

// Native commands share their validation and committing statements. A machine
// principal supplies its own live authority; it never becomes a person/session.
export async function workforceCommand(ctx,actor,path,data) {
 if(!isWorkforceAction(path))fail('not_found',404);
 if(OWNER_ACTIONS.includes(path)&&actor.kind!=='human-owner')fail('owner_required',403);
 const guard=actor.guard,g=guard.clause,ga=guard.args;
 const commit=actor.commit??(statements=>ctx.db.batch(statements));
 const run=async(_ctx,sql,...args)=>(await commit([ctx.db.prepare(sql).bind(...args)]))[0];
 const held=async result=>{if(!result.meta.changes){await actor.assertAuthority();return false;}return true;};
 const log=(event,subject,detail)=>auditDetail(ctx,actor.actorId,event,subject,detail);
 // Reads that still need the administrator's current authority.
 const authorized=()=>actor.assertAuthority();
 const app=async id=>appOf(await one(ctx,'SELECT * FROM auth_apps WHERE id=? AND disabled_at IS NULL',String(id||'')))||fail('app_not_found',404);

 if(path==='/saml-keys/stage'){const staged=await stageSamlKey(ctx,guard);if(!staged){await actor.assertAuthority();fail('session_authority_changed',403);}await log('saml_key_staged',staged.kid,{});return json({kid:staged.kid,state:staged.state},201);}
 if(path==='/saml-keys/activate'){await ensureSamlKey(ctx);if(!await activateSamlKey(ctx,String(data.kid||''),guard)){await actor.assertAuthority();fail('saml_key_not_staged',409);}await log('saml_key_activated',data.kid,{});return json({ok:true});}
 if(path==='/saml-keys/retire'){if(!await retireSamlKey(ctx,String(data.kid||''),guard)){await actor.assertAuthority();fail('saml_key_not_found',404);}await log('saml_key_retired',data.kid,{});return json({ok:true});}

 if(path==='/bookmarks/create') {
  const name=text(data.name,120,'invalid_bookmark_name'),icon=text(data.icon||'Link',12,'invalid_bookmark_icon');
  const url=endpoint(ctx,data.url,'bookmark_url');
  const group=await one(ctx,'SELECT id FROM auth_groups WHERE id=?',String(data.groupId??''))||fail('group_not_found',404),id=random();
  if(!await held(await run(ctx,`INSERT INTO auth_launcher_bookmarks(id,name,url,icon,group_id,created_by,created_at) SELECT ?,?,?,?,?,?,? WHERE ${g}`,id,name,url,icon,group.id,actor.actorId,ctx.now(),...ga)))fail('session_authority_changed',403);
  await log('bookmark_created',id,{name,groupId:group.id});return json({id},201);
 }
 if(path==='/bookmarks/remove') {
  if(!await held(await run(ctx,`DELETE FROM auth_launcher_bookmarks WHERE id=? AND ${g}`,String(data.id??''),...ga)))fail('bookmark_not_found',404);
  await log('bookmark_removed',data.id,{});return json({ok:true});
 }
 if(path==='/groups/create') {
  const id=random(),name=text(data.name,80,'invalid_group_name');
  if(await one(ctx,'SELECT 1 FROM auth_groups WHERE name=?',name))fail('group_exists',409);
  if(!await held(await run(ctx,`INSERT INTO auth_groups(id,name,created_by,created_at) SELECT ?,?,?,? WHERE ${g}`,id,name,actor.actorId,ctx.now(),...ga)))fail('session_authority_changed',403);
  await log('group_created',id,{name});return json({id,name},201);
 }
 if(path==='/groups/delete') {
  const group=await one(ctx,'SELECT id,name FROM auth_groups WHERE id=?',String(data.id||''))||fail('group_not_found',404);
  const members=(await all(ctx,'SELECT person_id FROM auth_group_members WHERE group_id=?',group.id)).map(m=>m.person_id),apps=await all(ctx,"SELECT app_id FROM auth_app_assignments WHERE principal_type='group' AND principal_id=?",group.id);
  const [,,,, done]=await commit([
   ctx.db.prepare(`DELETE FROM auth_app_assignments WHERE principal_type='group' AND principal_id=? AND ${g}`).bind(group.id,...ga),
   ctx.db.prepare(`DELETE FROM auth_group_members WHERE group_id=? AND ${g}`).bind(group.id,...ga),
   ctx.db.prepare(`DELETE FROM auth_group_exclusions WHERE group_id=? AND ${g}`).bind(group.id,...ga),
   ctx.db.prepare(`DELETE FROM auth_group_owners WHERE group_id=? AND ${g}`).bind(group.id,...ga),
   ctx.db.prepare(`DELETE FROM auth_groups WHERE id=? AND ${g}`).bind(group.id,...ga),
  ]);
  if(!await held(done))fail('group_not_found',404);
  await log('group_deleted',group.id,{name:group.name});
  for(const a of apps)await queue(ctx,a.app_id,[...members.map(id=>['person',id]),['group',group.id]],'group_deleted');
  return json({ok:true});
 }
 if(path==='/groups/add'||path==='/groups/remove') {
  const group=await one(ctx,'SELECT id,rule FROM auth_groups WHERE id=?',String(data.groupId||''))||fail('group_not_found',404);
  const person=await one(ctx,'SELECT id,email FROM oa_operators WHERE id=? OR email=?',String(data.personId||''),String(data.email||'').trim().toLowerCase())||fail('person_not_found',404);
  const adding=path==='/groups/add';let changed;
  if(adding) {
   // An administrator's addition pins the person, and lifts an earlier exclusion from a rule's group.
   const [added,lifted]=await commit([
    ctx.db.prepare(`INSERT INTO auth_group_members(group_id,person_id,added_by,added_at) SELECT ?,?,?,? WHERE ${g} ON CONFLICT(group_id,person_id) DO UPDATE SET source='manual',added_by=excluded.added_by,added_at=excluded.added_at WHERE auth_group_members.source='rule'`).bind(group.id,person.id,actor.actorId,ctx.now(),...ga),
    ctx.db.prepare(`DELETE FROM auth_group_exclusions WHERE group_id=? AND person_id=? AND ${g}`).bind(group.id,person.id,...ga),
   ]);
   changed={meta:{changes:added.meta.changes+lifted.meta.changes}};
  } else {
   // Removing someone a rule matches excludes them, so the rule does not add them back.
   const dir=group.rule?await loadDirectory(ctx):null,rule=group.rule&&JSON.parse(group.rule),excluded=Boolean(rule&&matches(rule,dir.values(dir.people.get(person.id))));
   const [removed,exclusion]=await commit([
    ctx.db.prepare(`DELETE FROM auth_group_members WHERE group_id=? AND person_id=? AND ${g}`).bind(group.id,person.id,...ga),
    ctx.db.prepare(`INSERT INTO auth_group_exclusions(group_id,person_id,reason,set_by,set_at) SELECT ?,?,?,?,? WHERE ${excluded?'1':'0'} AND ${g} ON CONFLICT DO NOTHING`).bind(group.id,person.id,data.reason?String(data.reason).slice(0,200):null,actor.actorId,ctx.now(),...ga),
   ]);
   changed={meta:{changes:removed.meta.changes+exclusion.meta.changes}};
  }
  if(!await held(changed))return json({ok:true,changed:false});
  await log(adding?'group_member_added':'group_member_removed',group.id,{person:person.email});
  await emit(ctx,adding?'group.member_added':'group.member_removed',{type:'person',id:person.id,email:person.email},{group:group.id});
  await groupChanged(ctx,group.id,[person.id],adding?'group_member_added':'group_member_removed');
  return json({ok:true,changed:true});
 }

 if(path==='/company-apps/create'||path==='/catalog/add') {
  const r=path==='/catalog/add'?recipe(String(data.recipe||'')):null;
  const settings=appSettings(ctx,r?{...data,...r.saml(data),name:data.name||r.name}:data),id=random(),now=ctx.now();
  if(await one(ctx,'SELECT 1 FROM auth_apps WHERE entity_id=?',settings.entityId))fail('entity_id_in_use',409);
  const statements=[ctx.db.prepare(`INSERT INTO auth_apps(id,recipe,${SETTINGS_SQL},created_by,created_at,updated_at) SELECT ?,?,${settingsColumns(settings).map(()=>'?').join(',')},?,?,? WHERE ${g}`).bind(id,r?.id??null,...settingsColumns(settings),actor.actorId,now,now,...ga)];
  if(r&&r.provisioning.kind==='scim'&&data.token)statements.push(ctx.db.prepare(`INSERT INTO auth_scim_connectors(app_id,base_url,sealed_token,deprovision,push_groups,created_by,created_at) SELECT ?,?,?,?,?,?,? WHERE ${g}`).bind(id,scimBase(ctx,r.provisioning.base(data)),await seal(ctx,'scim:'+id,text(data.token,4096,'invalid_scim_token')),'deactivate',r.provisioning.groups?1:0,actor.actorId,now,...ga));
  const [created]=await commit(statements);
  if(!await held(created))fail('session_authority_changed',403);
  await log(r?'catalog_app_added':'company_app_created',id,{name:settings.name,entityId:settings.entityId,recipe:r?.id??null});
  return json({id,name:settings.name,notes:settings.notes,provisioning:statements.length>1},201);
 }
 if(path==='/oidc-apps/create') {
  const c=clientSettings(ctx,data),name=text(data.name,120,'invalid_name'),attributes=parseAttributes(data.attributes??[]),id=random(),clientId=random(),now=ctx.now();
  const secret=c.authMethod.startsWith('client_secret')?random():null;
  const statements=[
   ctx.db.prepare(`INSERT INTO auth_apps(id,name,entity_id,acs,name_id_format,sign,digest,attributes,launch_url,protocol,created_by,created_at,updated_at) SELECT ?,?,?,'[]','persistent','response','sha256',?,?,'oidc',?,?,? WHERE ${g}`).bind(id,name,'oidc:'+clientId,JSON.stringify(attributes),data.launchUrl?endpoint(ctx,data.launchUrl,'launch_url'):null,actor.actorId,now,now,...ga),
   ctx.db.prepare(`INSERT INTO auth_oidc_clients(app_id,client_id,auth_method,jwks,redirect_uris,post_logout_redirect_uris,require_pkce,subject_type,legacy_flows,frontchannel_logout_uri,backchannel_logout_uri,id_token_alg) SELECT ?,?,?,?,?,?,?,?,?,?,?,? WHERE ${g}`).bind(id,clientId,c.authMethod,c.jwks?JSON.stringify(c.jwks):null,JSON.stringify(c.redirectUris),JSON.stringify(c.postLogout),c.requirePkce?1:0,c.subjectType,c.legacyFlows?1:0,c.frontchannel,c.backchannel,c.alg,...ga),
  ];
  if(secret)statements.push(ctx.db.prepare(`INSERT INTO auth_oidc_secrets(id,client_id,secret_hash,created_at) SELECT ?,?,?,? WHERE ${g}`).bind(random(),clientId,await hash(secret),now,...ga));
  const [created]=await commit(statements);
  if(!await held(created))fail('session_authority_changed',403);
  await log('oidc_app_created',id,{name,authMethod:c.authMethod,redirectUris:c.redirectUris});
  // The secret is shown once; Auth keeps only its digest.
  return json({id,clientId,clientSecret:secret,authMethod:c.authMethod,message:`Client ID ${clientId}${secret?`. Client secret, shown once: ${secret}`:''}`},201);
 }
 if(path==='/oidc-apps/rotate-secret') {
  const client=await one(ctx,"SELECT c.client_id,c.auth_method FROM auth_oidc_clients c JOIN auth_apps a ON a.id=c.app_id WHERE c.app_id=? AND a.disabled_at IS NULL",String(data.appId||''))||fail('app_not_found',404);
  if(!client.auth_method.startsWith('client_secret'))fail('app_has_no_secret',409);
  const overlap=overlapOf(data.overlapHours),secret=random(),now=ctx.now();
  const [,added]=await commit([
   ctx.db.prepare(`UPDATE auth_oidc_secrets SET expires_at=? WHERE client_id=? AND expires_at IS NULL AND ${g}`).bind(now+overlap,client.client_id,...ga),
   ctx.db.prepare(`INSERT INTO auth_oidc_secrets(id,client_id,secret_hash,created_at) SELECT ?,?,?,? WHERE ${g}`).bind(random(),client.client_id,await hash(secret),now,...ga),
  ]);
  if(!await held(added))fail('session_authority_changed',403);
  await log('oidc_secret_rotated',data.appId,{previousValidUntil:now+overlap});
  return json({clientSecret:secret,previousValidUntil:now+overlap,message:`New client secret, shown once: ${secret}. The previous secret works until ${new Date(now+overlap).toISOString()}.`});
 }
 if(path==='/company-apps/update') {
  if(actor.kind!=='service')fail('configuration_preview_required',409);
  const current=await app(data.id),settings=appSettings(ctx,data);if(current.protocol!=='saml')fail('not_a_saml_app',409);
  if(actor.kind==='service') {
   if(!data.metadata&&!Object.hasOwn(data,'signingCertificate'))settings.signingCertificates=current.spCertificates;
   if(!data.metadata&&!Object.hasOwn(data,'encryptionCertificate'))settings.encryptionCertificate=current.encryption_certificate;
  }
  if(await one(ctx,'SELECT 1 FROM auth_apps WHERE entity_id=? AND id!=?',settings.entityId,current.id))fail('entity_id_in_use',409);
  if(!await held(await run(ctx,`UPDATE auth_apps SET ${SETTINGS_SQL.split(',').map(c=>`${c}=?`).join(',')},version=version+1,updated_at=? WHERE id=? AND version=? AND disabled_at IS NULL AND ${g}`,...settingsColumns(settings),ctx.now(),current.id,Number(data.version??current.version),...ga)))fail('app_changed',409);
  await log('company_app_updated',current.id,{entityId:settings.entityId});
  return json({id:current.id,notes:settings.notes});
 }
 if(path==='/company-apps/remove') {
  const current=await app(data.id);
  if(!await held(await run(ctx,`UPDATE auth_apps SET disabled_at=?,version=version+1 WHERE id=? AND disabled_at IS NULL AND ${g}`,ctx.now(),current.id,...ga)))fail('app_not_found',404);
  await log('company_app_removed',current.id,{name:current.name});await emit(ctx,'app.removed',{type:'app',id:current.id},{name:current.name});
  await queueApp(ctx,current.id,'app_removed');
  return json({removed:true});
 }
 if(path==='/company-apps/assign'||path==='/company-apps/unassign') {
  // The form sends principal as 'group:<id>' or 'person:<id>'; the API may send the two fields.
  const [kind,given]=data.principal?String(data.principal).split(/:(.*)/s):[data.principalType,data.principalId];
  const current=await app(data.appId),type=kind==='group'?'group':'person',principal=String(given||'');
  const target=type==='group'?await one(ctx,'SELECT id,name FROM auth_groups WHERE id=?',principal):await one(ctx,"SELECT id,email AS name FROM oa_operators WHERE id=? AND status!='inactive'",principal);
  if(!target)fail(`${type}_not_found`,404);
  const role=data.role?text(data.role,80,'invalid_role'):null;
  const changed=path==='/company-apps/assign'
   ?await run(ctx,`INSERT INTO auth_app_assignments(app_id,principal_type,principal_id,role,created_by,created_at) SELECT ?,?,?,?,?,? WHERE ${g} ON CONFLICT(app_id,principal_type,principal_id) DO UPDATE SET role=excluded.role,created_by=excluded.created_by,created_at=excluded.created_at`,current.id,type,principal,role,actor.actorId,ctx.now(),...ga)
   :await run(ctx,`DELETE FROM auth_app_assignments WHERE app_id=? AND principal_type=? AND principal_id=? AND ${g}`,current.id,type,principal,...ga);
  if(!await held(changed))return json({ok:true,changed:false});
  await log(path==='/company-apps/assign'?'app_assigned':'app_unassigned',current.id,{[type]:target.name,role});
  await emit(ctx,path==='/company-apps/assign'?'app.assigned':'app.unassigned',{type,id:principal,...(type==='person'?{email:target.name}:{})},{app:current.id,role});
  const people=type==='person'?[principal]:(await all(ctx,'SELECT person_id FROM auth_group_members WHERE group_id=?',principal)).map(m=>m.person_id);
  const connector=await connectorOf(ctx,current.id);
  await queue(ctx,current.id,[...people.map(id=>['person',id]),...(type==='group'&&connector?.push_groups?[['group',principal]]:[])],path.slice('/company-apps/'.length));
  return json({ok:true,changed:true});
 }

 if(path==='/provisioning/connect'||path==='/provisioning/rotate') {
  const current=await app(data.appId),token=text(data.token,4096,'invalid_scim_token');
  if(path==='/provisioning/connect') {
   const base=scimBase(ctx,data.baseUrl),deprovision=data.deprovision==='delete'?'delete':'deactivate',groups=[true,'true','on','1'].includes(data.pushGroups)?1:0;
   if(!await held(await run(ctx,`INSERT INTO auth_scim_connectors(app_id,base_url,sealed_token,deprovision,push_groups,created_by,created_at) SELECT ?,?,?,?,?,?,? WHERE ${g} ON CONFLICT(app_id) DO UPDATE SET base_url=excluded.base_url,sealed_token=excluded.sealed_token,deprovision=excluded.deprovision,push_groups=excluded.push_groups,rotated_at=excluded.created_at`,current.id,base,await seal(ctx,'scim:'+current.id,token),deprovision,groups,actor.actorId,ctx.now(),...ga)))fail('session_authority_changed',403);
   await log('provisioning_connected',current.id,{baseUrl:base,deprovision,groups:Boolean(groups)});
   await queueApp(ctx,current.id,'connector_connected');
   return json({ok:true},201);
  }
  if(!await held(await run(ctx,`UPDATE auth_scim_connectors SET sealed_token=?,rotated_at=? WHERE app_id=? AND ${g}`,await seal(ctx,'scim:'+current.id,token),ctx.now(),current.id,...ga)))fail('connector_not_found',404);
  await log('provisioning_credential_rotated',current.id,{});return json({ok:true});
 }
 const current=await app(data.appId),connector=await connectorOf(ctx,current.id);
 if(path==='/provisioning/preview'){await authorized();const changes=await preview(ctx,current.id),count=op=>changes.filter(c=>c.operation===op).length;return json({app:current.id,connected:Boolean(connector),changes,message:`Preview: ${count('create')} to create, ${count('update')} to update, ${count('deactivate')+count('delete')} to deactivate or delete (destructive), ${count('none')} unchanged.`});}
 if(!connector)fail('connector_not_found',404);
 if(path==='/provisioning/disconnect') {
  if(!await held(await run(ctx,`DELETE FROM auth_scim_connectors WHERE app_id=? AND ${g}`,current.id,...ga)))fail('connector_not_found',404);
  await run(ctx,"UPDATE auth_provisioning SET state='failed',last_error='connector_removed' WHERE app_id=? AND state='pending'",current.id);
  await log('provisioning_disconnected',current.id,{});return json({ok:true});
 }
 await authorized();
 if(path==='/provisioning/test'){const result=await testConnection(ctx,connector);await log('provisioning_tested',current.id,{ok:result.ok,status:result.usersStatus});return json({...result,message:result.ok?`Connection works: Auth can read users${result.totalUsers===null?'':` (${result.totalUsers})`}.`:`Connection failed: the app answered ${result.usersStatus||'nothing'}.`});}
 if(path==='/provisioning/sync'){const result=await reconcile(ctx,current.id);await log('provisioning_reconciled',current.id,result);return json(result);}
 if(path==='/provisioning/retry') {
  const retried=await run(ctx,`UPDATE auth_provisioning SET state='pending',next_attempt_at=? WHERE app_id=? AND state IN ('failed','pending') AND ${g}`,ctx.now(),current.id,...ga);
  await dispatch(ctx,current.id);return json({retried:retried.meta.changes});
 }
 // '/provisioning/adopt': an administrator's collision decision binds an existing remote account.
 const person=await one(ctx,'SELECT id,email FROM oa_operators WHERE id=?',String(data.personId||''))||fail('person_not_found',404),remote=text(data.remoteId,256,'invalid_remote_id');
 if(!await held(await run(ctx,`INSERT INTO auth_scim_accounts(app_id,subject_type,subject_id,remote_id,state,updated_at) SELECT ?,'person',?,?,'active',? WHERE NOT EXISTS(SELECT 1 FROM auth_scim_accounts WHERE app_id=? AND subject_type='person' AND (subject_id=? OR remote_id=?)) AND ${g}`,current.id,person.id,remote,ctx.now(),current.id,person.id,remote,...ga)))fail('account_already_bound',409);
 await log('provisioning_account_adopted',current.id,{person:person.email,remoteId:remote});
 await queue(ctx,current.id,[['person',person.id]],'account_adopted');
 return json({ok:true});
}

// Apps page model for administrators.
export async function workforceModel(ctx) {
 const mappings=await all(ctx,'SELECT app_id,version,program,created_at FROM auth_mapping_versions ORDER BY version DESC');
 const [apps,assignments,groups,members,connectors,obligations,keys]=await Promise.all([
  all(ctx,'SELECT * FROM auth_apps ORDER BY name'),
  all(ctx,"SELECT a.app_id,a.principal_type,a.principal_id,a.role,COALESCE(g.name,p.email) AS label FROM auth_app_assignments a LEFT JOIN auth_groups g ON a.principal_type='group' AND g.id=a.principal_id LEFT JOIN oa_operators p ON a.principal_type='person' AND p.id=a.principal_id ORDER BY label"),
  all(ctx,'SELECT id,name,created_at FROM auth_groups ORDER BY name'),
  all(ctx,'SELECT m.group_id,p.id,p.email FROM auth_group_members m JOIN oa_operators p ON p.id=m.person_id ORDER BY p.email'),
  all(ctx,'SELECT app_id,base_url,deprovision,push_groups,created_at,rotated_at,last_success_at,last_error,last_reconciled_at FROM auth_scim_connectors'),
  all(ctx,"SELECT o.app_id,o.subject_type,o.subject_id,o.reason,o.operation,o.state,o.event_at,o.dispatched_at,o.verified_at,o.attempts,o.last_status,o.last_error,COALESCE(p.email,g.name) AS label FROM auth_provisioning o LEFT JOIN oa_operators p ON o.subject_type='person' AND p.id=o.subject_id LEFT JOIN auth_groups g ON o.subject_type='group' AND g.id=o.subject_id WHERE o.state!='superseded' ORDER BY o.event_at DESC LIMIT 200"),
  publishedKeys(ctx),
 ]);
 const oidc=await all(ctx,"SELECT c.*,(SELECT COUNT(*) FROM auth_oidc_secrets s WHERE s.client_id=c.client_id AND (s.expires_at IS NULL OR s.expires_at>?)) AS live_secrets,(SELECT MAX(expires_at) FROM auth_oidc_secrets s WHERE s.client_id=c.client_id AND s.expires_at>?) AS overlap_until FROM auth_oidc_clients c",ctx.now(),ctx.now());
 const now=ctx.now();
 return {
  idp:{entityId:idpEntity(ctx),metadataUrl:`${ctx.origin}/saml/metadata`,ssoUrl:`${ctx.origin}/saml/sso`,sloUrl:`${ctx.origin}/saml/slo`},
  samlKeys:keys.map(k=>({kid:k.kid,state:k.state,createdAt:k.created_at,activatedAt:k.activated_at})),
  companyApps:await Promise.all(apps.map(async row=>{const a=appOf(row),c=connectors.find(x=>x.app_id===a.id);const o=oidc.find(x=>x.app_id===a.id);return {configuration:a.protocol==='saml'?configurationOf(a):null,revisions:a.protocol==='saml'?await revisionHistory(ctx,a.id):[],id:a.id,name:a.name,mapping:{version:a.mapping_version,versions:mappings.filter(m=>m.app_id===a.id)},protocol:a.protocol,oidc:o?{clientId:o.client_id,authMethod:o.auth_method,redirectUris:JSON.parse(o.redirect_uris),postLogoutRedirectUris:JSON.parse(o.post_logout_redirect_uris),requirePkce:Boolean(o.require_pkce),subjectType:o.subject_type,legacyFlows:Boolean(o.legacy_flows),frontchannelLogoutUri:o.frontchannel_logout_uri,backchannelLogoutUri:o.backchannel_logout_uri,idTokenAlg:o.id_token_alg,liveSecrets:o.live_secrets,previousSecretUntil:o.overlap_until}:null,recipe:a.recipe,entityId:a.entity_id,acs:a.acs,slo:a.slo,nameIdFormat:a.name_id_format,sign:a.sign,digest:a.digest,encryption:a.encryption,idpInitiated:Boolean(a.idp_initiated),version:a.version,status:a.disabled_at?'removed':'active',metadata:spMetadata(a),
   assignments:assignments.filter(x=>x.app_id===a.id).map(x=>({type:x.principal_type,id:x.principal_id,label:x.label,role:x.role})),
   provisioning:c?{baseUrl:c.base_url,deprovision:c.deprovision,groups:Boolean(c.push_groups),lastSuccessAt:c.last_success_at,lastError:c.last_error,lastReconciledAt:c.last_reconciled_at,rotatedAt:c.rotated_at}:null,
   obligations:obligations.filter(o=>o.app_id===a.id).map(o=>({...o,overdue:o.state!=='verified'&&now-o.event_at>ESCALATE_AFTER}))};})),
  groups:groups.map(gr=>({...gr,members:members.filter(m=>m.group_id===gr.id).map(m=>({id:m.id,email:m.email}))})),
  bookmarks:await all(ctx,'SELECT b.*,g.name AS group_name FROM auth_launcher_bookmarks b JOIN auth_groups g ON g.id=b.group_id ORDER BY b.name'),
  catalog:catalog(),
  oidcMethods:METHODS,
  nameIdFormats:Object.keys(FORMATS),
 };
}

// GET doors: administrators read the workforce model and an app's exported
// metadata; everyone signed in reads their own launcher.
export async function workforceRead(ctx,request,path) {
 if(path==='/api/auth/launcher/open')return launcherOpen(ctx,request);
 if(path==='/api/auth/launcher'){const s=await session(ctx,request);if(!s)fail('sign_in_required',401);return json({apps:await launcher(ctx,s.person_id)});}
 await requireSession(ctx,request,true);
 if(path==='/api/auth/company-apps')return json(await workforceModel(ctx));
 if(path==='/api/auth/company-apps/metadata'){const a=appOf(await one(ctx,'SELECT * FROM auth_apps WHERE id=?',new URL(request.url).searchParams.get('id')||''))||fail('app_not_found',404);return new Response(spMetadata(a),{headers:{'content-type':'application/samlmetadata+xml; charset=utf-8','cache-control':'no-store'}});}
 fail('not_found',404);
}
export const WORKFORCE_READS=['/api/auth/launcher/open','/api/auth/launcher','/api/auth/company-apps','/api/auth/company-apps/metadata'];
