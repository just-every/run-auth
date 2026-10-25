import {notificationsModel,notifySecurity} from './notifications/index.mjs';
import {ownershipModel,requireVerifiedDomain} from './domains/ownership.mjs';
import {maintainFamilies} from './tokens/lifecycle.mjs';
import {refreshInventory} from './tokens/routes.mjs';
import {requestsRead} from './requests/index.mjs';
import {decisionsModel} from './decisions/policy.mjs';
import {reviewsModel} from './reviews/routes.mjs';
import {retentionRead} from './retention/index.mjs';
import {syncObligations} from './obligations/sources.mjs';
import {followupRead} from './obligations/routes.mjs';
import {roleModel,roleRead} from './roles/index.mjs';
import {delegationInventory,delegationConsentView} from './agents/delegation/index.mjs';
import {requireAccountRank} from './ranks.mjs';
import {ownerState,SCOPE_PERMISSIONS} from './admin-api/scoped-authority.mjs';
import {AuthError} from './core.mjs';
import {grantModel} from './grants/index.mjs';
import {erasureModel} from './erasure/index.mjs';
import {tenancyModel} from './tenancy/routes.mjs';
import {adminServicesModel} from './admin-api/credentials/index.mjs';
import {hookModel} from './hooks/index.mjs';
import {configuredProvider} from './domain-policy.mjs';
import {freshLocalEmail,requireLocalEmail,authority,requireAuthority} from './local-email.mjs';
import {stageSigningKey,retireSigningKey} from './keys.mjs';
import {random,email,one,all,run,requireSession,session,audit,json,fail,cookie,cookieName} from './core.mjs';
import {moveInModel} from './move-in/routes.mjs';
import {agentsModel} from './agents/routes.mjs';
import {appsModel} from './links/routes.mjs';
import {fencePerson} from './links/logout.mjs';
import {personChanged} from './provisioning/obligations.mjs';
import {workforceModel} from './workforce/routes.mjs';
import {directoryModel} from './workforce/people/model.mjs';
import {profileModel} from './profiles/routes.mjs';
import {launcher} from './workforce/directory.mjs';
import {emit,personSubject} from './events/store.mjs';
import {eventsModel} from './events/routes.mjs';
import {rerTrustModel} from './links/rer-trust.mjs';
export async function model(ctx,request,page='account') {
 const s=await session(ctx,request);if(!s)return {page,issuer:ctx.origin,user:null,me:null,isAdmin:false};
 const amr=JSON.parse(s.amr),isAdmin=['owner','admin'].includes(s.role)&&amr.includes('hwk');
 const user={id:s.person_id,name:s.display_name,email:s.email,role:s.role,amr};
 const [methods,notices,recoveries]=await Promise.all([
  all(ctx,'SELECT id,created_at,last_used_at FROM auth_passkeys WHERE person_id=?',s.person_id),
  all(ctx,'SELECT id,recovery_id,message,created_at FROM auth_notices WHERE session_id=? ORDER BY created_at DESC',s.id),
  all(ctx,isAdmin?'SELECT r.*,p.email FROM auth_recoveries r JOIN oa_operators p ON p.id=r.person_id WHERE r.cancelled_at IS NULL AND r.completed_at IS NULL':'SELECT * FROM auth_recoveries WHERE person_id=? AND cancelled_at IS NULL AND completed_at IS NULL',...(isAdmin?[]:[s.person_id])),
 ]);
 const result={page,issuer:ctx.origin,user,me:{...user,admin:isAdmin,method:amr.includes('hwk')?'passkey':'email'},isAdmin,localEmailConfirmed:freshLocalEmail(ctx,s),csrf:'',methods,passkeys:methods,notices,recoveries,people:[],domains:[],domainRules:[],policyProviders:[],apps:[],activity:[],unavailableActions:[],notice:null};
 if(isAdmin) {
  let apps;
  [result.people,result.domains,apps,result.activity,result.domainRules]=await Promise.all([
   all(ctx,'SELECT id,email,display_name AS name,role,status,created_at FROM oa_operators ORDER BY email'),
   all(ctx,'SELECT domain,created_at FROM auth_domains ORDER BY domain'),
   appsModel(ctx),
   all(ctx,`SELECT a.*,p.email AS actor_email,service.name AS service_name,custodian.email AS service_owner_email,d.detail FROM auth_activity a LEFT JOIN oa_operators p ON p.id=a.actor_id LEFT JOIN auth_admin_service_apps service ON a.actor_id='admin-service:'||service.id LEFT JOIN oa_operators custodian ON custodian.id=service.owner_id LEFT JOIN auth_activity_details d ON d.activity_id=a.id ORDER BY a.id DESC LIMIT 100`),
   all(ctx,'SELECT domain,provider_id FROM oa_domain_rules ORDER BY domain'),
  ]);
  Object.assign(result,apps);
  result.domainOwnership=await ownershipModel(ctx);
  result.rerTrust=await rerTrustModel(ctx);
  result.policyProviders=(ctx.upstreamProviders||[]).map(p=>({id:p.id,label:p.label||p.preset}));
  result.domainRules=result.domainRules.map(rule=>({...rule,available:Boolean(configuredProvider(ctx,rule.provider_id))}));
  if(page==='move-in')Object.assign(result,await moveInModel(ctx,request));
  if(page==='agents'){Object.assign(result,await agentsModel(ctx,request));result.adminServices=await adminServicesModel(ctx);}
  if(page==='people')result.directory=await directoryModel(ctx);
  if(page==='activity')result.followup=await (await followupRead(ctx,request)).json();
  if(page==='apps'){result.workforce=await workforceModel(ctx);result.events=await eventsModel(ctx);result.inlineHooks=await hookModel(ctx);}
 }
 if(page==='account'||page==='activity'){result.decisions=await decisionsModel(ctx,s);result.reviews=await reviewsModel(ctx,s);result.requests={...await (await requestsRead(ctx,request)).json(),canManage:isAdmin,meId:s.person_id,people:isAdmin?result.people:[],adminApps:isAdmin?await all(ctx,'SELECT id,name FROM auth_apps WHERE disabled_at IS NULL'):[]};}
 if(page==='activity'&&isAdmin)result.retention=await (await retentionRead(ctx,request,'/api/auth/retention')).json();
 if(page==='account'||page==='activity')result.notifications=await notificationsModel(ctx,request);
 if(page==='account')result.followup=await (await followupRead(ctx,request)).json();
 if(page==='roles') {
  try { result.roles=await roleModel(ctx,s); }
  catch(error) {if(!(error instanceof AuthError)||error.status!==403)throw error;result.roleError=error.message;}
  if(result.roles)try{result.rolePeople=(await (await roleRead(ctx,request,'/api/auth/roles/people')).json()).people;}catch(error){if(!(error instanceof AuthError)||error.status!==403)throw error;result.rolePeople=[];}
  if(result.roles?.ownGrants.some(grant=>grant.permissions.includes('admin-api.manage'))) {
   const custody=await ownerState(ctx,s.person_id);
   result.adminServices=(await adminServicesModel(ctx)).filter(app=>custody.legacy||app.ownerId===s.person_id);
   const globalScopes=new Set(['policies.read','policies.manage','idps.read','idps.manage','domains.read']);
   result.adminServiceCustody={scopes:custody.legacy?Object.keys(SCOPE_PERMISSIONS):Object.entries(SCOPE_PERMISSIONS).filter(([scope,permissions])=>!globalScopes.has(scope)&&custody.entries.some(entry=>entry.role.permissions.includes('admin-api.manage')&&permissions.every(permission=>entry.role.permissions.includes(permission)))).map(([scope])=>scope)};
  }

 }
 if(page==='permissions'&&isAdmin){result.resourceApis=await grantModel(ctx);result.workforce=await workforceModel(ctx);}
 if(page==='erasure'&&s.role==='owner'&&isAdmin)result.erasure=await erasureModel(ctx,request);
 result.organizations=await tenancyModel(ctx,request,s);
 result.launcher=await launcher(ctx,s.person_id);
 if(page==='account'){result.profile=await profileModel(ctx,s);result.refresh=await refreshInventory(ctx,request,s);}
 if(page==='account'||page==='agents') {
  result.delegations=await (await delegationInventory(ctx,request)).json();
  const selected=new URL(request.url).searchParams.get('delegation');
  if(selected)result.delegation=await (await delegationConsentView(ctx,request,selected)).json();
  if(page==='agents'&&s.role==='owner'&&isAdmin)result.delegationApps=await all(ctx,'SELECT id,name FROM auth_apps WHERE disabled_at IS NULL ORDER BY name');
 }
 return result;
}
// The one invitation message, from People and from move-in alike.
export async function sendInvitation(ctx,address) {
 await syncObligations(ctx);
 if(ctx.mail)await ctx.mail({to:address,subject:'You are invited to Auth',text:`Sign in to ${ctx.origin}${ctx.basePath??''}/signin with your email address to accept your invitation.`,html:'<p>You are invited to Auth. Sign in with your email address to accept.</p>'});
}
const ADMIN_ACTIONS=['/people/invite','/people/domain','/domains/add','/people/domain-rule','/people/suspend'];
const OWNER_ACTIONS=['/people/role','/keys/stage','/keys/retire'];
const domainOf=data=>{const domain=String(data.domain||'').trim().toLowerCase();if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||domain.length>253)fail('invalid_domain');return domain;};
export async function adminAction(ctx,request,path,data) {
 if(path==='/signout') {
  const s=await requireSession(ctx,request);await run(ctx,'UPDATE auth_sessions SET revoked_at=? WHERE id=?',ctx.now(),s.id);
  await maintainFamilies(ctx);
  return json({ok:true},200,{'set-cookie':cookie(ctx,cookieName(ctx),'',0)});
 }
 const s=await requireSession(ctx,request,true),owner=OWNER_ACTIONS.includes(path);
 if(!owner&&!ADMIN_ACTIONS.includes(path))fail('not_found',404);
 if(owner&&s.role!=='owner')fail('owner_required',403);
 // Every administration write needs this session's fresh local email proof,
 // rechecked with its authority by the write itself.
 requireLocalEmail(ctx,s);
 const guard=authority(ctx,s,owner?['owner']:['owner','admin']),g=guard.clause,ga=guard.args;
 if(path==='/people/invite') {
  const address=email(data.email);if(!address||(!ctx.local && /\.(localhost|test|invalid)$/.test(address)))fail('invalid_email');
  const name=String(data.name||address).trim().slice(0,160);
  // Invitation does not silently reactivate a suspended account or grant a role.
  const created=await run(ctx,`INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE ${g} ON CONFLICT(email) DO NOTHING`,random(),address,name,ctx.now(),...ga);
  if(!created.meta.changes){await requireAuthority(ctx,s,guard);fail('person_already_exists',409);}
  await sendInvitation(ctx,address);
  await audit(ctx,s.person_id,'person_invited',address);
  if(created.meta.changes){const p=await one(ctx,'SELECT id FROM oa_operators WHERE email=?',address);await emit(ctx,'person.invited',{type:'person',id:p.id,email:address},{name});}
  return json({ok:true},201);
 }
 if(path==='/people/domain'||path==='/domains/add') {
  const domain=domainOf(data);await requireVerifiedDomain(ctx,domain);
  const added=await run(ctx,`INSERT OR IGNORE INTO auth_domains(domain,created_by,created_at) SELECT ?,?,? WHERE ${g}`,domain,s.person_id,ctx.now(),...ga);
  if(!added.meta.changes)await requireAuthority(ctx,s,guard);
  await audit(ctx,s.person_id,'domain_allowed',domain);if(added.meta.changes)await emit(ctx,'policy.domain_allowed',{type:'domain',id:domain},{});return json({ok:true},201);
 }
 if(path==='/people/domain-rule') {
  const domain=domainOf(data),providerId=String(data.providerId||'');
  if(providerId&&!configuredProvider(ctx,providerId))fail('unknown_provider');
  if(providerId)await requireVerifiedDomain(ctx,domain);
  const changed=providerId
   ?await run(ctx,`INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) SELECT ?,?,?,? WHERE ${g} ON CONFLICT(domain) DO UPDATE SET provider_id=excluded.provider_id,created_by=excluded.created_by,created_at=excluded.created_at`,domain,providerId,s.person_id,ctx.now(),...ga)
   :await run(ctx,`DELETE FROM oa_domain_rules WHERE domain=? AND ${g}`,domain,...ga);
  if(!changed.meta.changes)await requireAuthority(ctx,s,guard);
  await audit(ctx,s.person_id,providerId?'domain_provider_required':'domain_provider_removed',domain);await emit(ctx,'policy.domain_rule_changed',{type:'domain',id:domain},{requiredProvider:providerId||null});return json({ok:true});
 }
 if(path==='/people/role') {
  const id=data.id||data.personId;if(!['admin','member'].includes(data.role))fail('invalid_role');
  const account=await requireAccountRank(ctx,s,id,guard);
  const changed=await run(ctx,`UPDATE oa_operators SET role=? WHERE id=? AND role!='owner' AND status='active' AND ${account.clause}`,data.role,id,...account.args);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('person_unavailable',409);}
  if(data.role==='admin')await notifySecurity(ctx,{personId:id,event:'administrator_role_granted',sourceId:'role:'+id+':'+ctx.now(),request});
  await audit(ctx,s.person_id,'person_role_changed',id);await emit(ctx,'person.role_changed',await personSubject(ctx,id),{role:data.role});return json({ok:true});
 }
 if(path==='/people/suspend') {
  const id=data.personId||data.id,p=await one(ctx,'SELECT id,role FROM oa_operators WHERE id=?',id);if(!p)fail('person_not_found',404);if(p.role==='owner')fail('owner_suspension_requires_transfer',403);
  // Base's version trigger also revokes all previously issued Base sessions.
  const account=await requireAccountRank(ctx,s,id,guard);
  const changed=await run(ctx,`UPDATE oa_operators SET status='inactive' WHERE id=? AND role!='owner' AND ${account.clause}`,id,...account.args);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('person_unavailable',409);}
  await audit(ctx,s.person_id,'person_suspended',id);await fencePerson(ctx,id);await emit(ctx,'person.suspended',await personSubject(ctx,id),{});await personChanged(ctx,id,'person_suspended');return json({ok:true});
 }
 if(path==='/keys/stage') {
  const staged=await stageSigningKey(ctx,data.alg,guard);if(!staged){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
  return json(staged,201);
 }
 if(!await retireSigningKey(ctx,data.kid,guard))await requireAuthority(ctx,s,guard);
 return json({ok:true});
}
