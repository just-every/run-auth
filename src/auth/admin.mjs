import {configuredProvider} from './domain-policy.mjs';
import {freshLocalEmail,requireLocalEmail,authority,requireAuthority} from './local-email.mjs';
import {stageSigningKey,retireSigningKey} from './keys.mjs';
import {random,email,one,all,run,requireSession,session,audit,json,fail,cookie,cookieName} from './core.mjs';
import {moveInModel} from './move-in/routes.mjs';
import {agentsModel} from './agents/routes.mjs';
export async function model(ctx,request,page='account') {
 const s=await session(ctx,request);if(!s)return {page,issuer:ctx.origin,user:null,me:null,isAdmin:false};
 const amr=JSON.parse(s.amr),isAdmin=['owner','admin'].includes(s.role)&&amr.includes('hwk');
 const user={id:s.person_id,name:s.display_name,email:s.email,role:s.role,amr};
 const [methods,notices,recoveries]=await Promise.all([
  all(ctx,'SELECT id,created_at,last_used_at FROM auth_passkeys WHERE person_id=?',s.person_id),
  all(ctx,'SELECT id,recovery_id,message,created_at FROM auth_notices WHERE session_id=? ORDER BY created_at DESC',s.id),
  all(ctx,isAdmin?'SELECT r.*,p.email FROM auth_recoveries r JOIN oa_operators p ON p.id=r.person_id WHERE r.cancelled_at IS NULL AND r.completed_at IS NULL':'SELECT * FROM auth_recoveries WHERE person_id=? AND cancelled_at IS NULL AND completed_at IS NULL',...(isAdmin?[]:[s.person_id])),
 ]);
 const result={page,issuer:ctx.origin,user,me:{...user,admin:isAdmin,method:amr.includes('hwk')?'passkey':'email'},isAdmin,localEmailConfirmed:freshLocalEmail(ctx,s),csrf:'',methods,passkeys:methods,notices,recoveries,people:[],domains:[],domainRules:[],policyProviders:[],apps:[],activity:[],unavailableActions:['apps.approve','apps.remove','account.signout-everywhere'],notice:null};
 if(isAdmin) {
  [result.people,result.domains,result.apps,result.activity,result.domainRules]=await Promise.all([
   all(ctx,'SELECT id,email,display_name AS name,role,status,created_at FROM oa_operators ORDER BY email'),
   all(ctx,'SELECT domain,created_at FROM auth_domains ORDER BY domain'),
   all(ctx,'SELECT id,name,origin,sector_id,source,created_at,disabled_at FROM auth_clients ORDER BY name'),
   all(ctx,'SELECT a.*,p.email AS actor_email,d.detail FROM auth_activity a LEFT JOIN oa_operators p ON p.id=a.actor_id LEFT JOIN auth_activity_details d ON d.activity_id=a.id ORDER BY a.id DESC LIMIT 100'),
   all(ctx,'SELECT domain,provider_id FROM oa_domain_rules ORDER BY domain'),
  ]);
  result.policyProviders=(ctx.upstreamProviders||[]).map(p=>({id:p.id,label:p.label||p.preset}));
  result.domainRules=result.domainRules.map(rule=>({...rule,available:Boolean(configuredProvider(ctx,rule.provider_id))}));
  if(page==='move-in')Object.assign(result,await moveInModel(ctx,request));
  if(page==='agents')Object.assign(result,await agentsModel(ctx,request));
 }
 return result;
}
// The one invitation message, from People and from move-in alike.
export async function sendInvitation(ctx,address) {
 if(ctx.mail)await ctx.mail({to:address,subject:'You are invited to Auth',text:`Sign in to ${ctx.origin}/signin with your email address to accept your invitation.`,html:'<p>You are invited to Auth. Sign in with your email address to accept.</p>'});
}
const ADMIN_ACTIONS=['/people/invite','/people/domain','/domains/add','/people/domain-rule','/people/suspend'];
const OWNER_ACTIONS=['/people/role','/keys/stage','/keys/retire'];
const domainOf=data=>{const domain=String(data.domain||'').trim().toLowerCase();if(!/^(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)||domain.length>253)fail('invalid_domain');return domain;};
export async function adminAction(ctx,request,path,data) {
 if(path==='/signout') {
  const s=await requireSession(ctx,request);await run(ctx,'UPDATE auth_sessions SET revoked_at=? WHERE id=?',ctx.now(),s.id);
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
  if(!created.meta.changes)await requireAuthority(ctx,s,guard);
  await sendInvitation(ctx,address);
  await audit(ctx,s.person_id,'person_invited',address);return json({ok:true},201);
 }
 if(path==='/people/domain'||path==='/domains/add') {
  const domain=domainOf(data);
  const added=await run(ctx,`INSERT OR IGNORE INTO auth_domains(domain,created_by,created_at) SELECT ?,?,? WHERE ${g}`,domain,s.person_id,ctx.now(),...ga);
  if(!added.meta.changes)await requireAuthority(ctx,s,guard);
  await audit(ctx,s.person_id,'domain_allowed',domain);return json({ok:true},201);
 }
 if(path==='/people/domain-rule') {
  const domain=domainOf(data),providerId=String(data.providerId||'');
  if(providerId&&!configuredProvider(ctx,providerId))fail('unknown_provider');
  const changed=providerId
   ?await run(ctx,`INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) SELECT ?,?,?,? WHERE ${g} ON CONFLICT(domain) DO UPDATE SET provider_id=excluded.provider_id,created_by=excluded.created_by,created_at=excluded.created_at`,domain,providerId,s.person_id,ctx.now(),...ga)
   :await run(ctx,`DELETE FROM oa_domain_rules WHERE domain=? AND ${g}`,domain,...ga);
  if(!changed.meta.changes)await requireAuthority(ctx,s,guard);
  await audit(ctx,s.person_id,providerId?'domain_provider_required':'domain_provider_removed',domain);return json({ok:true});
 }
 if(path==='/people/role') {
  const id=data.id||data.personId;if(!['admin','member'].includes(data.role))fail('invalid_role');
  const changed=await run(ctx,`UPDATE oa_operators SET role=? WHERE id=? AND role!='owner' AND status='active' AND ${g}`,data.role,id,...ga);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('person_unavailable',409);}
  await audit(ctx,s.person_id,'person_role_changed',id);return json({ok:true});
 }
 if(path==='/people/suspend') {
  const id=data.personId||data.id,p=await one(ctx,'SELECT id,role FROM oa_operators WHERE id=?',id);if(!p)fail('person_not_found',404);if(p.role==='owner')fail('owner_suspension_requires_transfer',403);
  // Base's version trigger also revokes all previously issued Base sessions.
  const changed=await run(ctx,`UPDATE oa_operators SET status='inactive' WHERE id=? AND role!='owner' AND ${g}`,id,...ga);
  if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('person_unavailable',409);}
  await audit(ctx,s.person_id,'person_suspended',id);return json({ok:true});
 }
 if(path==='/keys/stage') {
  const staged=await stageSigningKey(ctx,data.alg,guard);if(!staged){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
  return json(staged,201);
 }
 if(!await retireSigningKey(ctx,data.kid,guard))await requireAuthority(ctx,s,guard);
 return json({ok:true});
}
