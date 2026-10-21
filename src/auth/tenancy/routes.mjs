import {all,one,run,random,requireSession,json,fail,auditDetail,session} from '../core.mjs';
import {authority,requireAuthority,requireLocalEmail} from '../local-email.mjs';
import {provisionOrganization,organizationDatabase} from './storage.mjs';
import {organizationPath} from './context.mjs';

export const TENANCY_READ='/api/auth/organizations';
export const isTenancyAction=path=>['/organizations/create','/organizations/invite','/organizations/cancel-invitation','/organizations/switch'].includes(path);
export async function tenancyModel(ctx,request,s) {
 s??=await requireSession(ctx,request);
 const root=ctx.rootDb??ctx.db,available=[];
 // Only a live membership session reveals an employer, never an email match.
 const organizations=(await root.prepare("SELECT id,name FROM auth_organizations WHERE status='active' ORDER BY created_at,id").all()).results;
 for(const org of [{id:'root',name:'Installation'},...organizations]) {
  const db=org.id==='root'?root:(await organizationDatabase(root,org.id))?.db;
  if(!db)continue;
  const member=await session({...ctx,db,organizationId:org.id},request);
  if(member)available.push({...org,role:member.role,path:organizationPath(org.id)+'/app/account',active:org.id===(ctx.organizationId??'root')});
 }
 return {current:{id:ctx.organizationId??'root',name:ctx.organization?.name??'Installation'},memberships:available,canCreate:ctx.organizationId==='root'&&s.role==='owner'&&JSON.parse(s.amr).includes('hwk')};
}
export async function tenancyRead(ctx,request) {const s=await requireSession(ctx,request);return json(await tenancyModel(ctx,request,s));}
export async function tenancyAction(ctx,request,path,data) {
 if(path==='/organizations/switch') {
  await requireSession(ctx,request);
  const id=String(data.organizationId??'');
  if(id!=='root'&&!/^[a-f0-9]{32}$/.test(id))fail('organization_unavailable',404);
  const root=ctx.rootDb??ctx.db,selected=id==='root'?{db:root}:await organizationDatabase(root,id);
  if(!selected||!await session({...ctx,db:selected.db,organizationId:id},request))fail('organization_membership_required',403);
  await auditDetail(ctx,(await requireSession(ctx,request)).person_id,'organization_switched',null,{organizationId:id});
  return json({ok:true,redirect:organizationPath(id)+'/app/account'});
 }
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 if(path==='/organizations/create') {
  if(s.role!=='owner'||ctx.organizationId!=='root')fail('installation_owner_required',403);
  const name=String(data.name??'').trim();if(!name||name.length>100)fail('invalid_organization_name');
  const guard=authority(ctx,s,['owner']);await requireAuthority(ctx,s,guard);
  const id=crypto.randomUUID().replaceAll('-',''),root=ctx.rootDb??ctx.db;
  const selected=await provisionOrganization(root,{id,name,createdBy:s.person_id,now:ctx.now()});
  // The owner must prove email and enroll a passkey in this employer. Neither
  // a root session nor root factor material becomes employer authority.
  const personId=random();
  await requireAuthority(ctx,s,guard);
  const seeded=await root.prepare(`INSERT INTO ${selected.organization.namespace}oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'owner','active',1,? WHERE ${guard.clause}`).bind(personId,s.email,s.display_name,ctx.now(),...guard.args).run();
  if(!seeded.meta.changes){await requireAuthority(ctx,s,guard);fail('organization_creation_refused',409);}
  await auditDetail(ctx,s.person_id,'organization_created',id,{name});
  return json({id,name,signInPath:organizationPath(id)+'/signin?returnTo=%2Fapp%2Fmethods'},201);
 }
 // Invitation metadata expires even before a person first signs in. An
 // invitation is membership admission only; role grants use the roles planner.
 const address=String(data.email??'').trim().toLowerCase();
 if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(address))fail('invalid_email');
 const guard=authority(ctx,s,['owner','admin']);
 if(path==='/organizations/invite') {
  if(data.role&&data.role!=='member')fail('role_escalation_refused',403);
  const expiresAt=data.expiresAt===undefined?ctx.now()+7*86400000:Number(data.expiresAt);
  if(!Number.isSafeInteger(expiresAt)||expiresAt<=ctx.now()||expiresAt>ctx.now()+30*86400000)fail('invalid_invitation_expiry');
  const existing=await one(ctx,'SELECT * FROM oa_operators WHERE email=?',address);
  if(existing&&existing.status!=='invited')fail('person_unavailable',409);
  const id=existing?.id??random(),name=String(data.name||address).trim().slice(0,160);
  const changed=await ctx.db.batch([
   ctx.db.prepare(`INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE ${guard.clause} ON CONFLICT(email) DO NOTHING`).bind(id,address,name,ctx.now(),...guard.args),
   ctx.db.prepare(`INSERT INTO auth_org_invitations(person_id,expires_at,cancelled_at,created_by) SELECT ?,?,NULL,? WHERE ${guard.clause} ON CONFLICT(person_id) DO UPDATE SET expires_at=excluded.expires_at,cancelled_at=NULL,created_by=excluded.created_by`).bind(id,expiresAt,s.person_id,...guard.args),
  ]);
  if(!changed[1].meta.changes)await requireAuthority(ctx,s,guard);
  await auditDetail(ctx,s.person_id,'organization_invitation_created',id,{expiresAt});
  if(ctx.mail)await ctx.mail({to:address,subject:`Invitation to ${ctx.organization?.name??'Auth'}`,text:`Sign in to ${ctx.origin}${ctx.basePath??''}/signin to accept your invitation.`,html:'<p>You have an invitation to Auth. Follow the sign-in address in this message.</p>'});
  return json({id,expiresAt},201);
 }
 const p=await one(ctx,"SELECT id FROM oa_operators WHERE email=? AND status='invited'",address);if(!p)fail('invitation_unavailable',404);
 await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_org_invitations SET cancelled_at=? WHERE person_id=? AND ${guard.clause}`).bind(ctx.now(),p.id,...guard.args),
  ctx.db.prepare(`UPDATE oa_operators SET status='inactive' WHERE id=? AND status='invited' AND ${guard.clause}`).bind(p.id,...guard.args),
 ]);
 await requireAuthority(ctx,s,guard);await auditDetail(ctx,s.person_id,'organization_invitation_cancelled',p.id,{});
 return json({ok:true});
}
export async function invitationAdmitted(ctx,person) {
 if(person.status!=='invited')return true;
 const invitation=await one(ctx,'SELECT expires_at,cancelled_at FROM auth_org_invitations WHERE person_id=?',person.id);
 return !invitation||(invitation.cancelled_at===null&&invitation.expires_at>ctx.now());
}
