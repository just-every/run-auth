import {generateAuthenticationOptions,verifyAuthenticationResponse} from '@simplewebauthn/server';
import {all,one,random,hash,requireSession,fail,json,challenge,consumeChallenge,cookies,cookie,scopedCookieName,unb64} from '../core.mjs';
import {personSessionGuard,both} from '../agents/delegation/common.mjs';
import {organizationContext} from '../tenancy/context.mjs';

export const PAIRS_PREFIX='/api/auth/identity-pairs';
export const isPairPath=path=>path===PAIRS_PREFIX||path.startsWith(PAIRS_PREFIX+'/');
const binding=ctx=>scopedCookieName(ctx,ctx.local?'auth_identity_pair':'__Host-auth_identity_pair');
const prefix=id=>{if(!/^[a-f0-9]{32}$/.test(id))fail('organization_unavailable',404);return 'org_'+id+'_';};
const namespaceGuard=(guard,id)=>({clause:guard.clause.replace(/\b(auth_sessions|oa_operators)\b/g,name=>prefix(id)+name),args:guard.args});
const rootOnly=ctx=>{if(ctx.organizationId!=='root')fail('installation_identity_required',403);};
const passkey=async(ctx,request)=>{const s=await requireSession(ctx,request);if(!JSON.parse(s.amr).includes('hwk'))fail('independent_passkey_required',403);return s;};
async function bothSessions(ctx,request,organizationId) {
 rootOnly(ctx);prefix(organizationId);
 const root=await passkey(ctx,request),employer=await organizationContext({...ctx,db:ctx.rootDb??ctx.db},organizationId);
 const member=await passkey(employer,request);
 return {root,employer,member};
}
const held=async(ctx,guard)=>{if(!await one(ctx,`SELECT 1 WHERE ${guard.clause}`,...guard.args))fail('identity_pair_authority_changed',403);};
const pairGuard=(ctx,root,employer,member)=>both(personSessionGuard(ctx,root),namespaceGuard(personSessionGuard(employer,member),employer.organizationId),{clause:"EXISTS(SELECT 1 FROM auth_organizations WHERE id=? AND status='active')",args:[employer.organizationId]});
const exact=(data,keys)=>{if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(key=>!keys.includes(key))||keys.some(key=>!Object.hasOwn(data,key)))fail('invalid_identity_pair_request');};
async function options(ctx,s) {
 const keys=await all(ctx,'SELECT id,transports FROM auth_passkeys WHERE person_id=?',s.person_id);
 if(!keys.length)fail('passkey_required',403);
 return generateAuthenticationOptions({rpID:new URL(ctx.origin).hostname,userVerification:'required',allowCredentials:keys.map(key=>({id:key.id,transports:JSON.parse(key.transports)}))});
}
async function verified(ctx,s,response,expectedChallenge) {
 const key=await one(ctx,'SELECT * FROM auth_passkeys WHERE id=? AND person_id=?',String(response?.id??''),s.person_id)||fail('invalid_passkey');
 let checked;try{checked=await verifyAuthenticationResponse({response,expectedChallenge,expectedOrigin:ctx.origin,expectedRPID:new URL(ctx.origin).hostname,requireUserVerification:true,credential:{id:key.id,publicKey:unb64(key.public_key),counter:key.counter,transports:JSON.parse(key.transports)}});}catch{fail('invalid_passkey');}
 if(!checked.verified)fail('invalid_passkey');
 return {key,counter:checked.authenticationInfo.newCounter};
}
export async function pairModel(ctx,request) {
 rootOnly(ctx);const s=await requireSession(ctx,request);
 const links=await all(ctx,"SELECT p.handle,p.organization_id AS organizationId,o.name AS organizationName,p.created_at AS createdAt FROM auth_identity_pairs p JOIN auth_organizations o ON o.id=p.organization_id AND o.status='active' WHERE p.person_id=? ORDER BY p.created_at,p.handle",s.person_id);
 return {links,authorityTransferred:false};
}
export async function pairAction(ctx,request,path,data) {
 rootOnly(ctx);
 if(path===PAIRS_PREFIX+'/options') {
  exact(data,['organizationId']);const {root,employer,member}=await bothSessions(ctx,request,data.organizationId),guard=pairGuard(ctx,root,employer,member);
  const rootOptions=await options(ctx,root),memberOptions=await options(employer,member),browser=random();
  const transaction=await challenge(ctx,'identity-pair',root.person_id,await hash(browser),{organizationId:employer.organizationId,rootSessionId:root.id,memberSessionId:member.id,memberId:member.person_id,rootChallenge:rootOptions.challenge,memberChallenge:memberOptions.challenge},300000,guard);
  if(!transaction){await held(ctx,guard);fail('identity_pair_changed',409);}
  return json({transaction,rootOptions,memberOptions,organizationName:employer.organization.name,confirmation:'Link only for erasure notices; no proof or authority transfers.'},200,{'set-cookie':cookie(ctx,binding(ctx),browser,300)});
 }
 if(path===PAIRS_PREFIX+'/confirm') {
  exact(data,['transaction','rootResponse','memberResponse','confirm']);if(data.confirm!==true)fail('explicit_pair_consent_required',403);
  const browser=cookies(request)[binding(ctx)],tx=await consumeChallenge(ctx,data.transaction,'identity-pair',browser?await hash(browser):null);
  const {root,employer,member}=await bothSessions(ctx,request,tx.payload.organizationId);
  if(tx.person_id!==root.person_id||tx.payload.rootSessionId!==root.id||tx.payload.memberSessionId!==member.id||tx.payload.memberId!==member.person_id)fail('identity_pair_session_changed',403);
  const a=await verified(ctx,root,data.rootResponse,tx.payload.rootChallenge),b=await verified(employer,member,data.memberResponse,tx.payload.memberChallenge),ns=prefix(employer.organizationId);
  const handle=random(),operation=random(),guard=both(pairGuard(ctx,root,employer,member),{
   clause:`EXISTS(SELECT 1 FROM auth_passkeys WHERE id=? AND person_id=? AND counter=?) AND EXISTS(SELECT 1 FROM ${ns}auth_passkeys WHERE id=? AND person_id=? AND counter=?) AND NOT EXISTS(SELECT 1 FROM auth_identity_pairs rp JOIN ${ns}auth_identity_pairs mp ON mp.handle=rp.handle WHERE rp.person_id=? AND rp.organization_id=? AND mp.person_id=?)`,args:[a.key.id,root.person_id,a.key.counter,b.key.id,member.person_id,b.key.counter,root.person_id,employer.organizationId,member.person_id],
  }),marker='EXISTS(SELECT 1 FROM auth_admin_api_commits WHERE id=?)';
  const result=await ctx.db.batch([
   ctx.db.prepare(`INSERT INTO auth_admin_api_commits(id) SELECT ? WHERE ${guard.clause}`).bind(operation,...guard.args),
   ctx.db.prepare(`UPDATE auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND ${marker}`).bind(a.counter,ctx.now(),a.key.id,operation),
   ctx.db.prepare(`UPDATE ${ns}auth_passkeys SET counter=?,last_used_at=? WHERE id=? AND ${marker}`).bind(b.counter,ctx.now(),b.key.id,operation),
   ctx.db.prepare(`INSERT INTO auth_identity_pairs(handle,person_id,organization_id,created_at) SELECT ?,?,?,? WHERE ${marker}`).bind(handle,root.person_id,employer.organizationId,ctx.now(),operation),
   ctx.db.prepare(`INSERT INTO ${ns}auth_identity_pairs(handle,person_id,organization_id,created_at) SELECT ?,?,?,? WHERE ${marker}`).bind(handle,member.person_id,employer.organizationId,ctx.now(),operation),
   ctx.db.prepare('DELETE FROM auth_admin_api_commits WHERE id=?').bind(operation),
  ]);
  if(!result[0].meta.changes){await held(ctx,guard);fail('identity_pair_changed',409);}
  return json({handle,organizationId:employer.organizationId,authorityTransferred:false},201,{'set-cookie':cookie(ctx,binding(ctx),'',0)});
 }
 if(path===PAIRS_PREFIX+'/remove') {
  exact(data,['handle']);const s=await passkey(ctx,request),pair=await one(ctx,'SELECT * FROM auth_identity_pairs WHERE handle=? AND person_id=?',data.handle,s.person_id)||fail('identity_pair_unavailable',404);
  const guard=personSessionGuard(ctx,s),ns=prefix(pair.organization_id),marker='EXISTS(SELECT 1 FROM auth_identity_pairs WHERE handle=? AND person_id=?)';await held(ctx,guard);
  await ctx.db.batch([
   ctx.db.prepare(`DELETE FROM ${ns}auth_identity_pairs WHERE handle=? AND ${marker} AND ${guard.clause}`).bind(pair.handle,pair.handle,s.person_id,...guard.args),
   ctx.db.prepare(`DELETE FROM auth_identity_pairs WHERE handle=? AND person_id=? AND ${guard.clause}`).bind(pair.handle,s.person_id,...guard.args),
  ]);
  await held(ctx,guard);return json({removed:true});
 }
 fail('not_found',404);
}
