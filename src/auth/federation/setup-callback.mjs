import {AuthError,cookie,scopedCookieName,hash,one,fail,json} from '../core.mjs';
import {authority,requireAuthority} from '../local-email.mjs';
import {createFederationOidc} from './oidc.mjs';
import {createFederationSaml,readSamlInput} from './saml.mjs';
import {setupVerifierDatabase} from './setup-store.mjs';
import {setupById,setupConfiguration,setupOwner,requireSetupCreator,mappingPreview,mappingGuard} from './setup-state.mjs';

const RANDOM=/^[A-Za-z0-9_-]{43}$/;
const setupCookieName=(ctx,id)=>scopedCookieName(ctx,(ctx.local?'auth_federation_setup_':'__Host-auth_federation_setup_')+id);
export const setupCookie=(ctx,providerId,value,age=600)=>cookie(ctx,setupCookieName(ctx,providerId),value,age);
function setupBinding(ctx,request,providerId,{optional=false}={}) {
 const prefix=setupCookieName(ctx,providerId)+'=';
 const matches=(request.headers.get('cookie')??'').split(';').map(v=>v.trim()).filter(v=>v.startsWith(prefix));
 if(!matches.length&&optional)return null;
 if(matches.length!==1)fail('federation_setup_binding_required',403);
 const pieces=matches[0].slice(prefix.length).split('.');
 if(pieces.length!==2||pieces.some(v=>!RANDOM.test(v)))fail('federation_setup_binding_required',403);
 return {id:pieces[0],raw:pieces[1]};
}
async function ownerBinding(ctx,request,row) {
 const owner=await setupOwner(ctx,request),binding=setupBinding(ctx,request,row.provider_id);
 requireSetupCreator(row,owner);
 if(row.state!=='testing'||row.test_until<=ctx.now()||row.test_session_id!==owner.id||binding.id!==row.id||row.test_binding_hash!==await hash(binding.raw))fail('federation_setup_binding_required',403);
 return owner;
}
function protocol(ctx,row,provider,admission) {
 const config={...provider,federationSetupId:row.id};
 return provider.preset==='saml'?createFederationSaml({...ctx,federationSetupId:row.id},{providers:[config],admission}):createFederationOidc({...ctx,db:setupVerifierDatabase(ctx.db,row.id),secret:ctx.secret+'-federation-test-'+row.id},{providers:[config],admission});
}
// This admission deliberately only records a representative subject. No account,
// external identity, local email proof, upstream proof or session is created.
async function recordTest(ctx,request,row,provider,principal) {
 const owner=await ownerBinding(ctx,request,row);
 if(principal.provider!==row.provider_id||principal.issuer!==provider.issuer||principal.subject!==row.test_subject||!Object.hasOwn(provider.subjectEmails,principal.subject)||principal.associatedEmail!==provider.subjectEmails[principal.subject])fail('federation_representative_mismatch',403);
 const people=await mappingPreview(ctx,row.domain,provider),mapping=mappingGuard(ctx,row.domain,provider,people),guard=authority(ctx,owner,['owner']);
 const changed=await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_federation_setups SET state='tested',tested_subject=?,tested_at=?,test_binding_hash=NULL,test_until=NULL,revision=revision+1 WHERE id=? AND state='testing' AND revision=? AND test_session_id=? AND test_binding_hash=? AND test_until>? AND ${guard.clause} AND ${mapping.clause}`)
   .bind(principal.subject,ctx.now(),row.id,row.revision,owner.id,row.test_binding_hash,ctx.now(),...guard.args,...mapping.args),
  ctx.db.prepare("INSERT INTO auth_activity(actor_id,event,subject_id,created_at) SELECT ?,'federation_representative_tested',?,? WHERE changes()=1").bind(owner.person_id,row.id,ctx.now()),
  ctx.db.prepare('INSERT INTO auth_activity_details(activity_id,detail) SELECT last_insert_rowid(),? WHERE changes()=1').bind(JSON.stringify({providerId:row.provider_id,configurationHash:row.config_hash,subject:principal.subject})),
 ]);
 if(!changed[0].meta.changes){await requireAuthority(ctx,owner,guard);fail('federation_setup_changed',409);}
 return {returnTo:(ctx.basePath??'')+'/app/move-in?federation='+encodeURIComponent(row.id),cookie:setupCookie(ctx,row.provider_id,'',0)};
}
export async function beginSetupTest(ctx,request,row,provider,browser) {
 const path=provider.preset==='saml'?`/auth/saml/${provider.id}/start`:`/auth/oidc/${provider.id}/start`;
 const started=new Request(ctx.origin+path,{method:'POST',headers:{origin:ctx.origin,'content-type':'application/json','cf-connecting-ip':request.headers.get('cf-connecting-ip')??'',cookie:request.headers.get('cookie')??''},body:JSON.stringify({returnTo:'/app/move-in'})});
 const response=await protocol(ctx,row,provider,{admit:()=>fail('federation_test_start_only',403)}).fetch(started);
 if(!response)fail('federation_test_unavailable',503);
 const headers=new Headers(response.headers);
 if([302,303].includes(response.status))headers.append('set-cookie',setupCookie(ctx,row.provider_id,row.id+'.'+browser));
 return new Response(response.body,{status:response.status,headers});
}
export async function federationSetupRoute(ctx,request) {
 const url=new URL(request.url);let path=url.pathname;
 if(ctx.basePath&&path.startsWith(ctx.basePath+'/'))path=path.slice(ctx.basePath.length);
 const route=/^\/auth\/(oidc|saml)\/([a-z][a-z0-9-]{0,31})\/(callback|resume|metadata)$/.exec(path);
 if(!route)return null;
 try {
  if(url.origin!==ctx.origin)fail('wrong_issuer',403);
  let row;
  if(route[1]==='saml'&&route[3]==='callback'&&request.method==='POST') {
   // A cross-site POST has no owner Lax cookie. Choose only the exact setup
   // recorded by the correlated transaction; signature and POST cookie are
   // checked by the canonical SAML handler before any principal is parked.
   const form=new URLSearchParams(await readSamlInput(request.clone(),360000)),relay=form.get('RelayState');
   if(form.getAll('RelayState').length!==1||!RANDOM.test(relay??''))return null;
   row=await one(ctx,"SELECT s.* FROM auth_federation_transactions t JOIN auth_federation_setups s ON s.id=t.setup_id WHERE t.id=? AND t.provider_id=? AND t.configuration_hash=s.config_hash AND s.state='testing' AND s.test_until>? AND t.expires_at>?",await hash(relay),route[2],ctx.now(),ctx.now());
   if(!row)return null;
  } else if(route[1]==='saml'&&route[3]==='metadata'&&url.searchParams.has('setup')) {
   await setupOwner(ctx,request);row=await setupById(ctx,url.searchParams.get('setup'));
   if(!['draft','testing','tested','active'].includes(row.state)||row.provider_id!==route[2])fail('federation_setup_changed',409);
  } else {
   const binding=setupBinding(ctx,request,route[2],{optional:true});
   if(!binding)return null;
   row=await setupById(ctx,binding.id);
   if(row.provider_id!==route[2])fail('federation_setup_binding_required',403);
   await ownerBinding(ctx,request,row);
  }
  const provider=await setupConfiguration(ctx,row);
  if((provider.preset==='saml')!==(route[1]==='saml'))fail('federation_setup_binding_required',403);
  const runtime=protocol(ctx,row,provider,{admit:(req,principal)=>recordTest(ctx,req,row,provider,principal)});
  return await runtime.fetch(request);
 }catch(error){return json({error:error instanceof AuthError?error.message:'federation_setup_unavailable'},error instanceof AuthError?error.status:503);}
}
