import {all,one,fail,json,auditDetail,requireSession} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {seal,unseal} from '../keys.mjs';
import {createUpstreams} from '../upstreams.mjs';

export const EMPLOYER_PROVIDERS='/api/auth/organizations/providers';
const label=(ctx,id)=>'employer-provider:'+ctx.organizationId+':'+id;
export async function employerProviders(ctx) {
 if(!ctx.organizationId||ctx.organizationId==='root')return [];
 return Promise.all((await all(ctx,'SELECT provider_id,sealed_config FROM auth_employer_providers ORDER BY provider_id')).map(row=>unseal(ctx,label(ctx,row.provider_id),row.sealed_config)));
}
export async function configureEmployerProvider(ctx,request,data) {
 if(!ctx.organizationId||ctx.organizationId==='root')fail('employer_owner_required',403);
 const s=await requireSession(ctx,request,true);if(s.role!=='owner')fail('employer_owner_required',403);requireLocalEmail(ctx,s);
 const permitted=['id','label','preset','issuer','tenant','clientId','tokenAuthMethod','clientSecret','subjectEmails'];
 if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(key=>!permitted.includes(key))||!['google','microsoft','okta'].includes(data.preset))fail('invalid_provider_configuration');
 const existing=await one(ctx,'SELECT provider_id FROM auth_employer_providers WHERE provider_id=?',String(data.id));if(existing)fail('provider_already_registered',409);
 if((await all(ctx,'SELECT provider_id FROM auth_employer_providers')).length>=8)fail('provider_limit',409);
 const configuration={...data,redirectUri:ctx.origin+ctx.basePath+'/auth/oidc/'+data.id+'/callback'};
 try{createUpstreams({...ctx,upstreamProviders:[configuration]});}catch{fail('invalid_provider_configuration');}
 const guard=authority(ctx,s,['owner']),encrypted=await seal(ctx,label(ctx,data.id),configuration);
 const result=await ctx.db.prepare(`INSERT INTO auth_employer_providers(provider_id,sealed_config,created_by,created_at) SELECT ?,?,?,? WHERE ${guard.clause} AND (SELECT COUNT(*) FROM auth_employer_providers)<8`).bind(data.id,encrypted,s.person_id,ctx.now(),...guard.args).run();
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('provider_registration_changed',409);}
 await auditDetail(ctx,s.person_id,'employer_provider_registered',data.id,{preset:data.preset,callback:configuration.redirectUri});
 return json({id:data.id,preset:data.preset,callback:configuration.redirectUri},201);
}
