import {all,auditDetail,fail,hash,json,one,random,requireSession,run} from '../core.mjs';
import {genericClient,SCOPES} from '../oidc-apps/clients.mjs';
import {assignment} from '../workforce/directory.mjs';
import {decisionSnapshot,evaluate} from '../grants/decision.mjs';

export const profileFor=(ctx,clientId)=>one(ctx,'SELECT p.*,api.audience,api.policy,api.revision AS api_revision,c.app_id,a.version AS app_version FROM auth_refresh_profiles p JOIN auth_resource_apis api ON api.id=p.api_id JOIN auth_oidc_clients c ON c.client_id=p.client_id JOIN auth_apps a ON a.id=c.app_id WHERE p.client_id=? AND p.enabled=1 AND a.disabled_at IS NULL AND api.app_id=c.app_id',clientId);
export async function permittedScopes(ctx,profile,personId,scopes) {
 const snapshot=await decisionSnapshot(ctx,profile.api_id,personId),resources=JSON.parse(profile.policy).resources;
 return scopes.every(action=>resources.some(resource=>evaluate(ctx,snapshot,{apiId:profile.api_id,action,resource:resource.id}).allowed));
}
export async function offlineAuthorization(ctx,request,s,client) {
 const q=new URL(request.url).searchParams,profile=await profileFor(ctx,client.client_id);
 const refused=error=>{const u=new URL(q.get('redirect_uri'));u.searchParams.set('error',error);if(q.has('state'))u.searchParams.set('state',q.get('state'));u.searchParams.set('iss',ctx.issuer??ctx.origin);return new Response(null,{status:302,headers:{location:u.href,'cache-control':'no-store'}});};
 const scopes=[...new Set((q.get('scope')||'').split(' ').filter(Boolean))],apiScopes=scopes.filter(scope=>!SCOPES.includes(scope)&&scope!=='offline_access');
 if([...q.keys()].some(key=>q.getAll(key).length!==1))return refused('invalid_request');
 if(!profile||q.get('response_type')!=='code'||q.get('resource')!==profile.audience||!apiScopes.length||apiScopes.some(scope=>!JSON.parse(profile.scopes).includes(scope))||!await permittedScopes(ctx,profile,s.person_id,apiScopes))return refused('invalid_scope');
 if(q.get('code_challenge_method')!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(q.get('code_challenge')||'')||!/^[A-Za-z0-9_-]{43}$/.test(q.get('dpop_jkt')||'')||q.get('prompt')==='none')return refused('consent_required');
 const name=String(q.get('device_name')||'').trim();if(!name||name.length>120)return refused('invalid_request');
 const id=random();
 await run(ctx,`INSERT INTO auth_refresh_consents(id,client_id,person_id,session_id,person_version,profile_revision,api_revision,app_version,redirect_uri,challenge,nonce,state,scopes,api_scopes,jkt,device_name,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,id,client.client_id,s.person_id,s.id,s.person_version,profile.revision,profile.api_revision,profile.app_version,q.get('redirect_uri'),q.get('code_challenge'),q.get('nonce'),q.get('state'),JSON.stringify(scopes.filter(scope=>SCOPES.includes(scope))),JSON.stringify(apiScopes),q.get('dpop_jkt'),name,ctx.now(),ctx.now()+600000);
 return new Response(null,{status:302,headers:{location:`${ctx.basePath??''}/app/account?refreshConsent=${id}`,'cache-control':'no-store','referrer-policy':'no-referrer'}});
}
export async function consentView(ctx,s,id) {
 const row=await one(ctx,'SELECT * FROM auth_refresh_consents WHERE id=? AND person_id=? AND session_id=? AND expires_at>? AND decided_at IS NULL',id,s.person_id,s.id,ctx.now());
 if(!row)return null;
 const profile=await profileFor(ctx,row.client_id),client=await genericClient(ctx,row.client_id);
 if(!profile||!client)return null;
 return {id:row.id,appName:client.name,deviceName:row.device_name,audience:profile.audience,scopes:JSON.parse(row.api_scopes),identityScopes:JSON.parse(row.scopes),idleMs:profile.idle_ms,absoluteMs:profile.absolute_ms};
}
export async function decideConsent(ctx,request,data) {
 const s=await requireSession(ctx,request),row=await one(ctx,'SELECT * FROM auth_refresh_consents WHERE id=? AND person_id=? AND session_id=? AND expires_at>? AND decided_at IS NULL',String(data.id||''),s.person_id,s.id,ctx.now());
 if(!row||!['approve','deny'].includes(data.decision))fail('consent_expired_or_used',409);
 const profile=await profileFor(ctx,row.client_id),client=await genericClient(ctx,row.client_id);
 if(!profile||!client||profile.revision!==row.profile_revision||profile.api_revision!==row.api_revision||profile.app_version!==row.app_version||row.person_version!==s.person_version||!await assignment(ctx,client.app_id,s.person_id)||!await permittedScopes(ctx,profile,s.person_id,JSON.parse(row.api_scopes)))fail('consent_authority_changed',409);
 const code=random(),approved=data.decision==='approve',now=ctx.now();
 const results=await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_refresh_consents SET decided_at=?,approved_at=? WHERE id=? AND decided_at IS NULL AND expires_at>? AND EXISTS(SELECT 1 FROM auth_sessions live JOIN oa_operators p ON p.id=live.person_id WHERE live.id=? AND live.person_id=? AND live.person_version=p.version AND p.version=? AND p.status='active' AND live.revoked_at IS NULL AND live.expires_at>?)`).bind(now,approved?now:null,row.id,now,s.id,s.person_id,s.person_version,now),
  ...(approved?[ctx.db.prepare(`INSERT INTO auth_oidc_codes(code_hash,client_id,person_id,session_id,redirect_uri,challenge,nonce,scopes,expires_at,refresh_consent_id) SELECT ?,client_id,person_id,session_id,redirect_uri,challenge,nonce,scopes,?,id FROM auth_refresh_consents WHERE id=? AND changes()=1 AND approved_at=?`).bind(await hash(code),now+60000,row.id,now)]:[]),
 ]);
 if(!results[0].meta.changes)fail('consent_expired_or_used',409);
 await auditDetail(ctx,s.person_id,approved?'refresh_consent_approved':'refresh_consent_denied',row.id,{clientId:row.client_id,audience:profile.audience,scopes:JSON.parse(row.api_scopes)});
 const redirect=new URL(row.redirect_uri);redirect.searchParams.set(approved?'code':'error',approved?code:'access_denied');if(row.state!==null)redirect.searchParams.set('state',row.state);redirect.searchParams.set('iss',ctx.issuer??ctx.origin);
 return json({ok:true,redirect:redirect.href});
}
