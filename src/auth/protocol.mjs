import {permitsSession} from './domain-policy.mjs';
import {beginAuthorizationLogin,authorizationLogin,completedAuthorizationLogin} from './authorization-login.mjs';
import {createLocalJWKSet,jwtVerify} from 'jose';
import {AuthError,random,hash,one,run,session,json,fail,validateClientOrigin,EMAIL_MAX_AGE,audit,b64,utf8} from './core.mjs';
import {signToken,pairwiseSubject,activeSigningKey,TOKEN_SECONDS,SIGNING_ALGORITHMS} from './keys.mjs';
import {genericClient,LEGACY_TYPES,METHODS} from './oidc-apps/clients.mjs';
import {genericAuthorize} from './oidc-apps/flow.mjs';
export function discovery(ctx) {return {issuer:ctx.origin,rer_interfaces:['oidc-provider@1.0.0'],authorization_endpoint:`${ctx.origin}/oidc/authorize`,token_endpoint:`${ctx.origin}/oidc/token`,userinfo_endpoint:`${ctx.origin}/oidc/userinfo`,jwks_uri:`${ctx.origin}/oidc/jwks`,response_types_supported:['code',...LEGACY_TYPES],response_modes_supported:['query','fragment'],grant_types_supported:['authorization_code','implicit'],subject_types_supported:['pairwise','public'],id_token_signing_alg_values_supported:SIGNING_ALGORITHMS,token_endpoint_auth_methods_supported:['private_key_jwt',...METHODS.filter(m=>m!=='private_key_jwt')],token_endpoint_auth_signing_alg_values_supported:['ES256','RS256'],scopes_supported:['openid','email','profile','claim','groups'],claims_supported:['iss','sub','aud','iat','exp','nonce','auth_time','email','email_verified','email_verified_at','name','sid','amr','install_owner','groups','at_hash','c_hash'],frontchannel_logout_supported:true,frontchannel_logout_session_supported:true,code_challenge_methods_supported:['S256'],authorization_response_iss_parameter_supported:true,request_parameter_supported:false,request_uri_parameter_supported:false,end_session_endpoint:`${ctx.origin}/oidc/logout`,backchannel_logout_supported:true,backchannel_logout_session_supported:true};}
async function client(ctx,id) {
 const c=await one(ctx,'SELECT * FROM auth_clients WHERE id=? AND disabled_at IS NULL',id||'');if(!c)fail('invalid_client',400);validateClientOrigin(ctx,c.origin);return c;
}
function redirect(c,uri) {if(!JSON.parse(c.redirect_uris).includes(uri))fail('invalid_redirect_uri');const u=new URL(uri);if(u.origin!==c.origin ||u.hash ||u.username||u.password)fail('invalid_redirect_uri');return u;}
function oauthRedirect(ctx,url,params) {for(const [k,v] of Object.entries({...params,iss:ctx.origin}))url.searchParams.set(k,v);return new Response(null,{status:302,headers:{location:url.href,'cache-control':'no-store','referrer-policy':'no-referrer'}});}
export async function resumeAuthorization(ctx,request) {
 const login=await authorizationLogin(ctx,request);
 const response=await authorize(ctx,login.request,login.proof);
 if(response.status===302)response.headers.append('set-cookie',completedAuthorizationLogin(ctx));
 return response;
}
// RER registrations keep this strict profile. Discovery also lists what the
// general SaaS profile (oidc-apps/) offers its own registered clients only.
export async function authorize(ctx,request,login=null) {
 const generic=await genericClient(ctx,new URL(request.url).searchParams.get('client_id'));
 if(generic)return genericAuthorize(ctx,request,login,generic);
 const q=new URL(request.url).searchParams,c=await client(ctx,q.get('client_id')),uri=redirect(c,q.get('redirect_uri'));
 const state=q.get('state'),nonce=q.get('nonce'),scopes=(q.get('scope')||'').split(' ').filter(Boolean),pkce=q.get('code_challenge');
 if(state?.length>2048)fail('invalid_authorization_request');
 const error=code=>oauthRedirect(ctx,uri,{error:code,...(state===null?{}:{state})});
 // Validate the client and callback before any redirected error; do not fetch
 // request_uri or interpret a request object that this profile does not support.
 if(q.has('request'))return error('request_not_supported');
 if(q.has('request_uri'))return error('request_uri_not_supported');
 // Only the query response mode is advertised; never answer another mode in the query.
 if(q.getAll('response_mode').some(mode=>mode!=='query'))return error('invalid_request');
 if(!state||!nonce||nonce.length>2048||q.get('response_type')!=='code'||q.get('code_challenge_method')!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(pkce||'')||!scopes.includes('openid')||scopes.some(s=>!['openid','email','profile','claim'].includes(s)))fail('invalid_authorization_request');
 const prompts=(q.get('prompt')||'').split(' ').filter(Boolean),age=q.get('max_age');
 if(q.getAll('prompt').length>1||q.getAll('max_age').length>1||
  (prompts.includes('none')&&prompts.length!==1)||
  (age!==null&&(!/^\d+$/.test(age)||!Number.isSafeInteger(Number(age)))))return error('invalid_request');
 const maxAge=age===null?null:Number(age),s=await session(ctx,request);
 const freshlyAuthenticated=s&&login&&s.id!==login.previousSessionId&&s.created_at>=login.startedAt&&
  (!login.reauthenticate||JSON.parse(s.amr).some(method=>['email','hwk'].includes(method)));
 const authenticationAge=s?Math.floor(ctx.now()/1000)-Math.floor(s.created_at/1000):Infinity;
 const reauthenticate=Boolean(login?.reauthenticate)||prompts.includes('login')||maxAge===0||(maxAge!==null&&maxAge>0&&authenticationAge>maxAge);
 const needsLogin=!s||(!freshlyAuthenticated&&(login?.reauthenticate||prompts.includes('login')||maxAge===0))||
  (maxAge!==null&&maxAge>0&&authenticationAge>maxAge);
 if(needsLogin) {
  if(prompts.includes('none'))return error('login_required');
  return beginAuthorizationLogin(ctx,request,s,reauthenticate);
 }
 const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',s.person_id);
 if(!proof||ctx.now()-proof.verified_at>=EMAIL_MAX_AGE) {
  if(prompts.includes('none'))return error('login_required');
  return beginAuthorizationLogin(ctx,request,s);
 }
 await activeSigningKey(ctx,c.id_token_signed_response_alg);
 const code=random();await run(ctx,'INSERT INTO auth_codes(code_hash,client_id,person_id,session_id,redirect_uri,challenge,nonce,scopes,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',await hash(code),c.id,s.person_id,s.id,uri.href,pkce,nonce,JSON.stringify(scopes),ctx.now()+60000);
 await run(ctx,'INSERT OR IGNORE INTO auth_grants(client_id,person_id,created_at) VALUES(?,?,?)',c.id,s.person_id,ctx.now());
 return oauthRedirect(ctx,uri,{code,state});
}
export async function token(ctx,request) {
 if(!(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded'))fail('invalid_request');
 const text=await request.text();if(text.length>32768)fail('invalid_request');const p=new URLSearchParams(text);
 if(request.headers.has('authorization')||p.has('client_secret')||p.get('grant_type')!=='authorization_code'||p.get('client_assertion_type')!=='urn:ietf:params:oauth:client-assertion-type:jwt-bearer')fail('invalid_client',401);
 // Every client authentication failure answers alike, whichever part failed.
 const c=await client(ctx,p.get('client_id')).catch(error=>{throw error instanceof AuthError?new AuthError('invalid_client',401):error;});let assertion;
 try {({payload:assertion}=await jwtVerify(p.get('client_assertion')||'',createLocalJWKSet(JSON.parse(c.jwks)),{issuer:c.id,subject:c.id,audience:`${ctx.origin}/oidc/token`,algorithms:['ES256'],currentDate:new Date(ctx.now()),requiredClaims:['exp','iat','jti']}));}catch{fail('invalid_client',401);}
 const sec=Math.floor(ctx.now()/1000);if(typeof assertion.jti!=='string'||assertion.jti.length>256||!assertion.jti||typeof assertion.iat!=='number'||typeof assertion.exp!=='number'||assertion.iat>sec+30||assertion.exp>sec+300||assertion.exp-assertion.iat>300||assertion.iat<sec-300)fail('invalid_client',401);
 try {await run(ctx,'INSERT INTO auth_assertions(client_id,jti,expires_at) VALUES(?,?,?)',c.id,assertion.jti,assertion.exp*1000);}catch{fail('invalid_client',401);}
 const verifier=p.get('code_verifier')||'';if(!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier))fail('invalid_grant');
 const code=await one(ctx,'SELECT * FROM auth_codes WHERE code_hash=? AND client_id=? AND expires_at>? AND consumed_at IS NULL',await hash(p.get('code')||''),c.id,ctx.now());
 if(!code||code.redirect_uri!==p.get('redirect_uri')||code.challenge!==await hash(verifier))fail('invalid_grant');
 redirect(c,code.redirect_uri);
 const s=await one(ctx,"SELECT s.*,p.email,p.display_name,p.status,p.version,p.role FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id WHERE s.id=? AND s.revoked_at IS NULL AND s.expires_at>? AND p.status='active' AND p.version=s.person_version",code.session_id,ctx.now());
 const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',code.person_id);if(!s||!proof||ctx.now()-proof.verified_at>=EMAIL_MAX_AGE||(!ctx.local&&JSON.parse(s.amr).includes('dev')))fail('invalid_grant');
 if(!await permitsSession(ctx,s))fail('invalid_grant');
 await activeSigningKey(ctx,c.id_token_signed_response_alg);
 const consumed=await one(ctx,'DELETE FROM auth_codes WHERE code_hash=? AND consumed_at IS NULL RETURNING code_hash',code.code_hash);if(!consumed)fail('invalid_grant');
 const scopes=JSON.parse(code.scopes),claims={aud:c.id,sub:await pairwiseSubject(ctx,c.sector_id,code.person_id),nonce:code.nonce,sid:s.id,amr:ctx.local?['dev']:JSON.parse(s.amr),auth_time:Math.floor(s.created_at/1000),email_verified_at:Math.floor(proof.verified_at/1000)};
 if(scopes.includes('email'))Object.assign(claims,{email:s.email,email_verified:true});if(scopes.includes('profile'))claims.name=s.display_name;
 if(scopes.includes('claim')) {const owner=await one(ctx,'UPDATE auth_clients SET owner_claimed_at=? WHERE id=? AND owner_person_id=? AND owner_claimed_at IS NULL RETURNING id',ctx.now(),c.id,code.person_id);if(owner)claims.install_owner=true;}
 const expiresAt=Math.min(Math.floor(ctx.now()/1000)+TOKEN_SECONDS,Math.floor(s.expires_at/1000),Math.floor((proof.verified_at+EMAIL_MAX_AGE)/1000));
 if(expiresAt<=Math.floor(ctx.now()/1000))fail('invalid_grant');
 const alg=c.id_token_signed_response_alg;
 const access_token=await signToken(ctx,{aud:`${ctx.origin}/oidc/userinfo`,sub:claims.sub,client_id:c.id,sid:s.id,scope:scopes.join(' '),jti:random()},{alg,typ:'at+jwt',expiresAt});
 claims.at_hash=b64(new Uint8Array(await crypto.subtle.digest('SHA-256',utf8.encode(access_token))).slice(0,16));
 const id_token=await signToken(ctx,claims,{alg});await audit(ctx,code.person_id,'id_token_issued',c.id);
 await run(ctx,'INSERT OR IGNORE INTO auth_session_clients(session_id,client_id) VALUES(?,?)',s.id,c.id);return json({id_token,access_token,token_type:'Bearer',expires_in:expiresAt-Math.floor(ctx.now()/1000),scope:scopes.join(' ')},200,{pragma:'no-cache'});
}
