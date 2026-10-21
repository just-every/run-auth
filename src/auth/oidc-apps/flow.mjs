import {invokeHooks} from '../hooks/index.mjs';
import {recheckIssuance} from '../hooks/fences.mjs';
// The general OIDC profile's authorization and token endpoints: the code flow
// for every client (PKCE required for public clients and where an app asks),
// and the implicit and hybrid flows only for an app that opted in.
import {random,hash,one,run,session,json,fail,audit,b64,utf8,EMAIL_MAX_AGE,AuthError} from '../core.mjs';
import {signToken,TOKEN_SECONDS} from '../keys.mjs';
import {beginAuthorizationLogin} from '../authorization-login.mjs';
import {assignment} from '../workforce/directory.mjs';
import {SCOPES,LEGACY_TYPES,authenticate,subjectFor,claimsFor,namedClient} from './clients.mjs';

const CODE_LIFETIME=60000;
const halfHash=async value=>b64(new Uint8Array(await crypto.subtle.digest('SHA-256',utf8.encode(value))).slice(0,16));
const noStore={'cache-control':'no-store','referrer-policy':'no-referrer'};

function respond(ctx,uri,mode,params) {
 const url=new URL(uri),values=new URLSearchParams();
 for(const [k,v] of Object.entries({...params,iss:(ctx.issuer??ctx.origin)}))if(v!==undefined&&v!==null)values.set(k,String(v));
 if(mode==='fragment')url.hash=values.toString();else for(const [k,v] of values)url.searchParams.set(k,v);
 return new Response(null,{status:302,headers:{location:url.href,...noStore}});
}

async function tokens(ctx,client,s,{scopes,nonce,code,withIdToken,withAccessToken}) {
 const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',s.person_id);
 const assigned=await assignment(ctx,client.app_id,s.person_id);
 if(!proof||ctx.now()-proof.verified_at>=EMAIL_MAX_AGE||!assigned)return null;
 const sub=await subjectFor(ctx,client,s.person_id),alg=client.id_token_alg,out={};
 const expiresAt=Math.min(Math.floor(ctx.now()/1000)+TOKEN_SECONDS,Math.floor(s.expires_at/1000),Math.floor((proof.verified_at+EMAIL_MAX_AGE)/1000));
 if(expiresAt<=Math.floor(ctx.now()/1000))return null;
 const mappedClaims=withIdToken?await claimsFor(ctx,client,s,scopes,assigned.role,proof.verified_at):{};
 const extension=withIdToken?await invokeHooks(ctx,'token',{personId:s.person_id,appId:client.app_id}):{claims:{}};
 await recheckIssuance(ctx,s,{appId:client.app_id,appVersion:client.app_version,mappingVersion:client.mapping_version,assignmentRole:assigned.role});
 if(withAccessToken)Object.assign(out,{access_token:await signToken(ctx,{aud:`${(ctx.issuer??ctx.origin)}/oidc/userinfo`,sub,client_id:client.client_id,sid:s.id,scope:scopes.join(' '),jti:random()},{alg,typ:'at+jwt',expiresAt}),token_type:'Bearer',expires_in:expiresAt-Math.floor(ctx.now()/1000)});
 if(withIdToken) {
  const claims={aud:client.client_id,sub,sid:s.id,auth_time:Math.floor(s.created_at/1000),amr:JSON.parse(s.amr),...(nonce?{nonce}:{}),...mappedClaims,...extension.claims};
  if(out.access_token)claims.at_hash=await halfHash(out.access_token);
  if(code)claims.c_hash=await halfHash(code);
  out.id_token=await signToken(ctx,claims,{alg,expiresAt:Math.floor(ctx.now()/1000)+TOKEN_SECONDS});
 }
 await run(ctx,'INSERT OR IGNORE INTO auth_oidc_sessions(session_id,client_id,created_at) VALUES(?,?,?)',s.id,client.client_id,ctx.now());
 return out;
}

export async function genericAuthorize(ctx,request,login,client) {
 const q=new URL(request.url).searchParams,uri=q.get('redirect_uri');
 // Client and callback are checked before anything is sent back to the callback.
 if(!client.redirectUris.includes(uri))fail('invalid_redirect_uri');
 const type=(q.get('response_type')||'').split(' ').filter(Boolean).sort().join(' ');
 const front=type!=='code',state=q.get('state')??undefined;
 const mode=q.get('response_mode')||(front?'fragment':'query');
 const error=(code,m=mode)=>respond(ctx,uri,['query','fragment'].includes(m)?m:front?'fragment':'query',{error:code,state});
 if(q.getAll('response_mode').length>1||!['query','fragment'].includes(mode)||(front&&mode==='query'))return error('invalid_request');
 if(state&&state.length>2048)return error('invalid_request');
 if(q.has('request'))return error('request_not_supported');
 if(q.has('request_uri'))return error('request_uri_not_supported');
 if(type!=='code'&&!LEGACY_TYPES.includes(type))return error('unsupported_response_type');
 if(front&&!client.legacy_flows)return error('unauthorized_client');
 const scopes=(q.get('scope')||'').split(' ').filter(Boolean);
 if(!scopes.includes('openid')||scopes.some(s=>!SCOPES.includes(s)))return error('invalid_scope');
 const nonce=q.get('nonce');if((type.includes('id_token')&&!nonce)||(nonce&&nonce.length>2048))return error('invalid_request');
 const challenge=q.get('code_challenge'),method=q.get('code_challenge_method');
 if(type.includes('code')) {
  if(challenge!==null&&(method!=='S256'||!/^[A-Za-z0-9_-]{43}$/.test(challenge)))return error('invalid_request');
  if(challenge===null&&client.require_pkce)return error('invalid_request');
 }
 const prompts=(q.get('prompt')||'').split(' ').filter(Boolean),age=q.get('max_age');
 if((prompts.includes('none')&&prompts.length!==1)||(age!==null&&!/^\d+$/.test(age)))return error('invalid_request');
 const s=await session(ctx,request),maxAge=age===null?null:Number(age);
 const fresh=s&&login&&s.id!==login.previousSessionId&&s.created_at>=login.startedAt;
 const tooOld=s&&maxAge!==null&&Math.floor(ctx.now()/1000)-Math.floor(s.created_at/1000)>maxAge;
 if(!s||(!fresh&&(prompts.includes('login')||maxAge===0))||tooOld) {
  if(prompts.includes('none'))return error('login_required');
  return beginAuthorizationLogin(ctx,request,s,Boolean(s));
 }
 if(!await assignment(ctx,client.app_id,s.person_id)){await audit(ctx,s.person_id,'oidc_refused_unassigned',client.app_id);return error('access_denied');}
 let code;
 if(type.includes('code')) {
  code=random();
  await run(ctx,'INSERT INTO auth_oidc_codes(code_hash,client_id,person_id,session_id,redirect_uri,challenge,nonce,scopes,expires_at) VALUES(?,?,?,?,?,?,?,?,?)',await hash(code),client.client_id,s.person_id,s.id,uri,challenge,nonce,JSON.stringify(scopes),ctx.now()+CODE_LIFETIME);
 }
 const issued=front?await tokens(ctx,client,s,{scopes,nonce,code,withIdToken:type.includes('id_token'),withAccessToken:type.split(' ').includes('token')}):{};
 if(!issued)return error('access_denied');
 await audit(ctx,s.person_id,'oidc_authorized',client.app_id);
 return respond(ctx,uri,mode,{code,...issued,state});
}

const oauthError=(error,status=400,headers={})=>json({error},status,{pragma:'no-cache',...headers});
// null: the request names no general client, so the RER profile handles it.
export async function genericToken(ctx,request) {
 if(!(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded'))return null;
 const text=await request.clone().text();if(text.length>32768)return null;
 const form=new URLSearchParams(text),client=await namedClient(ctx,request,form);
 if(!client)return null;
 try {await authenticate(ctx,request,form,client,[`${(ctx.issuer??ctx.origin)}/oidc/token`,(ctx.issuer??ctx.origin)]);}
 catch(error){if(error instanceof AuthError)return oauthError('invalid_client',401,client.auth_method==='client_secret_basic'?{'www-authenticate':'Basic realm="token"'}:{});throw error;}
 if(form.get('grant_type')!=='authorization_code')return oauthError('unsupported_grant_type');
 // One winner: the code is gone whatever happens next.
 const code=await one(ctx,'DELETE FROM auth_oidc_codes WHERE code_hash=? AND client_id=? AND expires_at>? RETURNING *',await hash(form.get('code')||''),client.client_id,ctx.now());
 if(!code||code.redirect_uri!==form.get('redirect_uri'))return oauthError('invalid_grant');
 const verifier=form.get('code_verifier');
 if(code.challenge?!/^[A-Za-z0-9._~-]{43,128}$/.test(verifier||'')||code.challenge!==await hash(verifier):verifier!==null)return oauthError('invalid_grant');
 const s=await one(ctx,"SELECT s.*,p.email,p.display_name FROM auth_sessions s JOIN oa_operators p ON p.id=s.person_id WHERE s.id=? AND s.revoked_at IS NULL AND s.expires_at>? AND p.status='active' AND p.version=s.person_version",code.session_id,ctx.now());
 if(!s||JSON.parse(s.amr).includes('dev')&&!ctx.local)return oauthError('invalid_grant');
 const scopes=JSON.parse(code.scopes),issued=await tokens(ctx,client,s,{scopes,nonce:code.nonce,withIdToken:true,withAccessToken:true});
 if(!issued)return oauthError('invalid_grant');
 await audit(ctx,code.person_id,'id_token_issued',client.app_id);
 return json({...issued,scope:scopes.join(' ')},200,{pragma:'no-cache'});
}
