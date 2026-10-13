import {createLocalJWKSet,jwtVerify} from 'jose';
import {AuthError,json,one,sessionById,validateClientOrigin,EMAIL_MAX_AGE} from './core.mjs';
import {jwks,SIGNING_ALGORITHMS,TOKEN_SECONDS} from './keys.mjs';

function refusal(error='invalid_token',status=401) {
 return json({error},status,{'www-authenticate':`Bearer realm="userinfo"${error==='sign_in_required'?'':`, error="${error}"`}`});
}
async function bearer(request) {
 if(new URL(request.url).searchParams.has('access_token'))throw new AuthError('invalid_request',400);
 const header=request.headers.get('authorization');
 let bodyToken;
 if(request.method==='POST') {
  const text=await request.text();if(text.length>32768)throw new AuthError('invalid_request',400);
  if(text) {
   if(!(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded'))throw new AuthError('invalid_request',400);
   const form=new URLSearchParams(text);
   if(form.getAll('access_token').length>1)throw new AuthError('invalid_request',400);
   bodyToken=form.get('access_token');
  }
 }
 if(header&&bodyToken!==undefined&&bodyToken!==null)throw new AuthError('invalid_request',400);
 if(header) {
  const match=/^Bearer ([A-Za-z0-9._~-]+)$/i.exec(header);
  if(!match)throw new AuthError('invalid_token',401);
  return match[1];
 }
 if(!bodyToken)throw new AuthError('sign_in_required',401);
 return bodyToken;
}
export async function userinfo(ctx,request) {
 if(!['GET','POST'].includes(request.method))return json({error:'invalid_request'},405,{allow:'GET, POST'});
 let payload;
 try {
  const token=await bearer(request);
  if(token.length>16384)return refusal();
  ({payload}=await jwtVerify(token,createLocalJWKSet(await jwks(ctx)),{issuer:ctx.origin,audience:`${ctx.origin}/oidc/userinfo`,typ:'at+jwt',algorithms:SIGNING_ALGORITHMS,currentDate:new Date(ctx.now()),requiredClaims:['sub','client_id','sid','scope','jti','iat','exp']}));
 }catch(error) {return error instanceof AuthError?refusal(error.message,error.status):refusal();}
 const now=Math.floor(ctx.now()/1000);
 if(payload.aud!==`${ctx.origin}/oidc/userinfo`||!['sub','client_id','sid','scope','jti'].every(k=>typeof payload[k]==='string'&&payload[k].length>0)||!Number.isInteger(payload.iat)||!Number.isInteger(payload.exp)||payload.iat>now||payload.exp-payload.iat>TOKEN_SECONDS)return refusal();
 const scopes=payload.scope.split(' ');
 if(!scopes.includes('openid')||scopes.some(s=>!['openid','email','profile','claim'].includes(s)))return refusal();
 const client=await one(ctx,'SELECT * FROM auth_clients WHERE id=? AND disabled_at IS NULL',payload.client_id);
 if(!client)return refusal();
 try {validateClientOrigin(ctx,client.origin);}catch(error) {if(error instanceof AuthError)return refusal();throw error;}
 const s=await sessionById(ctx,request,payload.sid);
 if(!s)return refusal();
 const subject=await one(ctx,'SELECT subject FROM auth_subjects WHERE sector_id=? AND person_id=?',client.sector_id,s.person_id);
 const grant=await one(ctx,'SELECT person_id FROM auth_grants WHERE client_id=? AND person_id=?',client.id,s.person_id);
 const proof=await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',s.person_id);
 if(subject?.subject!==payload.sub||!grant||!proof||ctx.now()-proof.verified_at>EMAIL_MAX_AGE)return refusal();
 const claims={sub:payload.sub};
 if(scopes.includes('email'))Object.assign(claims,{email:s.email,email_verified:true,email_verified_at:Math.floor(proof.verified_at/1000)});
 if(scopes.includes('profile'))claims.name=s.display_name;
 return json(claims);
}
