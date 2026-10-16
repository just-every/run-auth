// General OpenID Connect clients for company SaaS, web and native apps. They
// never share code, client or key paths with RER registrations, which keep the
// strict private_key_jwt and mandatory PKCE profile in protocol.mjs.
import {createLocalJWKSet,jwtVerify,decodeJwt} from 'jose';
import {random,hash,one,run,fail,isLoopback,AuthError} from '../core.mjs';
import {pairwiseSubject} from '../keys.mjs';
import {groupNames} from '../workforce/directory.mjs';

export const METHODS=['client_secret_basic','client_secret_post','private_key_jwt','none'];
export const SCOPES=['openid','email','profile','groups'];
export const LEGACY_TYPES=['id_token','id_token token','code id_token','code token','code id_token token'];
const SECRET_OVERLAP_MAX=7*86400000;
const flag=v=>v===true||v==='true'||v==='on'||v==='1'||v===1;

// https, loopback http for a local install, or a native app's private-use
// scheme (reverse domain, RFC 8252) for a public client.
function redirect(ctx,value,publicClient) {
 let url;try{url=new URL(String(value||'').trim());}catch{fail('invalid_redirect_uri');}
 if(url.hash||url.username||url.password)fail('invalid_redirect_uri');
 if(url.protocol==='https:'&&!(isLoopback(url.hostname)&&!ctx.local))return url.href;
 if(url.protocol==='http:'&&(ctx.local||publicClient)&&isLoopback(url.hostname))return url.href;
 if(publicClient&&/^[a-z][a-z0-9+.-]*\.[a-z0-9+.-]+:$/.test(url.protocol))return url.href;
 fail('invalid_redirect_uri');
}
const list=value=>(Array.isArray(value)?value:String(value||'').split(/\s+|,/)).map(v=>String(v).trim()).filter(Boolean);

export function clientSettings(ctx,data) {
 const authMethod=data.authMethod||'client_secret_basic';if(!METHODS.includes(authMethod))fail('invalid_auth_method');
 const publicClient=authMethod==='none';
 const redirectUris=[...new Set(list(data.redirectUris).map(u=>redirect(ctx,u,publicClient)))];
 if(!redirectUris.length||redirectUris.length>20)fail('invalid_redirect_uri');
 const postLogout=[...new Set(list(data.postLogoutRedirectUris).map(u=>redirect(ctx,u,publicClient)))];
 let jwks=null;
 if(authMethod==='private_key_jwt') {
  try{jwks=typeof data.jwks==='string'?JSON.parse(data.jwks):data.jwks;}catch{fail('invalid_jwks');}
  if(!Array.isArray(jwks?.keys)||!jwks.keys.length||jwks.keys.length>5||jwks.keys.some(k=>k.d||!['EC','RSA'].includes(k.kty)))fail('invalid_jwks');
  jwks={keys:jwks.keys};
 }
 const channel=value=>value?redirect(ctx,value,false):null;
 const subjectType=data.subjectType==='public'?'public':'pairwise',alg=data.idTokenAlg==='ES256'?'ES256':'RS256';
 return {authMethod,redirectUris,postLogout,jwks,requirePkce:publicClient||flag(data.requirePkce),subjectType,legacyFlows:flag(data.legacyFlows),frontchannel:channel(data.frontchannelLogoutUri),backchannel:channel(data.backchannelLogoutUri),alg};
}

// A new secret: 256 random bits, shown once; only its digest is stored.
export async function newSecret(ctx,clientId) {
 const secret=random();
 return {secret,statement:ctx.db.prepare('INSERT INTO auth_oidc_secrets(id,client_id,secret_hash,created_at) VALUES(?,?,?,?)').bind(random(),clientId,await hash(secret),ctx.now())};
}
export const overlapOf=hours=>{const ms=Math.round(Number(hours??24)*3600000);if(!Number.isFinite(ms)||ms<0||ms>SECRET_OVERLAP_MAX)fail('invalid_overlap');return ms;};

const COLUMNS='c.*,a.name,a.attributes,a.disabled_at';
export async function genericClient(ctx,clientId) {
 if(typeof clientId!=='string'||!clientId)return null;
 const row=await one(ctx,`SELECT ${COLUMNS} FROM auth_oidc_clients c JOIN auth_apps a ON a.id=c.app_id WHERE c.client_id=? AND a.disabled_at IS NULL`,clientId);
 return row&&{...row,redirectUris:JSON.parse(row.redirect_uris),postLogout:JSON.parse(row.post_logout_redirect_uris),attributes:JSON.parse(row.attributes)};
}

const basic=request=>{
 const header=request.headers.get('authorization');if(!header)return null;
 const m=/^Basic ([A-Za-z0-9+/=]+)$/i.exec(header);if(!m)return {invalid:true};
 let text;try{text=atob(m[1]);}catch{return {invalid:true};}
 const at=text.indexOf(':');if(at<0)return {invalid:true};
 try{return {id:decodeURIComponent(text.slice(0,at).replace(/\+/g,' ')),secret:decodeURIComponent(text.slice(at+1).replace(/\+/g,' '))};}catch{return {invalid:true};}
};
// The client a token request names, whichever way it authenticates; used only
// to choose the general profile, never as authentication.
export async function namedClient(ctx,request,form) {
 const b=basic(request);
 let id=b&&!b.invalid?b.id:form.get('client_id');
 if(!id&&form.get('client_assertion')){try{id=decodeJwt(form.get('client_assertion')).iss;}catch{id=null;}}
 return genericClient(ctx,id);
}

const refuse=()=>{throw new AuthError('invalid_client',401);};
async function secretValid(ctx,client,secret) {
 if(typeof secret!=='string'||!secret||secret.length>256)return false;
 return Boolean(await one(ctx,'SELECT 1 FROM auth_oidc_secrets WHERE client_id=? AND secret_hash=? AND (expires_at IS NULL OR expires_at>?)',client.client_id,await hash(secret),ctx.now()));
}
// Exactly the client's registered method; anything else is invalid_client.
export async function authenticate(ctx,request,form,client,audiences) {
 const b=basic(request),postSecret=form.get('client_secret'),assertion=form.get('client_assertion');
 const given=[b?'basic':null,postSecret!==null?'post':null,assertion!==null?'jwt':null].filter(Boolean);
 if(given.length>1)refuse();
 if(form.get('client_id')!==null&&form.get('client_id')!==client.client_id)refuse();
 if(client.auth_method==='client_secret_basic'){if(!b||b.invalid||b.id!==client.client_id||given[0]!=='basic'||!await secretValid(ctx,client,b.secret))refuse();return;}
 if(client.auth_method==='client_secret_post'){if(given[0]!=='post'||form.get('client_id')!==client.client_id||!await secretValid(ctx,client,postSecret))refuse();return;}
 if(client.auth_method==='none'){if(given.length||form.get('client_id')!==client.client_id)refuse();return;}
 if(given[0]!=='jwt'||form.get('client_assertion_type')!=='urn:ietf:params:oauth:client-assertion-type:jwt-bearer')refuse();
 let claims;
 try{({payload:claims}=await jwtVerify(assertion,createLocalJWKSet(JSON.parse(client.jwks)),{issuer:client.client_id,subject:client.client_id,audience:audiences,algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['exp','jti']}));}catch{refuse();}
 const now=Math.floor(ctx.now()/1000);if(typeof claims.jti!=='string'||claims.jti.length>256||claims.exp>now+300)refuse();
 try{await run(ctx,'INSERT INTO auth_assertions(client_id,jti,expires_at) VALUES(?,?,?)','oidc:'+client.client_id,claims.jti,claims.exp*1000);}catch{refuse();}
}

export const subjectFor=(ctx,client,personId)=>client.subject_type==='public'?personId:pairwiseSubject(ctx,'oidc:'+client.client_id,personId);

// Identity claims by granted scope; the app's attribute mapping rides on profile.
export async function claimsFor(ctx,client,s,scopes,role,proofAt) {
 const claims={};
 if(scopes.includes('email'))Object.assign(claims,{email:s.email,email_verified:true,email_verified_at:Math.floor(proofAt/1000)});
 if(scopes.includes('profile')) {
  claims.name=s.display_name;
  const name=(s.display_name||'').trim(),space=name.lastIndexOf(' ');
  for(const a of client.attributes) {
   const value=a.source==='email'?s.email:a.source==='name'?name:a.source==='first_name'?(space>0?name.slice(0,space):name):a.source==='last_name'?(space>0?name.slice(space+1):''):a.source==='person_id'?s.person_id:a.source==='role'?role:await groupNames(ctx,s.person_id);
   if(value!==null&&value!==undefined&&!['sub','iss','aud','exp','iat','nonce','sid','auth_time','at_hash','c_hash'].includes(a.name))claims[a.name]=value;
  }
 }
 if(scopes.includes('groups'))claims.groups=await groupNames(ctx,s.person_id);
 return claims;
}
