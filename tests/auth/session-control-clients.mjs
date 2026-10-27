import assert from 'node:assert/strict';
import {createHash,randomBytes} from 'node:crypto';
import {createSessionClient} from '../../packages/session-sdk/index.mjs';
import {command} from './session-control-helpers.mjs';

export async function client(r,owner,cookie,name,{logout,offline=false}={}) {
 const slug=name.toLowerCase().replace(/\s+/g,'-'),redirectUri='https://sessions.example.com/'+slug+'/callback';
 const app=await command(r,owner,'/api/auth/oidc-apps/create',{name,authMethod:'none',redirectUris:[redirectUri],...(logout?{backchannelLogoutUri:'https://sessions.example.com/'+logout}:{})},201);
 await command(r,owner,'/api/auth/company-apps/assign',{appId:app.id,principalType:'person',principalId:'ada'});
 if(!offline) {
  const verifier=randomBytes(32).toString('base64url');
  const query=new URLSearchParams({client_id:app.clientId,redirect_uri:redirectUri,response_type:'code',scope:'openid email',state:randomBytes(16).toString('hex'),code_challenge:createHash('sha256').update(verifier).digest('base64url'),code_challenge_method:'S256'});
  const authorize=await r.call('/oidc/authorize?'+query,{cookie});
  assert.equal(authorize.status,302,await authorize.clone().text());
  const callback=new URL(authorize.headers.get('location'));assert.ok(callback.searchParams.get('code'),callback.href);
  const exchanged=await r.call('/oidc/token',{method:'POST',form:{grant_type:'authorization_code',client_id:app.clientId,redirect_uri:redirectUri,code_verifier:verifier,code:callback.searchParams.get('code')}});
  assert.equal(exchanged.status,200,await exchanged.clone().text());
  return {...app,tokens:await exchanged.json()};
 }
 const api=await command(r,owner,'/api/auth/resource-apis/register',{appId:app.id,name:name+' API',audience:'https://sessions.example.com/'+slug+'/api',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['record:1']}],resources:[{id:'record:1'}]},201);
 await command(r,owner,'/api/auth/resource-apis/assign',{apiId:api.id,principalType:'person',principalId:'ada',role:'reader'});
 await command(r,owner,'/api/auth/refresh/profile',{clientId:app.clientId,apiId:api.id,scopes:['read'],idleHours:1,absoluteHours:24});
 const connect=async deviceName=>{
  const sdk=await createSessionClient({issuer:r.origin,clientId:app.clientId,redirectUri,fetch:(url,options)=>{
   const u=new URL(url),headers=Object.fromEntries(new Headers(options.headers));
   return r.call(u.pathname+u.search,{method:options.method,headers,...(headers['content-type']==='application/json'?{data:JSON.parse(options.body)}:{form:Object.fromEntries(new URLSearchParams(options.body))})});
  }});
  const auth=await sdk.authorization({resource:'https://sessions.example.com/'+slug+'/api',scopes:['read'],deviceName});
  const u=new URL(auth.url),response=await r.call(u.pathname+u.search,{cookie});
  assert.equal(response.status,302,await response.clone().text());
  const consentId=new URL(response.headers.get('location'),r.origin).searchParams.get('refreshConsent');assert.ok(consentId);
  const consent=await command(r,cookie,'/api/auth/refresh/consent',{id:consentId,decision:'approve'});
  const tokens=await sdk.complete(consent.redirect);
  const check=()=>sdk.resourceRequest('/api/auth/resource-apis/check',{apiId:api.id,action:'read',resource:'record:1'});
  return {sdk,tokens,check};
 };
 return {...app,api,connect};
}
