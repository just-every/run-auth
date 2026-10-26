import {fail,AuthError} from '../core.mjs';
import {withinTimeout,checkedDestination,readBounded} from '../hooks/network.mjs';
import {object} from './network.mjs';

export function validateCredential(kind,value) {
 if(typeof value!=='string'||!value.trim()||value.length>16384)fail('directory_source_invalid_credential');
 if(kind==='entra'&&value.trim().startsWith('{')){
  let parsed;try{parsed=JSON.parse(value);}catch{fail('directory_source_invalid_credential');}
  if(!object(parsed)||Object.keys(parsed).some(key=>!['clientId','clientSecret'].includes(key))||typeof parsed.clientId!=='string'||!/^[a-f\d-]{36}$/i.test(parsed.clientId)||typeof parsed.clientSecret!=='string'||!parsed.clientSecret||parsed.clientSecret.length>4096||/[\x00-\x1f\x7f]/.test(parsed.clientSecret))fail('directory_source_invalid_credential');
  return value;
 }
 if(/[\x00-\x20\x7f]/.test(value))fail('directory_source_invalid_credential');return value;
}
export async function directoryCredential(ctx,source,value) {
 validateCredential(source.kind,value);
 if(source.kind!=='entra'||!value.trim().startsWith('{'))return value;
 const config=JSON.parse(value),tenant=source.organizationBinding;
 if(!/^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$/i.test(tenant))fail('directory_source_binding_refused',403);
 try{return await withinTimeout(15000,async signal=>{
  const endpoint=await checkedDestination(ctx,`https://login.microsoftonline.com/${tenant}/oauth2/v2.0/token`,signal);
  const response=await (ctx.connectorFetch||fetch)(endpoint,{method:'POST',redirect:'manual',signal,headers:{'content-type':'application/x-www-form-urlencoded',accept:'application/json'},body:new URLSearchParams({client_id:config.clientId,client_secret:config.clientSecret,grant_type:'client_credentials',scope:'https://graph.microsoft.com/.default'}).toString()});
  if(response.status!==200){await response.body?.cancel();fail('directory_source_credential_refused',502);}
  if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();fail('directory_source_credential_refused',502);}
  const body=JSON.parse(await readBounded(response,signal,32768));
  if(!object(body)||body.token_type?.toLowerCase()!=='bearer'||typeof body.access_token!=='string'||!body.access_token||body.access_token.length>16384||/[\x00-\x20\x7f]/.test(body.access_token))fail('directory_source_credential_refused',502);
  return body.access_token;
 });}catch(error){if(error instanceof AuthError&&error.message.startsWith('directory_source_'))throw error;fail('directory_source_credential_unavailable',503);}
}
