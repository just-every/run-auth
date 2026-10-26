import {AuthError,fail,json,random,hash,one,run,returnPath,limit} from '../core.mjs';
import {configurationHash} from '../domain-policy.mjs';
import {seal,unseal} from '../keys.mjs';
import {el,canonical,NS} from '../saml/xml.mjs';
import {sendMessage,BINDINGS} from '../saml/bindings.mjs';
import {fromBase64} from '../saml/der.mjs';
import {ensureSamlKey,publishedKeys} from '../saml/signing.mjs';
import {checkedFederationUrl} from './network.mjs';
import {withinTimeout} from '../hooks/network.mjs';
import {samlConfiguration,SAML_LIFETIME,SAML_SKEW} from './saml-config.mjs';
import {validateSamlResponse} from './saml-validation.mjs';

const RANDOM=/^[A-Za-z0-9_-]{43}$/;
const headers={'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};
const name=id=>'__Host-auth_federation_'+id;
// SAML's cross-site POST needs a narrowly scoped correlation cookie that is
// sent with POST. Admission happens on a later GET so Auth's Lax cookies return.
const cookie=(id,value,age=SAML_LIFETIME/1000)=>`${name(id)}=${value}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${age}`;
const redirect=(location,cookies=[])=>{
 const result=new Headers({...headers,location});for(const value of cookies)result.append('set-cookie',value);
 return new Response(null,{status:303,headers:result});
};
function binding(request,id) {
 const values=(request.headers.get('cookie')??'').split(';').map(value=>value.trim()).filter(value=>value.startsWith(name(id)+'='));
 if(values.length!==1||!RANDOM.test(values[0].slice(name(id).length+1)))fail('saml_browser_binding_required',403);
 return values[0].slice(name(id).length+1);
}
export async function readSamlInput(request,maximum) {
 const reader=request.body?.getReader();if(!reader)return '';
 const chunks=[];let size=0;
 try {for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>maximum)fail('request_too_large',413);chunks.push(value);}}
 finally{void reader.cancel().catch(()=>{});}
 const all=new Uint8Array(size);let at=0;for(const value of chunks){all.set(value,at);at+=value.length;}
 try{return new TextDecoder('utf-8',{fatal:true}).decode(all);}catch{fail('invalid_saml_message');}
}
async function metadata(ctx,provider) {
 let keys=[];
 if(provider.signAuthnRequests){await ensureSamlKey(ctx);keys=await publishedKeys(ctx);}
 return canonical(el('md:EntityDescriptor',{entityID:provider.entityId},[
  el('md:SPSSODescriptor',{protocolSupportEnumeration:NS.samlp,AuthnRequestsSigned:String(provider.signAuthnRequests),WantAssertionsSigned:'false'},[
   ...keys.map(key=>el('md:KeyDescriptor',{use:'signing'},[el('ds:KeyInfo',{},[el('ds:X509Data',{},[el('ds:X509Certificate',{},[key.certificate])])])])),
   el('md:NameIDFormat',{},[provider.nameIdFormat]),
   el('md:AssertionConsumerService',{Binding:BINDINGS.post,Location:provider.callback,index:'0',isDefault:'true'}),
  ]),
 ]));
}

export function createFederationSaml(ctx,{providers=ctx.upstreamProviders??[],admission}={}) {
 const originals=new Map(providers.filter(provider=>provider.preset==='saml').map(provider=>[provider.id,provider]));
 const configured=new Map([...originals].map(([id,provider])=>[id,samlConfiguration(ctx,provider)]));
 const fingerprint=id=>configurationHash(originals.get(id));
 const publicPath=path=>(ctx.basePath??'')+path;
 async function begin(request,provider) {
  if(request.method!=='POST')fail('method_not_allowed',405);
  if(request.headers.get('origin')!==ctx.origin||request.headers.get('sec-fetch-site')==='cross-site')fail('origin_required',403);
  if(new URL(request.url).search)fail('invalid_saml_route');
  const type=(request.headers.get('content-type')??'').split(';')[0];
  if(!['application/json','application/x-www-form-urlencoded'].includes(type))fail('unsupported_content_type',415);
  const input=await readSamlInput(request,4096);let data;
  try{if(type==='application/json')data=JSON.parse(input);else {const form=new URLSearchParams(input);if(form.getAll('returnTo').length>1)fail('invalid_saml_message');data={returnTo:form.get('returnTo')};}}catch{fail('invalid_saml_message');}
  if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_saml_message');
  const ip=request.headers.get('cf-connecting-ip');if(!ip||!await limit(ctx,'saml-start:'+provider.id+':'+await hash(ip),30,900000))fail('rate_limited',429);
  await withinTimeout(5000,signal=>checkedFederationUrl(ctx,provider.ssoUrl,signal));
  const relay=random(),browser=random(),id=await hash(relay),requestId='_'+random(),now=ctx.now();
  await run(ctx,'INSERT INTO auth_federation_transactions(id,provider_id,setup_id,configuration_hash,binding_hash,request_id,return_to,expires_at) VALUES(?,?,?,?,?,?,?,?)',id,provider.id,ctx.federationSetupId??null,await fingerprint(provider.id),await hash(browser),requestId,returnPath(data.returnTo),now+SAML_LIFETIME);
  const element=el('samlp:AuthnRequest',{ID:requestId,Version:'2.0',IssueInstant:new Date(now).toISOString(),Destination:provider.ssoUrl,AssertionConsumerServiceURL:provider.callback,ProtocolBinding:BINDINGS.post},[
   el('saml:Issuer',{},[provider.entityId]),el('samlp:NameIDPolicy',{Format:provider.nameIdFormat,AllowCreate:'false'}),
  ]);
  return sendMessage(ctx,{kind:'SAMLRequest',element,relayState:relay,endpoint:{url:provider.ssoUrl,binding:'redirect'},sign:provider.signAuthnRequests,digest:'sha256',headers:{'set-cookie':cookie(relay,browser)}});
 }
 async function callback(request,provider) {
  if(request.method!=='POST'||!(request.headers.get('content-type')??'').startsWith('application/x-www-form-urlencoded'))fail('invalid_saml_message');
  if(new URL(request.url).search)fail('invalid_saml_route');
  const form=new URLSearchParams(await readSamlInput(request,360000));
  if(form.getAll('RelayState').length!==1||form.getAll('SAMLResponse').length!==1||[...form.keys()].some(key=>!['RelayState','SAMLResponse'].includes(key)))fail('invalid_saml_message');
  const relay=form.get('RelayState');if(!RANDOM.test(relay))fail('saml_correlation_refused',403);
  const id=await hash(relay),browser=await hash(binding(request,relay)),configuration=await fingerprint(provider.id);
  const transaction=await one(ctx,'UPDATE auth_federation_transactions SET consumed_at=? WHERE id=? AND provider_id=? AND setup_id IS ? AND configuration_hash=? AND binding_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING *',ctx.now(),id,provider.id,ctx.federationSetupId??null,configuration,browser,ctx.now());
  if(!transaction)fail('saml_correlation_refused',403);
  const bytes=fromBase64(form.get('SAMLResponse'));if(bytes.length>262144)fail('invalid_saml_message');
  let xml;try{xml=new TextDecoder('utf-8',{fatal:true}).decode(bytes);}catch{fail('invalid_saml_message');}
  const verified=await validateSamlResponse(ctx,provider,xml,transaction);
  const sealed=await seal(ctx,'federation-principal:'+id,{principal:verified.principal,expiresAt:Math.min(transaction.expires_at,verified.expiresAt+SAML_SKEW)});
  // Assertion and response IDs are independently replay-protected. INSERT OR
  // IGNORE plus guarded completion makes concurrent replay have one winner.
  const assertion='assertion:'+verified.assertionId,response='response:'+verified.responseId;
  const results=await ctx.db.batch([
   ctx.db.prepare('INSERT OR IGNORE INTO auth_federation_replays(provider_id,assertion_id,expires_at) VALUES(?,?,?)').bind(provider.id,assertion,verified.expiresAt+SAML_SKEW),
   ctx.db.prepare(`UPDATE auth_federation_transactions SET verified_principal=?,verified_at=? WHERE id=? AND verified_principal IS NULL AND changes()=1`).bind(sealed,ctx.now(),id),
   ctx.db.prepare('INSERT OR IGNORE INTO auth_federation_replays(provider_id,assertion_id,expires_at) SELECT ?,?,? WHERE changes()=1').bind(provider.id,response,verified.expiresAt+SAML_SKEW),
   ctx.db.prepare('UPDATE auth_federation_transactions SET verified_principal=NULL WHERE id=? AND changes()=0').bind(id),
  ]);
  if(!results[1].meta.changes||!results[2].meta.changes)fail('saml_response_replayed',403);
  return redirect(publicPath(provider.resumePath)+'?state='+relay);
 }
 async function resume(request,provider) {
  if(request.method!=='GET')fail('method_not_allowed',405);
  const url=new URL(request.url),relay=url.searchParams.get('state');
  if(!RANDOM.test(relay)||url.searchParams.getAll('state').length!==1||[...url.searchParams.keys()].some(key=>key!=='state'))fail('saml_correlation_refused',403);
  const id=await hash(relay),transaction=await one(ctx,'UPDATE auth_federation_transactions SET completed_at=? WHERE id=? AND provider_id=? AND setup_id IS ? AND binding_hash=? AND configuration_hash=? AND consumed_at IS NOT NULL AND verified_principal IS NOT NULL AND completed_at IS NULL AND expires_at>? RETURNING *',ctx.now(),id,provider.id,ctx.federationSetupId??null,await hash(binding(request,relay)),await fingerprint(provider.id),ctx.now());
  if(!transaction)fail('saml_correlation_refused',403);
  const verified=await unseal(ctx,'federation-principal:'+id,transaction.verified_principal);
  await run(ctx,'UPDATE auth_federation_transactions SET verified_principal=NULL WHERE id=?',id);
  if(verified.expiresAt<=ctx.now()||verified.principal.provider!==provider.id||verified.principal.issuer!==provider.issuer)fail('stale_saml_message');
  const result=await admission.admit(request,verified.principal,{returnTo:transaction.return_to});
  return redirect(result.returnTo,[cookie(relay,'',0),...(result.cookie?[result.cookie]:[])]);
 }
 return {async list(){return [...configured.values()].map(provider=>({id:provider.id,label:provider.label??provider.id,preset:'saml',startPath:provider.startPath,authorizationOrigins:[new URL(provider.ssoUrl).origin],visible:true,linked:true}));},
  async fetch(request){
   const url=new URL(request.url);let path=url.pathname;
   if(ctx.basePath&&path.startsWith(ctx.basePath+'/'))path=path.slice(ctx.basePath.length);
   const route=/^\/auth\/saml\/([a-z][a-z0-9-]{0,31})\/(start|callback|resume|metadata)$/.exec(path);
   const provider=route&&configured.get(route[1]);if(!provider)return null;
   try {
    if(url.origin!==ctx.origin)fail('wrong_issuer',403);
    if(route[2]==='metadata') {if(request.method!=='GET')fail('method_not_allowed',405);return new Response(await metadata(ctx,provider),{headers:{...headers,'content-type':'application/samlmetadata+xml; charset=utf-8'}});}
    return await ({start:begin,callback,resume}[route[2]])(request,provider);
   }catch(error){return json({error:error instanceof AuthError?error.message:'federation_unavailable'},error instanceof AuthError?error.status:503);}
  },
 };
}
