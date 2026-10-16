// A company app's SAML service-provider settings: read from its metadata or
// entered by hand, validated, and reported with what Auth cannot do for it.
import {fail,isLoopback} from '../core.mjs';
import {parseXml,child,children,attr,textOf,el,canonical,NS} from './xml.mjs';
import {certificateKey} from './der.mjs';
import {BINDINGS} from './bindings.mjs';
import {ENCRYPTIONS} from './signing.mjs';

export const FORMATS={persistent:'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',emailAddress:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',unspecified:'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',transient:'urn:oasis:names:tc:SAML:2.0:nameid-format:transient'};
export const SOURCES=['email','name','first_name','last_name','person_id','role','groups'];
const bindingName=uri=>Object.entries(BINDINGS).find(([,u])=>u===uri)?.[0]??null;
const formatName=uri=>Object.entries(FORMATS).find(([,u])=>u===uri)?.[0]??null;
const flag=v=>v===true||v==='true'||v==='on'||v==='1'||v===1;

// The service provider's own metadata document (pasted, never fetched).
export function readMetadata(xml) {
 const root=parseXml(xml),entity=root.local==='EntityDescriptor'&&root.uri===NS.md?root:fail('invalid_metadata');
 const sp=child(entity,'SPSSODescriptor',NS.md)??fail('metadata_not_a_service_provider');
 const notes=[];
 if(!(attr(sp,'protocolSupportEnumeration')||'').split(/\s+/).includes('urn:oasis:names:tc:SAML:2.0:protocol'))fail('metadata_not_saml2');
 const acs=[];
 for(const e of children(sp,'AssertionConsumerService',NS.md)) {
  const binding=bindingName(attr(e,'Binding'));
  if(!binding){notes.push(`Assertion consumer ${attr(e,'Location')} uses ${attr(e,'Binding')}, which Auth does not support; it is not used.`);continue;}
  acs.push({url:attr(e,'Location'),binding,index:Number(attr(e,'index')??acs.length),isDefault:attr(e,'isDefault')==='true'});
 }
 const slo=children(sp,'SingleLogoutService',NS.md).map(e=>({url:attr(e,'Location'),responseUrl:attr(e,'ResponseLocation'),binding:bindingName(attr(e,'Binding'))})).find(e=>e.binding)??null;
 const certs=use=>children(sp,'KeyDescriptor',NS.md).filter(k=>!attr(k,'use')||attr(k,'use')===use).map(k=>textOf(child(child(child(k,'KeyInfo',NS.ds)??{children:[]},'X509Data',NS.ds)??{children:[]},'X509Certificate',NS.ds)).replace(/\s+/g,'')).filter(Boolean);
 const formats=children(sp,'NameIDFormat',NS.md).map(e=>textOf(e).trim());
 for(const f of formats)if(!formatName(f))notes.push(`NameID format ${f} is not supported; Auth offers persistent, emailAddress, unspecified and transient.`);
 return {entityId:attr(entity,'entityID'),acs,slo,signingCertificates:certs('signing'),encryptionCertificate:certs('encryption')[0]??null,nameIdFormat:formats.map(formatName).find(Boolean)??null,wantAssertionsSigned:attr(sp,'WantAssertionsSigned')==='true',authnRequestsSigned:attr(sp,'AuthnRequestsSigned')==='true',notes};
}

export function endpoint(ctx,value,label) {
 let url;try{url=new URL(String(value||''));}catch{fail(`invalid_${label}`);}
 if(url.username||url.password||url.hash||!(url.protocol==='https:'||(ctx.local&&url.protocol==='http:'&&isLoopback(url.hostname))))fail(`invalid_${label}`);
 return url.href;
}
export const parseAttributes=value=>{
 const lines=Array.isArray(value)?value:String(value||'').split(/\n|,/).map(l=>l.trim()).filter(Boolean).map(line=>{const [name,source]=line.split('=').map(s=>s?.trim());return {name,source};});
 if(lines.length>32)fail('invalid_attributes');
 for(const a of lines)if(!a.name||a.name.length>256||/[<>"&]/.test(a.name)||!SOURCES.includes(a.source))fail('invalid_attributes');
 return lines.map(({name,source})=>({name,source}));
};

// Normalized settings plus notes. `data` comes from the admin form or API; when
// it carries metadata, fields it does not set come from that document.
export function appSettings(ctx,data) {
 const meta=data.metadata?readMetadata(String(data.metadata)):null,notes=[...(meta?.notes??[])];
 const entityId=String(data.entityId||meta?.entityId||'').trim();
 if(!entityId||entityId.length>1024||/\s/.test(entityId))fail('invalid_entity_id');
 const acs=(data.acsUrl?[{url:data.acsUrl,binding:data.acsBinding==='redirect'?'redirect':'post',index:0,isDefault:true}]:meta?.acs??[]).map(a=>({...a,url:endpoint(ctx,a.url,'acs_url')}));
 if(!acs.length)fail('acs_required');
 if(acs.length>16)fail('invalid_acs_url');
 const sloUrl=data.sloUrl?{url:data.sloUrl,binding:data.sloBinding==='post'?'post':'redirect',responseUrl:null}:meta?.slo??null;
 const slo=sloUrl?{url:endpoint(ctx,sloUrl.url,'slo_url'),binding:sloUrl.binding,responseUrl:sloUrl.responseUrl?endpoint(ctx,sloUrl.responseUrl,'slo_url'):null}:null;
 const signingCertificates=(data.signingCertificate?[data.signingCertificate]:meta?.signingCertificates??[]).map(c=>certificateKey(c).base64);
 const encryptionText=data.encryptionCertificate||meta?.encryptionCertificate||null,encryptionCertificate=encryptionText?certificateKey(encryptionText).base64:null;
 const nameIdFormat=data.nameIdFormat||meta?.nameIdFormat||'persistent';if(!FORMATS[nameIdFormat])fail('invalid_name_id_format');
 const nameIdSource=data.nameIdSource||null;if(nameIdSource&&!['person_id','email'].includes(nameIdSource))fail('invalid_name_id_source');
 const sign=data.sign||(meta?.wantAssertionsSigned?'both':'response');if(!['response','assertion','both'].includes(sign))fail('invalid_signing');
 const digest=data.digest||'sha256',sha1Exception=flag(data.sha1Exception);
 if(!['sha256','sha512','sha1'].includes(digest))fail('invalid_digest');if(digest==='sha1'&&!sha1Exception)fail('sha1_requires_exception');
 const encryption=data.encryption||null;if(encryption&&!ENCRYPTIONS[encryption])fail('unsupported_encryption');if(encryption&&!encryptionCertificate)fail('encryption_certificate_required');
 const wantRequestsSigned=flag(data.wantRequestsSigned)||Boolean(meta?.authnRequestsSigned);if(wantRequestsSigned&&!signingCertificates.length)fail('signing_certificate_required');
 const name=String(data.name||entityId).trim().slice(0,120),relayState=data.relayState?String(data.relayState).slice(0,80):null;
 const launchUrl=data.launchUrl?endpoint(ctx,data.launchUrl,'launch_url'):null;
 if(!slo)notes.push('No single logout endpoint: signing out of Auth does not sign people out of this app.');
 if(!signingCertificates.length)notes.push('No signing certificate: Auth cannot verify this app\'s requests, so its sign-out requests are refused.');
 if(meta?.wantAssertionsSigned&&sign==='response')notes.push('The app asks for signed assertions; choose Assertion or Both.');
 if(digest==='sha1')notes.push('RSA-SHA1 is enabled for this app as a named compatibility exception.');
 return {name,entityId,acs,slo,signingCertificates,encryptionCertificate,nameIdFormat,nameIdSource,sign,digest,sha1Exception,encryption,wantRequestsSigned,idpInitiated:flag(data.idpInitiated),relayState,attributes:parseAttributes(data.attributes??(meta?[{name:'email',source:'email'},{name:'name',source:'name'}]:[])),launchUrl,notes};
}
export const settingsColumns=s=>[s.name,s.entityId,JSON.stringify(s.acs),s.slo?JSON.stringify(s.slo):null,JSON.stringify(s.signingCertificates),s.encryptionCertificate,s.nameIdFormat,s.nameIdSource,s.sign,s.digest,s.sha1Exception?1:0,s.encryption,s.wantRequestsSigned?1:0,s.idpInitiated?1:0,s.relayState,JSON.stringify(s.attributes),s.launchUrl];
export const SETTINGS_SQL='name,entity_id,acs,slo,sp_certificates,encryption_certificate,name_id_format,name_id_source,sign,digest,sha1_exception,encryption,want_requests_signed,idp_initiated,relay_state,attributes,launch_url';

export const appOf=row=>row&&{...row,acs:JSON.parse(row.acs),slo:row.slo?JSON.parse(row.slo):null,spCertificates:JSON.parse(row.sp_certificates),attributes:JSON.parse(row.attributes)};
export function defaultAcs(app,{url,index,binding}={}) {
 if(url)return app.acs.find(a=>a.url===url&&(!binding||a.binding===binding))??null;
 if(index!==undefined&&index!==null)return app.acs.find(a=>a.index===Number(index))??null;
 return app.acs.find(a=>a.isDefault)??app.acs[0];
}

// The service-provider settings Auth holds, exported as SAML metadata.
export function spMetadata(app) {
 const keys=[...app.spCertificates.map(c=>['signing',c]),...(app.encryption_certificate?[['encryption',app.encryption_certificate]]:[])];
 return '<?xml version="1.0" encoding="UTF-8"?>'+canonical(el('md:EntityDescriptor',{entityID:app.entity_id},[el('md:SPSSODescriptor',{AuthnRequestsSigned:app.want_requests_signed?'true':'false',WantAssertionsSigned:app.sign==='response'?'false':'true',protocolSupportEnumeration:'urn:oasis:names:tc:SAML:2.0:protocol'},[
  ...keys.map(([use,c])=>el('md:KeyDescriptor',{use},[el('ds:KeyInfo',{},[el('ds:X509Data',{},[el('ds:X509Certificate',{},[c])])])])),
  ...(app.slo?[el('md:SingleLogoutService',{Binding:BINDINGS[app.slo.binding],Location:app.slo.url,ResponseLocation:app.slo.responseUrl??undefined})]:[]),
  el('md:NameIDFormat',{},[FORMATS[app.name_id_format]]),
  ...app.acs.map(a=>el('md:AssertionConsumerService',{Binding:BINDINGS[a.binding],Location:a.url,index:a.index,isDefault:a.isDefault?'true':undefined})),
 ])]));
}
