// The SAML Response Auth sends an app: NameID in the app's format, the mapped
// attributes, signed and encrypted as the app is configured.
import {one,run,random} from '../core.mjs';
import {pairwiseSubject} from '../keys.mjs';
import {el,canonical} from './xml.mjs';
import {signElement,encryptElement} from './signing.mjs';
import {FORMATS} from './apps.mjs';
import {groupNames} from '../workforce/directory.mjs';

export const idpEntity=ctx=>`${ctx.origin}/saml/metadata`;
export const iso=ms=>new Date(ms).toISOString().replace(/\.\d{3}Z$/,'Z');
export const messageId=()=>'_'+[...crypto.getRandomValues(new Uint8Array(20))].map(b=>b.toString(16).padStart(2,'0')).join('');
export const STATUS='urn:oasis:names:tc:SAML:2.0:status:';
const ASSERTION_SECONDS=300;

async function nameId(ctx,app,s) {
 if(app.name_id_source==='person_id')return s.person_id;
 if(app.name_id_source==='email')return s.email;
 if(app.name_id_format==='persistent')return pairwiseSubject(ctx,'saml:'+app.id,s.person_id);
 if(app.name_id_format==='transient')return messageId();
 return s.email;
}
async function attributeValues(ctx,source,s,role) {
 const name=(s.display_name||'').trim(),space=name.lastIndexOf(' ');
 if(source==='email')return [s.email];
 if(source==='name')return [name||s.email];
 if(source==='first_name')return [space>0?name.slice(0,space):name];
 if(source==='last_name')return [space>0?name.slice(space+1):''];
 if(source==='person_id')return [s.person_id];
 if(source==='role')return role?[role]:[];
 return groupNames(ctx,s.person_id);
}

// Error responses carry no assertion: Requester/Responder with an optional second-level code.
export function statusResponse(ctx,{acs,inResponseTo,code,detail}) {
 return el('samlp:Response',{Destination:acs.url,ID:messageId(),InResponseTo:inResponseTo??undefined,IssueInstant:iso(ctx.now()),Version:'2.0'},[el('saml:Issuer',{},[idpEntity(ctx)]),el('samlp:Status',{},[el('samlp:StatusCode',{Value:STATUS+code},detail?[el('samlp:StatusCode',{Value:STATUS+detail})]:[])])]);
}

export async function signInResponse(ctx,{app,s,acs,inResponseTo,role}) {
 const now=ctx.now(),existing=await one(ctx,'SELECT session_index FROM auth_saml_sessions WHERE session_id=? AND app_id=?',s.id,app.id);
 const sessionIndex=existing?.session_index??random(),subject=await nameId(ctx,app,s),format=FORMATS[app.name_id_format];
 const attributes=[];
 for(const a of app.attributes){const values=await attributeValues(ctx,a.source,s,role);if(values.length)attributes.push(el('saml:Attribute',{Name:a.name,NameFormat:'urn:oasis:names:tc:SAML:2.0:attrname-format:basic'},values.map(v=>el('saml:AttributeValue',{},[v]))));}
 const assertion=el('saml:Assertion',{ID:messageId(),IssueInstant:iso(now),Version:'2.0'},[
  el('saml:Issuer',{},[idpEntity(ctx)]),
  el('saml:Subject',{},[el('saml:NameID',{Format:format,NameQualifier:app.name_id_format==='persistent'?idpEntity(ctx):undefined,SPNameQualifier:app.name_id_format==='persistent'?app.entity_id:undefined},[subject]),
   el('saml:SubjectConfirmation',{Method:'urn:oasis:names:tc:SAML:2.0:cm:bearer'},[el('saml:SubjectConfirmationData',{InResponseTo:inResponseTo??undefined,NotOnOrAfter:iso(now+ASSERTION_SECONDS*1000),Recipient:acs.url})])]),
  el('saml:Conditions',{NotBefore:iso(now-60000),NotOnOrAfter:iso(now+ASSERTION_SECONDS*1000)},[el('saml:AudienceRestriction',{},[el('saml:Audience',{},[app.entity_id])])]),
  el('saml:AuthnStatement',{AuthnInstant:iso(s.created_at),SessionIndex:sessionIndex,SessionNotOnOrAfter:iso(s.expires_at)},[el('saml:AuthnContext',{},[el('saml:AuthnContextClassRef',{},['urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified'])])]),
  attributes.length?el('saml:AttributeStatement',{},attributes):null,
 ]);
 if(app.sign!=='response')await signElement(ctx,assertion,app.digest);
 const carried=app.encryption?el('saml:EncryptedAssertion',{},[await encryptElement(canonical(assertion),app.encryption_certificate,app.encryption)]):assertion;
 await run(ctx,'INSERT INTO auth_saml_sessions(session_id,app_id,name_id,name_id_format,session_index,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(session_id,app_id) DO UPDATE SET name_id=excluded.name_id,name_id_format=excluded.name_id_format,ended_at=NULL',s.id,app.id,subject,format,sessionIndex,now);
 return el('samlp:Response',{Destination:acs.url,ID:messageId(),InResponseTo:inResponseTo??undefined,IssueInstant:iso(now),Version:'2.0'},[el('saml:Issuer',{},[idpEntity(ctx)]),el('samlp:Status',{},[el('samlp:StatusCode',{Value:STATUS+'Success'})]),carried]);
}
