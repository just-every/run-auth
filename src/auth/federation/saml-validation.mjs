import {fail} from '../core.mjs';
import {parseXml,children,attr,textOf,NS} from '../saml/xml.mjs';
import {verifyEnveloped} from '../saml/signing.mjs';
import {currentSamlCertificates,SAML_LIFETIME,SAML_SKEW} from './saml-config.mjs';

const ID=/^[A-Za-z_][\w.-]{0,255}$/;
const bearer='urn:oasis:names:tc:SAML:2.0:cm:bearer';
const success='urn:oasis:names:tc:SAML:2.0:status:Success';
function exactly(parent,name,uri) {
 const nodes=children(parent,name,uri);if(nodes.length!==1)fail('invalid_federation_assertion');return nodes[0];
}
function instant(value) {
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?Z$/.test(value??''))fail('invalid_saml_time');
 const at=Date.parse(value);if(!Number.isFinite(at))fail('invalid_saml_time');return at;
}
function issueTime(ctx,node) {
 const at=instant(attr(node,'IssueInstant'));
 if(at>ctx.now()+SAML_SKEW||at<ctx.now()-SAML_LIFETIME-SAML_SKEW)fail('stale_saml_message');
 return at;
}
function bounds(ctx,node,{required=true}={}) {
 const before=attr(node,'NotBefore'),after=attr(node,'NotOnOrAfter');
 if(required&&after===null)fail('saml_expiry_required');
 const starts=before===null?null:instant(before),ends=after===null?null:instant(after);
 if(starts!==null&&starts>ctx.now()+SAML_SKEW||ends!==null&&ends<=ctx.now()-SAML_SKEW||starts!==null&&ends!==null&&starts>=ends)fail('stale_saml_message');
 return ends;
}
function structure(root) {
 const ids=new Set(),signatures=[],assertions=[];
 const walk=node=>{
  const attributes=new Set();
  for(const a of node.attrs){const key=a.uri+'\0'+a.local;if(attributes.has(key))fail('ambiguous_saml_attribute');attributes.add(key);}
  const id=attr(node,'ID');
  if(id!==null){if(!ID.test(id)||ids.has(id))fail('ambiguous_saml_id');ids.add(id);}
  if(node.uri===NS.ds&&node.local==='Signature')signatures.push(node);
  if(node.uri===NS.saml&&node.local==='Assertion')assertions.push(node);
  for(const child of node.children)if(typeof child!=='string')walk(child);
 };walk(root);
 return {signatures,assertions};
}

// Validate the exact tree that signature verification covers; never select an
// assertion by an untrusted ID lookup or accept an unsolicited response.
export async function validateSamlResponse(ctx,provider,xml,transaction) {
 const root=parseXml(xml);
 if(root.local!=='Response'||root.uri!==NS.samlp||attr(root,'Version')!=='2.0'||!ID.test(attr(root,'ID')??''))fail('invalid_federation_response');
 if(attr(root,'Destination')!==provider.callback||attr(root,'InResponseTo')!==transaction.request_id)fail('saml_correlation_refused',403);
 if(textOf(exactly(root,'Issuer',NS.saml))!==provider.issuer)fail('saml_issuer_mismatch',403);
 issueTime(ctx,root);
 const status=exactly(exactly(root,'Status',NS.samlp),'StatusCode',NS.samlp);
 if(attr(status,'Value')!==success||children(status,'StatusCode',NS.samlp).length)fail('saml_authentication_refused',403);
 if(children(root,'EncryptedAssertion',NS.saml).length)fail('encrypted_upstream_assertion_unsupported');
 const assertion=exactly(root,'Assertion',NS.saml),tree=structure(root);
 if(tree.assertions.length!==1||tree.assertions[0]!==assertion||attr(assertion,'Version')!=='2.0'||!ID.test(attr(assertion,'ID')??''))fail('invalid_federation_assertion');
 const rootSignatures=children(root,'Signature',NS.ds),assertionSignatures=children(assertion,'Signature',NS.ds);
 if(rootSignatures.length>1||assertionSignatures.length>1||tree.signatures.length!==rootSignatures.length+assertionSignatures.length||!tree.signatures.length)fail('saml_signature_required',403);
 const certificates=currentSamlCertificates(ctx,provider);
 if(rootSignatures.length&&!await verifyEnveloped(root,certificates,false)||assertionSignatures.length&&!await verifyEnveloped(assertion,certificates,false))fail('invalid_saml_signature',403);
 if(textOf(exactly(assertion,'Issuer',NS.saml))!==provider.issuer)fail('saml_issuer_mismatch',403);
 const issuedAt=issueTime(ctx,assertion),conditions=exactly(assertion,'Conditions',NS.saml),expiresAt=bounds(ctx,conditions);
 const conditionNodes=conditions.children.filter(node=>typeof node!=='string');
 if(conditionNodes.some(node=>node.uri!==NS.saml||!['AudienceRestriction','OneTimeUse'].includes(node.local)))fail('unsupported_saml_condition');
 const restrictions=children(conditions,'AudienceRestriction',NS.saml);
 if(!restrictions.length||restrictions.some(restriction=>!children(restriction,'Audience',NS.saml).some(audience=>textOf(audience)===provider.entityId)))fail('saml_audience_mismatch',403);
 const subject=exactly(assertion,'Subject',NS.saml),name=exactly(subject,'NameID',NS.saml);
 if(attr(name,'Format')!==provider.nameIdFormat||attr(name,'NameQualifier')!==null&&attr(name,'NameQualifier')!==provider.issuer||attr(name,'SPNameQualifier')!==null&&attr(name,'SPNameQualifier')!==provider.entityId)fail('saml_subject_refused',403);
 const subjectId=textOf(name);
 if(!subjectId||subjectId.length>255||/[\x00-\x1f\x7f]/.test(subjectId)||!Object.hasOwn(provider.subjectEmails,subjectId))fail('federation_subject_unmapped',403);
 const confirmation=exactly(subject,'SubjectConfirmation',NS.saml);
 if(attr(confirmation,'Method')!==bearer)fail('saml_subject_refused',403);
 const data=exactly(confirmation,'SubjectConfirmationData',NS.saml);
 if(attr(data,'Recipient')!==provider.callback||attr(data,'InResponseTo')!==transaction.request_id||attr(data,'Address')!==null)fail('saml_correlation_refused',403);
 const confirmedUntil=bounds(ctx,data);
 const authentication=exactly(assertion,'AuthnStatement',NS.saml),authnAt=instant(attr(authentication,'AuthnInstant'));
 if(authnAt>ctx.now()+SAML_SKEW||authnAt>issuedAt+SAML_SKEW)fail('stale_saml_message');
 const sessionEnd=attr(authentication,'SessionNotOnOrAfter');
 if(sessionEnd!==null&&instant(sessionEnd)<=ctx.now()-SAML_SKEW)fail('stale_saml_message');
 const context=exactly(authentication,'AuthnContext',NS.saml),classes=children(context,'AuthnContextClassRef',NS.saml);
 if(classes.length!==1)fail('saml_authentication_context_required');
 const amr=['saml'];
 if(textOf(classes[0])==='https://refeds.org/profile/mfa')amr.push('mfa');
 // Mapping is limited to a reviewed immutable NameID. Attribute statements and
 // email-looking NameIDs never choose an account or assert local email proof.
 return {assertionId:attr(assertion,'ID'),responseId:attr(root,'ID'),expiresAt:Math.min(expiresAt,confirmedUntil,issuedAt+SAML_LIFETIME),principal:{provider:provider.id,issuer:provider.issuer,subject:subjectId,associatedEmail:provider.subjectEmails[subjectId],emailVerified:false,protocol:'saml',amr}};
}
