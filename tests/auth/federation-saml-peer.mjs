import {createRequire} from 'node:module';
import {generateKeyPair,exportPKCS8} from 'jose';
import {inflateRawSync} from 'node:zlib';
import {selfSignedCertificate,toBase64} from '../../src/auth/saml/der.mjs';

const require=createRequire(import.meta.url);
const {SignedXml}=createRequire(require.resolve('@node-saml/node-saml'))('xml-crypto');
export const samlRequest=url=>({request:inflateRawSync(Buffer.from(url.searchParams.get('SAMLRequest'),'base64')).toString('utf8'),relay:url.searchParams.get('RelayState')});
export async function samlCredential(now,label,{expired=false}={}) {
 const keys=await generateKeyPair('RS256',{extractable:true}),spki=new Uint8Array(await crypto.subtle.exportKey('spki',keys.publicKey));
 const certificate=toBase64(await selfSignedCertificate(keys.privateKey,spki,label,now-86400000,expired?now-60000:now+86400000));
 return {certificate,privateKey:await exportPKCS8(keys.privateKey),pem:'-----BEGIN CERTIFICATE-----\n'+certificate.match(/.{1,64}/g).join('\n')+'\n-----END CERTIFICATE-----\n'};
}
// Sign at the IdP network edge with an independent XML signature library.
export function samlSigner({issuer,entityId,callback,credential,now}) {
 return async(started,{audience=entityId,subject,requestId=started.request.match(/ ID="([^"]+)"/)[1],destination=callback,expiry=now()+120000,responseId}={})=>{
  const issued=new Date(now()).toISOString(),until=new Date(expiry).toISOString(),tag=responseId??'_'+crypto.randomUUID().replaceAll('-','');
  const xml=`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${tag}" Version="2.0" IssueInstant="${issued}" Destination="${destination}" InResponseTo="${requestId}"><saml:Issuer>${issuer}</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion ID="${tag}_assertion" Version="2.0" IssueInstant="${issued}"><saml:Issuer>${issuer}</saml:Issuer><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">${subject}</saml:NameID><saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData Recipient="${callback}" InResponseTo="${requestId}" NotOnOrAfter="${until}"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotOnOrAfter="${until}"><saml:AudienceRestriction><saml:Audience>${audience}</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant="${issued}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement></saml:Assertion></samlp:Response>`;
  const signer=new SignedXml({privateKey:credential.privateKey,publicCert:credential.pem,signatureAlgorithm:'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',canonicalizationAlgorithm:'http://www.w3.org/2001/10/xml-exc-c14n#'});
  signer.addReference({xpath:"/*[local-name()='Response']",transforms:['http://www.w3.org/2000/09/xmldsig#enveloped-signature','http://www.w3.org/2001/10/xml-exc-c14n#'],digestAlgorithm:'http://www.w3.org/2001/04/xmlenc#sha256'});
  signer.computeSignature(xml,{prefix:'ds',location:{reference:"/*[local-name()='Response']/*[local-name()='Issuer']",action:'after'}});
  return Buffer.from(signer.getSignedXml()).toString('base64');
 };
}
