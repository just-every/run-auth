import {fail,email} from '../core.mjs';
import {certificateKey,certificateValidity} from '../saml/der.mjs';
import {federationUrl} from './network.mjs';

export const PERSISTENT='urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
export const UNSPECIFIED='urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
export const SAML_LIFETIME=10*60000;
export const SAML_SKEW=60000;
export function samlConfiguration(ctx,provider) {
 if(provider.preset!=='saml'||!/^[a-z][a-z0-9-]{0,31}$/.test(provider.id??''))fail('invalid_saml_provider');
 if(typeof provider.issuer!=='string'||!provider.issuer||provider.issuer.length>2048||/[\s\x00-\x1f]/.test(provider.issuer))fail('invalid_saml_issuer');
 if(provider.issuer===(ctx.issuer??ctx.origin)||provider.issuer.startsWith(ctx.origin+'/'))fail('federation_loop',403);
 const base=ctx.issuer??ctx.origin,entityId=provider.entityId??`${base}/federation/saml/${provider.id}`;
 const callback=`${base}/auth/saml/${provider.id}/callback`;
 if(provider.redirectUri!==undefined&&provider.redirectUri!==callback)fail('invalid_saml_callback');
 if(typeof entityId!=='string'||!entityId||entityId.length>2048||/[\s\x00-\x1f]/.test(entityId))fail('invalid_saml_entity_id');
 const ssoUrl=federationUrl(ctx,provider.ssoUrl),certificates=provider.certificates;
 if(provider.signAuthnRequests!==undefined&&typeof provider.signAuthnRequests!=='boolean'||provider.wantAuthnRequestsSigned!==undefined&&typeof provider.wantAuthnRequestsSigned!=='boolean')fail('invalid_saml_request_signing');
 if(!Array.isArray(certificates)||!certificates.length||certificates.length>8)fail('invalid_saml_certificates');
 const pins=[...new Set(certificates.map(value=>certificateKey(value).base64))];
 for(const certificate of pins)certificateValidity(certificate);
 const nameIdFormat=provider.nameIdFormat??PERSISTENT;
 if(![PERSISTENT,UNSPECIFIED].includes(nameIdFormat))fail('immutable_saml_nameid_required');
 const mapping=provider.subjectEmails??{};
 if(!mapping||typeof mapping!=='object'||Array.isArray(mapping)||Object.entries(mapping).some(([subject,address])=>!subject||subject.length>255||/[\x00-\x1f\x7f]/.test(subject)||!email(address)))fail('invalid_saml_subjects');
 const subjectEmails=Object.fromEntries(Object.entries(mapping).map(([subject,address])=>[subject,email(address)]));
 return {...provider,entityId,callback,ssoUrl,certificates:pins,nameIdFormat,subjectEmails,signAuthnRequests:provider.signAuthnRequests===true||provider.wantAuthnRequestsSigned===true,
  startPath:`/auth/saml/${provider.id}/start`,callbackPath:`/auth/saml/${provider.id}/callback`,resumePath:`/auth/saml/${provider.id}/resume`};
}
export function currentSamlCertificates(ctx,provider) {
 const valid=provider.certificates.filter(certificate=>{const dates=certificateValidity(certificate);return dates.notBefore<=ctx.now()&&dates.notAfter>ctx.now();});
 if(!valid.length)fail('saml_trust_expired',403);
 return valid;
}
