import {fail} from '../core.mjs';
import {parseXml,children,attr,textOf,NS} from '../saml/xml.mjs';
import {certificateKey} from '../saml/der.mjs';
import {BINDINGS} from '../saml/bindings.mjs';
import {federationUrl,fetchFederationMetadata} from './network.mjs';

// Metadata proposes trust for the setup preview; parsing never activates it.
// A single IdP entity avoids ambiguous multi-entity trust selection.
export function parseFederationMetadata(ctx,xml) {
 const root=parseXml(xml);
 if(root.uri!==NS.md||root.local!=='EntityDescriptor')fail('invalid_federation_metadata');
 const issuer=attr(root,'entityID'),descriptors=children(root,'IDPSSODescriptor',NS.md);
 if(!issuer||descriptors.length!==1)fail('invalid_federation_metadata');
 if(issuer===(ctx.issuer??ctx.origin)||issuer.startsWith(ctx.origin+'/'))fail('federation_loop',403);
 const descriptor=descriptors[0];
 if(!(attr(descriptor,'protocolSupportEnumeration')??'').split(/\s+/).includes(NS.samlp))fail('invalid_federation_metadata');
 const services=children(descriptor,'SingleSignOnService',NS.md).filter(service=>attr(service,'Binding')===BINDINGS.redirect);
 if(services.length!==1)fail('saml_redirect_service_required');
 const ssoUrl=federationUrl(ctx,attr(services[0],'Location')),certificates=[];
 for(const key of children(descriptor,'KeyDescriptor',NS.md)) {
  if(attr(key,'use')&&attr(key,'use')!=='signing')continue;
  for(const info of children(key,'KeyInfo',NS.ds))for(const data of children(info,'X509Data',NS.ds))for(const certificate of children(data,'X509Certificate',NS.ds))certificates.push(certificateKey(textOf(certificate)).base64);
 }
 if(!certificates.length||certificates.length>8)fail('invalid_saml_certificates');
 const validUntil=attr(root,'validUntil')??attr(descriptor,'validUntil');
 if(validUntil!==null&&(!Number.isFinite(Date.parse(validUntil))||Date.parse(validUntil)<=ctx.now()))fail('expired_federation_metadata');
 return {preset:'saml',issuer,ssoUrl,certificates:[...new Set(certificates)],signAuthnRequests:['true','1'].includes(attr(descriptor,'WantAuthnRequestsSigned')),nameIdFormats:children(descriptor,'NameIDFormat',NS.md).map(textOf),metadataValidUntil:validUntil};
}
export async function readFederationMetadata(ctx,url) {
 return parseFederationMetadata(ctx,await fetchFederationMetadata(ctx,url));
}
