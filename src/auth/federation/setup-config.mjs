import {fail,email} from '../core.mjs';
import {configure} from '../../modules/operator-auth/identity/oidc/config.mjs';
import {PRESETS} from '../../modules/operator-auth/identity/oidc/presets.mjs';
import {normalizeOidcProvider} from './oidc.mjs';
import {samlConfiguration} from './saml-config.mjs';
import {federationUrl} from './network.mjs';
import {readFederationMetadata,parseFederationMetadata} from './metadata.mjs';

const COMMON=['id','preset','label','issuer','subjectEmails'];
const OIDC=['tenant','clientId','clientSecret','privateKey','tokenAuthMethod','endpointPins'];
const SAML=['entityId','ssoUrl','certificates','nameIdFormat','signAuthnRequests','wantAuthnRequestsSigned','metadataUrl','metadataXml'];
export async function setupProvider(ctx,input) {
 if(!input||typeof input!=='object'||Array.isArray(input)||!['google','microsoft','okta','oidc','saml'].includes(input.preset)||!/^[a-z][a-z0-9-]{0,31}$/.test(input.id??''))fail('invalid_provider_configuration');
 const allowed=[...COMMON,...(input.preset==='saml'?SAML:OIDC)];
 if(Object.keys(input).some(key=>!allowed.includes(key))||JSON.stringify(input).length>65536)fail('invalid_provider_configuration');
 if(input.label!==undefined&&(typeof input.label!=='string'||!input.label||input.label.length>60||/[\x00-\x1f\x7f]/.test(input.label)))fail('invalid_provider_configuration');
 const entries=Object.entries(input.subjectEmails??{});
 if(!input.subjectEmails||typeof input.subjectEmails!=='object'||Array.isArray(input.subjectEmails)||!entries.length||entries.length>200||entries.some(([subject,address])=>!subject||subject.length>255||/[\x00-\x1f\x7f]/.test(subject)||!email(address)))fail('reviewed_federation_subjects_required');
 let provider={...input,subjectEmails:Object.fromEntries(entries.map(([subject,address])=>[subject,email(address)])),revision:1};
 if(provider.preset==='saml') {
  if(provider.metadataUrl!==undefined&&provider.metadataXml!==undefined)fail('ambiguous_federation_metadata');
  const metadata=provider.metadataUrl!==undefined?await readFederationMetadata(ctx,provider.metadataUrl):provider.metadataXml!==undefined?parseFederationMetadata(ctx,provider.metadataXml):null;
  if(metadata) {
   for(const key of ['issuer','ssoUrl','certificates'])if(provider[key]!==undefined&&JSON.stringify(provider[key])!==JSON.stringify(metadata[key]))fail('federation_metadata_conflict');
   provider={...metadata,...provider,issuer:metadata.issuer,ssoUrl:metadata.ssoUrl,certificates:metadata.certificates};
  }
  delete provider.metadataUrl;delete provider.metadataXml;delete provider.nameIdFormats;
  return samlConfiguration(ctx,provider);
 }
 try {
  const preset=PRESETS[provider.preset];
  const issuer=preset?.issuer??(preset?.tenantIssuer?preset.tenantIssuer(provider.tenant):provider.issuer);
  if(provider.issuer!==undefined&&provider.issuer!==issuer)fail('invalid_provider_configuration');
  federationUrl(ctx,issuer);
  provider={...provider,issuer,redirectUri:`${ctx.issuer??ctx.origin}/auth/oidc/${provider.id}/callback`};
  const checked=configure({origin:ctx.origin,local:ctx.local,transactionSecret:ctx.secret,providers:[normalizeOidcProvider(ctx,provider)]}).providers[0];
  return {...provider,label:checked.label,tokenAuthMethod:checked.tokenAuthMethod};
 }catch{fail('invalid_provider_configuration');}
}
