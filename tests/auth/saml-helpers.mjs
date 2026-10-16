import assert from 'node:assert/strict';
import {inflateRawSync} from 'node:zlib';
import {SAML} from '@node-saml/node-saml';
import {openRuntime,emailSession} from './runtime.mjs';
import {passkeyPerson} from './agents-helpers.mjs';
import {selfSignedCertificate,toBase64} from '../../src/auth/saml/der.mjs';

const pem=(label,b64)=>`-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
// A service provider's own key and self-signed certificate (the SP is the far edge).
export async function spCredentials(name) {
 const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const spki=new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey)),der=await selfSignedCertificate(pair.privateKey,spki,name,Date.now()-60000,Date.now()+86400000);
 return {key:pem('PRIVATE KEY',toBase64(new Uint8Array(await crypto.subtle.exportKey('pkcs8',pair.privateKey)))),cert:pem('CERTIFICATE',toBase64(der)),certBase64:toBase64(der)};
}

// Auth with an owner (passkey, fresh local email) and an employee, on the real clock
// the service provider library checks assertions against.
export async function samlInstall(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.now();
 r.owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 await r.person('ada','ada@example.com');r.ada=await emailSession(r,'ada@example.com');
 await r.person('bob','bob@example.com');r.bob=await emailSession(r,'bob@example.com');
 r.tick=()=>{r.now=Date.now();};
 r.admin=async(path,data)=>{r.tick();return r.call('/api/auth/'+path,{method:'POST',data,cookie:r.owner.cookie});};
 return r;
}
export async function idpCertificates(r) {
 const xml=await (await r.call('/saml/metadata')).text();
 return [...xml.matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g)].map(m=>pem('CERTIFICATE',m[1]));
}
export function serviceProvider(r,{entity,idpCerts,sp,decryption,binding='HTTP-Redirect',format=null,response=true,assertion=true,algorithm='sha256'}) {
 return new SAML({entryPoint:`${r.origin}/saml/sso`,issuer:entity,audience:entity,callbackUrl:`${entity}/acs`,logoutUrl:`${r.origin}/saml/slo`,logoutCallbackUrl:`${entity}/slo`,
  idpCert:idpCerts,idpIssuer:`${r.origin}/saml/metadata`,privateKey:sp?.key,publicCert:sp?.cert,signatureAlgorithm:algorithm,digestAlgorithm:algorithm,decryptionPvk:decryption?.key,
  wantAuthnResponseSigned:response,wantAssertionsSigned:assertion,identifierFormat:format,authnRequestBinding:binding,validateInResponseTo:'always',disableRequestedAuthnContext:true,acceptedClockSkewMs:2000});
}
export const metadataOf=(saml,sp,decryption)=>saml.generateServiceProviderMetadata(decryption?.cert??null,sp?.cert??null);
export async function addApp(r,data) {
 const response=await r.admin('company-apps/create',data);assert.equal(response.status,201,await response.clone().text());
 const app=await response.json();
 for(const id of data.assign??['ada'])assert.equal((await r.admin('company-apps/assign',{appId:app.id,principalType:'person',principalId:id})).status,200);
 return app;
}

const decode=v=>v.replace(/&quot;/g,'"').replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
export const field=(html,name)=>{const m=html.match(new RegExp(`name="${name}" value="([^"]*)"`));return m?decode(m[1]):null;};
export const formAction=html=>decode(html.match(/<form method="post" action="([^"]*)"/)?.[1]??'');
const local=url=>{const u=new URL(url);return u.pathname+u.search;};

// The browser leg: follow Auth's redirects (same origin) until a page or a redirect off Auth.
export async function browse(r,path,{cookie,method='GET',form}={}) {
 r.tick();
 let response=await r.call(path,{method,cookie,form,headers:form?{origin:'https://sp.example.com'}:{}});
 for(let hops=0;[302,303].includes(response.status)&&hops<5;hops++) {
  const location=new URL(response.headers.get('location'),r.origin);if(location.origin!==r.origin)break;
  const parked=response.headers.getSetCookie().map(c=>c.split(';')[0]).join('; ');
  response=await r.call(location.pathname+location.search,{cookie:[cookie,parked].filter(Boolean).join('; ')});
 }
 return response;
}
// SP-initiated sign-in: the SP's own request, carried by the browser to Auth.
export async function signIn(r,saml,cookie,binding='HTTP-Redirect') {
 let response;
 if(binding==='HTTP-POST') {
  const html=await saml.getAuthorizeFormAsync('relay-1');
  response=await browse(r,'/saml/sso',{cookie,method:'POST',form:{SAMLRequest:field(html,'SAMLRequest'),RelayState:field(html,'RelayState')}});
 } else response=await browse(r,local(await saml.getAuthorizeUrlAsync('relay-1',undefined,{})),{cookie});
 return response;
}
export async function posted(response) {
 const html=await response.text();assert.equal(response.status,200,html.match(/refused \(([^)]+)\)/)?.[1]??html.match(/<h1>([^<]+)/)?.[1]??`${response.status} ${response.headers.get('location')}`);
 return {html,action:formAction(html),SAMLResponse:field(html,'SAMLResponse'),SAMLRequest:field(html,'SAMLRequest'),RelayState:field(html,'RelayState')};
}
export const inflate=value=>inflateRawSync(Buffer.from(value,'base64')).toString('utf8');
export const xmlOf=value=>Buffer.from(value,'base64').toString('utf8');
