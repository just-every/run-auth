// SAML HTTP-Redirect and HTTP-POST bindings: reading a message as it arrived,
// and sending one to a service provider's endpoint.
import {fail,utf8,random} from '../core.mjs';
import {canonical} from './xml.mjs';
import {signElement,signQuery} from './signing.mjs';
import {toBase64,fromBase64} from './der.mjs';
import {framedPage,FRAME_SOURCES} from '../page-frame.mjs';

export const BINDINGS={post:'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',redirect:'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'};
const MAX=262144;

async function inflate(bytes) {
 const reader=new Blob([bytes]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader(),parts=[];let size=0;
 try {
  for(;;){const {done,value}=await reader.read();if(done)break;size+=value.length;if(size>MAX)fail('invalid_saml_message');parts.push(value);}
 } catch(error) {reader.cancel().catch(()=>{});if(error?.message==='invalid_saml_message')throw error;fail('invalid_saml_message');}
 return new TextDecoder('utf-8',{fatal:true}).decode(await new Blob(parts).arrayBuffer());
}
async function deflate(text) {return new Uint8Array(await new Response(new Blob([utf8.encode(text)]).stream().pipeThrough(new CompressionStream('deflate-raw'))).arrayBuffer());}
const formDecode=raw=>{try{return decodeURIComponent(raw.replace(/\+/g,' '));}catch{return fail('invalid_saml_message');}};

// {kind, xml, relayState, binding, signature}: for Redirect, the signature and
// the exact octets it covers (the parameters as received, in protocol order).
export async function readMessage(request) {
 if(request.method==='GET') {
  const raw=new URL(request.url).search.slice(1);if(raw.length>MAX)fail('invalid_saml_message');
  const pairs=new Map();for(const part of raw.split('&')){const at=part.indexOf('=');const name=at<0?part:part.slice(0,at);if(pairs.has(name))fail('invalid_saml_message');pairs.set(name,at<0?'':part.slice(at+1));}
  const kind=['SAMLRequest','SAMLResponse'].find(k=>pairs.has(k))??fail('invalid_saml_message');
  if(pairs.has('SAMLRequest')&&pairs.has('SAMLResponse'))fail('invalid_saml_message');
  const xml=await inflate(fromBase64(formDecode(pairs.get(kind))));
  const relayState=pairs.has('RelayState')?formDecode(pairs.get('RelayState')):null;
  const signature=pairs.has('Signature')?{algorithm:formDecode(pairs.get('SigAlg')??''),value:fromBase64(formDecode(pairs.get('Signature'))),signed:utf8.encode([`${kind}=${pairs.get(kind)}`,...(pairs.has('RelayState')?[`RelayState=${pairs.get('RelayState')}`]:[]),`SigAlg=${pairs.get('SigAlg')??''}`].join('&'))}:null;
  if(relayState&&relayState.length>2048)fail('invalid_saml_message');
  return {kind,xml,relayState,binding:'redirect',signature};
 }
 if(request.method!=='POST'||!(request.headers.get('content-type')||'').startsWith('application/x-www-form-urlencoded'))fail('invalid_saml_message');
 const text=await request.text();if(text.length>MAX)fail('invalid_saml_message');
 const form=new URLSearchParams(text),kind=['SAMLRequest','SAMLResponse'].find(k=>form.has(k))??fail('invalid_saml_message');
 if(form.has('SAMLRequest')&&form.has('SAMLResponse'))fail('invalid_saml_message');
 // The binding sends plain base64; some service-provider libraries also deflate it.
 const bytes=fromBase64(form.get(kind)??''),plain=bytes.find(b=>![9,10,13,32,0xef,0xbb,0xbf].includes(b))===0x3c;
 let xml;try{xml=plain?new TextDecoder('utf-8',{fatal:true}).decode(bytes):await inflate(bytes);}catch(error){if(error?.message==='invalid_saml_message')throw error;fail('invalid_saml_message');}
 const relayState=form.get('RelayState');if(relayState&&relayState.length>2048)fail('invalid_saml_message');
 return {kind,xml,relayState,binding:'post',signature:null};
}

const escape=v=>String(v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
const noStore={'cache-control':'no-store','referrer-policy':'no-referrer','x-content-type-options':'nosniff'};

// endpoint {url, binding}; sign: whether the protocol message itself is signed.
export async function sendMessage(ctx,{kind,element,relayState,endpoint,digest,sign,headers={}}) {
 if(endpoint.binding==='redirect') {
  // A Redirect message carries its signature in the query, never in the XML.
  let query=`${kind}=${encodeURIComponent(toBase64(await deflate(canonical(element))))}${relayState?`&RelayState=${encodeURIComponent(relayState)}`:''}`;
  if(sign)query=await signQuery(ctx,query,digest);
  const url=new URL(endpoint.url);
  return new Response(null,{status:302,headers:{...noStore,...headers,location:`${url.href}${url.search?'&':'?'}${query}`}});
 }
 if(sign)await signElement(ctx,element,digest);
 const nonce=random(),target=new URL(endpoint.url);
 const body=framedPage('Continuing to the app',`<h1>Continuing to the app</h1><form method="post" action="${escape(target.href)}"><input type="hidden" name="${kind}" value="${toBase64(utf8.encode(canonical(element)))}">${relayState?`<input type="hidden" name="RelayState" value="${escape(relayState)}">`:''}<button type="submit">Continue</button></form><script nonce="${nonce}">document.forms[0].submit()</script>`);
 return new Response(body,{status:200,headers:{...noStore,...headers,'content-type':'text/html; charset=utf-8','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; script-src 'nonce-${nonce}'; form-action ${target.origin}; frame-ancestors 'none'; base-uri 'none'`}});
}

export const samlPage=(title,message,status=400,headers={},extra='')=>new Response(framedPage(title,`<h1>${escape(title)}</h1><p>${escape(message)}</p>${extra}`),{status,headers:{...noStore,...headers,'content-type':'text/html; charset=utf-8','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`}});
