// Auth's SAML signing certificates and the XML signature and encryption it
// applies. Certificates roll over with overlap: a staged certificate is
// published in metadata before it signs, and the previous one stays published
// until an owner retires it.
import {random,one,all,run,fail,utf8,b64} from '../core.mjs';
import {seal,unseal} from '../keys.mjs';
import {selfSignedCertificate,certificateKey,certificateValidity,toBase64,fromBase64} from './der.mjs';
import {el,canonical,child,children,attr,textOf,NS} from './xml.mjs';

const YEAR=365*86400000;
export const DIGESTS={
 sha256:{hash:'SHA-256',digest:'http://www.w3.org/2001/04/xmlenc#sha256',signature:'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'},
 sha512:{hash:'SHA-512',digest:'http://www.w3.org/2001/04/xmlenc#sha512',signature:'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512'},
 sha1:{hash:'SHA-1',digest:'http://www.w3.org/2000/09/xmldsig#sha1',signature:'http://www.w3.org/2000/09/xmldsig#rsa-sha1'},
};
const EXC='http://www.w3.org/2001/10/xml-exc-c14n#',ENVELOPED='http://www.w3.org/2000/09/xmldsig#enveloped-signature';
export const ENCRYPTIONS={'aes256-gcm':{uri:'http://www.w3.org/2009/xmlenc11#aes256-gcm',name:'AES-GCM',length:256,iv:12},'aes128-cbc':{uri:'http://www.w3.org/2001/04/xmlenc#aes128-cbc',name:'AES-CBC',length:128,iv:16}};
const algorithmOf=uri=>Object.entries(DIGESTS).find(([,d])=>d.signature===uri)?.[0]??null;
const digestOf=uri=>Object.entries(DIGESTS).find(([,d])=>d.digest===uri)?.[0]??null;

// guard: the acting session's authority; nothing is stored when it no longer holds.
export async function stageSamlKey(ctx,guard=null,state='next') {
 const pair=await crypto.subtle.generateKey({name:'RSASSA-PKCS1-v1_5',modulusLength:2048,publicExponent:new Uint8Array([1,0,1]),hash:'SHA-256'},true,['sign','verify']);
 const spki=new Uint8Array(await crypto.subtle.exportKey('spki',pair.publicKey)),pkcs8=b64(await crypto.subtle.exportKey('pkcs8',pair.privateKey));
 const now=ctx.now(),kid=random(),cert=toBase64(await selfSignedCertificate(pair.privateKey,spki,`${new URL(ctx.origin).hostname} SAML signing`,now-60000,now+5*YEAR));
 const stored=await run(ctx,`INSERT INTO auth_saml_keys(kid,certificate,encrypted_private,state,created_at,activated_at) SELECT ?,?,?,?,?,? WHERE ${guard?guard.clause:'1'}`,kid,cert,await seal(ctx,'saml:'+kid,pkcs8),state,now,state==='active'?now:null,...(guard?guard.args:[]));
 return stored.meta.changes?{kid,certificate:cert,state}:null;
}
export async function ensureSamlKey(ctx) {
 if(!await one(ctx,"SELECT kid FROM auth_saml_keys WHERE state='active'"))await stageSamlKey(ctx,null,'active').catch(async error=>{if(!await one(ctx,"SELECT kid FROM auth_saml_keys WHERE state='active'"))throw error;});
 return one(ctx,"SELECT * FROM auth_saml_keys WHERE state='active' ORDER BY activated_at DESC LIMIT 1");
}
// Published in metadata: everything not retired, the signing certificate first.
export const publishedKeys=ctx=>all(ctx,"SELECT kid,certificate,state,created_at,activated_at FROM auth_saml_keys WHERE state IN ('active','next','previous') ORDER BY CASE state WHEN 'active' THEN 0 WHEN 'next' THEN 1 ELSE 2 END,created_at DESC");
export async function activateSamlKey(ctx,kid,guard) {
 const next=await one(ctx,"SELECT kid FROM auth_saml_keys WHERE kid=? AND state='next'",kid)||fail('saml_key_not_staged',404);
 const g=guard.clause,ga=guard.args;
 const [, done]=await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_saml_keys SET state='previous' WHERE state='active' AND EXISTS(SELECT 1 FROM auth_saml_keys WHERE kid=? AND state='next') AND ${g}`).bind(next.kid,...ga),
  ctx.db.prepare(`UPDATE auth_saml_keys SET state='active',activated_at=? WHERE kid=? AND state='next' AND ${g}`).bind(ctx.now(),next.kid,...ga),
 ]);
 return done.meta.changes;
}
export async function retireSamlKey(ctx,kid,guard) {
 const row=await one(ctx,'SELECT state FROM auth_saml_keys WHERE kid=?',kid)||fail('saml_key_not_found',404);
 if(row.state==='active')fail('replacement_key_required',409);
 return (await run(ctx,`UPDATE auth_saml_keys SET state='retired',retired_at=? WHERE kid=? AND state IN ('next','previous') AND ${guard.clause}`,ctx.now(),kid,...guard.args)).meta.changes;
}

async function validSigningKey(ctx) {
 const key=await ensureSamlKey(ctx),validity=certificateValidity(key.certificate);
 if(validity.notBefore>ctx.now()||validity.notAfter<=ctx.now())fail('saml_signing_certificate_expired',503);
 return key;
}

async function privateKey(ctx,row,algorithm) {
 const pkcs8=await unseal(ctx,'saml:'+row.kid,row.encrypted_private);
 return crypto.subtle.importKey('pkcs8',Uint8Array.from(atob(pkcs8.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0)),{name:'RSASSA-PKCS1-v1_5',hash:DIGESTS[algorithm].hash},false,['sign']);
}
const digest=async(algorithm,text)=>toBase64(new Uint8Array(await crypto.subtle.digest(DIGESTS[algorithm].hash,utf8.encode(text))));

// Enveloped signature over `element` (it must carry an ID), placed after its Issuer.
export async function signElement(ctx,element,algorithm) {
 const key=await validSigningKey(ctx),id=attr(element,'ID'),d=DIGESTS[algorithm];
 const signedInfo=el('ds:SignedInfo',{},[el('ds:CanonicalizationMethod',{Algorithm:EXC}),el('ds:SignatureMethod',{Algorithm:d.signature}),el('ds:Reference',{URI:'#'+id},[el('ds:Transforms',{},[el('ds:Transform',{Algorithm:ENVELOPED}),el('ds:Transform',{Algorithm:EXC})]),el('ds:DigestMethod',{Algorithm:d.digest}),el('ds:DigestValue',{},[await digest(algorithm,canonical(element))])])]);
 const value=new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',await privateKey(ctx,key,algorithm),utf8.encode(canonical(signedInfo))));
 const signature=el('ds:Signature',{},[signedInfo,el('ds:SignatureValue',{},[toBase64(value)]),el('ds:KeyInfo',{},[el('ds:X509Data',{},[el('ds:X509Certificate',{},[key.certificate])])])]);
 const at=element.children.findIndex(c=>typeof c!=='string'&&c.local==='Issuer')+1;
 element.children.splice(at,0,signature);
 return element;
}

// HTTP-Redirect binding: the signature covers the exact query octets.
export async function signQuery(ctx,query,algorithm) {
 const key=await validSigningKey(ctx),signed=`${query}&SigAlg=${encodeURIComponent(DIGESTS[algorithm].signature)}`;
 return `${signed}&Signature=${encodeURIComponent(toBase64(new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',await privateKey(ctx,key,algorithm),utf8.encode(signed)))))}`;
}

const verifyKey=(cert,algorithm)=>crypto.subtle.importKey('spki',certificateKey(cert).spki,{name:'RSASSA-PKCS1-v1_5',hash:DIGESTS[algorithm].hash},false,['verify']).catch(()=>fail('unsupported_certificate_key'));
const allowed=(algorithm,sha1)=>algorithm&&(algorithm!=='sha1'||sha1);
export async function verifyBytes(certs,algorithmUri,bytes,signature,sha1) {
 const algorithm=algorithmOf(algorithmUri);if(!allowed(algorithm,sha1))return false;
 for(const cert of certs)if(await crypto.subtle.verify('RSASSA-PKCS1-v1_5',await verifyKey(cert,algorithm),signature,bytes))return true;
 return false;
}

// An enveloped signature directly under the root, referencing the root by ID.
// Anything else (wrapped or detached elements, other transforms) fails closed.
export async function verifyEnveloped(root,certs,sha1) {
 const signatures=children(root,'Signature',NS.ds);if(signatures.length!==1)return false;
 const signature=signatures[0],info=child(signature,'SignedInfo',NS.ds),c14n=child(info,'CanonicalizationMethod',NS.ds);
 if(!info||attr(c14n,'Algorithm')!==EXC)return false;
 const references=children(info,'Reference',NS.ds),id=attr(root,'ID');if(references.length!==1||!id||attr(references[0],'URI')!=='#'+id)return false;
 const transforms=children(child(references[0],'Transforms',NS.ds)??{children:[]},'Transform',NS.ds);
 if(transforms.length!==2||attr(transforms[0],'Algorithm')!==ENVELOPED||attr(transforms[1],'Algorithm')!==EXC)return false;
 const prefixes=node=>(attr(child(node,'InclusiveNamespaces','http://www.w3.org/2001/10/xml-exc-c14n#'),'PrefixList')||'').split(/\s+/).filter(Boolean);
 const algorithm=digestOf(attr(child(references[0],'DigestMethod',NS.ds),'Algorithm'));if(!allowed(algorithm,sha1))return false;
 if(await digest(algorithm,canonical(root,{omit:signature,inclusive:prefixes(transforms[1])}))!==textOf(child(references[0],'DigestValue',NS.ds)).replace(/\s+/g,''))return false;
 const value=fromBase64(textOf(child(signature,'SignatureValue',NS.ds)));
 return verifyBytes(certs,attr(child(info,'SignatureMethod',NS.ds),'Algorithm'),utf8.encode(canonical(info,{inclusive:prefixes(c14n)})),value,sha1);
}

// EncryptedAssertion for the service provider's RSA certificate (RSA-OAEP key transport).
export async function encryptElement(xml,cert,method) {
 const m=ENCRYPTIONS[method]??fail('unsupported_encryption');
 const key=await crypto.subtle.generateKey({name:m.name,length:m.length},true,['encrypt']),iv=crypto.getRandomValues(new Uint8Array(m.iv));
 const sealed=new Uint8Array(await crypto.subtle.encrypt({name:m.name,iv},key,utf8.encode(xml)));
 const transport=await crypto.subtle.importKey('spki',certificateKey(cert).spki,{name:'RSA-OAEP',hash:'SHA-1'},false,['encrypt']).catch(()=>fail('unsupported_certificate_key'));
 const wrapped=new Uint8Array(await crypto.subtle.encrypt({name:'RSA-OAEP'},transport,new Uint8Array(await crypto.subtle.exportKey('raw',key))));
 const cipher=new Uint8Array(iv.length+sealed.length);cipher.set(iv);cipher.set(sealed,iv.length);
 return el('xenc:EncryptedData',{Type:'http://www.w3.org/2001/04/xmlenc#Element'},[
  el('xenc:EncryptionMethod',{Algorithm:m.uri}),
  el('ds:KeyInfo',{},[el('xenc:EncryptedKey',{},[el('xenc:EncryptionMethod',{Algorithm:'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p'},[el('ds:DigestMethod',{Algorithm:DIGESTS.sha1.digest})]),el('xenc:CipherData',{},[el('xenc:CipherValue',{},[toBase64(wrapped)])])])]),
  el('xenc:CipherData',{},[el('xenc:CipherValue',{},[toBase64(cipher)])]),
 ]);
}
