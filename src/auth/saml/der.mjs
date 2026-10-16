// X.509 for SAML: a self-signed RSA certificate around Auth's signing key, and
// the public key read back out of a service provider's certificate.
import {fail,utf8} from '../core.mjs';

const concat=parts=>{const out=new Uint8Array(parts.reduce((n,p)=>n+p.length,0));let at=0;for(const p of parts){out.set(p,at);at+=p.length;}return out;};
const length=n=>n<128?[n]:n<256?[0x81,n]:n<65536?[0x82,n>>8,n&255]:[0x83,n>>16,(n>>8)&255,n&255];
const tlv=(tag,bytes)=>concat([new Uint8Array([tag,...length(bytes.length)]),bytes]);
const seq=(...parts)=>tlv(0x30,concat(parts));
const integer=bytes=>tlv(0x02,bytes[0]&0x80?concat([new Uint8Array([0]),bytes]):bytes);
function oid(value) {
 const [a,b,...rest]=value.split('.').map(Number),out=[a*40+b];
 for(const n of rest){const bytes=[n&127];for(let v=n>>>7;v;v>>>=7)bytes.unshift((v&127)|128);out.push(...bytes);}
 return tlv(0x06,new Uint8Array(out));
}
const time=ms=>{const d=new Date(ms),y=d.getUTCFullYear(),s=d.toISOString().replace(/[-:T]/g,'').slice(0,14)+'Z';return y<2050?tlv(0x17,utf8.encode(s.slice(2))):tlv(0x18,utf8.encode(s));};
const name=cn=>seq(tlv(0x31,seq(oid('2.5.4.3'),tlv(0x0c,utf8.encode(cn)))));
const SHA256_RSA=seq(oid('1.2.840.113549.1.1.11'),new Uint8Array([5,0]));

export const toBase64=bytes=>{let s='';for(let i=0;i<bytes.length;i+=32768)s+=String.fromCharCode(...bytes.subarray(i,i+32768));return btoa(s);};
export const fromBase64=value=>{try{return Uint8Array.from(atob(String(value).replace(/\s+/g,'')),c=>c.charCodeAt(0));}catch{return fail('invalid_certificate');}};

export async function selfSignedCertificate(privateKey,spki,commonName,notBefore,notAfter) {
 const serial=crypto.getRandomValues(new Uint8Array(16));serial[0]&=0x7f;serial[0]|=0x01;
 const tbs=seq(tlv(0xa0,integer(new Uint8Array([2]))),integer(serial),SHA256_RSA,name(commonName),seq(time(notBefore),time(notAfter)),name(commonName),spki);
 const signature=new Uint8Array(await crypto.subtle.sign('RSASSA-PKCS1-v1_5',privateKey,tbs));
 return seq(tbs,SHA256_RSA,tlv(0x03,concat([new Uint8Array([0]),signature])));
}

function read(bytes,at) {
 const tag=bytes[at];let size=bytes[at+1],head=2;
 if(tag===undefined||size===undefined)fail('invalid_certificate');
 if(size&0x80){const n=size&0x7f;if(!n||n>3)fail('invalid_certificate');size=0;for(let i=0;i<n;i++)size=size*256+bytes[at+2+i];head+=n;}
 if(at+head+size>bytes.length)fail('invalid_certificate');
 return {tag,start:at,body:at+head,end:at+head+size};
}
const items=(bytes,node)=>{const out=[];for(let at=node.body;at<node.end;){const n=read(bytes,at);out.push(n);at=n.end;}return out;};

// Base64 DER (PEM armour and whitespace allowed) -> {der, spki} for an RSA key.
export function certificateKey(value) {
 const der=fromBase64(String(value||'').replace(/-----(BEGIN|END) CERTIFICATE-----/g,''));
 if(der.length<64||der.length>16384)fail('invalid_certificate');
 const cert=read(der,0);if(cert.tag!==0x30||cert.end!==der.length)fail('invalid_certificate');
 const tbs=items(der,items(der,cert)[0]??fail('invalid_certificate')),fields=tbs[0]?.tag===0xa0?tbs.slice(1):tbs,spki=fields[5]??fail('invalid_certificate');
 if(spki.tag!==0x30)fail('invalid_certificate');
 return {der,base64:toBase64(der),spki:der.slice(spki.start,spki.end)};
}
