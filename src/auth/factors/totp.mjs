import {utf8,fail} from '../core.mjs';
const ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function encodeSecret(bytes) {
 let bits=0,value=0,out='';
 for(const byte of bytes){value=(value<<8)|byte;bits+=8;while(bits>=5){out+=ALPHABET[(value>>>(bits-5))&31];bits-=5;}}
 if(bits)out+=ALPHABET[(value<<(5-bits))&31];
 return out;
}
function decodeSecret(secret) {
 let bits=0,value=0;const out=[];
 for(const char of secret){const n=ALPHABET.indexOf(char);if(n<0)fail('invalid_factor');value=(value<<5)|n;bits+=5;if(bits>=8){out.push((value>>>(bits-8))&255);bits-=8;}}
 return Uint8Array.from(out);
}
export async function totp(secret,step) {
 const counter=new Uint8Array(8);new DataView(counter.buffer).setBigUint64(0,BigInt(step));
 const key=await crypto.subtle.importKey('raw',decodeSecret(secret),{name:'HMAC',hash:'SHA-1'},false,['sign']);
 const digest=new Uint8Array(await crypto.subtle.sign('HMAC',key,counter)),offset=digest[19]&15;
 const number=((digest[offset]&127)*0x1000000+(digest[offset+1]<<16)+(digest[offset+2]<<8)+digest[offset+3])%1000000;
 return String(number).padStart(6,'0');
}
export async function matchingStep(secret,code,now,lastStep=-1) {
 if(typeof code!=='string'||!/^\d{6}$/.test(code))fail('invalid_factor_code',403);
 const current=Math.floor(now/30000);
 for(const step of [current,current-1,current+1])if(step>lastStep) {
  const expected=utf8.encode(await totp(secret,step)),actual=utf8.encode(code);let difference=0;
  for(let i=0;i<6;i++)difference|=expected[i]^actual[i];
  if(!difference)return step;
 }
 fail('invalid_factor_code',403);
}
