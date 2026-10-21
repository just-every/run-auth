import {utf8} from '../core.mjs';
import {toBase64,fromBase64} from '../saml/der.mjs';
export const newSecret=()=>'whsec_'+toBase64(crypto.getRandomValues(new Uint8Array(32)));
export async function signature(secret,id,timestamp,body) {
 const key=await crypto.subtle.importKey('raw',fromBase64(secret.slice(6)),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return 'v1,'+toBase64(new Uint8Array(await crypto.subtle.sign('HMAC',key,utf8.encode(`${id}.${timestamp}.${body}`))));
}
