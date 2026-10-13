import {generateKeyPairSync,createHash,sign,randomBytes} from 'node:crypto';
const enc=v=>Buffer.from(v).toString('base64url');
const digest=v=>createHash('sha256').update(v).digest();
function cbor(value) {
 const size=(major,n)=>n<24?Buffer.from([major*32+n]):n<256?Buffer.from([major*32+24,n]):Buffer.from([major*32+25,n>>8,n&255]);
 if(typeof value==='number')return size(value<0?1:0,value<0?-1-value:value);
 if(typeof value==='string'){const v=Buffer.from(value);return Buffer.concat([size(3,v.length),v]);}
 if(Buffer.isBuffer(value))return Buffer.concat([size(2,value.length),value]);
 const entries=[...value];return Buffer.concat([size(5,entries.length),...entries.flatMap(([k,v])=>[cbor(k),cbor(v)])]);
}
// A real software authenticator at the hardware boundary: genuine EC signatures,
// COSE public key and WebAuthn attestation, verified by the production library.
export function authenticator(origin='https://auth.example.com') {
 const {publicKey,privateKey}=generateKeyPairSync('ec',{namedCurve:'prime256v1'}),jwk=publicKey.export({format:'jwk'}),id=randomBytes(32),rp=digest(new URL(origin).hostname);let count=0;
 return {id:enc(id),register(options,override={}) {
  const client=Buffer.from(JSON.stringify({type:'webauthn.create',challenge:options.challenge,origin,...override}));
  const key=cbor(new Map([[1,2],[3,-7],[-1,1],[-2,Buffer.from(jwk.x,'base64url')],[-3,Buffer.from(jwk.y,'base64url')]]));
  const auth=Buffer.concat([rp,Buffer.from([0x45]),Buffer.alloc(4),Buffer.alloc(16),Buffer.from([0,id.length]),id,key]);
  return {id:enc(id),rawId:enc(id),type:'public-key',response:{clientDataJSON:enc(client),attestationObject:enc(cbor(new Map([['fmt','none'],['attStmt',new Map()],['authData',auth]]))),transports:['internal']},clientExtensionResults:{}};
 },authenticate(options,override={}) {
  count++;const client=Buffer.from(JSON.stringify({type:'webauthn.get',challenge:options.challenge,origin,...override})),counter=Buffer.alloc(4);counter.writeUInt32BE(count);
  const auth=Buffer.concat([rp,Buffer.from([0x05]),counter]);
  return {id:enc(id),rawId:enc(id),type:'public-key',response:{clientDataJSON:enc(client),authenticatorData:enc(auth),signature:enc(sign('sha256',Buffer.concat([auth,digest(client)]),privateKey))},clientExtensionResults:{}};
 }};
}
export async function register(r,cookie,key=authenticator(r.origin)) {
 const offered=await r.call('/auth/passkeys/register/options',{method:'POST',cookie,data:{}});const transaction=await offered.json();
 const result=await r.call('/auth/passkeys/register/verify',{method:'POST',cookie:`${cookie}; ${offered.headers.get('set-cookie').split(';')[0]}`,data:{transaction:transaction.transaction,response:key.register(transaction.options)}});
 if(result.status!==200)throw new Error(`register ${result.status}: ${await result.text()}`);
 return {key,cookie:result.headers.get('set-cookie').split(';')[0]};
}
export async function authenticate(r,key) {
 const response=await r.call('/auth/passkeys/authenticate/options',{method:'POST',data:{}}),tx=await response.json();
 return {response:await r.call('/auth/passkeys/authenticate/verify',{method:'POST',cookie:response.headers.get('set-cookie').split(';')[0],data:{transaction:tx.transaction,response:key.authenticate(tx.options)}}),binding:response.headers.get('set-cookie').split(';')[0]};
}
