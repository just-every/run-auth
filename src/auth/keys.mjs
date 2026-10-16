import {generateKeyPair,exportJWK,importJWK,SignJWT} from 'jose';
import {b64,unb64,utf8,random,one,all,run,fail} from './core.mjs';
export const JWKS_CACHE_SECONDS=300;
export const TOKEN_SECONDS=300;
export const SIGNING_ALGORITHMS=['ES256','RS256'];
function signingAlgorithm(alg) {if(!SIGNING_ALGORITHMS.includes(alg))fail('unsupported_signing_algorithm');return alg;}
async function wrappingKey(ctx) { let bytes;try{bytes=/^[a-f0-9]{64}$/i.test(ctx.secret) ? Uint8Array.from(ctx.secret.match(/../g),v=>parseInt(v,16)) : unb64(ctx.secret);}catch{fail('signing_secret_required',503);}if(bytes.length!==32)fail('signing_secret_required',503);return crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['encrypt','decrypt']); }
async function encrypt(ctx,kid,value) {const iv=crypto.getRandomValues(new Uint8Array(12));const encrypted=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:utf8.encode(kid)},await wrappingKey(ctx),utf8.encode(JSON.stringify(value)));return `${b64(iv)}.${b64(encrypted)}`;}
async function decrypt(ctx,row) {const [iv,data]=row.encrypted_private.split('.');return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(iv),additionalData:utf8.encode(row.kid)},await wrappingKey(ctx),unb64(data))));}
// Other installation secrets (SAML signing keys, connector credentials) under the
// same AUTH_ENCRYPTION_KEY, each bound to its own label.
export const seal=(ctx,label,value)=>encrypt(ctx,label,value);
export const unseal=(ctx,label,sealed)=>decrypt(ctx,{kid:label,encrypted_private:sealed});
// With a guard (an acting session's authority) the key is stored only while it holds; null otherwise.
export async function stageSigningKey(ctx,alg='ES256',guard=null) {
 signingAlgorithm(alg);
 const {publicKey,privateKey}=await generateKeyPair(alg,{extractable:true}),kid=random(),now=ctx.now();
 const jwk={...await exportJWK(publicKey),kid,use:'sig',alg};
 const stored=await run(ctx,`INSERT INTO auth_signing_keys(kid,public_jwk,encrypted_private,published_at,use_after) SELECT ?,?,?,?,? WHERE ${guard?guard.clause:'1'}`,kid,JSON.stringify(jwk),await encrypt(ctx,kid,await exportJWK(privateKey)),now,now+JWKS_CACHE_SECONDS*1000,...(guard?guard.args:[]));
 return stored.meta.changes?{kid,useAfter:now+JWKS_CACHE_SECONDS*1000}:null;
}
export async function activeSigningKey(ctx,alg='ES256') {
 signingAlgorithm(alg);
 const row=await one(ctx,"SELECT * FROM auth_signing_keys WHERE json_extract(public_jwk,'$.alg')=? AND use_after<=? AND retire_at IS NULL ORDER BY use_after DESC,kid DESC LIMIT 1",alg,ctx.now());if(!row)fail('signing_key_not_ready',503);return row;
}
export async function retireSigningKey(ctx,kid,guard=null) {
 const row=await one(ctx,'SELECT public_jwk FROM auth_signing_keys WHERE kid=?',kid);if(!row)fail('signing_key_not_found',404);
 const active=await activeSigningKey(ctx,JSON.parse(row.public_jwk).alg);if(active.kid===kid)fail('replacement_key_required',409);
 return (await run(ctx,`UPDATE auth_signing_keys SET retire_at=? WHERE kid=? AND retire_at IS NULL AND ${guard?guard.clause:'1'}`,ctx.now()+TOKEN_SECONDS*1000,kid,...(guard?guard.args:[]))).meta.changes;
}
export async function jwks(ctx) {await run(ctx,'DELETE FROM auth_signing_keys WHERE retire_at IS NOT NULL AND retire_at<=?',ctx.now());return {keys:(await all(ctx,'SELECT public_jwk FROM auth_signing_keys WHERE retire_at IS NULL OR retire_at>?',ctx.now())).map(r=>JSON.parse(r.public_jwk))};}
// published: sign with the newest key already in the JWKS, even before its cache
// lifetime has passed. Only for documents verified long after signing (grant maps).
export async function signToken(ctx,claims,{alg='ES256',typ='JWT',expiresAt=Math.floor(ctx.now()/1000)+TOKEN_SECONDS,published=false}={}) {
 const row=published?await one(ctx,"SELECT * FROM auth_signing_keys WHERE json_extract(public_jwk,'$.alg')=? AND retire_at IS NULL ORDER BY published_at DESC,kid DESC LIMIT 1",alg)||fail('signing_key_not_ready',503):await activeSigningKey(ctx,alg);
 const key=await importJWK(await decrypt(ctx,row),alg);
 return new SignJWT(claims).setProtectedHeader({alg,kid:row.kid,typ}).setIssuer(ctx.origin).setIssuedAt(Math.floor(ctx.now()/1000)).setExpirationTime(expiresAt).sign(key);
}
export async function pairwiseSubject(ctx,sector,person) {
 await run(ctx,"INSERT OR IGNORE INTO auth_settings(key,value) VALUES('pairwise_key',?)",random());
 const row=await one(ctx,"SELECT value FROM auth_settings WHERE key='pairwise_key'");
 const key=await crypto.subtle.importKey('raw',unb64(row.value),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 const candidate=b64(await crypto.subtle.sign('HMAC',key,utf8.encode(JSON.stringify([sector,person]))));
 await run(ctx,'INSERT OR IGNORE INTO auth_subjects(sector_id,person_id,subject) VALUES(?,?,?)',sector,person,candidate);
 return (await one(ctx,'SELECT subject FROM auth_subjects WHERE sector_id=? AND person_id=?',sector,person)).subject;
}

export async function ensureSigningKey(ctx) {
 let staged=null;
 for(const alg of SIGNING_ALGORITHMS)if(!await one(ctx,"SELECT kid FROM auth_signing_keys WHERE json_extract(public_jwk,'$.alg')=? AND retire_at IS NULL LIMIT 1",alg))staged=await stageSigningKey(ctx,alg);
 return staged;
}
