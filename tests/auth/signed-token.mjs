import {SignJWT,importJWK} from 'jose';

// Security tests need genuinely signed invalid claims, not a broken signature
// that would fail before audience, lifetime or session validation is reached.
export async function signedToken(context,claims,options={},issuer=context.origin) {
 const alg=options.alg||'ES256';
 const row=await context.db.prepare("SELECT * FROM auth_signing_keys WHERE json_extract(public_jwk,'$.alg')=? AND use_after<=? AND retire_at IS NULL ORDER BY use_after DESC,kid DESC LIMIT 1").bind(alg,context.now()).first();
 const bytes=Uint8Array.from(context.secret.match(/../g),v=>parseInt(v,16));
 const wrapping=await crypto.subtle.importKey('raw',bytes,'AES-GCM',false,['decrypt']);
 const decode=value=>Uint8Array.from(atob(value.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
 const [iv,data]=row.encrypted_private.split('.');
 const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:decode(iv),additionalData:new TextEncoder().encode(row.kid)},wrapping,decode(data));
 const key=await importJWK(JSON.parse(new TextDecoder().decode(clear)),alg);
 return new SignJWT({...claims,iss:issuer}).setProtectedHeader({alg,kid:row.kid,typ:options.typ||'at+jwt'}).sign(key);
}
