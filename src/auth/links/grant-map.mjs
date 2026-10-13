// The signed grant map an export carries: every app sector, each person's
// pairwise subject there, and former subjects kept from move-in. It is signed
// with Auth's own ES256 key, so a new provider can verify it against this
// issuer's published JWKS before re-binding anyone. It names no secret.
import {random,all,one,run} from '../core.mjs';
import {signToken,ensureSigningKey} from '../keys.mjs';

export async function rememberIssuer(ctx) {
 await run(ctx,"INSERT INTO auth_settings(key,value) VALUES('issuer',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE value!=excluded.value",ctx.origin);
}
export async function writeGrantMap(ctx) {
 const [clients,subjects,former]=await Promise.all([
  all(ctx,'SELECT id,origin,sector_id,disabled_at FROM auth_clients ORDER BY sector_id'),
  all(ctx,'SELECT s.sector_id,s.person_id,s.subject,p.email FROM auth_subjects s JOIN oa_operators p ON p.id=s.person_id ORDER BY s.sector_id,s.person_id'),
  all(ctx,'SELECT f.source_system,f.subject,f.person_id,p.email FROM auth_former_subjects f JOIN oa_operators p ON p.id=f.person_id ORDER BY f.source_system,f.subject'),
 ]);
 const map={typ:'rer-grant-map',sectors:clients.map(c=>({sector_id:c.sector_id,client_id:c.id,origin:c.origin,removed:Boolean(c.disabled_at),subjects:subjects.filter(s=>s.sector_id===c.sector_id).map(s=>({person:s.person_id,email:s.email,sub:s.subject}))})),
  former_subjects:former.map(f=>({source:f.source_system,subject:f.subject,person:f.person_id,email:f.email}))};
 await ensureSigningKey(ctx);
 const now=Math.floor(ctx.now()/1000),jws=await signToken(ctx,{...map,aud:ctx.origin,jti:random()},{typ:'grant-map+jwt',expiresAt:now+365*86400,published:true});
 const id=random();
 await run(ctx,'INSERT INTO auth_grant_maps(id,issuer,created_at,map) VALUES(?,?,?,?)',id,ctx.origin,ctx.now(),jws);
 return {id,sectors:map.sectors.length,subjects:subjects.length,former:former.length};
}
export const issuerOf=async ctx=>(await one(ctx,"SELECT value FROM auth_settings WHERE key='issuer'"))?.value??null;
