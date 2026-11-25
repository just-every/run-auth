import {test} from 'node:test';
import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {createHash,randomBytes} from 'node:crypto';
import {join} from 'node:path';
import {fileURLToPath} from 'node:url';
import {openApp,cookieOf} from './runtime.mjs';

const root=fileURLToPath(new URL('../../',import.meta.url));
// What `rer signin` writes through Cloudflare's D1 API: a one-time grant for the claimed owner, stored as the token's digest.
function mintOwnerSignin(app) {
 const token=randomBytes(32).toString('base64url'),digest=createHash('sha256').update(`owner-signin\0${token}`).digest('hex'),now=Date.now();
 const sql=`INSERT INTO oa_owner_signins(id,token_hash,operator_id,operator_version,created_at,expires_at) SELECT '${crypto.randomUUID()}','${digest}',o.id,o.version,${now},${now+900_000} FROM oa_operators o LEFT JOIN oa_bootstrap b ON b.claim_id=o.id WHERE o.role='owner' AND o.status='active' ORDER BY b.claim_id IS NULL, o.created_at, o.id LIMIT 1`;
 execFileSync(process.execPath,[join(root,'node_modules/wrangler/bin/wrangler.js'),'d1','execute','DB','--local','--persist-to',join(app.directory,'.wrangler/state'),'--config',join(root,'dist/server/wrangler.json'),'--command',sql],{stdio:'ignore',env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false'}});
 return token;
}

test('mail off: sign-in mail is refused with mail_off and the owner signs in once with the rer signin link',async t=>{
 const app=await openApp({mailOff:true});t.after(()=>app.close());
 await app.claim();
 const requested=await app.post('/auth/identity/email/request',{email:app.vars.OWNER_EMAIL,returnTo:'/app'});
 assert.equal(requested.status,503);assert.equal((await requested.json()).error,'mail_off');
 await app.pause();const token=mintOwnerSignin(app);await app.resume();
 const confirm=await app.get(`/auth/owner-signin?token=${token}`);assert.equal(confirm.status,200);
 const signin=()=>fetch(app.origin+'/auth/owner-signin',{method:'POST',redirect:'manual',headers:{origin:app.origin,'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({token})});
 const signed=await signin();assert.equal(signed.status,303);assert.equal(signed.headers.get('location'),'/auth/owner-signin');
 const cookie=cookieOf(signed);assert.equal((await app.get('/auth/owner-signin',{cookie})).status,200);
 const session=await(await app.get('/auth/session',{cookie})).json();assert.equal(session.operator.email,app.vars.OWNER_EMAIL);assert.equal(session.operator.role,'owner');
 assert.equal((await signin()).status,400,'the link signs in once');
});
