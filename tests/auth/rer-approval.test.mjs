import {test} from 'node:test';
import assert from 'node:assert/strict';
import {generateKeyPair,exportJWK,SignJWT,calculateJwkThumbprint} from 'jose';
import {openLink} from './link/runtime.mjs';
import {AUTH_ORIGIN,APP_ORIGIN,APP_SETUP_TOKEN} from './link/origins.mjs';
import {emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';

const INTERFACE='oidc-provider@1',APP_SETUP=APP_SETUP_TOKEN;
async function rerKey() {
 const {publicKey,privateKey}=await generateKeyPair('ES256',{extractable:true});
 const jwk=await exportJWK(publicKey),kid=await calculateJwkThumbprint(jwk);
 return {kid,privateKey,public:{...jwk,kid,alg:'ES256',use:'sig'}};
}
// RER's approval as RER Managed signs it; each case changes exactly one thing.
async function approval(key,claims,{lifetime=300,aud=AUTH_ORIGIN}={}) {
 const now=Math.floor(Date.now()/1000);
 return new SignJWT({origin:APP_ORIGIN,interface:INTERFACE,...claims}).setProtectedHeader({alg:'ES256',kid:key.kid,typ:'rer-link-approval+jwt'}).setIssuer('http://127.0.0.1:5175').setAudience(aud).setIssuedAt(now).setExpirationTime(now+lifetime).setJti(claims.jti??crypto.randomUUID()).sign(key.privateKey);
}

test('Auth links an app only on a fresh, trusted RER approval that binds its origin and key, and claims only for its owner',async t=>{
 const r=await openLink();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');
 const owner=await register(r,await emailSession(r,'owner@example.com'));
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(Date.now()-1).run();
 const account=await rerKey(),other=await rerKey();
 const trusted=await r.call('/api/auth/rer-trust/add',{method:'POST',data:{key:JSON.stringify(account.public)},cookie:owner.cookie});
 assert.equal(trusted.status,201,await trusted.clone().text());
 const appKey=(await(await r.send(APP_ORIGIN+'/.well-known/rer-link/jwks/'+INTERFACE)).json()).keys[0];
 const initiate=async jws=>{const response=await r.send(AUTH_ORIGIN+'/oidc/link/initiate',{method:'POST',json:{origin:APP_ORIGIN,interface:INTERFACE,approval:jws},cookies:false});return {status:response.status,error:(await response.json()).error};};
 const strangerKey=(await rerKey()).public;
 const replayed=crypto.randomUUID();
 await initiate(await approval(account,{link_key:appKey,jti:replayed}));
 const cases=[
  ['a replayed jti',await approval(account,{link_key:appKey,jti:replayed}),409,'rer_approval_used'],
  ['exp over five minutes',await approval(account,{link_key:appKey},{lifetime:600}),401,'invalid_rer_approval'],
  ['aud of another install',await approval(account,{link_key:appKey},{aud:'https://id.other.example'}),401,'invalid_rer_approval'],
  ['another origin',await approval(account,{link_key:appKey,origin:'https://other.example.com'}),403,'rer_approval_origin_mismatch'],
  ['another link key',await approval(account,{link_key:strangerKey}),403,'rer_approval_key_mismatch'],
  ['claim for someone other than the Auth owner',await approval(account,{link_key:appKey,claim:{email:'someone@example.com'}}),403,'rer_claim_not_auth_owner'],
  ['a key from another account',await approval(other,{link_key:appKey}),403,'untrusted_rer_approval'],
 ];
 for(const [name,jws,status,error] of cases)assert.deepEqual(await initiate(jws),{status,error},name);
 assert.equal((await r.db.prepare('SELECT count(*) AS n FROM auth_clients').first()).n,0,'no refused approval links anything');

 // The app's own approval is open (as RER opens it with the setup token): a valid approval links it.
 assert.equal((await r.send(APP_ORIGIN+'/auth/dependencies/setup',{method:'POST',json:{issuer:AUTH_ORIGIN,interface:INTERFACE,token:APP_SETUP}})).status,200);
 assert.equal((await r.send(APP_ORIGIN+'/auth/bootstrap',{method:'POST',json:{token:APP_SETUP,displayName:'Owner'}})).status,303);
 const linked=await r.send(AUTH_ORIGIN+'/oidc/link/initiate',{method:'POST',json:{origin:APP_ORIGIN,interface:INTERFACE,approval:await approval(account,{link_key:appKey})},cookies:false});
 assert.equal(linked.status,200,await linked.clone().text());
 assert.equal((await r.db.prepare('SELECT source FROM auth_clients').first()).source,'rer');
 assert.ok((await r.mails()).some(m=>m.text.startsWith('Created by RER')),'administrators hear about an RER-made link');

 const withdrawn=await r.call('/api/auth/rer-trust/withdraw',{method:'POST',data:{kid:account.kid},cookie:owner.cookie});
 assert.equal(withdrawn.status,200);
 assert.deepEqual(await initiate(await approval(account,{link_key:appKey})),{status:403,error:'untrusted_rer_approval'},'after trust is withdrawn');
});
