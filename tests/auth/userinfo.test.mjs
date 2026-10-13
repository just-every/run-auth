import {test} from 'node:test';
import assert from 'node:assert/strict';
import {jwtVerify,createLocalJWKSet} from 'jose';
import {fixture} from './protocol-helpers.mjs';
import {register} from './webauthn.mjs';
import {requestProof,finishProof,sessionCookie} from './policy-helpers.mjs';

async function issued(r,scope='openid email profile claim') {
 const response=await r.redeem(await r.authorize({scope}));assert.equal(response.status,200);
 const tokens=await response.json(),keys=createLocalJWKSet(await(await r.call('/oidc/jwks')).json());
 const id=await jwtVerify(tokens.id_token,keys,{issuer:r.origin,audience:'app',currentDate:new Date(r.now)});
 const access=await jwtVerify(tokens.access_token,keys,{issuer:r.origin,audience:r.origin+'/oidc/userinfo',typ:'at+jwt',currentDate:new Date(r.now)});
 return {tokens,id,access};
}
const get=(r,token,extra={})=>r.call('/oidc/userinfo',{headers:{authorization:'Bearer '+token},...extra});
async function refused(response,status=401,error='invalid_token') {
 assert.equal(response.status,status);assert.match(response.headers.get('www-authenticate'),/^Bearer /);
 assert.equal(response.headers.get('cache-control'),'no-store');assert.equal((await response.json()).error,error);
}

test('ES256 and RS256 tokens resolve matching scoped userinfo through GET and POST',async t=>{
 for(const algorithm of ['ES256','RS256']) {
  const r=await fixture(t,{algorithm}),{tokens,id,access}=await issued(r);
  assert.equal(id.protectedHeader.alg,algorithm);assert.equal(access.protectedHeader.alg,algorithm);
  assert.equal(tokens.token_type,'Bearer');assert.ok(tokens.expires_in>0);assert.equal(tokens.refresh_token,undefined);
  assert.equal(access.payload.client_id,'app');assert.equal(access.payload.sid,id.payload.sid);assert.equal(access.payload.sub,id.payload.sub);
  assert.equal(access.payload.email,undefined);assert.equal(access.payload.install_owner,undefined);
  const response=await get(r,tokens.access_token);assert.equal(response.status,200);
  const claims=await response.json();assert.equal(claims.sub,id.payload.sub);assert.equal(claims.email,id.payload.email);assert.equal(claims.name,id.payload.name);assert.equal(claims.email_verified,true);assert.equal(claims.install_owner,undefined);assert.equal(claims.sid,undefined);assert.equal(claims.roles,undefined);
  const posted=await r.call('/oidc/userinfo',{method:'POST',form:{access_token:tokens.access_token}});assert.equal(posted.status,200);assert.deepEqual(await posted.json(),claims);
  assert.equal((await get(r,tokens.access_token,{method:'POST'})).status,200);
  assert.equal((await r.call('/api/auth/me',{headers:{authorization:'Bearer '+tokens.access_token}})).status,401);
  for(const scope of ['openid','openid email','openid profile']) {
   const limited=await issued(r,scope),result=await get(r,limited.tokens.access_token);assert.equal(result.status,200);const body=await result.json();
   assert.equal(body.sub,id.payload.sub);assert.equal(typeof body.email==='string',scope.includes('email'));assert.equal(typeof body.name==='string',scope.includes('profile'));assert.equal('email_verified' in body,scope.includes('email'));
  }
  await r.close();
 }
});

test('userinfo refuses missing, malformed, tampered, expired and incorrectly bound signed tokens',async t=>{
 const r=await fixture(t),{tokens,id,access}=await issued(r);
 await refused(await r.call('/oidc/userinfo'),401,'sign_in_required');
 for(const token of ['not-a-jwt',tokens.id_token,tokens.access_token.slice(0,-10)+'AAAAAAAAAA'])await refused(await get(r,token));
 const altered=[{aud:'https://other.example.com/userinfo'},{aud:'app'},{aud:[r.origin+'/oidc/userinfo','https://other.example.com']},{iss:'https://other.example.com'},{sub:'someone-else'},{client_id:'unknown'},{sid:'missing-session'},{scope:'openid admin'},{iat:Math.floor(r.now/1000)+60},{jti:''}];
 for(const changes of altered) {
  const signed=await r.call('/',{action:'signed-token',claims:{...access.payload,...changes},tokenIssuer:changes.iss,options:{typ:'at+jwt'}});
  await refused(await get(r,(await signed.json()).token));
 }
 const wrongType=await r.call('/',{action:'signed-token',claims:access.payload,options:{typ:'JWT'}});await refused(await get(r,(await wrongType.json()).token));
 r.now=access.payload.exp*1000;await refused(await get(r,tokens.access_token));
 assert.ok(id.payload.nonce);
});

test('userinfo bearer transport refuses ambiguous or URL credentials without cookies granting access',async t=>{
 const r=await fixture(t),{tokens}=await issued(r);
 await refused(await r.call('/oidc/userinfo',{cookie:r.cookie}),401,'sign_in_required');
 await refused(await r.call('/oidc/userinfo?access_token='+tokens.access_token),400,'invalid_request');
 await refused(await r.call('/oidc/userinfo',{method:'POST',headers:{authorization:'Bearer '+tokens.access_token},form:{access_token:tokens.access_token}}),400,'invalid_request');
 await refused(await r.call('/oidc/userinfo',{method:'POST',form:{access_token:tokens.access_token},headers:{'content-type':'application/json'}}),400,'invalid_request');
 assert.equal((await r.call('/oidc/userinfo',{method:'PUT'})).status,405);
});

test('signout revokes a previously usable access token immediately; session expiry caps its lifetime',async t=>{
 const r=await fixture(t),{tokens,access}=await issued(r);assert.equal((await get(r,tokens.access_token)).status,200);
 assert.equal((await r.call('/api/auth/signout',{method:'POST',data:{},cookie:r.cookie})).status,200);await refused(await get(r,tokens.access_token));
 const expiring=await fixture(t);await expiring.db.prepare('UPDATE auth_sessions SET expires_at=?').bind(expiring.now+45000).run();
 const short=await issued(expiring);assert.equal(short.access.payload.exp,Math.floor((expiring.now+45000)/1000));assert.ok(short.tokens.expires_in<tokens.expires_in);
 expiring.now+=45000;await refused(await get(expiring,short.tokens.access_token));assert.ok(access.payload.exp);
});

test('client, subject, account version, proof and required-provider changes remove userinfo authority',async t=>{
 const mutations=[
  ["UPDATE auth_clients SET disabled_at=? WHERE id='app'",r=>[r.now]],
  ["UPDATE auth_clients SET sector_id='different-sector' WHERE id='app'",()=>[]],
  ["UPDATE auth_clients SET origin='http://insecure.example.com' WHERE id='app'",()=>[]],
  ["DELETE FROM auth_grants WHERE client_id='app'",()=>[]],
  ["UPDATE oa_operators SET status='inactive' WHERE id='owner'",()=>[]],
  ["UPDATE oa_operators SET version=version+1 WHERE id='owner'",()=>[]],
  ["UPDATE auth_emails SET verified_at=? WHERE person_id='owner'",r=>[r.now-31*86400000]],
 ];
 for(const [sql,args]of mutations) {
  const r=await fixture(t),{tokens}=await issued(r);assert.equal((await get(r,tokens.access_token)).status,200);
  await r.person('spare-owner','spare@example.com','owner');
  await r.db.prepare(sql).bind(...args(r)).run();await refused(await get(r,tokens.access_token));await r.close();
 }
 const r=await fixture(t),{tokens}=await issued(r);
 await r.person('spare-owner','spare@example.com','owner');
 await r.db.prepare("UPDATE oa_operators SET role='member' WHERE id='owner'").run();
 await r.db.prepare("INSERT INTO oa_domain_rules(domain,provider_id,created_by,created_at) VALUES('example.com','required','spare-owner',?)").bind(r.now).run();
 await refused(await get(r,tokens.access_token));
});

test('RS256 rotation publishes before signing and cannot retire its only mature key',async t=>{
 const r=await fixture(t,{algorithm:'RS256'}),owner=await register(r,r.cookie),first=await issued(r),old=first.id.protectedHeader.kid;
 assert.equal((await r.call('/api/auth/keys/retire',{method:'POST',data:{kid:old},cookie:owner.cookie})).status,409);
 const staged=await r.call('/api/auth/keys/stage',{method:'POST',data:{alg:'RS256'},cookie:owner.cookie});assert.equal(staged.status,201);const next=await staged.json();
 const keys=await(await r.call('/oidc/jwks')).json();const published=keys.keys.find(k=>k.kid===next.kid);assert.equal(published.alg,'RS256');assert.equal(published.d,undefined);
 assert.equal((await issued(r)).id.protectedHeader.kid,old);
 assert.equal((await r.call('/api/auth/keys/retire',{method:'POST',data:{kid:old},cookie:owner.cookie})).status,409);
 r.now=next.useAfter-1000;const retained=await issued(r);
 r.now=next.useAfter+1;const current=await issued(r);assert.equal(current.id.protectedHeader.kid,next.kid);assert.equal(current.access.protectedHeader.kid,next.kid);
 // Retirement is a sensitive owner action: ten minutes on, it needs a new local email confirmation.
 const confirmed=await finishProof(r,await requestProof(r,'owner@example.com',owner.cookie));assert.equal(confirmed.status,200);const fresh=sessionCookie(confirmed);
 assert.equal((await r.call('/api/auth/keys/retire',{method:'POST',data:{kid:old},cookie:fresh})).status,200);
 assert.equal((await get(r,current.tokens.access_token)).status,200);
 assert.equal((await get(r,retained.tokens.access_token)).status,200);
 assert.ok((await(await r.call('/oidc/jwks')).json()).keys.some(k=>k.kid===old));
 r.now=(await r.db.prepare('SELECT retire_at FROM auth_signing_keys WHERE kid=?').bind(old).first()).retire_at+1;assert.equal((await(await r.call('/oidc/jwks')).json()).keys.some(k=>k.kid===old),false);
 assert.equal((await r.call('/api/auth/keys/stage',{method:'POST',data:{alg:'HS256'},cookie:fresh})).status,400);
});
