// The provider half of the pull handshake. `link` decides continuity before any
// network call, posts a one-use code to the app's fixed callback and answers
// only after the app redeemed it; `redeem` is the app's signed exchange.
import {createLocalJWKSet,jwtVerify} from 'jose';
import {random,hash,one,run,fail,json,auditDetail,email as emailOf} from '../core.mjs';
import {signToken,pairwiseSubject} from '../keys.mjs';
import {CALLBACK,fetcherOf,sameKey,storedKey,punycode,readBody} from './app.mjs';
import {recordVersion,downgrade,holdVersion} from './versions.mjs';

export const REDEEM='/oidc/link/redeem';
const JWT_BEARER='urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const shownToPerson=source=>['owner','proposal'].includes(source);
const SOURCES={owner:'Approved by an administrator',token:'Created with a link token',rer:'Created by RER',proposal:'Approved from an agent proposal'};

// What linking this app replaces besides its own client at its own origin: the
// client holding its sector at another origin, which moves here with its people's
// identifiers, and an active client at this origin with another sector, which is
// removed so its people's identifiers at this app change.
export async function replacements(ctx,app) {
 const [moved,other]=await Promise.all([
  one(ctx,'SELECT id,name,origin FROM auth_clients WHERE sector_id=? AND origin!=?',app.sector,app.origin),
  one(ctx,'SELECT id,name,origin FROM auth_clients WHERE origin=? AND sector_id!=? AND disabled_at IS NULL',app.origin,app.sector),
 ]);
 return [moved&&{client:moved.id,name:moved.name,origin:moved.origin,change:'moves'},other&&{client:other.id,name:other.name,origin:other.origin,change:'identifiers'}].filter(Boolean);
}

// Continuity: a client is found by its sector. Its own unchanged key proves it
// ("previous-key"); a new key only counts when an administrator approved with
// the existing client shown ("provider-owner"). A key alone never counts, and an
// approval covers only the replacements the person was shown (`approved`).
async function continuity(ctx,app,source,approved) {
 const shown=shownToPerson(source);
 const existing=await one(ctx,'SELECT * FROM auth_clients WHERE sector_id=?',app.sector);
 const replaced=await replacements(ctx,app),other=replaced.find(r=>r.change==='identifiers')?.client??null;
 if(other&&!shown)fail('origin_linked_to_another_install',409);
 if(existing&&existing.origin!==app.origin&&!shown)fail('origin_changed_requires_owner',409);
 if(replaced.some(r=>!approved.includes(r.client)))fail('replacement_not_approved',409);
 if(!existing)return {existing:null,continuity:null,replaces:other};
 if(sameKey(storedKey(existing),app.key))return {existing,continuity:'previous-key',replaces:other};
 if(!shown)fail('link_continuity_required',409);
 return {existing,continuity:'provider-owner',replaces:other};
}

// A lower interface version waits for the owner: only an owner's own approval
// of the link accepts it at once.
async function ownerApproved(ctx,source,approvedBy) {
 return shownToPerson(source)&&Boolean(await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND role='owner' AND status='active'",approvedBy));
}

async function postCallback(ctx,origin,body) {
 const controller=AbortSignal.timeout(15000);
 let response;try{response=await fetcherOf(ctx)(origin+CALLBACK,{method:'POST',redirect:'manual',signal:controller,headers:{'content-type':'application/json',accept:'application/json'},body:JSON.stringify(body)});}catch{fail('app_unreachable',502);}
 const text=(await response.text()).slice(0,4096);let answer=null;try{answer=JSON.parse(text);}catch{}
 return {status:response.status,answer};
}

// link: {app, source, approvedBy, claimPerson?, replacing?: client ids the approver was shown replaced}
export async function link(ctx,{app,source,approvedBy,claimPerson=null,replacing=[]}) {
 const {existing,continuity:kept,replaces}=await continuity(ctx,app,source,replacing);
 if(existing&&await downgrade(ctx,existing.id,app.version)&&!await ownerApproved(ctx,source,approvedBy)){await holdVersion(ctx,existing.id,app.version);fail('downgrade_requires_owner',409);}
 const code=random(),now=ctx.now();
 const grant={name:app.name,key:app.key,callbacks:app.callbacks,version:app.version,source,approvedBy,claimPerson,continuity:kept,clientId:existing?.id??null,replaces};
 await run(ctx,'INSERT INTO auth_link_codes(code_hash,origin,interface,callback,sector_id,link,expires_at) VALUES(?,?,?,?,?,?,?)',await hash(code),app.origin,app.interface,app.origin+CALLBACK,app.sector,JSON.stringify(grant),now+60000);
 await run(ctx,'INSERT OR IGNORE INTO auth_origins_seen(origin,first_seen_at) VALUES(?,?)',app.origin,now);
 const {status,answer}=await postCallback(ctx,app.origin,{issuer:ctx.origin,interface:app.interface,code});
 const redeemed=await one(ctx,'SELECT consumed_at FROM auth_link_codes WHERE code_hash=?',await hash(code));
 if(status!==200||answer?.linked!==true||!redeemed?.consumed_at) {
  await run(ctx,'UPDATE auth_link_codes SET expires_at=0 WHERE code_hash=? AND consumed_at IS NULL',await hash(code));
  // Administrators see why: the app's own answer, as a symbolic code only.
  const reason=typeof answer?.error==='string'&&/^[a-z_]{1,64}$/.test(answer.error)?answer.error:status?`status_${status}`:'no_answer';
  await auditDetail(ctx,approvedBy,'app_link_failed',null,{origin:app.origin,source:SOURCES[source],reason});
  fail(`app_refused_link:${reason}`,409);
 }
 const client=await one(ctx,'SELECT id,name,origin FROM auth_clients WHERE sector_id=?',app.sector);
 await auditDetail(ctx,approvedBy,'app_linked',client.id,{origin:app.origin,source:SOURCES[source],continuity:kept??'new',...(punycode(app.origin)?{punycode:true}:{})});
 if(!shownToPerson(source))await notifyAdministrators(ctx,client,source);
 return {client_id:client.id,origin:client.origin,name:client.name,source};
}

// Links not made by an administrator in Auth itself are announced to every administrator.
async function notifyAdministrators(ctx,client,source) {
 if(!ctx.mail)return;
 const people=(await ctx.db.prepare("SELECT email FROM oa_operators WHERE role IN ('owner','admin') AND status='active'").all()).results;
 const text=`${SOURCES[source]}: ${client.name} (${client.origin}) can now sign people in with ${ctx.origin}. Review or remove it on ${ctx.origin}/app/apps.`;
 for(const person of people){try{await ctx.mail({to:person.email,subject:`An app was linked to Auth: ${client.origin}`,text,html:`<p>${text.replace(/&/g,'&amp;').replace(/</g,'&lt;')}</p>`});}catch{}}
}


export async function redeem(ctx,request) {
 const data=await readBody(request);
 if(Object.keys(data).some(k=>!['code','interface','origin','callback','client_assertion_type','client_assertion'].includes(k))||typeof data.code!=='string'||data.code.length>200)fail('invalid_request');
 const row=await one(ctx,'SELECT * FROM auth_link_codes WHERE code_hash=?',await hash(data.code));
 if(!row||row.consumed_at||row.expires_at<=ctx.now()||data.interface!==row.interface||data.origin!==row.origin||data.callback!==row.callback)fail('invalid_grant');
 const grant=JSON.parse(row.link),sec=Math.floor(ctx.now()/1000);
 if(data.client_assertion_type!==JWT_BEARER||typeof data.client_assertion!=='string')fail('invalid_client',401);
 let claims;
 try{({payload:claims}=await jwtVerify(data.client_assertion,createLocalJWKSet({keys:[grant.key]}),{issuer:row.origin,subject:row.origin,audience:ctx.origin+REDEEM,algorithms:['ES256'],currentDate:new Date(ctx.now()),requiredClaims:['iat','exp','jti']}));}catch{fail('invalid_client',401);}
 if(claims.exp-claims.iat>60||claims.iat>sec+30||typeof claims.jti!=='string'||!claims.jti||claims.jti.length>256||claims.code!==data.code||claims.interface!==row.interface||claims.sector_id!==row.sector_id||claims.callback!==row.callback)fail('invalid_client',401);
 try{await run(ctx,'INSERT INTO auth_assertions(client_id,jti,expires_at) VALUES(?,?,?)','link:'+row.origin,claims.jti,claims.exp*1000);}catch{fail('invalid_client',401);}
 // One winner: concurrent redemptions of the same code race on this statement.
 if(!await one(ctx,'UPDATE auth_link_codes SET consumed_at=? WHERE code_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING code_hash',ctx.now(),row.code_hash,ctx.now()))fail('invalid_grant');
 const clientId=await commitClient(ctx,row,grant);
 const answer={issuer:ctx.origin,interface:row.interface,origin:row.origin,callback:row.callback,sector_id:row.sector_id,client_id:clientId};
 if(grant.continuity)answer.continuity=grant.continuity;
 const owner=grant.claimPerson?await installOwner(ctx,clientId,row.sector_id,grant.claimPerson):null;
 if(owner)answer.install_owner=owner;
 return json(answer);
}

async function commitClient(ctx,row,grant) {
 const now=ctx.now(),redirects=JSON.stringify([row.origin+'/auth/oidc/auth/callback']),jwks=JSON.stringify({keys:[grant.key]}),logout=row.origin+'/auth/oidc/auth/logout';
 const id=grant.clientId??random();
 const statements=[grant.clientId
  ?ctx.db.prepare('UPDATE auth_clients SET name=?,origin=?,redirect_uris=?,jwks=?,logout_uri=?,linked_at=?,source=?,approved_by=?,interface=?,disabled_at=NULL WHERE id=? AND sector_id=?').bind(grant.name,row.origin,redirects,jwks,logout,now,grant.source,grant.approvedBy,row.interface,id,row.sector_id)
  :ctx.db.prepare('INSERT INTO auth_clients(id,name,origin,sector_id,redirect_uris,jwks,source,created_at,interface,logout_uri,linked_at,approved_by) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)').bind(id,grant.name,row.origin,row.sector_id,redirects,jwks,grant.source,now,row.interface,logout,now,grant.approvedBy)];
 if(grant.replaces&&grant.replaces!==id)statements.push(ctx.db.prepare('UPDATE auth_clients SET disabled_at=? WHERE id=? AND disabled_at IS NULL').bind(now,grant.replaces));
 await ctx.db.batch(statements);
 await recordVersion(ctx,id,grant.version,grant.approvedBy);
 return id;
}

// install_owner goes once per client, only to the person named at approval.
async function installOwner(ctx,clientId,sector,personId) {
 const claimed=await one(ctx,"UPDATE auth_clients SET owner_person_id=?,owner_claimed_at=? WHERE id=? AND owner_claimed_at IS NULL AND EXISTS(SELECT 1 FROM oa_operators WHERE id=? AND status='active') RETURNING id",personId,ctx.now(),clientId,personId);
 if(!claimed)return null;
 const person=await one(ctx,'SELECT p.email,e.verified_at FROM oa_operators p JOIN auth_emails e ON e.person_id=p.id WHERE p.id=?',personId);
 if(!person||!emailOf(person.email))return null;
 const subject=await pairwiseSubject(ctx,sector,personId),now=Math.floor(ctx.now()/1000);
 return signToken(ctx,{aud:clientId,sub:subject,jti:random(),...(ctx.local?{amr:['dev']}:{}),email:person.email,email_verified:true,email_verified_at:Math.floor(person.verified_at/1000),install_owner:{client_id:clientId,sector_id:sector,subject,email:person.email}},{expiresAt:now+300});
}
