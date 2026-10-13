// Auth as an oidc-provider@1 link provider: its well-known documents, the
// server-to-server link endpoints, and the Apps page's administrator actions.
import {createLocalJWKSet,jwtVerify} from 'jose';
import {random,hash,one,all,run,fail,json,requireSession,auditDetail,validateClientOrigin} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {INTERFACE,callbacksFor,pullApp,firstSeen,punycode,sameKey,storedKey,readBody} from './app.mjs';
import {link,redeem,REDEEM} from './handshake.mjs';
import {report,REPORT,approveVersion,versionsOf} from './versions.mjs';
import {rerApproval} from './rer-approval.mjs';
import {withdrawBySignature,WITHDRAW} from './rer-trust.mjs';

const INITIATE='/oidc/link/initiate',DEREGISTER='/oidc/link/deregister';
const TOKEN_LIFETIME=3600000,REQUEST_LIFETIME=3600000;
export const LINK_PATHS=['/.well-known/rer-provider','/.well-known/rer-dependencies',INITIATE,REDEEM,DEREGISTER,REPORT,WITHDRAW];

// Auth provides oidc-provider@1 and depends on nothing, so its own graph node is a leaf.
async function dependencies(ctx) {
 await run(ctx,'INSERT INTO rer_dependency_installation(singleton,sector_id) VALUES(1,?) ON CONFLICT DO NOTHING',crypto.randomUUID());
 const installation=await one(ctx,'SELECT sector_id FROM rer_dependency_installation WHERE singleton=1');
 return {name:'Auth',version:1,origin:ctx.origin,sector_id:installation.sector_id,provides:[INTERFACE],dependencies:[],claim:false};
}

export async function linkRoute(ctx,request,path) {
 if(request.method==='GET') {
  if(path==='/.well-known/rer-provider')return json({issuer:ctx.origin,version:1,interface:INTERFACE,provides:[INTERFACE],initiate:ctx.origin+INITIATE,redeem:ctx.origin+REDEEM,deregister:ctx.origin+DEREGISTER,report:ctx.origin+REPORT});
  if(path==='/.well-known/rer-dependencies')return json(await dependencies(ctx));
  fail('not_found',404);
 }
 if(request.method!=='POST')fail('method_not_allowed',405);
 if(path===REDEEM)return redeem(ctx,request);
 if(path===REPORT)return report(ctx,request);
 if(path===DEREGISTER)return deregister(ctx,request);
 if(path===INITIATE)return initiate(ctx,request);
 if(path===WITHDRAW)return withdrawBySignature(ctx,request);
 fail('not_found',404);
}

// From `rer setup` with a link token, or from RER Managed with a signed link approval.
async function initiate(ctx,request) {
 const data=await readBody(request);
 if(data.interface!==INTERFACE||typeof data.origin!=='string')fail('invalid_request');
 const origin=validateClientOrigin(ctx,data.origin);
 if(typeof data.approval==='string')return json({linked:true,...await rerApproval(ctx,origin,data.approval)});
 if(typeof data.token!=='string'||!data.token||data.token.length>200)fail('invalid_request');
 // Single use: the first request consumes it, whatever happens next.
 const token=await one(ctx,'UPDATE auth_link_tokens SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND expires_at>? RETURNING *',ctx.now(),await hash(data.token),ctx.now());
 if(!token||token.origin!==origin||token.interface!==INTERFACE)fail('invalid_link_token',403);
 const app=await pullApp(ctx,origin);
 if(JSON.stringify(app.callbacks)!==token.callbacks)fail('invalid_link_token',403);
 return json({linked:true,...await link(ctx,{app,source:'token',approvedBy:token.created_by})});
}

// The app unlinked itself: it signs with the key Auth holds for its client.
async function deregister(ctx,request) {
 const data=await readBody(request);
 const client=await one(ctx,'SELECT * FROM auth_clients WHERE id=? AND origin=? AND disabled_at IS NULL',String(data.client_id||''),String(data.origin||''))||fail('invalid_client',401);
 let claims;try{({payload:claims}=await jwtVerify(String(data.client_assertion||''),createLocalJWKSet(JSON.parse(client.jwks)),{issuer:client.id,subject:client.id,audience:ctx.origin+DEREGISTER,algorithms:['ES256'],currentDate:new Date(ctx.now()),requiredClaims:['iat','exp','jti']}));}catch{fail('invalid_client',401);}
 try{await run(ctx,'INSERT INTO auth_assertions(client_id,jti,expires_at) VALUES(?,?,?)',client.id,claims.jti,claims.exp*1000);}catch{fail('invalid_client',401);}
 await run(ctx,'UPDATE auth_clients SET disabled_at=? WHERE id=? AND disabled_at IS NULL',ctx.now(),client.id);
 await auditDetail(ctx,null,'app_deregistered',client.id,{origin:client.origin});
 return json({deregistered:true});
}

// Apps page model: active and removed clients, open requests, versions in use.
export async function appsModel(ctx) {
 const [clients,requests]=await Promise.all([
  all(ctx,'SELECT id,name,origin,sector_id,source,created_at,linked_at,disabled_at FROM auth_clients ORDER BY name'),
  all(ctx,'SELECT * FROM auth_link_requests WHERE decided_at IS NULL AND expires_at>? ORDER BY created_at DESC',ctx.now()),
 ]);
 const versions=await versionsOf(ctx,clients.map(c=>c.id));
 return {
  apps:clients.map(c=>({...c,status:c.disabled_at?'removed':'active',versions:versions[c.id].versions,heldVersions:versions[c.id].held,punycode:punycode(c.origin)})),
  pendingApps:requests.map(r=>{const app=JSON.parse(r.app);return {id:r.id,name:app.name,origin:r.origin,status:'pending',source:'owner',created_at:r.created_at,firstSeen:Boolean(r.first_seen),punycode:Boolean(r.punycode),replacesClient:r.client_id,keyChanged:Boolean(r.key_changed),versions:[app.version]};}),
 };
}

const ACTIONS=['/apps/request','/apps/approve','/apps/remove','/apps/link-token','/apps/version'];
export const isAppAction=path=>ACTIONS.includes(path);
export async function appAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const guard=authority(ctx,s,['owner','admin']);
 if(path==='/apps/link-token') {
  const origin=validateClientOrigin(ctx,String(data.origin||'')),token=random(),now=ctx.now(),callbacks=callbacksFor(origin);
  const minted=await run(ctx,`INSERT INTO auth_link_tokens(token_hash,origin,interface,callbacks,created_by,issued_at,expires_at) SELECT ?,?,?,?,?,?,? WHERE ${guard.clause}`,await hash(token),origin,INTERFACE,JSON.stringify(callbacks),s.person_id,now,now+TOKEN_LIFETIME,...guard.args);
  if(!minted.meta.changes){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
  await auditDetail(ctx,s.person_id,'link_token_created',null,{origin});
  // The envelope `rer setup` reads from RER_LINK_TOKEN_FILE; shown once.
  return json({token,issuer:ctx.origin,interface:INTERFACE,origin,callbacks,issuedAt:now,expiresAt:now+TOKEN_LIFETIME},201);
 }
 if(path==='/apps/request') {
  const app=await pullApp(ctx,String(data.origin||''));
  const existing=await one(ctx,'SELECT * FROM auth_clients WHERE sector_id=?',app.sector);
  const id=random(),seen=await firstSeen(ctx,app.origin);
  const stored=await run(ctx,`INSERT INTO auth_link_requests(id,origin,interface,app,client_id,key_changed,first_seen,punycode,requested_by,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE ${guard.clause}`,id,app.origin,INTERFACE,JSON.stringify(app),existing?.id??null,existing&&!sameKey(storedKey(existing),app.key)?1:0,seen?1:0,punycode(app.origin)?1:0,s.person_id,ctx.now(),ctx.now()+REQUEST_LIFETIME,...guard.args);
  if(!stored.meta.changes){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
  await run(ctx,'INSERT OR IGNORE INTO auth_origins_seen(origin,first_seen_at) VALUES(?,?)',app.origin,ctx.now());
  return json({id,origin:app.origin,name:app.name,firstSeen:seen,punycode:punycode(app.origin),replacesClient:existing?.id??null},201);
 }
 if(path==='/apps/approve') {
  const r=await one(ctx,'SELECT * FROM auth_link_requests WHERE id=? AND decided_at IS NULL AND expires_at>?',String(data.id||''),ctx.now())||fail('link_request_not_found',404);
  const shown=JSON.parse(r.app),app=await pullApp(ctx,r.origin);
  // Approval covers what the administrator was shown, not what the app serves later.
  if(app.sector!==shown.sector||!sameKey(app.key,shown.key)||JSON.stringify(app.callbacks)!==JSON.stringify(shown.callbacks))fail('app_changed_since_request',409);
  const decided=await run(ctx,`UPDATE auth_link_requests SET decided_by=?,decided_at=? WHERE id=? AND decided_at IS NULL AND ${guard.clause}`,s.person_id,ctx.now(),r.id,...guard.args);
  if(!decided.meta.changes){await requireAuthority(ctx,s,guard);fail('link_request_decided',409);}
  const result=await link(ctx,{app,source:'owner',approvedBy:s.person_id,versionApproved:true});
  await run(ctx,'UPDATE auth_link_requests SET outcome=? WHERE id=?','linked',r.id);
  return json({linked:true,...result});
 }
 if(path==='/apps/remove') {
  const client=await one(ctx,'SELECT id,origin FROM auth_clients WHERE id=? AND disabled_at IS NULL',String(data.id||''))||fail('app_not_found',404);
  const removed=await run(ctx,`UPDATE auth_clients SET disabled_at=? WHERE id=? AND disabled_at IS NULL AND ${guard.clause}`,ctx.now(),client.id,...guard.args);
  if(!removed.meta.changes){await requireAuthority(ctx,s,guard);fail('app_not_found',404);}
  await auditDetail(ctx,s.person_id,'app_removed',client.id,{origin:client.origin});
  return json({removed:true});
 }
 // '/apps/version': an owner accepts a held lower interface version.
 if(s.role!=='owner')fail('owner_required',403);
 const clientId=String(data.id||''),version=String(data.version||'');
 if(!await approveVersion(ctx,clientId,version,authority(ctx,s,['owner']),s.person_id)){await requireAuthority(ctx,s,guard);fail('version_not_held',404);}
 await auditDetail(ctx,s.person_id,'app_downgrade_approved',clientId,{version});
 return json({approved:true,version});
}
