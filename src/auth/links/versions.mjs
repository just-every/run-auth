// Interface versions in use. Auth keeps every version a live client reports;
// a report below the highest one already accepted waits for an owner.
import {createLocalJWKSet,jwtVerify} from 'jose';
import {one,all,run,fail,json,audit} from '../core.mjs';
import {readBody} from './app.mjs';

export const REPORT='/oidc/link/report';
const parse=value=>{const m=/^([a-z][a-z0-9-]*)@([1-9][0-9]*)(?:\.(0|[1-9][0-9]*))?(?:\.(0|[1-9][0-9]*))?$/.exec(value||'');return m?{name:m[1],parts:[+m[2],+(m[3]??0),+(m[4]??0)]}:null;};
export const validVersion=value=>Boolean(parse(value));
function compare(a,b) {const x=parse(a),y=parse(b);for(let i=0;i<3;i++)if(x.parts[i]!==y.parts[i])return x.parts[i]-y.parts[i];return 0;}

async function accepted(ctx,clientId,name) {
 return (await all(ctx,'SELECT version FROM auth_client_versions WHERE client_id=? AND approved_at IS NOT NULL',clientId)).map(r=>r.version).filter(v=>parse(v)?.name===name);
}
export async function downgrade(ctx,clientId,version) {
 const name=parse(version)?.name,known=await accepted(ctx,clientId,name);
 // Lower than the highest version already accepted for this interface.
 return known.length>0&&!known.includes(version)&&compare(version,known.reduce((a,b)=>compare(a,b)>=0?a:b))<0;
}
export async function recordVersion(ctx,clientId,version,approvedBy=null) {
 await run(ctx,'INSERT INTO auth_client_versions(client_id,version,reported_at,approved_by,approved_at) VALUES(?,?,?,?,?) ON CONFLICT(client_id,version) DO UPDATE SET reported_at=excluded.reported_at,approved_by=COALESCE(auth_client_versions.approved_by,excluded.approved_by),approved_at=COALESCE(auth_client_versions.approved_at,excluded.approved_at)',clientId,version,ctx.now(),approvedBy,ctx.now());
}

// POST /oidc/link/report {client_id, version, client_assertion}: an app reports
// the interface version it now runs, signed with its link key (aud = this URL).
export async function report(ctx,request) {
 const data=await readBody(request);
 if(!validVersion(data.version)||typeof data.client_id!=='string'||typeof data.client_assertion!=='string')fail('invalid_request');
 const client=await one(ctx,'SELECT * FROM auth_clients WHERE id=? AND disabled_at IS NULL',data.client_id)||fail('invalid_client',401);
 let claims;try{({payload:claims}=await jwtVerify(data.client_assertion,createLocalJWKSet(JSON.parse(client.jwks)),{issuer:client.id,subject:client.id,audience:ctx.origin+REPORT,algorithms:['ES256'],currentDate:new Date(ctx.now()),requiredClaims:['iat','exp','jti']}));}catch{fail('invalid_client',401);}
 if(claims.exp-claims.iat>60||claims.version!==data.version)fail('invalid_client',401);
 try{await run(ctx,'INSERT INTO auth_assertions(client_id,jti,expires_at) VALUES(?,?,?)',client.id,claims.jti,claims.exp*1000);}catch{fail('invalid_client',401);}
 if(await downgrade(ctx,client.id,data.version)) {
  await run(ctx,'INSERT INTO auth_client_versions(client_id,version,reported_at) VALUES(?,?,?) ON CONFLICT(client_id,version) DO UPDATE SET reported_at=excluded.reported_at',client.id,data.version,ctx.now());
  await audit(ctx,null,'app_downgrade_held',client.id);
  return json({error:'downgrade_requires_owner',version:data.version},409);
 }
 await recordVersion(ctx,client.id,data.version);
 return json({recorded:true,version:data.version});
}
export async function approveVersion(ctx,clientId,version,guard,personId) {
 const done=await run(ctx,`UPDATE auth_client_versions SET approved_by=?,approved_at=? WHERE client_id=? AND version=? AND approved_at IS NULL AND ${guard.clause}`,personId,ctx.now(),clientId,version,...guard.args);
 return done.meta.changes===1;
}
export async function versionsOf(ctx,clientIds) {
 const rows=clientIds.length?await all(ctx,`SELECT client_id,version,approved_at FROM auth_client_versions WHERE client_id IN (${clientIds.map(()=>'?').join(',')}) ORDER BY version`,...clientIds):[];
 return Object.fromEntries(clientIds.map(id=>[id,{versions:rows.filter(r=>r.client_id===id&&r.approved_at).map(r=>r.version),held:rows.filter(r=>r.client_id===id&&!r.approved_at).map(r=>r.version)}]));
}
