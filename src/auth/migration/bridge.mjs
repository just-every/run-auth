import {all,one,random,run,requireSession,fail,json,auditDetail,limit,hash,utf8,b64} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {seal,unseal} from '../keys.mjs';
import {checkedDestination,withinTimeout,readBounded} from '../hooks/network.mjs';
import {invokeHooks} from '../hooks/index.mjs';
import {requestEmail} from '../email.mjs';
export const BRIDGE='/api/auth/migration/bridge';
const exact=(data,keys)=>{if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(key=>!keys.includes(key))||keys.some(key=>!Object.hasOwn(data,key)))fail('invalid_bridge_request');};
async function administrator(ctx,request){const s=await requireSession(ctx,request,true);if(!['owner','admin'].includes(s.role))fail('administrator_required',403);requireLocalEmail(ctx,s);return s;}
export async function bridgeRegister(ctx,request,data) {
 exact(data,['url','credential','expiresAt','subjects','confirm']);if(data.confirm!==true)fail('explicit_bridge_consent_required',403);
 const s=await administrator(ctx,request);
 if(typeof data.credential!=='string'||data.credential.length<16||data.credential.length>4096||!Number.isSafeInteger(data.expiresAt)||data.expiresAt<=ctx.now()||data.expiresAt>ctx.now()+30*86400000||!Array.isArray(data.subjects)||!data.subjects.length||data.subjects.length>200)fail('invalid_bridge_configuration');
 const url=await withinTimeout(5000,signal=>checkedDestination(ctx,data.url,signal));
 const rows=[];
 for(const mapping of data.subjects){exact(mapping,['sourceSystem','sourceSubject','personId','batchId']);
  const row=await one(ctx,`SELECT p.id,p.email,p.version,b.id AS batch_id,b.source_system,f.subject FROM auth_former_subjects f JOIN oa_operators p ON p.id=f.person_id JOIN auth_import_batches b ON b.id=f.batch_id JOIN auth_import_rows r ON r.batch_id=b.id AND r.person_id=p.id AND r.source_id=f.subject WHERE f.source_system=? AND f.subject=? AND f.person_id=? AND b.id=? AND b.undone_at IS NULL AND r.status='admitted' AND COALESCE(r.disabled,0)=0 AND p.status IN ('active','invited') AND p.role='member' AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL)`,mapping.sourceSystem,mapping.sourceSubject,mapping.personId,mapping.batchId);
  if(!row)fail('reviewed_bridge_subject_required',409);
  if(rows.some(existing=>existing.id===row.id||existing.subject===row.subject))fail('bridge_subject_collision',409);rows.push(row);
 }
 const id=random(),encrypted=await seal(ctx,'migration-bridge:'+id,data.credential),authorityGuard=authority(ctx,s,['owner','admin']);
 const checks=rows.map(row=>({clause:"EXISTS(SELECT 1 FROM oa_operators p JOIN auth_import_batches b ON b.id=? JOIN auth_import_rows r ON r.batch_id=b.id AND r.person_id=p.id JOIN auth_former_subjects f ON f.batch_id=b.id AND f.person_id=p.id AND f.subject=r.source_id WHERE p.id=? AND p.version=? AND p.email=? AND p.status IN ('active','invited') AND p.role='member' AND b.undone_at IS NULL AND r.status='admitted' AND COALESCE(r.disabled,0)=0 AND f.source_system=? AND f.subject=? AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL))",args:[row.batch_id,row.id,row.version,row.email,row.source_system,row.subject]}));
 const guard={clause:[authorityGuard,...checks].map(item=>'('+item.clause+')').join(' AND '),args:[...authorityGuard.args,...checks.flatMap(item=>item.args)]};
 const marker={clause:'EXISTS(SELECT 1 FROM auth_migration_bridges WHERE id=?)',args:[id]};
 const statements=[ctx.db.prepare(`INSERT INTO auth_migration_bridges(id,url,sealed_credential,created_by,owner_version,created_at,expires_at) SELECT ?,?,?,?,?,?,? WHERE ${guard.clause}`).bind(id,url,encrypted,s.person_id,s.person_version,ctx.now(),data.expiresAt,...guard.args)];
 for(const row of rows)statements.push(ctx.db.prepare(`INSERT INTO auth_migration_subjects(bridge_id,source_system,source_subject,person_id,email,person_version,batch_id) SELECT ?,?,?,?,?,?,? WHERE ${marker.clause}`).bind(id,row.source_system,row.subject,row.id,row.email,row.version,row.batch_id,id));
 let result;try{result=await ctx.db.batch(statements);}catch(error){if(/UNIQUE constraint failed/.test(String(error?.message)))fail('bridge_subject_already_bound',409);throw error;}
 if(!result[0].meta.changes){await requireAuthority(ctx,s,guard);fail('bridge_registration_changed',409);}
 if(result.slice(1).some(row=>!row.meta.changes)){await run(ctx,'UPDATE auth_migration_bridges SET state=\'disabled\',sealed_credential=NULL,disabled_at=? WHERE id=?',ctx.now(),id);fail('bridge_subject_changed',409);}
 await auditDetail(ctx,s.person_id,'migration_bridge_registered',id,{subjects:rows.length,expiresAt:data.expiresAt});
 return json({id,expiresAt:data.expiresAt,subjects:rows.map(row=>({sourceSystem:row.source_system,sourceSubject:row.subject,personId:row.id})),passwordHashes:'reset-required',factors:'reenrollment-required'},201);
}
export async function bridgeDisable(ctx,request,data) {
 exact(data,['bridgeId']);const s=await administrator(ctx,request),guard=authority(ctx,s,['owner','admin']);
 const result=await run(ctx,`UPDATE auth_migration_bridges SET state='disabled',sealed_credential=NULL,disabled_at=? WHERE id=? AND state='active' AND ${guard.clause}`,ctx.now(),data.bridgeId,...guard.args);
 if(!result.meta.changes){await requireAuthority(ctx,s,guard);fail('bridge_unavailable',404);}
 await auditDetail(ctx,s.person_id,'migration_bridge_disabled',data.bridgeId,{});return json({disabled:true,credentialDestroyed:true});
}
const eligible=(ctx,bridgeId,subject)=>one(ctx,`SELECT m.*,b.url,b.sealed_credential,b.expires_at FROM auth_migration_subjects m JOIN auth_migration_bridges b ON b.id=m.bridge_id JOIN oa_operators p ON p.id=m.person_id JOIN oa_operators custodian ON custodian.id=b.created_by JOIN auth_import_batches batch ON batch.id=m.batch_id JOIN auth_import_rows r ON r.batch_id=m.batch_id AND r.person_id=p.id AND r.source_id=m.source_subject WHERE b.id=? AND m.source_subject=? AND b.state='active' AND b.expires_at>? AND custodian.status='active' AND custodian.role IN ('owner','admin') AND custodian.version=b.owner_version AND p.email=m.email AND (p.version=m.person_version OR m.completed_at IS NOT NULL) AND p.status IN ('active','invited') AND p.role='member' AND batch.undone_at IS NULL AND r.status='admitted' AND COALESCE(r.disabled,0)=0 AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL)`,bridgeId,subject,ctx.now());
export async function legacyLogin(ctx,request,data) {
 exact(data,['bridgeId','sourceSubject','password']);
 if(typeof data.bridgeId!=='string'||data.bridgeId.length>100||typeof data.sourceSubject!=='string'||data.sourceSubject.length>256||typeof data.password!=='string'||!data.password||data.password.length>4096)fail('invalid_legacy_credentials',403);
 if(!await limit(ctx,'legacy-login-ip:'+(request.headers.get('cf-connecting-ip')??''),30,60000)||!await limit(ctx,'legacy-login-subject:'+await hash(data.bridgeId+':'+data.sourceSubject),5,60000))fail('rate_limited',429);
 const mapping=await eligible(ctx,data.bridgeId,data.sourceSubject)||fail('invalid_legacy_credentials',403);
 if(mapping.completed_at!==null)return json({state:'already-migrated',next:'/signin',oldPasswordAuthority:false},202);
 // The inherited password-import hook receives only the reviewed person and
 // source identifiers, never the password, bridge credential or response body.
 await invokeHooks(ctx,'password_import',{personId:mapping.person_id,sourceId:mapping.source_subject});
 const callId=random(),started=Date.now();let verified=false;
 try {
  verified=await withinTimeout(5000,async signal=>{
   const url=await checkedDestination(ctx,mapping.url,signal),credential=await unseal(ctx,'migration-bridge:'+mapping.bridge_id,mapping.sealed_credential);
   const body=JSON.stringify({version:1,id:callId,subject:mapping.source_subject,password:data.password}),timestamp=String(Math.floor(ctx.now()/1000));
   const key=await crypto.subtle.importKey('raw',utf8.encode(credential),{name:'HMAC',hash:'SHA-256'},false,['sign']);
   const signature=b64(await crypto.subtle.sign('HMAC',key,utf8.encode(callId+'.'+timestamp+'.'+body)));
   const response=await (ctx.connectorFetch||fetch)(url,{method:'POST',redirect:'manual',signal,headers:{'content-type':'application/json','bridge-id':mapping.bridge_id,'bridge-call-id':callId,'bridge-timestamp':timestamp,'bridge-signature':'v1,'+signature},body});
   if(!response.ok){await response.body?.cancel();return false;}
   if(!/^application\/json(?:\s*;|$)/i.test(response.headers.get('content-type')??'')){await response.body?.cancel();return false;}
   const output=JSON.parse(await readBounded(response,signal,2048));
   return output&&Object.keys(output).every(key=>['authenticated','subject'].includes(key))&&output.authenticated===true&&output.subject===mapping.source_subject;
  });
 }catch{await auditDetail(ctx,null,'migration_bridge_call',mapping.bridge_id,{callId,outcome:'unavailable',latencyMs:Date.now()-started});fail('legacy_verifier_unavailable',503);}
 await auditDetail(ctx,null,'migration_bridge_call',mapping.bridge_id,{callId,outcome:verified?'verified':'refused',latencyMs:Date.now()-started});
 if(!verified)fail('invalid_legacy_credentials',403);
 const current=await eligible(ctx,mapping.bridge_id,mapping.source_subject);if(!current||current.completed_at!==null)fail('migration_changed',409);
 // A write after network verification rechecks the entire reviewed authority.
 const result=await run(ctx,`UPDATE auth_migration_subjects SET completed_at=? WHERE bridge_id=? AND source_subject=? AND completed_at IS NULL AND EXISTS(SELECT 1 FROM auth_migration_bridges b WHERE b.id=? AND b.state='active' AND b.expires_at>? AND EXISTS(SELECT 1 FROM oa_operators custodian WHERE custodian.id=b.created_by AND custodian.status='active' AND custodian.role IN ('owner','admin') AND custodian.version=b.owner_version)) AND EXISTS(SELECT 1 FROM oa_operators p JOIN auth_import_batches b ON b.id=? WHERE p.id=? AND p.email=? AND p.version=? AND p.status IN ('active','invited') AND p.role='member' AND b.undone_at IS NULL AND NOT EXISTS(SELECT 1 FROM auth_role_grants g WHERE g.person_id=p.id AND g.revoked_at IS NULL))`,ctx.now(),mapping.bridge_id,mapping.source_subject,mapping.bridge_id,ctx.now(),mapping.batch_id,mapping.person_id,mapping.email,mapping.person_version);
 if(!result.meta.changes)fail('migration_changed',409);
 // Old password verification supplies no Auth session, factor, app grant or
 // administrator right. Auth's own browser-bound email proof and enrollment
 // policy remain the only next sign-in door. A delivery interruption leaves
 // this one durable completion and directs a retry to ordinary /signin.
 await auditDetail(ctx,null,'migration_worker_verified',mapping.bridge_id,{personId:mapping.person_id,sourceSystem:mapping.source_system});
 return requestEmail(ctx,request,{email:mapping.email,returnTo:'/app/methods'});
}
