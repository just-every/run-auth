// Preparer keys. An administrator with passkey proof mints, renews and revokes
// them; the raw key is returned once and only its digest is stored. A key is
// accepted only by the preparer API, only while it is unexpired, unrevoked and
// its accountable owner is still the administrator it was minted by: the key
// records the owner's oa_operators.version, which Base bumps on every status or
// role change, so a key ends for good when its owner is demoted, suspended or
// removed and promoting or restoring them again does not bring it back.
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {random,hash,one,all,run,requireSession,json,fail,limit,auditDetail,DAY} from '../core.mjs';

export const KEY_LIFETIME=30*DAY;
const ADMIN=['owner','admin'];

export async function administrator(ctx,request) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 return {s,guard:authority(ctx,s,ADMIN)};
}
const labelOf=value=>{const label=String(value??'').replace(/\s+/g,' ').trim();if(!label||label.length>80)fail('invalid_label');return label;};

export async function mintKey(ctx,request,data) {
 const {s,guard}=await administrator(ctx,request),label=labelOf(data.label);
 const id=random().slice(0,16),secret='authprep_'+random(),now=ctx.now(),expiresAt=now+KEY_LIFETIME;
 const inserted=await run(ctx,`INSERT INTO auth_agent_keys(id,label,secret_hash,owner_id,owner_version,created_at,expires_at) SELECT ?,?,?,?,(SELECT version FROM oa_operators WHERE id=?),?,? WHERE ${guard.clause}`,id,label,await hash(secret),s.person_id,s.person_id,now,expiresAt,...guard.args);
 if(!inserted.meta.changes){await requireAuthority(ctx,s,guard);fail('session_authority_changed',403);}
 await auditDetail(ctx,s.person_id,'agent_key_minted',id,{key:label});
 // The only response that ever carries the key.
 return json({id,label,key:secret,expiresAt},201);
}

async function changeKey(ctx,request,data,event,change) {
 const {s,guard}=await administrator(ctx,request);
 const key=await one(ctx,'SELECT id,label FROM auth_agent_keys WHERE id=?',String(data.keyId||''))||fail('key_not_found',404);
 const {sql,args}=change(s,ctx.now());
 const changed=await run(ctx,`UPDATE auth_agent_keys SET ${sql} AND ${guard.clause}`,...args,key.id,...guard.args);
 if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('key_unavailable',409);}
 await auditDetail(ctx,s.person_id,event,key.id,{key:key.label});
 return json({ok:true});
}
// Revocation is immediate: the next request with the key is refused.
export const revokeKey=(ctx,request,data)=>changeKey(ctx,request,data,'agent_key_revoked',(s,now)=>({sql:'revoked_at=?,revoked_by=? WHERE id=? AND revoked_at IS NULL',args:[now,s.person_id]}));
// Renewal gives an unexpired, unrevoked key another full lifetime from now. It
// never records a new owner version: a key its owner has outlived stays ended.
export const renewKey=(ctx,request,data)=>changeKey(ctx,request,data,'agent_key_renewed',(s,now)=>({sql:'expires_at=?,renewed_at=? WHERE id=? AND revoked_at IS NULL AND expires_at>'+now+' AND owner_version=(SELECT version FROM oa_operators WHERE id=owner_id)',args:[now+KEY_LIFETIME,now]}));

// Why a key that was not revoked can no longer be used, or null while its owner
// is the administrator it was minted by. `owner` is the owner's row now.
export const endedReason=(key,owner)=>key.revoked_at||key.owner_version===owner.version?null:owner.status!=='active'?'owner_suspended':!ADMIN.includes(owner.role)?'owner_demoted':'owner_changed';

// Keys as administrators see them: never the key or its digest.
export async function listKeys(ctx) {
 const rows=await all(ctx,'SELECT k.id,k.label,p.email AS owner_email,k.created_at,k.expires_at,k.last_used_at,k.renewed_at,k.revoked_at,r.email AS revoked_by_email,k.owner_version,p.version AS current_version,p.status AS owner_status,p.role AS owner_role FROM auth_agent_keys k JOIN oa_operators p ON p.id=k.owner_id LEFT JOIN oa_operators r ON r.id=k.revoked_by ORDER BY k.revoked_at IS NOT NULL,k.created_at DESC');
 return rows.map(({owner_version,current_version,owner_status,owner_role,...key})=>({...key,ended_reason:endedReason({...key,owner_version},{version:current_version,status:owner_status,role:owner_role})}));
}

// The preparer API's only credential: `Authorization: Preparer <key>`. Cookies
// are never read here, and the key is read nowhere else.
export async function requireKey(ctx,request,bucket,maximum) {
 const match=/^Preparer (authprep_[A-Za-z0-9_-]{43})$/.exec(request.headers.get('authorization')||'');
 if(!match)fail('preparer_key_required',401);
 const now=ctx.now();
 const key=await one(ctx,"SELECT k.* FROM auth_agent_keys k JOIN oa_operators p ON p.id=k.owner_id WHERE k.secret_hash=? AND k.revoked_at IS NULL AND k.expires_at>? AND k.owner_version=p.version AND p.status='active' AND p.role IN ('owner','admin')",await hash(match[1]),now);
 if(!key)fail('preparer_key_refused',401);
 if(!await limit(ctx,`preparer-${bucket}:${key.id}`,maximum,3600000))fail('rate_limited',429);
 await run(ctx,'UPDATE auth_agent_keys SET last_used_at=? WHERE id=?',now,key.id);
 return key;
}
