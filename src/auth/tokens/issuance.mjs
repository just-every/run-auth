import {subjectFor} from '../oidc-apps/clients.mjs';
import {AuthError,auditDetail,fail,hash,json,one,random,run} from '../core.mjs';
import {ensureSigningKey,signToken} from '../keys.mjs';
import {invokeHooks} from '../hooks/index.mjs';
import {familyGuard,requireFamily} from './authority.mjs';
import {deviceProof} from './dpop.mjs';
import {endFamily} from './lifecycle.mjs';
import {profileFor} from './consent.mjs';

async function accessToken(ctx,client,f,refreshToken) {
 const profile=await profileFor(ctx,client.client_id);
 await requireFamily(ctx,f);
 // Hooks run at each issuance. Their failure cannot leave a usable successor.
 await invokeHooks(ctx,'token',{personId:f.person_id,appId:client.app_id});
 await requireFamily(ctx,f);await ensureSigningKey(ctx);
 const now=Math.floor(ctx.now()/1000),expiry=Math.min(now+300,Math.floor(f.idle_expires_at/1000),Math.floor(f.absolute_expires_at/1000));
 if(expiry<=now)fail('invalid_grant');
 const token=await signToken(ctx,{aud:profile.audience,sub:await subjectFor(ctx,client,f.person_id),client_id:f.client_id,refresh_family:f.id,api_id:f.api_id,api_revision:f.api_revision,organization_id:ctx.organizationId??'root',scope:JSON.parse(f.scopes).join(' '),cnf:{jkt:f.jkt},jti:random()},{alg:client.id_token_alg,typ:'at+jwt',expiresAt:expiry,published:true});
 await requireFamily(ctx,f);
 return {access_token:token,refresh_token:refreshToken,token_type:'DPoP',expires_in:expiry-now,scope:JSON.parse(f.scopes).join(' '),grant_id:f.id};
}
export async function initialProof(ctx,request,code) {
 if(!code?.refresh_consent_id)return;
 const consent=await one(ctx,'SELECT * FROM auth_refresh_consents WHERE id=? AND approved_at IS NOT NULL AND expires_at>?',code.refresh_consent_id,ctx.now());
 if(!consent)fail('invalid_grant');
 await deviceProof(ctx,request,consent.jkt,null,consent.id);
}
export async function initialFamily(ctx,client,code) {
 const c=await one(ctx,'SELECT * FROM auth_refresh_consents WHERE id=? AND approved_at IS NOT NULL AND expires_at>?',code.refresh_consent_id,ctx.now());
 const p=c&&await profileFor(ctx,client.client_id);
 if(!c||!p||c.client_id!==client.client_id||p.revision!==c.profile_revision||p.api_revision!==c.api_revision||p.app_version!==c.app_version)fail('invalid_grant');
 const raw=random(),digest=await hash(raw),now=ctx.now();
 const f={id:c.id,client_id:c.client_id,api_id:p.api_id,person_id:c.person_id,person_version:c.person_version,session_id:c.session_id,profile_revision:c.profile_revision,api_revision:c.api_revision,app_version:c.app_version,scopes:c.api_scopes,jkt:c.jkt,device_name:c.device_name,current_hash:digest,created_at:now,last_used_at:now,idle_expires_at:now+p.idle_ms,absolute_expires_at:now+p.absolute_ms};
 const columns=Object.keys(f);
 await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_refresh_families(${columns.join(',')}) VALUES(${columns.map(()=>'?').join(',')})`).bind(...Object.values(f)),
  ctx.db.prepare('INSERT INTO auth_refresh_credentials(token_hash,family_id,generation,created_at) VALUES(?,?,0,?)').bind(digest,f.id,now),
 ]);
 try {const issued=await accessToken(ctx,client,f,raw);await auditDetail(ctx,c.person_id,'refresh_family_created',f.id,{clientId:c.client_id,scopes:JSON.parse(c.api_scopes)});return issued;}
 catch(error){await endFamily(ctx,f.id,'issuance_failed');throw error;}
}
export async function refreshFamily(ctx,request,form,client) {
 const raw=form.get('refresh_token');if(typeof raw!=='string'||raw.length>256)fail('invalid_grant');
 const credential=await one(ctx,'SELECT * FROM auth_refresh_credentials WHERE token_hash=?',await hash(raw));
 const f=credential&&await one(ctx,'SELECT * FROM auth_refresh_families WHERE id=? AND client_id=?',credential.family_id,client.client_id);
 if(!f)fail('invalid_grant');
 // A stolen digest alone cannot trigger family denial: authenticate the bound
 // client and device before making a reuse decision.
 await deviceProof(ctx,request,f.jkt,null,f.id);
 if(form.has('resource')||form.has('scope'))fail('invalid_scope');
 if(credential.consumed_at!==null||credential.token_hash!==f.current_hash){await endFamily(ctx,f.id,'refresh_reuse');fail('invalid_grant');}
 await requireFamily(ctx,f);
 const profile=await profileFor(ctx,client.client_id),next=random(),digest=await hash(next),now=ctx.now(),guard=familyGuard(ctx,f);
 const rotated=await ctx.db.batch([
  ctx.db.prepare(`UPDATE auth_refresh_families SET current_hash=?,generation=generation+1,last_used_at=?,idle_expires_at=MIN(absolute_expires_at,?) WHERE id=? AND current_hash=? AND ${guard.clause}`).bind(digest,now,now+profile.idle_ms,f.id,credential.token_hash,...guard.args),
  ctx.db.prepare('UPDATE auth_refresh_credentials SET consumed_at=? WHERE token_hash=? AND consumed_at IS NULL AND EXISTS(SELECT 1 FROM auth_refresh_families WHERE id=? AND current_hash=?)').bind(now,credential.token_hash,f.id,digest),
  ctx.db.prepare('INSERT INTO auth_refresh_credentials(token_hash,family_id,generation,created_at) SELECT current_hash,id,generation,? FROM auth_refresh_families WHERE id=? AND current_hash=?').bind(now,f.id,digest),
 ]);
 if(!rotated[0].meta.changes){await endFamily(ctx,f.id,'concurrent_refresh');fail('invalid_grant');}
 try {
  const current=await one(ctx,'SELECT * FROM auth_refresh_families WHERE id=?',f.id),issued=await accessToken(ctx,client,current,next);
  await auditDetail(ctx,f.person_id,'refresh_rotated',f.id,{clientId:f.client_id,generation:current.generation});return json(issued);
 }catch(error){await endFamily(ctx,f.id,'issuance_failed');throw error;}
}
