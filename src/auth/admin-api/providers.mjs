import {federationProviders} from '../federation/setup-state.mjs';
import {employerProviders} from '../tenancy/providers.mjs';
import {all,auditDetail,fail,json} from '../core.mjs';
import {only,requireScope} from './resources.mjs';

// Configuration owns identity and credentials; this table only controls whether
// a configured upstream is currently offered and accepts verified proofs.
export async function resolveProviders(ctx) {
 const legacy=ctx.organizationId&&ctx.organizationId!=='root'?await employerProviders(ctx):ctx.configuredUpstreamProviders??ctx.upstreamProviders??[];
 const delegated=await federationProviders(ctx),configured=[...legacy,...delegated.filter(provider=>!legacy.some(existing=>existing.id===provider.id))];
 const disabled=new Set((await all(ctx,'SELECT provider_id FROM auth_provider_states WHERE enabled=0')).map(row=>row.provider_id));
 return {...ctx,configuredUpstreamProviders:configured,upstreamProviders:configured.filter(provider=>!disabled.has(provider.id))};
}

export async function writeProvider(ctx,actor,id,data) {
 requireScope(actor,'idps.manage');only(data,['enabled']);
 if(typeof data.enabled!=='boolean')fail('invalid_provider_enabled');
 const provider=(ctx.configuredUpstreamProviders??ctx.upstreamProviders??[]).find(p=>p.id===id&&['google','microsoft','okta','oidc','saml'].includes(p.preset));
 if(!provider)fail('unknown_provider',404);
 const guard=actor.guard;
 const statement=ctx.db.prepare(`INSERT INTO auth_provider_states(provider_id,enabled,revision,updated_by,updated_at)
  SELECT ?,?,1,?,? WHERE ${guard.clause}
  ON CONFLICT(provider_id) DO UPDATE SET enabled=excluded.enabled,revision=auth_provider_states.revision+1,updated_by=excluded.updated_by,updated_at=excluded.updated_at`)
  .bind(provider.id,Number(data.enabled),actor.actorId,ctx.now(),...guard.args);
 await actor.commit([statement]);
 await auditDetail(ctx,actor.actorId,'provider_state_changed',provider.id,{enabled:data.enabled});
 return json({id:provider.id,enabled:data.enabled});
}
