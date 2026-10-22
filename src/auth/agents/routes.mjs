import {syncObligations} from '../obligations/sources.mjs';
// Administration of agents: keys and the proposals their keys filed. Every
// handler authorizes its own request with the administrator's session.
import {one,all,fail} from '../core.mjs';
import {mintKey,revokeKey,renewKey,listKeys,endedReason} from './keys.mjs';
import {approvalOptions,approve,reject} from './approval.mjs';
import {KINDS,digest,changes} from './kinds.mjs';
export {preparer} from './preparer.mjs';

async function action(ctx,request,path,data) {
 if(path==='/agents/mint')return mintKey(ctx,request,data);
 if(path==='/agents/revoke')return revokeKey(ctx,request,data);
 if(path==='/agents/renew')return renewKey(ctx,request,data);
 if(path==='/agents/approve/options')return approvalOptions(ctx,request,data);
 if(path==='/agents/approve')return approve(ctx,request,data);
 if(path==='/agents/reject')return reject(ctx,request,data);
 fail('not_found',404);
}

const PROPOSALS="SELECT p.id,p.kind,p.target,p.reason,p.effect,p.target_state,p.state_digest,p.params,p.created_at,p.expires_at,p.status,p.outcome,p.decided_at,d.email AS decided_by_email,k.id AS key_id,k.label AS key_label,k.revoked_at AS key_revoked_at,k.owner_version,o.version AS owner_now,o.status AS owner_status,o.role AS owner_role,o.email AS key_owner_email FROM auth_agent_proposals p JOIN auth_agent_keys k ON k.id=p.key_id JOIN oa_operators o ON o.id=k.owner_id LEFT JOIN oa_operators d ON d.id=p.decided_by";
const view=(ctx,p)=>({id:p.id,kind:p.kind,reason:p.reason,effect:JSON.parse(p.effect),created_at:p.created_at,expires_at:p.expires_at,status:p.status==='pending'&&p.expires_at<=ctx.now()?'expired':p.status,outcome:p.outcome?JSON.parse(p.outcome):null,decided_at:p.decided_at,decided_by_email:p.decided_by_email,key_label:p.key_label,key_revoked_at:p.key_revoked_at,key_ended_reason:endedReason({revoked_at:p.key_revoked_at,owner_version:p.owner_version},{version:p.owner_now,status:p.owner_status,role:p.owner_role}),key_owner_email:p.key_owner_email});

// The page model: keys, recent proposals, and one proposal's stored effect
// beside its effect computed now.
export async function agentsModel(ctx,request) {
 const [keys,proposals]=await Promise.all([listKeys(ctx),all(ctx,`${PROPOSALS} ORDER BY p.status='pending' DESC,p.created_at DESC LIMIT 100`)]);
 const id=new URL(request.url).searchParams.get('proposal');
 const p=id?await one(ctx,`${PROPOSALS} WHERE p.id=?`,id):null;
 let proposal=null;
 if(p) {
  const kind=KINDS[p.kind],params=JSON.parse(p.params),state=await kind.state(ctx,p.target,params);
  const unchanged=await digest(state)===p.state_digest;
  proposal={...view(ctx,p),fresh:await kind.effect(ctx,state,params),unchanged,changed:unchanged?[]:changes(JSON.parse(p.target_state),state)};
 }
 return {agents:{now:ctx.now(),keys,proposals:proposals.map(row=>view(ctx,row)),proposal}};
}

export async function agentsAction(ctx,request,path,data) {const response=await action(ctx,request,path,data);await syncObligations(ctx);return response;}
