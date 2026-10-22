import {contains} from '../erasure/scrub.mjs';
const rows=(stores,name)=>stores.get(name)?.rows??[];
// Carry source ownership through opaque references before removing credentials.
export function followupReferences(stores,identifiers,reset) {
 for(const name of ['auth_agent_proposals','auth_link_requests','auth_link_tokens','auth_followup_link_tokens'])
  for(const row of rows(stores,name))if(reset||contains(row,identifiers))for(const key of ['id','token_hash'])if(row[key])identifiers.add(row[key]);
}
export function followupErasure(table,row,{stores,identifiers,reset,reference}) {
 if(!['auth_obligations','auth_obligation_history'].includes(table.name))return null;
 if(reset)return {remove:true};
 if(table.name==='auth_obligations') {
  if(!contains(row,identifiers))return null;
  return {update:{source_id:reference+':'+row.id,owner_id:null,person_id:null,app_id:null,state:row.state==='open'?'cancelled':row.state,next_action:'erased_source',last_error:null,delivery_error:null,claim_id:null,claimed_until:null}};
 }
 const affected=rows(stores,'auth_obligations').some(ob=>ob.id===row.obligation_id&&contains(ob,identifiers));
 if(!affected&&!contains(row,identifiers))return null;
 return {update:{actor_id:null,recipient_id:null,error:null}};
}
