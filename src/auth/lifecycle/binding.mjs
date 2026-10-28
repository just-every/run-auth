import {hash,one} from '../core.mjs';
// The opaque digest binds work to the approved connection without retaining
// its credential. A later rotation or destination change needs fresh review.
export const scimBinding=connector=>hash(JSON.stringify([connector.base_url,connector.sealed_token,connector.deprovision,connector.push_groups,connector.created_by,connector.created_at]));
export const logoutBinding=(client,generic=false)=>hash(JSON.stringify(generic?[client.client_id,client.app_id,client.backchannel_logout_uri]:[client.id,client.sector_id,client.logout_uri]));
export async function approvedBinding(ctx,workId,current) {
 const step=await one(ctx,'SELECT binding FROM auth_lifecycle_steps WHERE work_id=?',workId);
 return !step||step.binding===current;
}
