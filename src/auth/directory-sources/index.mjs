import {AuthError,fail} from '../core.mjs';
import {withinTimeout} from '../hooks/network.mjs';
import {snapshotNetwork,object} from './network.mjs';
import {validateReferences} from './normalize.mjs';
import {oktaSnapshot} from './okta.mjs';
import {entraSnapshot} from './entra.mjs';
import {googleSnapshot} from './google.mjs';
import {scimSnapshot} from './scim.mjs';

const ADAPTERS={okta:oktaSnapshot,entra:entraSnapshot,google:googleSnapshot,scim:scimSnapshot};
// Caller owns custody, unsealing, live administrator approval and persistence.
// An authenticated read confers no authority to change Auth's directory.
export async function fetchDirectorySnapshot(ctx,source,credential) {
 if(!object(source)||!Object.hasOwn(ADAPTERS,source.kind)||typeof source.organizationBinding!=='string')fail('directory_source_invalid_configuration');
 if(typeof credential!=='string'||!credential||credential.length>16384||/[\x00-\x20\x7f]/.test(credential))fail('directory_source_invalid_credential');
 try{return await withinTimeout(55000,async signal=>{
  const net=snapshotNetwork(ctx,(source.kind==='okta'?'SSWS ':'Bearer ')+credential,signal);
  const snapshot=await ADAPTERS[source.kind](net,source);
  validateReferences(snapshot.users,snapshot.groups);
  return {complete:true,users:snapshot.users,groups:snapshot.groups,binding:{kind:source.kind,organizationId:snapshot.organizationId},observedAt:ctx.now(),pages:net.pages};
 });}catch(error){if(error instanceof AuthError&&error.message.startsWith('directory_source_'))throw error;fail('directory_source_unavailable',503);}
}
