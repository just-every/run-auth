import {one,fail} from '../core.mjs';
import {deviceProof} from './dpop.mjs';
import {familyGuard,liveFamily} from './authority.mjs';

export async function employeePrincipal(ctx,request,api,claims,raw) {
 const f=typeof claims.refresh_family==='string'&&await one(ctx,'SELECT * FROM auth_refresh_families WHERE id=?',claims.refresh_family);
 if(!f||!await liveFamily(ctx,f)||f.api_id!==api.id||f.api_revision!==api.revision||claims.client_id!==f.client_id||claims.sub!==f.person_id||claims.cnf?.jkt!==f.jkt||claims.scope!==JSON.parse(f.scopes).join(' ')||claims.exp*1000>f.absolute_expires_at||claims.exp*1000>f.idle_expires_at)fail('invalid_resource_token',401);
 await deviceProof(ctx,request,f.jkt,raw);
 return {kind:'employee',id:f.person_id,clientId:f.client_id,ownerId:f.person_id,scopes:JSON.parse(f.scopes),resources:['*'],family:f,guard:familyGuard(ctx,f),api,expiresAt:claims.exp*1000};
}
