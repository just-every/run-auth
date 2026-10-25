// Counts describe removed durable credential authorities, not token strings.
// One OAuth authority may have signed several stateless access tokens; removing
// it ends all of them through the resource door's live authority check.
const kinds={
 sessions:['auth_sessions','oa_sessions'],
 apiKeys:['auth_agent_keys'],
 passkeys:['auth_passkeys','oa_credentials'],
 oauthClientTokens:['auth_resource_services','auth_admin_service_apps','auth_oidc_sessions'],
 refreshTokens:['auth_refresh_credentials'],
 delegations:['auth_delegated_tasks','auth_external_tasks','auth_role_grants'],
};
export function revocationAudit(plan) {
 const counts=Object.fromEntries(Object.entries(kinds).map(([kind,tables])=>[kind,tables.reduce((total,name)=>total+(plan.stores.get(name)?.rows.filter((_,index)=>plan.removed.has(name+':'+index)).length??0),0)]));
 return {id:plan.reference,counts};
}
