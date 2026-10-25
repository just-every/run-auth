// The approved effect carries the exact public protocol target for its scoped
// probe. The model cannot supply or replace any of these values.
export function diagnosticProbe(state,params) {
 if(!state.app||!state.person)return null;
 const common={personId:state.person.id,appId:state.app.id,protocol:state.app.protocol};
 if(state.client) {
  if(!['none','client_secret_basic','client_secret_post'].includes(state.client.auth_method))return null;
  const redirects=params.repair?.field==='redirect_uris'?params.repair.after:state.redirects;
  if(redirects?.length!==1)return null;
  return {...common,clientId:state.client.client_id,authMethod:state.client.auth_method,redirectUri:redirects[0],postLogoutRedirectUri:JSON.parse(state.client.post_logout_redirect_uris)[0]};
 }
 const acs=JSON.parse(state.app.acs),slo=state.app.slo?JSON.parse(state.app.slo):null;
 if(!acs.length||!slo||!JSON.parse(state.app.sp_certificates).length)return null;
 return {...common,entityId:state.app.entity_id,acsUrl:(acs.find(a=>a.isDefault)??acs[0]).url,sloUrl:slo.responseUrl??slo.url,sign:state.app.sign,spCertificate:JSON.parse(state.app.sp_certificates)[0]};
}
