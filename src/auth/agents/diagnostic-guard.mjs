// One SQLite value binds all public state that could change this repair's
// scope. The committing proposal claim compares it again in its transaction.
export const diagnosticStamp=`SELECT json_object(
 'app',(SELECT json_object('id',id,'version',version,'disabled',disabled_at) FROM auth_apps WHERE id=?),
 'person',(SELECT json_object('id',id,'version',version,'status',status,'email',email) FROM oa_operators WHERE id=?),
 'client',(SELECT json_object('id',client_id,'method',auth_method,'redirects',redirect_uris,'logout',post_logout_redirect_uris) FROM auth_oidc_clients WHERE app_id=?),
 'assignments',(SELECT json_group_array(json_object('app',app_id,'type',principal_type,'id',principal_id,'role',role)) FROM (SELECT * FROM auth_app_assignments ORDER BY app_id,principal_type,principal_id)),
 'members',(SELECT json_group_array(json_object('group',group_id,'person',person_id)) FROM (SELECT * FROM auth_group_members ORDER BY group_id,person_id)),
 'denials',(SELECT json_group_array(json_object('app',app_id,'person',person_id)) FROM (SELECT * FROM auth_app_denials ORDER BY app_id,person_id)),
 'reductions',(SELECT json_group_array(json_object('app',app_id,'person',person_id,'role',role,'revision',order_revision)) FROM (SELECT * FROM auth_app_reductions ORDER BY app_id,person_id)),
 'roleOrder',(SELECT json_group_array(json_object('app',app_id,'role',role,'level',level,'revision',revision)) FROM (SELECT * FROM auth_app_role_order ORDER BY app_id,role)),
 'policy',(SELECT json_group_array(json_object('domain',domain,'provider',provider_id)) FROM (SELECT * FROM oa_domain_rules ORDER BY domain)),
 'samlApps',(SELECT json_group_array(json_object('id',id,'name',name,'version',version,'disabled',disabled_at)) FROM (SELECT * FROM auth_apps WHERE protocol='saml' ORDER BY id)),
 'keys',(SELECT json_group_array(json_object('id',kid,'state',state,'certificate',certificate)) FROM (SELECT * FROM auth_saml_keys WHERE state IN ('active','next') ORDER BY kid)),
 'recovery',(SELECT json_object('id',id,'approved',approved_by,'cancelled',cancelled_at,'completed',completed_at) FROM auth_recoveries WHERE id=?),
 'mail',(SELECT max(id) FROM auth_activity WHERE subject_id=? AND event IN ('recovery_mail_failed','recovery_mail_resent'))
) AS stamp`;
export const stampArgs=(appId,params)=>[appId,params.personId,appId,params.recoveryId??'',params.recoveryId??''];
