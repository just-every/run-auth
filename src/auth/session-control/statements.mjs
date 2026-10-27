import {LOGOUT_EVENT} from '../links/logout.mjs';

// Revocation and every supported delivery are one transaction. Delivery workers
// can resume the existing queues even if the request dies immediately afterward.
export function endSessionStatements(ctx,personId,operationId,g,q) {
 const now=ctx.now(),prefix=operationId+':';
 return [
  q(`UPDATE auth_role_operations SET detail=json_set(detail,
   '$.nativeSessionsEnded',(SELECT count(*) FROM auth_sessions WHERE person_id=? AND revoked_at IS NULL),
   '$.refreshGrantsEnded',(SELECT count(*) FROM auth_refresh_families WHERE person_id=? AND revoked_at IS NULL),
   '$.unavailable',(SELECT count(*) FROM auth_grants g JOIN auth_clients c ON c.id=g.client_id WHERE g.person_id=? AND c.disabled_at IS NULL AND c.logout_uri IS NULL)
    +(SELECT count(*) FROM (SELECT os.client_id FROM auth_oidc_sessions os JOIN auth_sessions s ON s.id=os.session_id JOIN auth_oidc_clients c ON c.client_id=os.client_id WHERE s.person_id=? AND c.backchannel_logout_uri IS NULL
      UNION SELECT f.client_id FROM auth_refresh_families f JOIN auth_oidc_clients c ON c.client_id=f.client_id WHERE f.person_id=? AND f.revoked_at IS NULL AND c.backchannel_logout_uri IS NULL)))
   WHERE id=? AND ${g.clause}`,personId,personId,personId,personId,personId,operationId,...g.args),
  q(`INSERT INTO auth_logout_deliveries(id,client_id,person_id,event,jti,next_attempt_at,created_at)
   SELECT ?||c.id,c.id,?,?,?||c.id,?,? FROM auth_grants grants JOIN auth_clients c ON c.id=grants.client_id
   WHERE grants.person_id=? AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL AND ${g.clause}`,
  prefix+'link:',personId,LOGOUT_EVENT,prefix+'link:',now,now,personId,...g.args),
  q(`INSERT INTO auth_oidc_logouts(id,client_id,person_id,sid,jti,next_attempt_at,created_at)
   SELECT ?||os.session_id||':'||os.client_id,os.client_id,s.person_id,os.session_id,?||os.session_id||':'||os.client_id,?,?
   FROM auth_oidc_sessions os JOIN auth_sessions s ON s.id=os.session_id JOIN auth_oidc_clients c ON c.client_id=os.client_id
   WHERE s.person_id=? AND c.backchannel_logout_uri IS NOT NULL AND ${g.clause}`,
  prefix+'oidc:',prefix+'oidc:',now,now,personId,...g.args),
  q(`INSERT INTO auth_oidc_logouts(id,client_id,person_id,sid,jti,next_attempt_at,created_at)
   SELECT ?||f.id,f.client_id,f.person_id,f.id,?||f.id,?,? FROM auth_refresh_families f JOIN auth_oidc_clients c ON c.client_id=f.client_id
   WHERE f.person_id=? AND f.logout_queued_at IS NULL AND c.backchannel_logout_uri IS NOT NULL AND ${g.clause}`,
  prefix+'refresh:',prefix+'refresh:',now,now,personId,...g.args),
  q(`UPDATE auth_refresh_families SET revoked_at=COALESCE(revoked_at,?),reason=CASE WHEN revoked_at IS NULL THEN 'help_desk_ended_sessions' ELSE reason END,logout_queued_at=COALESCE(logout_queued_at,?) WHERE person_id=? AND ${g.clause}`,now,now,personId,...g.args),
  q(`UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND revoked_at IS NULL AND ${g.clause}`,now,personId,...g.args),
  q(`DELETE FROM auth_oidc_sessions WHERE session_id IN (SELECT id FROM auth_sessions WHERE person_id=?) AND ${g.clause}`,personId,...g.args),
 ];
}
