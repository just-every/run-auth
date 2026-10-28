import {logoutBinding,approvedBinding} from '../lifecycle/binding.mjs';
import {appAccess} from '../onboarding/gate.mjs';
// What a general OIDC app gets after sign-in: UserInfo while the person, the
// session and the app assignment all still hold, and front- and back-channel
// logout when the Auth session ends.
import {one,all,run,random,json,sessionById,EMAIL_MAX_AGE} from '../core.mjs';
import {signToken} from '../keys.mjs';
import {assignment} from '../workforce/directory.mjs';
import {SCOPES,subjectFor,claimsFor} from './clients.mjs';

const HORIZON=86400000,RETRY=[60000,300000,900000,3600000,10800000];
const refusal=()=>json({error:'invalid_token'},401,{'www-authenticate':'Bearer realm="userinfo", error="invalid_token"'});

export async function genericUserinfo(ctx,request,payload,client) {
 const scopes=payload.scope.split(' ');
 if(!scopes.includes('openid')||scopes.some(s=>!SCOPES.includes(s)))return refusal();
 const s=await sessionById(ctx,request,payload.sid),assigned=s&&await assignment(ctx,client.app_id,s.person_id);
 const proof=s&&await one(ctx,'SELECT verified_at FROM auth_emails WHERE person_id=?',s.person_id);
 if(!assigned||!await appAccess(ctx,s)||!proof||ctx.now()-proof.verified_at>EMAIL_MAX_AGE||await subjectFor(ctx,client,s.person_id)!==payload.sub)return refusal();
 return json({sub:payload.sub,...await claimsFor(ctx,client,s,scopes,assigned.role,proof.verified_at)});
}

// The session's general OIDC apps: front-channel frames to show now, and
// back-channel logout tokens queued and sent.
export async function endGenericSessions(ctx,s) {
 const apps=await all(ctx,'SELECT c.client_id,c.frontchannel_logout_uri,c.backchannel_logout_uri FROM auth_oidc_sessions os JOIN auth_oidc_clients c ON c.client_id=os.client_id WHERE os.session_id=?',s.id);
 await run(ctx,'DELETE FROM auth_oidc_sessions WHERE session_id=?',s.id);
 const now=ctx.now(),queued=apps.filter(a=>a.backchannel_logout_uri).map(a=>({id:random(),client:a.client_id}));
 if(queued.length)await ctx.db.batch(queued.map(q=>ctx.db.prepare('INSERT INTO auth_oidc_logouts(id,client_id,person_id,sid,jti,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?)').bind(q.id,q.client,s.person_id,s.id,random(),now,now)));
 if(queued.length){const work=deliverGenericLogouts(ctx,queued.map(q=>q.id));if(ctx.waitUntil)ctx.waitUntil(work);else await work;}
 return apps.filter(a=>a.frontchannel_logout_uri).map(a=>{const url=new URL(a.frontchannel_logout_uri);url.searchParams.set('iss',(ctx.issuer??ctx.origin));url.searchParams.set('sid',s.id);return url.href;});
}

async function attempt(ctx,d) {
 const client=await one(ctx,'SELECT * FROM auth_oidc_clients WHERE client_id=?',d.client_id);
 if(!client?.backchannel_logout_uri)return {finished:true,outcome:'app_removed'};
 if(!await approvedBinding(ctx,d.id,await logoutBinding(client,true)))return {finished:true,outcome:'approved_app_changed'};
 const token=await signToken(ctx,{aud:client.client_id,sub:await subjectFor(ctx,client,d.person_id),sid:d.sid,jti:d.jti,events:{'http://schemas.openid.net/event/backchannel-logout':{}}},{alg:client.id_token_alg,typ:'logout+jwt',expiresAt:Math.floor(ctx.now()/1000)+120});
 let status;
 try {
  const response=await (ctx.connectorFetch||fetch)(client.backchannel_logout_uri,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({logout_token:token}).toString()});
  status=response.status;await response.body?.cancel();
 } catch {status=0;}
 if(status>=200&&status<300)return {finished:true,outcome:'delivered'};
 if(status>=400&&status<500&&status!==408&&status!==429)return {finished:true,outcome:`refused_${status}`};
 return {finished:false,outcome:status?`retry_${status}`:'retry_unreachable'};
}
export async function deliverGenericLogouts(ctx,ids=null) {
 const due=ids?await all(ctx,`SELECT * FROM auth_oidc_logouts WHERE finished_at IS NULL AND id IN (${ids.map(()=>'?').join(',')})`,...ids)
  :await all(ctx,'SELECT * FROM auth_oidc_logouts WHERE finished_at IS NULL AND next_attempt_at<=? ORDER BY next_attempt_at LIMIT 50',ctx.now());
 for(const row of due) {
  const d=await one(ctx,'UPDATE auth_oidc_logouts SET claimed_until=? WHERE id=? AND finished_at IS NULL AND next_attempt_at<=? AND (claimed_until IS NULL OR claimed_until<=?) RETURNING *',ctx.now()+120000,row.id,ctx.now(),ctx.now());
  if(!d)continue;
  const result=await attempt(ctx,d),attempts=d.attempts+1,next=ctx.now()+RETRY[Math.min(attempts-1,RETRY.length-1)],expired=!result.finished&&next>d.created_at+HORIZON;
  await run(ctx,'UPDATE auth_oidc_logouts SET claimed_until=NULL,attempts=?,next_attempt_at=?,finished_at=?,outcome=? WHERE id=? AND finished_at IS NULL',attempts,next,result.finished||expired?ctx.now():null,expired?'abandoned_after_24h':result.outcome,d.id);
 }
}
