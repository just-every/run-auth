import {maintainFamilies} from '../tokens/lifecycle.mjs';
// Back-channel logout and identity fences for linked apps. Each delivery is a
// signed logout+jwt with one stable jti, posted to the app's registered logout
// path and retried until it is accepted or 24 hours have passed.
import {random,one,all,run,json,requireSession,cookie,cookieName,audit} from '../core.mjs';
import {signToken,pairwiseSubject} from '../keys.mjs';
import {fetcherOf} from './app.mjs';

export const LOGOUT_EVENT='http://schemas.openid.net/event/backchannel-logout';
export const FENCE_EVENT='https://runeditrun.com/events/identity-fence';
const HORIZON=86400000,AT_ONCE=50,RETRY=[60000,300000,900000,3600000,10800000,21600000,43200000];

// clients: [{id}] to address; sid narrows a logout to one Auth session.
export async function queueLogouts(ctx,personId,{event=LOGOUT_EVENT,sid=null,clients=null}={}) {
 const targets=clients??await all(ctx,'SELECT c.id FROM auth_grants g JOIN auth_clients c ON c.id=g.client_id WHERE g.person_id=? AND c.disabled_at IS NULL AND c.logout_uri IS NOT NULL',personId);
 return queue(ctx,targets.map(c=>({client:c.id,person:personId})),event,sid);
}

// A removed app: everyone it signed in through Auth is signed out there, since
// Auth sends it no later sign-out or fence. The first deliveries go now, the
// rest with the scheduled retries.
export async function signOutRemovedApp(ctx,clientId) {
 const people=await all(ctx,'SELECT g.person_id FROM auth_grants g JOIN auth_clients c ON c.id=g.client_id WHERE g.client_id=? AND c.logout_uri IS NOT NULL',clientId);
 return queue(ctx,people.map(p=>({client:clientId,person:p.person_id})),LOGOUT_EVENT,null,AT_ONCE);
}

async function queue(ctx,targets,event,sid,atOnce=targets.length) {
 if(!targets.length)return [];
 const now=ctx.now(),ids=targets.map(()=>random());
 await ctx.db.batch(targets.map((t,i)=>ctx.db.prepare('INSERT INTO auth_logout_deliveries(id,client_id,person_id,event,sid,jti,next_attempt_at,created_at) VALUES(?,?,?,?,?,?,?,?)').bind(ids[i],t.client,t.person,event,sid,random(),now,now)));
 const work=deliverLogouts(ctx,ids.slice(0,atOnce));
 if(ctx.waitUntil)ctx.waitUntil(work);else await work;
 return ids;
}

// A delivery queued before its app was removed still goes: the person's
// sessions there were made by Auth and can still be live.
async function attempt(ctx,d) {
 const client=await one(ctx,'SELECT id,sector_id,logout_uri FROM auth_clients WHERE id=?',d.client_id);
 if(!client||!client.logout_uri)return {finished:true,outcome:'app_removed'};
 const claims={aud:client.id,sub:await pairwiseSubject(ctx,client.sector_id,d.person_id),jti:d.jti,events:{[d.event]:{}},...(d.sid?{sid:d.sid}:{})};
 const token=await signToken(ctx,claims,{typ:'logout+jwt',expiresAt:Math.floor(ctx.now()/1000)+120});
 let status;
 try {
  const response=await fetcherOf(ctx)(client.logout_uri,{method:'POST',redirect:'manual',signal:AbortSignal.timeout(10000),headers:{'content-type':'application/x-www-form-urlencoded'},body:new URLSearchParams({logout_token:token}).toString()});
  status=response.status;await response.body?.cancel();
 } catch {status=0;}
 // 409 means the app already consumed this jti: an earlier attempt arrived.
 if(status>=200&&status<300||status===409)return {finished:true,outcome:'delivered'};
 if(status>=400&&status<500&&status!==408&&status!==429)return {finished:true,outcome:`refused_${status}`};
 return {finished:false,outcome:status?`retry_${status}`:'retry_unreachable'};
}

export async function deliverLogouts(ctx,ids=null) {
 const now=ctx.now();
 const due=ids?await all(ctx,`SELECT * FROM auth_logout_deliveries WHERE finished_at IS NULL AND id IN (${ids.map(()=>'?').join(',')})`,...ids)
  :await all(ctx,'SELECT * FROM auth_logout_deliveries WHERE finished_at IS NULL AND next_attempt_at<=? ORDER BY next_attempt_at LIMIT 50',now);
 for(const d of due) {
  const result=await attempt(ctx,d),attempts=d.attempts+1,next=now+(RETRY[Math.min(attempts-1,RETRY.length-1)]);
  const expired=!result.finished&&next>d.created_at+HORIZON;
  await run(ctx,'UPDATE auth_logout_deliveries SET attempts=?,next_attempt_at=?,finished_at=?,outcome=? WHERE id=? AND finished_at IS NULL',attempts,next,result.finished||expired?ctx.now():null,expired?'abandoned_after_24h':result.outcome,d.id);
 }
}

// Everyone's own control: end every Auth session and tell every app this person used.
export async function signOutEverywhere(ctx,request) {
 const s=await requireSession(ctx,request);
 await run(ctx,'UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND revoked_at IS NULL',ctx.now(),s.person_id);
 await maintainFamilies(ctx,{personId:s.person_id,reason:'signed_out_everywhere'});
 const deliveries=await queueLogouts(ctx,s.person_id);
 await audit(ctx,s.person_id,'signed_out_everywhere',null);
 return json({ok:true,apps:deliveries.length},200,{'set-cookie':cookie(ctx,cookieName(ctx),'',0)});
}

// Suspension or compromise: every app fences this person's sessions and minted credentials.
export const fencePerson=(ctx,personId)=>queueLogouts(ctx,personId,{event:FENCE_EVENT});
