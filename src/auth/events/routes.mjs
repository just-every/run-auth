// Event subscriptions: administrators subscribe an endpoint, rotate its signing
// secret, replay an event or stop it; a subscriber reads missed events from a
// cursor with its own read key, which opens nothing else.
import {random,hash,one,all,run,json,fail,requireSession,auditDetail} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {seal} from '../keys.mjs';
import {toBase64} from '../saml/der.mjs';
import {outboundUrl} from '../outbound.mjs';
import {TYPES,eventsAfter} from './store.mjs';
import {deliverEvents,secretsOf} from './delivery.mjs';

const ACTIONS=['/events/subscribe','/events/rotate-secret','/events/replay','/events/disable'];
export const isEventsAction=path=>ACTIONS.includes(path);
export const EVENTS_READ='/api/auth/events';
const newSecret=()=>'whsec_'+toBase64(crypto.getRandomValues(new Uint8Array(32)));

export async function eventsAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const guard=authority(ctx,s,['owner','admin']),g=guard.clause,ga=guard.args;
 const held=async result=>{if(!result.meta.changes){await requireAuthority(ctx,s,guard);return false;}return true;};
 if(path==='/events/subscribe') {
  const url=outboundUrl(ctx,data.url,'invalid_event_url',{query:true}).href;
  const types=[data.types??'*'].flat().map(String).filter(Boolean);
  if(!types.length||types.some(t=>t!=='*'&&!TYPES.includes(t)))fail('invalid_event_types');
  const id=random(),secret=newSecret(),readKey='evr_'+random();
  if(!await held(await run(ctx,`INSERT INTO auth_event_subscriptions(id,url,types,sealed_secrets,read_key_hash,created_by,created_at) SELECT ?,?,?,?,?,?,? WHERE ${g}`,id,url,JSON.stringify(types),await seal(ctx,'events:'+id,JSON.stringify([{secret}])),await hash(readKey),s.person_id,ctx.now(),...ga)))fail('session_authority_changed',403);
  await auditDetail(ctx,s.person_id,'event_subscription_created',id,{url,types});
  // Both are shown once; Auth keeps the secret sealed and the read key as a digest.
  return json({id,secret,readKey,message:`Signing secret, shown once: ${secret}. Read key for the event cursor, shown once: ${readKey}`},201);
 }
 const sub=await one(ctx,'SELECT * FROM auth_event_subscriptions WHERE id=? AND disabled_at IS NULL',String(data.id||''))||fail('subscription_not_found',404);
 if(path==='/events/rotate-secret') {
  const hours=Number(data.overlapHours??24);if(!Number.isFinite(hours)||hours<0||hours>168)fail('invalid_overlap');
  const now=ctx.now(),secret=newSecret(),secrets=(await secretsOf(ctx,sub)).filter(x=>!x.until||x.until>now).map(x=>({...x,until:x.until??now+hours*3600000}));
  if(!await held(await run(ctx,`UPDATE auth_event_subscriptions SET sealed_secrets=? WHERE id=? AND sealed_secrets=? AND ${g}`,await seal(ctx,'events:'+sub.id,JSON.stringify([{secret},...secrets])),sub.id,sub.sealed_secrets,...ga)))fail('subscription_changed',409);
  await auditDetail(ctx,s.person_id,'event_secret_rotated',sub.id,{previousValidUntil:now+hours*3600000});
  return json({secret,message:`New signing secret, shown once: ${secret}. Deliveries are signed with the previous secret too for ${hours} hours.`});
 }
 if(path==='/events/replay') {
  const seq=Number(data.seq);if(!Number.isSafeInteger(seq))fail('event_not_found',404);
  const event=await one(ctx,'SELECT seq FROM auth_events WHERE seq=?',seq)||fail('event_not_found',404);
  if(!await held(await run(ctx,`INSERT INTO auth_event_deliveries(subscription_id,seq,next_attempt_at,state) SELECT ?,?,?,'pending' WHERE ${g} ON CONFLICT(subscription_id,seq) DO UPDATE SET state='pending',next_attempt_at=excluded.next_attempt_at,attempts=0`,sub.id,event.seq,ctx.now(),...ga)))fail('session_authority_changed',403);
  await auditDetail(ctx,s.person_id,'event_replayed',sub.id,{seq});
  await deliverEvents(ctx,sub.id);
  return json({ok:true,message:'Event sent again with its original ID.'});
 }
 if(!await held(await run(ctx,`UPDATE auth_event_subscriptions SET disabled_at=? WHERE id=? AND disabled_at IS NULL AND ${g}`,ctx.now(),sub.id,...ga)))fail('subscription_not_found',404);
 await auditDetail(ctx,s.person_id,'event_subscription_disabled',sub.id,{url:sub.url});
 return json({ok:true});
}

// GET /api/auth/events?after=<seq>&limit=<n> with "Authorization: Bearer <read key>".
export async function eventsRead(ctx,request) {
 const match=/^Bearer (evr_[A-Za-z0-9_-]{43})$/.exec(request.headers.get('authorization')||'');
 const sub=match&&await one(ctx,'SELECT * FROM auth_event_subscriptions WHERE read_key_hash=? AND disabled_at IS NULL',await hash(match[1]));
 if(!sub)return json({error:'invalid_token'},401,{'www-authenticate':'Bearer realm="events"'});
 const q=new URL(request.url).searchParams,after=Number(q.get('after')||0),limit=Math.min(Math.max(Number(q.get('limit')||100),1),500);
 if(!Number.isSafeInteger(after)||after<0||!Number.isSafeInteger(limit))fail('invalid_request');
 const page=await eventsAfter(ctx,JSON.parse(sub.types),after,limit);
 return json({...page,next:page.events.at(-1)?.seq??after});
}

export async function eventsModel(ctx) {
 const subs=await all(ctx,'SELECT id,url,types,created_at,disabled_at FROM auth_event_subscriptions ORDER BY created_at');
 const counts=await all(ctx,'SELECT subscription_id,state,COUNT(*) AS n,MAX(last_status) AS status FROM auth_event_deliveries GROUP BY subscription_id,state');
 return {types:TYPES,subscriptions:subs.map(x=>({id:x.id,url:x.url,types:JSON.parse(x.types),createdAt:x.created_at,status:x.disabled_at?'stopped':'active',deliveries:Object.fromEntries(counts.filter(c=>c.subscription_id===x.id).map(c=>[c.state,c.n]))}))};
}
