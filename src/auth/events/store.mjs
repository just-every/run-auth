// Versioned lifecycle events. Each is recorded after the change it reports has
// committed, gets a stable ID and an ordering number (the cursor), and is queued
// for every active subscriber whose types include it.
import {one,all} from '../core.mjs';
import {deliverEvents} from './delivery.mjs';

export const VERSION=1;
export const TYPES=['person.invited','person.activated','person.suspended','person.restored','person.role_changed','group.member_added','group.member_removed','app.assigned','app.unassigned','app.removed','provisioning.verified','provisioning.failed','recovery.requested','recovery.approved','recovery.cancelled','recovery.completed','policy.domain_allowed','policy.domain_rule_changed'];
export const matches=(types,type)=>types.includes('*')||types.includes(type);

// subject: {type, id, email?}; data carries no secrets, links or tokens.
export async function emit(ctx,type,subject,data={}) {
 if(!TYPES.includes(type))throw new Error('unknown event type '+type);
 const id='evt_'+[...crypto.getRandomValues(new Uint8Array(16))].map(b=>b.toString(16).padStart(2,'0')).join(''),now=ctx.now();
 const event=await one(ctx,'INSERT INTO auth_events(id,type,version,subject,data,occurred_at) VALUES(?,?,?,?,?,?) RETURNING seq',id,type,VERSION,JSON.stringify(subject),JSON.stringify(data),now);
 const subscribers=(await all(ctx,'SELECT id,types FROM auth_event_subscriptions WHERE disabled_at IS NULL')).filter(s=>matches(JSON.parse(s.types),type));
 if(!subscribers.length)return id;
 await ctx.db.batch(subscribers.map(s=>ctx.db.prepare("INSERT INTO auth_event_deliveries(subscription_id,seq,next_attempt_at,state) VALUES(?,?,?,'pending')").bind(s.id,event.seq,now)));
 const work=deliverEvents(ctx);if(ctx.waitUntil)ctx.waitUntil(work);else await work;
 return id;
}
export const personSubject=async(ctx,personId)=>{const p=await one(ctx,'SELECT id,email FROM oa_operators WHERE id=?',personId);return {type:'person',id:personId,email:p?.email??null};};
export const shape=row=>({id:row.id,type:row.type,version:row.version,seq:row.seq,occurredAt:new Date(row.occurred_at).toISOString(),subject:JSON.parse(row.subject),data:JSON.parse(row.data)});
// The cursor: events after `after` of the subscriber's types, in commit order.
export async function eventsAfter(ctx,types,after,limit) {
 const filter=types.includes('*')?'':` AND type IN (${types.map(()=>'?').join(',')})`;
 const rows=await all(ctx,`SELECT * FROM auth_events WHERE seq>?${filter} ORDER BY seq LIMIT ?`,after,...(types.includes('*')?[]:types),limit+1);
 return {events:rows.slice(0,limit).map(shape),hasMore:rows.length>limit};
}
