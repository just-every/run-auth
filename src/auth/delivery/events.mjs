import {verifyWebhook} from '../../modules/mail/index.mjs';
import {hash,one,json,fail} from '../core.mjs';
import {recipientHash} from './send.mjs';

const states={processed:'accepted',deferred:'deferred',delivered:'delivered',bounce:'bounced',dropped:'rejected',spamreport:'complained'};
const suppress=new Set(['bounced','rejected','complained']);
const bounded=value=>typeof value==='string'&&value.length>0&&value.length<=1024&&!/[\x00-\x1f\x7f]/.test(value);

export async function sendgridEvents(ctx,request) {
 if(request.method!=='POST')fail('method_not_allowed',405);
 if(ctx.mailProvider!=='sendgrid'||!ctx.sendgridWebhookKey)fail('not_found',404);
 if(Number(request.headers.get('content-length')??0)>1048576)fail('request_too_large',413);
 const reader=request.body?.getReader(),chunks=[];let size=0;
 if(reader)try {for(;;){const {value,done}=await reader.read();if(done)break;size+=value.length;if(size>1048576){await reader.cancel();fail('request_too_large',413);}chunks.push(value);}}finally{reader.releaseLock();}
 const raw=new Uint8Array(size);let offset=0;for(const chunk of chunks){raw.set(chunk,offset);offset+=chunk.length;}
 if(!await verifyWebhook({provider:'sendgrid',rawBody:raw,headers:request.headers,key:ctx.sendgridWebhookKey,now:ctx.now()}))fail('delivery_event_unauthorized',401);
 let batch;try{batch=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(raw));}catch{fail('invalid_delivery_event');}
 if(!Array.isArray(batch)||!batch.length||batch.length>1000)fail('invalid_delivery_event');
 const pending=[];
 // Authenticate and validate the entire batch before its first write. Events
 // belonging to another product or an unknown local claim have no effect.
 for(const event of batch) {
  if(!event||typeof event!=='object'||!bounded(event.sg_event_id)||!Number.isSafeInteger(event.timestamp)||event.timestamp<0||event.timestamp*1000>ctx.now()+300000)fail('invalid_delivery_event');
  if(!Object.hasOwn(states,event.event)||event.rer_product!=='auth'||!bounded(event.rer_delivery_id)||typeof event.email!=='string')continue;
  const recipient=await recipientHash(ctx,event.email),claim=await one(ctx,"SELECT id,created_at FROM auth_mail_deliveries WHERE id=? AND recipient_hash=? AND provider='sendgrid' AND state NOT IN ('queued','suppressed')",event.rer_delivery_id,recipient);
  if(!claim||event.timestamp*1000<claim.created_at-300000)continue;
  const state=states[event.event],at=event.timestamp*1000,id=await hash(event.sg_event_id);
  // An event ID reused with different normalized evidence refuses the batch.
  const existing=await one(ctx,'SELECT delivery_id,state,occurred_at FROM auth_mail_events WHERE id=?',id);
  if(existing&&(existing.delivery_id!==claim.id||existing.state!==state||existing.occurred_at!==at))fail('delivery_event_conflict',409);
  pending.push({id,deliveryId:claim.id,recipient,state,at});
 }
 const statements=[];
 for(const event of pending) {
  statements.push(ctx.db.prepare('INSERT OR IGNORE INTO auth_mail_events(id,delivery_id,state,occurred_at) VALUES(?,?,?,?)').bind(event.id,event.deliveryId,event.state,event.at));
  // Negative terminal evidence always stops later mail. Delivery cannot erase
  // a bounce, and an old processed event cannot regress a final outcome.
  statements.push(ctx.db.prepare(`UPDATE auth_mail_deliveries SET state=?,event_at=?,updated_at=?,error=NULL WHERE id=? AND
   ((?=1 AND state NOT IN ('bounced','rejected','complained')) OR
    (COALESCE(event_at,0)<=? AND state NOT IN ('delivered','bounced','rejected','complained')))`)
   .bind(event.state,event.at,ctx.now(),event.deliveryId,suppress.has(event.state)?1:0,event.at));
  if(suppress.has(event.state))statements.push(ctx.db.prepare('INSERT OR IGNORE INTO auth_mail_suppressions(recipient_hash,reason,created_at) VALUES(?,?,?)').bind(event.recipient,event.state,ctx.now()));
 }
 if(statements.length)try{await ctx.db.batch(statements);}catch{fail('delivery_event_conflict',409);}
 return json({ok:true});
}
