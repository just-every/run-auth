import {fail} from '../core.mjs';
const DAY=86400000,unknown='unknown';
const iso=value=>value===null||value===undefined?unknown:new Date(value).toISOString();
const observed=(value,asOf)=>value!==null&&value!==undefined&&value<=asOf?value:null;

export function timingPeriod(query,now) {
 const parse=(key,fallback)=>{
  if(!query.has(key))return fallback;
  const value=query.get(key),at=Date.parse(value);
  if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/.test(value)||!Number.isSafeInteger(at))fail('invalid_timing_period');
  return at;
 };
 const asOf=parse('asOf',now),end=parse('end',asOf),start=parse('start',end-30*DAY);
 if(asOf>now||start>=end||end>asOf||end-start>366*DAY)fail('invalid_timing_period');
 return {start,end,asOf};
}

export function episodeProjection(episode,inventory,visibleApp,asOf) {
 const all=inventory.filter(row=>row.episode_id===episode.id),hidden=all.some(row=>!visibleApp(row.app_id,row.channel));
 const visible=all.filter(row=>visibleApp(row.app_id,row.channel));
 const facts=visible.map(row=>({appId:row.app_id,app:row.app_name,channel:row.channel.startsWith('scim-group:')?'scim-group':row.channel,
  eventAt:iso(episode.event_at),localDenialAt:iso(episode.local_denial_at),
  dispatchedAt:iso(observed(row.dispatched_at,asOf)),acceptedAt:iso(observed(row.accepted_at,asOf)),
  remoteVerifiedAt:iso(observed(row.verified_at,asOf)),
  observation:observed(row.verified_at,asOf)!==null?'remote readback':row.connector_retired?'connector removed; unverified':row.channel==='backchannel'&&observed(row.accepted_at,asOf)!==null?'back-channel accepted; remote state unknown':'unverified'}));
 const complete=episode.inventory_complete===1&&!hidden&&all.length>0&&all.every(row=>(row.channel==='scim'||row.channel.startsWith('scim-group:'))&&observed(row.verified_at,asOf)!==null);
 const completedAt=complete?Math.max(episode.local_denial_at,...all.map(row=>row.verified_at)):null;
 return {episodeId:episode.id,leaverEventAt:iso(episode.event_at),localDenialAt:iso(episode.local_denial_at),
  dispatchedAt:!hidden&&all.length&&all.every(row=>observed(row.dispatched_at,asOf)!==null)?iso(Math.max(...all.map(row=>row.dispatched_at))):unknown,
  remoteVerifiedAt:iso(completedAt),observedDeprovisionAt:iso(completedAt),fullDeprovisionAt:unknown,
  apps:facts,inventoryCoverage:episode.inventory_complete===1?'captured native inventory':'unknown after evidence erasure',unresolvedApps:[...new Set(facts.filter(row=>row.remoteVerifiedAt===unknown).map(row=>row.app))],
  unresolvedOutsideScope:hidden?unknown:false,sourceObservedAt:unknown,
  timingQualification:'native committed denial and captured app observations; all-surface qualification unknown'};
}

export function timingSummary(rows,period) {
 const durations=rows.map(row=>row.observedDeprovisionAt===unknown?null:Date.parse(row.observedDeprovisionAt)-Date.parse(row.leaverEventAt));
 const count=limit=>durations.filter(value=>value!==null&&value>=0&&value<=limit).length;
 const total=rows.length,known=durations.filter(value=>value!==null).length;
 return {start:iso(period.start),end:iso(period.end),asOf:iso(period.asOf),leaverEpisodes:total,
  nativeObservedComplete:known,nativeWithinOneHour:count(3600000),nativeWithin24Hours:count(DAY),unknownEpisodes:total-known,
  nativeShareWithinOneHour:total?count(3600000)/total:unknown,nativeShareWithin24Hours:total?count(DAY)/total:unknown,
  fullyDeprovisionedWithinOneHour:unknown,fullyDeprovisionedWithin24Hours:unknown,
  coverage:'Captured native inventory only. Unknown, hidden, unsupported and unobserved apps never count as complete. Historical missing episodes and all-surface coverage remain unknown.'};
}
