import {fail} from '../core.mjs';
const pad=n=>String(n).padStart(2,'0');
const dateOf=p=>`${p.year}-${pad(p.month)}-${pad(p.day)}`;
export function calendar(value={}) {
 if(!value||typeof value!=='object'||Array.isArray(value))fail('invalid_followup_calendar');
 const timezone=value.timezone??'UTC';
 try {new Intl.DateTimeFormat('en',{timeZone:timezone}).format(0);}catch{fail('invalid_followup_timezone');}
 const weekdays=value.weekdays??[1,2,3,4,5],holidays=value.holidays??[],at=value.at??'09:00';
 if(typeof timezone!=='string'||timezone.length>100||!Array.isArray(weekdays)||!weekdays.length||weekdays.length>7||new Set(weekdays).size!==weekdays.length||weekdays.some(d=>!Number.isInteger(d)||d<0||d>6))fail('invalid_followup_calendar');
 if(!Array.isArray(holidays)||holidays.length>366||holidays.some(d=>typeof d!=='string'||!/^\d{4}-\d{2}-\d{2}$/.test(d)||!Number.isFinite(Date.parse(d+'T00:00:00Z'))||new Date(d+'T00:00:00Z').toISOString().slice(0,10)!==d)||!/^([01]\d|2[0-3]):[0-5]\d$/.test(at))fail('invalid_followup_calendar');
 return {timezone,weekdays:[...weekdays].sort(),holidays:[...new Set(holidays)].sort(),at};
}
function parts(at,zone) {
 const p=Object.fromEntries(new Intl.DateTimeFormat('en-CA',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',hourCycle:'h23'}).formatToParts(at).filter(p=>p.type!=='literal').map(p=>[p.type,Number(p.value)]));
 return p;
}
const wall=p=>Date.UTC(p.year,p.month-1,p.day,p.hour??0,p.minute??0,p.second??0);
const working=(day,c)=>c.weekdays.includes(new Date(day+'T00:00:00Z').getUTCDay())&&!c.holidays.includes(day);
// Round-trip candidate offsets, including both sides of a timezone transition.
// A repeated wall minute uses its first occurrence; a skipped minute advances
// to the first real wall minute after the gap rather than changing the date.
function instant(p,zone) {
 const target=wall(p),offsets=new Set();
 for(let hours=-36;hours<=36;hours+=6){const t=target+hours*3600000;offsets.add(wall(parts(t,zone))-t);}
 for(let minute=0;minute<=180;minute++) {
  const wanted=target+minute*60000,candidates=[...offsets].map(o=>wanted-o).filter(t=>wall(parts(t,zone))===wanted);
  if(candidates.length)return Math.min(...candidates);
 }
 fail('unresolvable_followup_calendar');
}
export function businessDue(after,days,c) {
 const p=parts(after,c.timezone),[hour,minute]=c.at.split(':').map(Number);let d=new Date(Date.UTC(p.year,p.month-1,p.day)),remaining=days;
 if(days>0)d.setUTCDate(d.getUTCDate()+1);
 for(let guard=0;guard<1100;guard++,d.setUTCDate(d.getUTCDate()+1)) {
  if(!working(d.toISOString().slice(0,10),c))continue;
  if(remaining>1){remaining--;continue;}
  const due=instant({year:d.getUTCFullYear(),month:d.getUTCMonth()+1,day:d.getUTCDate(),hour,minute},c.timezone);
  if(due>after)return due;
 }
 fail('unresolvable_followup_calendar');
}
export function deliveryWindow(now,c) {
 const p=parts(now,c.timezone),[hour,minute]=c.at.split(':').map(Number);
 return working(dateOf(p),c)&&p.hour*60+p.minute>=hour*60+minute;
}
