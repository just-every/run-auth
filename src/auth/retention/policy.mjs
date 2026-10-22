import {one,fail,DAY} from '../core.mjs';
export const CLASSES=Object.freeze(['profiles','sourceSnapshots','authentication','decisions','provisioning','audit','modelTraces','erasureReceipts']);
export const PREVIEW_WINDOW=7*DAY;
export const DEFAULT_POLICY=Object.freeze({classes:Object.fromEntries(CLASSES.map(name=>[name,{unit:'months',value:13}]))});
export async function retentionPolicy(ctx) {
 const row=await one(ctx,'SELECT policy,revision,updated_by,updated_at FROM auth_retention_policy WHERE id=1');
 return row?{...JSON.parse(row.policy),revision:row.revision,configured:true,updatedBy:row.updated_by,updatedAt:row.updated_at}:{...DEFAULT_POLICY,revision:0,configured:false};
}
// Calendar arithmetic clamps the original day, including leap days. Thirteen
// months never means 390 fixed days and seven years never means 2555 days.
export function subtractPeriod(at,period) {
 if(period.unit==='days')return at-period.value*DAY;
 const date=new Date(at),day=date.getUTCDate();date.setUTCDate(1);
 date.setUTCMonth(date.getUTCMonth()-(period.unit==='years'?12*period.value:period.value));
 const last=new Date(Date.UTC(date.getUTCFullYear(),date.getUTCMonth()+1,0)).getUTCDate();
 date.setUTCDate(Math.min(day,last));return date.getTime();
}
export function validateRetentionPolicy(data) {
 if(data.confirm!==true)fail('retention_explicit_confirmation_required');
 if(!data.classes||typeof data.classes!=='object'||Array.isArray(data.classes)||Object.keys(data.classes).some(name=>!CLASSES.includes(name)))fail('invalid_retention_classes');
 const classes={};
 for(const name of CLASSES) {
  const value=data.classes[name];
  if(!value||!['days','months','years'].includes(value.unit)||!Number.isInteger(value.value)||value.value<1)fail('invalid_retention_period');
  const limits={days:[90,2556],months:[3,84],years:[1,7]}[value.unit];
  // Three calendar months can be shorter than ninety days. Require four.
  if(value.value<limits[0]||value.value>limits[1]||(value.unit==='months'&&value.value===3))fail('retention_period_out_of_bounds');
  if(value.unit==='days'&&value.value>2555)fail('retention_use_calendar_years_for_seven_year_max');
  classes[name]={unit:value.unit,value:value.value};
 }
 return {classes};
}
