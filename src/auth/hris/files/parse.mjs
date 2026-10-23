import {readCsv} from '../../move-in/csv.mjs';
import {addressOf} from '../../move-in/parse.mjs';
import {fail} from '../../core.mjs';
export const MAX_BYTES=1024*1024;
const FIELDS=['sourceId','email','name','kind','department','location','title','manager','start_date','end_date','state','effectiveAt'];
export function feedMapping(value) {
 if(!value||typeof value!=='object'||Array.isArray(value)||Object.keys(value).some(key=>!FIELDS.includes(key))||
    !['sourceId','email','state','effectiveAt'].every(key=>typeof value[key]==='string')||
    Object.values(value).some(column=>typeof column!=='string'||!column.trim()||column.length>100)||new Set(Object.values(value)).size!==Object.keys(value).length)fail('invalid_hr_mapping');
 const mapped=Object.fromEntries(Object.entries(value).map(([key,column])=>[key,column.trim()]));
 if(new Set(Object.values(mapped)).size!==Object.keys(mapped).length)fail('invalid_hr_mapping');
 return mapped;
}
export function parseFeed(text,mapping) {
 if(typeof text!=='string'||new TextEncoder().encode(text).length>MAX_BYTES||text.includes('\0'))return {records:[],errors:['malformed_file']};
 let csv;try{csv=readCsv(text,202,100);}catch{return {records:[],errors:['malformed_file']};}
 if(!csv.length)return {records:[],errors:['empty_file']};
 const headers=csv[0].map(column=>column.trim());
 if(new Set(headers).size!==headers.length||Object.values(mapping).some(column=>!headers.includes(column)))return {records:[],errors:['malformed_mapping']};
 const rows=csv.slice(1);if(!rows.length)return {records:[],errors:['empty_file']};
 if(rows.length>200)return {records:[],errors:['too_many_rows']};
 const records=[],ids=new Set(),emails=new Set();
 for(const row of rows) {
  if(row.length!==headers.length)return {records:[],errors:['malformed_row']};
  const value=Object.fromEntries(Object.entries(mapping).map(([field,column])=>[field,(row[headers.indexOf(column)]??'').trim()]));
  const {email,problem}=addressOf(value.email),sourceId=value.sourceId,effectiveAt=Date.parse(value.effectiveAt);
  if(problem||!sourceId||sourceId.length>80||/[\x00-\x20]/.test(sourceId)||ids.has(sourceId)||emails.has(email)||
     !['active','suspended','terminated'].includes(value.state)||!/^\d{4}-\d\d-\d\dT(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(value.effectiveAt)||!Number.isFinite(effectiveAt)||!new Date(value.effectiveAt.slice(0,10)+'T00:00:00Z').toISOString().startsWith(value.effectiveAt.slice(0,10))||
     Object.values(value).some(item=>item.length>320))return {records:[],errors:['invalid_hr_record']};
  ids.add(sourceId);emails.add(email);
  const fields=Object.fromEntries(Object.entries(value).filter(([key,v])=>!['sourceId','email','state','effectiveAt'].includes(key)&&v!==''));
  records.push({sourceId,email,fields,state:value.state,effectiveAt});
 }
 return {records,errors:[]};
}
