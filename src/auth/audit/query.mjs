import {all,one,fail,b64,unb64,utf8} from '../core.mjs';
import {roleState} from '../roles/state.mjs';
import {assertPermission,permitted,requireHardware} from '../roles/policy.mjs';

const integer=(value,min,max)=>{
 if(!/^\d+$/.test(String(value)))fail('invalid_audit_filter');
 const n=Number(value);if(!Number.isSafeInteger(n)||n<min||n>max)fail('invalid_audit_filter');return n;
};
const timestamp=(raw,fallback)=>{
 if(raw===null||raw==='')return fallback;
 if(/^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d)?$/.test(raw)) {
  const n=Date.parse(raw+'Z');if(Number.isFinite(n))return n;
 }
 return integer(raw,0,8640000000000000);
};
async function key(ctx) {
 if(typeof ctx.secret!=='string'||ctx.secret.length<32)fail('audit_cursor_unavailable',503);
 return crypto.subtle.importKey('raw',utf8.encode(ctx.secret),{name:'HMAC',hash:'SHA-256'},false,['sign','verify']);
}
async function encode(ctx,value) {
 const body=b64(utf8.encode(JSON.stringify(value)));
 return body+'.'+b64(await crypto.subtle.sign('HMAC',await key(ctx),utf8.encode('auth-audit-v1:'+body)));
}
async function decode(ctx,raw) {
 if(raw.length>4096)fail('invalid_audit_cursor');
 try {
  const [body,signature,...rest]=raw.split('.');
  if(rest.length||!await crypto.subtle.verify('HMAC',await key(ctx),unb64(signature),utf8.encode('auth-audit-v1:'+body)))fail('invalid_audit_cursor');
  return JSON.parse(new TextDecoder().decode(unb64(body)));
 }catch {fail('invalid_audit_cursor');}
}
export async function auditPage(ctx,s,request) {
 requireHardware(s);
 const state=await roleState(ctx,s);assertPermission(state,'audit.view',{write:false});
 const params=new URL(request.url).searchParams;
 for(const name of ['from','to','person','event','limit','cursor'])if(params.getAll(name).length>1)fail('invalid_audit_filter');
 const filters={from:timestamp(params.get('from'),0),to:timestamp(params.get('to'),8640000000000000),person:params.get('person')??'',event:params.get('event')??''};
 if(filters.from>filters.to||filters.person.length>200||filters.event.length>100||filters.event&&!/^[a-zA-Z0-9_.-]+$/.test(filters.event))fail('invalid_audit_filter');
 if(filters.person&&!state.legacy)assertPermission(state,'audit.view',{personId:filters.person,write:false});
 const limit=integer(params.get('limit')??50,1,100),binding={issuer:ctx.issuer??ctx.origin,organization:ctx.organizationId??'root',session:s.id,epoch:state.epoch,filters,limit};
 let cursor;
 if(params.has('cursor')) {
  cursor=await decode(ctx,params.get('cursor'));
  if(JSON.stringify(cursor.binding)!==JSON.stringify(binding))fail('audit_cursor_authority_changed',409);
  if(cursor.expiresAt<=ctx.now())fail('audit_cursor_expired',410);
  integer(cursor.max,0,Number.MAX_SAFE_INTEGER);integer(cursor.before,0,Number.MAX_SAFE_INTEGER);
 } else {
  const max=(await one(ctx,'SELECT COALESCE(MAX(id),0) AS id FROM auth_activity')).id;
  cursor={binding,max,before:max+1,asOf:ctx.now(),expiresAt:ctx.now()+15*60000};
 }
 // Scope is rebuilt for every page. Summaries expose no free-form plans or
 // personal fields from another resource carried inside an event's details.
 const visible=new Set();
 if(!state.legacy) {
  for(const p of state.dir.people.values())if(permitted(state,'audit.view',{personId:p.id,write:false})){visible.add(p.id);visible.add(p.email);}
  for(const [kind,rows] of [['groupId',state.dir.groups],['appId',state.apps],['caseId',state.cases]])for(const row of rows)if(permitted(state,'audit.view',{[kind]:row.id,write:false}))visible.add(row.id);
 }
 const person=filters.person?state.dir.people.get(filters.person):null;
 const where=['a.id<=?','a.created_at>=?','a.created_at<=?'],args=[cursor.max,filters.from,Math.min(filters.to,cursor.asOf)];
 if(filters.event){where.push('a.event=?');args.push(filters.event);}
 if(filters.person){where.push('(a.actor_id=? OR a.subject_id=? OR a.subject_id=?)');args.push(filters.person,filters.person,person?.email??filters.person);}
 if(!state.legacy) {
  where.push('(a.subject_id IN (SELECT value FROM json_each(?)) OR (a.subject_id IS NULL AND a.actor_id IN (SELECT value FROM json_each(?))))');
  const scope=JSON.stringify([...visible]);args.push(scope,scope);
  // Apply related-resource exclusions before either counting or paging. Names
  // in older native details are accepted only when they resolve unambiguously.
  const groups=state.dir.groups,groupNames=groups.filter(g=>groups.filter(other=>other.name===g.name).length===1&&visible.has(g.id)).map(g=>g.name);
  const references={person:[...state.dir.people.values()].filter(p=>visible.has(p.id)).flatMap(p=>[p.id,p.email]),group:[...groups.filter(g=>visible.has(g.id)).map(g=>g.id),...groupNames],app:state.apps.filter(a=>visible.has(a.id)).map(a=>a.id),case:state.cases.filter(c=>visible.has(c.id)).map(c=>c.id)};
  const fields={person:['person','personId','person_id'],group:['group','groupId','group_id'],app:['app','appId','app_id'],case:['caseId','case_id']};
  const conditions=[];
  for(const [kind,keys] of Object.entries(fields)) {
   const plural=kind==='person'?'people':kind==='case'?'cases':kind+'s';
   conditions.push(`((j.key IN (${keys.map(()=>'?').join(',')}) OR parent.key=? OR j.path LIKE ? OR j.path LIKE ?) AND (j.type!='text' OR j.value NOT IN (SELECT value FROM json_each(?))))`);
   args.push(...keys,plural,'%.'+plural+'.%','%.'+plural+'[%',JSON.stringify(references[kind]));
  }
  where.push(`NOT EXISTS(SELECT 1 FROM auth_activity_details related, json_tree(CASE WHEN json_valid(related.detail) THEN related.detail ELSE '{}' END) j LEFT JOIN json_tree(CASE WHEN json_valid(related.detail) THEN related.detail ELSE '{}' END) parent ON parent.id=j.parent WHERE related.activity_id=a.id AND j.type NOT IN ('null','object','array') AND (${conditions.join(' OR ')}))`);
  where.push(`(a.event NOT IN ('app_assigned','app_unassigned','group_member_added','group_member_removed') OR EXISTS(SELECT 1 FROM auth_activity_details related WHERE related.activity_id=a.id AND json_valid(related.detail) AND (json_type(related.detail,'$.person')='text' OR json_type(related.detail,'$.group')='text')))`);
  // The companion native event records all assignment targets; the generic
  // command receipt does not and cannot safely qualify a scoped read.
  where.push("a.event!='roles.command'");

 }
 const predicate=where.join(' AND ');
 const {total}=await one(ctx,`SELECT COUNT(*) AS total FROM auth_activity a WHERE ${predicate}`,...args);
 const rows=await all(ctx,`SELECT a.id,a.actor_id,a.event,a.subject_id,a.created_at,p.email AS actor_email,service.name AS service_name,custodian.email AS service_owner_email,d.detail FROM auth_activity a LEFT JOIN oa_operators p ON p.id=a.actor_id LEFT JOIN auth_admin_service_apps service ON a.actor_id='admin-service:'||service.id LEFT JOIN oa_operators custodian ON custodian.id=service.owner_id LEFT JOIN auth_activity_details d ON d.activity_id=a.id WHERE ${predicate} AND a.id<? ORDER BY a.id DESC LIMIT ?`,...args,cursor.before,limit+1);
 const events=rows.map(row=>{
  const eventId=`${ctx.organizationId??'root'}:activity:${row.id}`;
  return state.legacy?{...row,eventId}:{id:row.id,eventId,event:row.event,actor_id:row.actor_id,subject_id:state.dir.people.get(row.subject_id)?.id??[...state.dir.people.values()].find(p=>p.email===row.subject_id)?.id??row.subject_id,created_at:row.created_at};
 });
 const held=await one(ctx,`SELECT 1 FROM auth_sessions a JOIN oa_operators p ON p.id=a.person_id JOIN auth_role_epoch e ON e.id=1 WHERE a.id=? AND a.person_id=? AND a.amr=? AND a.person_version=p.version AND p.status='active' AND a.revoked_at IS NULL AND a.expires_at>? AND e.epoch=?`,s.id,s.person_id,s.amr,ctx.now(),state.epoch);
 if(!held)fail('role_authority_changed',409);
 const more=events.length>limit;events.length=Math.min(events.length,limit);
 return {events,total,asOf:cursor.asOf,filters,limit,nextCursor:more?await encode(ctx,{...cursor,before:events.at(-1).id}):null};
}
