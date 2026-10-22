import assert from 'node:assert/strict';
import {openRuntime,emailSession} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
const DAY=86400000;
const classes=['profiles','sourceSnapshots','authentication','decisions','provisioning','audit','modelTraces','erasureReceipts'];
const periods=(unit,value)=>Object.fromEntries(classes.map(name=>[name,{unit,value}]));
export async function retentionFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.parse('2026-10-23T12:00:00Z');
 const address='synthetic-auth-1@example.com';let owner=await passkeyPerson(r,'synthetic-auth-1',address,'owner');
 const admin=async(path,data,status=200)=>{const response=await r.call('/api/auth/retention/'+path,{method:'POST',cookie:owner.cookie,data});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const read=async(path='')=>{const response=await r.call('/api/auth/retention'+path,{cookie:owner.cookie});assert.equal(response.status,200,await response.clone().text());return response.json();};
 assert.equal((await r.call('/api/auth/retention')).status,401);
 const member=await passkeyPerson(r,'synthetic-auth-2','synthetic-auth-2@example.com','member');
 assert.equal((await r.call('/api/auth/retention',{cookie:member.cookie})).status,403);
 const emailOnly=await emailSession(r,address);
 assert.equal((await r.call('/api/auth/retention/settings',{method:'POST',cookie:emailOnly,data:{confirm:true,classes:periods('days',90)}})).status,403);
 const original=await read();assert.deepEqual(original.policy.classes.audit,{unit:'months',value:13});
 const calendarCutoff=Date.parse('2025-09-23T12:00:00Z');
 for(const [event,at] of [['synthetic_default_expired',calendarCutoff],['synthetic_default_kept',calendarCutoff+DAY]])await r.db.prepare('INSERT INTO auth_activity(event,created_at) VALUES(?,?)').bind(event,at).run();
 const defaultPreview=JSON.stringify((await read('/preview')).preview);assert.match(defaultPreview,/synthetic_default_expired/);assert.doesNotMatch(defaultPreview,/synthetic_default_kept/,'default audit expiry uses thirteen calendar months');
 await admin('settings',null,400);
 await admin('settings',{confirm:true,classes:periods('days',30)},400);
 await admin('settings',{confirm:true,classes:periods('years',8)},400);
 await admin('settings',{confirm:false,classes:periods('days',90)},400);
 assert.equal((await read()).policy.revision,0);
 r.now+=11*60000;await admin('settings',{confirm:true,classes:periods('days',90)},403);
 owner=await signInAgain(r,owner,address);await admin('settings',{confirm:true,classes:periods('days',90)});
 const aged=r.now-120*DAY,heldAt=aged+DAY;
 // Synthetic persisted history is aged in SQLite; all observation, export,
 // policy/hold changes and cleanup enter through real HTTP/cron doors.
 for(const [event,time] of [['synthetic_retention_expire',aged],['synthetic_retention_review',heldAt],['model_synthetic_trace',aged]])await r.db.prepare('INSERT INTO auth_activity(actor_id,event,subject_id,created_at) VALUES(?,?,?,?)').bind('synthetic-auth-1',event,null,time).run();
 await r.db.prepare("INSERT INTO oa_auth_audit VALUES('synthetic-auth-3','synthetic-auth-1','retention_fixture','{}',?)").bind(aged).run();
 await r.db.prepare("INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,verified_at,state,next_attempt_at) VALUES('synthetic-auth-4','synthetic-auth-app','person','synthetic-auth-2','synthetic',?,?,'verified',?)").bind(aged,aged,aged).run();
 await r.db.prepare("INSERT INTO auth_import_batches(id,source_system,format,file_name,file_hash,export_date,row_count,created_by,created_at) VALUES('synthetic-auth-5','synthetic','csv','synthetic-auth-5.csv','synthetic-auth-5','2026-01-01',1,'synthetic-auth-1',?)").bind(aged).run();
 await r.db.prepare("INSERT INTO auth_import_rows(batch_id,idx,email,display_name,groups,status,reasons) VALUES('synthetic-auth-5',1,'synthetic-auth-3@example.com','synthetic-auth-3','[]','admitted','[]')").run();
 await r.db.prepare("INSERT INTO auth_decision_operations VALUES('synthetic-auth-6','synthetic-auth-1','synthetic-auth-session','group','synthetic-auth-group','add','synthetic-auth-2','synthetic',?)").bind(aged).run();
 await r.person('synthetic-auth-7','synthetic-auth-7@example.com');
 await r.db.prepare("UPDATE oa_operators SET status='inactive' WHERE id='synthetic-auth-7'").run();
 await r.db.prepare("INSERT INTO auth_people(person_id,terminated_at) VALUES('synthetic-auth-7',?)").bind(aged).run();
 await r.db.prepare("INSERT INTO auth_person_fields VALUES('synthetic-auth-7','department','manual','\"synthetic-auth-7\"','synthetic-auth-1',?)").bind(aged).run();
 await r.db.prepare("INSERT INTO auth_erasure_receipts VALUES('synthetic-auth-8','synthetic-auth-8','person','anonymous',?,'{}','[]','{}','completed','{}')").bind(aged).run();
 await r.db.prepare("INSERT INTO auth_sessions(id,token_hash,person_id,person_version,amr,created_at,expires_at) SELECT 'synthetic-auth-9','synthetic-auth-9',id,version,'[\"hwk\"]',?,? FROM oa_operators WHERE id='synthetic-auth-2'").bind(aged,aged+DAY).run();
 const started=await r.call('/api/auth/reviews/create',{method:'POST',cookie:owner.cookie,data:{name:'synthetic-auth-13',reviewerId:'synthetic-auth-1',periodStart:heldAt-1,periodEnd:heldAt+1,dueAt:r.now+30*DAY}});assert.equal(started.status,201,await started.clone().text());const review=await started.json();
 const hold=await admin('hold',{kind:'legal',periodStart:heldAt,periodEnd:heldAt,classes:['profiles'],reason:'synthetic-auth legal period'});
 const preview=await read('/preview'),records=JSON.stringify(preview.preview);
 for(const name of classes)assert.ok(preview.preview.summary[name].count>0,name+' has an eligible retained class');
 assert.match(records,/synthetic_retention_expire/);assert.doesNotMatch(records,/synthetic_retention_review/);
 assert.doesNotMatch(records,/token_hash|encrypted_private|sealed_token/,'preview never contains credential columns');
 const queued=await admin('preview',{});assert.ok(queued.run);
 const exported=await read('/export?runId='+queued.run.id);
 assert.match(JSON.stringify(exported.records),/synthetic_retention_expire/);
 await r.restart();await r.call('/',{action:'maintain'});
 assert.ok((await read()).runs.find(run=>run.id===queued.run.id&&run.status==='queued'),'no deletion during export window');
 // A hold added after a queued preview must win at commit too.
 const late=await admin('hold',{kind:'investigation',periodStart:aged,periodEnd:aged,classes:['modelTraces'],reason:'synthetic-auth late hold'});
 r.now+=8*DAY;await r.restart();await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 owner=await signInAgain(r,owner,address);
 const history=await(await r.call('/api/auth/activity',{cookie:owner.cookie})).json(),text=JSON.stringify(history);
 assert.doesNotMatch(text,/synthetic_retention_expire/);assert.match(text,/synthetic_retention_review/);assert.match(text,/model_synthetic_trace/);
 const after=await read(),completed=after.runs.find(run=>run.id===queued.run.id);assert.equal(completed.status,'completed');
 assert.ok(Object.values(completed.result).some(count=>count>0));assert.ok(after.expiryEvidence.some(proof=>proof.runId===queued.run.id&&proof.tableName==='auth_activity'&&typeof proof.signature==='string'),'policy expiry commits authenticated row evidence through the public read');
 assert.equal((await r.call('/api/auth/retention/export?runId='+queued.run.id,{cookie:owner.cookie})).status,404);
 const directory=await(await r.call('/api/auth/directory',{cookie:owner.cookie})).json();assert.doesNotMatch(JSON.stringify(directory),/synthetic-auth-7@example.com/);
 assert.match(text,/retention_cleanup_completed/);assert.match(text,/retention_exported/);
 // An unfinished obligation's entire evidence period survives independently of
 // the expired transient state that originally helped to authorize its source.
 const sourceAt=r.now-110*DAY;
 await r.db.prepare("INSERT INTO auth_provisioning(id,app_id,subject_type,subject_id,reason,event_at,state,next_attempt_at) VALUES('synthetic-auth-10','synthetic-auth-missing','person','synthetic-auth-2','synthetic',?,'blocked',?)").bind(sourceAt,r.now+DAY).run();
 await r.db.prepare("INSERT INTO auth_activity(actor_id,event,created_at) VALUES('synthetic-auth-1','synthetic_unfinished_evidence',?)").bind(sourceAt).run();
 await r.db.prepare("INSERT INTO auth_challenges VALUES('synthetic-auth-11','synthetic',NULL,'synthetic-auth-11','{}',?)").bind(r.now-DAY).run();
 await r.call('/',{action:'maintain'});
 await r.db.prepare("INSERT INTO auth_access_requests(id,app_id,person_id,purpose,duration_ms,decider_id,policy_revision,created_at,state,expires_at) VALUES('synthetic-auth-14','synthetic-auth-missing','synthetic-auth-2','synthetic',86400000,'synthetic-auth-1',1,?,'pending',?)").bind(sourceAt-2*DAY,r.now+DAY).run();
 await r.db.prepare("INSERT INTO auth_activity(actor_id,event,created_at) VALUES('synthetic-auth-1','synthetic_request_evidence',?)").bind(sourceAt-DAY).run();
 const kept=JSON.stringify((await read('/preview')).preview);assert.doesNotMatch(kept,/synthetic_request_evidence/);assert.ok((await read()).holds.some(h=>h.source==='request'&&h.id==='synthetic-auth-14'));assert.doesNotMatch(kept,/synthetic_unfinished_evidence/);
 const activity=JSON.stringify(await(await r.call('/api/auth/activity',{cookie:owner.cookie})).json());assert.match(activity,/synthetic_unfinished_evidence/);
 assert.equal(await r.db.prepare("SELECT 1 FROM auth_challenges WHERE id='synthetic-auth-11'").first(),null);
 assert.equal((await r.db.prepare("SELECT state FROM auth_provisioning WHERE id='synthetic-auth-10'").first()).state,'blocked');
 const close=await r.call('/api/auth/reviews/close',{method:'POST',cookie:owner.cookie,data:{id:review.id}});assert.equal(close.status,200,await close.clone().text());
 await admin('hold',{id:hold.id,release:true});await admin('hold',{id:late.id,release:true});
 // An employer namespace uses its own policy and holds; installation roles
 // cannot view its preview or change its retention settings.
 const organization=await r.call('/api/auth/organizations/create',{method:'POST',cookie:owner.cookie,data:{name:'synthetic-auth-12'}});assert.equal(organization.status,201);
 const {id}=await organization.json();
 for(const suffix of ['', '/preview','/export'])assert.ok([401,403].includes((await r.call('/org/'+id+'/api/auth/retention'+suffix,{cookie:owner.cookie})).status));
 assert.ok([401,403].includes((await r.call('/org/'+id+'/api/auth/retention/settings',{method:'POST',cookie:owner.cookie,data:{confirm:true,classes:periods('days',90)}})).status));
}
