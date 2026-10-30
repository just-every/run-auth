import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import ssh2 from 'ssh2';
const {Client,utils}=ssh2;
import {createSftpIngress,fingerprint} from '../../connectors/sftp/server.mjs';
import {ownerInstall,post,passkeyPerson,signInAgain} from './agents-helpers.mjs';
import {emailSession,cookieOf} from './runtime.mjs';
import {authenticate} from './webauthn.mjs';
const result=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
const mapping={sourceId:'Employee ID',email:'Work email',name:'Name',department:'Department',state:'Status',effectiveAt:'Effective'};
const csv=rows=>'Employee ID,Work email,Name,Department,Status,Effective\n'+rows.map(row=>row.join(',')).join('\n')+'\n';
// ssh2 1.17.0 truncates leading zero bytes in generated Ed25519 keys; use P-256 fixtures.
const keyPair=()=>utils.generateKeyPairSync('ecdsa',{bits:256});
const keyFingerprint=key=>fingerprint(utils.parseKey(key.public).getPublicSSH());
async function fixture(t) {
 const {r,owner}=await ownerInstall(t),key=keyPair();
 const create=async schedule=>result(await r.call('/api/auth/hr-feeds/create',post({name:'Reviewed HR source',schedule,mapping,fingerprint:keyFingerprint(key),confirm:true},owner.cookie)),201);
 return {r,owner,key,create};
}
export async function hrFilePreviewFlow(t) {
 const {r,owner,key,create}=await fixture(t),feed=await create('hourly'),at=new Date(r.now-1000).toISOString();
 for(let i=0;i<5;i++)await passkeyPerson(r,'worker-'+i,'synthetic-auth-'+(140+i)+'@example.com','member');
 for(let i=0;i<2;i++)await result(await r.call('/api/auth/directory/source',post({source:'hr',records:[{sourceId:feed.id+':source-'+i,personId:'worker-'+i,email:'synthetic-auth-'+(140+i)+'@example.com',fields:{department:'Support'}}]},owner.cookie)));
 const file=csv([['new-hire','synthetic-auth-145@example.com','New hire','Engineering','active',at],['source-0','synthetic-auth-140@example.com','Mover','Engineering','active',at],['source-1','synthetic-auth-141@example.com','Leaver','Support','terminated',at]]);
 const passkeyOnly=cookieOf((await authenticate(r,owner.key)).response);
 for(const [path,data] of [['hr-feeds/create',{name:'No email',schedule:'hourly',mapping,fingerprint:keyFingerprint(key),confirm:true}],['hr-feeds/upload',{feedId:feed.id,fileName:'blocked.csv',text:file}],['hr-feeds/apply',{feedId:feed.id,fileId:'synthetic-auth-180',digest:'synthetic-auth-181',rows:[0],confirm:true}],['hr-feeds/disable',{feedId:feed.id}],['hr-feeds/close-file',{feedId:feed.id,fileId:'synthetic-auth-182',confirm:true}]])assert.equal((await r.call('/api/auth/'+path,post(data,passkeyOnly))).status,403,path+' still needs fresh local email');
 const badMapping=await r.call('/api/auth/hr-feeds/create',post({name:'Ambiguous columns',schedule:'daily',mapping:{sourceId:' ID ',email:'ID',state:'State',effectiveAt:'Effective'},fingerprint:keyFingerprint(key),confirm:true},owner.cookie));assert.equal(badMapping.status,400,'trimmed column names remain one-to-one');
 const upload=(text,fileName='hr.csv')=>r.call('/api/auth/hr-feeds/upload',post({feedId:feed.id,fileName,text},owner.cookie));
 const received=await result(await upload(file),202);assert.equal(received.state,'held');assert.deepEqual(received.reasons,['termination_threshold_exceeded']);assert.equal((await r.db.prepare('SELECT last_success_at FROM auth_hr_feeds WHERE id=?').bind(feed.id).first()).last_success_at,r.now,'a valid held delivery remains a successful source read');
 const preview=await result(await r.call('/api/auth/hr-feeds?fileId='+received.fileId,{cookie:owner.cookie}));
 assert.equal(preview.preview.outcomes.find(row=>row.sourceId==='new-hire').outcome,'new_hire_review_required');
 assert.equal(preview.preview.plan.entries.length,2);
 assert.ok(preview.preview.plan.entries.some(entry=>entry.state?.kind==='terminate'));
 assert.equal((await r.db.prepare('SELECT status FROM oa_operators WHERE id=?').bind('worker-1').first()).status,'active','even a valid file grants no destructive or enrollment authority');
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind('synthetic-auth-145@example.com').first(),null,'ingest never creates an unreviewed identity');
 const again=await result(await upload(file),202);assert.equal(again.fileId,received.fileId);assert.equal(again.replayed,true);
 assert.ok((await result(await upload(''),202)).reasons.includes('empty_file'));
 assert.ok((await result(await upload('"unterminated'),202)).reasons.includes('malformed_file'));
 for(const date of ['2026-02-31T12:00:00Z','2026-10-23T24:00:00Z']){const invalid=await result(await upload(csv([['bad-date','synthetic-auth-184@example.com','Invalid date','Support','active',date]]),'invalid-date.csv'),202);assert.equal(invalid.state,'held');assert.ok(invalid.reasons.includes('invalid_hr_record'));}
 assert.equal((await upload(file,'../hr.csv')).status,400);
 const malformedProfile=await result(await upload(csv([['bad-profile','synthetic-auth-148@example.com','Invalid','x'.repeat(121),'active',at]]),'invalid-field.csv'),202);assert.equal(malformedProfile.state,'held');assert.ok(malformedProfile.reasons.includes('invalid_profile_field'));
 const future=await result(await upload(csv([['future','synthetic-auth-146@example.com','Future','Support','active',new Date(r.now+86400000).toISOString()]]),'future.csv'),202);
 const futureView=await result(await r.call('/api/auth/hr-feeds?fileId='+future.fileId,{cookie:owner.cookie}));assert.equal(futureView.preview.outcomes[0].outcome,'future_effective');
 assert.equal((await r.call('/api/auth/hr-feeds',{cookie:await emailSession(r,'synthetic-auth-140@example.com')})).status,403);
 const model=await result(await r.call('/api/auth/hr-feeds',{cookie:owner.cookie}));assert.ok(!JSON.stringify(model).includes(feed.ingressToken));
 r.now+=2*3600000+1;await r.restart();
 const stale=await result(await r.call('/api/auth/hr-feeds',{cookie:owner.cookie}));assert.equal(stale.feeds[0].stale,true);
 const followup=await result(await r.call('/api/auth/followup',{cookie:owner.cookie}));
 const obligation=followup.obligations.find(row=>row.kind==='hr_file_feed');assert.ok(obligation);assert.equal(obligation.next_action,'review_stale_hr_feed');
 await r.call('/api/auth/followup',{cookie:owner.cookie});assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_hr_feed_obligations').first()).n,1,'restart and reads do not duplicate a stale episode');
 // A valid, non-destructive next delivery completes only source freshness.
 const freshOwner=await signInAgain(r,owner,'owner@example.com');owner.cookie=freshOwner.cookie;
 const restored=await result(await upload(csv([['source-0','synthetic-auth-140@example.com','Mover','Engineering','active',new Date(r.now-1).toISOString()]]),'next.csv'),202);assert.equal(restored.state,'staged');
 const followupAfter=await result(await r.call('/api/auth/followup',{cookie:owner.cookie}));assert.equal(followupAfter.obligations.find(row=>row.id===obligation.id).state,'completed');
 assert.equal((await r.db.prepare('SELECT status FROM oa_operators WHERE id=?').bind('worker-1').first()).status,'active');
 await result(await r.call('/api/auth/hr-feeds/close-file',post({feedId:feed.id,fileId:received.fileId,confirm:true},owner.cookie)));
 assert.equal((await r.db.prepare('SELECT state FROM auth_hr_files WHERE id=?').bind(received.fileId).first()).state,'reviewed');
 await result(await r.call('/api/auth/erasure/policy',post({confirm:true,automaticDeletion:false,honorLegalHolds:true},owner.cookie)));
 const erase=await result(await r.call('/api/auth/erasure/preview',post({kind:'person',target:'worker-0'},owner.cookie)));
 await result(await r.call('/api/auth/erasure/confirm',post({previewId:erase.id,confirmation:'ERASE',destinations:[]},owner.cookie)));
 const retained=await r.db.prepare('SELECT record FROM auth_hr_file_rows').all();assert.ok(!JSON.stringify(retained.results).includes('synthetic-auth-140@example.com'),'person erasure removes their retained HR snapshots');
 assert.ok(JSON.stringify(retained.results).includes('synthetic-auth-141@example.com'),'another worker snapshot survives');
}

export async function sftpIngressFlow(t) {
 const {r,owner,key,create}=await fixture(t),feed=await create('daily');
 const http=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  const response=await r.call(req.url,{method:req.method,headers:req.headers,data:body?JSON.parse(body):undefined});
  res.writeHead(response.status,Object.fromEntries(response.headers));res.end(await response.text());
 });
 await new Promise(resolve=>http.listen(0,'127.0.0.1',resolve));t.after(()=>new Promise(resolve=>http.close(resolve)));
 // Keep the issuer already registered in this runtime. Only the network edge
 // translates its hostname to the local HTTP Worker gateway.
 const send=(url,options)=>fetch('http://127.0.0.1:'+http.address().port+new URL(url).pathname,options);
 const host=keyPair(),service=createSftpIngress({hostKey:host.private,feeds:[{feedId:feed.id,issuer:r.origin,publicKey:key.public,fingerprint:feed.fingerprint,ingressToken:feed.ingressToken}],fetch:send});
 const listener=await service.listen({port:0});t.after(()=>service.close());
 const connect=privateKey=>new Promise((resolve,reject)=>{const client=new Client();client.once('error',reject);client.once('ready',()=>resolve(client));client.connect({host:'127.0.0.1',port:listener.port,username:feed.id,privateKey,hostVerifier:actual=>fingerprint(actual)===keyFingerprint(host),readyTimeout:10000});});
 await assert.rejects(connect(keyPair().private));
 const client=await connect(key.private);t.after(()=>client.end());
 const sftp=await new Promise((resolve,reject)=>client.sftp((error,value)=>error?reject(error):resolve(value)));
 const put=(path,text)=>new Promise((resolve,reject)=>{const stream=sftp.createWriteStream(path);stream.once('error',reject);stream.once('close',resolve);stream.end(text);});
 const command=async(path,data,status=200)=>result(await r.call('/api/auth/'+path,post(data,owner.cookie)),status);
 const workers=[];for(let i=0;i<5;i++)workers.push(await passkeyPerson(r,'sftp-worker-'+i,'synthetic-auth-'+(190+i)+'@example.com','member'));
 for(let i=0;i<2;i++)await command('directory/source',{source:'hr',records:[{sourceId:feed.id+':source-'+i,personId:'sftp-worker-'+i,email:'synthetic-auth-'+(190+i)+'@example.com',fields:{department:'Support'}}]});
 const group=await command('groups/create',{name:'Reviewed SFTP Engineering'},201);await command('groups/rule',{groupId:group.id,rule:{match:'all',conditions:[{field:'department',op:'eq',value:'Engineering'}]}});
 const app=await command('oidc-apps/create',{name:'SFTP Engineering documents',authMethod:'none',redirectUris:['https://sftp-documents.example.com/callback']},201);
 await command('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id});
 const effective=new Date(r.now-1).toISOString();
 const file=csv([['hire','synthetic-auth-147@example.com','SFTP hire','Engineering','active',effective],['source-0','synthetic-auth-190@example.com','SFTP mover','Engineering','active',effective],['source-1','synthetic-auth-191@example.com','SFTP leaver','Support','terminated',effective]]);
 await put('delivery.csv',file);
 await assert.rejects(put('../escape.csv',file));
 await assert.rejects(put('oversized.csv','x'.repeat(1024*1024+1)),'oversized SFTP writes never reach the Worker');
 await new Promise(resolve=>client.exec('uname -a',error=>{assert.ok(error,'no shell or command execution');resolve();}));
 const view=await result(await r.call('/api/auth/hr-feeds',{cookie:owner.cookie}));assert.equal(view.files[0].transport,'sftp');assert.equal(view.files[0].state,'held');assert.deepEqual(view.files[0].reasons,['termination_threshold_exceeded']);
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind('synthetic-auth-147@example.com').first(),null,'SFTP credentials cannot create or authenticate a person');
 const review=(await result(await r.call('/api/auth/hr-feeds?fileId='+view.files[0].id,{cookie:owner.cookie}))).preview;
 assert.ok(review.plan.entries.some(entry=>entry.state?.kind==='terminate'));assert.ok(review.newPlans[0].plan.groups.added.some(row=>row.id===group.id));
 await command('hr-feeds/apply',{feedId:feed.id,fileId:view.files[0].id,digest:review.digest,rows:[0,1,2],confirm:true,confirmHeld:true});
 assert.equal((await r.call('/api/auth/me',{cookie:workers[1].cookie})).status,401,'the SFTP leaver loses Auth access at the native door');
 assert.ok((await result(await r.call('/api/auth/launcher',{cookie:workers[0].cookie}))).apps.some(row=>row.id===app.id),'the SFTP mover gains exactly the rule-assigned app');
 const {register}=await import('./webauthn.mjs');const joined=await register(r,await emailSession(r,'synthetic-auth-147@example.com'));
 assert.ok((await result(await r.call('/api/auth/launcher',{cookie:joined.cookie}))).apps.some(row=>row.id===app.id),'the SFTP hire enrolls with Auth proof before accessing the assigned app');
 const repeated=await command('hr-feeds/upload',{feedId:feed.id,fileName:'already-ended.csv',text:csv([['source-1','synthetic-auth-191@example.com','Already ended','Support','terminated',effective]])},202);assert.equal(repeated.state,'staged','an already terminated source row is not a new destructive transition');
 const foreign=await result(await r.call('/api/auth/organizations/create',post({name:'Separate HR employer'},owner.cookie)),201);
 const denied=await r.call('/org/'+foreign.id+'/api/auth/hr-feeds/ingest',{method:'POST',data:{feedId:feed.id,fileName:'foreign.csv',text:file},headers:{authorization:'AuthFeed '+feed.ingressToken,'x-auth-sftp-fingerprint':feed.fingerprint}});assert.equal(denied.status,401,'a feed token cannot cross employers');
 await result(await r.call('/api/auth/hr-feeds/disable',post({feedId:feed.id},owner.cookie)));
 await assert.rejects(put('disabled.csv',file));
 const audit=await result(await r.call('/api/auth/activity',{cookie:owner.cookie}));assert.ok(!JSON.stringify(audit).includes(feed.ingressToken));
}

export async function hrFileApplyFlow(t) {
 const {r,owner,create}=await fixture(t),feed=await create('hourly'),at=new Date(r.now-1000).toISOString();
 const command=async(path,data,status=200)=>result(await r.call('/api/auth/'+path,post(data,owner.cookie)),status);
 const {hookServer,verifiedHook}=await import('./hooks-server.mjs');const edge=await hookServer(t);r.edges=edge.edges;
 for(let i=0;i<5;i++)await passkeyPerson(r,'active-'+i,'synthetic-auth-'+(150+i)+'@example.com','member');
 for(let i=0;i<2;i++)await command('directory/source',{source:'hr',records:[{sourceId:feed.id+':source-'+i,personId:'active-'+i,email:'synthetic-auth-'+(150+i)+'@example.com',fields:{department:'Support'}}]});
 const group=await command('groups/create',{name:'Engineering from reviewed HR'},201);
 await command('groups/rule',{groupId:group.id,rule:{match:'all',conditions:[{field:'department',op:'eq',value:'Engineering'}]}});
 const app=await command('oidc-apps/create',{name:'Engineering documents',authMethod:'none',redirectUris:['https://documents.example.com/callback']},201);
 await command('company-apps/assign',{appId:app.id,principalType:'group',principalId:group.id});
 const file=await command('hr-feeds/upload',{feedId:feed.id,fileName:'approved.csv',text:csv([
  ['hire','synthetic-auth-155@example.com','Reviewed hire','Engineering','active',at],
  ['source-0','synthetic-auth-150@example.com','Reviewed mover','Engineering','active',at],
  ['source-1','synthetic-auth-151@example.com','Reviewed leaver','Support','terminated',at],
 ])},202);
 const read=async()=>result(await r.call('/api/auth/hr-feeds?fileId='+file.fileId,{cookie:owner.cookie}));
 const hook=await command('hooks/register',{point:'user_import',url:'https://hooks.example.com/hr-import',allowedFields:['name']},201);
 edge.responses.set('/hr-import',{body:{allow:false}});assert.equal((await r.call('/api/auth/hr-feeds?fileId='+file.fileId,{cookie:owner.cookie})).status,403,'inherited import hook can refuse before review/apply');
 edge.responses.set('/hr-import',{body:{allow:true,profile:{role:'admin'}}});assert.equal((await r.call('/api/auth/hr-feeds?fileId='+file.fileId,{cookie:owner.cookie})).status,403,'a hook cannot add authority');
 edge.responses.set('/hr-import',{body:{allow:true,profile:{name:'Reviewed HR name'}}});
 const preview=(await read()).preview;
 assert.ok(preview.newPlans[0].plan.groups.added.some(row=>row.id===group.id),'new-hire preview includes resulting rule-based access');
 const params={feedId:feed.id,fileId:file.fileId,digest:preview.digest,rows:[0,1,2],confirm:true};
 assert.equal((await r.call('/api/auth/hr-feeds/apply',post(params,owner.cookie))).status,403,'destructive threshold needs its own explicit confirmation');
 assert.equal((await r.call('/api/auth/hr-feeds/apply',post({...params,digest:'synthetic-auth-stale',confirmHeld:true},owner.cookie))).status,409);
 const applied=await command('hr-feeds/apply',{...params,confirmHeld:true});assert.equal(applied.locallyApplied.length,3);assert.equal(applied.remote,'unverified');
 assert.equal((await r.db.prepare('SELECT status FROM oa_operators WHERE id=?').bind('active-1').first()).status,'inactive');
 for(const call of edge.received.filter(row=>row.path==='/hr-import')){assert.ok(verifiedHook(hook.secret,call));assert.deepEqual(Object.keys(JSON.parse(call.body).data).sort(),['email','name','sourceId']);}
 const newPerson=await r.db.prepare('SELECT id,status,role FROM oa_operators WHERE email=?').bind('synthetic-auth-155@example.com').first();assert.equal(newPerson.status,'invited');assert.equal(newPerson.role,'member');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE person_id=?').bind(newPerson.id).first()).n,0,'file approval creates no sign-in proof');
 const {register}=await import('./webauthn.mjs');const hire=await register(r,await emailSession(r,'synthetic-auth-155@example.com'));
 const launcher=await result(await r.call('/api/auth/launcher',{cookie:hire.cookie}));assert.ok(launcher.apps.some(row=>row.id===app.id));
 const mover=await emailSession(r,'synthetic-auth-150@example.com');assert.ok((await result(await r.call('/api/auth/launcher',{cookie:mover}))).apps.some(row=>row.id===app.id));
 assert.equal((await r.call('/api/auth/hr-feeds/apply',post(params,owner.cookie))).status,409,'the old preview cannot replay after native effects');
 await r.restart();assert.ok((await read()).preview.outcomes.every(row=>row.outcome==='locally_applied'));
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM oa_operators WHERE email=?').bind('synthetic-auth-155@example.com').first()).n,1,'restart retains one stable source-bound hire');
 const pending=await command('hr-feeds/upload',{feedId:feed.id,fileName:'cutover.csv',text:csv([['cutover','synthetic-auth-156@example.com','Cutover hire','Engineering','active',at]])},202);
 const pendingView=(await result(await r.call('/api/auth/hr-feeds?fileId='+pending.fileId,{cookie:owner.cookie}))).preview;
 edge.responses.set('/hr-import',async()=>{await command('hr-feeds/disable',{feedId:feed.id});return {body:{allow:true,profile:{name:'Reviewed HR name'}}};});
 const stopped=await r.call('/api/auth/hr-feeds/apply',post({feedId:feed.id,fileId:pending.fileId,digest:pendingView.digest,rows:[0],confirm:true},owner.cookie));
 assert.ok([403,409].includes(stopped.status),'disabling during an import hook fences the native commit');
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind('synthetic-auth-156@example.com').first(),null);
 await approvedHrLifecycleFlow(t);

}

async function approvedHrLifecycleFlow(t) {
 const {r,owner,key}=await fixture(t);
 const command=async(path,data,status=200)=>result(await r.call('/api/auth'+path,post(data,owner.cookie)),status);
 const feed=await command('/hr-feeds/create',{name:'Dated source managers',schedule:'hourly',fingerprint:keyFingerprint(key),mapping:{...mapping,managerSourceId:'Manager ID'},confirm:true},201);
 for(const [id,email] of [['manager','synthetic-auth-160@example.com'],['mover','synthetic-auth-161@example.com'],['leaver','synthetic-auth-173@example.com']])await r.person(id,email);
 await command('/directory/source',{source:'hr',records:[{sourceId:feed.id+':manager',personId:'manager',email:'synthetic-auth-160@example.com',fields:{department:'Engineering'}},{sourceId:feed.id+':mover',personId:'mover',email:'synthetic-auth-161@example.com',fields:{department:'Support'}}]});
 await command('/directory/source',{source:'hr',records:[{sourceId:feed.id+':leaver',personId:'leaver',email:'synthetic-auth-173@example.com',fields:{department:'Support'}}]});
 const upload=async(name,rows)=>command('/hr-feeds/upload',{feedId:feed.id,fileName:name+'.csv',text:'Employee ID,Work email,Name,Department,Status,Effective,Manager ID\n'+rows.map(row=>row.join(',')).join('\n')+'\n'},202);
 const view=async file=>(await result(await r.call('/api/auth/hr-feeds?fileId='+file.fileId,{cookie:owner.cookie}))).preview;
 const approve=async(file,rows=[0])=>{const preview=await view(file);await command('/hr-feeds/approve',{feedId:feed.id,fileId:file.fileId,digest:preview.digest,rows,confirm:true,confirmHeld:true});return preview.digest;};
 const tick=async()=>result(await r.call('/',{action:'maintain'}));
 const effective=new Date(r.now+3600000).toISOString();
 const dated=await upload('dated', [['mover','synthetic-auth-161@example.com','Dated mover','Engineering','active',effective,'manager'],['dated-hire','synthetic-auth-174@example.com','Dated hire','Engineering','active',effective,'manager'],['leaver','synthetic-auth-173@example.com','Dated leaver','Support','terminated',effective,'manager']]);
 const preview=await view(dated);assert.equal(preview.outcomes[0].outcome,'future_effective');assert.ok(preview.plan.entries[0].writes.some(w=>w.field==='manager'&&w.value==='manager'),'manager source ID resolves only within this employer feed');
 assert.equal((await r.call('/api/auth/hr-feeds/approve',post({feedId:feed.id,fileId:dated.fileId,digest:preview.digest,rows:[0],confirm:true},cookieOf((await authenticate(r,owner.key)).response)))).status,403,'future approval needs fresh email as well as the hardware session');
 const digest=await approve(dated,[0,1,2]);
 await upload('unapproved',[['unapproved','synthetic-auth-162@example.com','Unapproved','Engineering','active',effective,'manager']]);
 await tick();assert.equal(await r.db.prepare("SELECT value FROM auth_person_fields WHERE person_id='mover' AND field='manager'").first(),null,'approval does not apply early');
 r.now+=3600000;await r.restart();await Promise.all([tick(),tick()]);
 assert.equal((await r.db.prepare("SELECT value FROM auth_person_fields WHERE person_id='mover' AND field='manager'").first()).value,'manager');
 assert.equal((await r.db.prepare("SELECT value FROM auth_person_fields WHERE person_id='mover' AND field='department' AND source='hr'").first()).value,'Engineering');
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind('synthetic-auth-162@example.com').first(),null,'an unapproved recurring delivery never applies');
 const rows=(await r.db.prepare("SELECT a.actor_id,d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='hr_file_row_applied'").all()).results;
 const proof=rows.filter(v=>JSON.parse(v.detail).fileId===dated.fileId);assert.equal(proof.length,3,'concurrent scheduled workers apply each approved row exactly once');assert.equal(new Set(proof.map(v=>JSON.parse(v.detail).row)).size,3);
 const datedHire=await r.db.prepare('SELECT id,status,role FROM oa_operators WHERE email=?').bind('synthetic-auth-174@example.com').first();assert.equal(datedHire.status,'invited');assert.equal(datedHire.role,'member');assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_sessions WHERE person_id=?').bind(datedHire.id).first()).n,0);assert.equal((await r.db.prepare("SELECT status FROM oa_operators WHERE id='leaver'").first()).status,'inactive');assert.equal(proof[0].actor_id,'owner');assert.equal(JSON.parse(proof[0].detail).digest,digest);
 owner.cookie=(await signInAgain(r,owner,'owner@example.com')).cookie;
 // Authority, file content and target changes each return to explicit review.
 const custody=await passkeyPerson(r,'approver','synthetic-auth-163@example.com','admin');
 const removed=await passkeyPerson(r,'removed-approver','synthetic-auth-172@example.com','admin');
 const cases=[];
 for(const suffix of ['digest','target','demoted','removed']){
  const file=await upload(suffix,[[suffix,'synthetic-auth-'+({digest:164,target:165,demoted:166,removed:167}[suffix])+'@example.com','Approved hire','Engineering','active',new Date(r.now+3600000).toISOString(),'manager']]);
  const p=await view(file);
  const approver=suffix==='demoted'?custody:suffix==='removed'?removed:owner;
  await result(await r.call('/api/auth/hr-feeds/approve',post({feedId:feed.id,fileId:file.fileId,digest:p.digest,rows:[0],confirm:true},approver.cookie)));
  cases.push({suffix,file});
 }
 await r.db.prepare('UPDATE auth_hr_files SET digest=? WHERE id=?').bind('synthetic-auth-changed-digest',cases[0].file.fileId).run();
 await r.person('foreign-target','synthetic-auth-168@example.com');
 await command('/directory/source',{source:'hr',records:[{sourceId:feed.id+':target',personId:'foreign-target',email:'synthetic-auth-168@example.com',fields:{department:'Support'}}]});
 await command('/people/role',{personId:'approver',role:'member'});
 // Remove an already-suspended approver from the fixture directory to cover
 // absence as well as demotion at the real scheduled execution door.
 await command('/people/suspend',{personId:'removed-approver'});
 await command('/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const removal=await command('/erasure/preview',{kind:'person',target:'removed-approver'});await command('/erasure/confirm',{previewId:removal.id,confirmation:'ERASE',destinations:[]});
 assert.equal(await r.db.prepare("SELECT id FROM oa_operators WHERE id='removed-approver'").first(),null);
 r.now+=3600000;await r.restart();await tick();
 for(const {suffix,file} of cases){
  const approval=await r.db.prepare('SELECT state FROM auth_hr_approved_rows WHERE file_id=?').bind(file.fileId).first();
  if(suffix==='removed'){assert.equal(approval,null,'erasure destroys the absent approver receipt');assert.equal((await view(file)).outcomes[0].outcome,'new_hire_review_required');}
  else assert.equal(approval.state,'review_required',suffix+' refuses and returns to review');
 }
 assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM oa_operators WHERE email IN ('synthetic-auth-164@example.com','synthetic-auth-165@example.com','synthetic-auth-166@example.com','synthetic-auth-167@example.com')").first()).n,0);
 owner.cookie=(await signInAgain(r,owner,'owner@example.com')).cookie;
 const missing=await upload('unknown-manager',[['unresolved','synthetic-auth-169@example.com','Unresolved','Engineering','active',new Date(r.now-1).toISOString(),'missing-manager']]);
 assert.equal((await view(missing)).outcomes[0].outcome,'manager_source_review_required');
 // A fail-closed network-edge outage after the first native commit interrupts
 // the multi-row file. Durable row receipts survive restart without replay.
 const {hookServer}=await import('./hooks-server.mjs'),edge=await hookServer(t);r.edges=edge.edges;
 await command('/hooks/register',{point:'user_import',url:'https://hooks.example.com/interrupted-hr',allowedFields:[]},201);
 const interrupted=await upload('interrupted',[
  ['resume-one','synthetic-auth-170@example.com','First hire','Engineering','active',new Date(r.now-1).toISOString(),'manager'],
  ['resume-two','synthetic-auth-171@example.com','Second hire','Engineering','active',new Date(r.now-1).toISOString(),'manager']]);
 edge.responses.set('/interrupted-hr',{body:{allow:true}});await approve(interrupted,[0,1]);
 edge.responses.set('/interrupted-hr',async()=>({status:(await r.db.prepare('SELECT applied_at FROM auth_hr_file_rows WHERE file_id=? AND idx=0').bind(interrupted.fileId).first()).applied_at?503:200,body:{allow:true}}));
 await tick();assert.equal((await r.db.prepare("SELECT COUNT(*) AS n FROM auth_hr_approved_rows WHERE file_id=? AND state='completed'").bind(interrupted.fileId).first()).n,1);
 edge.responses.set('/interrupted-hr',{body:{allow:true}});await r.restart();await tick();await tick();
 const status=await view(interrupted);assert.ok(status.outcomes.every(v=>v.outcome==='locally_applied'));
 for(const address of ['synthetic-auth-170@example.com','synthetic-auth-171@example.com'])assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM oa_operators WHERE email=?').bind(address).first()).n,1);
 const audits=(await r.db.prepare("SELECT d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='hr_file_row_applied'").all()).results.filter(v=>JSON.parse(v.detail).fileId===interrupted.fileId);assert.equal(audits.length,2,'each resumed row has one approver and digest receipt');
 assert.ok(status.approvals.every(v=>v.approved_by==='owner'&&v.state==='completed'));
}
