import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import ssh2 from 'ssh2';
const {Client,utils}=ssh2;
import {createSftpIngress,fingerprint} from '../../connectors/sftp/server.mjs';
import {ownerInstall,post,passkeyPerson,signInAgain} from './agents-helpers.mjs';
import {emailSession} from './runtime.mjs';
const result=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
const mapping={sourceId:'Employee ID',email:'Work email',name:'Name',department:'Department',state:'Status',effectiveAt:'Effective'};
const csv=rows=>'Employee ID,Work email,Name,Department,Status,Effective\n'+rows.map(row=>row.join(',')).join('\n')+'\n';
const keyPair=()=>utils.generateKeyPairSync('ed25519');
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
 const upload=(text,fileName='hr.csv')=>r.call('/api/auth/hr-feeds/upload',post({feedId:feed.id,fileName,text},owner.cookie));
 const received=await result(await upload(file),202);assert.equal(received.state,'held');assert.deepEqual(received.reasons,['termination_threshold_exceeded']);
 const preview=await result(await r.call('/api/auth/hr-feeds?fileId='+received.fileId,{cookie:owner.cookie}));
 assert.equal(preview.preview.outcomes.find(row=>row.sourceId==='new-hire').outcome,'new_hire_review_required');
 assert.equal(preview.preview.plan.entries.length,2);
 assert.ok(preview.preview.plan.entries.some(entry=>entry.state?.kind==='terminate'));
 assert.equal((await r.db.prepare('SELECT status FROM oa_operators WHERE id=?').bind('worker-1').first()).status,'active','even a valid file grants no destructive or enrollment authority');
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind('synthetic-auth-145@example.com').first(),null,'ingest never creates an unreviewed identity');
 const again=await result(await upload(file),202);assert.equal(again.fileId,received.fileId);assert.equal(again.replayed,true);
 assert.ok((await result(await upload(''),202)).reasons.includes('empty_file'));
 assert.ok((await result(await upload('"unterminated'),202)).reasons.includes('malformed_file'));
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
 const file=csv([['hire','synthetic-auth-147@example.com','SFTP hire','Engineering','active',new Date(r.now-1).toISOString()]]);
 await put('delivery.csv',file);
 await assert.rejects(put('../escape.csv',file));
 await assert.rejects(put('oversized.csv','x'.repeat(1024*1024+1)),'oversized SFTP writes never reach the Worker');
 await new Promise(resolve=>client.exec('uname -a',error=>{assert.ok(error,'no shell or command execution');resolve();}));
 const view=await result(await r.call('/api/auth/hr-feeds',{cookie:owner.cookie}));assert.equal(view.files[0].transport,'sftp');assert.equal(view.files[0].state,'staged');
 assert.equal(await r.db.prepare('SELECT id FROM oa_operators WHERE email=?').bind('synthetic-auth-147@example.com').first(),null,'SFTP credentials cannot create or authenticate a person');
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
}
