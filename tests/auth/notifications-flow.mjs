import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHash} from 'node:crypto';
import {generateKeyPair,decodeJwt} from 'jose';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
import {register,authenticate} from './webauthn.mjs';
import {createSessionClient} from '../../packages/session-sdk/index.mjs';

const local=url=>{const u=new URL(url);return u.pathname+u.search;};
const policy={confirm:true,emailEnabled:true,newDevice:true,factorEnrolled:true,securityOwnerId:'synthetic-auth-1',slackEnabled:false,endSessionsOnReport:false};
const reportLink=mail=>mail.text.match(/Report suspicious activity: (https?:\/\/\S+)/)?.[1];
const deviceCookie=response=>response.headers.getSetCookie().map(v=>v.split(';')[0]).find(v=>v.startsWith('__Host-auth_device='));
async function signIn(r,key,device) {
 const offered=await r.call('/auth/passkeys/authenticate/options',{method:'POST',data:{}}),tx=await offered.json();
 const response=await r.call('/auth/passkeys/authenticate/verify',{method:'POST',cookie:[cookieOf(offered),device].filter(Boolean).join('; '),headers:{'user-agent':'Synthetic Auth Browser <script>untrusted</script>'},data:{transaction:tx.transaction,response:key.authenticate(tx.options)}});
 assert.equal(response.status,200,await response.clone().text());return {cookie:cookieOf(response),device:deviceCookie(response)};
}
async function edge(t,handler) {
 const server=createServer(async(req,res)=>{try{let body='';for await(const part of req)body+=part;await handler(req,body,res);}catch{res.writeHead(500);res.end();}});
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 return 'http://127.0.0.1:'+server.address().port;
}
export async function nativeGrant(r,post,personId,cookie) {
 await r.call('/.well-known/openid-configuration');await r.db.prepare('UPDATE auth_signing_keys SET use_after=?').bind(r.now-1).run();
 const app=await post('/oidc-apps/create',{name:'Synthetic Auth Documents',authMethod:'none',redirectUris:['com.synthetic.auth:/callback','https://native.example.com/callback'],backchannelLogoutUri:'https://native.example.com/logout'},201);
 const api=await post('/resource-apis/register',{appId:app.id,name:'Synthetic Auth Documents API',audience:'https://native.example.com/documents',scopes:['read'],roles:[{role:'reader',scopes:['read'],resources:['document:*']}],resources:[{id:'document:one'}]},201);
 await post('/resource-apis/assign',{apiId:api.id,principalType:'person',principalId:personId,role:'reader'});
 await post('/refresh/profile',{clientId:app.clientId,apiId:api.id,scopes:['read'],idleHours:24,absoluteHours:48});
 const keyPair=await generateKeyPair('ES256',{extractable:true});
 const sdk=await createSessionClient({issuer:r.origin,clientId:app.clientId,redirectUri:'com.synthetic.auth:/callback',keyPair,fetch:(url,options={})=>{const headers={...Object.fromEntries(new Headers(options.headers)),origin:'https://native.example.com'};return r.call(local(url),{method:options.method,headers,...(headers['content-type']==='application/json'?{data:JSON.parse(options.body)}:{form:options.body?Object.fromEntries(new URLSearchParams(options.body)):undefined})});}});
 const authorization=await sdk.authorization({resource:'https://native.example.com/documents',scopes:['read'],deviceName:'Synthetic Auth Tablet'}),response=await r.call(local(authorization.url),{cookie}),location=new URL(response.headers.get('location'),r.origin),id=location.searchParams.get('refreshConsent');
 assert.ok(id,await response.clone().text());
 const consent=await post('/refresh/consent',{id,decision:'approve'},200,cookie);const tokens=await sdk.complete(consent.redirect);
 return {sdk,tokens,app,api};
}

export async function notificationsFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());r.now=Date.now();
 let owner=await passkeyPerson(r,'synthetic-auth-1','security-owner@example.com','owner');
 const employee=await passkeyPerson(r,'synthetic-auth-2','employee@example.com','member');
 const slack=[],logouts=[];
 r.notificationSlackWebhook='https://hooks.slack.com/services/synthetic-auth-1';
 r.notificationEdge=await edge(t,async(req,body,res)=>{slack.push(JSON.parse(body));res.end('ok');});
 const logoutEdge=await edge(t,async(req,body,res)=>{logouts.push(decodeJwt(new URLSearchParams(body).get('logout_token')));res.end('ok');});
 r.edges={'https://native.example.com':logoutEdge};
 const post=async(path,data,status=200,cookie=owner.cookie)=>{const response=await r.call('/api/auth'+path,{method:'POST',data,cookie});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 await post('/notifications/settings',{...policy,slackEnabled:true,endSessionsOnReport:true});
 const first=await signIn(r,employee.key),notice=(await r.mails()).findLast(mail=>mail.subject==='Auth sign-in from a new browser');
 assert.ok(first.device);assert.equal(notice.to,'employee@example.com');assert.match(notice.text,/App: Auth\nTime: .*\nApproximate location: Unavailable\nIP: 192.0.2.10\nDevice: Synthetic Auth Browser/);
 assert.match(notice.html,/&lt;script&gt;untrusted&lt;\/script&gt;/);assert.doesNotMatch(notice.html,/<script>/);
 const link=reportLink(notice);assert.ok(link);assert.doesNotMatch(notice.text,/email\/confirm|sign-in link|[?&]code=/i);
 const before=(await r.mails()).filter(mail=>mail.subject==='Auth sign-in from a new browser').length;
 const recognized=await signIn(r,employee.key,first.device);
 assert.equal((await r.mails()).filter(mail=>mail.subject==='Auth sign-in from a new browser').length,before,'recognized browser sends no repeated notice');
 const grant=await nativeGrant(r,post,'synthetic-auth-2',recognized.cookie);assert.ok((await grant.sdk.refresh()).refresh_token);
 // The browser-bound original authorize request supplies the requesting app.
 const query=new URLSearchParams({client_id:grant.app.clientId,redirect_uri:'com.synthetic.auth:/callback',response_type:'code',scope:'openid',code_challenge:createHash('sha256').update('synthetic-auth-4'.repeat(4)).digest('base64url'),code_challenge_method:'S256',state:'synthetic-auth-5'});
 const login=await r.call('/oidc/authorize?'+query),returnTo=new URL(login.headers.get('location'),r.origin).searchParams.get('returnTo');assert.ok(returnTo);
 const requested=await r.call('/auth/identity/email/request',{method:'POST',cookie:cookieOf(login),data:{email:'employee@example.com',returnTo}});
 const proofMail=(await r.mails()).at(-1),proof=new URL(proofMail.text.match(/https?:\/\/\S+$/)[0]).searchParams.get('token');
 const confirmed=await r.call('/auth/identity/email/confirm',{method:'POST',cookie:[cookieOf(login),cookieOf(requested)].join('; '),data:{token:proof}});assert.equal(confirmed.status,200,await confirmed.clone().text());
 assert.match((await r.mails()).findLast(mail=>mail.subject==='Auth sign-in from a new browser').text,/App: Synthetic Auth Documents/);

 // Email report action works with no Auth cookie; simultaneous consumers get one winner.
 const reports=await Promise.all([r.call(local(link)),r.call(local(link))]);assert.deepEqual(reports.map(response=>response.status).sort(),[200,410]);
 assert.equal(slack.length,1);assert.match(slack[0].text,/Auth suspicious activity reported/);
 assert.equal((await r.call('/api/auth/me',{cookie:recognized.cookie})).status,401);
 await assert.rejects(grant.sdk.refresh());assert.ok(logouts.some(logout=>logout.sid===grant.tokens.grant_id),'refresh revocation delivers the native app back-channel logout');
 const inventory=await(await r.call('/api/auth/notifications',{cookie:owner.cookie})).json();assert.equal(inventory.reports.length,1);assert.equal(inventory.reports[0].sessions_state,'ended');assert.equal(inventory.reports[0].slack_state,'accepted');
 const activity=await(await r.call('/api/auth/activity',{cookie:owner.cookie})).json();assert.match(JSON.stringify(activity),/suspicious_activity_reported/);
 const followup=await(await r.call('/api/auth/followup',{cookie:owner.cookie})).json();assert.ok(followup.obligations.some(ob=>ob.source_id==='security-report:'+inventory.reports[0].id&&ob.state==='open'));assert.ok(followup.history.some(item=>item.event==='security_slack_accepted'));
 await r.restart();await r.call('/',{action:'maintain'});assert.equal(slack.length,1);assert.equal((await r.call(local(link))).status,410);
 await post('/notifications/resolve',{reportId:inventory.reports[0].id,confirm:true});
 const reviewed=await(await r.call('/api/auth/followup',{cookie:owner.cookie})).json();assert.equal(reviewed.obligations.find(ob=>ob.source_id==='security-report:'+inventory.reports[0].id).state,'completed');
 owner=await signInAgain(r,owner,'security-owner@example.com');
}

export async function notificationsSafety(t) {
 const r=await openRuntime();t.after(()=>r.close());
 let owner=await passkeyPerson(r,'synthetic-auth-1','security-owner@example.com','owner');
 let employee=await passkeyPerson(r,'synthetic-auth-2','employee@example.com','member');
 const post=async(path,data,status=200,cookie=owner.cookie)=>{const response=await r.call('/api/auth'+path,{method:'POST',data,cookie});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 await post('/notifications/settings',policy,403,employee.cookie);
 await post('/notifications/settings',{...policy,confirm:false},400);
 await post('/notifications/settings',policy);
 await passkeyPerson(r,'synthetic-auth-4','administrator@example.com','member');
 await post('/people/role',{personId:'synthetic-auth-4',role:'admin'});
 assert.ok((await r.mails()).some(mail=>mail.subject==='Auth administrator role granted'&&reportLink(mail)));
 for(const event of ['recovery_started','factor_reset','factor_removed','administrator_role_granted'])await post('/notifications/settings',{...policy,[event]:false},400);
 await post('/notifications/settings',{...policy,emailEnabled:false},400);
 const before=r.now;r.now+=600001;await post('/notifications/settings',policy,403);r.now=before;
 // Optional new browser notices can stop without weakening the mandatory events.
 await post('/notifications/settings',{...policy,newDevice:false});const count=(await r.mails()).filter(mail=>mail.subject==='Auth sign-in from a new browser').length;
 await signIn(r,employee.key);assert.equal((await r.mails()).filter(mail=>mail.subject==='Auth sign-in from a new browser').length,count);
 employee=await register(r,employee.cookie);
 const enrolled=(await r.mails()).findLast(mail=>mail.subject==='Auth sign-in factor enrolled');assert.ok(enrolled&&reportLink(enrolled));
 const recovery=await post('/recovery/start',{},201,employee.cookie),started=(await r.mails()).findLast(mail=>mail.subject==='Auth recovery started');assert.ok(started);assert.match(started.text,/cancel this recovery/);assert.ok(reportLink(started));
 await post('/recovery/cancel',{id:recovery.id},200,employee.cookie);
 const cancelled=await r.call('/api/auth/me',{cookie:employee.cookie});assert.equal(cancelled.status,200);
 // A forged signature never consumes the genuine capability.
 const link=new URL(reportLink(enrolled)),token=link.searchParams.get('token');link.searchParams.set('token',token.slice(0,-2)+'xx');assert.equal((await r.call(local(link))).status,410);
 const isolated=await post('/organizations/create',{name:'Synthetic Auth Employer'},201);
 assert.equal((await r.call('/org/'+isolated.id+local(reportLink(enrolled)))).status,410,'report authority cannot cross employers');
 const genuine=reportLink(enrolled),reported=await r.call(local(genuine));assert.equal(reported.status,200);assert.equal((await r.call('/api/auth/me',{cookie:employee.cookie})).status,200,'default report policy leaves sessions live');
 const expired=reportLink(started);r.now+=7*86400000;assert.equal((await r.call(local(expired))).status,410);r.now=before;
 // Recovery completed by its real distinct-admin door emits mandatory reset mail.
 employee=await signInAgain(r,employee,'employee@example.com');
 const recovery2=await post('/recovery/start',{},201,employee.cookie);await post('/recovery/approve',{id:recovery2.id});
 await post('/recovery/complete',{id:recovery2.id},200,employee.cookie);
 assert.ok((await r.mails()).some(mail=>mail.subject==='Auth sign-in factor reset'&&reportLink(mail)));
 // Help-desk custody is scoped through its normal role and reset doors.
 const desk=await passkeyPerson(r,'synthetic-auth-3','help-desk@example.com','member');
 const preview=await post('/roles/preview',{kind:'grant',personId:'synthetic-auth-3',roleId:'help-desk',resources:{view:{people:['synthetic-auth-2'],cases:['*']},edit:{people:['synthetic-auth-2'],cases:['*']}}});
 await post('/roles/apply',{previewId:preview.previewId});
 employee=await register(r,await emailSession(r,'employee@example.com'));
 await post('/directory/edit',{personId:'synthetic-auth-2',set:{manager:'synthetic-auth-1'}});
 const recoveryCase=await post('/roles/recovery-case',{action:'open',personId:'synthetic-auth-2',reason:'Employee lost their factor'},201,desk.cookie);
 await post('/recovery/case-attest',{caseId:recoveryCase.caseId});
 const resetCount=(await r.mails()).filter(mail=>mail.subject==='Auth sign-in factor reset').length;
 await post('/roles/reset-factors',{personId:'synthetic-auth-2',caseId:recoveryCase.caseId,reason:'Synthetic Auth verified help-desk request'},200,desk.cookie);
 const reset=(await r.mails()).filter(mail=>mail.subject==='Auth sign-in factor reset');assert.equal(reset.length,resetCount+1);assert.match(reset.at(-1).text,/Passkeys reset by help desk/);assert.ok(reportLink(reset.at(-1)));
 assert.equal((await r.call('/api/auth/me',{cookie:employee.cookie})).status,401);
 // Former browser recognition falls outside the last twenty successful sign-ins.
 const replacementEmail=await emailSession(r,'employee@example.com'),enrollment=(await r.mails()).findLast(mail=>mail.subject==='Auth recovery enrollment link');
 const enrollmentLink=new URL(enrollment.text.match(/https:\/\/\S+$/)[0]);
 await post('/recovery/enroll',Object.fromEntries(new URLSearchParams(enrollmentLink.hash.slice(1))),200,replacementEmail);
 employee=await register(r,replacementEmail);
 await post('/notifications/settings',{...policy,newDevice:true});const old=await signIn(r,employee.key);
 await post('/notifications/settings',{...policy,newDevice:false});
 for(let i=0;i<20;i++){r.now+=3001;await signIn(r,employee.key);}
 await post('/notifications/settings',policy);const recent=(await r.mails()).filter(mail=>mail.subject==='Auth sign-in from a new browser').length;
 await signIn(r,employee.key,old.device);assert.equal((await r.mails()).filter(mail=>mail.subject==='Auth sign-in from a new browser').length,recent+1);
 owner=await signInAgain(r,owner,'security-owner@example.com');
 await roleGrantNotices(t);
}

async function roleGrantNotices(t) {
 const r=await openRuntime();t.after(()=>r.close());
 const address=n=>['synthetic-auth-'+n,'example.com'].join('@');
 let owner=await passkeyPerson(r,'synthetic-auth-1',address(1),'owner');
 const employee=await passkeyPerson(r,'synthetic-auth-2',address(2),'member');
 for(let n=3;n<=12;n++)await passkeyPerson(r,'synthetic-auth-'+n,address(n),'member');
 const post=async(path,data,status=200,extra={})=>{const response=await r.call('/api/auth'+path,{method:'POST',cookie:owner.cookie,data,...extra});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const count=async table=>(await r.db.prepare('SELECT count(*) AS n FROM '+table).first()).n;
 const notices=async()=>(await r.mails()).filter(mail=>mail.subject==='Auth administrator role granted');
 const preview=(n,roleId='app-administrator')=>post('/roles/preview',{kind:'grant',personId:'synthetic-auth-'+n,roleId,resources:{view:{apps:['*']},edit:{apps:['*']}}});
 const apply=plan=>post('/roles/apply',{previewId:plan.previewId});
 const followup=async()=>(await(await r.call('/api/auth/followup',{cookie:owner.cookie})).json()).obligations;
 const intent=id=>r.db.prepare('SELECT * FROM auth_security_notice_intents WHERE id=?').bind(id).first();
 // Required events exist before setup; consent controls transport, not custody.
 const unconfigured=await apply(await preview(2));assert.equal((await notices()).length,0);
 assert.equal((await intent(unconfigured.operationId)).state,'blocked');
 assert.ok((await followup()).some(ob=>ob.source_id==='security-notice:'+unconfigured.operationId&&ob.state==='open'&&ob.last_error==='notification_channel_setup_required'));
 await post('/notifications/settings',{...policy,newDevice:false});
 await r.restart();await r.call('/',{action:'maintain'});
 assert.equal((await notices()).length,1);assert.equal((await notices())[0].to,address(2));
 assert.equal((await intent(unconfigured.operationId)).state,'accepted');
 assert.ok((await followup()).some(ob=>ob.source_id==='security-notice:'+unconfigured.operationId&&ob.state==='completed'));
 const builtIn=await preview(3);assert.equal((await notices()).length,1,'preview sends nothing');
 assert.equal(await count('auth_security_notice_intents'),1,'preview records no intent');
 const granted=await apply(builtIn),sent=(await notices()).at(-1);
 assert.equal((await notices()).length,2);assert.equal(sent.to,address(3));assert.match(sent.text,/App administrator/);assert.ok(reportLink(sent));
 const bound=await intent(granted.operationId);assert.equal(bound.grant_id,granted.plan.id);assert.equal(bound.recipient_email,address(3));
 assert.equal((await r.db.prepare('SELECT source_id FROM auth_security_notifications WHERE id=?').bind(bound.notification_id).first()).source_id,granted.operationId);
 await post('/roles/apply',{previewId:builtIn.previewId},409);assert.equal((await notices()).length,2,'replay sends nothing');
 const custom=await post('/roles/preview',{kind:'role',role:{name:'Scoped native administrator',rank:40,permissions:['apps.view','apps.edit']}});
 const designed=await apply(custom),customGrant=await apply(await preview(4,designed.plan.role.id));
 assert.equal((await notices()).length,3);assert.equal((await notices()).at(-1).to,address(4));assert.match((await notices()).at(-1).text,/Scoped native administrator/);
 assert.equal((await intent(customGrant.operationId)).state,'accepted');
 const zeroRank=await apply(await preview(5,'app-owner'));assert.equal(await intent(zeroRank.operationId),null,'ordinary zero-rank role keeps its existing classification');assert.equal((await notices()).length,3);
 const stale=await preview(6);await apply(await preview(7,'app-owner'));
 await post('/roles/apply',{previewId:stale.previewId},409);assert.equal((await notices()).length,3,'stale preview sends nothing');
 await post('/roles/preview',{kind:'grant',personId:'synthetic-auth-6',roleId:'owner',resources:{view:{apps:['*']},edit:{apps:['*']}}},403);
 await post('/roles/apply',{previewId:stale.previewId},409,{cookie:employee.cookie});
 assert.equal(await count('auth_security_notice_intents'),3,'refused grants record no intent');
 // Loss of fresh proof inside the committing batch cannot leave a grant or mail.
 const lost=await preview(6),grantCount=await count('auth_role_grants');
 await post('/roles/apply',{previewId:lost.previewId},409,{factorRace:'UPDATE auth_sessions SET local_email_verified_at=0'});
 assert.equal(await count('auth_role_grants'),grantCount);assert.equal(await count('auth_security_notice_intents'),3);assert.equal((await notices()).length,3);
 owner=await signInAgain(r,owner,address(1));
 // Failure of intent persistence rolls back the source action and its preview.
 const rollback=await preview(6);
 await r.db.prepare("CREATE TRIGGER synthetic_notice_abort BEFORE INSERT ON auth_security_notice_intents BEGIN SELECT RAISE(ABORT,'synthetic_notice_persistence_failure'); END;").run();
 const aborted=await r.call('/api/auth/roles/apply',{method:'POST',cookie:owner.cookie,data:{previewId:rollback.previewId}});assert.equal(aborted.status,500);
 assert.equal(await count('auth_role_grants'),grantCount);assert.equal((await r.db.prepare('SELECT consumed_at FROM auth_role_previews WHERE id=?').bind(rollback.previewId).first()).consumed_at,null);
 await r.db.prepare('DROP TRIGGER synthetic_notice_abort').run();
 // The commit survives a lost response; restart delivers its intent only once.
 const interrupted=await preview(6);
 const lostResponse=await r.call('/api/auth/roles/apply',{method:'POST',cookie:owner.cookie,data:{previewId:interrupted.previewId},roleNoticeFault:'after_grant'});assert.equal(lostResponse.status,500);
 const pending=await r.db.prepare("SELECT * FROM auth_security_notice_intents WHERE grant_id=?").bind(interrupted.plan.id).first();assert.equal(pending.state,'pending');assert.equal((await notices()).length,3);
 await r.restart();await Promise.all([r.call('/',{action:'maintain'}),r.call('/',{action:'maintain'})]);
 assert.equal((await notices()).length,4);assert.equal((await intent(pending.id)).state,'accepted');
 await post('/roles/apply',{previewId:interrupted.previewId},409);
 // A changed mailbox never redirects a committed intent to an unbound address.
 const moved=await preview(8);
 assert.equal((await r.call('/api/auth/roles/apply',{method:'POST',cookie:owner.cookie,data:{previewId:moved.previewId},roleNoticeFault:'after_grant'})).status,500);
 await post('/directory/edit',{personId:'synthetic-auth-8',email:address(18)});
 await r.call('/',{action:'maintain'});assert.equal((await notices()).length,4);
 const refused=await r.db.prepare('SELECT * FROM auth_security_notice_intents WHERE grant_id=?').bind(moved.plan.id).first();assert.equal(refused.state,'refused');assert.equal(refused.recipient_email,address(8));
 // A provider refusal and an accepted send with lost bookkeeping stay visible,
 // with no automatic retry after restart or duplicate maintenance.
 const attempted=[];r.mailEdge=await edge(t,async(_req,body,res)=>{attempted.push(JSON.parse(body));res.writeHead(503);res.end();});
 const failed=await apply(await preview(9));assert.equal(attempted.length,1);assert.equal((await intent(failed.operationId)).state,'failed');
 r.mailEdge=undefined;
 const uncertain=await preview(10);
 assert.equal((await r.call('/api/auth/roles/apply',{method:'POST',cookie:owner.cookie,data:{previewId:uncertain.previewId},roleNoticeFault:'after_delivery'})).status,500);
 const unknown=await r.db.prepare('SELECT * FROM auth_security_notice_intents WHERE grant_id=?').bind(uncertain.plan.id).first();assert.equal(unknown.state,'dispatching');assert.equal((await notices()).length,5);
 await r.restart();await r.call('/',{action:'maintain'});await r.call('/',{action:'maintain'});
 assert.equal((await notices()).length,5);assert.equal(attempted.length,1);
 const outstanding=await followup();
 assert.ok(outstanding.some(ob=>ob.source_id==='security-notice:'+failed.operationId&&ob.state==='open'&&ob.last_error==='security_mail_failed_or_unknown'));
 assert.ok(outstanding.some(ob=>ob.source_id==='security-notice:'+unknown.id&&ob.state==='open'&&ob.last_error==='security_mail_outcome_unknown'));
 // A person without a current verified work address retains an undeliverable
 // intent; a request cannot supply an alternate recipient.
 await post('/directory/edit',{personId:'synthetic-auth-12',email:address(22)});
 const unverified=await apply(await preview(12));assert.equal((await intent(unverified.operationId)).recipient_email,null);assert.equal((await intent(unverified.operationId)).state,'refused');assert.equal((await notices()).length,5);
 // Generic reminder consent cannot authorize another security-mail attempt.
 await post('/followup/settings',{confirm:true,enabled:true,calendar:{timezone:'UTC',weekdays:[0,1,2,3,4,5,6],holidays:[],at:'09:00'},reminderBusinessDays:1,deadlineBusinessDays:5,recipients:['synthetic-auth-1'],escalationRecipients:['synthetic-auth-1'],escalation:'repeat_until_resolved'});
 const mailCount=(await r.mails()).length;
 for(const operationId of [failed.operationId,unknown.id]) {
  const ob=(await followup()).find(ob=>ob.source_id==='security-notice:'+operationId);assert.ok(ob);
  await post('/followup/send',{id:ob.id});
 }
 assert.equal((await r.mails()).length,mailCount,'general reminder consent cannot resend a required security notice');
 const foreign=await post('/organizations/create',{name:'Other notice employer'},201);
 const foreignModel=await r.call('/org/'+foreign.id+'/api/auth/notifications',{cookie:owner.cookie});assert.equal(foreignModel.status,401);
 const employer={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+foreign.id+path,options)};
 const foreignOwner=await register(employer,await emailSession(employer,address(1)));
 const foreignReports=await(await employer.call('/api/auth/notifications',{cookie:foreignOwner.cookie})).json();assert.deepEqual(foreignReports.reports,[]);
 const foreignWork=await(await employer.call('/api/auth/followup',{cookie:foreignOwner.cookie})).json();assert.ok(!JSON.stringify(foreignWork.obligations).includes('security-notice:'));
 const report=reportLink(sent);assert.equal((await r.call('/org/'+foreign.id+local(report))).status,410);
 assert.equal((await r.call(local(report))).status,200);assert.equal((await r.call(local(report))).status,410);
 // Erasure removes queued personal data and invalidates already issued reports.
 const erased=await preview(11);
 assert.equal((await r.call('/api/auth/roles/apply',{method:'POST',cookie:owner.cookie,data:{previewId:erased.previewId},roleNoticeFault:'after_grant'})).status,500);
 await post('/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const erase=await post('/erasure/preview',{kind:'person',target:'synthetic-auth-11'});
 await post('/erasure/confirm',{previewId:erase.id,confirmation:'ERASE',destinations:[]});
 await r.restart();await r.call('/',{action:'maintain'});assert.equal((await notices()).length,5);
 assert.equal(await r.db.prepare('SELECT id FROM auth_security_notice_intents WHERE grant_id=?').bind(erased.plan.id).first(),null);
 const deliveredErase=await post('/erasure/preview',{kind:'person',target:'synthetic-auth-4'});
 await post('/erasure/confirm',{previewId:deliveredErase.id,confirmation:'ERASE',destinations:[]});
 assert.equal((await r.call(local(reportLink((await notices()).find(mail=>mail.to===address(4)))))).status,410);
}
