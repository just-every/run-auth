import assert from 'node:assert/strict';
import {ownerInstall,passkeyPerson,post} from './agents-helpers.mjs';
import {emailSession,cookieOf} from './runtime.mjs';
import {register} from './webauthn.mjs';

export async function identityPairsFlow(t) {
 const {r,owner}=await ownerInstall(t);
 const worker=await passkeyPerson(r,'worker','worker@example.com','member'),outsider=await passkeyPerson(r,'outsider','outsider@example.com','member');
 const json=async(response,status=200)=>{assert.equal(response.status,status,await response.clone().text());return response.json();};
 const command=(client,cookie,path,data,status=200)=>jsonResponse(client.call('/api/auth'+path,post(data,cookie)),status);
 const jsonResponse=async(promise,status=200)=>json(await promise,status);
 const organizations=[];
 for(const name of ['Linked A','Unproved B','Unlinked C']) {
  const org=await command(r,owner.cookie,'/organizations/create',{name},201);
  const client={origin:r.origin,get now(){return r.now;},mails:()=>r.mails(),call:(path,options)=>r.call('/org/'+org.id+path,options)};
  const admin=await register(client,await emailSession(client,'owner@example.com'));
  const invited=await command(client,admin.cookie,'/organizations/invite',{email:'worker@example.com',name:'Independent employee'},201);
  const member=await register(client,await emailSession(client,'worker@example.com'));
  organizations.push({org,client,admin,member,personId:invited.id});
 }
 const [a,b,c]=organizations,both=worker.cookie+'; '+a.member.cookie;
 assert.deepEqual((await json(await r.call('/api/auth/identity-pairs',{cookie:worker.cookie}))).links,[]);
 assert.equal((await r.call('/api/auth/identity-pairs/options',post({organizationId:b.org.id},worker.cookie))).status,401,'root proof alone cannot link B');
 const offered=await r.call('/api/auth/identity-pairs/options',post({organizationId:a.org.id},both)),options=await json(offered);
 const confirmation={transaction:options.transaction,rootResponse:worker.key.authenticate(options.rootOptions),memberResponse:a.member.key.authenticate(options.memberOptions),confirm:true};
 const binding=both+'; '+cookieOf(offered);
 const foreign={...confirmation,memberResponse:b.member.key.authenticate(options.memberOptions)};
 assert.equal((await r.call('/api/auth/identity-pairs/confirm',post(foreign,binding))).status,400,'foreign employer factor does not satisfy the paired membership');
 // A failed ceremony is one-use; restart rather than replaying its proof.
 const next=await r.call('/api/auth/identity-pairs/options',post({organizationId:a.org.id},both)),again=await json(next);
 const pair=await json(await r.call('/api/auth/identity-pairs/confirm',post({transaction:again.transaction,rootResponse:worker.key.authenticate(again.rootOptions),memberResponse:a.member.key.authenticate(again.memberOptions),confirm:true},both+'; '+cookieOf(next))),201);
 assert.equal(pair.authorityTransferred,false);
 for(const path of ['/api/auth/me','/api/auth/people','/api/auth/roles/export?personId=worker']){const response=await r.call(path,{cookie:owner.cookie});assert.equal(response.status,200);assert.ok(!(await response.text()).includes(pair.handle),path+' hides voluntary pair handles');}
 assert.equal((await a.client.call('/api/auth/identity-pairs',{cookie:a.admin.cookie})).status,403,'employer administration cannot read the installation pair ledger');
 assert.equal((await r.call('/api/auth/identity-pairs/confirm',post(confirmation,binding))).status,400,'spent proof cannot be reused');
 const mine=await json(await r.call('/api/auth/identity-pairs/export',{cookie:worker.cookie}));assert.equal(mine.links.length,1);assert.equal(mine.links[0].handle,pair.handle);
 for(const cookie of [owner.cookie,outsider.cookie])assert.deepEqual((await json(await r.call('/api/auth/identity-pairs',{cookie}))).links,[],'each person sees only their own voluntary pairs');
 assert.equal((await r.call('/api/auth/identity-pairs/remove',post({handle:pair.handle},outsider.cookie))).status,404);
 // Removing and recreating the link destroys the old per-pair handle.
 await command(r,both,'/identity-pairs/remove',{handle:pair.handle});
 assert.equal((await json(await r.call('/api/auth/identity-pairs',{cookie:worker.cookie}))).links.length,0);
 const relink=await r.call('/api/auth/identity-pairs/options',post({organizationId:a.org.id},both)),relinkOptions=await json(relink);
 const linked=await command(r,both+'; '+cookieOf(relink),'/identity-pairs/confirm',{transaction:relinkOptions.transaction,rootResponse:worker.key.authenticate(relinkOptions.rootOptions),memberResponse:a.member.key.authenticate(relinkOptions.memberOptions),confirm:true},201);
 assert.notEqual(linked.handle,pair.handle);
 // A receipt key is requested explicitly by the independently proved person.
 const issue='/identity-pairs/receipt-key',read='/identity-pairs/receipt',revoke='/identity-pairs/receipt-revoke';
 await command(r,worker.cookie,issue,{confirm:false},403);
 await command(r,undefined,issue,{confirm:true},401);
 const emailOnly=await emailSession(r,'worker@example.com');
 await command(r,emailOnly,issue,{confirm:true},403);
 await command(r,worker.cookie,issue,{confirm:true,personId:'outsider'},400);
 const issued=await command(r,worker.cookie,issue,{confirm:true},201),receiptKey=issued.receiptKey;
 const expiring=(await command(r,worker.cookie,issue,{confirm:true},201)).receiptKey;
 const outsiderKey=(await command(r,outsider.cookie,issue,{confirm:true},201)).receiptKey;
 assert.equal((await command(r,undefined,read,{receiptKey:outsiderKey})).state,'awaiting-installation-erasure');
 const stored=(await r.db.prepare('SELECT * FROM auth_erasure_person_receipts').all()).results;
 for(const raw of [receiptKey,expiring,outsiderKey])assert.ok(!JSON.stringify(stored).includes(raw),'only digests are persisted');
 assert.ok(issued.expiresAt>r.now);
 for(const path of ['/api/auth/me','/api/auth/identity-pairs','/api/auth/identity-pairs/export'])assert.equal((await r.call(path,{headers:{authorization:'Bearer '+receiptKey}})).status,401,'receipt authority never signs in or lists memberships');
 assert.equal((await r.call('/api/auth/erasure/policy',{...post({confirm:true,receiptKey}),headers:{authorization:'Bearer '+receiptKey}})).status,401,'receipt authority cannot erase');
 assert.equal((await r.call('/api/auth'+read+'?receiptKey=synthetic-auth-1',post({receiptKey}))).status,400,'a URL is never a receipt-key transport');
 assert.equal((await r.call('/api/auth'+read+'?receiptKey=synthetic-auth-1')).status,404);
 await command(r,undefined,read,{receiptKey:'synthetic-auth-1'},404);
 assert.equal((await command(r,undefined,'/identity-pairs/receipt',{receiptKey})).state,'awaiting-installation-erasure');
 await command(r,owner.cookie,'/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const preview=await command(r,owner.cookie,'/erasure/preview',{kind:'person',target:'worker'});
 for(const privateValue of [...organizations.flatMap(item=>[item.org.name,item.org.id]),linked.handle,receiptKey,'auth_identity_pairs'])assert.ok(!JSON.stringify(preview).includes(privateValue),'root preview reveals neither employer names/counts nor private handles');
 const erased=await command(r,owner.cookie,'/erasure/confirm',{previewId:preview.id,confirmation:'ERASE',destinations:[]});assert.equal(erased.local,'complete');
 for(const privateValue of [...organizations.flatMap(item=>[item.org.name,item.org.id]),linked.handle,receiptKey,'auth_identity_pairs'])assert.ok(!JSON.stringify(erased).includes(privateValue),'root receipt reveals no employer or pair count');
 assert.equal((await r.call('/api/auth/me',{cookie:worker.cookie})).status,401);
 const aNotices=(await json(await a.client.call('/api/auth/identity-release-notices',{cookie:a.admin.cookie}))).notices;assert.equal(aNotices.length,1);assert.equal(aNotices[0].handle,linked.handle);assert.equal(aNotices[0].erasureReference,erased.reference);assert.equal(aNotices[0].personId,undefined);
 for(const item of [b,c])assert.deepEqual((await json(await item.client.call('/api/auth/identity-release-notices',{cookie:item.admin.cookie}))).notices,[],'unlinked employers receive nothing');
 const followup=await json(await a.client.call('/api/auth/followup',{cookie:a.admin.cookie}));
 const obligation=followup.obligations.find(row=>row.kind==='identity_release');assert.ok(obligation);assert.equal(obligation.owner_id,(await json(await a.client.call('/api/auth/me',{cookie:a.admin.cookie}))).user.id);assert.equal(obligation.state,'open');
 assert.equal((await a.client.call('/api/auth/identity-release-notices',{cookie:a.member.cookie})).status,403);
 assert.equal((await command(r,undefined,'/identity-pairs/receipt',{receiptKey})).notices[0].state,'pending');
 await command(a.client,a.admin.cookie,'/erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const hold=await command(a.client,a.admin.cookie,'/erasure/hold',{kind:'person',target:a.personId,reason:'Preserve the active investigation'},201);
 await command(a.client,a.admin.cookie,'/identity-release-notices/hold',{noticeId:aNotices[0].id,holdId:hold.id});
 const heldReceipt=await command(r,undefined,'/identity-pairs/receipt',{receiptKey});assert.equal(heldReceipt.notices[0].state,'held');
 assert.equal((await json(await a.client.call('/api/auth/followup',{cookie:a.admin.cookie}))).obligations.find(row=>row.kind==='identity_release').state,'completed');
 await command(a.client,a.admin.cookie,'/erasure/hold',{release:true,id:hold.id});
 assert.equal((await json(await a.client.call('/api/auth/followup',{cookie:a.admin.cookie}))).obligations.find(row=>row.kind==='identity_release').state,'open');
 const memberPreview=await command(a.client,a.admin.cookie,'/erasure/preview',{kind:'person',releaseNoticeId:aNotices[0].id});
 await command(a.client,a.admin.cookie,'/erasure/confirm',{previewId:memberPreview.id,confirmation:'ERASE',destinations:[]});
 const receipt=await command(r,undefined,'/identity-pairs/receipt',{receiptKey});assert.deepEqual(receipt.notices,[{handle:linked.handle,erasureReference:erased.reference,state:'erased'}]);
 for(const org of organizations)for(const value of [org.org.name,org.org.id])assert.ok(!JSON.stringify(receipt).includes(value),'receipt contains no employer identity');
 assert.deepEqual(Object.keys(receipt).sort(),['message','notices','state']);assert.equal(receipt.message,'Auth erased your installation identity. Memberships you did not link are held separately by those employers; Auth did not see or erase them. Ask each employer to erase them.');
 assert.equal((await c.client.call('/api/auth/me',{cookie:c.member.cookie})).status,200,'unlinked membership is not erased');
 await r.restart();assert.equal((await command(r,undefined,'/identity-pairs/receipt',{receiptKey})).notices[0].state,'erased','receipt and notice survive restart');
 const resetPreview=await command(r,owner.cookie,'/erasure/preview',{kind:'organization',target:a.org.id});
 await command(r,owner.cookie,'/erasure/confirm',{organizationId:a.org.id,previewId:resetPreview.id,confirmation:'RESET '+r.origin+'/org/'+a.org.id});
 const afterReset=await command(r,undefined,read,{receiptKey});
 assert.deepEqual(afterReset.notices,[{handle:linked.handle,erasureReference:erased.reference,state:'employer-erased'}]);
 for(const table of ['auth_identity_pairs','auth_identity_release_notices'])assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM org_'+a.org.id+'_'+table).first()).n,0,'organization reset destroys its handles');
 assert.equal((await command(r,undefined,read,{receiptKey:outsiderKey})).state,'awaiting-installation-erasure','each key reads only its own receipt');
 await command(r,undefined,revoke,{receiptKey,confirm:false},403);
 await command(r,undefined,revoke,{receiptKey,confirm:true});
 await command(r,undefined,read,{receiptKey},404);
 await r.restart();await command(r,undefined,read,{receiptKey},404);
 assert.ok((await r.db.prepare('SELECT revoked_at FROM auth_erasure_person_receipts WHERE revoked_at IS NOT NULL').first()).revoked_at,'revocation leaves a retained anonymous fact');
 const activity=await json(await r.call('/api/auth/activity',{cookie:owner.cookie}));assert.ok(!JSON.stringify(activity).includes(linked.handle));assert.ok(!JSON.stringify(activity).includes(receiptKey));
 // An installation creator is provenance, never ownership of the employer's
 // independent records. A second root owner can erase that creator alone.
 const successor=await passkeyPerson(r,'successor','successor@example.com','owner');
 const creatorPreview=await command(r,successor.cookie,'/erasure/preview',{kind:'person',target:'owner'});
 await command(r,successor.cookie,'/erasure/confirm',{previewId:creatorPreview.id,confirmation:'ERASE',destinations:[]});
 assert.equal((await c.client.call('/api/auth/me',{cookie:c.admin.cookie})).status,200,'erasing the root creator leaves the employer and its independent owner');
 const deadline=new Date(stored[0].created_at);deadline.setUTCMonth(deadline.getUTCMonth()+13);
 r.now=deadline.getTime()-1;assert.equal((await command(r,undefined,read,{receiptKey:expiring})).state,'installation-erased','read authority lasts until the thirteen-month boundary');
 r.now=deadline.getTime();
 await command(r,undefined,read,{receiptKey:expiring},404);
 await r.call('/scheduled',{action:'maintain'});await r.restart();
 await command(r,undefined,read,{receiptKey:expiring},404);
 const facts=(await r.db.prepare('SELECT * FROM auth_erasure_person_receipts').all()).results;
 assert.ok(facts.every(row=>row.expired_at===row.expires_at),'expiry leaves retained facts even without a read');
 assert.ok(facts.every(row=>row.person_id===null&&row.notices==='[]'),'ended keys retain no receipt payload or identity');
 assert.ok(facts.some(row=>row.revoked_at!==null),'expiry preserves the prior revocation fact');
}
