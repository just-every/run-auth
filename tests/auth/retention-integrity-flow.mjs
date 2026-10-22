import assert from 'node:assert/strict';
import {openRuntime} from './runtime.mjs';
import {passkeyPerson,signInAgain} from './agents-helpers.mjs';
const DAY=86400000;
export async function retentionIntegrityFlow(t) {
 const r=await openRuntime();t.after(()=>r.close());let owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 const command=async(path,data,status=200)=>{const response=await r.call('/api/auth/'+path,{method:'POST',cookie:owner.cookie,data});assert.equal(response.status,status,path+' '+await response.clone().text());return response.json();};
 const aged=r.now-120*DAY;
 await r.db.prepare("INSERT INTO auth_activity(actor_id,event,created_at) VALUES('owner','synthetic_old_retained_audit',?)").bind(aged).run();
 await r.person('synthetic-auth-17','synthetic-auth-17@example.com');
 await command('erasure/policy',{confirm:true,automaticDeletion:false,honorLegalHolds:true});
 const preview=await command('erasure/preview',{kind:'person',target:'synthetic-auth-17'}),erased=await command('erasure/confirm',{previewId:preview.id,confirmation:'ERASE',destinations:[]});
 const integrity=async()=>{const response=await r.call('/api/auth/erasure/integrity?receiptId='+erased.id,{cookie:owner.cookie});assert.equal(response.status,200,await response.clone().text());return response.json();};
 assert.equal((await integrity()).valid,true);
 const classes=Object.fromEntries(['profiles','sourceSnapshots','authentication','decisions','provisioning','audit','modelTraces','erasureReceipts'].map(name=>[name,{unit:'days',value:name==='audit'?90:2555}]));
 await command('retention/settings',{confirm:true,classes});await command('retention/preview',{});
 r.now+=8*DAY;await r.call('/',{action:'maintain'});await r.restart();owner=await signInAgain(r,owner,'owner@example.com');
 assert.equal(await r.db.prepare("SELECT 1 FROM auth_activity WHERE event='synthetic_old_retained_audit'").first(),null);
 assert.equal((await integrity()).valid,true,'authenticated policy expiry keeps the erasure commitment verifiable');
 const proof=await r.db.prepare("SELECT id FROM auth_retention_expiry WHERE table_name='auth_activity' LIMIT 1").first();assert.ok(proof);
 await r.db.prepare("UPDATE auth_retention_expiry SET signature='synthetic-auth-18' WHERE id=?").bind(proof.id).run();
 assert.equal((await integrity()).valid,false,'tampered expiry proof cannot excuse deleted audit evidence');
}
