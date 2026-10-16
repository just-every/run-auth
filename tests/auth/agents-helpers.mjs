import assert from 'node:assert/strict';
import {openRuntime,emailSession,cookieOf} from './runtime.mjs';
import {register,authenticate} from './webauthn.mjs';
import {requestProof,finishProof} from './policy-helpers.mjs';

export const post=(data={},cookie)=>({method:'POST',data,cookie});
export const table=async(r,name)=>(await r.db.prepare(`SELECT * FROM ${name} ORDER BY 1`).all()).results;
export const proposal=(r,id)=>r.db.prepare('SELECT * FROM auth_agent_proposals WHERE id=?').bind(id).first();
export const person=(r,email)=>r.db.prepare('SELECT * FROM oa_operators WHERE email=?').bind(email).first();

// A person signed in with a hardware passkey and a fresh local email proof.
export async function passkeyPerson(r,id,email,role,key) {
 await r.person(id,email,role);
 return register(r,await emailSession(r,email),key);
}
export async function ownerInstall(t) {
 const r=await openRuntime();t.after(()=>r.close());
 const owner=await passkeyPerson(r,'owner','owner@example.com','owner');
 return {r,owner};
}
export async function mint(r,cookie,label='Directory agent') {
 const response=await r.call('/api/auth/agents/mint',post({label},cookie));assert.equal(response.status,201,await response.clone().text());
 return (await response.json()).key;
}
export const preparer=(r,key,{method='GET',data,headers={}}={})=>r.call('/api/auth/preparer',{method,data,headers:{authorization:'Preparer '+key,...headers}});
export async function file(r,key,data) {
 const response=await preparer(r,key,{method:'POST',data});assert.equal(response.status,201,await response.clone().text());
 return (await response.json()).id;
}
// A person approves: the challenge names the proposal, the passkey signs it.
export async function approvalProof(r,{cookie,key},proposalId) {
 const options=await r.call('/api/auth/agents/approve/options',post({proposalId},cookie));
 if(options.status!==200)return {refused:options};
 const tx=await options.json(),binding=options.headers.get('set-cookie').split(';')[0];
 return {options:tx.options,request:post({transaction:tx.transaction,response:key.authenticate(tx.options)},`${cookie}; ${binding}`)};
}
export async function approve(r,approver,proposalId) {
 const proof=await approvalProof(r,approver,proposalId);
 return proof.refused??r.call('/api/auth/agents/approve',proof.request);
}
export const reject=(r,cookie,proposalId)=>r.call('/api/auth/agents/reject',post({proposalId},cookie));
export async function activity(r,event) {
 return (await r.db.prepare('SELECT a.*,d.detail FROM auth_activity a LEFT JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event=? ORDER BY a.id').bind(event).all()).results.map(row=>({...row,detail:row.detail?JSON.parse(row.detail):null}));
}
// A new passkey session with a fresh local email proof, as after a day away.
export async function signInAgain(r,{key},email) {
 const {response}=await authenticate(r,key);assert.equal(response.status,200);
 const confirmed=await finishProof(r,await requestProof(r,email,cookieOf(response)));assert.equal(confirmed.status,200);
 return {key,cookie:cookieOf(confirmed)};
}
// Everything a test process writes, to show a key never reaches a log.
export function captureOutput(t) {
 const written=[],originals=[process.stdout.write,process.stderr.write];
 for(const stream of [process.stdout,process.stderr]){const original=stream.write;stream.write=function(chunk,...rest){written.push(String(chunk));return original.call(this,chunk,...rest);};}
 t.after(()=>{[process.stdout.write,process.stderr.write]=originals;});
 return ()=>written.join('');
}
export async function everyRow(r) {
 const tables=(await r.db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'").all()).results.map(row=>row.name);
 return JSON.stringify(await Promise.all(tables.map(name=>table(r,name))));
}
