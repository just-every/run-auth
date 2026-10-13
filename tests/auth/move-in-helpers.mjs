import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {openRuntime,emailSession} from './runtime.mjs';
import {register} from './webauthn.mjs';

export const fixture=name=>readFile(new URL('../fixtures/move-in/'+name,import.meta.url),'utf8');
export const post=(data={},cookie)=>({method:'POST',data,cookie});
export const count=async(r,sql,...args)=>(await r.db.prepare(sql).bind(...args).first()).n;
export const table=async(r,name)=>(await r.db.prepare(`SELECT * FROM ${name} ORDER BY 1,2`).all()).results;

// An owner signed in with a hardware passkey and a fresh local email proof.
export async function ownerInstall(t) {
 const r=await openRuntime();t.after(()=>r.close());
 await r.person('owner','owner@example.com','owner');
 const {cookie}=await register(r,await emailSession(r,'owner@example.com'));
 return {r,cookie};
}
export async function stage(r,cookie,name,{text,exportDate='2026-10-11'}={}) {
 return r.call('/api/auth/move-in/stage',post({fileName:name,exportDate,text:text??await fixture(name)},cookie));
}
export async function staged(r,cookie,name) {
 const response=await stage(r,cookie,name);assert.equal(response.status,201,await response.clone().text());
 return (await response.json()).batchId;
}
export async function review(r,cookie,batch) {
 const response=await r.call('/api/auth/move-in?batch='+encodeURIComponent(batch),{cookie});assert.equal(response.status,200);
 return (await response.json()).rows;
}
export const byEmail=(rows,email)=>rows.find(row=>row.email===email);
export async function admit(r,cookie,batch,indexes) {
 return r.call('/api/auth/move-in/admit',post({batchId:batch,rows:indexes},cookie));
}
