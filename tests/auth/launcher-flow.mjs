import assert from 'node:assert/strict';
import {passkeyPerson} from './agents-helpers.mjs';
import {submitRequest,decide} from './access-decisions-flow.mjs';
export async function temporaryLauncherGrant(r,app,id='temporary-worker') {
 const employee=await passkeyPerson(r,id,`${id}@example.com`,'member');
 assert.equal((await r.admin('/api/auth/requests/policy',{appId:app.id,deciderId:'owner',maxDurationMs:60000})).status,200);
 const submitted=await submitRequest(r,employee,{appId:app.id,purpose:'Read the assigned app',durationMs:60000});
 assert.equal(submitted.status,201,await submitted.clone().text());const request=await submitted.json();
 const approved=await decide(r,r.owner,{kind:'request',targetId:request.id,operation:'approve',reason:'One minute of explicitly approved access'});
 assert.equal(approved.status,200,await approved.clone().text());
 return employee;
}
