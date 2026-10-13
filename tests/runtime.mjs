import {queuedEntrypoint} from '../scripts/base-onboarding/queued-entry.mjs';
const queued=await queuedEntrypoint(import.meta.url,'verify:runtime');if(queued!==null)process.exit(queued);
import assert from 'node:assert/strict';
import {openApp} from './integration/runtime.mjs';

const app=await openApp();
try {
 assert.deepEqual(await(await app.get('/health')).json(),{status:'ok'});
 const document=await app.get('/');assert.equal(document.status,303);assert.match(document.headers.get('location'),/^\/signin/);
 const signin=await app.get('/signin');assert.equal(signin.status,200);assert.match(await signin.text(),/<form[^>]+\/auth\/identity\/email\/request/);
 for(const path of ['/missing','/health/extra','/api','/api/missing','/app/missing'])assert.equal((await app.get(path)).status,404,path);
 console.log('HTTP-001 passed against emitted Auth Worker: health, protected root, real sign-in document and HTTP/document 404s');
} finally {await app.close();}
