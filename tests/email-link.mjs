import {queuedEntrypoint} from '@runeditrun/rer/queued-entry';
const queued=await queuedEntrypoint(import.meta.url,'verify:email-link');if(queued!==null)process.exit(queued);
import assert from 'node:assert/strict';
import {openApp} from './integration/runtime.mjs';
const app=await openApp();
try {
 await app.claim();const cookie=await app.signIn('/setup');
 const session=await app.get('/api/auth/me',{cookie});
 assert.equal(session.status,200);assert.equal((await session.json()).user.email,app.vars.OWNER_EMAIL);
 console.log('Email-link sign-in passed against emitted Auth Worker: bootstrap, real gated outbox, browser-bound proof, own session');
} finally {await app.close();}
