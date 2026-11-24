import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createAuthRuntime,maintainAuth} from '../../src/auth/index.mjs';
import {openMigratedD1,metered,total,seedHistory,NOW} from './cron-d1-history.mjs';

// The scheduled run fires every five minutes, 288 times a day, against a
// Workers Free database that allows five million rows read a day to every
// tool on the account. What it reads is D1's own count.
async function settledRun(days) {
 const {db,close}=await openMigratedD1();
 try {
  await seedHistory(db,{days});
  const log=[],runtime=createAuthRuntime({db:metered(db,log),origin:'https://auth.example.com',secret:'1a'.repeat(32),local:false,now:()=>NOW,mail:async()=>{},waitUntil:()=>{}});
  // The first run after an upgrade looks through what already exists, once.
  await maintainAuth(runtime.context);
  log.length=0;
  await maintainAuth(runtime.context);
  return total(log);
 } finally {await close();}
}

test('a scheduled maintenance run costs the same rows whether the history is three days or a month',async()=>{
 const short=await settledRun(3),long=await settledRun(30);
 console.log(`scheduled run, 3 days of history: ${short.read} rows read, ${short.written} written; 30 days: ${long.read} read, ${long.written} written`);
 assert.ok(long.read<=1000,`a month of history costs ${long.read} rows per run`);
 assert.ok(long.read<=short.read+100,`${long.read} rows against ${short.read} for a tenth of the history`);
 assert.ok(long.written<=10,`a run with nothing to do wrote ${long.written} rows`);
});
