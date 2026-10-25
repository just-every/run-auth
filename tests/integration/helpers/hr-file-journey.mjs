import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {rm} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {createHash} from 'node:crypto';
import ssh2 from 'ssh2';
import {expect} from '@playwright/test';
const root=fileURLToPath(new URL('../../../',import.meta.url));
export async function hrFileJourney({app,context,page,shoot}) {
 const key=ssh2.utils.generateKeyPairSync('ed25519');
 const fingerprint='SHA256:'+createHash('sha256').update(ssh2.utils.parseKey(key.public).getPublicSSH()).digest('base64').replace(/=+$/,'');
 const post=(path,data)=>context.request.post(app.origin+'/api/auth/'+path,{data,headers:{origin:app.origin}});
 const registered=await post('hr-feeds/create',{name:'Reviewed hourly HR delivery',schedule:'hourly',fingerprint,
  mapping:{sourceId:'ID',email:'Email',state:'State',effectiveAt:'Effective'},confirm:true});assert.equal(registered.status(),201);
 const feed=(await registered.json()).id;assert.match(feed,/^[A-Za-z0-9_-]{43}$/);
 const delivered=await post('hr-feeds/upload',{feedId:feed,fileName:'workforce.csv',text:'ID,Email,State,Effective\nsynthetic-auth-170,synthetic-auth-170@example.com,active,'+new Date(Date.now()-1000).toISOString()+'\n'});assert.equal(delivered.status(),202);
 // Age the actual retained source timestamp; no fake page/session/source or
 // production clock override is installed. The ordinary source engine reads it.
 await app.pause();
 try {
  execFileSync(process.execPath,[join(root,'node_modules/wrangler/bin/wrangler.js'),'d1','execute','DB','--local','--persist-to',join(app.directory,'.wrangler/state'),'--config',join(root,'dist/server/wrangler.json'),'--command',`UPDATE auth_hr_feeds SET created_at=${Date.now()-3*3600000},last_success_at=${Date.now()-3*3600000} WHERE id='${feed}'`],{cwd:root,stdio:'ignore',env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',X_LOCAL_EXPLORER:'false'}});
 } finally {
  // Wrangler keeps scratch beside the emitted config, outside the temporary D1 state.
  await rm(join(root,'dist/server/.wrangler'),{recursive:true,force:true});
 }
 await app.resume();
 const followup=await context.request.get(app.origin+'/api/auth/followup');assert.equal(followup.status(),200);
 const item=(await followup.json()).obligations.find(row=>row.kind==='hr_file_feed');assert.ok(item);assert.equal(item.canSend,false);
 await page.goto(app.origin+'/app/activity');
 const row=page.locator('[data-followup-id="'+item.id+'"]');await expect(row).toContainText('hr file feed');await expect(row).toContainText('review stale hr feed');
 await expect(row.getByRole('link',{name:'Open HR file feed guide'})).toBeVisible();await expect(row.getByRole('button',{name:'Send reminder early'})).toHaveCount(0);
 await shoot('hr-feed-stale');
 await expect(row.getByRole('link',{name:'Open HR file feed guide'})).toHaveAttribute('href','https://run-auth.com/docs/hr-file-feeds');
}
