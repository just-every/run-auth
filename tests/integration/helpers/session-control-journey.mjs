import assert from 'node:assert/strict';
import {execFileSync} from 'node:child_process';
import {fileURLToPath} from 'node:url';
import {join} from 'node:path';
import {expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

// Extends the existing authority journey before recovery destroys the passkey.
export async function sessionControlJourney({app,page,context,helperPage,helperContext,workerPage,workerContext,worker,helper,group,appConfig,post,saved,directory}) {
 const action='/api/auth/roles/end-sessions';
 const reason='Employee reported a lost signed-in device. Case synthetic-auth-12345678901234567890123456789012345678901234567890';
 const ownerId=(await(await context.request.get(app.origin+'/api/auth/me')).json()).user.id;
 const read=async(client,path)=>{const response=await client.request.get(app.origin+path);assert.equal(response.status(),200);return response.json();};
 const capture=async(name,target)=>{
  for(const theme of ['light','dark'])for(const width of [1440,390]) {
   await target.setViewportSize({width,height:1000});
   await target.emulateMedia({colorScheme:theme});
   await target.evaluate(selected=>{localStorage.setItem('auth-theme',selected);document.documentElement.dataset.theme=selected;},theme);
   await target.evaluate(async()=>{
    document.body.getBoundingClientRect();
    await Promise.all(document.getAnimations().filter(animation=>animation.effect?.getTiming().iterations!==Infinity).map(animation=>animation.finished.catch(()=>{})));
   });
   assert.ok(await target.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits '+width);
   if(width===1440) {
    const audit=await new AxeBuilder({page:target}).analyze();
    assert.deepEqual(audit.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
    const modal=target.locator('dialog[open]');
    const surface=await modal.count()?modal:target;
    for(const control of await surface.locator('[data-tooltip]:visible').all()) {
     assert.ok((await control.getAttribute('data-tooltip')).trim().split(/\s+/).length>=2);
     assert.ok((await control.getAttribute('data-tooltip')).trim().split(/\s+/).length<=4);
     await target.mouse.move(0,0);await control.blur();await expect(target.getByRole('tooltip')).toBeHidden();
     await control.evaluate(el=>{
      const tip=document.querySelector('[role=tooltip]');
      el.addEventListener('mouseenter',()=>{el.dataset.sessionHoverStarted=String(performance.now());},{once:true});
      const observer=new MutationObserver(()=>{if(!tip.hidden){el.dataset.sessionHoverDelay=String(performance.now()-Number(el.dataset.sessionHoverStarted));observer.disconnect();}});
      observer.observe(tip,{attributes:true,attributeFilter:['hidden']});
     });
     await control.hover();
     await expect(target.getByRole('tooltip')).toBeVisible();await target.mouse.move(0,0);
     assert.ok(Number(await control.getAttribute('data-session-hover-delay'))>=250,'tooltip waits about 300 ms from pointer entry');
     await control.focus();assert.equal(await target.getByRole('tooltip').isVisible(),true);
     await target.keyboard.press('Escape');await control.blur();
    }
   }
   await target.screenshot({path:join(directory,`session-control-${name}-${width}-${theme}.png`),fullPage:true});
  }
  await target.setViewportSize({width:1440,height:1000});await target.emulateMedia({colorScheme:'light'});
  await target.evaluate(()=>{localStorage.setItem('auth-theme','light');document.documentElement.dataset.theme='light';});
 };
 // A role which permits factor recovery alone cannot end sessions.
 await expect(helperPage.locator('[data-session-control]')).toHaveCount(0);
 await post(action,{personId:worker.id,reason},403,helperContext);
 await capture('permission-hidden',helperPage);
 const grant=await post('/api/auth/roles/preview',{kind:'grant',personId:helper.id,roleId:'help-desk',resources:{view:{groups:[group.id]},edit:{groups:[group.id]}}});
 await post('/api/auth/roles/apply',{previewId:grant.previewId});
 await helperPage.reload();
 const inventory=await read(helperContext,'/api/auth/roles/people');
 assert.equal(inventory.people.find(p=>p.id===worker.id).canEndSessions,true);
 // A target outside this help desk's scope and rank remains protected.
 await post(action,{personId:ownerId,reason},403,helperContext);
 await post(action,{personId:worker.id,reason:''},400,helperContext);
 await page.goto(app.origin+'/app/people');
 const adminPanel=page.locator(`[data-session-control="${worker.id}"]`);
 await page.locator(`[data-open-dialog="sessions-${worker.id}"]`).click();
 await expect(adminPanel.getByRole('button',{name:'End all sessions',exact:true})).toBeVisible();
 await capture('people-action',page);
 await post('/api/auth/company-apps/assign',{appId:appConfig.id,principal:'group:'+group.id,role:'reader'});
 await adminPanel.getByRole('button',{name:'Close',exact:true}).click();
 const before=await read(context,'/api/auth/directory/groups');
 const beforeGroups=before.groups.filter(row=>row.members.some(member=>(member.id??member.personId)===worker.id));
 assert.ok(beforeGroups.some(row=>row.id===group.id),'employee has scoped group membership before session termination');
 assert.ok(beforeGroups.some(row=>row.apps.some(assignment=>assignment.appId===appConfig.id)),'group has a real app assignment to retain');
 const credentialIds=methods=>methods.map(({id,created_at})=>({id,created_at})).sort((a,b)=>a.id.localeCompare(b.id));
 const methodsBefore=credentialIds(await read(workerContext,'/api/auth/methods'));
 assert.ok(methodsBefore.length>0);
 const panel=helperPage.locator(`[data-session-control="${worker.id}"]`);
 await panel.locator(':scope > summary').click();
 const form=panel.locator('form');
 await form.getByRole('button',{name:'End all sessions',exact:true}).click();
 assert.equal(await form.getByLabel('Reason for ending sessions').evaluate(input=>input.validity.valueMissing),true);
 await form.getByLabel('Reason for ending sessions').fill(reason);
 await capture('scoped-confirmation',helperPage);
 // Rejecting the explicit native confirmation preserves the employee session.
 const acceptDialogs=dialog=>dialog.accept();
 helperPage.removeAllListeners('dialog');
 helperPage.once('dialog',dialog=>dialog.dismiss());
 await form.getByRole('button',{name:'End all sessions',exact:true}).click();
 assert.equal((await workerContext.request.get(app.origin+'/api/auth/me')).status(),200);
 helperPage.on('dialog',acceptDialogs);
 const ended=helperPage.waitForResponse(response=>response.url().endsWith(action)).then(async response=>{
  assert.equal(response.status(),200);
  return response.json();
 });
 await saved(()=>form.getByRole('button',{name:'End all sessions',exact:true}).click(),helperPage);
 const result=await ended;assert.ok(result.nativeSessionsEnded>=1);assert.ok(result.operationId);
 assert.equal((await workerContext.request.get(app.origin+'/api/auth/me')).status(),401,'old employee session is revoked');
 await panel.locator(':scope > summary').click();
 const receipt=panel.locator(`[data-session-operation="${result.operationId}"]`);
 const actor=(await read(helperContext,'/api/auth/me')).user;
 assert.equal(actor.id,helper.id);
 await expect(receipt).toContainText(actor.email);
 await expect(receipt).toContainText(reason);
 await expect(receipt).toContainText(`${result.nativeSessionsEnded} Auth sessions and ${result.refreshGrantsEnded} refresh grants`);
 const operations=await read(helperContext,'/api/auth/session-control?personId='+worker.id);
 const operation=operations.operations.find(row=>row.id===result.operationId);
 assert.equal(operation.actorId,helper.id);assert.equal(operation.reason,reason);
 assert.equal(operation.nativeSessionsEnded,result.nativeSessionsEnded);
 assert.equal(operation.refreshGrantsEnded,result.refreshGrantsEnded);
 await receipt.getByText('Back-channel delivery',{exact:true}).click();
 await capture('scoped-outcome',helperPage);
 // Resident credential remains usable without enrollment or account recovery.
 await workerPage.goto(app.origin+'/signin');
 await workerPage.getByRole('button',{name:'Continue with a passkey'}).click();
 await workerPage.waitForURL(app.origin+'/app');
 const fresh=await read(workerContext,'/api/auth/me');assert.equal(fresh.user.id,worker.id);assert.ok(fresh.user.amr.includes('hwk'));
 const methodsAfter=credentialIds(await read(workerContext,'/api/auth/methods'));
 assert.deepEqual(methodsAfter,methodsBefore,'passkeys retained through end sessions');
 const after=await read(context,'/api/auth/directory/groups');
 assert.deepEqual(after.groups.filter(row=>row.members.some(member=>(member.id??member.personId)===worker.id)),beforeGroups,'group membership and group app assignments retained');
 await page.reload();await page.locator(`[data-open-dialog="sessions-${worker.id}"]`).click();
 const adminReceipt=page.locator(`[data-session-operation="${result.operationId}"]`);
 await expect(adminReceipt).toContainText(reason);
 await adminReceipt.getByText('Back-channel delivery',{exact:true}).click();
 await capture('people-outcome',page);

 // A historical receipt predates terminal counters. Model that stored record,
 // then load both real administrator pages to prove the evidence warning.
 await app.pause();
 try {
  const root=fileURLToPath(new URL('../../../',import.meta.url));
  execFileSync(process.execPath,[join(root,'node_modules/wrangler/bin/wrangler.js'),'d1','execute','DB','--local','--persist-to',join(app.directory,'.wrangler/state'),'--config',join(root,'dist/server/wrangler.json'),'--command',`UPDATE auth_role_operations SET detail=json_remove(detail,'$.logoutOutcomes') WHERE id='${result.operationId}'`],{stdio:'ignore',env:{...process.env,CI:'true',WRANGLER_SEND_METRICS:'false',X_LOCAL_EXPLORER:'false'}});
 } finally {await app.resume();}
 for(const [target,name] of [[page,'people'],[helperPage,'scoped']]) {
  await target.reload();
  if(name==='people')await target.locator(`[data-open-dialog="sessions-${worker.id}"]`).click();
  else await target.locator(`[data-session-control="${worker.id}"] > summary`).click();
  const legacy=target.locator(`[data-session-operation="${result.operationId}"]`);
  await legacy.getByText('Back-channel delivery',{exact:true}).click();
  await expect(legacy).toContainText('Historical delivery evidence expired or was not retained.');
  await capture(name+'-historical-evidence',target);
 }
}
