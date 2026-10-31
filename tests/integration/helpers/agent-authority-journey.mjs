import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {authorityFixture,heldMembershipPolicy} from '../../agent-door/authority-fixture.mjs';

export async function agentAuthorityJourney(t) {
 const f=await authorityFixture(t),{app,people:p,groups:g}=f;
 await f.policy(heldMembershipPolicy());
 const browser=await chromium.launch({headless:true,executablePath:process.env.AUTH_CHROMIUM||undefined,args:['--no-sandbox','--use-mock-keychain','--password-store=basic']});
 t.after(()=>browser.close());
 const pageFor=async person=>{
  const context=await browser.newContext({viewport:{width:1440,height:1000}});
  await context.addCookies(person.cookie().split('; ').map(pair=>{const at=pair.indexOf('=');return {name:pair.slice(0,at),value:pair.slice(at+1),url:app.origin};}));
  const page=await context.newPage();page.setDefaultTimeout(30000);return page;
 };
 const owner=await pageFor(p.owner),editor=await pageFor(p.editor),reader=await pageFor(p.reader);
 const errors=[];for(const page of [owner,editor,reader])page.on('pageerror',error=>errors.push(error.message));
 await owner.goto(app.origin+'/app/roles');
 if(new URL(owner.url()).pathname==='/setup') {
  await owner.getByRole('checkbox').check();await owner.getByRole('button',{name:'Finish setup'}).click();
  await owner.goto(app.origin+'/app/roles');
 }
 await expect(owner.getByRole('heading',{name:'Delegate a role',exact:true})).toBeVisible();
 const grant=owner.locator('[data-role-form=grant]');
 await grant.locator('[name=personId]').selectOption(p.editor.id);
 await grant.locator('[name=roleId]').selectOption('group-owner');
 await grant.locator('[name="view.groups"]').selectOption([g.first.id,g.second.id]);
 await grant.locator('[name="view.people"]').selectOption(p.worker.id);
 await grant.locator('[name="edit.groups"]').selectOption(g.first.id);
 await grant.locator('[name="edit.people"]').selectOption(p.worker.id);
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const screen=async(name,page)=>{
  await page.bringToFront();
  for(const width of [1440,390])for(const theme of ['light','dark']) {
   await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});
   await page.evaluate(async()=>{document.body.getBoundingClientRect();await Promise.all(document.getAnimations().filter(a=>a.effect?.getTiming().iterations!==Infinity).map(a=>a.finished.catch(()=>{})));});
   if(width===1440) {
    assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),name+' fits');
    const result=await new AxeBuilder({page}).analyze();
    assert.deepEqual(result.violations.filter(v=>['critical','serious'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
    for(const control of await page.locator('[data-tooltip]:visible').all()) {
     await page.mouse.move(0,0);await control.blur();await control.hover();await page.waitForTimeout(150);await expect(page.getByRole('tooltip')).toBeHidden();
     await expect(page.getByRole('tooltip')).toBeVisible();await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true);
     await page.keyboard.press('Escape');await control.blur();
    }
   }
   await page.screenshot({path:join(directory,'agent-authority-'+name+'-'+width+'-'+theme+'.png'),fullPage:true});
  }
  await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});
 };
 await screen('scoped-delegation',owner);
 await reader.goto(app.origin+'/app/roles');
 await expect(reader.getByRole('heading',{name:'Delegate a role',exact:true})).toHaveCount(0);
 assert.equal((await p.reader.call('/api/auth/roles/group',{groupId:g.first.id,personId:p.worker.id,action:'add'})).status,403);
 const readerCall=await f.call(p.reader,'auth.groups.add',{group_id:g.first.id,person_id:p.worker.id,idempotency_key:'reader-ui'});
 assert.equal(readerCall._meta['com.runeditrun/error'].code,'admin_service_owner_permission_required');
 await screen('reader',reader);
 await f.policy();
 const savedAdd={group_id:g.first.id,person_id:p.worker.id,idempotency_key:'saved-ui-add'};
 const savedRemove={id:g.first.id+'/'+p.worker.id,idempotency_key:'saved-ui-remove'};
 assert.equal((await f.call(p.editor,'auth.groups.add',savedAdd)).isError,false);
 assert.equal((await f.call(p.editor,'auth.groups.remove',savedRemove)).isError,false);
 assert.equal((await f.call(p.editor,'auth.groups.add',{...savedAdd,idempotency_key:'saved-ui-add-again'})).isError,false);
 await f.policy(heldMembershipPolicy());
 const pending=await f.call(p.editor,'auth.groups.remove',{id:savedRemove.id,idempotency_key:'pending-ui'});
 assert.equal(pending.resultType,'input_required');
 const approvalId=pending._meta['com.runeditrun/approval'].id;
 await editor.goto(app.origin+'/agents/approvals/'+approvalId);
 await expect(editor.getByRole('button',{name:'Approve',exact:true})).toBeVisible();
 await expect(editor.locator('[data-approval-summary]')).toContainText('Synthetic first');
 await screen('pending',editor);
 // Revocation is performed through the owner's ordinary reviewed UI, without
 // ending read access or the independent edit grant for the second group.
 const revoke=owner.locator('[data-role-form=revoke]').filter({has:owner.locator('input[name=grantId][value="'+f.grants.first.id+'"]')});
 await revoke.getByRole('button',{name:'Preview revocation',exact:true}).click();
 await expect(revoke.locator('[data-role-apply]')).toBeVisible();
 await Promise.all([owner.waitForEvent('load'),revoke.locator('[data-role-apply]').click()]);
 await editor.bringToFront();await editor.getByRole('button',{name:'Approve',exact:true}).click();
 await expect(editor.locator('[data-approval-state]')).toHaveText('refused');
 await expect(editor.getByRole('button',{name:'Approve',exact:true})).toHaveCount(0);
 const membership=(await f.members()).find(group=>group.id===g.first.id);
 assert.equal(membership.members.some(person=>person.id===p.worker.id),true);
 const visible=await f.call(p.editor,'auth.groups.inspect',{id:g.first.id});assert.equal(visible.isError,false);
 for(const [name,args] of [['auth.groups.add',savedAdd],['auth.groups.remove',savedRemove]]) {
  const retry=await f.call(p.editor,name,args);
  assert.equal(retry.isError,true);assert.equal(retry.structuredContent,undefined);
  assert.equal(retry._meta['com.runeditrun/error'].code,'admin_service_owner_permission_required');
 }
 const separate=await f.call(p.editor,'auth.groups.add',{group_id:g.second.id,person_id:p.other.id,idempotency_key:'independent-ui-add'});
 assert.equal(separate.resultType,'input_required');
 assert.equal((await f.approve(p.editor,separate)).approval.state,'executed');
 assert.equal((await f.members()).find(group=>group.id===g.second.id).members.some(person=>person.id===p.other.id),true);
 await screen('authority-ended',editor);
 await app.pause();await app.resume();await editor.reload();
 await expect(editor.locator('[data-approval-state]')).toHaveText('refused');
 assert.deepEqual(errors,[]);
}
