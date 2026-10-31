import assert from 'node:assert/strict';
import {mkdir} from 'node:fs/promises';
import {join} from 'node:path';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {attributionFlow,names} from '../../agent-door/attribution.test.mjs';
import {captureViews} from './capture-views.mjs';

export async function agentAttributionJourney(t) {
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic','--no-sandbox'],executablePath:process.env.AUTH_CHROMIUM||undefined});
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 try {await attributionFlow(t,async({stage,policy,hosted,person,id,row})=>{
  const context=await browser.newContext({viewport:{width:1440,height:1000},serviceWorkers:'block'});
  try {
   // These are only the disposable journey's ordinary native sessions.
   await context.addCookies(person.cookie().split('; ').map(pair=>{const at=pair.indexOf('=');return {name:pair.slice(0,at),value:pair.slice(at+1),url:hosted.origin};}));
   await context.route('**/*',async route=>{
    const req=route.request(),url=new URL(req.url());assert.equal(url.origin,hosted.origin);
    const response=await hosted.fetch(url.href.slice(hosted.origin.length+1),{method:req.method(),headers:await req.allHeaders(),...(req.postDataBuffer()?{body:req.postDataBuffer()}:{})});
    const headers=Object.fromEntries(response.headers);delete headers['content-encoding'];delete headers['content-length'];
    await route.fulfill({status:response.status,headers,body:Buffer.from(await response.arrayBuffer())});
   });
   const page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
   if(stage==='approve') {
    await page.goto(hosted.origin+'/agents/approvals/'+id);await expect(page.locator('[data-approval-summary]')).toBeVisible();
    await expect(page.getByText(names.agent+' for '+names.sponsor,{exact:true})).toBeVisible();
    await page.getByRole('button',{name:'Approve',exact:true}).click();await expect(page.locator('[data-approval-state]')).toHaveText('executed');
    await expect(page.getByText(names.approver+' · person:synthetic-auth-approver',{exact:false})).toBeVisible();
   } else {
    await page.goto(hosted.origin+'/app/activity?event=agent_door_effect');
    const activity=page.locator('.activity-row');await expect(activity).toHaveCount(1);
    await expect(activity.locator('td').nth(1)).toHaveText('Actor'+names.agent+' for '+names.sponsor);
    const detail=activity.locator('[data-activity-detail]');
    if(policy==='held')await expect(detail).toContainText('Human approvers: '+names.approver);
    else {await expect(detail).not.toContainText('Human approvers:');await expect(activity).not.toContainText(names.approver);}
    await expect(detail).toContainText('OperationId:');
    assert.equal(await activity.locator('img').count(),0,'hostile names stay text');assert.equal(await page.evaluate(()=>window.attributionInjected),undefined);
    await page.getByRole('link',{name:'Skip to activity history'}).focus();await page.keyboard.press('Enter');await expect(page.locator('#activity-history')).toBeFocused();
    await captureViews({page,views:[[1440,'light'],[1440,'dark'],[390,'light'],[390,'dark']],errors,capture:async(page,width,theme)=>{
     // Assertions run at the desktop width; phone views are visual proof.
     if(width===1440) {
      await expect(activity).toContainText(row.actor_id);if(policy==='held')await expect(detail).toContainText('Human approvers: '+names.approver);
      assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Activity fits');
      const axe=await new AxeBuilder({page}).analyze();assert.deepEqual(axe.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[]);
      assert.ok(await detail.evaluate(el=>parseFloat(getComputedStyle(el).fontSize)>=13),'attribution is readable');
      for(const control of await page.locator('[data-tooltip]:visible').all()) {
       await page.mouse.move(0,0);await control.blur();await control.hover();await page.waitForTimeout(350);await expect(page.getByRole('tooltip')).toBeVisible();
       await page.mouse.move(0,0);await control.focus();assert.equal(await page.getByRole('tooltip').isVisible(),true);await page.keyboard.press('Escape');await control.blur();
      }
     }
     await activity.scrollIntoViewIfNeeded();
     await page.screenshot({path:join(directory,`agent-attribution-${policy}-${width}-${theme}.png`)});
    }});
   }
   assert.deepEqual(errors,[]);
  } finally {await context.close();}
 });} finally {await browser.close();}
}
