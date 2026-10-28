import assert from 'node:assert/strict';
import {expect} from '@playwright/test';
import {captureViews} from './capture-views.mjs';

// Use the emitted Worker, an enrolled administrator and the app's real SAML
// peer. Exercise the user flow at one width; capture its states at both widths.
export async function catalogConfigurationJourney({app,context,page,employeePage,sp,views,errors,capture}) {
 const response=await context.request.post(app.origin+'/api/auth/catalog/add',{headers:{origin:app.origin},data:{recipe:'aws-iam-identity-center',name:'Catalog expenses',metadata:sp.metadata}});
 assert.equal(response.status(),201,await response.text());const added=await response.json();
 const model=async()=> (await (await context.request.get(app.origin+'/api/auth/company-apps')).json()).companyApps.find(a=>a.id===added.id);
 const employee=(await(await employeePage.context().request.get(app.origin+'/api/auth/me')).json()).user;
 assert.equal((await context.request.post(app.origin+'/api/auth/company-apps/assign',{headers:{origin:app.origin},data:{appId:added.id,principalType:'person',principalId:employee.id,role:'reviewer'}})).status(),200);
 await employeePage.goto(sp.origin+'/login');await expect(employeePage.getByRole('heading',{name:`Signed in as ${employee.email} (assigned)`,exact:true})).toBeVisible();
 await page.goto(app.origin+'/app/apps');
 const panel=page.locator(`section[aria-labelledby="company-app-${added.id}"]`),settings=panel.locator('[data-configuration]');
 const form=settings.locator('[data-configuration-form]').first(),approve=settings.getByRole('button',{name:'Approve configuration',exact:true});
 const preview=async target=>{
  const s=target.locator(`section[aria-labelledby="company-app-${added.id}"] [data-configuration]`);
  await s.locator(':scope > summary').click();await s.getByLabel('App name',{exact:true}).fill('Reviewed expenses');await s.getByRole('button',{name:'Preview configuration',exact:true}).click();
  await expect(s.locator('[data-configuration-result]')).toContainText('No settings changed');return s;
 };
 await preview(page);await expect(approve).toBeDisabled();
 assert.equal((await model()).name,'Catalog expenses');
 await form.getByLabel('App name',{exact:true}).fill('Different expenses');await expect(settings.locator('[data-configuration-review]')).toBeHidden();
 await form.getByLabel('App name',{exact:true}).fill('Reviewed expenses');await form.getByRole('button',{name:'Preview configuration',exact:true}).click();await expect(settings.locator('[data-configuration-proposed]')).toContainText('Reviewed expenses');
 await captureViews({page,views,errors,workers:1,prepare:preview,capture:(target,width,theme)=>capture(target,width,theme,'configuration-preview')});
 await settings.locator('[data-configuration-confirm]').check();await approve.click();
 await expect(panel.getByRole('heading',{name:'Reviewed expenses',exact:true})).toBeVisible();assert.equal((await model()).version,2);
 await employeePage.goto(sp.origin+'/login');await expect(employeePage.getByRole('heading',{name:`Signed in as ${employee.email} (assigned)`,exact:true})).toBeVisible();
 // Hold an on-screen review while a second native approval changes the app.
 const conflict=async target=>{
  const s=await preview(target),current=await model();
  const review=await context.request.post(app.origin+'/api/auth/catalog/preview',{headers:{origin:app.origin},data:{appId:added.id,version:current.version,settings:{name:'Concurrent expenses'}}});assert.equal(review.status(),200);
  const committed=await context.request.post(app.origin+'/api/auth/catalog/approve',{headers:{origin:app.origin},data:{appId:added.id,preview:(await review.json()).preview,confirm:true}});assert.equal(committed.status(),200);
  await s.locator('[data-configuration-confirm]').check();await s.getByRole('button',{name:'Approve configuration',exact:true}).click();await expect(s.locator('[data-configuration-result]')).toContainText('changed');await expect(s.getByRole('button',{name:'Approve configuration',exact:true})).toBeDisabled();
 };
 // Capture serially so each screenshot's live version change is deliberate.
 for(const [width,theme] of views){await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await page.reload();await conflict(page);await capture(page,width,theme,'configuration-conflict');}
 await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});await page.reload();
 const rollback=async target=>{
  const s=target.locator(`section[aria-labelledby="company-app-${added.id}"] [data-configuration]`);await s.locator(':scope > summary').click();await s.getByLabel('Previous configuration',{exact:true}).selectOption('1');await s.getByRole('button',{name:'Preview rollback',exact:true}).click();await expect(s.locator('[data-configuration-title]')).toContainText('rollback to version 1');return s;
 };
 await captureViews({page,views,errors,workers:1,prepare:rollback,capture:(target,width,theme)=>capture(target,width,theme,'configuration-rollback')});
 await settings.locator('[data-configuration-confirm]').check();await approve.click();await expect(panel.getByRole('heading',{name:'Catalog expenses',exact:true})).toBeVisible();
 const restored=await model();assert.equal(restored.revisions[0].rolled_back_from,1);assert.equal(restored.assignments[0].role,'reviewer');
 await app.pause();await app.resume();await page.reload();assert.equal((await model()).version,restored.version);
 await employeePage.goto(sp.origin+'/login');await expect(employeePage.getByRole('heading',{name:`Signed in as ${employee.email} (assigned)`,exact:true})).toBeVisible();
 await page.goto(app.origin+'/app/apps');await panel.getByRole('button',{name:'Remove app',exact:true}).click();await expect(panel).toHaveCount(0);
}
