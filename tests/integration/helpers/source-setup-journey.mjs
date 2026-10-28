import assert from 'node:assert/strict';
import {expect} from '@playwright/test';
import {join} from 'node:path';

export async function sourceSetupJourney({app,providerEdge,owner,page,shoot,directory,accessible,sourceEdge}) {
 const json=async(response,status=200)=>{if(response.status()!==status)assert.fail(await response.text());return response.json();};
 const post=(path,data)=>owner.request.post(app.origin+path,{data,headers:{origin:app.origin},maxRedirects:0});
 const challenge=await json(await post('/api/auth/domains/challenge',{domain:'example.com'}),201);
 providerEdge.dnsRecords.set(challenge.label,challenge.value);
 await json(await post('/api/auth/domains/verify',{domain:'example.com',id:challenge.id}));
 const provider={...providerEdge.provider,id:'delegated-company',preset:'oidc',label:'Delegated company',endpointPins:{authorization:providerEdge.provider.issuer+'/authorize',token:providerEdge.provider.issuer+'/token',jwks:providerEdge.provider.issuer+'/keys'},subjectEmails:{'synthetic-auth-campaign-0':'campaign.worker0@example.com'}};
 await page.goto(app.origin+'/app/move-in');
 await page.getByText('Configure an upstream',{exact:true}).click();
 await page.getByLabel('Verified employer domain',{exact:true}).fill('example.com');
 await page.getByLabel('Private provider configuration',{exact:true}).fill(JSON.stringify(provider));
 await page.getByLabel('I approve preparing this exact upstream and subject map',{exact:true}).check();
 await shoot('federation-setup',undefined,'federation');
 const prepared=page.waitForResponse(response=>response.url().endsWith('/federation/create'));
 await page.getByRole('button',{name:'Prepare upstream',exact:true}).click();assert.equal((await prepared).status(),201);
 await expect(page).toHaveURL(/\?federation=/);const setup={id:new URL(page.url()).searchParams.get('federation')};
 await expect(page.getByRole('region',{name:'Federation mapping preview'})).toBeVisible();await shoot('federation-draft');
 await page.route(providerEdge.provider.issuer+'/authorize?**',async route=>{
  const url=new URL(route.request().url());await providerEdge.claims('synthetic-auth-campaign-0',url.searchParams.get('nonce'));
  const callback=new URL(url.searchParams.get('redirect_uri'));
  for(const [name,value] of Object.entries({code:'synthetic-auth-setup-browser',state:url.searchParams.get('state'),iss:providerEdge.provider.issuer}))callback.searchParams.set(name,value);
  await route.fulfill({contentType:'text/html',body:`<!doctype html><title>Test identity provider</title><a href="${callback.href.replaceAll('&','&amp;')}">Prove test employee</a>`});
 });
 await page.locator(`[data-federation-setup="${setup.id}"]`).getByLabel('Representative immutable subject').fill('synthetic-auth-campaign-0');
 const testing=page.waitForResponse(response=>response.url().endsWith('/federation/test'));
 await page.getByRole('button',{name:'Test representative sign-in',exact:true}).click();const tested=await testing;assert.equal(tested.status(),200,tested.status()===200?'':await tested.text());await page.getByRole('link',{name:'Prove test employee',exact:true}).click();
 await expect(page.getByRole('button',{name:'Activate upstream',exact:true})).toBeVisible();
 const who=await json(await owner.request.get(app.origin+'/api/auth/me'));assert.equal(who.user.email,'owner@example.com','representative callback preserves only the initiating owner session');
 await shoot('federation-tested');
 await page.getByLabel('I approve this tested upstream and these exact subject mappings',{exact:true}).check();
 await page.getByRole('button',{name:'Activate upstream',exact:true}).click();await expect(page.locator(`[data-federation-setup="${setup.id}"]`)).toContainText('active');await shoot('federation-active');
 await page.goto(app.origin+'/app/methods');await expect(page.locator('.data-row strong').filter({hasText:/^Delegated company$/})).toBeVisible();await shoot('federation-methods');
 await page.goto(app.origin+'/signin');await expect(page.getByRole('button',{name:'Continue with Delegated company',exact:true})).toBeVisible();await shoot('federation-signin');
 await page.goto(app.origin+'/app/move-in');await page.getByText('Connect a directory source',{exact:true}).click();
 await page.getByLabel('Source name',{exact:true}).fill('Engineering directory');
 await page.getByLabel('Directory provider',{exact:true}).selectOption('scim');
 await page.getByLabel('Connection direction',{exact:true}).selectOption('push');
 await page.getByLabel('Organization binding',{exact:true}).fill(app.origin);
 await page.getByLabel('I authorize this bound source and its selected fields',{exact:true}).check();await shoot('directory-source-setup',undefined,'source');
 const connected=page.waitForResponse(response=>response.url().endsWith('/directory-sources/create'));
 await page.getByRole('button',{name:'Connect source',exact:true}).click();const source=await json(await connected,201);
 await expect(page.getByLabel('One-time SCIM credential',{exact:true})).toBeVisible();assert.equal(await page.getByLabel('One-time SCIM credential',{exact:true}).inputValue(),source.ingressToken);
 for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});await page.waitForTimeout(250);await accessible('one-time source credential '+width);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth));
  await page.getByRole('region',{name:'Directory sources',exact:true}).screenshot({path:join(directory,`move-in-directory-source-connected-${width}.png`),mask:[page.getByLabel('One-time SCIM credential',{exact:true})]});
 }await page.setViewportSize({width:1440,height:1000});
 await page.getByRole('link',{name:'Open source dashboard',exact:true}).click();
 const headers={authorization:'Bearer '+source.ingressToken,'content-type':'application/scim+json'};
 await json(await owner.request.post(source.scimBase+'/Users',{headers,data:{schemas:['urn:ietf:params:scim:schemas:core:2.0:User','urn:ietf:params:scim:schemas:extension:enterprise:2.0:User'],externalId:'synthetic-auth-ui-worker',userName:'directory.worker@example.com',displayName:'Sofia Patel',active:true,['urn:ietf:params:scim:schemas:extension:enterprise:2.0:User']:{department:'Customer success'}}}),201);
 const group=await owner.request.post(source.scimBase+'/Groups',{headers,data:{schemas:['urn:ietf:params:scim:schemas:core:2.0:Group'],externalId:'synthetic-auth-ui-team',displayName:'Customer operations',members:[{value:'synthetic-auth-ui-worker',type:'User'}]}});await json(group,201);
 await page.goto(app.origin+'/app/move-in?sourceSnapshot='+group.headers()['x-auth-directory-snapshot']);
 await expect(page.getByRole('region',{name:'Directory change preview'})).toContainText('Sofia Patel');await shoot('directory-source-held',async()=>{await page.getByText('Source field values',{exact:true}).click();await expect(page.getByText('Customer success',{exact:true})).toBeVisible();});
 await page.getByLabel('I approve these exact directory changes',{exact:true}).check();await page.getByLabel('I separately confirm the held changes',{exact:true}).check();
 await page.getByRole('button',{name:'Apply reviewed changes',exact:true}).click();await expect(page.getByText('These observations have been applied. No approval remains pending.',{exact:true})).toBeVisible();await shoot('directory-source-applied');
 await page.locator(`[data-directory-source="${source.sourceId}"]`).getByText('Source settings',{exact:true}).click();
 await page.getByRole('button',{name:'Disable source',exact:true}).click();await expect(page.locator(`[data-directory-source="${source.sourceId}"]`)).toContainText('Disabled');await shoot('directory-source-disabled');
 const stopped=await owner.request.get(source.scimBase+'/Users',{headers});assert.equal(stopped.status(),401);
 await directoryFreshnessJourney({app,owner,page,shoot,sourceEdge});
 await page.goto(app.origin+'/app/move-in?federation='+setup.id);await page.getByRole('button',{name:'Disable upstream',exact:true}).click();await expect(page.locator(`[data-federation-setup="${setup.id}"]`)).toContainText('disabled');await shoot('federation-disabled');
}

export function sourceFreshnessEdge(next) {
 const state={failure:false,reads:0};
 return {...state,get failure(){return state.failure;},set failure(value){state.failure=value;},async fetch(request) {
  const url=new URL(request.url);
  if(url.hostname==='cloudflare-dns.com'&&url.searchParams.get('name')==='freshness.example.com')return Response.json({Status:0,Answer:url.searchParams.get('type')==='A'?[{type:1,data:'93.184.216.34'}]:[]});
  if(url.origin!=='https://freshness.example.com')return next(request);
  state.reads++;
  if(request.headers.get('authorization')!=='Bearer synthetic-auth-205')return Response.json({}, {status:401});
  if(state.failure)return Response.json({}, {status:503});
  const users=[{schemas:['urn:ietf:params:scim:schemas:core:2.0:User'],id:'synthetic-auth-206',userName:['synthetic-auth-206','example.com'].join('@'),displayName:'Synthetic freshness worker',active:true}];
  const rows=url.pathname==='/scim/Users'?users:[];
  return Response.json({schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:rows.length,startIndex:1,itemsPerPage:rows.length,Resources:rows});
 }};
}
async function directoryFreshnessJourney({app,owner,page,shoot,sourceEdge}) {
 const post=(path,data)=>owner.request.post(app.origin+'/api/auth/'+path,{data,headers:{origin:app.origin}});
 const response=await post('directory-sources/create',{kind:'scim',mode:'pull',name:'Freshness directory',baseUrl:'https://freshness.example.com/scim',organizationBinding:'https://freshness.example.com',credential:'synthetic-auth-205',fields:['name'],confirm:true});assert.equal(response.status(),201,await response.text());const source=await response.json();
 sourceEdge.failure=true;
 await page.goto(app.origin+'/app/move-in');
 const card=()=>page.locator(`[data-directory-source="${source.sourceId}"]`);
 await card().getByText('Source settings',{exact:true}).click();
 let read=page.waitForResponse(response=>response.url().endsWith('/directory-sources/pull'));await card().getByRole('button',{name:'Read directory now'}).click();assert.equal((await read).status(),502);
 await page.reload();await expect(card().locator('[data-source-freshness]')).toContainText('Directory read failed');
 await shoot('directory-freshness-failed',async width=>{if(width===1440){await expect(card()).toContainText('Check the source credential and connection');await expect(card()).toContainText('Reminders are not authorized');}});
 await page.goto(app.origin+'/app/activity');
 const records=await(await owner.request.get(app.origin+'/api/auth/followup')).json();const obligation=records.obligations.find(row=>row.kind==='directory_source'&&row.sourceLink.endsWith(source.sourceId));assert.ok(obligation);assert.equal(obligation.canSend,false);
 const followup=()=>page.locator(`[data-followup-id="${obligation.id}"]`);
 await expect(followup().locator('[data-followup-state]')).toHaveText('open');await expect(followup().getByRole('button',{name:'Send reminder early'})).toHaveCount(0);
 await app.pause();await app.resume();await page.reload();await expect(followup().locator('[data-followup-state]')).toHaveText('open');
 await shoot('directory-freshness-obligation',async width=>{if(width===1440){await expect(followup()).toContainText('directory source request refused');await expect(followup().getByRole('link',{name:'Open directory source'})).toHaveAttribute('href',new RegExp(source.sourceId));}});
 await followup().getByRole('link',{name:'Open directory source'}).click();await expect(card()).toBeVisible();
 sourceEdge.failure=false;await card().getByText('Source settings',{exact:true}).click();
 read=page.waitForResponse(response=>response.url().endsWith('/directory-sources/pull'));await card().getByRole('button',{name:'Read directory now'}).click();const recovered=await read;assert.equal(recovered.status(),202);const result=await recovered.json();assert.equal(result.replayed,true);assert.equal(result.snapshotId,source.snapshotId);
 await expect(card().locator('[data-source-freshness]')).toContainText('Observation current');await shoot('directory-freshness-recovered');
 const people=await(await owner.request.get(app.origin+'/api/auth/people')).json();assert.equal(people.some(row=>row.email===['synthetic-auth-206','example.com'].join('@')),false,'recovery never approves staged people');
 await page.goto(app.origin+'/app/activity');await expect(followup().locator('[data-followup-state]')).toHaveText('completed');await shoot('directory-freshness-history');
 await post('directory-sources/disable',{sourceId:source.sourceId,confirm:true});
}
