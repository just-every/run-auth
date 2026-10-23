import assert from 'node:assert/strict';
import {expect} from '@playwright/test';

// Request once, then observe its real asynchronous delivery at the public,
// key-gated outbox. An invitation or another person's mail is not this proof.
export async function requestRefreshSignIn(app,page,address) {
 const headers={'x-rer-dev-key':app.vars.RER_DEV_KEY};
 const read=async path=>{const response=await app.get(path,headers);assert.equal(response.status,200);return response.text();};
 const messages=async()=>[...new Set([...(await read('/__dev/outbox')).matchAll(/href="(\/__dev\/outbox\?message=[^"]+)"/g)].map(match=>match[1].replaceAll('&amp;','&')))];
 const before=new Set(await messages());
 const accepted=page.waitForResponse(response=>response.url().endsWith('/auth/identity/email/request')&&response.request().method()==='POST');
 await page.getByRole('button',{name:'Email me a sign-in link'}).click();assert.equal((await accepted).status(),202);
 let link;
 await expect.poll(async()=>{
  for(const path of (await messages()).filter(path=>!before.has(path))) {
   const body=await read(path);
   if(!body.includes(address))continue;
   const href=body.match(/href="([^"]*\/auth\/identity\/email\/confirm\?token=[^"]+)"/)?.[1];
   if(href){link=new URL(href.replaceAll('&amp;','&'),app.origin);assert.equal(link.origin,app.origin);return true;}
  }
  return false;
 },{timeout:15000,message:'the requested sign-in proof reaches the real outbox'}).toBe(true);
 return link;
}
