import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {once} from 'node:events';
import {chromium} from '@playwright/test';
import {openRuntime,emailSession} from './runtime.mjs';

test('Chromium creates and uses a host-bound passkey through the Auth HTTP API',async t=>{
 const r=await openRuntime();t.after(()=>r.close());r.local=true;
 const server=createServer(async(req,res)=>{
  try {
   if(req.url==='/'||req.url==='/app/account'){res.setHeader('Content-Type','text/html');res.end('<!doctype html><html><title>Auth WebAuthn proof</title><body>Auth WebAuthn proof</body></html>');return;}
   const chunks=[];for await(const part of req)chunks.push(part);const body=Buffer.concat(chunks).toString();
   const response=await r.call(req.url,{method:req.method,headers:req.headers,cookie:req.headers.cookie,...(body?(req.headers['content-type']?.startsWith('application/x-www-form-urlencoded')?{form:Object.fromEntries(new URLSearchParams(body))}:{data:JSON.parse(body)}):{})});
   const headers=Object.fromEntries(response.headers),cookies=response.headers.getSetCookie();
   if(cookies.length)headers['set-cookie']=cookies;
   res.writeHead(response.status,headers);res.end(Buffer.from(await response.arrayBuffer()));
  }catch(error){res.writeHead(500);res.end(String(error));}
 });
 server.listen(0,'127.0.0.1');await once(server,'listening');t.after(()=>new Promise(resolve=>server.close(resolve)));
 r.origin=`http://localhost:${server.address().port}`;
 await r.person('owner','owner@example.com','owner');
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());const context=await browser.newContext();
 const page=await context.newPage(),cdp=await context.newCDPSession(page);await cdp.send('WebAuthn.enable');
 await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'internal',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
 await page.goto(r.origin);
 await page.evaluate(()=>fetch('/auth/identity/email/request',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({email:'owner@example.com'})}));
 const link=(await r.mails()).at(-1).text.match(/https?:\/\/\S+$/)[0];await page.goto(link);
 await Promise.all([page.waitForURL(r.origin+'/app/account'),page.getByRole('button',{name:'Continue to Auth'}).click()]);
 await page.goto(r.origin);
 const result=await page.evaluate(async()=>{
  const decode=v=>Uint8Array.from(atob(v.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
  const encode=v=>btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
  async function call(path,data={}){const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)});return {status:r.status,body:await r.json()};}
  const registration=await call('/auth/passkeys/register/options'),options=registration.body.options;
  options.challenge=decode(options.challenge);options.user.id=decode(options.user.id);options.excludeCredentials=options.excludeCredentials.map(c=>({...c,id:decode(c.id)}));
  const credential=await navigator.credentials.create({publicKey:options});
  const registered=await call('/auth/passkeys/register/verify',{transaction:registration.body.transaction,response:{id:credential.id,rawId:encode(credential.rawId),type:credential.type,response:{clientDataJSON:encode(credential.response.clientDataJSON),attestationObject:encode(credential.response.attestationObject),transports:credential.response.getTransports()},clientExtensionResults:credential.getClientExtensionResults()}});
  await call('/api/auth/signout');
  const authentication=await call('/auth/passkeys/authenticate/options',{returnTo:'/app/people'}),auth=authentication.body.options;auth.challenge=decode(auth.challenge);
  if(auth.allowCredentials)auth.allowCredentials=auth.allowCredentials.map(c=>({...c,id:decode(c.id)}));
  const assertion=await navigator.credentials.get({publicKey:auth});
  const signedIn=await call('/auth/passkeys/authenticate/verify',{transaction:authentication.body.transaction,response:{id:assertion.id,rawId:encode(assertion.rawId),type:assertion.type,response:{clientDataJSON:encode(assertion.response.clientDataJSON),authenticatorData:encode(assertion.response.authenticatorData),signature:encode(assertion.response.signature),userHandle:assertion.response.userHandle?encode(assertion.response.userHandle):null},clientExtensionResults:assertion.getClientExtensionResults()}});
  return {registered,signedIn,peopleStatus:(await fetch('/api/auth/people')).status};
 });
 assert.equal(result.registered.status,200);assert.equal(result.signedIn.status,200);assert.equal(result.signedIn.body.returnTo,'/app/people');assert.equal(result.peopleStatus,200);
});
