import {authenticator} from '../auth/webauthn.mjs';

// Only the WebAuthn hardware and paid mail boundaries are fixtures. All account,
// email, proof, session and passkey state is created by the production handlers.
export async function nativePerson({request,origin,email,mail,claim}) {
 const jar=new Map();
 async function call(path,data,{form=false}={}) {
  const response=await request(new URL(path,origin).href,{method:'POST',redirect:'manual',headers:{origin,cookie:[...jar].map(([k,v])=>k+'='+v).join('; '),'content-type':form?'application/x-www-form-urlencoded':'application/json'},body:form?new URLSearchParams(data):JSON.stringify(data)});
  for(const value of response.headers.getSetCookie()){const [pair]=value.split(';');const at=pair.indexOf('=');jar.set(pair.slice(0,at),pair.slice(at+1));}
  return response;
 }
 if(claim) {
  const claimed=await call(claim.path,{token:claim.token,displayName:'Avery Owner',returnTo:'/setup'});
  if(claimed.status!==303)throw new Error('Native signed claim refused');
 }
 async function emailProof() {
  const after=Date.now()-1,started=await call('/auth/identity/email/request',{email,returnTo:'/app/account'});
  if(started.status!==202)throw new Error('Native email request refused');
  let token;
  for(let i=0;i<20&&!token;i++) {
   const messages=await mail.read({after});
   const match=(messages.at(-1)?.text??'').match(/https:\/\/[^\s]+\/auth\/identity\/email\/confirm\?token=([^\s]+)/);
   token=match?.[1];
   if(!token)await new Promise(resolve=>setTimeout(resolve,100));
  }
  if(!token)throw new Error('Native email not captured');
  const confirmed=await call('/auth/identity/email/confirm',{token},{form:true});
  if(confirmed.status!==303)throw new Error('Native email confirmation refused');
  return confirmed;
 }
 await emailProof();
 const key=authenticator(origin),offered=await call('/auth/passkeys/register/options',{});
 if(!offered.ok)throw new Error('Native passkey enrollment refused');
 const tx=await offered.json(),registered=await call('/auth/passkeys/register/verify',{transaction:tx.transaction,response:key.register(tx.options)});
 if(!registered.ok)throw new Error('Native passkey verification refused');
 const response=await emailProof();
 return {response,call,cookie:()=>[...jar].map(([k,v])=>k+'='+v).join('; ')};
}
