// Apps this test process answers for, beside the real Base app: each holds its
// own ES256 link key and serves Auth's pulls, link callback and sign-in exchange,
// so a test can link apps at several origins and choose what each publishes.
import {generateKeyPair,exportJWK,SignJWT,decodeJwt} from 'jose';
import {createHash,randomBytes} from 'node:crypto';
import {AUTH_ORIGIN} from './origins.mjs';

const INTERFACE='oidc-provider@1',CALLBACK='/.well-known/rer-link/callback',SIGN_IN='/auth/oidc/auth/callback',LOGOUT='/auth/oidc/auth/logout';
const b64=buffer=>Buffer.from(buffer).toString('base64url');

export function scriptedApps() {
 const apps=new Map();let r=null;
 const sign=(app,claims)=>{const now=Math.floor(Date.now()/1000);return new SignJWT(claims).setProtectedHeader({alg:'ES256',kid:app.public.kid}).setIssuedAt(now).setExpirationTime(now+60).setJti(crypto.randomUUID()).sign(app.privateKey);};
 const scripted={
  bind(runtime){r=runtime;},
  async add(origin,{sector='sector-'+crypto.randomUUID(),version}={}) {
   const {publicKey,privateKey}=await generateKeyPair('ES256',{extractable:true});
   const app={origin,sector,version,privateKey,public:{...await exportJWK(publicKey),kid:crypto.randomUUID(),alg:'ES256',use:'sig'},clientId:null};
   apps.set(origin,app);return app;
  },
  // A person (cookie at Auth) signs in at the app: authorize, then the app's signed code exchange.
  async signIn(app,cookie) {
   const verifier=b64(randomBytes(32)),challenge=b64(createHash('sha256').update(verifier).digest());
   const query=new URLSearchParams({response_type:'code',client_id:app.clientId,redirect_uri:app.origin+SIGN_IN,scope:'openid email',state:'s'+crypto.randomUUID(),nonce:'n'+crypto.randomUUID(),code_challenge:challenge,code_challenge_method:'S256'});
   const authorize=await r.send(AUTH_ORIGIN+'/oidc/authorize?'+query,{cookies:false,headers:{cookie}});
   const code=new URL(authorize.headers.get('location')||'about:blank').searchParams.get('code');
   if(!code)return {status:authorize.status};
   const assertion=await sign(app,{iss:app.clientId,sub:app.clientId,aud:AUTH_ORIGIN+'/oidc/token'});
   const token=await r.send(AUTH_ORIGIN+'/oidc/token',{method:'POST',form:{grant_type:'authorization_code',code,redirect_uri:app.origin+SIGN_IN,code_verifier:verifier,client_id:app.clientId,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion},cookies:false});
   const body=await token.json();
   return {status:token.status,claims:body.id_token?decodeJwt(body.id_token):null};
  },
  async handle(request) {
   const url=new URL(request.url),app=apps.get(url.origin);
   if(!app)throw new TypeError('network unreachable');
   if(request.method==='GET'&&url.pathname==='/.well-known/rer-dependencies')return Response.json({name:'App at '+url.host,version:1,origin:app.origin,sector_id:app.sector,callback:app.origin+CALLBACK,...(app.version?{interface_version:app.version}:{}),provides:[],dependencies:[{interface:INTERFACE,optional:true,cardinality:1,provider:null,paths:[app.origin+SIGN_IN,app.origin+LOGOUT],jwks_uri:app.origin+'/.well-known/rer-link/jwks/'+INTERFACE}]});
   if(request.method==='GET'&&url.pathname==='/.well-known/rer-link/jwks/'+INTERFACE)return Response.json({keys:[app.public]});
   if(request.method==='POST'&&url.pathname===CALLBACK) {
    const {code}=await request.json();
    const assertion=await sign(app,{iss:app.origin,sub:app.origin,aud:AUTH_ORIGIN+'/oidc/link/redeem',code,interface:INTERFACE,sector_id:app.sector,callback:app.origin+CALLBACK});
    const redeemed=await r.send(AUTH_ORIGIN+'/oidc/link/redeem',{method:'POST',json:{code,interface:INTERFACE,origin:app.origin,callback:app.origin+CALLBACK,client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',client_assertion:assertion},cookies:false});
    if(redeemed.status!==200)return Response.json({error:'redeem_failed'},{status:400});
    app.clientId=(await redeemed.json()).client_id;
    return app.refuseCallback?Response.json({error:'synthetic_callback_refused'},{status:409}):Response.json({linked:true});
   }
   if(request.method==='POST'&&url.pathname===LOGOUT)return new Response(null,{status:204});
   return new Response(null,{status:404});
  },
 };
 return scripted;
}
