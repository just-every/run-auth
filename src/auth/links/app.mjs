// Pulling an app: Auth reads only what the app itself serves at its exact
// origin (its dependency document and link JWKS), never a URL from a request.
import {readJson} from '../../modules/operator-auth/identity/oidc/network.mjs';
import {CALLBACK,PATHS,INTERFACE} from '../../modules/dependencies/protocol.mjs';
import {fail,one,validateClientOrigin} from '../core.mjs';

export {INTERFACE,CALLBACK};
export const NETWORK={timeoutMs:5000};
export const callbacksFor=origin=>[origin+CALLBACK,...PATHS.map(path=>origin+path)].sort();
export const fetcherOf=ctx=>ctx.linkFetch||globalThis.fetch;
export const punycode=origin=>new URL(origin).hostname.split('.').some(part=>part.toLowerCase().startsWith('xn--'));
const VERSION=/^[a-z][a-z0-9-]*@[1-9][0-9]*(?:\.(?:0|[1-9][0-9]*)){0,2}$/;

function sameOrigin(origin,value) {
 let url;try{url=new URL(value);}catch{fail('app_document_invalid',502);}
 if(url.origin!==origin||url.search||url.hash||url.username||url.password)fail('app_document_invalid',502);
 return url.href;
}
// The one public ES256 key an app links with; private members are refused.
export function linkKey(jwks) {
 const keys=Array.isArray(jwks?.keys)?jwks.keys:[];
 if(keys.length!==1)fail('app_keys_invalid',502);
 const k=keys[0];
 if(k.kty!=='EC'||k.crv!=='P-256'||typeof k.x!=='string'||typeof k.y!=='string'||'d' in k||(k.alg&&k.alg!=='ES256')||typeof k.kid!=='string'||!k.kid||k.kid.length>200)fail('app_keys_invalid',502);
 return {kty:'EC',crv:'P-256',x:k.x,y:k.y,kid:k.kid,alg:'ES256',use:'sig'};
}
export const sameKey=(a,b)=>a.x===b.x&&a.y===b.y&&a.crv===b.crv;
export const storedKey=client=>JSON.parse(client.jwks).keys[0];

export async function pullApp(ctx,value) {
 const origin=validateClientOrigin(ctx,value),fetcher=fetcherOf(ctx);
 let doc;try{doc=await readJson(fetcher,origin+'/.well-known/rer-dependencies',NETWORK);}catch{fail('app_document_unavailable',502);}
 if(doc.origin!==origin||doc.version!==1||typeof doc.sector_id!=='string'||!/^[A-Za-z0-9._:-]{8,200}$/.test(doc.sector_id)||doc.callback!==origin+CALLBACK)fail('app_document_invalid',502);
 const dependency=Array.isArray(doc.dependencies)?doc.dependencies.find(d=>d?.interface===INTERFACE):null;
 if(!dependency||!Array.isArray(dependency.paths))fail('app_does_not_use_auth',409);
 const callbacks=[doc.callback,...dependency.paths.map(path=>sameOrigin(origin,path))].sort();
 if(JSON.stringify(callbacks)!==JSON.stringify(callbacksFor(origin)))fail('app_callbacks_unsupported',409);
 let jwks;try{jwks=await readJson(fetcher,sameOrigin(origin,dependency.jwks_uri),NETWORK);}catch{fail('app_keys_unavailable',502);}
 const reported=typeof doc.interface_version==='string'&&VERSION.test(doc.interface_version)?doc.interface_version:`${INTERFACE}`;
 return {origin,interface:INTERFACE,name:String(doc.name||new URL(origin).host).replace(/\s+/g,' ').trim().slice(0,120),sector:doc.sector_id,callbacks,key:linkKey(jwks),version:reported,provider:typeof dependency.provider==='string'?dependency.provider:null};
}
export async function firstSeen(ctx,origin) {return !await one(ctx,'SELECT 1 FROM auth_origins_seen WHERE origin=?',origin);}

// JSON bodies from apps and RER, server to server: no browser Origin applies.
export async function readBody(request) {
 if(!(request.headers.get('content-type')||'').startsWith('application/json'))fail('invalid_request');
 const text=await request.text();if(text.length>16384)fail('invalid_request');
 try{const value=JSON.parse(text);if(value&&typeof value==='object'&&!Array.isArray(value))return value;}catch{}
 fail('invalid_request');
}
