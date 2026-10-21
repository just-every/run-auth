import {AuthError,one,hash,json,fail,auditDetail} from '../core.mjs';
import {authenticateAdmin} from './credentials/index.mjs';
import {readAdmin} from './reads.mjs';
import {adminOpenApi} from './openapi.mjs';
import {writeAdmin} from './commands.mjs';
import {epoch,entityTag,precondition,transactionPrincipal} from './concurrency.mjs';

const BASE='/api/auth/admin/v1',RATE=120,WINDOW=60000;
async function body(request) {
 if(request.method==='DELETE'&&!request.headers.get('content-type'))return {};
 if(!(request.headers.get('content-type')||'').startsWith('application/json'))fail('unsupported_content_type',415);
 if(Number(request.headers.get('content-length')||0)>65536)fail('request_too_large',413);
 const text=await request.text();if(text.length>65536)fail('request_too_large',413);
 let data;try{data=JSON.parse(text);}catch{fail('invalid_json');}
 if(!data||typeof data!=='object'||Array.isArray(data))fail('invalid_json');return data;
}
async function quota(ctx,key) {
 return one(ctx,'INSERT INTO auth_limits(bucket,count,expires_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET count=CASE WHEN expires_at<=? THEN 1 ELSE count+1 END, expires_at=CASE WHEN expires_at<=? THEN excluded.expires_at ELSE expires_at END RETURNING count,expires_at','admin-rest:'+key,ctx.now()+WINDOW,ctx.now(),ctx.now());
}
export async function adminApi(ctx,request) {
 const url=new URL(request.url),path=url.pathname.slice(BASE.length);let principal=null,identity=null,response,result='server_error',rate=null;
 try {
  if(!url.pathname.startsWith(BASE+'/')&&url.pathname!==BASE)fail('not_found',404);
  principal=await authenticateAdmin(ctx,request);
  rate=await quota(ctx,principal.id);if(rate.count>RATE)fail('rate_limited',429);
  if(request.method==='GET') {
   const before=await epoch(ctx);
   response=path==='/openapi.json'?json(adminOpenApi(ctx)):await readAdmin(ctx,principal,path,url);
   if(!response)fail('not_found',404);
   await principal.assertAuthority();
   if(before!==await epoch(ctx))fail('resource_changed',409);
   if(path!=='/logs')response.headers.set('etag',entityTag(principal,before));
  } else if(['POST','PUT','PATCH','DELETE'].includes(request.method)) {
   const data=await body(request),version=await precondition(ctx,request,principal,!(request.method==='POST'&&['/groups','/apps','/people'].includes(path)));
   response=await writeAdmin(ctx,transactionPrincipal(ctx,principal,version),path,request.method,data);
   response.headers.set('etag',entityTag(principal,await epoch(ctx)));
  } else fail('method_not_allowed',405);
  result=response.ok?'allowed':`http_${response.status}`;
 } catch(error) {
  result=error instanceof AuthError?error.message:'server_error';identity=error.adminAudit??null;
  response=json({error:result},error instanceof AuthError?error.status:500);
 }
 const actor=principal??identity;
 await auditDetail(ctx,actor?'admin-service:'+actor.id:null,'admin_api_call',actor?.id??null,{serviceApp:actor?.id??null,owner:actor?.ownerId??null,scope:actor?.scopes.join(' ')??'',result,authenticated:Boolean(principal),method:request.method,path});
 if(!rate)rate=await quota(ctx,'untrusted:'+await hash(request.headers.get('cf-connecting-ip')||'unknown'));
 response.headers.set('ratelimit-limit',String(RATE));response.headers.set('ratelimit-remaining',String(Math.max(0,RATE-rate.count)));response.headers.set('ratelimit-reset',String(Math.max(0,Math.ceil((rate.expires_at-ctx.now())/1000))));response.headers.set('ratelimit-policy',`${RATE};w=60`);
 if(response.status===429)response.headers.set('retry-after','60');
 return response;
}
