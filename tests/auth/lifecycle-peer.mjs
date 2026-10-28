import {createServer} from 'node:http';
import {decodeJwt} from 'jose';
import {scimServer} from './scim-server.mjs';

// A test-owned peer with separate account and session endpoints.
export async function lifecyclePeer(t,token) {
 const scim=await scimServer(t,token),logout=[];let logoutStatus=200;
 const server=createServer(async(request,response)=>{
  let body='';for await(const chunk of request)body+=chunk;
  if(request.url==='/logout') {
   logout.push(decodeJwt(new URLSearchParams(body).get('logout_token')));
   response.writeHead(logoutStatus);response.end();return;
  }
  const result=await fetch(scim.url+request.url,{method:request.method,headers:request.headers,...(body?{body}:{})});
  response.writeHead(result.status,Object.fromEntries(result.headers));response.end(Buffer.from(await result.arrayBuffer()));
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>new Promise(done=>server.close(done)));
 return {...scim,logout,logoutStatus:status=>{logoutStatus=status;},url:`http://127.0.0.1:${server.address().port}`};
}
