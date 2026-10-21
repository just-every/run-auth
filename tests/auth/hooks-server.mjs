// Only the paid/network boundary is faked: Auth still runs its built routes,
// resolver, request signing, timeout and output policy.
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
export async function hookServer(t) {
 const received=[],responses=new Map(),privateHosts=new Set(['private.example.com']);
 const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  const url=new URL(req.url,'https://hooks.example.com');
  if(url.pathname==='/dns-query'){
   const name=url.searchParams.get('name'),type=url.searchParams.get('type');
   res.writeHead(200,{'content-type':'application/dns-json'});return res.end(JSON.stringify({Status:0,Answer:type==='AAAA'?[]:[{type:1,name,data:privateHosts.has(name)?'10.0.0.8':'93.184.216.34'}]}));
  }
  const record={path:url.pathname,body,headers:req.headers};received.push(record);
  const configured=responses.get(url.pathname),step=typeof configured==='function'?await configured(JSON.parse(body),record):configured;
  if(step==='hang')return;
  res.writeHead(step?.status??200,{'content-type':'application/json'});
  res.end(JSON.stringify(step?.body??(url.pathname.includes('registration')?{allow:true}:url.pathname.includes('saml')?{attributes:{cost_center:'CC-42'}}:{claims:{cost_center:'CC-42'}})));
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 const origin=`http://127.0.0.1:${server.address().port}`;
 const fetchEdge=async request=>{
  const url=new URL(request.url);
  if(!['hooks.example.com','cloudflare-dns.com'].includes(url.hostname))return fetch(request);
  return fetch(origin+url.pathname+url.search,{method:request.method,headers:request.headers,body:['GET','HEAD'].includes(request.method)?undefined:await request.arrayBuffer(),signal:request.signal,redirect:'manual'});
 };
 return {origin,received,responses,privateHosts,fetch:fetchEdge,edges:{'https://hooks.example.com':origin,'https://cloudflare-dns.com':origin}};
}
export const verifiedHook=(secret,{headers,body})=>headers['webhook-signature']==='v1,'+createHmac('sha256',Buffer.from(secret.slice(6),'base64')).update(`${headers['webhook-id']}.${headers['webhook-timestamp']}.${body}`).digest('base64');
