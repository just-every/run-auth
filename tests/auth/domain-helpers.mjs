import assert from 'node:assert/strict';
import {createServer} from 'node:http';

const edges=new WeakMap();
export async function domainDns(t,r) {
 if(!edges.has(r))edges.set(r,(async()=>{
  const records=new Map();
  const server=createServer((request,response)=>{
   const url=new URL(request.url,'http://127.0.0.1'),name=url.searchParams.get('name')?.replace(/\.$/,'').toLowerCase();
   const value=url.searchParams.get('type')==='TXT'?records.get(name):undefined;
   response.writeHead(200,{'content-type':'application/dns-json'});
   response.end(JSON.stringify({Status:0,Answer:value===undefined?[]:[{name:name+'.',type:16,data:JSON.stringify(value)}]}));
  });
  await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
  t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
  r.dnsEdge='http://127.0.0.1:'+server.address().port;
  return records;
 })());
 return edges.get(r);
}

// Publish only the TXT challenges issued through Auth's public administrator API.
export async function verifyDomains(t,r,cookie,domains) {
 const records=await domainDns(t,r);
 for(const domain of domains) {
  const challenge=await r.call('/api/auth/domains/challenge',{method:'POST',data:{domain},cookie});
  assert.equal(challenge.status,201,await challenge.clone().text());
  const {id,label,value}=await challenge.json();
  records.set(label.toLowerCase(),value);
  const verified=await r.call('/api/auth/domains/verify',{method:'POST',data:{domain,id},cookie});
  assert.equal(verified.status,200,await verified.clone().text());
 }
}
