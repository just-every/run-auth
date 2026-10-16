// A SCIM 2.0 service at the network edge (RFC 7643/7644 subset): users and
// groups, filters, pagination, PATCH, bearer auth, and injected failures.
import {createServer} from 'node:http';
import {randomUUID} from 'node:crypto';

export async function scimServer(t,token='scim-secret-token-1') {
 const users=new Map(),groups=new Map(),log=[],faults=[];
 // fail: answer the next requests with an error; lose: do the work, then answer with an error.
 const state={token,users,groups,log,faults,fail:(count,status,retryAfter=null)=>{for(let i=0;i<count;i++)faults.push({status,retryAfter});},lose:(status,method='POST')=>faults.push({status,after:true,method})};
 const send=(res,status,body,headers={})=>{res.writeHead(status,{'content-type':'application/scim+json',...headers});res.end(body===undefined?'':JSON.stringify(body));};
 const list=(items,url)=>{const start=Number(url.searchParams.get('startIndex')||1),count=Number(url.searchParams.get('count')||100),page=items.slice(start-1,start-1+count);return {schemas:['urn:ietf:params:scim:api:messages:2.0:ListResponse'],totalResults:items.length,startIndex:start,itemsPerPage:page.length,Resources:page};};
 const filtered=(items,url)=>{const f=url.searchParams.get('filter');if(!f)return items;const [,attr,value]=f.match(/^(\w+) eq "(.*)"$/)||[];return items.filter(x=>String(x[attr]??'').toLowerCase()===String(value).toLowerCase());};
 const apply=(target,ops)=>{for(const op of ops){const kind=op.op?.toLowerCase();if(kind==='remove'&&op.path)delete target[op.path];if(kind!=='replace')continue;if(op.path)target[op.path]=op.value;else Object.assign(target,op.value);}};
 const server=createServer(async(req,original)=>{
  let res=original;
  let body='';for await(const chunk of req)body+=chunk;
  const url=new URL(req.url,'http://scim'),parts=url.pathname.replace(/^\/scim\/v2/,'').split('/').filter(Boolean),json=body?JSON.parse(body):null;
  log.push({method:req.method,path:url.pathname+url.search,body:json});
  if(req.headers.authorization!==`Bearer ${state.token}`)return send(res,401,{status:'401',detail:'unauthorized'});
  const fault=faults[0]&&(!faults[0].method||faults[0].method===req.method)?faults.shift():null;if(fault&&!fault.after)return send(res,fault.status,{status:String(fault.status)},fault.retryAfter?{'retry-after':String(fault.retryAfter)}:{});
  if(fault?.after){res={writeHead:()=>{},end:()=>send(original,fault.status,{status:String(fault.status)})};}
  if(parts[0]==='ServiceProviderConfig')return send(res,200,{patch:{supported:true},filter:{supported:true,maxResults:200}});
  const store=parts[0]==='Users'?users:parts[0]==='Groups'?groups:null;if(!store)return send(res,404,{status:'404'});
  const id=parts[1];
  if(req.method==='GET'&&!id)return send(res,200,list(filtered([...store.values()],url),url));
  if(req.method==='POST') {
   if(store===users&&[...users.values()].some(u=>u.userName.toLowerCase()===json.userName.toLowerCase()))return send(res,409,{status:'409',scimType:'uniqueness'});
   const item={...json,id:randomUUID()};store.set(item.id,item);return send(res,201,item);
  }
  const item=store.get(id);if(!item)return send(res,404,{status:'404'});
  if(req.method==='GET')return send(res,200,item);
  if(req.method==='PATCH'){apply(item,json.Operations??[]);return send(res,200,item);}
  if(req.method==='PUT'){store.set(id,{...json,id});return send(res,200,store.get(id));}
  if(req.method==='DELETE'){store.delete(id);return send(res,204);}
  send(res,405,{status:'405'});
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));
 t.after(()=>new Promise(done=>server.close(done)));
 state.url=`http://127.0.0.1:${server.address().port}`;
 state.writes=()=>log.filter(l=>l.method!=='GET');
 return state;
}
