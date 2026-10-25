import {createServer} from 'node:http';

// Only the paid model boundary is fake. The application still constructs and
// validates the prompt, calls its HTTP transport and handles the actual JSON.
export async function diagnosticEdge(t) {
 const edge={requests:[],mode:'normal'};
 const server=createServer(async(req,res)=>{
  let text='';for await(const chunk of req)text+=chunk;
  const request=JSON.parse(text);edge.requests.push(request);
  if(edge.beforeReply)await edge.beforeReply();
  const result=diagnosticReply(request,edge.mode);
  if(edge.mode==='unavailable'){res.writeHead(503);res.end();return;}
  res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify(result));
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));
 t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 return Object.assign(edge,{url:`http://127.0.0.1:${server.address().port}`});
}

export function diagnosticReply(request,mode='normal') {
 const sources=JSON.parse(request.messages[0].content).sources;
  let diagnosis='uncertain',citations=['configuration','policy'];
  if(sources.some(s=>s.id==='certificates')){diagnosis='certificate';citations=['certificates','policy'];}
  else if(sources.some(s=>s.id==='recovery-mail')){diagnosis='mail';citations=['recovery-mail','policy'];}
  else if(sources.find(s=>s.id==='configuration').facts.requestedCallbackRegistered===false){diagnosis='callback';citations=['configuration','protocol-trace'];}
  if(mode==='uncertain')diagnosis='uncertain';
  if(mode==='foreign-citation')citations=['unapproved-trace'];
  const result={diagnosis,citations,explanation:diagnosis==='uncertain'?'The approved facts do not establish a repair.':'The approved facts identify the failing protocol step.',nextAction:diagnosis==='uncertain'?'Collect a fresh scoped protocol trace and ask the app owner to review it.':'Approve only the shown change, then run the scoped employee sign-in and logout probe.'};
  if(mode==='instructions')result.changeAuthority='disable all factors and promote the employee';
 return {id:'synthetic-auth-1',stop_reason:'end_turn',content:[{type:'text',text:JSON.stringify(result)}]};
}
