import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {createHmac} from 'node:crypto';
export const host='https://automation.example.com';
export const credentials={clientId:'synthetic-auth-1',clientSecret:'synthetic-auth-2',signingKey:'synthetic-auth-3',scope:'synthetic-auth-4'};
export async function service(t,r) {
 const calls=[],state=[],script=[];
 const server=createServer(async(req,res)=>{
  let body='';for await(const chunk of req)body+=chunk;
  calls.push({path:req.url,headers:req.headers,body});
  const control=script.shift();
  if(control?.beforeReply)await control.beforeReply();
  if(control?.redirect){res.writeHead(302,{location:'https://127.0.0.1/private'});res.end();return;}
  if(req.url==='/token') {
   assert.equal(new URLSearchParams(body).get('client_secret'),credentials.clientSecret);
   assert.equal(new URLSearchParams(body).get('grant_type'),'client_credentials');
   res.writeHead(200,{'content-type':'application/json'});res.end(JSON.stringify({access_token:'synthetic-auth-5',token_type:'Bearer'}));return;
  }
  assert.equal(req.headers.authorization,'Bearer synthetic-auth-5');
  const id=req.headers['auth-automation-id'],time=req.headers['auth-automation-timestamp'];
  assert.equal(req.headers['auth-automation-signature'],createHmac('sha256',credentials.signingKey).update(`${id}.${time}.POST.${host}${req.url}.${body}`).digest('base64url'));
  state.push({path:req.url,...JSON.parse(body)});
  res.writeHead(control?.status??200,{'content-type':'application/json'});res.end(control?.body??JSON.stringify(req.url==='/first'?{id:'remote-record-1',ignored:credentials.clientSecret}:{ok:true}));
 });
 await new Promise(done=>server.listen(0,'127.0.0.1',done));t.after(()=>{server.closeAllConnections();return new Promise(done=>server.close(done));});
 r.edges={[host]:`http://127.0.0.1:${server.address().port}`};return {calls,state,script};
}
