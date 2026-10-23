import {createHash, randomBytes, timingSafeEqual} from 'node:crypto';
import ssh2 from 'ssh2';
const {Server,utils}=ssh2;
const {STATUS_CODE:S,OPEN_MODE:O}=utils.sftp;
const fingerprint=data=>'SHA256:'+createHash('sha256').update(data).digest('base64').replace(/=+$/,'');
const MAX=1024*1024;
function configuration(value) {
 if(!Array.isArray(value)||value.length<1||value.length>200)throw new Error('invalid_feed_configuration');
 const feeds=new Map();
 for(const row of value) {
  const issuer=new URL(row.issuer);
  if(issuer.username||issuer.password||issuer.search||issuer.hash||
     issuer.protocol!=='https:'&&!(issuer.protocol==='http:'&&['localhost','127.0.0.1','[::1]'].includes(issuer.hostname))||
     !/^\/(?:org\/[a-f0-9]{32}\/?)?$/.test(issuer.pathname)||!/^[A-Za-z0-9_-]{43}$/.test(row.feedId??'')||
     !/^[A-Za-z0-9_-]{43}$/.test(row.ingressToken??''))throw new Error('invalid_feed_configuration');
  const key=utils.parseKey(row.publicKey);if(key instanceof Error||!key.getPublicSSH)throw new Error('invalid_feed_public_key');
  const actual=fingerprint(key.getPublicSSH());
  if(actual!==row.fingerprint||feeds.has(row.feedId))throw new Error('invalid_feed_binding');
  feeds.set(row.feedId,{...row,issuer:issuer.href.replace(/\/$/,''),public:key.getPublicSSH()});
 }
 return feeds;
}
/** Auth-hosted SSH listener with no shell, filesystem, downloads or key lookup. */
export function createSftpIngress({hostKey,feeds:settings,fetch:send=globalThis.fetch}) {
 const feeds=configuration(settings),clients=new Set();let transfers=0;
 const server=new Server({hostKeys:[hostKey],readyTimeout:15000},client=>{
  clients.add(client);client.on('close',()=>clients.delete(client));client.on('error',()=>{});
  let authenticated=null;
  client.on('authentication',ctx=>{
   const feed=feeds.get(ctx.username);
   if(ctx.method!=='publickey'||!feed||ctx.key.data.length!==feed.public.length||!timingSafeEqual(ctx.key.data,feed.public))return ctx.reject(['publickey']);
   const parsed=utils.parseKey(ctx.key.data);
   if(parsed instanceof Error||ctx.signature&&parsed.verify(ctx.blob,ctx.signature,ctx.hashAlgo)!==true)return ctx.reject(['publickey']);
   authenticated=feed;ctx.accept();
  });
  client.on('ready',()=>client.on('session',accept=>{
   if(!authenticated)return client.end();
   const session=accept();
   session.on('shell',(_accept,reject)=>reject());session.on('exec',(_accept,reject)=>reject());
   session.on('sftp',acceptSftp=>{
    const stream=acceptSftp(),handles=new Map();
    const idle=setTimeout(()=>client.end(),60000);idle.unref();
    const remove=key=>{if(handles.delete(key))transfers--;};
    const close=()=>{clearTimeout(idle);for(const key of handles.keys())remove(key);};
    stream.on('close',close);stream.on('end',close);stream.on('error',()=>{});
    stream.on('REALPATH',(id,path)=>path==='.'||path==='/'?stream.name(id,[{filename:'/',longname:'/',attrs:{}}]):stream.status(id,S.PERMISSION_DENIED));
    stream.on('OPEN',(id,path,flags)=>{
     if(!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.csv$/.test(path)||path.includes('..')||
        flags!==(O.WRITE|O.CREAT|O.TRUNC)||handles.size>=2||transfers>=20)return stream.status(id,S.PERMISSION_DENIED);
     const handle=randomBytes(16),key=handle.toString('hex');handles.set(key,{name:path,chunks:[],size:0,failed:false});transfers++;stream.handle(id,handle);
    });
    stream.on('WRITE',(id,handle,offset,data)=>{
     const file=handles.get(handle.toString('hex'));
     if(!file||file.failed||offset!==file.size||file.size+data.length>MAX){if(file)file.failed=true;return stream.status(id,S.FAILURE);}
     file.chunks.push(Buffer.from(data));file.size+=data.length;stream.status(id,S.OK);
    });
    stream.on('CLOSE',async(id,handle)=>{
     const key=handle.toString('hex'),file=handles.get(key);if(!file)return stream.status(id,S.FAILURE);
     if(file.closing)return stream.status(id,S.FAILURE);file.closing=true;
     if(file.failed){remove(key);return stream.status(id,S.FAILURE);}
     try {
      const text=new TextDecoder('utf-8',{fatal:true}).decode(Buffer.concat(file.chunks));file.chunks=[];
      const response=await send(authenticated.issuer+'/api/auth/hr-feeds/ingest',{method:'POST',redirect:'error',signal:AbortSignal.timeout(15000),
       headers:{origin:new URL(authenticated.issuer).origin,'content-type':'application/json',authorization:'AuthFeed '+authenticated.ingressToken,
        'x-auth-sftp-fingerprint':authenticated.fingerprint},body:JSON.stringify({feedId:authenticated.feedId,fileName:file.name,text})});
      await response.body?.cancel();stream.status(id,response.status===202?S.OK:S.FAILURE);
     }catch{if(!stream.destroyed)stream.status(id,S.FAILURE);}
     finally{remove(key);}
    });
    for(const event of ['READ','OPENDIR','READDIR','REMOVE','RENAME','MKDIR','RMDIR','SETSTAT','FSETSTAT','SYMLINK','READLINK'])stream.on(event,id=>stream.status(id,S.PERMISSION_DENIED));
    for(const event of ['STAT','LSTAT','FSTAT'])stream.on(event,id=>stream.status(id,S.NO_SUCH_FILE));
   });
  }));
 });
 return {async listen({host='127.0.0.1',port=2222}={}) {await new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,resolve);});return server.address();},
  async close(){for(const client of clients)client.end();await new Promise(resolve=>server.close(resolve));}};
}
export {fingerprint};
