import {readFile,stat} from 'node:fs/promises';
import {createSftpIngress} from './server.mjs';
async function privateFile(path) {
 const info=await stat(path);if(!info.isFile()||(info.mode&0o777)!==0o600||info.uid!==process.getuid())throw new Error('private_configuration_required');
 return readFile(path,'utf8');
}
try {
 const feeds=JSON.parse(await privateFile(process.env.AUTH_SFTP_FEEDS_FILE));
 const hostKey=await privateFile(process.env.AUTH_SFTP_HOST_KEY_FILE);
 const port=Number(process.env.AUTH_SFTP_PORT??2222);if(!Number.isInteger(port)||port<1||port>65535)throw new Error('invalid_port');
 const service=createSftpIngress({hostKey,feeds});
 await service.listen({host:process.env.AUTH_SFTP_BIND??'127.0.0.1',port});
 let stopping=false;const stop=async()=>{if(stopping)return;stopping=true;await service.close();};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 console.log('Auth SFTP ingress ready');
}catch{console.error('Auth SFTP ingress failed; check private configuration and listener availability');process.exitCode=1;}
