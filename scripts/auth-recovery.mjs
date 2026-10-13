import {randomBytes,createHash} from 'node:crypto';
import {mkdir,lstat,writeFile,rename,unlink} from 'node:fs/promises';
import {join,resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';

const wrangler=fileURLToPath(new URL('../node_modules/wrangler/bin/wrangler.js',import.meta.url));
async function localDirectory(root,relative) {
 const path=join(root,relative);await mkdir(path,{recursive:true,mode:0o700});
 const stat=await lstat(path);if(!stat.isDirectory()||stat.isSymbolicLink())throw new Error('Recovery requires a real checkout-local directory.');return path;
}
export async function recovery(argv=[],{root=process.cwd()}={}) {
 if(argv.some(arg=>arg!=='--local')||argv.length>1)throw new Error('Usage: rer recovery [--local]. Recovery installation is local only.');
 root=resolve(root);
 await localDirectory(root,'.rer');const directory=await localDirectory(root,'.rer/local');
 // Inspect the canonical state path before invoking wrangler; never follow a state symlink.
 await localDirectory(root,'.wrangler');await localDirectory(root,'.wrangler/state');
 const token=randomBytes(32).toString('base64url'),digest=createHash('sha256').update(token).digest('base64url'),now=Date.now();
 const sql=`DELETE FROM auth_recovery_tokens WHERE consumed_at IS NULL; INSERT INTO auth_recovery_tokens(token_hash,created_at) VALUES('${digest}',${now});`;
 const output=await new Promise((resolve,reject)=>{
  const child=spawn(process.execPath,[wrangler,'d1','execute','auth','--local','--persist-to','.wrangler/state','--config','wrangler.jsonc','--command',sql],{cwd:root,env:{...process.env,WRANGLER_SEND_METRICS:'false',CI:'true'},stdio:['ignore','pipe','pipe']});
  let logs='';child.stdout.on('data',b=>{logs+=b;});child.stderr.on('data',b=>{logs+=b;});child.once('error',reject);child.once('exit',code=>code===0?resolve(logs):reject(new Error(`Local recovery installation failed (wrangler exit ${code}). Run local setup migrations first. ${logs}`)));
 });
 const destination=join(directory,'recovery-token'),temporary=join(directory,`.recovery-token-${randomBytes(12).toString('hex')}`);
 try {await writeFile(temporary,token+'\n',{mode:0o600,flag:'wx'});await rename(temporary,destination);}finally{await unlink(temporary).catch(error=>{if(error.code!=='ENOENT')throw error;});}
 return {path:destination};
}
export default recovery;
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)) {
 try {await recovery(process.argv.slice(2));console.log('Recovery token installed locally. Stored in .rer/local/recovery-token (owner-only).');}
 catch(error){console.error(error.message);process.exitCode=1;}
}
