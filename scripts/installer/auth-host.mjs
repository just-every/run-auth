import {access} from 'node:fs/promises';
import {join} from 'node:path';
import {parse} from '../base-cli/cli/parse.mjs';

// WebAuthn requires a domain RP ID. Choose localhost on a fresh local install;
// an existing issuer belongs to its owner and must never be silently moved.
export async function localHostArguments(argv) {
 let options;try {options=parse(argv,process.cwd(),{deferTail:true});}catch{return argv;}
 if (!['setup','dev','preview'].includes(options.verb) || options.host || options.help || options.stop) return argv;
 try {await access(join(options.cwd,'.dev.vars'));return argv;}catch(error){if(error.code!=='ENOENT')throw error;}
 return [...argv,'--host','localhost'];
}
