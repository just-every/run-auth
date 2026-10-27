// Incrementally migrate existing acceptance notes to generated contract rows.
// Only registered clauses are regenerated; historical journey text is retained.
import {readFile,writeFile} from 'node:fs/promises';
import {parseContract} from '../src/base/seed-contract.mjs';
const [mode,...requested]=process.argv.slice(2);
if(!['write','check'].includes(mode))throw new Error('Use write or check, optionally followed by clause IDs');
const source=await readFile('CONTRACT.md','utf8'),contract=parseContract(source),lines=source.split('\n');
let acceptance=await readFile('ACCEPTANCE.md','utf8'),claims;
try{claims=await readFile('docs/CLAIMS.md','utf8');}catch(error){if(error.code!=='ENOENT')throw error;claims='# Auth claim register\n\nGenerated from CONTRACT.md. Historical acceptance journeys remain in ACCEPTANCE.md.\n';}
const ids=[...new Set([...claims.matchAll(/^## (AUTH-[A-Z0-9-]+)$/gm)].map(m=>m[1]).concat(requested))].sort();
if(!ids.length)throw new Error('Register a clause ID for the first generation');
for(const id of ids) {
 const clause=contract.clauses.find(c=>c.id===id);if(!clause)throw new Error('Unknown clause '+id);
 const cells=lines[clause.row-1].split('|').map(cell=>cell.trim()),evidence=cells[5],gap=cells[6];
 const block=`## ${id}\n\nStatus: ${clause.status}\n\nEvidence: ${evidence}\n\nGap: ${gap}\n`;
 const section=new RegExp('^## '+id+'\\n[\\s\\S]*?(?=^## |$(?![\\s\\S]))','m');
 claims=section.test(claims)?claims.replace(section,block+'\n'):claims.trimEnd()+'\n\n'+block;
 const entry=new RegExp('(\\*\\*'+id+' — [^\\n]+\\n\\n)([\\s\\S]*?)(?=\\n\\n\\*\\*AUTH-|\\n\\n### |\\n\\n## |$(?![\\s\\S]))','m');
 if(!entry.test(acceptance))throw new Error('Acceptance entry not found for '+id);
 acceptance=acceptance.replace(entry,(_,journey)=>journey+`Existing evidence and limits: ${evidence}${gap?' — '+gap:''}`);
}
claims=claims.trimEnd()+'\n';
for(const [path,value] of [['ACCEPTANCE.md',acceptance],['docs/CLAIMS.md',claims]]) {
 if(mode==='write')await writeFile(path,value);
 else if(await readFile(path,'utf8')!==value)throw new Error('Stale generated contract document: '+path);
}
console.log(`contract docs ${mode}: ${ids.join(', ')}`);
