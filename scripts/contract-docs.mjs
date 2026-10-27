// Preserve the legacy acceptance journeys while generating changed status
// metadata from the contract. Unmarked legacy evidence remains untouched.
import fs from 'node:fs';
const {readFile,writeFile}=fs.promises;
const mode=process.argv[2];
if(!['write','check'].includes(mode))throw new Error('Use write or check followed by clause ids');
const contract=await readFile('CONTRACT.md','utf8'),acceptance=await readFile('ACCEPTANCE.md','utf8');
const rows=[...contract.matchAll(/^\| `?([^`|]+?)`? \| ([^|]+) \| ([^|]+) \| (done|partial|missing) \| (.*?) \| (.*?) \|$/gm)].map(([,id,title,kind,status,evidence,gap])=>({id,title:title.trim(),kind:kind.trim(),status,evidence,gap}));
const selected=new Set([...process.argv.slice(3),...[...acceptance.matchAll(/<!-- contract-status:([^ ]+) -->/g)].map(m=>m[1])]);
let result=acceptance;
for(const id of selected) {
 const row=rows.find(r=>r.id===id);if(!row)throw new Error('Unknown clause '+id);
 const marker=`<!-- contract-status:${id} -->`,end='<!-- /contract-status -->';
 const generated=`${marker}\nExisting evidence and limits: ${row.evidence}${row.gap?' — '+row.gap:''}\n${end}`;
 if(result.includes(marker)) {
  const start=result.indexOf(marker),finish=result.indexOf(end,start);if(finish<0)throw new Error('Unclosed generated metadata '+id);
  result=result.slice(0,start)+generated+result.slice(finish+end.length);
 } else {
  const start=result.indexOf('**'+id+' — '),next=result.indexOf('\n**',start+3),section=result.slice(start,next<0?undefined:next);
  if(start<0||!section.includes('Existing evidence and limits: '))throw new Error('Missing legacy evidence section '+id);
  const old=section.match(/Existing evidence and limits: [^\n]*/)[0];result=result.slice(0,start)+section.replace(old,generated)+result.slice(next<0?result.length:next);
 }
 const heading=new RegExp('(\\*\\*'+id+' — [^\\n]+?\\()(done|partial|missing)(\\)\\.\\*\\*)');
 result=result.replace(heading,(_,before,status,after)=>before+row.status+after);
}
const count=status=>rows.filter(r=>r.status===status).length;
const claims='# Auth implementation claims\n\nGenerated from CONTRACT.md. Acceptance journeys remain in ACCEPTANCE.md.\n\n'+`Done: ${count('done')}; partial: ${count('partial')}; missing: ${count('missing')}; total: ${rows.length}.\n\n`+'| Clause | Title | Status |\n| --- | --- | --- |\n'+rows.map(r=>`| ${r.id} | ${r.title} | ${r.status} |`).join('\n')+'\n';
const summary=contract.replace(/^\| (Published|Target and push further|All) \| \d+ \| \d+ \| \d+ \| \d+ \|$/gm,(_,label)=>{
 const selected=rows.filter(row=>label==='All'||(label==='Published'?row.kind==='published':row.kind!=='published'));
 return '| '+label+' | '+['done','partial','missing'].map(status=>selected.filter(row=>row.status===status).length).join(' | ')+' | '+selected.length+' |';
});
for(const [path,text] of [['CONTRACT.md',summary],['ACCEPTANCE.md',result],['docs/CLAIMS.md',claims]]) {
 if(mode==='write')await writeFile(path,text);
 else if(await readFile(path,'utf8').catch(()=>null)!==text)throw new Error('Stale generated document '+path);
}
console.log('Contract documentation '+mode+': '+rows.length+' clauses; '+selected.size+' updated metadata blocks');
