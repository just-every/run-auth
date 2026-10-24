import {readFile,mkdir,writeFile} from 'node:fs/promises';
import {deploymentSpec} from './delivery/base/spec.mjs';
const root=new URL('../',import.meta.url).pathname;
const config=JSON.parse(await readFile(new URL('../packaging.json',import.meta.url),'utf8'));
const text=JSON.stringify(await deploymentSpec(root,config.artifact.specInputs),null,2)+'\n';
const target=new URL('../management/integration/deployment-spec.json',import.meta.url);
if(process.argv.includes('--check')) {
 if(await readFile(target,'utf8')!==text)throw Error('Deployment specification is stale; run pnpm delivery:spec after the real build.');
 console.log('Deployment specification matches the real build and source policy.');
} else {
 await mkdir(new URL('./',target),{recursive:true});await writeFile(target,text);
 console.log('Wrote management/integration/deployment-spec.json');
}
