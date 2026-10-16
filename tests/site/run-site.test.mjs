import {test} from 'node:test';
import assert from 'node:assert/strict';
import {spawnSync} from 'node:child_process';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';

// The run site (run-auth.com) through its public door: `rer build --site` builds the
// homepage, /run and every docs page site.json lists, and the homepage sends
// people to /run and /docs, never to an installed instance's routes.
test('rer build --site writes the homepage, the Run page and every listed docs page',async()=>{
 const root=join(import.meta.dirname,'..','..');
 const built=spawnSync(process.execPath,['scripts/rer.mjs','build','--site','--non-interactive'],{cwd:root,encoding:'utf8'});
 assert.equal(built.status,0,built.stderr+built.stdout);
 const site=join(root,'dist/site'),page=path=>readFile(join(site,path),'utf8');
 const home=await page('index.html');
 assert.match(home,/<a class="run-button" href="\/run">Run Auth/);
 assert.match(home,/href="\/docs"/);
 assert.doesNotMatch(home,/href="\/(signin|setup|app)\b/);
 assert.match(await page('run.html'),/rer dev/);
 const {sections}=JSON.parse(await readFile(join(root,'docs/site.json'),'utf8'));
 const index=await page('docs.html');
 for(const {slug,title} of sections.flatMap(section=>section.pages)){
  assert.ok(index.includes(`href="/docs/${slug}"`),slug);
  assert.ok((await page(`docs/${slug}.html`)).includes(`<h1>${title}</h1>`),slug);
 }
});
