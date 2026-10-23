import assert from 'node:assert/strict';
import {createServer} from 'node:http';
import {readFile,mkdir} from 'node:fs/promises';
import {join,resolve,extname} from 'node:path';
import {fileURLToPath} from 'node:url';
import {chromium,expect} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
const root=fileURLToPath(new URL('../../../',import.meta.url));
export async function docsJourney(t) {
 const site=join(root,'dist/site'),server=createServer(async(req,res)=>{
  const path=new URL(req.url,'http://localhost').pathname;
  const relative=path==='/docs'?'docs.html':/^\/docs\/[^/]+$/.test(path)?path.slice(1)+'.html':path.slice(1);
  const file=resolve(site,relative);if(!file.startsWith(site+'/')){res.writeHead(404);return res.end();}
  try{const body=await readFile(file);res.writeHead(200,{'content-type':({'.html':'text/html','.css':'text/css','.js':'text/javascript','.svg':'image/svg+xml','.webp':'image/webp','.woff2':'font/woff2'})[extname(file)]??'application/octet-stream'});res.end(body);}catch{res.writeHead(404);res.end();}
 });
 await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>{server.closeAllConnections();return new Promise(resolve=>server.close(resolve));});
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext(),page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const manifest=JSON.parse(await readFile(join(root,'docs/site.json'),'utf8'));
 const paths=['docs',...manifest.sections.flatMap(section=>section.pages.map(page=>'docs/'+page.slug))];
 let keyboardRegions=0;
 for(const path of paths)for(const width of [1440,390]){
  await page.setViewportSize({width,height:1000});
  const response=await page.goto('http://127.0.0.1:'+server.address().port+'/'+path);assert.equal(response.status(),200,path);
  await expect(page.locator('h1').first()).toBeVisible();
  const results=await new AxeBuilder({page}).analyze();assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],`${path} ${width}`);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${path} fits ${width}`);
  for(const block of await page.locator('pre').all())if(await block.evaluate(el=>el.scrollWidth>el.clientWidth)){
   assert.equal(await block.getAttribute('tabindex'),'0','overflowing code is keyboard reachable');
   await block.focus();await block.evaluate(el=>{el.scrollLeft=0;});await page.keyboard.press('ArrowRight');await page.waitForTimeout(200);
   assert.ok(await block.evaluate(el=>el.scrollLeft>0),'arrow keys scroll a focused code example');keyboardRegions++;
  }
  for(const control of await page.locator('button,a').all())if(await control.isVisible()&&!(await control.innerText()).trim())assert.ok(await control.getAttribute('data-tooltip'),'icon-only controls have a tooltip');
  await page.screenshot({path:join(directory,'public-'+path.replaceAll('/','-')+'-'+width+'.png'),fullPage:true});
 }
 assert.ok(keyboardRegions>0,'the long integration examples exercise real keyboard scrolling');
 assert.deepEqual(errors,[]);
 console.log('Public docs proof: '+paths.length+' pages at 1440 and 390; '+keyboardRegions+' keyboard-scrolled code regions');
}
