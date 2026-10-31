import assert from 'node:assert/strict';
import {openGuideInstallation} from '../../agent-door/docs-flow.mjs';
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
 const installation=await openGuideInstallation();t.after(()=>installation.close());
 const installedServer=createServer(async(req,res)=>{
  try {
   const response=await installation.request(installation.hosted.origin+req.url);
   const headers=new Headers(response.headers);headers.delete('content-encoding');headers.delete('content-length');
   res.writeHead(response.status,Object.fromEntries(headers));res.end(Buffer.from(await response.arrayBuffer()));
  } catch {res.writeHead(500);res.end();}
 });
 await new Promise(resolve=>installedServer.listen(0,'127.0.0.1',resolve));t.after(()=>{installedServer.closeAllConnections();return new Promise(resolve=>installedServer.close(resolve));});
 const browser=await chromium.launch({headless:true,args:['--use-mock-keychain','--password-store=basic','--no-sandbox'],executablePath:process.env.AUTH_CHROMIUM||undefined});t.after(()=>browser.close());
 const context=await browser.newContext(),page=await context.newPage(),errors=[];page.on('pageerror',error=>errors.push(error.message));
 const directory=process.env.AUTH_SCREENSHOTS||'test-results/auth-journeys';await mkdir(directory,{recursive:true});
 const manifest=JSON.parse(await readFile(join(root,'docs/site.json'),'utf8'));
 const paths=['docs',...manifest.sections.flatMap(section=>section.pages.map(page=>'docs/'+page.slug)),'installed/docs/agents'];
 let keyboardRegions=0;
 for(const path of paths)for(const width of [1440,390])for(const theme of (path.endsWith('/agents')?['light','dark']:['light'])){
  await page.emulateMedia({colorScheme:theme});
  await page.setViewportSize({width,height:1000});
  const installed=path.startsWith('installed/'),host=installed?installedServer:server,route=installed?path.slice('installed/'.length):path;
  const response=await page.goto('http://127.0.0.1:'+host.address().port+'/'+route);assert.equal(response.status(),200,path);
  if(path.endsWith('/agents')){
   const section=page.getByRole('navigation',{name:'On this page'}).getByRole('link',{name:'Tools by job',exact:true});
   await section.focus();await expect(section).toBeFocused();await page.keyboard.press('Enter');
   await expect(page).toHaveURL(/#tools-by-job$/);await expect(page.getByRole('heading',{name:'Tools by job',exact:true})).toBeVisible();
   await page.goto('http://127.0.0.1:'+host.address().port+'/'+route);
  }
  await expect(page.locator('h1').first()).toBeVisible();
  const results=await new AxeBuilder({page}).analyze();assert.deepEqual(results.violations.filter(v=>['serious','critical'].includes(v.impact)).map(v=>({id:v.id,nodes:v.nodes.map(n=>n.target)})),[],`${path} ${width}`);
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),`${path} fits ${width}`);
  for(const block of await page.locator('pre').all())if(await block.evaluate(el=>el.scrollWidth>el.clientWidth)){
   assert.equal(await block.getAttribute('tabindex'),'0','overflowing code is keyboard reachable');
   await block.focus();await block.evaluate(el=>{el.scrollLeft=0;});await page.keyboard.press('ArrowRight');await page.waitForTimeout(200);
   assert.ok(await block.evaluate(el=>el.scrollLeft>0),'arrow keys scroll a focused code example');keyboardRegions++;
  }
  for(const control of await page.locator('button,a').all())if(await control.isVisible()&&!(await control.innerText()).trim())assert.ok(await control.getAttribute('data-tooltip'),'icon-only controls have a tooltip');
  await page.screenshot({path:join(directory,'public-'+path.replaceAll('/','-')+'-'+width+'-'+theme+'.png'),fullPage:true});
 }
 assert.ok(keyboardRegions>0,'the long integration examples exercise real keyboard scrolling');
 assert.deepEqual(errors,[]);
 console.log('Public docs proof: '+paths.length+' pages at 1440 and 390, agent guide in both themes on the run site and production installation; '+keyboardRegions+' keyboard-scrolled code regions');
}
