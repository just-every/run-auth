// Keep the original page in the capture flow: preparation may open controls
// that the journey uses after its screenshots have finished.
export async function captureViews({page,views,errors,prepare=async()=>{},capture,workers=2}) {
 const url=page.url();
 if(workers===1) {
  try {
   for(const [width,theme] of views) {
    await page.setViewportSize({width,height:1000});await page.emulateMedia({colorScheme:theme});await page.goto(url);
    await page.bringToFront();await prepare(page);
    await page.waitForFunction(()=>document.getAnimations().filter(a=>a instanceof CSSTransition).every(a=>a.playState!=='running'));
    await capture(page,width,theme);
   }
  } finally {await page.setViewportSize({width:1440,height:1000});await page.emulateMedia({colorScheme:'light'});}
  return;
 }
 const second=await page.context().newPage();
 second.on('pageerror',error=>errors.push(error.message));
 const worker=async(target,offset)=>{
  for(let index=offset;index<views.length;index+=2) {
   const [width,theme]=views[index];
   await target.setViewportSize({width,height:1000});
   await target.emulateMedia({colorScheme:theme});
   if(index===offset) {
    if(target===page)await target.reload();else await target.goto(url);
   }
   await prepare(target);
   await capture(target,width,theme);
  }
 };
 try {
  // Let both workers finish before closing the extra page, including on error.
  const results=await Promise.allSettled([worker(page,0),worker(second,1)]);
  const failed=results.find(result=>result.status==='rejected');
  if(failed)throw failed.reason;
 } finally {
  await second.close();
  await page.setViewportSize({width:1440,height:1000});
  await page.emulateMedia({colorScheme:'light'});
 }
}
