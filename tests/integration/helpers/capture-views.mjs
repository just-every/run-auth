// Keep the original page in the capture flow: preparation may open controls
// that the journey uses after its screenshots have finished.
export async function captureViews({page,views,errors,prepare=async()=>{},capture,parallel=true}) {
 const url=page.url(),second=parallel?await page.context().newPage():null;
 second?.on('pageerror',error=>errors.push(error.message));
 const worker=async(target,offset,stride=2)=>{
  for(let index=offset;index<views.length;index+=stride) {
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
  if(parallel) {
   const results=await Promise.allSettled([worker(page,0),worker(second,1)]);
   const failed=results.find(result=>result.status==='rejected');
   if(failed)throw failed.reason;
  } else await worker(page,0,1);
 } finally {
  await second?.close();
  await page.setViewportSize({width:1440,height:1000});
  await page.emulateMedia({colorScheme:'light'});
 }
}
