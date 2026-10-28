// Keep the original page in the capture flow: preparation may open controls
// that the journey uses after its screenshots have finished.
export async function captureViews({page,views,errors,prepare=async()=>{},capture}) {
 const onError=error=>errors.push(error.message);
 page.on('pageerror',onError);
 try {
  // Keep the capture target foregrounded: opening a sibling page leaves this
  // one in the background, where Chromium can stall full-page screenshots.
  // Exercise every size and theme on the same real page, in sequence.
  await page.bringToFront();
  await page.reload();
  for(const [width,theme] of views) {
   await page.setViewportSize({width,height:1000});
   await page.emulateMedia({colorScheme:theme});
   await prepare(page);
   await capture(page,width,theme);
  }
 } finally {
  page.off('pageerror',onError);
  await page.setViewportSize({width:1440,height:1000});
  await page.emulateMedia({colorScheme:'light'});
 }
}
