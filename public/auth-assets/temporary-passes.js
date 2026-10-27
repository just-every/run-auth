(() => {
 document.addEventListener('submit',async event=>{
  const form=event.target.closest('form[data-temporary-pass-issue]');if(!form)return;
  event.preventDefault();const button=event.submitter,status=document.querySelector('[data-temporary-pass-status]');button.disabled=true;
  try {
   const response=await fetch(form.action,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(Object.fromEntries(new FormData(form)))}),result=await response.json();
   if(!response.ok)throw new Error(result.error||'Temporary pass could not be issued.');
   const field=document.querySelector('[data-temporary-pass-value]');field.value=result.pass;
   document.querySelector('[data-temporary-pass-result]').hidden=false;field.focus();field.select();
   status.textContent='Pass issued. Copy it now; it is not shown again.';
  }catch(error){status.textContent=error.message;button.disabled=false;}
 });
 document.addEventListener('click',event=>{
  const button=event.target.closest('[data-temporary-pass-show]');if(!button)return;
  const field=document.querySelector('[data-temporary-pass-value]');field.type=field.type==='password'?'text':'password';button.textContent=field.type==='password'?'Show pass':'Hide pass';
 });
})();
