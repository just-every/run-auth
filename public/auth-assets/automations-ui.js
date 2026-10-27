for(const form of document.querySelectorAll('[data-automation-form]'))form.addEventListener('submit',async event=>{
 event.preventDefault();const button=form.querySelector('button'),result=form.querySelector('[data-automation-result]');button.disabled=true;
 const data=Object.fromEntries(new FormData(form));
 if('path1' in data){data.paths=[data.path1,data.path2];delete data.path1;delete data.path2;}
 if('grant' in data)data.grant=data.grant==='on';
 try {
  const response=await fetch(form.action,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(data)}),answer=await response.json();
  if(!response.ok)throw new Error(answer.error||'Automation could not continue');
  form.querySelectorAll('input[type=password]').forEach(input=>{input.value='';});
  if(form.action.endsWith('/dry-run')){result.textContent='Dry run complete. No outbound calls.';form.nextElementSibling.textContent=JSON.stringify(answer.intended,null,2);}
  else location.reload();
 }catch(error){result.textContent=error.message;result.setAttribute('role','alert');}
 finally{button.disabled=false;}
});
