(() => {
 const prefix=location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
 const split=value=>String(value || '').trim().split(/\s+/).filter(Boolean)
 for(const form of document.querySelectorAll('[data-resource-form]'))form.addEventListener('submit',async event=>{
  event.preventDefault()
  const data=Object.fromEntries(new FormData(form)),kind=form.dataset.resourceForm,output=form.querySelector('[data-resource-result]')
  try {
   if(kind==='register') {
    data.scopes=split(data.scopes)
    data.roles=[{role:data.role,scopes:data.scopes,resources:[data.resource]}]
    data.resources=[{id:data.resource}]
    delete data.role;delete data.resource
   }
   if(kind==='assign')data.principalType='group'
   if(kind==='service-create') {data.scopes=split(data.scopes);data.resources=split(data.resources);data.jwks=JSON.parse(data.jwks);data.expiresAt=new Date(data.expiresAt).toISOString()}
   const response=await fetch(prefix+'/api/auth/resource-apis/'+kind,{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(data)})
   const body=await response.json()
   if(!response.ok)throw new Error(body.error==='local_email_step_up_required'?'Confirm your email in Sign-in methods, then try again.':body.error)
   location.reload()
  }catch(error){output.textContent=error.message}
 })
})()
