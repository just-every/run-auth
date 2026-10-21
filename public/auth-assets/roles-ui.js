(() => {
 const prefix=location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
 const post=async(path,data)=>{
  const response=await fetch(prefix+'/api/auth/roles/'+path,{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(data)})
  const body=await response.json()
  if(!response.ok)throw new Error(body.error==='local_email_step_up_required'?'Confirm your email in Sign-in methods, then try again.':body.error)
  return body
 }
 for(const form of document.querySelectorAll('[data-role-form]')) {
  const apply=form.querySelector('[data-role-apply]'),output=form.querySelector('[data-role-preview]')
  form.addEventListener('input',()=>{apply.hidden=true})
  form.addEventListener('submit',async event=>{
   event.preventDefault();apply.hidden=true
   const fields=new FormData(form),kind=form.dataset.roleForm
   let data={kind}
   if(kind==='role')data.role={name:fields.get('name'),rank:Number(fields.get('rank')),permissions:fields.getAll('permissions')}
   if(kind==='grant')data={kind,personId:fields.get('personId'),roleId:fields.get('roleId'),resources:Object.fromEntries(['view','edit'].map(mode=>[mode,Object.fromEntries(['groups','apps','people','cases'].map(key=>[key,fields.getAll(mode+'.'+key)]))]))}
   if(kind==='revoke')data.grantId=fields.get('grantId')
   try {
    const preview=await post('preview',data),effects=preview.plan.effects || []
    output.textContent=effects.length?effects.map(effect=>`${effect.email}: gains ${effect.gained.length} actions; loses ${effect.lost.length} actions.`).join(' '):'Role definition prepared. No person gains authority until it is delegated.'
    apply.hidden=false
    apply.onclick=async()=>{apply.disabled=true;try{await post('apply',{previewId:preview.previewId});location.reload()}catch(error){output.textContent=error.message;apply.hidden=true;apply.disabled=false}}
   }catch(error){output.textContent=error.message}
  })
 }
})()
