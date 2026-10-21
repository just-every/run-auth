(() => {
 const prefix=location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
 const post=async(action,data)=>{
  const response=await fetch(prefix+'/api/auth/erasure/'+action,{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(data)})
  const body=await response.json();if(!response.ok)throw new Error(body.error==='local_email_step_up_required'?'Confirm your email in Sign-in methods, then try again.':body.error)
  return body
 }
 const bind=(selector,action,fields)=>{for(const form of document.querySelectorAll(selector))form.addEventListener('submit',async event=>{event.preventDefault();try{await post(action,fields(Object.fromEntries(new FormData(form))));location.reload()}catch(error){form.querySelector('[data-erasure-result]').textContent=error.message}})}
 bind('[data-erasure-policy]','policy',()=>({confirm:true,automaticDeletion:false,honorLegalHolds:true}))
 bind('[data-erasure-hold]','hold',data=>({...data,kind:'person'}))
 bind('[data-erasure-release]','hold',data=>({...data,release:true}))
 for(const form of document.querySelectorAll('[data-erasure-preview]')) {
  const output=form.querySelector('[data-erasure-summary]'),confirm=form.querySelector('[data-erasure-confirm]'),commit=form.querySelector('[data-erasure-commit]')
  let preview=null
  form.querySelector('[name=target]').addEventListener('change',()=>{preview=null;confirm.hidden=true})
  form.addEventListener('submit',async event=>{
   event.preventDefault();confirm.hidden=true
   try {
    preview=await post('preview',{kind:'person',target:new FormData(form).get('target')})
    output.replaceChildren()
    const summary=document.createElement('p');summary.textContent=`Type ${preview.confirmation} to confirm. ${preview.holds.length} active holds. ${preview.remote.length} remote removal tasks.`;output.append(summary)
    const list=document.createElement('ul')
    for(const store of preview.stores.filter(s=>s.deleted||s.anonymized)){const row=document.createElement('li');row.textContent=`${store.store}: remove ${store.deleted}; anonymize ${store.anonymized}`;list.append(row)}
    output.append(list);confirm.hidden=false
   }catch(error){output.textContent=error.message}
  })
  commit.addEventListener('click',async()=>{
   if(!preview)return
   try{await post('confirm',{previewId:preview.id,confirmation:new FormData(form).get('confirmation'),confirmRemoteDeletion:form.querySelector('[name=confirmRemoteDeletion]').checked});location.reload()}catch(error){output.textContent=error.message}
  })
 }
})()
