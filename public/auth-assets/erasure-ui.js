(() => {
 const prefix=location.pathname.match(/^\/org\/[a-f0-9]{32}(?=\/|$)/)?.[0] || ''
 const post=async(action,data)=>{
  const response=await fetch(prefix+'/api/auth/erasure/'+action,{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify(data)})
  const body=await response.json();if(!response.ok)throw new Error(body.error==='local_email_step_up_required'?'Confirm your email in Sign-in methods, then try again.':body.error)
  return body
 }
 const destinations=form=>[...new Set(new FormData(form).getAll('destinations').map(String))]
 const bind=(selector,action,fields)=>{for(const form of document.querySelectorAll(selector))form.addEventListener('submit',async event=>{
  event.preventDefault()
  try{await post(action,fields(Object.fromEntries(new FormData(form)),form));location.reload()}catch(error){form.querySelector('[data-erasure-result]').textContent=error.message}
 })}
 bind('[data-erasure-retry]','retry',(data,form)=>data.retained?{retained:true,receiptId:data.receiptId,workId:data.workId,confirmRetry:data.confirmRetry==='on',...(data.connectionToken?{connection:{token:data.connectionToken}}:{})}:{receiptId:data.receiptId,destinations:destinations(form),confirmRemoteDeletion:true})
 bind('[data-erasure-abandon]','abandon',(data,form)=>data.retained?{retained:true,receiptId:data.receiptId,confirmation:data.confirmation,workIds:new FormData(form).getAll('workIds')}:{receiptId:data.receiptId,confirmation:data.confirmation,destinations:destinations(form)})
 bind('[data-erasure-policy]','policy',()=>({confirm:true,automaticDeletion:false,honorLegalHolds:true}))
 bind('[data-erasure-hold]','hold',data=>({...data,kind:'person'}))
 bind('[data-erasure-release]','hold',data=>({...data,release:true}))
 for(const form of document.querySelectorAll('[data-erasure-preview]')) {
  const output=form.querySelector('[data-erasure-summary]'),confirm=form.querySelector('[data-erasure-confirm]'),commit=form.querySelector('[data-erasure-commit]'),choices=form.querySelector('[data-erasure-destinations]')
  let preview=null
  form.querySelector('[name=target]')?.addEventListener('change',()=>{preview=null;confirm.hidden=true;choices.replaceChildren()})
  form.addEventListener('submit',async event=>{
   event.preventDefault();confirm.hidden=true;preview=null;choices.replaceChildren()
   try {
    const currentTarget=new FormData(form).get('target')
    const received=await post(form.hasAttribute('data-reset-consent')?'reset-preview':'preview',{kind:form.dataset.erasureKind||'person',target:currentTarget})
    if(new FormData(form).get('target')!==currentTarget)return
    preview=received;output.replaceChildren()
    const summary=document.createElement('p');summary.textContent=`Type ${preview.confirmation} to confirm. ${preview.holds.length} active holds. ${preview.remote.length} remote tasks.`;output.append(summary)
    const list=document.createElement('ul')
    for(const store of preview.stores.filter(store=>store.deleted||store.anonymized)){const row=document.createElement('li');row.textContent=`${store.store}: remove ${store.deleted}; anonymize ${store.anonymized}`;list.append(row)}
    output.append(list)
    const partners=new Map()
    for(const task of preview.remote){if(!task.partner){const line=document.createElement('p');line.textContent=`${task.app}: ${task.kind} · ${task.deletionPreauthorized?'employer deletion consent recorded':'no deletion consent'}`;choices.append(line);continue}const group=partners.get(task.partner)||[];group.push(task);partners.set(task.partner,group)}
    for(const [partner,tasks] of partners) {
     const container=document.createElement('div'),description=document.createElement('p')
     description.textContent=`${partner}: ${tasks.map(task=>task.kind).join(', ')}`;container.append(description)
     if(tasks.some(task=>['scim-delete','partner-delete'].includes(task.kind))) {
      const label=document.createElement('label'),checkbox=document.createElement('input');checkbox.type='checkbox';checkbox.name='destinations';checkbox.value=partner
      label.append(checkbox,document.createTextNode(` Authorize data deletion at ${partner}`));container.append(label)
     }
     choices.append(container)
    }
    if(!preview.remote.length){const empty=document.createElement('p');empty.textContent='No downstream data deletion destinations are listed.';choices.append(empty)}
    confirm.hidden=false
   }catch(error){output.textContent=error.message}
  })
  commit.addEventListener('click',async()=>{
   if(!preview)return
   commit.disabled=true
   try{const consent=form.hasAttribute('data-reset-consent'),reset=form.dataset.erasureKind==='organization'&&!consent;await post(consent?'reset-consent':'confirm',{previewId:preview.id,confirmation:new FormData(form).get('confirmation'),...(reset?{organizationId:preview.organizationId}:{destinations:destinations(form),confirmRemoteDeletion:true})});location.reload()}catch(error){output.textContent=error.message;commit.disabled=false}
  })
 }
})()
