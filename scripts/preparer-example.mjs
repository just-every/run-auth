// An agent's side of Auth administration with a preparer key (AGENTS.md,
// "Prepare administration"): read the inventory, file one proposal, then wait
// while a person approves or rejects it in Auth. The key comes from the
// environment and is never printed.
//
//   AUTH_ORIGIN=http://localhost:8787 AUTH_PREPARER_KEY=authprep_... \
//     node scripts/preparer-example.mjs suspend_person person@example.com "Left on 10 October"
const [kind,target,reason,providerId]=process.argv.slice(2);
const origin=process.env.AUTH_ORIGIN,key=process.env.AUTH_PREPARER_KEY,waitSeconds=Number(process.env.AUTH_PREPARER_WAIT_SECONDS||900);
if(!origin||!key||!kind||!target||!reason){console.error('Set AUTH_ORIGIN and AUTH_PREPARER_KEY, then pass KIND TARGET "REASON" [PROVIDER_ID].');process.exit(2);}
const api=async(method,body)=>{
 const response=await fetch(new URL('/api/auth/preparer',origin),{method,headers:{authorization:`Preparer ${key}`,...(body?{'content-type':'application/json'}:{})},body:body&&JSON.stringify(body)});
 const data=await response.json().catch(()=>({}));
 if(!response.ok)throw new Error(`Auth answered ${response.status} ${data.error??''}`.trim());
 return data;
};
const inventory=await api('GET');
const person=inventory.people.find(p=>p.email===target.toLowerCase()||p.id===target);
console.log(JSON.stringify({step:'inventory',people:inventory.people.length,invitations:inventory.invitations.length,target:person?{email:person.email,state:person.state,passkey:person.passkey,lastSignInAt:person.lastSignInAt}:target}));
const filed=await api('POST',{kind,target,reason,...(providerId?{providerId}:{})});
console.log(JSON.stringify({step:'filed',proposal:filed.id,expiresAt:new Date(filed.expiresAt).toISOString(),effect:filed.effect}));
console.log(JSON.stringify({step:'waiting',message:'A person must approve this in Auth (Agents page) with their passkey.'}));
for(const deadline=Date.now()+waitSeconds*1000;Date.now()<deadline;) {
 const proposal=(await api('GET')).proposals.find(p=>p.id===filed.id);
 if(proposal.status!=='pending'){console.log(JSON.stringify({step:'decided',status:proposal.status,outcome:proposal.outcome}));process.exit(proposal.status==='done'?0:1);}
 await new Promise(resolve=>setTimeout(resolve,2000));
}
console.log(JSON.stringify({step:'still_waiting',proposal:filed.id}));process.exit(3);
