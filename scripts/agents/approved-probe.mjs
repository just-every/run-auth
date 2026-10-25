import {probeOidc,probeSaml} from './probe.mjs';

// Read only the key's own approved effect. Neither model prose nor caller
// supplied app parameters can redirect verification to a different target.
export async function probeApprovedRepair({origin,proposalId,preparerKey,cookie,clientSecret,spPrivateKey,fetcher=fetch,now=Date.now}) {
 const response=await fetcher(origin+'/api/auth/preparer',{headers:{authorization:'Preparer '+preparerKey},redirect:'manual'});
 if(!response.ok)throw new Error('The accountable preparer key is unavailable.');
 const proposal=(await response.json()).proposals.find(p=>p.id===proposalId);
 if(proposal?.kind!=='repair_signin'||proposal.status!=='done'||!proposal.effect.diagnostic?.repair)throw new Error('An exact approved repair is required before probing.');
 const plan=proposal.effect.diagnostic.probe;
 if(!plan)throw new Error('Use the app owner’s existing protocol consumer for this unsupported probe profile; access remains unverified.');
 const options={...plan,origin,cookie,clientSecret,spPrivateKey,fetcher,now};
 const result=plan.protocol==='oidc'?await probeOidc(options):await probeSaml(options);
 return {...result,proposalId,appId:plan.appId};
}
