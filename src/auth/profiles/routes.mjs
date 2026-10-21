// Profile and identity-link doors for the signed-in person. Reads and edits need
// only a live session; linking and unlinking also need this session's fresh email proof.
import {json,fail,session} from '../core.mjs';
import {profileView,updateProfile} from './profile.mjs';
import {beginLink,unlink,linksOf} from './links.mjs';
import {configuredProvider} from '../domain-policy.mjs';

export const PROFILE_READS=['/api/auth/profile'];
export const isProfileAction=path=>['/profile/update','/profile/links/start','/profile/links/unlink'].includes(path);

// The profile, the connected providers and the ones that can still be connected.
export async function profileModel(ctx,s) {
 const links=await linksOf(ctx,s.person_id);
 return {...await profileView(ctx,s),links:links.map(l=>({providerId:l.providerId,label:l.providerId?(configuredProvider(ctx,l.providerId)?.label||l.providerId):l.issuer})),
  providers:(ctx.upstreamProviders||[]).filter(p=>['google','microsoft','okta'].includes(p.preset)).map(p=>({id:p.id,label:p.label||p.preset,linked:links.some(l=>l.providerId===p.id)}))};
}
export async function profileRead(ctx,request) {
 const s=await session(ctx,request);if(!s)fail('sign_in_required',401);
 return json(await profileModel(ctx,s));
}

export async function profileAction(ctx,request,path,data,{upstreams}) {
 if(path==='/profile/update'){const s=await session(ctx,request);if(!s)fail('sign_in_required',401);return updateProfile(ctx,s,{fields:data.fields??Object.fromEntries(Object.entries(data).filter(([key])=>key!=='csrf'))});}
 if(path==='/profile/links/unlink'){await unlink(ctx,request,data);return json({ok:true});}
 // The browser continues at the provider: Auth's own start for it, carried with the intent cookie.
 const intent=await beginLink(ctx,request,data,upstreams);
 const started=await upstreams.fetch(new Request(new URL(`/auth/oidc/${intent.provider.id}/start`,ctx.origin),{method:'POST',headers:{'content-type':'application/json',origin:ctx.origin,'cf-connecting-ip':request.headers.get('cf-connecting-ip')||''},body:JSON.stringify({returnTo:'/app/account'})}));
 if(!started||started.status!==303)fail('upstream_unavailable',502);
 const headers=new Headers({'content-type':'application/json','cache-control':'no-store','referrer-policy':'no-referrer'});
 for(const value of started.headers.getSetCookie())headers.append('set-cookie',value);
 headers.append('set-cookie',intent.header);
 return new Response(JSON.stringify({redirect:started.headers.get('location')}),{status:200,headers});
}
