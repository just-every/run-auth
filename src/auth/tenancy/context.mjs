import {AuthError,fail,json} from '../core.mjs';
import {organizationDatabase} from './storage.mjs';

export const organizationPath=id=>id==='root'?'':`/org/${id}`;
export function organizationRequest(request) {
 const url=new URL(request.url),match=/^\/org\/([a-f0-9]{32})(?=\/|$)/.exec(url.pathname);
 if(!match)return {request,id:'root',basePath:''};
 url.pathname=url.pathname.slice(match[0].length)||'/';
 return {request:new Request(url,request),id:match[1],basePath:match[0]};
}
export async function organizationContext(ctx,id='root') {
 if(id==='root')return {...ctx,organizationId:'root',basePath:'',issuer:ctx.origin,rootDb:ctx.db,mail:ctx.mail?(message=>ctx.mail(message,{db:ctx.db,organizationId:'root'})):undefined};
 const selected=await organizationDatabase(ctx.db,id);
 if(!selected)fail('organization_unavailable',404);
 // Provider registrations and Managed trust are installation-owner custody;
 // a new employer starts with neither, and cannot borrow the root's authority.
 return {...ctx,db:selected.db,rootDb:ctx.db,organization:selected.organization,organizationId:id,basePath:organizationPath(id),issuer:ctx.origin+organizationPath(id),upstreamProviders:undefined,rerTrustKeys:undefined,mail:ctx.mail?(message=>ctx.mail(message,{db:selected.db,organizationId:id})):undefined};
}
export function publicPath(ctx,path) {
 if(!ctx.basePath||!path?.startsWith('/')||path.startsWith('//')||path.startsWith('/org/'))return path;
 return ctx.basePath+path;
}
export async function organizationResponse(ctx,response) {
 if(!response||!ctx.basePath)return response;
 const headers=new Headers(response.headers),location=headers.get('location');
 if(location)headers.set('location',publicPath(ctx,location));
 let body=response.body;
 if(headers.get('content-type')?.includes('text/html')) {
  body=(await response.text()).replace(/\b(href|action)="(\/(?:app|signin|setup|auth\/|api\/|oidc\/|saml\/|__dev\/)[^"]*)"/g,(_,attribute,path)=>`${attribute}="${publicPath(ctx,path)}"`);
 }
 return new Response(body,{status:response.status,statusText:response.statusText,headers});
}
export async function organizationError(work) {
 try{return await work();}catch(error){if(!(error instanceof AuthError))throw error;return json({error:error.message},error.status);}
}
