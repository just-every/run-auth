// Auth's SAML identity provider doors: metadata, single sign-on, IdP-initiated
// launch and single logout. Failures before Auth trusts an app's consumer
// address answer with a local page, never a redirect.
import {AuthError} from '../core.mjs';
import {el,canonical} from './xml.mjs';
import {publishedKeys,ensureSamlKey} from './signing.mjs';
import {BINDINGS,samlPage} from './bindings.mjs';
import {FORMATS} from './apps.mjs';
import {idpEntity} from './assertion.mjs';
import {sso,resume,launch,SSO_PATH,RESUME_PATH} from './sso.mjs';
import {slo,logout,SLO_PATH,LOGOUT_PATH} from './slo.mjs';

export const METADATA_PATH='/saml/metadata';
export const isSamlPath=path=>path.startsWith('/saml/');

async function metadata(ctx) {
 await ensureSamlKey(ctx);
 const keys=await publishedKeys(ctx),endpoints=(name,path)=>Object.values(BINDINGS).map(binding=>el(`md:${name}`,{Binding:binding,Location:(ctx.issuer??ctx.origin)+path}));
 const xml=canonical(el('md:EntityDescriptor',{entityID:idpEntity(ctx)},[el('md:IDPSSODescriptor',{WantAuthnRequestsSigned:'false',protocolSupportEnumeration:'urn:oasis:names:tc:SAML:2.0:protocol'},[
  ...keys.map(k=>el('md:KeyDescriptor',{use:'signing'},[el('ds:KeyInfo',{},[el('ds:X509Data',{},[el('ds:X509Certificate',{},[k.certificate])])])])),
  ...endpoints('SingleLogoutService',SLO_PATH),
  ...Object.values(FORMATS).map(f=>el('md:NameIDFormat',{},[f])),
  ...endpoints('SingleSignOnService',SSO_PATH),
 ])]));
 return new Response('<?xml version="1.0" encoding="UTF-8"?>'+xml,{headers:{'content-type':'application/samlmetadata+xml; charset=utf-8','cache-control':'public, max-age=300'}});
}

export async function samlRoute(ctx,request,path) {
 try {
  if(path===METADATA_PATH&&request.method==='GET')return await metadata(ctx);
  if(path===SSO_PATH&&['GET','POST'].includes(request.method))return await sso(ctx,request);
  if(path===RESUME_PATH&&request.method==='GET')return await resume(ctx,request);
  if(path.startsWith('/saml/launch/')&&request.method==='GET')return await launch(ctx,request,decodeURIComponent(path.slice('/saml/launch/'.length)));
  if(path===SLO_PATH&&['GET','POST'].includes(request.method))return await slo(ctx,request);
  if(path===LOGOUT_PATH&&['GET','POST'].includes(request.method))return await logout(ctx,request);
  return samlPage('Not found','There is nothing at this address.',404);
 } catch(error) {
  if(!(error instanceof AuthError))throw error;
  return samlPage('Sign-in could not continue',`The app's SAML message was refused (${error.message}). Check the app's SAML settings in Auth.`,error.status>=500?error.status:400);
 }
}
