// Run outside the model with an explicitly consented employee session. The
// same protocol doors an app uses supply positive and negative live probes.
import * as oidc from 'openid-client';
import {SAML} from '@node-saml/node-saml';
import {inflateRawSync} from 'node:zlib';
import {parseXml,attr,child,textOf,NS} from '../../src/auth/saml/xml.mjs';
import {X509Certificate} from 'node:crypto';

const requireThat=(condition,message)=>{if(!condition)throw new Error(message);};
const field=(html,name)=>html.match(new RegExp(`name="${name}" value="([^"]*)"`))?.[1]?.replaceAll('&quot;','"').replaceAll('&amp;','&');
const pem=body=>`-----BEGIN CERTIFICATE-----\n${body}\n-----END CERTIFICATE-----`;
async function employee(fetcher,origin,cookie,personId) {
 const response=await fetcher(origin+'/api/auth/me',{headers:{cookie},redirect:'manual'});
 requireThat(response.ok,'The test employee must sign in and consent to ending this session.');
 const model=await response.json();requireThat(model.user.id===personId,'This session belongs to a different test employee.');
}
export async function probeOidc({origin,personId,cookie,clientId,clientSecret,authMethod='none',redirectUri,postLogoutRedirectUri,fetcher=fetch}) {
 await employee(fetcher,origin,cookie,personId);
 const config=await oidc.discovery(new URL(origin),clientId,undefined,authMethod==='client_secret_post'?oidc.ClientSecretPost(clientSecret):clientSecret?oidc.ClientSecretBasic(clientSecret):oidc.None(),{[oidc.customFetch]:fetcher,...(origin.startsWith('http://')?{execute:[oidc.allowInsecureRequests]}:{})});
 config[oidc.customFetch]=fetcher;
 const verifier=oidc.randomPKCECodeVerifier(),state=oidc.randomState(),nonce=oidc.randomNonce();
 const url=oidc.buildAuthorizationUrl(config,{redirect_uri:redirectUri,scope:'openid email',state,nonce,code_challenge:await oidc.calculatePKCECodeChallenge(verifier),code_challenge_method:'S256'});
 const authorized=await fetcher(url,{headers:{cookie},redirect:'manual'});
 requireThat(authorized.status===302,'The app did not complete sign-in.');
 const callback=new URL(authorized.headers.get('location'),origin);
 requireThat(callback.origin+callback.pathname===new URL(redirectUri).origin+new URL(redirectUri).pathname,'Sign-in returned to another callback.');
 const tokens=await oidc.authorizationCodeGrant(config,callback,{pkceCodeVerifier:verifier,expectedState:state,expectedNonce:nonce});
 await oidc.fetchUserInfo(config,tokens.access_token,tokens.claims().sub);
 const end=oidc.buildEndSessionUrl(config,{id_token_hint:tokens.id_token,...(postLogoutRedirectUri?{post_logout_redirect_uri:postLogoutRedirectUri}:{}),state:'diagnostic-probe'});
 const ended=await fetcher(end,{headers:{cookie},redirect:'manual'});
 requireThat(ended.ok||ended.status===302,'Logout did not complete.');
 const denied=await fetcher(origin+'/oidc/userinfo',{headers:{authorization:'Bearer '+tokens.access_token},redirect:'manual'});
 const session=await fetcher(origin+'/api/auth/me',{headers:{cookie},redirect:'manual'});
 requireThat(denied.status===401&&session.status===401,'Logout left the tested token or employee session usable.');
 return {signIn:'verified',logout:'verified',testIdentity:personId};
}
export async function probeSaml({origin,personId,cookie,entityId,acsUrl,sloUrl,spPrivateKey,spCertificate,sign='response',fetcher=fetch,now=Date.now}) {
 await employee(fetcher,origin,cookie,personId);
 const metadata=await fetcher(origin+'/saml/metadata',{redirect:'manual'});requireThat(metadata.ok,'Metadata unavailable.');
 const certificates=[...((await metadata.text()).matchAll(/<ds:X509Certificate>([^<]+)<\/ds:X509Certificate>/g))].map(m=>pem(m[1])).filter(cert=>{const x=new X509Certificate(cert);return Date.parse(x.validFrom)<=now()&&Date.parse(x.validTo)>now();});
 requireThat(certificates.length,'No currently valid published signing certificate.');
 const saml=new SAML({entryPoint:origin+'/saml/sso',issuer:entityId,audience:entityId,callbackUrl:acsUrl,logoutUrl:origin+'/saml/slo',logoutCallbackUrl:sloUrl,idpCert:certificates,idpIssuer:origin+'/saml/metadata',privateKey:spPrivateKey,publicCert:spCertificate,signatureAlgorithm:'sha256',digestAlgorithm:'sha256',wantAuthnResponseSigned:sign!=='assertion',wantAssertionsSigned:sign!=='response',identifierFormat:null,validateInResponseTo:'always',disableRequestedAuthnContext:true});
 const start=await saml.getAuthorizeUrlAsync('diagnostic-probe',undefined,{});
 const response=await fetcher(start,{headers:{cookie},redirect:'manual'});requireThat(response.ok,'SAML sign-in failed.');
 const html=await response.text(),encoded=field(html,'SAMLResponse');requireThat(encoded,'No SAML response.');
 const {profile}=await saml.validatePostResponseAsync({SAMLResponse:encoded});requireThat(profile&&!profile.isLogout,'The app refused the signed assertion.');
 const logout=await saml.getLogoutUrlAsync(profile,'diagnostic-probe',{});
 const ended=await fetcher(logout,{headers:{cookie},redirect:'manual'});requireThat(ended.ok||ended.status===302,'SAML logout failed.');
 const requestRoot=parseXml(inflateRawSync(Buffer.from(new URL(logout).searchParams.get('SAMLRequest'),'base64')).toString('utf8'));
 const expected=attr(requestRoot,'ID');let answerRoot;
 if(ended.status===302) {
  const location=new URL(ended.headers.get('location'));
  answerRoot=parseXml(inflateRawSync(Buffer.from(location.searchParams.get('SAMLResponse'),'base64')).toString('utf8'));
  requireThat((await saml.validateRedirectAsync(Object.fromEntries(location.searchParams),location.search.slice(1))).loggedOut,'App logout response refused.');
 } else {
  const answer=field(await ended.text(),'SAMLResponse');requireThat(answer,'No app logout response.');
  // node-saml checks InResponseTo only on Response, so verify the signed
  // LogoutResponse correlation explicitly after its signature is validated.
  saml.options.validateInResponseTo='ifPresent';
  requireThat((await saml.validatePostResponseAsync({SAMLResponse:answer})).loggedOut,'App logout response refused.');
  answerRoot=parseXml(Buffer.from(answer,'base64').toString('utf8'));
 }
 requireThat(answerRoot.local==='LogoutResponse'&&attr(answerRoot,'InResponseTo')===expected&&attr(answerRoot,'Destination')===sloUrl&&textOf(child(answerRoot,'Issuer',NS.saml))===origin+'/saml/metadata'&&attr(child(child(answerRoot,'Status',NS.samlp),'StatusCode',NS.samlp),'Value')==='urn:oasis:names:tc:SAML:2.0:status:Success','Logout response does not match the exact test request.');
 requireThat(await saml.cacheProvider.getAsync(expected),'Logout request was not issued by this probe.');
 await saml.cacheProvider.removeAsync(expected);
 requireThat((await fetcher(origin+'/api/auth/me',{headers:{cookie},redirect:'manual'})).status===401,'Logout left the employee session usable.');
 return {signIn:'verified',logout:'verified',testIdentity:personId};
}
