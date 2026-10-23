import {SignJWT} from 'jose';

const digest=async value=>{
 const bytes=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value));
 return btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+','-').replaceAll('/','_').replace(/=+$/,'');
};

/** Call before each effect. expected comes from the resource's own route/tool,
 * person and request parser, never from the agent's task envelope alone.
 * No JWT-only, cached-success, fail-open or retry path is supported.
 */
export function createResourceAuthorizer({issuer,resourceId,clientId,audience,privateKey,kid,alg='ES256',fetch:send=fetch}) {
 const origin=new URL(issuer);
 if(origin.protocol!=='https:'&&!(origin.protocol==='http:'&&['localhost','127.0.0.1'].includes(origin.hostname)))throw new Error('invalid_auth_issuer');
 if(!['ES256','RS256'].includes(alg)||!resourceId||clientId!=='delegated-resource:'+resourceId||new URL(audience).protocol!=='https:')throw new Error('invalid_resource_configuration');
 const endpoint=issuer.replace(/\/$/,'')+'/api/auth/delegations/resources/redeem';
 return async function authorize(request,{grantId,effectDigest,task,expected}) {
  if(request.method!=='POST'||!expected||!['personId','resource','operation','arguments'].every(key=>Object.hasOwn(expected,key)))throw new Error('actual_operation_required');
  // Compare the concrete operation at Auth against the approved exact effect.
  // Identity and operation supplied by the route always replace agent metadata.
  const effect={...task,resourceId,apiId:resourceId,audience,personId:expected.personId,accountablePersonId:expected.personId,resource:expected.resource,operation:expected.operation,arguments:expected.arguments};
  const authorization=request.headers.get('authorization')??'',proof=request.headers.get('dpop')??'';
  if(!/^DPoP [A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/i.test(authorization))return {ok:false,response:Response.json({error:'invalid_token'},{status:401})};
  const assertion=await new SignJWT({delegation_use:'redeem',grant_id:grantId,effect_digest:effectDigest,token_hash:await digest(authorization.slice(5)),proof_hash:await digest(proof)})
   .setProtectedHeader({alg,kid}).setIssuer(clientId).setSubject(clientId).setAudience(endpoint).setIssuedAt().setExpirationTime('2m').setJti(crypto.randomUUID()).sign(privateKey);
  const response=await send(endpoint,{method:'POST',headers:{'content-type':'application/json',authorization,DPoP:proof},body:JSON.stringify({resourceId,resourceAssertion:assertion,grantId,effectDigest,task:effect}),redirect:'error'});
  if(!response.ok)return {ok:false,response};
  const receipt=await response.json();
  if(receipt.authorized!==true||receipt.personId!==expected.personId||receipt.task?.operation!==expected.operation||receipt.task?.resource!==expected.resource||receipt.task?.audience!==audience||receipt.grantId!==grantId||!receipt.executionId)throw new Error('invalid_auth_receipt');
  return {ok:true,authorization:receipt};
 };
}
