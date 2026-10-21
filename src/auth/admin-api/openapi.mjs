import {SCOPES} from './credentials/config.mjs';

const ref=name=>({$ref:'#/components/schemas/'+name});
const string={type:'string'},boolean={type:'boolean'};
const object=(properties,required=[])=>({type:'object',properties,required,additionalProperties:false});
const array=items=>({type:'array',items});
const nullable=schema=>({anyOf:[schema,{type:'null'}]});
const fieldSet={type:'object',description:'Effective directory attribute keys (standard keys and x.<custom-name>); null clears this source.',additionalProperties:nullable(string)};
const source={type:'string',enum:['manual','hr','directory'],default:'manual'};
const exclusions='No scope can change administrator roles or resource sets, factors, recovery, signing keys, emergency accounts, admin service apps or the credential’s own policy. Owner and administrator people are readable through the safe person projection, but cannot be mutated. Credential state and material are excluded from reads and logs.';
const rateHeaders={
 'RateLimit-Limit':{description:'Requests permitted in the current window.',schema:{type:'integer'}},
 'RateLimit-Remaining':{description:'Requests remaining in the current window (REST responses).',schema:{type:'integer'}},
 'RateLimit-Reset':{description:'Seconds until the rate window resets.',schema:{type:'integer'}},
 'RateLimit-Policy':{description:'Rate policy, in requests;w=seconds form.',schema:string},
};
const responses={
 '400':{description:'Invalid input or pagination.',content:{'application/json':{schema:ref('Error')}}},
 '401':{description:'Missing, invalid, expired or revoked machine token.',content:{'application/json':{schema:ref('Error')}}},
 '403':{description:'Required scope, live authority or resource permission is missing; excluded operation.',content:{'application/json':{schema:ref('Error')}}},
 '404':{description:'Resource not found, outside the permitted read resource set, or route unknown.',content:{'application/json':{schema:ref('Error')}}},
 '409':{description:'Current directory state or native app validation prevents the operation.',content:{'application/json':{schema:ref('Error')}}},
 '405':{description:'Unsupported HTTP method.',content:{'application/json':{schema:ref('Error')}}},
 '412':{description:'If-Match does not match the current strong ETag.',content:{'application/json':{schema:ref('Error')}}},
 '413':{description:'Request body exceeds the size limit.',content:{'application/json':{schema:ref('Error')}}},
 '415':{description:'Mutation requires an application/json body.',content:{'application/json':{schema:ref('Error')}}},
 '428':{description:'Existing-resource mutation requires If-Match.',content:{'application/json':{schema:ref('Error')}}},
 '429':{description:'Rate limit exceeded.',headers:{...rateHeaders,'Retry-After':{schema:{type:'integer'},description:'Seconds before another attempt.'}},content:{'application/json':{schema:ref('Error')}}},
};
const queryParameters=[
 {in:'query',name:'limit',schema:{type:'integer',minimum:1,maximum:100,default:25}},
 {in:'query',name:'offset',schema:{type:'integer',minimum:0,default:0}},
];
const pathParameters=path=>[...path.matchAll(/\{([^}]+)\}/g)].map(([,name])=>({in:'path',name,required:true,schema:name==='principalType'?{type:'string',enum:['person','group']}:string}));
const result=(schema,description='Success')=>({description,headers:{...rateHeaders,ETag:{description:'Strong revision tag; use it verbatim in If-Match on a subsequent existing-resource mutation.',schema:string}},content:{'application/json':{schema}}});
const paged=name=>object({items:array(ref(name)),total:{type:'integer',minimum:0},nextOffset:nullable({type:'integer',minimum:0})},['items','total','nextOffset']);

export function adminOpenApi(ctx) {
 const paths={};
 const add=(path,method,scope,summary,{schema=ref('Result'),body,list=false,existing=false,created=false,description=''}={})=>{
  const parameters=[...pathParameters(path),...(list?queryParameters:[]),...(existing?[{in:'header',name:'If-Match',required:true,description:'Exact current strong ETag, including quotes. Weak tags and * are refused.',schema:string}]:[])];
  const operation={summary,description:description||exclusions,operationId:method+path.replace(/[{}]/g,'').replace(/\W+/g,'_'),security:[{adminBearer:[]}],parameters,'x-required-scopes':method==='get'&&scope&&!['domains.read','logs.read'].includes(scope)?[scope,scope.replace('.read','.manage')]:[scope],responses:{...responses,[created?'201':'200']:result(schema,created?'Created':'Success')}};
  if(body)operation.requestBody={required:true,content:{'application/json':{schema:body}}};
  (paths[path]??={})[method]=operation;
 };
 add('/openapi.json','get',null,'Read this OpenAPI description',{schema:{type:'object'},description:'Requires a live machine token; no additional read scope.'});
 paths['/openapi.json'].get['x-required-scopes']=[];
 for(const [path,name,scope] of [['/people','Person','people'],['/groups','Group','groups'],['/apps','App','apps'],['/assignments','Assignment','assignments'],['/policies','Policy','policies'],['/idps','Provider','idps'],['/domains','Domain','domains'],['/logs','Log','logs']])add(path,'get',scope+'.read','List '+scope,{schema:paged(name),list:true});
 delete paths['/logs'].get.responses['200'].headers.ETag;
 for(const [path,name,scope] of [['/people/{id}','Person','people'],['/groups/{id}','Group','groups'],['/apps/{id}','App','apps']])add(path,'get',scope+'.read','Read '+scope.slice(0,-1),{schema:ref(name)});
 add('/groups/{id}/members','get','groups.read','List permitted people in a group',{schema:paged('Person'),list:true,description:'Requires groups.read or groups.manage. Both the group and each returned person must be in the credential’s resource sets. '+exclusions});
 add('/groups','post','groups.manage','Create a static group',{created:true,body:object({name:string},['name'])});
 add('/groups/{id}','delete','groups.manage','Delete a group',{existing:true});
 add('/groups/{id}/members/{personId}','put','groups.manage','Add a manual group member',{existing:true,body:object({reason:string})});
 add('/groups/{id}/members/{personId}','delete','groups.manage','Remove a group member and exclude a matching rule member',{existing:true});
 add('/groups/{id}/rule','put','groups.manage','Set or clear an attribute membership rule',{existing:true,body:object({rule:nullable(ref('GroupRule'))},['rule'])});
 add('/apps','post','apps.manage','Create a SAML or OIDC company app',{created:true,body:ref('AppCreate'),description:'Native company-app validation applies. Creation requires an unrestricted apps resource set. These are company apps, separate from RER registrations and admin service apps. '+exclusions});
 add('/apps/{id}','patch','apps.manage','Update a SAML company app',{existing:true,body:ref('SamlSettings'),description:'SAML settings use the existing native validation; OIDC app updates and client-secret rotation are not supported here. '+exclusions});
 add('/apps/{id}','delete','apps.manage','Disable a company app',{existing:true});
 add('/assignments/{appId}/{principalType}/{principalId}','put','assignments.manage','Assign a person or group to an app',{existing:true,body:object({role:nullable(string)}),description:'role is the app’s mapped role, never an Auth administrator role. The app and target person/group must both be permitted. '+exclusions});
 add('/assignments/{appId}/{principalType}/{principalId}','delete','assignments.manage','Remove an app assignment',{existing:true});
 add('/people','post','people.manage','Onboard an invited member without sending an invitation',{created:true,body:object({email:{type:'string',format:'email'},name:string,kind:{type:'string',enum:['employee','contractor','service']},source,sourceId:string,set:fieldSet},['email']),description:'Creates a member directory record in invited state. Does not send mail, accept an invitation or grant proof. Existing email addresses are refused, never merged. '+exclusions});
 add('/people/{id}','patch','people.manage','Edit member profile, email or lifecycle state',{existing:true,body:object({source,set:fieldSet,email:{type:'string',format:'email'},state:{type:'string',enum:['active','suspended','terminated']}}),description:'Uses directory source precedence, lifecycle validation, group evaluation and provisioning. State changes do not accept an invitation. All affected people, groups and apps must be permitted. '+exclusions});
 add('/idps/{id}','put','idps.manage','Enable or disable an owner-configured provider',{existing:true,body:object({enabled:boolean},['enabled']),description:'Changes availability of an existing Google, Microsoft or Okta configuration. Never changes issuer, client credentials or identity bindings. '+exclusions});
 add('/policies/{domain}','put','policies.manage','Require a configured provider for an email domain',{existing:true,body:object({providerId:string},['providerId']),description:'Policies currently mean exact-domain required-provider rules only. The provider must already exist in AUTH_UPSTREAM_PROVIDERS. '+exclusions});
 add('/policies/{domain}','delete','policies.manage','Remove a domain required-provider rule',{existing:true});
 const saml=object({name:string,metadata:string,entityId:string,acsUrl:{type:'string',format:'uri'},acsBinding:{type:'string',enum:['post','redirect']},sloUrl:string,sloBinding:{type:'string',enum:['post','redirect']},nameIdFormat:{type:'string',enum:['persistent','emailAddress','unspecified','transient']},nameIdSource:{type:'string',enum:['person_id','email']},sign:{type:'string',enum:['response','assertion','both']},digest:{type:'string',enum:['sha256','sha512','sha1']},sha1Exception:boolean,encryption:{type:'string',enum:['aes256-gcm','aes128-cbc']},signingCertificate:string,encryptionCertificate:string,wantRequestsSigned:boolean,idpInitiated:boolean,relayState:string,attributes:array(object({name:string,source:string},['name','source'])),launchUrl:string});
 const oidc=object({name:string,authMethod:{type:'string',enum:['client_secret_basic','client_secret_post','private_key_jwt','none']},jwks:{type:'object',description:'Public app verification keys only.'},redirectUris:array(string),postLogoutRedirectUris:array(string),requirePkce:boolean,subjectType:{type:'string',enum:['public','pairwise']},legacyFlows:boolean,frontchannelLogoutUri:string,backchannelLogoutUri:string,idTokenAlg:{type:'string',enum:['ES256','RS256']},attributes:array(object({name:string,source:string},['name','source'])),launchUrl:string},['name','redirectUris']);
 return {
  openapi:'3.1.0',info:{title:'Auth machine administration API',version:'1.0.0',description:'Versioned, scoped machine administration. '+exclusions+' Current policy scope is domain-provider requirements; idps.manage controls availability of preconfigured providers. Future custom-role, policy and federation capabilities inherit this credential and exclusion model under their own clauses; the Terraform provider is a separate deliverable.'},
  servers:[{url:(ctx.issuer??ctx.origin)+'/api/auth/admin/v1'}],security:[{adminBearer:[]}],paths,
  'x-token-endpoint':(ctx.issuer??ctx.origin)+'/oidc/token','x-client-authentication':{grant_type:'client_credentials',method:'private_key_jwt',clientIdPrefix:'auth-admin-service:',clientSecretSupported:false,maxTokenSeconds:300,maxRegistrationDays:365,sourceIpHeader:'CF-Connecting-IP'},
  'x-exclusions':exclusions,'x-scopes':Object.fromEntries(SCOPES.map(s=>[s,s==='idps.manage'?'Read and enable/disable owner-configured providers; no credential, issuer or subject association changes.':s==='policies.manage'?'Read and change exact-domain required-provider rules only.':s.endsWith('.manage')?'Read and mutate the named family within permitted resources and exclusions.':'Read the safe projection of the named family.'])),
  components:{securitySchemes:{adminBearer:{type:'http',scheme:'bearer',bearerFormat:'JWT',description:'OAuth client_credentials access token from /oidc/token authenticated by private_key_jwt, with audience '+(ctx.issuer??ctx.origin)+'/api/auth/admin/v1. Browser sessions, preparer keys, general OIDC tokens and RER tokens are refused.'}},schemas:{
   Error:{type:'object',required:['error'],properties:{error:string,refusals:array(string)}},Result:{type:'object',description:'Native operation result; contains no administrator credential material.'},
   Person:object({id:string,email:{type:'string',format:'email'},name:string,state:{type:'string',enum:['invited','active','suspended','terminated']},profile:{type:'object',additionalProperties:string}},['id','email','name','state','profile']),
   Group:object({id:string,name:string,rule:nullable(ref('GroupRule'))},['id','name','rule']),
   GroupRule:object({match:{type:'string',enum:['all','any']},conditions:{type:'array',minItems:1,maxItems:10,items:object({field:string,op:{type:'string',enum:['eq','neq','in','present','absent']},value:string,values:array(string)},['field','op'])}},['conditions']),
   App:{type:'object',required:['id','name','protocol'],properties:{id:string,name:string,protocol:{type:'string',enum:['saml','oidc']}},description:'Explicit safe protocol settings. No key material, client secrets, secret digests, sessions or provisioning credentials.'},
   Assignment:object({appId:string,principalType:{type:'string',enum:['person','group']},principalId:string,role:nullable(string)},['appId','principalType','principalId','role']),
   Policy:object({domain:string,providerId:string,available:boolean},['domain','providerId','available']),Provider:object({id:string,label:string,preset:{type:'string',enum:['google','microsoft','okta']},available:boolean},['id','label','preset','available']),Domain:object({domain:string,createdAt:{type:'integer'}},['domain','createdAt']),
   Log:object({id:{type:'integer'},event:string,subject:nullable(string),time:{type:'integer'},detail:object({serviceApp:string,owner:string,scope:string,result:{oneOf:[string,{type:'integer'}]}})},['id','event','subject','time']),
   SamlSettings:saml,AppCreate:{oneOf:[{...saml,properties:{protocol:{const:'saml'},...saml.properties},required:['protocol']},{...oidc,properties:{protocol:{const:'oidc'},...oidc.properties},required:['protocol',...oidc.required]}]},
  }},
 };
}
