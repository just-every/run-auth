import {test} from 'node:test';
import assert from 'node:assert/strict';
import {samlInstall,spCredentials,idpCertificates,serviceProvider,metadataOf,signIn,posted} from './saml-helpers.mjs';
import {passkeyPerson} from './agents-helpers.mjs';

const INPUTS={'google-workspace':{domain:'company.com'},'microsoft-365':{domain:'company.com'},slack:{workspace:'company'},'github-enterprise':{enterprise:'company'},salesforce:{myDomain:'company',orgId:'00D000000000001AAA'},zoom:{vanity:'company'}};

test('the catalog configures the seven named apps as working SAML apps with their SCIM connectors, and states what each needs',async t=>{
 const r=await samlInstall(t),idpCerts=await idpCertificates(r);
 const model=await (await r.call('/api/auth/company-apps',{cookie:r.owner.cookie})).json();
 assert.deepEqual(model.catalog.map(c=>c.id).sort(),['aws-iam-identity-center','github-enterprise','google-workspace','microsoft-365','salesforce','slack','zoom']);
 for(const c of model.catalog){assert.ok(c.edition&&c.permissions&&c.testUser&&c.rotation&&c.limits,c.id);assert.equal(c.verifiedAt,null);}
 // Inputs are checked before anything is stored.
 assert.equal((await r.admin('catalog/add',{recipe:'slack',workspace:'not a subdomain'})).status,400);
 assert.equal((await r.admin('catalog/add',{recipe:'salesforce',myDomain:'company',orgId:'nope'})).status,400);
 assert.equal((await r.admin('catalog/add',{recipe:'unknown'})).status,404);
 for(const [recipe,inputs] of Object.entries(INPUTS)) {
  const added=await r.admin('catalog/add',{recipe,...inputs,token:recipe==='slack'?'synthetic-slack-admin-token':undefined});assert.equal(added.status,201,`${recipe}: ${await added.clone().text()}`);
 }
 const sp=await spCredentials('aws');
 const aws=serviceProvider(r,{entity:'https://us-east-1.signin.aws.amazon.com/platform/saml/d-0000000000',idpCerts,sp,format:'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',assertion:false});
 assert.equal((await r.admin('catalog/add',{recipe:'aws-iam-identity-center',metadata:metadataOf(aws,sp),scimEndpoint:'https://scim.us-east-1.amazonaws.com/abc-123/scim/v2',token:'aws-scim-token'})).status,201);
 const apps=(await (await r.call('/api/auth/company-apps',{cookie:r.owner.cookie})).json()).companyApps,by=id=>apps.find(a=>a.recipe===id);
 assert.equal(by('slack').entityId,'https://slack.com');assert.equal(by('slack').acs[0].url,'https://company.slack.com/sso/saml');assert.equal(by('slack').provisioning.baseUrl,'https://api.slack.com/scim/v2');assert.equal(by('slack').provisioning.groups,true);
 const github=new URL(by('github-enterprise').acs[0].url);assert.equal(github.hostname,'github.com');assert.equal(github.pathname,'/enterprises/company/saml/consume');
 assert.equal(by('salesforce').acs[0].url,'https://company.my.salesforce.com/?so=00D000000000001AAA');
 assert.equal(by('microsoft-365').entityId,'urn:federation:MicrosoftOnline');assert.equal(by('google-workspace').acs[0].url,'https://www.google.com/a/company.com/acs');
 assert.equal(by('aws-iam-identity-center').provisioning.baseUrl,'https://scim.us-east-1.amazonaws.com/abc-123/scim/v2');assert.equal(by('zoom').provisioning,null);
 // A catalog app signs a person in like any SAML app: Zoom by email, Microsoft 365 by the person's Auth ID with IDPEmail.
 for(const [recipe,entity,acs] of [['zoom','company.zoom.us','https://company.zoom.us/saml/SSO'],['microsoft-365','urn:federation:MicrosoftOnline','https://login.microsoftonline.com/login.srf']]) {
  await r.admin('company-apps/assign',{appId:by(recipe).id,principalType:'person',principalId:'ada'});
  const saml=serviceProvider(r,{entity,idpCerts,assertion:false});saml.options.callbackUrl=acs;
  const {profile}=await saml.validatePostResponseAsync({SAMLResponse:(await posted(await signIn(r,saml,r.ada))).SAMLResponse});
  if(recipe==='zoom'){assert.equal(profile.nameID,'ada@example.com');assert.equal(profile.email,'ada@example.com');}
  else {assert.equal(profile.nameID,'ada');assert.equal(profile.IDPEmail,'ada@example.com');}
 }
});

test('company-app administration needs a passkey administrator with a fresh email proof, and signing certificates are the owner\'s',async t=>{
 const r=await samlInstall(t);
 const admin=await passkeyPerson(r,'admin','admin@example.com','admin');
 const as=(cookie,path,data)=>{r.tick();return r.call('/api/auth/'+path,{method:'POST',data,cookie});};
 assert.equal((await as(r.ada,'groups/create',{name:'Ops'})).status,403);
 assert.equal((await as(admin.cookie,'groups/create',{name:'Ops'})).status,201);
 assert.equal((await as(admin.cookie,'saml-keys/stage',{})).status,403);
 assert.equal((await as(r.ada,'company-apps/create',{entityId:'https://x.example.com',acsUrl:'https://x.example.com/acs'})).status,403);
 // Eleven minutes later the email proof is stale: refused until it is renewed, and nothing is written.
 r.tick=()=>{r.now=Date.now()+11*60000;};
 const stale=await as(admin.cookie,'company-apps/create',{entityId:'https://x.example.com',acsUrl:'https://x.example.com/acs'});
 assert.equal(stale.status,403);assert.equal((await stale.json()).error,'local_email_step_up_required');
 assert.equal((await r.db.prepare('SELECT COUNT(*) AS n FROM auth_apps').first()).n,0);
});
