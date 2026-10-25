import {probeApprovedRepair} from './agents/approved-probe.mjs';
// Credentials stay in the operator's process environment, outside model text.
const env=process.env;
try {
 if(env.AUTH_PROBE_CONSENT!=='end-test-session')throw new Error('Consent to ending this scoped test session is required.');
 const result=await probeApprovedRepair({origin:env.AUTH_ORIGIN,proposalId:env.AUTH_PROPOSAL_ID,preparerKey:env.AUTH_PREPARER_KEY,cookie:env.AUTH_TEST_SESSION,clientSecret:env.AUTH_PROBE_CLIENT_SECRET,spPrivateKey:env.AUTH_PROBE_SP_PRIVATE_KEY});
 console.log(JSON.stringify(result));
}catch{console.error('Scoped sign-in and logout verification failed. The repair remains unverified; inspect the employee journey without sharing credentials.');process.exitCode=1;}
