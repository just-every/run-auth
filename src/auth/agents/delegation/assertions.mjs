import {createLocalJWKSet,jwtVerify} from 'jose';
import {fail,run} from '../../core.mjs';
import {agentGuard} from './state.mjs';

export async function verifyPrivateAssertion(ctx,agent,raw,audience,claims) {
 if(typeof raw!=='string'||!raw||raw.length>16384)fail('invalid_client',401);
 let payload;
 try {
  ({payload}=await jwtVerify(raw,createLocalJWKSet(JSON.parse(agent.service.jwks)),{issuer:agent.client_id,subject:agent.client_id,audience,algorithms:['ES256','RS256'],currentDate:new Date(ctx.now()),requiredClaims:['jti','iat','exp']}));
 }catch{fail('invalid_client',401);}
 const now=Math.floor(ctx.now()/1000);
 if(payload.aud!==audience||typeof payload.jti!=='string'||!payload.jti||payload.jti.length>200||!Number.isSafeInteger(payload.iat)||!Number.isSafeInteger(payload.exp)||payload.iat>now+30||payload.iat<now-300||payload.exp<=now||payload.exp<=payload.iat||payload.exp>now+300||payload.exp-payload.iat>300||Object.entries(claims).some(([k,v])=>payload[k]!==v))fail('invalid_client',401);
 return payload;
}
export async function privateAssertion(ctx,agent,raw,audience,claims,guard=null) {
 guard??=await agentGuard(ctx,agent);
 const payload=await verifyPrivateAssertion(ctx,agent,raw,audience,claims);
 ctx.delegationActor??={actorId:'delegated-agent:'+agent.id,agentId:agent.id,accountablePersonId:null,approvedBy:null,grantId:claims.grant_id??null};
 await run(ctx,`DELETE FROM auth_delegation_assertions WHERE agent_id=? AND expires_at<=? AND ${guard.clause}`,agent.id,ctx.now(),...guard.args);
 let used;
 try {used=await run(ctx,`INSERT INTO auth_delegation_assertions(agent_id,jti,expires_at) SELECT ?,?,? WHERE ${guard.clause}`,agent.id,payload.jti,payload.exp*1000,...guard.args);}catch(error){if(/UNIQUE constraint failed|PRIMARY KEY constraint failed/.test(String(error?.message)))fail('invalid_client',401);throw error;}
 if(!used.meta.changes)fail('invalid_client',401);
 return payload;
}
