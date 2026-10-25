import {syncObligations} from '../obligations/sources.mjs';
// The preparer API, the one door a preparer key opens: GET reads the inventory,
// POST files a proposal. It reads no cookie and changes nothing but the
// proposal it files, its key's last use and an Activity entry.
import {random,one,all,json,fail,auditDetail,DAY} from '../core.mjs';
import {requireKey} from './keys.mjs';
import {KINDS,UNAVAILABLE,digest} from './kinds.mjs';

export const PROPOSAL_LIFETIME=DAY;
const READS_PER_HOUR=600,FILINGS_PER_HOUR=30;

// A proposal as its key sees it: what, why, who and which apps it affects, and what became of it.
const proposalView=(ctx,p)=>({id:p.id,kind:p.kind,target:p.target,reason:p.reason,effect:JSON.parse(p.effect),status:p.status==='pending'&&p.expires_at<=ctx.now()?'expired':p.status,outcome:p.outcome?JSON.parse(p.outcome):null,createdAt:p.created_at,expiresAt:p.expires_at,decidedAt:p.decided_at});

// Only these facts leave Auth through a key: no session, passkey, key or token material.
async function inventory(ctx,key) {
 const [people,allowed,rules,apps,proposals]=await Promise.all([
  all(ctx,"SELECT p.id,p.email,p.display_name AS name,p.role,p.status,p.created_at,(SELECT max(created_at) FROM auth_sessions s WHERE s.person_id=p.id) AS last_sign_in,EXISTS(SELECT 1 FROM auth_passkeys k WHERE k.person_id=p.id) AS passkey FROM oa_operators p ORDER BY p.email"),
  all(ctx,'SELECT domain FROM auth_domains ORDER BY domain'),
  all(ctx,'SELECT domain,provider_id FROM oa_domain_rules ORDER BY domain'),
  all(ctx,'SELECT id,name,origin,disabled_at FROM auth_clients ORDER BY name'),
  all(ctx,'SELECT * FROM auth_agent_proposals WHERE key_id=? ORDER BY created_at DESC LIMIT 100',key.id),
 ]);
 return {
  key:{id:key.id,label:key.label,expiresAt:key.expires_at},
  people:people.map(p=>({id:p.id,email:p.email,name:p.name,role:p.role,state:p.status,suspended:p.status==='inactive',passkey:Boolean(p.passkey),lastSignInAt:p.last_sign_in})),
  invitations:people.filter(p=>p.status==='invited').map(p=>({id:p.id,email:p.email,name:p.name,invitedAt:p.created_at})),
  allowedDomains:allowed.map(d=>d.domain),
  domainRules:rules.map(r=>({domain:r.domain,providerId:r.provider_id})),
  providers:(ctx.upstreamProviders||[]).map(p=>({id:p.id,label:p.label||p.preset})),
  apps:apps.map(a=>({id:a.id,name:a.name,origin:a.origin,disabled:Boolean(a.disabled_at)})),
  proposals:proposals.map(p=>proposalView(ctx,p)),
  proposalKinds:Object.keys(KINDS),
  unavailableKinds:Object.entries(UNAVAILABLE).map(([kind,reason])=>({kind,reason})),
  generatedAt:ctx.now(),
 };
}

async function body(ctx,request) {
 if(!(request.headers.get('content-type')||'').startsWith('application/json'))fail('unsupported_content_type',415);
 const text=await request.text();if(text.length>8192)fail('request_too_large',413);
 try {const data=JSON.parse(text);if(data&&typeof data==='object'&&!Array.isArray(data))return data;} catch {}
 fail('invalid_json');
}
const reasonOf=value=>{const reason=typeof value==='string'?value.trim():'';if(!reason||reason.length>200||/[\r\n]/.test(reason))fail('reason_required');return reason;};

async function file(ctx,request,key) {
 const data=await body(ctx,request),kindName=String(data.kind||'');
 if(Object.hasOwn(UNAVAILABLE,kindName))fail(UNAVAILABLE[kindName],409);
 const kind=Object.hasOwn(KINDS,kindName)?KINDS[kindName]:fail('unknown_kind');
 const reason=reasonOf(data.reason),{target,params}=await kind.target(ctx,data);
 return storeProposal(ctx,key,kindName,target,params,reason);
}

export async function storeProposal(ctx,key,kindName,target,params,reason,guard=null,originalState=null) {
 const kind=KINDS[kindName],state=originalState??await kind.state(ctx,target,params),refusal=await kind.check(state,ctx,params);
 if(refusal)fail(refusal,409);
 const id=random().slice(0,22),now=ctx.now(),effect=await kind.effect(ctx,state,params);
 const stored=await ctx.db.prepare(`INSERT INTO auth_agent_proposals(id,key_id,kind,target,params,reason,effect,target_state,state_digest,created_at,expires_at) SELECT ?,?,?,?,?,?,?,?,?,?,? WHERE ${guard?.clause??'1'}`)
  .bind(id,key.id,kindName,target,JSON.stringify(params),reason,JSON.stringify(effect),JSON.stringify(state),await digest(state),now,now+PROPOSAL_LIFETIME,...(guard?.args??[])).run();
 if(!stored.meta.changes)fail('session_authority_changed',403);
 await auditDetail(ctx,null,'agent_proposal_filed',id,{key:key.label,proposal:kindName.replace(/_/g,' '),target:effect.person?.email??effect.domain,reason});
 if(['approve_app_link','remove_app_link'].includes(kindName))await syncObligations(ctx);
 return json({...proposalView(ctx,await one(ctx,'SELECT * FROM auth_agent_proposals WHERE id=?',id)),...(kindName==='repair_signin'?{message:'Diagnosis prepared. Review the cited facts and exact diff on Agents before approving.',redirect:'/app/agents?proposal='+id}:{})},201);
}

export async function preparer(ctx,request) {
 if(request.method==='GET')return json(await inventory(ctx,await requireKey(ctx,request,'read',READS_PER_HOUR)));
 if(request.method==='POST')return file(ctx,request,await requireKey(ctx,request,'file',FILINGS_PER_HOUR));
 fail('method_not_allowed',405);
}
