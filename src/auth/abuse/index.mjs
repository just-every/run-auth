import {all,auditDetail,bindingName,cookie,hash,json,limitState,one,random,requireSession,run,session,fail} from '../core.mjs';
import {authority,requireAuthority,requireLocalEmail} from '../local-email.mjs';

const DEFAULTS={sourceLimit:60,aggregateLimit:300,cooldownSeconds:60};
const SETTING='abuse_policy';
// Only the hosting adapter may supply source identity. Cloudflare overwrites
// this header at ingress; a standalone Request has no trusted edge metadata.
export function trustedSource(ctx,request) {
 if(ctx.trustedSource)return String(ctx.trustedSource(request)).slice(0,128);
 if(ctx.local)return 'local-listener';
 return request.cf?request.headers.get('cf-connecting-ip')||'unavailable':'unavailable';
}
export async function abusePolicy(ctx) {
 const row=await one(ctx,'SELECT value FROM auth_settings WHERE key=?',SETTING);
 return row?JSON.parse(row.value):{...DEFAULTS,revision:'default'};
}
export async function abuseModel(ctx) {
 return {policy:await abusePolicy(ctx),refusals:await all(ctx,"SELECT a.created_at,d.detail FROM auth_activity a JOIN auth_activity_details d ON d.activity_id=a.id WHERE a.event='abuse_refused' ORDER BY a.id DESC LIMIT 10")};
}
export async function abuseRead(ctx,request) {await requireSession(ctx,request,true);return json(await abuseModel(ctx));}
export async function configureAbuse(ctx,request,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 const policy={};
 for(const [key,max] of [['sourceLimit',10000],['aggregateLimit',100000],['cooldownSeconds',300]]) {
  const value=Number(data[key]);if(!Number.isSafeInteger(value)||value<1||value>max)fail('invalid_abuse_policy');policy[key]=value;
 }
 if(policy.aggregateLimit<policy.sourceLimit)fail('invalid_abuse_policy');
 policy.revision=random();
 const guard=authority(ctx,s,['owner','admin']);
 const result=await run(ctx,`INSERT INTO auth_settings(key,value) SELECT ?,? WHERE ${guard.clause} ON CONFLICT(key) DO UPDATE SET value=excluded.value`,SETTING,JSON.stringify(policy),...guard.args);
 if(!result.meta.changes)await requireAuthority(ctx,s,guard);
 await auditDetail(ctx,s.person_id,'abuse_configured',null,{...policy,result:'configured'});
 return json({policy});
}
function door(path) {
 if(path==='/auth/identity/email/request')return 'email-request';
 if(path==='/auth/identity/email/confirm')return 'email-confirm';
 if(/^\/auth\/(?:identity\/)?passkeys\/(?:register|authenticate)\/(?:options|verify)$/.test(path))return 'webauthn';
 if(/^\/api\/auth\/recovery\/(?:start|request|approve|complete|cancel|token)$/.test(path))return 'recovery';
 if(path==='/oidc/token')return 'token';
 return null;
}
async function clientIdentity(ctx,request) {
 const text=await request.clone().text();if(text.length>32768)fail('invalid_request');
 const form=new URLSearchParams(text),names=[form.get('client_id')];
 const basic=/^Basic ([A-Za-z0-9+/=]{1,32768})$/i.exec(request.headers.get('authorization')||'');
 if(basic)try{names.push(decodeURIComponent(atob(basic[1]).split(':')[0]));}catch{}
 const assertion=form.get('client_assertion');
 if(assertion&&assertion.length<=16384)try{names.push(JSON.parse(atob(assertion.split('.')[1].replace(/-/g,'+').replace(/_/g,'/'))).iss);}catch{}
 for(const name of names) {
  if(typeof name!=='string'||name.length>256)continue;
  for(const [table,column] of [['auth_clients','id'],['auth_oidc_clients','client_id'],['auth_admin_service_apps','client_id'],['auth_resource_services','client_id'],['auth_delegated_agents','client_id']]) {
   if(await one(ctx,`SELECT ${column} FROM ${table} WHERE ${column}=?`,name))return name;
  }
 }
 return 'unregistered';
}
export async function enforceAbuse(ctx,request,path) {
 const kind=request.method==='POST'&&door(path);if(!kind)return null;
 const policy=await abusePolicy(ctx);
 // Recovery has its own authenticated budget: anonymous traffic cannot spend
 // a proved person's recovery allowance, including emergency recovery.
 const person=kind==='recovery'?await session(ctx,request):null;
 const identity=kind==='token'?await clientIdentity(ctx,request):kind==='recovery'?person?.id??'anonymous':'public';
 const scope=await hash(JSON.stringify([kind,identity]));
 const source=await hash(ctx.abuseSource??'unavailable');
 const duration=policy.cooldownSeconds*1000;
 // Revision is deliberately absent: reconfiguration cannot reset spent budgets.
 const aggregate=await limitState(ctx,`abuse:aggregate:${scope}`,policy.aggregateLimit,duration);
 const individual=await limitState(ctx,`abuse:source:${scope}:${source}`,policy.sourceLimit,duration);
 if(aggregate.allowed&&individual.allowed)return null;
 const retryAfter=Math.max(aggregate.allowed?0:aggregate.retryAfter,individual.allowed?0:individual.retryAfter);
 await auditDetail(ctx,null,'abuse_refused',null,{door:kind,identity:await hash(identity),source,revision:policy.revision,result:'refused',reason:aggregate.allowed?'source_limit':'aggregate_limit',retryAfter,aggregateCount:aggregate.count,sourceCount:individual.count});
 if(kind==='email-request')return json({message:'If this address can sign in, a link has been sent.'},202,{'set-cookie':cookie(ctx,bindingName(ctx),random(),900)});
 return json({error:'rate_limited',retryAfter,message:`Too many attempts. Try again in ${retryAfter} seconds. Recovery remains available to a proved session.`},429,{'retry-after':String(retryAfter)});
}
