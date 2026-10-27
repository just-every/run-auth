import {one,all,run,email,random,hash,fail,json,requireSession,session,createSession,audit,DAY} from '../core.mjs';
import {authority,requireLocalEmail,requireAuthority} from '../local-email.mjs';
import {requireAccountRank} from '../ranks.mjs';
import {fencePerson} from '../links/logout.mjs';
import {framedPage,FRAME_SOURCES} from '../page-frame.mjs';

// An employer-local time must identify exactly one instant. Ambiguous and
// nonexistent daylight-saving times require the administrator to choose again.
export function startInstant(local,zone) {
 if(!/^\d{4}-\d\d-\d\dT\d\d:\d\d$/.test(local??''))fail('invalid_start_time');
 let format;try{format=new Intl.DateTimeFormat('sv-SE',{timeZone:zone,year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',hourCycle:'h23'});}catch{fail('invalid_time_zone');}
 const base=Date.parse(local+'Z'),matches=[];
 if(!Number.isFinite(base))fail('invalid_start_time');
 for(let offset=-14*60;offset<=14*60;offset+=15) {
  const instant=base+offset*60000;
  if(format.format(new Date(instant)).replace(' ','T')===local)matches.push(instant);
 }
 if(matches.length!==1)fail('ambiguous_or_invalid_start_time');
 return matches[0];
}
function schedule(data) {
 const start_at=startInstant(data.startLocal,data.timeZone),lead_days=Number(data.leadDays??7);
 if(!Number.isInteger(lead_days)||lead_days<0||lead_days>30)fail('invalid_lead_time');
 return {start_at,lead_days};
}
export async function onboardingModel(ctx) {
 return all(ctx,'SELECT person_id,start_at,start_local,time_zone,lead_days,personal_verified_at,dispatched_at,consumed_at,rescinded_at FROM auth_onboarding ORDER BY start_at');
}
export async function onboardingAction(ctx,request,action,data) {
 const s=await requireSession(ctx,request,true);requireLocalEmail(ctx,s);
 let guard=authority(ctx,s,['owner','admin']);
 const q=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 if(action==='/onboarding/create') {
  const address=email(data.email),personal=email(data.personalEmail),name=String(data.name??'').trim().slice(0,160),values=schedule(data),id=random();
  if(!address||!personal||personal===address||!name||values.start_at<=ctx.now())fail('invalid_future_hire');
  // A duplicate work address is refused, never merged. Personal contacts are
  // not identifiers and may belong to an unrelated existing account.
  const result=await ctx.db.batch([
   q(`INSERT INTO oa_operators(id,email,display_name,role,status,version,created_at) SELECT ?,?,?,'member','invited',1,? WHERE ${guard.clause} ON CONFLICT(email) DO NOTHING`,id,address,name,ctx.now(),...guard.args),
   q(`INSERT INTO auth_onboarding(person_id,personal_email,start_at,start_local,time_zone,lead_days,created_at) SELECT id,?,?,?,?,?,? FROM oa_operators WHERE id=?`,personal,values.start_at,data.startLocal,data.timeZone,values.lead_days,ctx.now(),id),
  ]);
  if(!result[0].meta.changes){await requireAuthority(ctx,s,guard);fail('person_already_exists',409);}
  await audit(ctx,s.person_id,'onboarding_created',id);await maintainOnboarding(ctx);return json({ok:true,personId:id},201);
 }
 const id=String(data.personId??''),hire=await one(ctx,'SELECT * FROM auth_onboarding WHERE person_id=? AND rescinded_at IS NULL',id);
 if(!hire)fail('hire_unavailable',404);
 guard=await requireAccountRank(ctx,s,id,guard);
 let changed;
 if(action==='/onboarding/schedule') {
  const values=schedule(data);
  changed=await run(ctx,`UPDATE auth_onboarding SET start_at=?,start_local=?,time_zone=?,lead_days=? WHERE person_id=? AND rescinded_at IS NULL AND ${guard.clause}`,values.start_at,data.startLocal,data.timeZone,values.lead_days,id,...guard.args);
 } else if(action==='/onboarding/reissue') {
  const results=await ctx.db.batch([q(`UPDATE auth_onboarding SET generation=generation+1,operation_id=?,dispatched_at=NULL,consumed_at=NULL WHERE person_id=? AND personal_verified_at IS NULL AND start_at>? AND rescinded_at IS NULL AND ${guard.clause}`,random(),id,ctx.now(),...guard.args)]);changed=results[0];
 } else if(action==='/onboarding/rescind') {
  const marker=random();
  const result=await ctx.db.batch([
   q(`UPDATE auth_onboarding SET rescinded_at=?,operation_id=?,generation=generation+1 WHERE person_id=? AND rescinded_at IS NULL AND ${guard.clause}`,ctx.now(),marker,id,...guard.args),
   q("UPDATE oa_operators SET status='inactive' WHERE id=? AND EXISTS(SELECT 1 FROM auth_onboarding WHERE person_id=? AND operation_id=?)",id,id,marker),
   q('DELETE FROM auth_passkeys WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_onboarding WHERE person_id=? AND operation_id=?)',id,id,marker),
   q('UPDATE auth_sessions SET revoked_at=? WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_onboarding WHERE person_id=? AND operation_id=?)',ctx.now(),id,id,marker),
   q('DELETE FROM auth_onboarding_links WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_onboarding WHERE person_id=? AND operation_id=?)',id,id,marker),
  ]);changed=result[0];
 } else fail('not_found',404);
 if(!changed.meta.changes){await requireAuthority(ctx,s,guard);fail('hire_changed',409);}
 if(action==='/onboarding/rescind')await fencePerson(ctx,id);
 await audit(ctx,s.person_id,'onboarding_'+action.split('/').at(-1),id);await maintainOnboarding(ctx);return json({ok:true});
}
export async function maintainOnboarding(ctx) {
 const due=await all(ctx,`SELECT h.* FROM auth_onboarding h JOIN oa_operators p ON p.id=h.person_id WHERE h.rescinded_at IS NULL AND h.personal_verified_at IS NULL AND h.dispatched_at IS NULL AND h.start_at>? AND h.start_at-h.lead_days*?<=? AND p.status='invited'`,ctx.now(),DAY,ctx.now());
 for(const hire of due) {
  const raw=random(),digest=await hash(raw);
  const marker=random(),results=await ctx.db.batch([
   ctx.db.prepare(`UPDATE auth_onboarding SET operation_id=?,dispatched_at=? WHERE person_id=? AND generation=? AND dispatched_at IS NULL AND rescinded_at IS NULL AND personal_verified_at IS NULL AND start_at>? AND start_at-lead_days*?<=?`).bind(marker,ctx.now(),hire.person_id,hire.generation,ctx.now(),DAY,ctx.now()),
   ctx.db.prepare(`INSERT INTO auth_onboarding_links(person_id,generation,token_hash,expires_at) SELECT person_id,generation,?,? FROM auth_onboarding WHERE person_id=? AND operation_id=? ON CONFLICT(person_id) DO UPDATE SET generation=excluded.generation,token_hash=excluded.token_hash,expires_at=excluded.expires_at`).bind(digest,ctx.now()+7*DAY,hire.person_id,marker),
  ]);
  if(!results[0].meta.changes)continue;
  const link=`${ctx.origin}${ctx.basePath??''}/auth/identity/onboarding?person=${encodeURIComponent(hire.person_id)}&token=${encodeURIComponent(raw)}`;
  try {
   if(!ctx.mail)throw new Error('mail_unavailable');
   await ctx.mail({personId:hire.person_id,to:hire.personal_email,subject:'Activate your Auth enrollment',text:`Enroll your passkey before your start time: ${link}`,html:`<p>Enroll your passkey before your start time.</p><p><a href="${link}">Activate enrollment</a></p>`});
   await audit(ctx,null,'onboarding_invitation_dispatched',hire.person_id);
  }catch {
   // An uncertain send is never retried automatically. Reissue explicitly
   // invalidates the previous credential before another message is attempted.
   await audit(ctx,null,'onboarding_delivery_uncertain',hire.person_id);
  }
 }
}
export function activationPage() {
 return new Response(framedPage('Activate your enrollment','<h1>Activate your enrollment</h1><p>This personal-address proof permits passkey enrollment only. App access requires work-address proof and your authorized start time.</p><form method="post"><button class="primary-button">Activate enrollment</button></form>'),{headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'strict-origin','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`}});
}
export async function activate(ctx,request,data) {
 const id=String(data.person??''),digest=await hash(String(data.token??'')),current=await session(ctx,request);
 if(current&&current.person_id!==id)fail('activation_person_mismatch',403);
 const hire=await one(ctx,'SELECT h.* FROM auth_onboarding h JOIN auth_onboarding_links l ON l.person_id=h.person_id AND l.generation=h.generation WHERE h.person_id=? AND l.token_hash=? AND h.consumed_at IS NULL AND h.rescinded_at IS NULL AND l.expires_at>?',id,digest,ctx.now());
 if(!hire)fail('activation_unavailable',403);
 const marker=random(),q=(sql,...args)=>ctx.db.prepare(sql).bind(...args);
 const result=await ctx.db.batch([
  q('UPDATE auth_onboarding SET consumed_at=?,personal_verified_at=?,operation_id=? WHERE person_id=? AND consumed_at IS NULL AND rescinded_at IS NULL AND EXISTS(SELECT 1 FROM auth_onboarding_links l WHERE l.person_id=auth_onboarding.person_id AND l.generation=auth_onboarding.generation AND l.token_hash=? AND l.expires_at>?)',ctx.now(),ctx.now(),marker,id,digest,ctx.now()),
  q("UPDATE oa_operators SET status='active' WHERE id=? AND status='invited' AND EXISTS(SELECT 1 FROM auth_onboarding WHERE person_id=? AND operation_id=?)",id,id,marker),
  q("INSERT INTO auth_emails(person_id,verified_at,proof_kind) SELECT person_id,?,'onboarding' FROM auth_onboarding WHERE person_id=? AND operation_id=? ON CONFLICT(person_id) DO UPDATE SET verified_at=excluded.verified_at,proof_kind=excluded.proof_kind",ctx.now(),id,marker),
  q('DELETE FROM auth_onboarding_links WHERE person_id=? AND EXISTS(SELECT 1 FROM auth_onboarding WHERE person_id=? AND operation_id=?)',id,id,marker),
 ]);
 if(!result[0].meta.changes)fail('activation_unavailable',403);
 const established=await createSession(ctx,id,['email','onboarding'],null,{localEmailVerifiedAt:ctx.now()});
 await audit(ctx,id,'onboarding_personal_address_proved');
 const headers={'set-cookie':established.header};
 if(request.headers.get('content-type')?.startsWith('application/x-www-form-urlencoded'))return new Response(null,{status:303,headers:{...headers,location:'/app/methods','cache-control':'no-store'}});
 return json({ok:true,returnTo:'/app/methods'},200,headers);
}

export function activationError(error) {
 return new Response(framedPage('Activation could not continue','<h1>Activation could not continue</h1><p role="alert">This activation is expired, used, rescinded, or belongs to a different person. Ask your administrator to review your enrollment or reissue an unused activation.</p><a class="primary-button" href="/signin">Return to sign-in</a>'),{status:error.status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-store','referrer-policy':'no-referrer','content-security-policy':`default-src 'none'; ${FRAME_SOURCES}; form-action 'self'; frame-ancestors 'none'; base-uri 'none'`}});
}
