import {fail,input,requireSession} from '../../core.mjs';
import {authority,requireLocalEmail} from '../../local-email.mjs';
export const CLIENT_PREFIX='delegated-agent:';
export const SCOPE='assignments.manage';
export const API_ID='auth.assignments';
export const TARGET_PATH='/api/auth/admin/v1/delegated-assignments/execute';
export const issuer=ctx=>ctx.issuer??ctx.origin;
export const organization=ctx=>ctx.organizationId??'root';
export const target=ctx=>issuer(ctx)+TARGET_PATH;
export const publicPath=(ctx,path)=>(ctx.basePath??'')+path;
export function id(value,code='invalid_identifier') {
 if(typeof value!=='string'||!value||value.length>200||!/^[-A-Za-z0-9_:]+$/.test(value))fail(code);
 return value;
}
export function text(value,max,code) {
 if(typeof value!=='string'||!value.trim()||value!==value.trim()||value.length>max||/[\x00-\x1f]/.test(value))fail(code);
 return value;
}
export function exact(data,keys,required=keys) {
 if(!data||typeof data!=='object'||Array.isArray(data)||Object.keys(data).some(k=>!keys.includes(k))||required.some(k=>!Object.hasOwn(data,k)))fail('invalid_delegation_request');
}
export async function body(ctx,request,{browser=false}={}) {
 if(browser)return input(ctx,request);
 if(!(request.headers.get('content-type')??'').startsWith('application/json'))fail('unsupported_content_type',415);
 if(Number(request.headers.get('content-length')||0)>32768)fail('request_too_large',413);
 const raw=await request.text();if(raw.length>32768)fail('request_too_large',413);
 try {return JSON.parse(raw);}catch{fail('invalid_json');}
}
export async function ownerSession(ctx,request) {
 const s=await requireSession(ctx,request,true);
 if(s.role!=='owner')fail('owner_required',403);
 requireLocalEmail(ctx,s);return s;
}
export const ownerGuard=(ctx,s)=>authority(ctx,s,['owner']);
export async function approvalSession(ctx,request) {
 const s=await requireSession(ctx,request,true);
 if(!['owner','admin'].includes(s.role))fail('legacy_administrator_required',403);
 requireLocalEmail(ctx,s);return s;
}
export const approvalGuard=(ctx,s)=>authority(ctx,s,['owner','admin']);
export async function consentingSession(ctx,request) {
 const s=await requireSession(ctx,request);
 if(!JSON.parse(s.amr).includes('hwk'))fail('passkey_consent_required',403);
 return s;
}
export function personSessionGuard(ctx,s) {
 return {clause:"EXISTS(SELECT 1 FROM auth_sessions ds JOIN oa_operators dp ON dp.id=ds.person_id WHERE ds.id=? AND ds.person_id=? AND ds.amr=? AND ds.person_version=? AND ds.person_version=dp.version AND dp.status='active' AND ds.revoked_at IS NULL AND ds.expires_at>?)",args:[s.id,s.person_id,s.amr,s.person_version,ctx.now()]};
}
export const both=(...guards)=>({clause:guards.map(g=>'('+g.clause+')').join(' AND '),args:guards.flatMap(g=>g.args)});
export async function browserData(ctx,request,data) {
 if(request.method!=='POST')fail('method_not_allowed',405);
 if(request.headers.get('origin')!==ctx.origin)fail('origin_required',403);
 return data??await body(ctx,request,{browser:true});
}
