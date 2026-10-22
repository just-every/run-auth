import {all,fail} from '../core.mjs';
import {CLASSES} from './policy.mjs';
export async function retentionHolds(ctx) {
 const [manual,reviews,requests,legal]=await Promise.all([
  all(ctx,'SELECT id,kind,period_start,period_end,classes,reason,created_by,created_at FROM auth_retention_holds WHERE released_at IS NULL ORDER BY created_at,id'),
  all(ctx,"SELECT id,period_start,period_end FROM auth_reviews WHERE status='open'"),
  all(ctx,"SELECT id,created_at AS period_start,COALESCE(expires_at,8640000000000000) AS period_end FROM auth_access_requests WHERE state IN ('pending','approved','revocation_pending')"),
  all(ctx,'SELECT id,kind,reason,created_at FROM auth_erasure_holds WHERE released_at IS NULL'),
 ]);
 return [...manual.map(h=>({...h,classes:JSON.parse(h.classes),source:'retention'})),...reviews.map(h=>({...h,kind:'review',classes:[...CLASSES],source:'review'})),...requests.map(h=>({...h,kind:'request',classes:[...CLASSES],source:'request'})),...legal.map(h=>({...h,kind:'legal',classes:[...CLASSES],period_start:0,period_end:8640000000000000,source:'erasure',scope:h.kind}))];
}
export function validateHold(data,now) {
 if(!['review','request','investigation','legal'].includes(data.kind)||!Number.isSafeInteger(data.periodStart)||!Number.isSafeInteger(data.periodEnd)||data.periodStart<0||data.periodEnd<data.periodStart||data.periodEnd>8640000000000000)fail('invalid_retention_hold_period');
 if(typeof data.reason!=='string'||!data.reason.trim()||data.reason.length>500||/[\r\n]/.test(data.reason))fail('invalid_retention_hold_reason');
 const classes=data.classes??[...CLASSES];
 if(!Array.isArray(classes)||!classes.length||classes.some(c=>!CLASSES.includes(c)))fail('invalid_retention_hold_classes');
 return {kind:data.kind,periodStart:data.periodStart,periodEnd:data.periodEnd,reason:data.reason.trim(),classes:[...new Set(classes)],createdAt:now};
}
// SQL is generated from the fixed catalog and integer timestamps. Every delete
// checks these sources in its own transaction, including holds created after
// the seven-day preview and an open review created moments before cleanup.
export function unheld(entry,time) {
 return `NOT EXISTS(SELECT 1 FROM auth_retention_holds h WHERE h.released_at IS NULL AND h.period_start<=${time} AND h.period_end>=${time} AND EXISTS(SELECT 1 FROM json_each(h.classes) hc WHERE hc.value='${entry.class}'))
 AND NOT EXISTS(SELECT 1 FROM auth_reviews r WHERE r.status='open' AND r.period_start<=${time} AND r.period_end>=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_access_requests q WHERE q.state IN ('pending','approved','revocation_pending') AND q.created_at<=${time} AND COALESCE(q.expires_at,8640000000000000)>=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_erasure_holds h WHERE h.released_at IS NULL)`;
}
// Retain the full evidence period since each unfinished operation began. This
// is deliberately wider than matching one subject string in a JSON detail.
export const unfinished=time=>`NOT EXISTS(SELECT 1 FROM auth_access_requests q WHERE q.state IN ('pending','approved','revocation_pending') AND q.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_obligations o WHERE o.state='open' AND o.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_provisioning p WHERE p.state IN ('pending','failed','blocked') AND p.event_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_recoveries r WHERE r.completed_at IS NULL AND r.cancelled_at IS NULL AND r.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_role_cases c WHERE c.state='open' AND c.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_agent_proposals p WHERE p.status='pending' AND p.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_delegated_tasks d WHERE d.state IN ('requested','consented','approved') AND d.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_logout_deliveries d WHERE d.finished_at IS NULL AND d.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_oidc_logouts d WHERE d.finished_at IS NULL AND d.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_delegation_reversals r WHERE r.state='requested' AND r.created_at<=${time})
 AND NOT EXISTS(SELECT 1 FROM auth_erasure_remote e WHERE e.state!='verified' AND e.created_at<=${time})`;
