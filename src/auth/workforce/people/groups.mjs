// Attribute-driven groups. A rule matches people by their effective directory
// values; a group's members are the people an administrator added ('manual'),
// plus those its rule matches ('rule'), minus explicit exclusions. Every
// member can be explained: which of the two put them there, and who or what.
import {AuthError,fail} from '../../core.mjs';

const OPS=['eq','neq','in','present','absent'];
const lower=value=>String(value??'').toLowerCase();

// The rule as stored, or the refusal. At least one condition: an empty rule would match everyone.
export function normalizeRule(defs,raw) {
 if(!raw||typeof raw!=='object'||!Array.isArray(raw.conditions)||!raw.conditions.length||raw.conditions.length>10)fail('invalid_rule');
 const match=raw.match==='any'?'any':'all';
 const conditions=raw.conditions.map(c=>{
  const spec=defs.get(String(c?.field||''));if(!spec||!OPS.includes(c?.op))throw new AuthError('invalid_rule');
  if(c.op==='present'||c.op==='absent')return {field:spec.key,op:c.op};
  if(c.op==='in'){const values=(Array.isArray(c.values)?c.values:[]).map(v=>String(v).trim()).filter(Boolean).slice(0,50);if(!values.length)throw new AuthError('invalid_rule');return {field:spec.key,op:'in',values};}
  const value=String(c.value??'').trim();if(!value||value.length>200)throw new AuthError('invalid_rule');
  return {field:spec.key,op:c.op,value};
 });
 return {match,conditions};
}
const holds=(c,values)=>{
 const have=lower(values[c.field]);
 if(c.op==='present')return have!=='';
 if(c.op==='absent')return have==='';
 if(c.op==='eq')return have===lower(c.value);
 if(c.op==='neq')return have!==lower(c.value);
 return c.values.some(v=>have===lower(v));
};
export const matches=(rule,values)=>rule.match==='any'?rule.conditions.some(c=>holds(c,values)):rule.conditions.every(c=>holds(c,values));
// The conditions that held for a person, in words an administrator can read.
export const because=(rule,values)=>rule.conditions.filter(c=>holds(c,values)).map(c=>c.op==='present'||c.op==='absent'?`${c.field} ${c.op==='present'?'is set':'is not set'}`:c.op==='in'?`${c.field} is one of ${c.values.join(', ')}`:`${c.field} ${c.op==='eq'?'is':'is not'} ${c.value}`);

// Dynamic membership the rule gives a person with these values: the rule's groups they belong to now.
export const ruleGroupsFor=(dir,personId,values)=>dir.ruleGroups.filter(g=>matches(g.rule,values)&&!dir.exclusions.has(g.id+':'+personId));

export const addRuleMember=(ctx,guard,groupId,personId,by)=>ctx.db.prepare(`INSERT INTO auth_group_members(group_id,person_id,added_by,added_at,source) SELECT ?,?,?,?,'rule' WHERE ${guard.clause} ON CONFLICT DO NOTHING`).bind(groupId,personId,by,ctx.now(),...guard.args);
export const dropRuleMember=(ctx,guard,groupId,personId)=>ctx.db.prepare(`DELETE FROM auth_group_members WHERE group_id=? AND person_id=? AND source='rule' AND ${guard.clause}`).bind(groupId,personId,...guard.args);
