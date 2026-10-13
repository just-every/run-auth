// What the owner needs to decide for each staged row. Classification is pure:
// it reads the rows plus the current people, so a review is always current.
import {addressOf,mailboxOf,FORMULA} from './parse.mjs';

// Reasons that make a row impossible to admit, and reasons that only start it unselected.
export const BLOCKING=['owner_address','existing_person','refused_domain','invalid_email'];
export const CAUTION=['duplicate_in_file','disabled_at_source','formula_text'];

const reserved=(ctx,email)=>!ctx.local&&/\.(localhost|test|invalid)$/.test(email);
export function classify(ctx,rows,people) {
 const byEmail=new Map(people.map(p=>[p.email,p])),mailboxes=new Map();
 for(const row of rows)if(row.email&&!row.emailProblem){const key=mailboxOf(row.email);mailboxes.set(key,[...(mailboxes.get(key)||[]),row]);}
 return rows.map(row=>{
  const reasons=[],person=row.email?byEmail.get(row.email):null;
  if(row.emailProblem==='invalid_email'||!row.email)reasons.push('invalid_email');
  else if(row.emailProblem==='refused_domain'||reserved(ctx,row.email))reasons.push('refused_domain');
  if(person?.role==='owner')reasons.push('owner_address');
  else if(person)reasons.push('existing_person');
  const twins=row.email&&!row.emailProblem?mailboxes.get(mailboxOf(row.email)).filter(other=>other!==row):[];
  if(twins.length)reasons.push('duplicate_in_file');
  if(row.disabled===true)reasons.push('disabled_at_source');
  if(row.formulaName)reasons.push('formula_text');
  const admittable=!reasons.some(r=>BLOCKING.includes(r));
  return {...row,reasons,admittable,selected:admittable&&!reasons.some(r=>CAUTION.includes(r))};
 });
}


// A stored row back in the parser's shape: the address and name checks are pure,
// so they give the same answer as at staging.
export function stagedShape(row) {
 const name=row.display_name||'';
 return {idx:row.idx,sourceId:row.source_id,email:row.email,emailProblem:row.email?addressOf(row.email).problem:'invalid_email',displayName:row.display_name,formulaName:FORMULA.test(name),disabled:row.disabled===null?null:Boolean(row.disabled),groups:JSON.parse(row.groups),status:row.status,personId:row.person_id,invitedAt:row.invited_at};
}
