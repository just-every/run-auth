import {one} from '../core.mjs';
// A separate source binding is additive for existing employer namespaces.
// It follows the same portability/erasure custody as its obligation metadata.
export const caseProjection='(SELECT case_id FROM auth_followup_cases WHERE obligation_id=auth_obligations.id) AS case_id';
export async function withCase(ctx,ob) {
 if(!ob||ob.case_id!==undefined)return ob;
 const binding=ob.id?await one(ctx,'SELECT case_id FROM auth_followup_cases WHERE obligation_id=?',ob.id):null;
 return {...ob,case_id:binding?.case_id??null};
}
