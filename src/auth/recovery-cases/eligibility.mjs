import {fail} from '../core.mjs';
import {privilegedApp,privilegedGroup} from '../decisions/privilege.mjs';
import {assignment} from '../workforce/directory.mjs';

// Recovery follows the existing administrator ranks and app and group marks.
// Ordinary relationship roles alone do not grant administrator custody.
export async function requireRecoveryEmployee(ctx,state,id) {
 const person=state.dir.people.get(id);
 if(!person||person.status!=='active'||person.role!=='member'||state.rankOf(id)>0)fail('administrator_recovery_required',403);
 for(const group of state.memberships.get(id)??[])if(await privilegedGroup(ctx,group))fail('administrator_recovery_required',403);
 for(const app of state.apps) {
  const held=await assignment(ctx,app.id,id);
  if(held&&await privilegedApp(ctx,app.id,held.role))fail('administrator_recovery_required',403);
 }
 return person;
}
