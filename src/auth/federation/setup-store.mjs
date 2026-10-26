import {fail} from '../core.mjs';

// Restrict rewriting to the maintained verifier's two generated SQL tables.
// All configuration values remain bind parameters. No request supplies SQL.
export function setupVerifierDatabase(db,setupId) {
 if(!/^[A-Za-z0-9_-]{43}$/.test(setupId))fail('invalid_federation_setup');
 const replacements={oa_identity_providers:'auth_federation_test_providers',oa_identity_provider_health:'auth_federation_test_health'};
 return {prepare(sql){
  const selected=Object.keys(replacements).filter(table=>new RegExp('\\b'+table+'\\b').test(sql));
  if(!selected.length)return db.prepare(sql);
  if(selected.length!==1||/[;'"`]/.test(sql.replace(/'[^']*'/g,'')))fail('unsupported_federation_verifier_query',503);
  const table=selected[0],target=replacements[table],scope=`setup_id='${setupId}'`;
  let rewritten=sql.replace(new RegExp('\\b'+table+'\\b','g'),target);
  if(/^\s*INSERT\b/i.test(sql)) {
   rewritten=rewritten.replace(new RegExp('('+target+'\\s*\\()'),'$1setup_id,').replace(/\bVALUES\s*\(/i,`VALUES('${setupId}',`).replace(/ON CONFLICT\(provider_id\)/i,'ON CONFLICT(setup_id,provider_id)');
  } else if(/^\s*(SELECT|UPDATE|DELETE)\b/i.test(sql)) {
   rewritten=/\bWHERE\b/i.test(rewritten)?rewritten.replace(/\bWHERE\b/i,'WHERE '+scope+' AND'):rewritten+' WHERE '+scope;
  } else fail('unsupported_federation_verifier_query',503);
  return db.prepare(rewritten);
 }};
}
