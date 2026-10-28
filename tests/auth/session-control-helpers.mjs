import assert from 'node:assert/strict';

export async function command(r,cookie,path,data,status=200,extra={}) {
 const response=await r.call(path,{method:'POST',cookie,data,...extra});
 assert.equal(response.status,status,path+' '+await response.clone().text());
 return response.json();
}
export async function changeRole(r,owner,data) {
 const preview=await command(r,owner,'/api/auth/roles/preview',data);
 return (await command(r,owner,'/api/auth/roles/apply',{previewId:preview.previewId})).plan;
}
export async function grant(r,owner,personId,roleId,view,edit=view) {
 return changeRole(r,owner,{kind:'grant',personId,roleId,resources:{view:{people:view},edit:{people:edit}}});
}
export async function operations(r,cookie,personId) {
 const response=await r.call('/api/auth/session-control?'+new URLSearchParams({personId}),{cookie});
 assert.equal(response.status,200,await response.clone().text());
 return (await response.json()).operations;
}
export async function people(r,cookie) {
 const response=await r.call('/api/auth/roles/people',{cookie});
 assert.equal(response.status,200,await response.clone().text());
 return (await response.json()).people;
}
export async function identityState(r,personId) {
 const read=(sql,...args)=>r.db.prepare(sql).bind(...args).all().then(result=>result.results);
 const [person,passkeys,roles,apps,links]=await Promise.all([
  read('SELECT id,email,status,role,version FROM oa_operators WHERE id=?',personId),
  read('SELECT * FROM auth_passkeys WHERE person_id=? ORDER BY id',personId),
  read('SELECT * FROM auth_role_grants WHERE person_id=? ORDER BY id',personId),
  read("SELECT * FROM auth_app_assignments WHERE principal_type='person' AND principal_id=? ORDER BY app_id",personId),
  read('SELECT * FROM auth_grants WHERE person_id=? ORDER BY client_id',personId),
 ]);
 return {person,passkeys,roles,apps,links};
}
export async function credentialsState(r,personId) {
 const tables=['auth_sessions','auth_refresh_families','auth_logout_deliveries','auth_oidc_logouts'];
 return Promise.all(tables.map(async name=>(await r.db.prepare(`SELECT * FROM ${name} WHERE person_id=? ORDER BY id`).bind(personId).all()).results));
}

export const fixtureEmail=n=>[`synthetic-auth-${n}`,'example.com'].join('@');
