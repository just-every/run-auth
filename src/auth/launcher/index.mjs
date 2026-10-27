import {all,one,run,json,fail,requireSession} from '../core.mjs';
import {assignment} from '../workforce/directory.mjs';

// Saved preferences never create an assignment or disclose another person's tiles.
export async function launcher(ctx,personId) {
 if(!await one(ctx,"SELECT 1 FROM oa_operators WHERE id=? AND status='active'",personId))return [];
 const apps=await all(ctx,`SELECT DISTINCT p.* FROM auth_apps p WHERE p.disabled_at IS NULL AND (
 EXISTS(SELECT 1 FROM auth_app_assignments a LEFT JOIN auth_group_members m ON a.principal_type='group' AND m.group_id=a.principal_id
 WHERE a.app_id=p.id AND ((a.principal_type='person' AND a.principal_id=?) OR m.person_id=?))
 OR EXISTS(SELECT 1 FROM auth_request_policies r WHERE r.app_id=p.id)
 OR EXISTS(SELECT 1 FROM auth_access_requests r WHERE r.app_id=p.id AND r.person_id=? AND r.state IN ('denied','approved','revocation_pending','expired_verified')))`,personId,personId,personId);
 const tiles=[];
 for(const a of apps) {
  const assigned=await assignment(ctx,a.id,personId);
  const hasAssignment=await one(ctx,`SELECT 1 FROM auth_app_assignments a LEFT JOIN auth_group_members m ON a.principal_type='group' AND m.group_id=a.principal_id WHERE a.app_id=? AND ((a.principal_type='person' AND a.principal_id=?) OR m.person_id=?)`,a.id,personId,personId);
  const denied=await one(ctx,'SELECT 1 FROM auth_app_denials WHERE app_id=? AND person_id=?',a.id,personId);
  const request=await one(ctx,"SELECT state,expires_at FROM auth_access_requests WHERE app_id=? AND person_id=? AND state IN ('denied','approved','revocation_pending','expired_verified') ORDER BY created_at DESC,id DESC LIMIT 1",a.id,personId);
  const policy=await one(ctx,'SELECT 1 FROM auth_request_policies WHERE app_id=?',a.id);
  let state=assigned?'ready':denied||request?.state==='denied'?'denied':request?.expires_at&&request.expires_at<=ctx.now()?'expired':hasAssignment?'denied':'unassigned';
  if(assigned) {
   const connector=await one(ctx,'SELECT last_error FROM auth_scim_connectors WHERE app_id=?',a.id);
   const pending=await one(ctx,"SELECT state FROM auth_provisioning WHERE app_id=? AND subject_id=? AND subject_type='person' AND state IN ('pending','failed','blocked')",a.id,personId);
   const account=connector&&await one(ctx,"SELECT state FROM auth_scim_accounts WHERE app_id=? AND subject_id=? AND subject_type='person'",a.id,personId);
   if(connector&&(connector.last_error||['failed','blocked'].includes(pending?.state)))state='connector-blocked';
   else if(connector&&account?.state!=='active')state='unprovisioned';
  }
  tiles.push({id:a.id,name:a.name,kind:a.protocol,role:assigned?.role??null,state,requestable:Boolean(policy),launch:state==='ready'?(a.idp_initiated?`/saml/launch/${encodeURIComponent(a.id)}`:a.launch_url):null});
 }
 const bookmarks=await all(ctx,`SELECT b.* FROM auth_launcher_bookmarks b JOIN auth_group_members m ON m.group_id=b.group_id WHERE m.person_id=?`,personId);
 tiles.push(...bookmarks.map(b=>({id:b.id,name:b.name,icon:b.icon,kind:'bookmark',state:'ready',launch:b.url})));
 const preferences=await all(ctx,'SELECT * FROM auth_launcher_preferences WHERE person_id=?',personId);
 return tiles.map(tile=>{const p=preferences.find(p=>p.tile_id===tile.id);return {...tile,favorite:Boolean(p?.favorite),lastUsedAt:p?.last_used_at??null};}).sort((a,b)=>a.name.localeCompare(b.name));
}

export async function launcherPreference(ctx,request,data) {
 const s=await requireSession(ctx,request),tile=(await launcher(ctx,s.person_id)).find(t=>t.id===data.id);
 const favorite=data.favorite===true||data.favorite==='true';
 if(!tile||(favorite&&tile.state!=='ready'))fail('launcher_access_unavailable',403);
 await run(ctx,`INSERT INTO auth_launcher_preferences(person_id,tile_id,favorite) VALUES(?,?,?) ON CONFLICT(person_id,tile_id) DO UPDATE SET favorite=excluded.favorite`,s.person_id,tile.id,favorite?1:0);
 return json({ok:true});
}

export async function launcherOpen(ctx,request) {
 const s=await requireSession(ctx,request),id=new URL(request.url).searchParams.get('id');
 const tile=(await launcher(ctx,s.person_id)).find(t=>t.id===id);
 if(!tile||tile.state!=='ready'||!tile.launch)fail('launcher_access_unavailable',403);
 await run(ctx,`INSERT INTO auth_launcher_preferences(person_id,tile_id,last_used_at) VALUES(?,?,?) ON CONFLICT(person_id,tile_id) DO UPDATE SET last_used_at=excluded.last_used_at`,s.person_id,tile.id,ctx.now());
 return new Response(null,{status:303,headers:{location:tile.launch,'cache-control':'no-store','referrer-policy':'no-referrer'}});
}
