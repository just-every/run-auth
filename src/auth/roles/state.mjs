import {one,all,fail} from '../core.mjs';
import {loadDirectory} from '../workforce/people/load.mjs';
import {matches} from '../workforce/people/groups.mjs';
import {BUILTINS,ALL_RESOURCES,LEGACY_RANK,subset,RESOURCE_KINDS} from './permissions.mjs';

export async function roleState(ctx,s) {
 // Reading the epoch first makes a concurrent change invalidate any later write,
 // including a membership change between the directory and the grant reads.
 const {epoch}=await one(ctx,'SELECT epoch FROM auth_role_epoch WHERE id=1');
 const [dir,custom,grants,cases,apps]=await Promise.all([
  loadDirectory(ctx),all(ctx,'SELECT * FROM auth_roles'),all(ctx,'SELECT * FROM auth_role_grants'),
  all(ctx,'SELECT * FROM auth_role_cases ORDER BY created_at,id'),
  all(ctx,'SELECT id,name,disabled_at,version FROM auth_apps ORDER BY name'),
 ]);
 const roles=new Map(BUILTINS.map(r=>[r.id,r]));
 for(const r of custom)roles.set(r.id,{...r,builtin:false,permissions:JSON.parse(r.permissions)});
 const memberships=new Map([...dir.people.keys()].map(id=>[id,new Set()]));
 for(const g of dir.groups)for(const p of dir.people.values()) {
  const row=dir.members.get(g.id)?.get(p.id);
  const excluded=dir.exclusions.has(g.id+':'+p.id);
  if(!excluded&&(row?.source==='manual'||g.rule&&matches(g.rule,dir.values(p))))memberships.get(p.id).add(g.id);
 }
 const byId=new Map(grants.map(g=>[g.id,g])),cache=new Map();
 const live=(g,seen=new Set())=>{
  if(cache.has(g.id))return cache.get(g.id);
  if(seen.has(g.id))return null;
  seen.add(g.id);
  const p=dir.people.get(g.person_id),issuer=dir.people.get(g.granted_by),r=roles.get(g.role_id);
  if(g.revoked_at!==null||!r||r.revision!==g.role_revision||p?.status!=='active'||issuer?.status!=='active')return null;
  const scope=JSON.parse(g.resources);
  let valid=false;
  if(!g.sponsor_grant_id)valid=['owner','admin'].includes(issuer.role)&&LEGACY_RANK[issuer.role]>r.rank;
  else {
   const parent=byId.get(g.sponsor_grant_id),sponsor=parent&&live(parent,seen);
   valid=Boolean(sponsor&&parent.person_id===issuer.id&&sponsor.role.rank>r.rank&&r.permissions.every(p=>sponsor.role.permissions.includes(p))&&['view','edit'].every(m=>RESOURCE_KINDS.every(k=>subset(scope[m][k],sponsor.resources[m][k]))));
  }
  const result=valid?{...g,role:r,resources:scope}:null;
  cache.set(g.id,result);return result;
 };
 const activeGrants=grants.map(g=>live(g)).filter(Boolean);
 const p=dir.people.get(s.person_id);
 if(!p||p.status!=='active')fail('session_authority_changed',403);
 const legacy=['owner','admin'].includes(p.role);
 const canDesignRoles=p.role==='owner'||p.role==='admin'&&(ctx.organizationId??'root')==='root';
 const entries=legacy?[{id:null,role:{id:p.role,rank:LEGACY_RANK[p.role],permissions:BUILTINS[0].permissions},resources:ALL_RESOURCES}]:activeGrants.filter(g=>g.person_id===s.person_id);
 // An unrevoked administrator assignment protects its target account even
 // while suspended or after its sponsor loses authority. Only revocation
 // removes that classification. Inactive assignments grant the actor nothing.
 const rankOf=id=>Math.max(LEGACY_RANK[dir.people.get(id)?.role]??0,...grants.filter(g=>g.person_id===id&&g.revoked_at===null).map(g=>roles.get(g.role_id)?.rank??0));
 const rank=Math.max(LEGACY_RANK[p.role]??0,...activeGrants.filter(g=>g.person_id===s.person_id).map(g=>g.role.rank));
 return {epoch,dir,roles,grants,activeGrants,cases,apps,memberships,person:p,legacy,canDesignRoles,entries,rank,rankOf};
}
