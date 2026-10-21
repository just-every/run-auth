import {one,all,json,fail,requireSession,auditDetail} from '../core.mjs';
import {requireLocalEmail,authority,requireAuthority} from '../local-email.mjs';
import {mappingDirectory} from './context.mjs';
import {validateProgram,evaluateProgram,previewDigest} from './program.mjs';
import {queueApp} from '../provisioning/obligations.mjs';
export const isMappingAction=path=>['/mapping/preview','/mapping/save','/mapping/rollback'].includes(path);
export async function mappingAction(ctx,request,path,data) {
 const s=await requireSession(ctx,request,true);
 const app=await one(ctx,'SELECT id,mapping_version FROM auth_apps WHERE id=? AND disabled_at IS NULL',String(data.appId??''))??fail('app_not_found',404);
 const directory=await mappingDirectory(ctx);
 let program;
 if(path==='/mapping/rollback'){
  const old=await one(ctx,'SELECT program FROM auth_mapping_versions WHERE app_id=? AND version=?',app.id,Number(data.targetVersion));if(!old)fail('mapping_version_not_found',404);program=validateProgram(old.program,directory.schema);
 }else program=validateProgram(data.program,directory.schema);
 const allRows=evaluateProgram(program,directory);
 const personIds=Array.isArray(data.personIds)?data.personIds:String(data.personIds??'').split(/[\s,]+/).filter(Boolean);
 if(!personIds.length||personIds.length>50||personIds.some(id=>!directory.dir.people.has(id)))fail('mapping_choose_people');
 const rows=allRows.filter(r=>personIds.includes(r.personId));
 const digest=await previewDigest(app.mapping_version,program,allRows);
 if(path==='/mapping/preview')return json({version:app.mapping_version,digest,rows,message:rows.map(r=>`${r.email}: ${JSON.stringify(r.values)}${r.warnings.length?' · '+r.warnings.join(', '):''}`).join('\n')});
 requireLocalEmail(ctx,s);const guard=authority(ctx,s,['owner','admin']);
 if(path==='/mapping/save'&&data.digest!==digest)fail('mapping_preview_changed',409);
 if(Number(data.version)!==app.mapping_version)fail('mapping_version_changed',409);
 const next=app.mapping_version+1;
 const condition=`EXISTS(SELECT 1 FROM auth_apps WHERE id=? AND mapping_version=? AND disabled_at IS NULL) AND ${guard.clause}`;
 const [created,updated]=await ctx.db.batch([
  ctx.db.prepare(`INSERT INTO auth_mapping_versions(app_id,version,program,created_by,created_at,rolled_back_from) SELECT ?,?,?,?,?,? WHERE ${condition}`).bind(app.id,next,JSON.stringify(program),s.person_id,ctx.now(),path==='/mapping/rollback'?Number(data.targetVersion):null,app.id,app.mapping_version,...guard.args),
  ctx.db.prepare(`UPDATE auth_apps SET mapping_version=?,updated_at=? WHERE id=? AND mapping_version=? AND disabled_at IS NULL AND ${guard.clause}`).bind(next,ctx.now(),app.id,app.mapping_version,...guard.args),
 ]);
 if(!created.meta.changes||!updated.meta.changes){await requireAuthority(ctx,s,guard);fail('mapping_version_changed',409);}
 await auditDetail(ctx,s.person_id,path==='/mapping/rollback'?'mapping_rolled_back':'mapping_saved',app.id,{version:next,from:app.mapping_version,target:path==='/mapping/rollback'?Number(data.targetVersion):null});
 await queueApp(ctx,app.id,'mapping_changed');return json({version:next,message:`Mapping version ${next} is active.`});
}
export async function mappingVersions(ctx,appId){return all(ctx,'SELECT version,program,created_at,rolled_back_from FROM auth_mapping_versions WHERE app_id=? ORDER BY version DESC',appId);}
