// App-link proposals: a preparer asks to link or remove an app; an
// administrator approves with a passkey exactly as for the other kinds. Linking
// pulls the app again after the claim and links only what the person was shown.
import {one,fail,validateClientOrigin} from '../core.mjs';
import {pullApp,firstSeen,punycode,sameKey} from '../links/app.mjs';
import {link} from '../links/handshake.mjs';

const clientByOrigin=(ctx,origin)=>one(ctx,'SELECT id,name,origin,linked_at FROM auth_clients WHERE origin=? AND disabled_at IS NULL',origin);
async function clientTarget(ctx,data) {
 const value=String(data.target||'').trim();
 const c=await one(ctx,'SELECT id FROM auth_clients WHERE (id=? OR origin=?) AND disabled_at IS NULL',value,value)||fail('app_not_found',404);
 return {target:c.id,params:{}};
}

export const APP_KINDS={
 approve_app_link:{
  async target(ctx,data) {
   const app=await pullApp(ctx,validateClientOrigin(ctx,String(data.target||'').trim()));
   return {target:app.origin,params:{app,firstSeen:await firstSeen(ctx,app.origin)}};
  },
  state:async(ctx,target)=>{const c=await clientByOrigin(ctx,target);return {origin:target,client:c?.id??null,linked_at:c?.linked_at??null};},
  same:state=>state.client
   ?{sql:'EXISTS(SELECT 1 FROM auth_clients WHERE id=? AND origin=? AND linked_at IS ? AND disabled_at IS NULL)',args:[state.client,state.origin,state.linked_at]}
   :{sql:'NOT EXISTS(SELECT 1 FROM auth_clients WHERE origin=? AND disabled_at IS NULL)',args:[state.origin]},
  check:()=>null,
  effect:async(ctx,state,params)=>({app:{origin:state.origin,name:params.app.name,firstSeen:params.firstSeen,punycode:punycode(state.origin),replaces:state.client},after:'linked'}),
  run:()=>[],
  async after(ctx,state,params,approverId) {
   const app=await pullApp(ctx,state.origin),shown=params.app;
   if(app.sector!==shown.sector||!sameKey(app.key,shown.key))fail('app_changed_since_proposal',409);
   await link(ctx,{app,source:'proposal',approvedBy:approverId,versionApproved:true});
  }},
 remove_app_link:{
  target:clientTarget,
  state:async(ctx,target)=>await one(ctx,'SELECT id,name,origin,disabled_at FROM auth_clients WHERE id=?',target)||null,
  same:state=>({sql:'EXISTS(SELECT 1 FROM auth_clients WHERE id=? AND disabled_at IS NULL)',args:[state?.id??'']}),
  check:state=>!state?'app_not_found':state.disabled_at?'app_not_linked':null,
  effect:async(ctx,state)=>({app:state?{origin:state.origin,name:state.name}:null,after:'removed'}),
  run:(ctx,state,claim)=>[ctx.db.prepare(`UPDATE auth_clients SET disabled_at=? WHERE id=? AND disabled_at IS NULL AND ${claim.sql}`).bind(ctx.now(),state.id,...claim.args)]},
};
